"""
api_routes.py  –  REST API layer for the Data Manager tool
===========================================================
Mount this blueprint in app.py with:

    from api_routes import api_bp
    app.register_blueprint(api_bp)

All endpoints live under /api/...
Browser routes in app.py continue to use @login_required() + Flask sessions.
API routes use @api_login_required which validates a Bearer token instead.

Workflow for external callers (e.g. CRM):
------------------------------------------
1.  POST /api/auth/token                    – exchange username+password for a Bearer token
2.  POST /api/auth/refresh                  – extend an existing token's expiry (no re-login)
3.  POST /api/auth/revoke                   – invalidate the token when done
4.  POST /api/upload                        – upload Excel file (base64)
5.  GET  /api/rules                         – list available rules, optionally filter by column type
6.  POST /api/clean                         – run the cleaning pipeline
7.  GET  /api/preview/<job_id>              – paginated preview of cleaned rows
8.  GET  /api/download/<type>/<job_id>      – download result file as base64
9.  GET  /api/logs                          – activity logs (RBAC-filtered, paginated)
10. GET  /api/users                         – user list (RBAC-filtered, paginated)
11. POST /api/users/<id>/role               – change a user's role (admin only)
12. POST /api/users/<id>/toggle             – enable/disable a user account (admin only)
13. POST /api/users/<id>/reset_password     – admin resets a user's password (admin only)
14. POST /api/account/change_password       – logged-in user changes their own password
15. GET  /api/presets                       – list the caller's saved rule presets
16. GET  /api/presets/<id>                  – load a single preset (rules JSON)
17. POST /api/presets/save                  – save / overwrite a named preset
18. POST /api/presets/<id>/delete           – delete a preset
19. POST /api/users/create                  – create a new user (admin or manager only)

SESSION FIX
-----------
Flask sessions are cookie-based and unreliable for stateless API calls.
Instead, API state (uploaded file path, cleaned file paths, selected rules)
is stored in a server-side dict `_api_state` keyed by user_id.
This means state persists across requests as long as the Flask process is running.
Browser routes are completely unaffected — they still use Flask session as before.
"""

import base64
import json
import math
import os
import secrets
import string
from collections import defaultdict
from datetime import datetime
from io import BytesIO

import bcrypt
import pandas as pd
from flask import Blueprint, jsonify, request, g

from cleaning.engine import run_cleaning_pipeline
from cleaning.type_resolver import resolve_column_type
from cleaning.rules_registry import RULES_REGISTRY
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from helpers import (
    get_db_connection, log_action,
    fetch_visible_logs, detect_identifier_columns,
    generate_api_token, resolve_token, revoke_api_token,
    refresh_api_token, api_login_required,
    validate_password,
    check_login_rate_limit, record_login_attempt,
    get_visible_user_ids
)


api_bp = Blueprint("api", __name__, url_prefix="/api")
# Rate limiter - attach to the blueprint
# Uses IP address as the key. For production behind a proxy, set RATELIMIT_HEADERS_ENABLED and pass
# the real IP via X-Forwarded_For.
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[], #No global limit - we set per-route limites below
    storage_uri="memory://" # Use Redis? URI here for multi-worker: "redis://localhost:6379"
)

# ── Server-side state store (replaces Flask session for API routes) ───────────
#
# Keyed by user_id (int). Each entry holds:
#   {
#     "temp_file":      "temp_api_<user_id>.xlsx",
#     "uploaded_file":  "leads.xlsx",
#     "cleaned_file":   "leads_cleaned_20260310_153000.xlsx",
#     "invalid_file":   "leads_invalid_20260310_153000.xlsx",
#     "removed_file":   None,
#     "selected_rules": [("validate_email", "Email"), ...]
#   }
#
# In-memory — resets on Flask restart. Good enough for a single-server
# deployment. Move to Redis or DB for multi-worker setups.

from helpers import(get_db_connection, log_action, fetch_visible_logs, detect_identifier_columns,
                    generate_api_token, resolve_token, revoke_api_token, refresh_api_token,
                    api_login_required, validate_password, check_login_rate_limit,
                      record_login_attempt, get_job_state, set_job_state, clear_job_files,
                       MAX_PAGE_SIZE )


# ── Response helpers ──────────────────────────────────────────────────────────

def _unauthorised(msg="Unauthorised"):
    return jsonify({"error": msg}), 401

def _forbidden(msg="Forbidden"):
    return jsonify({"error": msg}), 403

def _bad_request(msg):
    return jsonify({"error": msg}), 400

def _not_found(msg):
    return jsonify({"error": msg}), 404


# ═════════════════════════════════════════════════════════════════════════════
# AUTH ENDPOINTS
# ═════════════════════════════════════════════════════════════════════════════

# ── 1. POST /api/auth/token ───────────────────────────────────────────────────

@api_bp.route("/auth/token", methods=["POST"])
def api_get_token():
    """
    Exchange username + password for a Bearer token (valid 24 hours).
    Blocked after 5 failed attempts in 10 minutes (matches browser login).

    Request body (JSON):
        { "username": "crm_user", "password": "..." }

    Response 200:
        {
          "token": "a3f9...",
          "expires_at": "2026-03-11T14:30:00",
          "role": "user"
        }

    Response 429 (too many failures):
        { "error": "Too many failed attempts. Try again in 3 minute(s)." }
    """
    if not request.is_json:
        return _bad_request("Content-Type must be application/json")

    data     = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return _bad_request("username and password are required")

    # Rate limit check — same logic as browser login route
    is_blocked, mins_left = check_login_rate_limit(username)
    if is_blocked:
        return jsonify({
            "error": f"Too many failed attempts. Try again in {mins_left} minute(s)."
        }), 429

    conn   = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        "SELECT id, username, password, role, is_active FROM users WHERE username = %s",
        (username,)
    )
    user = cursor.fetchone()
    conn.close()

    # Deliberately vague — don't reveal whether the username exists
    if not user or not user["is_active"]:
        record_login_attempt(username, success=False)
        return jsonify({"error": "Invalid credentials"}), 401

    if not bcrypt.checkpw(password.encode("utf-8"), user["password"].encode("utf-8")):
        record_login_attempt(username, success=False)
        log_action(user["id"], f"[API] Failed token request for '{username}'")
        return jsonify({"error": "Invalid credentials"}), 401

    record_login_attempt(username, success=True)
    token, expires_at = generate_api_token(user["id"], expires_hours=24)
    log_action(user["id"], f"[API] Token issued for user '{username}'")

    return jsonify({
        "token":      token,
        "expires_at": expires_at.isoformat(),
        "role":       user["role"],
    }), 200


# ── 2. POST /api/auth/refresh ─────────────────────────────────────────────────

@api_bp.route("/auth/refresh", methods=["POST"])
@api_login_required
def api_refresh_token():
    """
    Extend the current token's expiry by another 24 hours without re-logging in.
    Call this before the token expires to keep a long-running job alive.

    No request body needed.

    Response 200:
        { "success": true, "expires_at": "2026-03-12T14:30:00" }
    """
    token_str  = request.headers.get("Authorization", "").split(" ", 1)[1].strip()
    new_expiry = refresh_api_token(token_str, extends_hours=24)

    if not new_expiry:
        return _bad_request("Could not refresh token")

    log_action(g.api_user_id, f"[API] Token refreshed by '{g.api_username}'")

    return jsonify({
        "success":    True,
        "expires_at": new_expiry.isoformat(),
    }), 200


# ── 3. POST /api/auth/revoke ──────────────────────────────────────────────────

@api_bp.route("/auth/revoke", methods=["POST"])
@api_login_required
def api_revoke_token():
    """
    Invalidate the Bearer token used in this request.

    No request body needed.

    Response 200:
        { "success": true, "message": "Token revoked" }
    """
    token_str = request.headers.get("Authorization", "").split(" ", 1)[1].strip()
    revoke_api_token(token_str)
    log_action(g.api_user_id, f"[API] Token revoked by '{g.api_username}'")
    return jsonify({"success": True, "message": "Token revoked"}), 200


# ═════════════════════════════════════════════════════════════════════════════
# FILE / CLEANING ENDPOINTS
# ═════════════════════════════════════════════════════════════════════════════

# ── 4. POST /api/upload ───────────────────────────────────────────────────────

@api_bp.route("/upload", methods=["POST"])
@api_login_required
@limiter.limit("30 per hour")
def api_upload():
    """
    Upload an Excel or CSV file encoded as base64.
    Max file size: 10MB.
    """
    if not request.is_json:
        return _bad_request("Content-Type must be application/json")

    data = request.get_json()

    if "file_b64" not in data:
        return _bad_request("Missing required field: file_b64")

    try:
        file_bytes = base64.b64decode(data["file_b64"])
    except Exception:
        return _bad_request("file_b64 is not valid base64")

    # 1. File size limit check
    if len(file_bytes) > 10 * 1024 * 1024:
        return jsonify({"error": "File too large. Maximum size is 10MB."}), 413

    # 2. Filename sanitization and extension check
    filename = os.path.basename(data.get("filename", "uploaded_file.xlsx"))
    ext = os.path.splitext(filename)[1].lower()
    
    if not filename or ext not in (".xls", ".xlsx", ".csv"):
        filename = "uploaded_file.xlsx"
        ext = ".xlsx"

    # 3. Save raw bytes to disk (This ensures we have a physical file for pandas to read)
    temp_path = f"temp_api_{g.api_user_id}{ext}"
    with open(temp_path, "wb") as f:
        f.write(file_bytes)

    # 4. Read into DataFrame (The "Clean" Version)
    try:
        if ext == ".csv":
            try:
                # Try standard comma first
                df = pd.read_csv(temp_path)
            except Exception:
                # Fallback to auto-detecting delimiter (semicolon, tabs, etc.)
                df = pd.read_csv(temp_path, sep=None, engine="python")
        else:
            # Handles .xls and .xlsx
            df = pd.read_excel(temp_path)
    except Exception as e:
        return jsonify({"error": f"Could not parse file: {e}"}), 422

    # 5. Store in server-side state
    set_job_state(g.api_user_id, temp_file=temp_path, uploaded_file=filename)

    log_action(g.api_user_id, f"[API] Uploaded file '{filename}' ({len(df)} rows)")

    # 6. Metadata detection
    column_types = {col: resolve_column_type(df, col) for col in df.columns}
    identifier_columns = detect_identifier_columns(df)

    return jsonify({
        "success": True,
        "message": "File uploaded successfully",
        "filename": filename,
        "columns": df.columns.tolist(),
        "column_types": column_types,
        "identifier_columns": identifier_columns,
        "total_rows": len(df),
    }), 200


# ── 5. GET /api/rules ─────────────────────────────────────────────────────────

@api_bp.route("/rules", methods=["GET"])
@api_login_required
def api_rules():
    """
    Return all cleaning rules from the registry.

    Optional query param:
        ?column_type=email   – only return rules compatible with that column type

    Response 200:
        {
          "rules": {
            "validate_email": {
              "label": "Validate Email",
              "type": "validation",
              "allowed_types": ["email"],
              "description": ""
            }, ...
          }
        }
    """
    col_type_filter = request.args.get("column_type", "").strip().lower()

    rules_out = {}
    for key, meta in RULES_REGISTRY.items():
        allowed = meta.get("allowed_types", [])
        if col_type_filter and col_type_filter not in allowed:
            continue
        rules_out[key] = {
            "label":         meta.get("label", key),
            "type":          meta.get("type", "unknown"),
            "allowed_types": allowed,
            "description":   meta.get("description", ""),
        }

    return jsonify({"rules": rules_out}), 200


# ── 6. POST /api/clean ────────────────────────────────────────────────────────

@api_bp.route("/clean", methods=["POST"])
@api_login_required
@limiter.limit("60 per hour")
def api_clean():
    """
    Run the cleaning pipeline on the previously uploaded file.

    Request body (JSON):
        {
          "selected_rules": [
            {"rule": "validate_email",    "column": "Email"},
            {"rule": "validate_phone",    "column": "Phone"},
            {"rule": "handle_missing",    "column": "Phone",  "strategy": "flag"},
            {"rule": "handle_missing",    "column": "Budget", "strategy": "mean"},
            {"rule": "normalize_currency","column": "Budget"},
            {"rule": "trim_whitespace",   "column": "Name"},
            {"rule": "drop_duplicates",   "column": "Email"}
          ]
        }

    handle_missing strategy options: flag (default) | drop | median | mean | placeholder

    Response 200:
        {
          "success": true,
          "job_id": "20260310_153000",
          "summary": { "total_rows": 11, "clean_rows": 9, "invalid_rows": 2, ... },
          "files": {
            "cleaned": "leads_cleaned_20260310_153000.xlsx",
            "invalid": "leads_invalid_20260310_153000.xlsx",
            "removed": null
          },
          "system_warnings": [],
          "detailed_errors": [...]
        }
    """
    if not request.is_json:
        return _bad_request("Content-Type must be application/json")

    state     = get_job_state(g.api_user_id)
    temp_path = state.get("temp_file")

    if not temp_path or not os.path.exists(temp_path):
        return _bad_request("No uploaded file found. Call /api/upload first.")

    data      = request.get_json()
    raw_rules = data.get("selected_rules", [])

    if not raw_rules:
        return _bad_request("selected_rules must be a non-empty list.")

    # Build tuples exactly as app.py's /clean route does
    engine_rules = []
    dup_columns  = []

    for item in raw_rules:
        rule_name = item.get("rule", "").strip()
        column    = item.get("column", "").strip()
        if not rule_name or not column:
            continue
        if rule_name == "drop_duplicates":
            dup_columns.append(column)
        elif rule_name == "handle_missing":
            strategy = item.get("strategy", "flag").strip()
            engine_rules.append((rule_name, column, strategy))
        else:
            engine_rules.append((rule_name, column))

    try:
        if temp_path.endswith(".csv"):
            df = pd.read_csv(temp_path)
        else:
            df = pd.read_excel(temp_path)
    except Exception as e:
        return jsonify({"error": f"Could not read uploaded file: {e}"}), 500

    total_before = len(df)

    (
        cleaned_df,
        invalid_df,
        removed_rows,
        detailed_errors,
        incompatibility_errors,
        cleaning_summary,
    ) = run_cleaning_pipeline(
        df=df,
        selected_rules=engine_rules,
        duplicate_columns=dup_columns,
    )

    # Delete previous output files before saving new ones
    clear_job_files(g.api_user_id)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = os.path.splitext(state.get("uploaded_file", "file"))[0]

    cleaned_file = f"{base_name}_cleaned_{timestamp}.xlsx"
    cleaned_df.to_excel(cleaned_file, index=False)

    invalid_file = None
    if not invalid_df.empty:
        invalid_file = f"{base_name}_invalid_{timestamp}.xlsx"
        invalid_df.to_excel(invalid_file, index=False)

    removed_file = None
    if not removed_rows.empty:
        removed_file = f"{base_name}_removed_{timestamp}.xlsx"
        removed_rows.to_excel(removed_file, index=False)

    # Ingest data to Supabase database (CDP tables)
    from helpers import ingest_cleaning_results
    try:
        ingest_cleaning_results(cleaned_df, invalid_df, removed_rows, detailed_errors, g.api_user_id)
    except Exception as e:
        print(f"API Database Ingestion Warning: {e}")

    # Store in server-side state
    import json as _json
    set_job_state(
        g.api_user_id,
        cleaned_file=cleaned_file,
        invalid_file=invalid_file or "",
        removed_file=removed_file or "",
        rules_json=_json.dumps(engine_rules + [("drop_duplicates", c) for c in dup_columns])
    )
    all_rules = engine_rules + [("drop_duplicates", c) for c in dup_columns]

    # Build display string for logging
    column_rule_map = defaultdict(list)
    for rule_tuple in all_rules:
        rule_name    = rule_tuple[0]
        column       = rule_tuple[1]
        rule_meta    = RULES_REGISTRY.get(rule_name, {})
        display_name = rule_meta.get("label") or rule_name
        column_rule_map[column].append(display_name)

    rules_applied_display = [
        f"{col} ({', '.join(rules)})" for col, rules in column_rule_map.items()
    ]

    log_action(
        g.api_user_id,
        f"[API] Cleaned '{state.get('uploaded_file')}' | "
        f"rules: {', '.join(rules_applied_display)} | summary: {cleaning_summary}",
        total=total_before,
        valid=len(cleaned_df),
        invalid=len(invalid_df),
        removed=len(removed_rows),
        rules_applied=[(r[0], r[1]) for r in engine_rules],
        rule_counts=cleaning_summary.get("rules_trigger_counts", {}),
    )

    return jsonify({
        "success":         True,
        "job_id":          timestamp,
        "summary":         cleaning_summary,
        "files": {
            "cleaned": cleaned_file,
            "invalid": invalid_file,
            "removed": removed_file,
        },
        "system_warnings": incompatibility_errors,
        "detailed_errors": detailed_errors,
    }), 200


# ── 7. GET /api/preview/<job_id> ──────────────────────────────────────────────

@api_bp.route("/preview/<job_id>", methods=["GET"])
@api_login_required
def api_preview(job_id):
    """
    Paginated JSON preview of the cleaned rows for a given job.
    Matches the browser /preview/page pagination endpoint.

    Query params:
        ?page=1&per_page=20     defaults: page=1, per_page=20, max=100

    Response 200:
        {
          "job_id": "20260310_153000",
          "page": 1, "per_page": 20,
          "total_rows": 9, "total_pages": 1,
          "columns": [...],
          "rows": [...]
        }
    """
    state        = get_job_state(g.api_user_id)
    cleaned_file = state.get("cleaned_file", "")

    if not cleaned_file or job_id not in cleaned_file:
        return _not_found("No preview found for this job_id. Call /api/clean first.")

    if not os.path.exists(cleaned_file):
        return _not_found("Cleaned file no longer exists on disk.")

    page     = request.args.get("page", 1, type=int)
    per_page = min(request.args.get("per_page", 20, type=int), MAX_PAGE_SIZE)

    df          = pd.read_excel(cleaned_file)
    total_rows  = len(df)
    total_pages = max(1, math.ceil(total_rows / per_page))
    page        = max(1, min(page, total_pages))

    start    = (page - 1) * per_page
    slice_df = df.iloc[start : start + per_page].fillna("").astype(str)

    return jsonify({
        "job_id":      job_id,
        "page":        page,
        "per_page":    per_page,
        "total_rows":  total_rows,
        "total_pages": total_pages,
        "columns":     df.columns.tolist(),
        "rows":        slice_df.to_dict(orient="records"),
    }), 200


# ── 8. GET /api/download/<type>/<job_id> ──────────────────────────────────────

@api_bp.route("/download/<file_type>/<job_id>", methods=["GET"])
@api_login_required
@limiter.limit("120 per hour")
def api_download(file_type, job_id):
    """
    Return a base64-encoded Excel file for download.

    file_type: "cleaned" | "invalid" | "removed"
    job_id:    timestamp string returned by /api/clean

    Response 200:
        {
          "file_type": "cleaned",
          "filename":  "leads_cleaned_20260310_153000.xlsx",
          "file_b64":  "<base64 string>"
        }
    """
    type_to_key = {
        "cleaned": "cleaned_file",
        "invalid": "invalid_file",
        "removed": "removed_file",
    }

    if file_type not in type_to_key:
        return _bad_request(f"file_type must be one of: {', '.join(type_to_key)}")

    state    = get_job_state(g.api_user_id)
    filepath = state.get(type_to_key[file_type])

    if not filepath:
        return _not_found(f"No {file_type} file found. Call /api/clean first.")
    if job_id not in filepath:
        return _not_found("job_id does not match the most recent clean job.")
    if not os.path.exists(filepath):
        return _not_found("File no longer exists on disk.")

    with open(filepath, "rb") as f:
        encoded = base64.b64encode(f.read()).decode("utf-8")

    log_action(g.api_user_id, f"[API] Downloaded {file_type} file: {filepath}")

    return jsonify({
        "file_type": file_type,
        "filename":  os.path.basename(filepath),
        "file_b64":  encoded,
    }), 200


# ═════════════════════════════════════════════════════════════════════════════
# LOGS & USERS
# ═════════════════════════════════════════════════════════════════════════════

# ── 9. GET /api/logs ──────────────────────────────────────────────────────────

@api_bp.route("/logs", methods=["GET"])
@api_login_required
@limiter.limit("200 per hour")
def api_logs():
    """
    Paginated activity logs filtered by the caller's RBAC role.

    Query params:
        ?page=1&per_page=10&search=alice&from_date=2024-01-01&to_date=2024-12-31

    Response 200:
        {
          "page": 1, "per_page": 10, "total_logs": 120, "total_pages": 12,
          "logs": [{"id": 42, "username": "alice", "action": "...",
                    "total_rows": 500, "valid_rows": 480, "invalid_rows": 12,
                    "created_at": "2024-06-01T14:30:00"}, ...]
        }
    """
    page      = request.args.get("page", 1, type=int)
    per_page  = min(request.args.get("per_page", 10, type=int), MAX_PAGE_SIZE)
    search    = request.args.get("search", "").strip()
    from_date = request.args.get("from_date", "").strip()
    to_date   = request.args.get("to_date", "").strip()

    conn   = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    logs, total_logs = fetch_visible_logs(
        cursor,
        search=search     or None,
        from_date=from_date or None,
        to_date=to_date   or None,
        page=page,
        per_page=per_page,
        role=g.api_role,
        user_id=g.api_user_id,
    )
    conn.close()

    serialised = []
    for row in logs:
        r = dict(row)
        if isinstance(r.get("created_at"), datetime):
            r["created_at"] = r["created_at"].isoformat()
        serialised.append(r)

    total_pages = max(1, math.ceil(total_logs / per_page))

    return jsonify({
        "page":        page,
        "per_page":    per_page,
        "total_logs":  total_logs,
        "total_pages": total_pages,
        "logs":        serialised,
    }), 200


# ── 10. GET /api/users ────────────────────────────────────────────────────────

@api_bp.route("/users", methods=["GET"])
@api_login_required
@limiter.limit("200 per hour")
def api_users():
    """
    Users visible to the caller based on their RBAC role.

    Query params:
        ?page=1&per_page=10&search=alice&role=user&status=active&sort=newest

    Response 200:
        {
          "page": 1, "per_page": 10, "total_users": 35, "total_pages": 4,
          "users": [{"id": 1, "username": "alice", "role": "user", "is_active": true}, ...]
        }
    """
    role    = g.api_role
    user_id = g.api_user_id

    search        = request.args.get("search", "").strip()
    role_filter   = request.args.get("role", "").strip()
    status_filter = request.args.get("status", "").strip()
    sort          = request.args.get("sort", "").strip()
    page          = request.args.get("page", 1, type=int)
    per_page      = min(request.args.get("per_page", 10, type=int), MAX_PAGE_SIZE)
    offset        = (page - 1) * per_page

    base_query = "FROM users WHERE 1=1"
    params     = []

    if role == "admin":
        pass #sees everyone
    elif role in ("manager","team_lead"):
        conn_tmp = get_db_connection()
        cursor_tmp = conn_tmp.cursor(dictionary=True)
        visible_ids = get_visible_user_ids(cursor_tmp, role=role, user_id=user_id)
        conn_tmp.close()
        if visible_ids:
            placeholders = ", ".join(["%s"] * len(visible_ids))
            base_query += f" AND id IN ({placeholders})"
            params.extend(visible_ids)
        else:
            base_query += " AND 1=0"
    elif role == "user":
        base_query += " AND id = %s"
        params.append(user_id)

    if search:
        base_query += " AND username LIKE %s"
        params.append(f"%{search}%")
    if role_filter:
        base_query += " AND role = %s"
        params.append(role_filter)
    if status_filter == "active":
        base_query += " AND is_active = TRUE"
    elif status_filter == "inactive":
        base_query += " AND is_active = FALSE"

    order_clause = " ORDER BY username ASC"
    if sort == "username_desc":
        order_clause = " ORDER BY username DESC"
    elif sort == "newest":
        order_clause = " ORDER BY id DESC"
    elif sort == "oldest":
        order_clause = " ORDER BY id ASC"
    elif sort == "role":
        order_clause = " ORDER BY role ASC"

    conn   = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute(f"SELECT COUNT(*) AS total {base_query}", params)
    total_users = cursor.fetchone()["total"]

    cursor.execute(
        f"SELECT id, username, role, is_active {base_query}{order_clause} LIMIT %s OFFSET %s",
        params + [per_page, offset],
    )
    users = cursor.fetchall()
    conn.close()

    total_pages = max(1, math.ceil(total_users / per_page))

    return jsonify({
        "page":        page,
        "per_page":    per_page,
        "total_users": total_users,
        "total_pages": total_pages,
        "users":       users,
    }), 200


# ── 11. POST /api/users/<id>/role ─────────────────────────────────────────────

@api_bp.route("/users/<int:target_id>/role", methods=["POST"])
@api_login_required
def api_change_role(target_id):
    """
    Change the role of a user (admin only).

    Request body (JSON):
        { "new_role": "manager" }

    Response 200:
        { "success": true, "message": "Role updated to manager" }
    """
    if g.api_role != "admin":
        return _forbidden()

    if not request.is_json:
        return _bad_request("Content-Type must be application/json")

    data          = request.get_json()
    new_role      = data.get("new_role", "").strip()
    allowed_roles = {"user", "manager", "team_lead", "admin"}

    if new_role not in allowed_roles:
        return _bad_request(f"new_role must be one of: {', '.join(sorted(allowed_roles))}")

    conn   = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT role, username FROM users WHERE id = %s", (target_id,))
    user = cursor.fetchone()

    if not user:
        conn.close()
        return _not_found("User not found.")
    if user["username"] == g.api_username:
        conn.close()
        return _bad_request("You cannot change your own role.")
    if user["role"] == "admin":
        conn.close()
        return _bad_request("Cannot modify another admin's role.")
    if user["role"] == new_role:
        conn.close()
        return jsonify({"success": True, "message": "User already has this role."}), 200

    cursor.execute("UPDATE users SET role = %s WHERE id = %s", (new_role, target_id))
    conn.commit()
    conn.close()

    log_action(
        g.api_user_id,
        f"[API] Changed role of '{user['username']}' from {user['role']} to {new_role}",
    )

    return jsonify({"success": True, "message": f"Role updated to {new_role}"}), 200


# ── 12. POST /api/users/<id>/toggle ──────────────────────────────────────────

@api_bp.route("/users/<int:target_id>/toggle", methods=["POST"])
@api_login_required
def api_toggle_user(target_id):
    """
    Enable or disable a user account (admin only).

    No request body needed.

    Response 200:
        { "success": true, "message": "User disabled.", "is_active": false }
    """
    if g.api_role != "admin":
        return _forbidden()

    conn   = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        "SELECT username, role, is_active FROM users WHERE id = %s",
        (target_id,)
    )
    user = cursor.fetchone()

    if not user:
        conn.close()
        return _not_found("User not found.")
    if target_id == g.api_user_id:
        conn.close()
        return _bad_request("Cannot disable your own account.")
    if user["role"] == "admin":
        conn.close()
        return _bad_request("Cannot disable admin accounts.")

    new_status = False if user["is_active"] else True
    cursor.execute(
        "UPDATE users SET is_active = %s WHERE id = %s",
        (new_status, target_id)
    )
    conn.commit()
    conn.close()

    action_text = "Disabled" if not new_status else "Enabled"
    log_action(
        g.api_user_id,
        f"[API] {action_text} user (id={target_id}, username='{user['username']}')",
    )

    return jsonify({
        "success":   True,
        "message":   f"User {action_text.lower()}.",
        "is_active": new_status,
    }), 200


# ── 13. POST /api/users/<id>/reset_password ───────────────────────────────────

@api_bp.route("/users/<int:target_id>/reset_password", methods=["POST"])
@api_login_required
def api_reset_password(target_id):
    """
    Admin resets any non-admin user's password to a random temporary password.
    Unlike the browser (which flashes it once), the API returns the temp
    password in the JSON response — the caller is responsible for passing
    it to the user securely.

    Admin only. Cannot reset another admin's password.

    No request body needed.

    Response 200:
        {
          "success": true,
          "username": "john",
          "temp_password": "xK3!mPqw9Z"
        }
    """
    if g.api_role != "admin":
        return _forbidden()

    conn   = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT username, role FROM users WHERE id = %s", (target_id,))
    user = cursor.fetchone()

    if not user:
        conn.close()
        return _not_found("User not found.")

    if user["role"] == "admin":
        conn.close()
        return _forbidden("Cannot reset another admin's password.")

    # Generate a cryptographically random 10-char password that satisfies
    # validate_password rules (upper, lower, digit, special)
    chars = string.ascii_letters + string.digits + "!@#$"
    temp_password = (
        secrets.choice(string.ascii_uppercase) +
        secrets.choice(string.ascii_lowercase) +
        secrets.choice(string.digits) +
        secrets.choice("!@#$") +
        "".join(secrets.choice(chars) for _ in range(6))
    )
    temp_list = list(temp_password)
    secrets.SystemRandom().shuffle(temp_list)
    temp_password = "".join(temp_list)

    hashed = bcrypt.hashpw(temp_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    cursor.execute("UPDATE users SET password = %s WHERE id = %s", (hashed, target_id))
    conn.commit()
    conn.close()

    log_action(
        g.api_user_id,
        f"[API] Reset password for user '{user['username']}' (id={target_id})",
    )

    return jsonify({
        "success":       True,
        "username":      user["username"],
        "temp_password": temp_password,
    }), 200


# ═════════════════════════════════════════════════════════════════════════════
# ACCOUNT MANAGEMENT
# ═════════════════════════════════════════════════════════════════════════════

# ── 14. POST /api/account/change_password ─────────────────────────────────────

@api_bp.route("/account/change_password", methods=["POST"])
@api_login_required
def api_change_password():
    """
    Logged-in user changes their own password.
    Mirrors the browser POST /account/change_password route exactly.

    Request body (JSON):
        {
          "current_password": "oldPass1!",
          "new_password":     "newPass2@",
          "confirm_password": "newPass2@"
        }

    Response 200:
        { "success": true, "message": "Password changed successfully." }

    Response 400: current password wrong | passwords don't match | validation fails
    """
    if not request.is_json:
        return _bad_request("Content-Type must be application/json")

    data             = request.get_json()
    current_password = data.get("current_password", "")
    new_password     = data.get("new_password", "")
    confirm_password = data.get("confirm_password", "")

    if not current_password or not new_password or not confirm_password:
        return _bad_request("current_password, new_password and confirm_password are all required.")

    if new_password != confirm_password:
        return _bad_request("New passwords do not match.")

    errors = validate_password(new_password)
    if errors:
        return jsonify({"error": "Password does not meet requirements.", "details": errors}), 400

    conn   = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT password FROM users WHERE id = %s", (g.api_user_id,))
    user = cursor.fetchone()

    if not bcrypt.checkpw(current_password.encode("utf-8"), user["password"].encode("utf-8")):
        conn.close()
        return _bad_request("Current password is incorrect.")

    hashed = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    cursor.execute("UPDATE users SET password = %s WHERE id = %s", (hashed, g.api_user_id))
    conn.commit()
    conn.close()

    log_action(g.api_user_id, f"[API] '{g.api_username}' changed own password")
    return jsonify({"success": True, "message": "Password changed successfully."}), 200


# ═════════════════════════════════════════════════════════════════════════════
# PRESETS
# ═════════════════════════════════════════════════════════════════════════════

# ── 15. GET /api/presets ──────────────────────────────────────────────────────

@api_bp.route("/presets", methods=["GET"])
@api_login_required
def api_list_presets():
    """
    List all rule presets saved by the authenticated user.

    Response 200:
        {
          "presets": [
            {"id": 1, "name": "Daily CRM Clean", "created_at": "2026-03-10T09:00:00"},
            ...
          ]
        }
    """
    conn   = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        "SELECT id, name, created_at FROM rule_presets WHERE user_id = %s ORDER BY name",
        (g.api_user_id,)
    )
    presets = cursor.fetchall()
    conn.close()

    for p in presets:
        if hasattr(p.get("created_at"), "isoformat"):
            p["created_at"] = p["created_at"].isoformat()

    return jsonify({"presets": presets}), 200


# ── 16. GET /api/presets/<id> ─────────────────────────────────────────────────

@api_bp.route("/presets/<int:preset_id>", methods=["GET"])
@api_login_required
def api_get_preset(preset_id):
    """
    Load a single preset — returns the rules and strategies so the caller
    can pass them directly into /api/clean's selected_rules format.

    Response 200:
        {
          "id": 1,
          "name": "Daily CRM Clean",
          "rules": {
            "Email": ["validate_email", "validate_not_empty"],
            "Phone": ["validate_phone"]
          },
          "strategies": {
            "Phone": "flag"
          }
        }

    The caller should translate this into selected_rules like so:
        For each column/rule pair, emit {"rule": rule, "column": col}.
        For handle_missing, also include the strategy from strategies[col].
    """
    conn   = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        "SELECT id, name, rules_json FROM rule_presets WHERE id = %s AND user_id = %s",
        (preset_id, g.api_user_id)
    )
    preset = cursor.fetchone()
    conn.close()

    if not preset:
        return _not_found("Preset not found.")

    rules_data = json.loads(preset["rules_json"])

    # Support both old format (plain dict) and new format (rules + strategies)
    if isinstance(rules_data, dict) and "rules" in rules_data and "strategies" in rules_data:
        rules      = rules_data["rules"]
        strategies = rules_data["strategies"]
    else:
        rules      = rules_data
        strategies = {}

    return jsonify({
        "id":         preset["id"],
        "name":       preset["name"],
        "rules":      rules,
        "strategies": strategies,
    }), 200


# ── 17. POST /api/presets/save ────────────────────────────────────────────────

@api_bp.route("/presets/save", methods=["POST"])
@api_login_required
def api_save_preset():
    """
    Save or overwrite a named rule preset for the authenticated user.
    If a preset with the same name already exists for this user, it is overwritten.

    Request body (JSON):
        {
          "name": "Daily CRM Clean",
          "rules": {
            "Email": ["validate_email", "validate_not_empty"],
            "Phone": ["validate_phone", "handle_missing"]
          },
          "strategies": {
            "Phone": "flag"
          }
        }

    The strategies field is optional (defaults to {}).
    It maps column name → handle_missing strategy for any column that has
    handle_missing in its rules list.

    Response 200:
        { "success": true, "message": "Preset 'Daily CRM Clean' saved." }
    """
    if not request.is_json:
        return _bad_request("Content-Type must be application/json")

    data       = request.get_json()
    name       = data.get("name", "").strip()
    rules      = data.get("rules", {})
    strategies = data.get("strategies", {})

    if not name:
        return _bad_request("name is required.")
    if not rules or not isinstance(rules, dict):
        return _bad_request("rules must be a non-empty object mapping column names to rule lists.")

    # Store both rules and strategies together so they can be reloaded intact
    rules_json = json.dumps({"rules": rules, "strategies": strategies})

    conn   = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO rule_presets (user_id, name, rules_json)
        VALUES (%s, %s, %s)
        ON CONFLICT (user_id, name) DO UPDATE SET rules_json = EXCLUDED.rules_json
    """, (g.api_user_id, name, rules_json))
    conn.commit()
    conn.close()

    log_action(g.api_user_id, f"[API] '{g.api_username}' saved preset '{name}'")
    return jsonify({"success": True, "message": f"Preset '{name}' saved."}), 200


# ── 18. POST /api/presets/<id>/delete ─────────────────────────────────────────

@api_bp.route("/presets/<int:preset_id>/delete", methods=["POST"])
@api_login_required
def api_delete_preset(preset_id):
    """
    Delete a preset belonging to the authenticated user.
    Users can only delete their own presets.

    No request body needed.

    Response 200:
        { "success": true, "message": "Preset deleted." }

    Response 404: preset not found or belongs to another user
    """
    conn   = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "DELETE FROM rule_presets WHERE id = %s AND user_id = %s",
        (preset_id, g.api_user_id)
    )
    affected = cursor.rowcount
    conn.commit()
    conn.close()

    if affected == 0:
        return _not_found("Preset not found.")

    log_action(g.api_user_id, f"[API] '{g.api_username}' deleted preset id={preset_id}")
    return jsonify({"success": True, "message": "Preset deleted."}), 200

# ── 19. POST /api/users/create ────────────────────────────────────────────────

@api_bp.route("/users/create", methods=["POST"])
@api_login_required
def api_create_user():
    """
    Create a new user account (admin or manager only).

    Admins can create any role including other managers.
    Managers can only create users and team_leads (under themselves).

    Request body (JSON):
        {
          "username":         "john_doe",
          "password":         "TempPass1!",
          "confirm_password": "TempPass1!",
          "role":             "user",
          "email":            "john@example.com",   (optional)
          "manager_id":       3                     (optional, admin only)
        }

    Response 200:
        { "success": true, "user_id": 42, "username": "john_doe", "role": "user" }

    Notes:
      - Admins can set manager_id freely.
      - Managers always become the new user's supervisor (manager_id = caller's id).
      - role must be one the caller is allowed to create.
    """
    if g.api_role not in ("admin", "manager"):
        return _forbidden("Only admins and managers can create users.")

    if not request.is_json:
        return _bad_request("Content-Type must be application/json")

    data             = request.get_json()
    username         = data.get("username", "").strip()
    password         = data.get("password", "")
    confirm_password = data.get("confirm_password", "")
    role             = data.get("role", "").strip()
    email            = data.get("email", "").strip() or None

    # Role whitelist per caller
    if g.api_role == "admin":
        allowed_roles = {"user", "team_lead", "manager", "admin"}
    else:
        allowed_roles = {"user", "team_lead"}

    if not username:
        return _bad_request("username is required.")
    if not password:
        return _bad_request("password is required.")
    if password != confirm_password:
        return _bad_request("Passwords do not match.")
    if role not in allowed_roles:
        return _bad_request(f"role must be one of: {', '.join(sorted(allowed_roles))}")

    errors = validate_password(password)
    if errors:
        return jsonify({"error": "Password does not meet requirements.", "details": errors}), 400

    # Determine manager_id
    if role == "manager":
        new_manager_id = None          # managers report to admin implicitly
    elif g.api_role == "admin":
        raw = data.get("manager_id")
        new_manager_id = int(raw) if raw else None
    else:
        new_manager_id = g.api_user_id  # manager creating someone — they become supervisor

    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    conn   = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute(
            "INSERT INTO users (username, password, role, email, manager_id, created_by) "
            "VALUES (%s, %s, %s, %s, %s, %s) RETURNING id",
            (username, hashed, role, email, new_manager_id, g.api_user_id)
        )
        res = cursor.fetchone()
        new_user_id = res['id'] if isinstance(res, dict) else res[0]
        conn.commit()

        # Backfill role_id (matches app.py behaviour)
        cursor.execute("SELECT id FROM roles WHERE name = %s", (role,))
        role_row = cursor.fetchone()
        if role_row:
            cursor.execute("UPDATE users SET role_id = %s WHERE id = %s",
                           (role_row["id"], new_user_id))
            conn.commit()

        log_action(g.api_user_id,
                   f"[API] Created user '{username}' (id={new_user_id}) with role '{role}'")

        return jsonify({
            "success":  True,
            "user_id":  new_user_id,
            "username": username,
            "role":     role,
        }), 200

    except Exception as e:
        conn.rollback()
        if "Duplicate entry" in str(e) or "1062" in str(e):
            return _bad_request("Username already exists.")
        return jsonify({"error": f"Database error: {e}"}), 500
    finally:
        conn.close()


# ── 14b. POST /api/account/change_email ──────────────────────────────────────

@api_bp.route("/account/change_email", methods=["POST"])
@api_login_required
def api_change_email():
    """
    Logged-in user updates their own email address.

    Request body (JSON):
        { "email": "newemail@example.com" }

    Pass an empty string or omit "email" to clear the email field.

    Response 200:
        { "success": true, "message": "Email updated." }
    """
    if not request.is_json:
        return _bad_request("Content-Type must be application/json")

    data      = request.get_json()
    new_email = data.get("email", "").strip() or None

    conn   = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE users SET email = %s WHERE id = %s",
        (new_email, g.api_user_id)
    )
    conn.commit()
    conn.close()

    log_action(g.api_user_id, f"[API] '{g.api_username}' updated email")
    return jsonify({"success": True, "message": "Email updated."}), 200



# ── GET /api/health  (no auth required) ───────────────────────────────────────
@api_bp.route("/health", methods=["GET"])
def api_health():
    """Simple liveness check. No auth required. Returns 200 if the API is up."""
    return jsonify({"status": "ok"}), 200
