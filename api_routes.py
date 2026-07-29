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
20. GET  /api/v1/records/query             – filter & query master database (paginated JSON)

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
import logging
import string
from collections import defaultdict
from datetime import datetime
from io import BytesIO

_logger = logging.getLogger(__name__)

import bcrypt
import pandas as pd
from flask import Blueprint, jsonify, request, g, send_file

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
    Upload an Excel or CSV file.
    Supports BOTH:
    1. application/json with Base64 payload: {"file_b64": "...", "filename": "leads.xlsx"}
    2. multipart/form-data with file upload (form field 'file' or 'file_b64')
    Max file size: 10MB.
    """
    file_bytes = None
    raw_filename = None

    if request.is_json:
        data = request.get_json()
        if "file_b64" not in data:
            return _bad_request("Missing required field: file_b64")
        try:
            file_bytes = base64.b64decode(data["file_b64"])
        except Exception:
            return _bad_request("file_b64 is not valid base64")
        raw_filename = data.get("filename", "uploaded_file.xlsx")
    elif request.files and ("file" in request.files or "file_b64" in request.files):
        uploaded_file = request.files.get("file") or request.files.get("file_b64")
        raw_filename = uploaded_file.filename or "uploaded_file.xlsx"
        file_bytes = uploaded_file.read()
    elif request.form and "file_b64" in request.form:
        try:
            file_bytes = base64.b64decode(request.form["file_b64"])
        except Exception:
            return _bad_request("file_b64 form value is not valid base64")
        raw_filename = request.form.get("filename", "uploaded_file.xlsx")
    else:
        return _bad_request("Request must be application/json or multipart/form-data with a file.")

    if not file_bytes:
        return _bad_request("Uploaded file content is empty.")

    # 1. File size limit check
    if len(file_bytes) > 10 * 1024 * 1024:
        return jsonify({"error": "File too large. Maximum size is 10MB."}), 413

    # 2. Filename sanitization and extension check
    filename = os.path.basename(raw_filename)
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

    # 5. Generate unique job_id & record in uploaded_files DB table
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    job_id = f"job_{timestamp_str}_{secrets.token_hex(4)}"

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            INSERT INTO uploaded_files (user_id, filename, original_filename, uploaded_at, total_rows, rows_imported, rows_rejected, status)
            VALUES (%s, %s, %s, NOW(), %s, 0, 0, 'uploaded')
        """, (g.api_user_id, job_id, filename, len(df)))
        conn.commit()
    except Exception as exc:
        pass
    finally:
        conn.close()

    # Store in server-side state
    set_job_state(g.api_user_id, temp_file=temp_path, uploaded_file=filename, job_id=job_id)

    log_action(g.api_user_id, f"[API] Uploaded file '{filename}' ({len(df)} rows) | job_id={job_id}")

    # 6. Metadata detection
    column_types = {col: resolve_column_type(df, col) for col in df.columns}
    identifier_columns = detect_identifier_columns(df)

    return jsonify({
        "success": True,
        "job_id": job_id,
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


# ── 8b. GET /api/status/<job_id> ──────────────────────────────────────────────

@api_bp.route("/status/<job_id>", methods=["GET"])
@api_bp.route("/jobs/<job_id>/status", methods=["GET"])
@api_login_required
def api_job_status(job_id):
    """
    Check status, summary, inserted rows, rejected rows, and total counts for a job.

    Parameters:
        job_id (string): Unique job ID returned from /api/upload or /api/clean

    Response 200:
        {
          "success": true,
          "job_id": "job_20260723_151520_a1b2",
          "status": "completed",
          "filename": "leads.xlsx",
          "uploaded_at": "2026-07-23T15:15:20",
          "summary": {
            "total_rows": 500,
            "inserted_rows": 475,
            "valid_rows": 475,
            "rejected_rows": 15,
            "invalid_rows": 15,
            "removed_rows": 10
          },
          "rules_applied": [...],
          "rule_counts": {...}
        }
    """
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    job_data = None
    log_data = None

    try:
        if job_id.isdigit():
            cursor.execute(
                "SELECT * FROM uploaded_files WHERE (id = %s OR filename = %s) AND user_id = %s",
                (int(job_id), job_id, g.api_user_id)
            )
        else:
            cursor.execute(
                "SELECT * FROM uploaded_files WHERE (filename = %s OR filename LIKE %s) AND user_id = %s",
                (job_id, f"%{job_id}%", g.api_user_id)
            )
        job_data = cursor.fetchone()

        cursor.execute(
            "SELECT * FROM logs WHERE user_id = %s AND (action LIKE %s OR action LIKE %s) ORDER BY id DESC LIMIT 1",
            (g.api_user_id, f"%{job_id}%", "%[API] %")
        )
        log_data = cursor.fetchone()

    except Exception as e:
        _logger.warning("Error querying job status: %s", e)
    finally:
        conn.close()

    state = get_job_state(g.api_user_id)
    state_job_id = state.get("job_id") or ""
    state_file = state.get("uploaded_file") or ""

    if not job_data and not log_data and job_id != state_job_id and job_id not in state_file:
        return _not_found(f"Job ID '{job_id}' not found.")

    filename = (job_data.get("original_filename") if job_data else None) or state_file or "file.xlsx"
    status = (job_data.get("status") if job_data else None) or "completed"

    if job_data and isinstance(job_data.get("uploaded_at"), datetime):
        uploaded_at = job_data["uploaded_at"].isoformat()
    elif log_data and isinstance(log_data.get("created_at"), datetime):
        uploaded_at = log_data["created_at"].isoformat()
    else:
        uploaded_at = datetime.now().isoformat()

    total_rows = (log_data.get("total_rows") if log_data else None) or (job_data.get("total_rows") if job_data else 0)
    valid_rows = (log_data.get("valid_rows") if log_data else None) or (job_data.get("rows_imported") if job_data else total_rows)
    invalid_rows = (log_data.get("invalid_rows") if log_data else None) or (job_data.get("rows_rejected") if job_data else 0)
    removed_rows = (log_data.get("removed_rows") if log_data else None) or 0

    rules_applied = []
    rule_counts = {}
    if log_data:
        if log_data.get("rules_applied"):
            try:
                rules_applied = json.loads(log_data["rules_applied"])
            except Exception:
                pass
        if log_data.get("rule_counts"):
            try:
                rule_counts = json.loads(log_data["rule_counts"])
            except Exception:
                pass

    return jsonify({
        "success": True,
        "job_id": job_id,
        "status": status,
        "filename": filename,
        "uploaded_at": uploaded_at,
        "summary": {
          "total_rows": total_rows,
          "inserted_rows": valid_rows,
          "valid_rows": valid_rows,
          "rejected_rows": invalid_rows,
          "invalid_rows": invalid_rows,
          "removed_rows": removed_rows
        },
        "rules_applied": rules_applied,
        "rule_counts": rule_counts
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
        base_query += " AND is_active = 1"
    elif status_filter == "inactive":
        base_query += " AND is_active = 0"

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
    if g.api_role not in ["admin", "manager"]:
        return _forbidden()

    if not request.is_json:
        return _bad_request("Content-Type must be application/json")

    data          = request.get_json()
    new_role      = data.get("new_role", "").strip()
    
    if g.api_role == "admin":
        allowed_roles = {"user", "manager", "team_lead", "admin", "client"}
    else:
        allowed_roles = {"user", "team_lead", "client"}

    if new_role not in allowed_roles:
        return _bad_request(f"new_role must be one of: {', '.join(sorted(allowed_roles))}")

    conn   = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    if g.api_role == "manager":
        from helpers import get_visible_user_ids
        visible_ids = get_visible_user_ids(cursor, role="manager", user_id=g.api_user_id)
        if target_id not in visible_ids:
            conn.close()
            return _forbidden()
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

    new_status = 0 if user["is_active"] else 1
    cursor.execute(
        "UPDATE users SET is_active = %s WHERE id = %s",
        (new_status, target_id)
    )
    conn.commit()
    conn.close()

    action_text = "Disabled" if new_status == 0 else "Enabled"
    log_action(
        g.api_user_id,
        f"[API] {action_text} user (id={target_id}, username='{user['username']}')",
    )

    return jsonify({
        "success":   True,
        "message":   f"User {action_text.lower()}.",
        "is_active": bool(new_status),
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
        allowed_roles = {"user", "team_lead", "manager", "admin", "client"}
    else:
        allowed_roles = {"user", "team_lead", "client"}

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
            "VALUES (%s, %s, %s, %s, %s, %s)",
            (username, hashed, role, email, new_manager_id, g.api_user_id)
        )
        conn.commit()
        new_user_id = cursor.lastrowid

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


# ── 20. GET /api/v1/records/query ──────────────────────────────────────────────

@api_bp.route("/v1/records/query", methods=["GET"])
@api_login_required
@limiter.limit("300 per hour")
def api_query_master_records():
    """
    Pull API — Filter and query the master database with paginated JSON response.

    Query params:
        Pagination:
            ?page=1&per_page=20 (or ?limit=20)
        Sorting:
            ?sort_by=created_at&sort_order=desc
        General Search:
            ?search=john (or ?q=john) -> ILIKE match across key fields
        Field Filters:
            ?first_name=John&last_name=Doe&email_address=john@example.com
            ?company_name=Acme&city=New+York&country=USA&industry=Tech
            ?record_status=active&imported_by=admin&file_id=1&gender=Male
            ?phone=1234567890&state=NY&zip=10001
        Exact Match toggle:
            ?exact=true (default: false -> uses ILIKE/contains matching for string fields)
        Date Range Filters:
            ?created_after=2026-01-01&created_before=2026-12-31
            ?updated_after=2026-01-01&updated_before=2026-12-31

    Response 200:
        {
          "success": true,
          "page": 1,
          "per_page": 20,
          "total_records": 150,
          "total_pages": 8,
          "records": [ ... ],
          "filters_applied": { ... }
        }
    """
    raw_page = request.args.get("page", 1)
    raw_per_page = request.args.get("per_page") or request.args.get("limit") or 20

    try:
        page = max(1, int(raw_page))
    except (ValueError, TypeError):
        page = 1

    try:
        per_page = max(1, min(int(raw_per_page), MAX_PAGE_SIZE))
    except (ValueError, TypeError):
        per_page = 20

    sort_by = request.args.get("sort_by") or request.args.get("order_by") or "id"
    sort_order = (request.args.get("sort_order") or request.args.get("order") or "desc").lower()

    allowed_sort_fields = {
        "id": "id",
        "file_id": "file_id",
        "first_name": "first_name",
        "last_name": "last_name",
        "email_address": "email_address",
        "email": "email_address",
        "company_name": "company_name",
        "company": "company_name",
        "job_title": "job_title",
        "department": "department",
        "city": "city",
        "state_province": "state_province",
        "state": "state_province",
        "postal_zip_code": "postal_zip_code",
        "zip": "postal_zip_code",
        "country": "country",
        "industry": "industry",
        "lead_source": "lead_source",
        "record_status": "record_status",
        "status": "record_status",
        "gender": "gender",
        "created_at": "created_at",
        "updated_at": "updated_at",
        "imported_by": "imported_by"
    }

    db_sort_col = allowed_sort_fields.get(sort_by.lower(), "id")
    db_sort_dir = "ASC" if sort_order == "asc" else "DESC"

    exact_match = request.args.get("exact", "").lower() in ("true", "1", "yes")

    field_mappings = {
        "id": ("id", "int"),
        "file_id": ("file_id", "int"),
        "first_name": ("first_name", "text"),
        "last_name": ("last_name", "text"),
        "email_address": ("email_address", "text"),
        "email": ("email_address", "text"),
        "primary_phone_number": ("primary_phone_number", "text"),
        "phone": ("primary_phone_number", "text"),
        "alternate_phone_number": ("alternate_phone_number", "text"),
        "company_name": ("company_name", "text"),
        "company": ("company_name", "text"),
        "job_title": ("job_title", "text"),
        "department": ("department", "text"),
        "website_url": ("website_url", "text"),
        "address_line_1": ("address_line_1", "text"),
        "address_line_2": ("address_line_2", "text"),
        "city": ("city", "text"),
        "state_province": ("state_province", "text"),
        "state": ("state_province", "text"),
        "postal_zip_code": ("postal_zip_code", "text"),
        "zip": ("postal_zip_code", "text"),
        "country": ("country", "text"),
        "linkedin_profile_url": ("linkedin_profile_url", "text"),
        "industry": ("industry", "text"),
        "lead_source": ("lead_source", "text"),
        "record_status": ("record_status", "text"),
        "status": ("record_status", "text"),
        "date_of_birth": ("date_of_birth", "text"),
        "gender": ("gender", "text"),
        "company_size": ("company_size", "text"),
        "annual_revenue": ("annual_revenue", "text"),
        "imported_by": ("imported_by", "text")
    }

    where_clauses = []
    params = []
    applied_filters = {}

    for param_name, (col_name, col_type) in field_mappings.items():
        val = request.args.get(param_name, "").strip()
        if val:
            applied_filters[param_name] = val
            if col_type == "int":
                try:
                    where_clauses.append(f"{col_name} = %s")
                    params.append(int(val))
                except ValueError:
                    return _bad_request(f"Invalid integer value for parameter '{param_name}': {val}")
            else:
                if exact_match:
                    where_clauses.append(f"LOWER({col_name}) = LOWER(%s)")
                    params.append(val)
                else:
                    where_clauses.append(f"{col_name} ILIKE %s")
                    params.append(f"%{val}%")

    search_q = (request.args.get("search") or request.args.get("q") or "").strip()
    if search_q:
        applied_filters["search"] = search_q
        search_cols = [
            "first_name", "last_name", "email_address", "primary_phone_number",
            "company_name", "job_title", "department", "city", "state_province",
            "country", "industry", "lead_source", "imported_by"
        ]
        search_clauses = [f"{c} ILIKE %s" for c in search_cols]
        where_clauses.append(f"({' OR '.join(search_clauses)})")
        params.extend([f"%{search_q}%"] * len(search_cols))

    created_after = request.args.get("created_after") or request.args.get("start_date")
    if created_after and created_after.strip():
        val = created_after.strip()
        applied_filters["created_after"] = val
        where_clauses.append("created_at >= %s")
        params.append(val)

    created_before = request.args.get("created_before") or request.args.get("end_date")
    if created_before and created_before.strip():
        val = created_before.strip()
        applied_filters["created_before"] = val
        where_clauses.append("created_at <= %s")
        params.append(val)

    updated_after = request.args.get("updated_after")
    if updated_after and updated_after.strip():
        val = updated_after.strip()
        applied_filters["updated_after"] = val
        where_clauses.append("updated_at >= %s")
        params.append(val)

    updated_before = request.args.get("updated_before")
    if updated_before and updated_before.strip():
        val = updated_before.strip()
        applied_filters["updated_before"] = val
        where_clauses.append("updated_at <= %s")
        params.append(val)

    applied_filters["exact"] = exact_match
    applied_filters["sort_by"] = db_sort_col
    applied_filters["sort_order"] = db_sort_dir.lower()

    where_sql = f" WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

    output_format = (request.args.get("format") or request.args.get("export") or "json").lower()
    applied_filters["format"] = output_format

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Load field_registry mapping to replace integer field IDs (e.g., '65') with human readable attribute names
        cursor.execute("SELECT id, field_name FROM field_registry")
        field_reg_rows = cursor.fetchall() or []
        field_name_map = {str(r["id"]): r["field_name"] for r in field_reg_rows}

        def resolve_custom_fields(cf_raw):
            if not cf_raw:
                return {}
            if isinstance(cf_raw, str):
                try:
                    cf_raw = json.loads(cf_raw)
                except Exception:
                    return {}
            if isinstance(cf_raw, dict):
                resolved = {}
                for key, val in cf_raw.items():
                    str_key = str(key)
                    if str_key in field_name_map:
                        resolved[field_name_map[str_key]] = val
                    else:
                        resolved[key] = val
                return resolved
            return {}

        count_sql = f"SELECT COUNT(*) AS total FROM master_records{where_sql}"
        cursor.execute(count_sql, params)
        count_res = cursor.fetchone()
        total_records = count_res["total"] if count_res else 0

        # Handle Excel / CSV / Base64 file export requests
        if output_format in ("excel", "xlsx", "csv", "base64", "b64", "excel_b64"):
            export_limit = min(total_records, 50000)
            query_sql = (
                f"SELECT * FROM master_records{where_sql} "
                f"ORDER BY {db_sort_col} {db_sort_dir} "
                f"LIMIT %s"
            )
            cursor.execute(query_sql, list(params) + [export_limit])
            export_rows = cursor.fetchall()

            clean_rows = []
            for r in export_rows:
                row_dict = dict(r)
                if isinstance(row_dict.get("created_at"), datetime):
                    row_dict["created_at"] = row_dict["created_at"].strftime("%Y-%m-%d %H:%M:%S")
                if isinstance(row_dict.get("updated_at"), datetime):
                    row_dict["updated_at"] = row_dict["updated_at"].strftime("%Y-%m-%d %H:%M:%S")

                resolved_cf = resolve_custom_fields(row_dict.get("custom_fields"))
                row_dict["custom_fields"] = json.dumps(resolved_cf) if resolved_cf else None
                clean_rows.append(row_dict)

            df = pd.DataFrame(clean_rows) if clean_rows else pd.DataFrame()
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

            log_action(
                g.api_user_id,
                f"[API] '{g.api_username}' exported master_records as {output_format}: count={len(clean_rows)}"
            )

            if output_format in ("base64", "b64", "excel_b64"):
                out_bytes = BytesIO()
                with pd.ExcelWriter(out_bytes, engine="openpyxl") as writer:
                    df.to_excel(writer, index=False, sheet_name="Filtered Records")
                out_bytes.seek(0)
                encoded = base64.b64encode(out_bytes.read()).decode("utf-8")
                filename = f"filtered_master_records_{timestamp}.xlsx"
                return jsonify({
                    "success": True,
                    "filename": filename,
                    "total_records": len(clean_rows),
                    "file_b64": encoded
                }), 200

            elif output_format in ("excel", "xlsx"):
                out_bytes = BytesIO()
                with pd.ExcelWriter(out_bytes, engine="openpyxl") as writer:
                    df.to_excel(writer, index=False, sheet_name="Filtered Records")
                out_bytes.seek(0)
                filename = f"filtered_master_records_{timestamp}.xlsx"
                return send_file(
                    out_bytes,
                    mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    as_attachment=True,
                    download_name=filename
                )
            elif output_format == "csv":
                out_bytes = BytesIO()
                df.to_csv(out_bytes, index=False, encoding="utf-8-sig")
                out_bytes.seek(0)
                filename = f"filtered_master_records_{timestamp}.csv"
                return send_file(
                    out_bytes,
                    mimetype="text/csv",
                    as_attachment=True,
                    download_name=filename
                )

        offset = (page - 1) * per_page
        total_pages = max(1, math.ceil(total_records / per_page)) if total_records > 0 else 0

        query_sql = (
            f"SELECT * FROM master_records{where_sql} "
            f"ORDER BY {db_sort_col} {db_sort_dir} "
            f"LIMIT %s OFFSET %s"
        )
        query_params = list(params) + [per_page, offset]
        cursor.execute(query_sql, query_params)
        rows = cursor.fetchall()

        serialised = []
        for row in rows:
            r = dict(row)
            if isinstance(r.get("created_at"), datetime):
                r["created_at"] = r["created_at"].isoformat()
            if isinstance(r.get("updated_at"), datetime):
                r["updated_at"] = r["updated_at"].isoformat()

            r["custom_fields"] = resolve_custom_fields(r.get("custom_fields"))
            serialised.append(r)

        log_action(
            g.api_user_id,
            f"[API] '{g.api_username}' queried master_records: page={page}, total={total_records}"
        )

        return jsonify({
            "success": True,
            "page": page,
            "per_page": per_page,
            "total_records": total_records,
            "total_pages": total_pages,
            "records": serialised,
            "filters_applied": applied_filters
        }), 200


    except Exception as e:
        return jsonify({"error": f"Database query error: {str(e)}"}), 500
    finally:
        conn.close()



# ── 21. GET /api/v1/client/export ──────────────────────────────────────────────

def _validate_client_api_key(required_type):
    """
    Helper function to validate client API keys passed via:
      - Header 'X-API-Key'
      - Header 'Authorization: Bearer <key>'
      - Query param '?api_key=...'
    """
    key_str = request.headers.get("X-API-Key", "").strip()
    if not key_str and request.headers.get("Authorization", "").startswith("Bearer "):
        key_str = request.headers.get("Authorization", "").split(" ", 1)[1].strip()
    if not key_str:
        key_str = request.args.get("api_key", "").strip()

    if not key_str:
        return None, _unauthorised("Missing API Key. Provide X-API-Key header or api_key parameter.")

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT k.*, u.username FROM client_api_keys k JOIN users u ON k.user_id = u.id WHERE k.api_key = %s", (key_str,))
        key_row = cursor.fetchone()
    finally:
        conn.close()

    if not key_row:
        return None, _unauthorised("Invalid API key.")
    if key_row.get("status") == "pending":
        return None, _forbidden("This API Key request is pending admin approval.")
    if key_row.get("status") == "rejected":
        return None, _forbidden("This API Key request was rejected by admin.")
    if not key_row.get("is_active"):
        return None, _forbidden("This API key is deactivated.")
    if key_row.get("key_type") != required_type:
        return None, _forbidden(f"This API key is configured for {key_row.get('key_type').upper()} operations, not {required_type.upper()}.")

    if key_row.get("expires_at"):
        exp_at = key_row["expires_at"]
        if isinstance(exp_at, str):
            try:
                exp_at = datetime.fromisoformat(exp_at)
            except Exception:
                exp_at = None
        if exp_at and datetime.now() > exp_at:
            exp_str = exp_at.strftime('%Y-%m-%d')
            return None, _forbidden(f"This API key has expired on {exp_str}.")

    return key_row, None




@api_bp.route("/v1/client/export", methods=["GET"])
@limiter.limit("300 per hour")
def api_client_export():
    """
    Export master database records using an approved Client Export API Key.
    Applies the admin-approved filters pre-configured for this key.
    """
    key_row, err_resp = _validate_client_api_key("export")
    if err_resp:
        return err_resp

    approved_filters = {}
    if key_row.get("filters_json"):
        try:
            approved_filters = json.loads(key_row["filters_json"])
        except Exception:
            approved_filters = {}

    params = dict(approved_filters)
    for k, v in request.args.items():
        if k not in ("api_key",):
            params[k] = v

    where_clauses = []
    sql_params = []

    field_mappings = {
        "country": "country",
        "industry": "industry",
        "status": "record_status",
        "company": "company_name",
        "city": "city",
        "state": "state_province",
        "imported_by": "imported_by"
    }

    for param, col in field_mappings.items():
        val = params.get(param)
        if val:
            where_clauses.append(f"{col} ILIKE %s")
            sql_params.append(f"%{val}%")

    if params.get("created_after"):
        where_clauses.append("created_at >= %s")
        sql_params.append(params["created_after"])
    if params.get("created_before"):
        where_clauses.append("created_at <= %s")
        sql_params.append(params["created_before"])

    if params.get("search") or params.get("q"):
        sq = params.get("search") or params.get("q")
        search_cols = ["first_name", "last_name", "email_address", "company_name", "city", "country", "industry"]
        search_clauses = [f"{c} ILIKE %s" for c in search_cols]
        where_clauses.append(f"({' OR '.join(search_clauses)})")
        sql_params.extend([f"%{sq}%"] * len(search_cols))

    where_sql = f" WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

    sort_col = params.get("sort_by", "id")
    sort_dir = "ASC" if str(params.get("sort_order", "desc")).lower() == "asc" else "DESC"

    output_format = (params.get("format") or params.get("export") or "json").lower()
    page = max(1, int(params.get("page", 1)))
    approved_max = key_row.get("max_rows_limit") or MAX_PAGE_SIZE
    per_page = max(1, min(int(params.get("per_page", approved_max)), approved_max))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("SELECT id, field_name FROM field_registry")
        reg_rows = cursor.fetchall() or []
        field_name_map = {str(r["id"]): r["field_name"] for r in reg_rows}

        def resolve_cf(raw_cf):
            if not raw_cf:
                return {}
            if isinstance(raw_cf, str):
                try:
                    raw_cf = json.loads(raw_cf)
                except Exception:
                    return {}
            if isinstance(raw_cf, dict):
                return {field_name_map.get(str(k), str(k)): v for k, v in raw_cf.items()}
            return {}

        count_sql = f"SELECT COUNT(*) AS total FROM master_records{where_sql}"
        cursor.execute(count_sql, sql_params)
        total_records = cursor.fetchone()["total"]

        if output_format in ("excel", "xlsx", "csv"):
            query_sql = f"SELECT * FROM master_records{where_sql} ORDER BY {sort_col} {sort_dir} LIMIT 50000"
            cursor.execute(query_sql, sql_params)
            rows = cursor.fetchall()

            clean_rows = []
            for r in rows:
                row_dict = dict(r)
                if isinstance(row_dict.get("created_at"), datetime):
                    row_dict["created_at"] = row_dict["created_at"].strftime("%Y-%m-%d %H:%M:%S")
                if isinstance(row_dict.get("updated_at"), datetime):
                    row_dict["updated_at"] = row_dict["updated_at"].strftime("%Y-%m-%d %H:%M:%S")
                rcf = resolve_cf(row_dict.get("custom_fields"))
                row_dict["custom_fields"] = json.dumps(rcf) if rcf else None
                clean_rows.append(row_dict)

            df = pd.DataFrame(clean_rows) if clean_rows else pd.DataFrame()
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

            log_action(key_row["user_id"], f"[API KEY] Client '{key_row['username']}' exported records via API Key '{key_row['key_name']}'")

            if output_format in ("excel", "xlsx"):
                out_bytes = BytesIO()
                with pd.ExcelWriter(out_bytes, engine="openpyxl") as writer:
                    df.to_excel(writer, index=False, sheet_name="Filtered Export")
                out_bytes.seek(0)
                return send_file(out_bytes, mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", as_attachment=True, download_name=f"client_export_{timestamp}.xlsx")
            else:
                out_bytes = BytesIO()
                df.to_csv(out_bytes, index=False, encoding="utf-8-sig")
                out_bytes.seek(0)
                return send_file(out_bytes, mimetype="text/csv", as_attachment=True, download_name=f"client_export_{timestamp}.csv")

        offset = (page - 1) * per_page
        total_pages = max(1, math.ceil(total_records / per_page)) if total_records > 0 else 0

        query_sql = f"SELECT * FROM master_records{where_sql} ORDER BY {sort_col} {sort_dir} LIMIT %s OFFSET %s"
        cursor.execute(query_sql, sql_params + [per_page, offset])
        rows = cursor.fetchall()

        serialised = []
        for r in rows:
            row_dict = dict(r)
            if isinstance(row_dict.get("created_at"), datetime):
                row_dict["created_at"] = row_dict["created_at"].isoformat()
            if isinstance(row_dict.get("updated_at"), datetime):
                row_dict["updated_at"] = row_dict["updated_at"].isoformat()
            row_dict["custom_fields"] = resolve_cf(row_dict.get("custom_fields"))
            serialised.append(row_dict)

        log_action(key_row["user_id"], f"[API KEY] Client '{key_row['username']}' queried export via API Key '{key_row['key_name']}' (count={len(rows)})")

        return jsonify({
            "success": True,
            "key_name": key_row["key_name"],
            "page": page,
            "per_page": per_page,
            "total_records": total_records,
            "total_pages": total_pages,
            "records": serialised,
            "applied_filters": params
        }), 200

    except Exception as e:
        return jsonify({"error": f"Database query error: {str(e)}"}), 500
    finally:
        conn.close()


# ── 22. POST /api/v1/client/import ─────────────────────────────────────────────

@api_bp.route("/v1/client/import", methods=["POST"])
@limiter.limit("60 per hour")
def api_client_import():
    """
    Import dataset records using an approved Client Import API Key.
    Accepts JSON array of objects or file upload.
    """
    key_row, err_resp = _validate_client_api_key("import")
    if err_resp:
        return err_resp

    records_data = []

    if request.is_json:
        payload = request.get_json()
        if isinstance(payload, list):
            records_data = payload
        elif isinstance(payload, dict) and "records" in payload:
            records_data = payload["records"]
        elif isinstance(payload, dict) and "file_b64" in payload:
            try:
                fb = base64.b64decode(payload["file_b64"])
                df = pd.read_excel(BytesIO(fb)) if payload.get("filename", "").endswith((".xls", ".xlsx")) else pd.read_csv(BytesIO(fb))
                records_data = df.to_dict(orient="records")
            except Exception as e:
                return jsonify({"error": f"Failed to parse Base64 file: {e}"}), 422
    elif request.files and "file" in request.files:
        try:
            up_file = request.files["file"]
            df = pd.read_excel(up_file) if up_file.filename.endswith((".xls", ".xlsx")) else pd.read_csv(up_file)
            records_data = df.to_dict(orient="records")
        except Exception as e:
            return jsonify({"error": f"Failed to parse uploaded file: {e}"}), 422
    else:
        return _bad_request("Provide a JSON array of records or file upload.")

    if not records_data:
        return _bad_request("No valid records found in payload.")

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("""
            INSERT INTO uploaded_files (user_id, filename, original_filename, uploaded_at, total_rows, rows_imported, status)
            VALUES (%s, %s, %s, NOW(), %s, %s, 'completed')
        """, (key_row["user_id"], f"api_import_{secrets.token_hex(4)}", f"API Import ({key_row['key_name']})", len(records_data), len(records_data)))
        conn.commit()
        file_id = cursor.lastrowid

        inserted_count = 0
        for rec in records_data:
            cursor.execute("""
                INSERT INTO master_records (file_id, first_name, last_name, email_address, primary_phone_number, company_name, job_title, department, city, state_province, country, industry, record_status, imported_by)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                file_id,
                rec.get("first_name") or rec.get("First Name"),
                rec.get("last_name") or rec.get("Last Name"),
                rec.get("email_address") or rec.get("email") or rec.get("Email"),
                rec.get("primary_phone_number") or rec.get("phone") or rec.get("Phone"),
                rec.get("company_name") or rec.get("company") or rec.get("Company"),
                rec.get("job_title") or rec.get("Job Title"),
                rec.get("department"),
                rec.get("city") or rec.get("City"),
                rec.get("state_province") or rec.get("state"),
                rec.get("country") or rec.get("Country"),
                rec.get("industry") or rec.get("Industry"),
                rec.get("record_status") or rec.get("status") or "active",
                key_row["username"]
            ))
            inserted_count += 1

        conn.commit()
        log_action(key_row["user_id"], f"[API KEY] Client '{key_row['username']}' imported {inserted_count} records via API Key '{key_row['key_name']}'")

        return jsonify({
            "success": True,
            "message": f"Successfully imported {inserted_count} records via API Key.",
            "file_id": file_id,
            "rows_imported": inserted_count,
            "status": "completed"
        }), 200

    except Exception as e:
        conn.rollback()
        return jsonify({"error": f"Import failed: {str(e)}"}), 500
    finally:
        conn.close()


# ── GET /api/health  (no auth required) ───────────────────────────────────────
@api_bp.route("/health", methods=["GET"])
def api_health():
    """Simple liveness check. No auth required. Returns 200 if the API is up."""
    return jsonify({"status": "ok"}), 200

