"""
helpers.py  –  Shared helper functions for app.py and api_routes.py
"""

import os
import re
import secrets
import json
from datetime import datetime, timedelta
from functools import wraps

import bcrypt
import mysql.connector
import pandas as pd
from flask import session, redirect, url_for, flash, request, jsonify, g
import logging
_logger=logging.getLogger(__name__)

MAX_PAGE_SIZE = 100

INACTIVITY_LIMIT = timedelta(minutes=60)


# ── Database ──────────────────────────────────────────────────────────────────

def get_db_connection():
    return mysql.connector.connect(
        host="127.0.0.1",
        user="excel_cleaner_app",
        password="excelapppass",
        database="excel_cleaner_db",
        auth_plugin="mysql_native_password"
    )


# ── Logging ───────────────────────────────────────────────────────────────────

def log_action(user_id, action, total=0, valid=0, invalid=0, removed=0,
               rules_applied=None, rule_counts=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO logs (user_id, action, total_rows, valid_rows, invalid_rows, removed_rows,
                          rules_applied, rule_counts)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    """, (
        user_id, action, total, valid, invalid, removed,
        json.dumps(rules_applied) if rules_applied else None,
        json.dumps(rule_counts)   if rule_counts   else None,
    ))
    conn.commit()
    conn.close()


# ── RBAC helpers ──────────────────────────────────────────────────────────────

def get_visible_user_ids(cursor, role=None, user_id=None):
    """Returns the list of user IDs the caller is permitted to see. 
    Uses the manager_id column for true hierarcy-based filering
    
    Admin -> everyone
    Manager -> their direct team_leads (manager_id = self) + all users under those team_leads
    Team Lead -> only users under manager_id = self
    User/None -> only themselves
    """
    if role is None:
        role = session.get("role")
    if user_id is None:
        user_id = session.get("user_id")

    if role == "admin":
        cursor.execute("SELECT id FROM users")
        return [row["id"] for row in cursor.fetchall()]
    elif role == "manager":
        #Step 1: get team leads directly under this manager
        cursor.execute("SELECT id FROM users WHERE manager_id = %s AND role = 'team_lead'", (user_id,)
                       )
        tl_ids = [row["id"] for row in cursor.fetchall()]

        #Step 2: get users under those team leads
        visible = list(tl_ids)
        if tl_ids:
            placeholders=", ".join(["%s"]*len(tl_ids))
            cursor.execute(f"SELECT id FROM users WHERE manager_id IN ({placeholders}) AND role = 'user'", tl_ids)
            visible += [row["id"] for row in cursor.fetchall()]
        return visible
    

    elif role == "team_lead":
        cursor.execute("SELECT id FROM users WHERE manager_id = %s AND role = 'user'", (user_id,)
                       )
        return [row["id"] for row in cursor.fetchall()]
    else:
        return [user_id] if user_id else []
    
def load_permissions_from_db(role_name):
    """Fetch the set of permission names for a given role from the DB.
    Returns a set of strings e.g. {'upload_file', 'view_own_logs', ...}
    """
    conn= get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
                   SELECT p.name FROM permissions p 
                   JOIN role_permissions rp ON p.id = rp.permission_id
                   JOIN roles r ON rp.role_id = r.id
                   WHERE r.name = %s
                   """, (role_name,))
    rows = cursor.fetchall()
    conn.close()
    return {row["name"] for row in rows}


def _table_exists(cursor, table_name):
    try:
        cursor.execute("SHOW TABLES LIKE %s", (table_name,))
        return cursor.fetchone() is not None
    except Exception:
        return False


def fetch_visible_logs(cursor, *, search=None, from_date=None, to_date=None,
                       log_type=None, page=1, per_page=10, role=None, user_id=None):
    visible_user_ids = get_visible_user_ids(cursor, role=role, user_id=user_id)
    if not visible_user_ids:
        return [], 0

    log_type = (log_type or "").strip().lower()
    offset = (page - 1) * per_page
    placeholders = ",".join(["%s"] * len(visible_user_ids))

    if log_type == "search":
        try:
            if _table_exists(cursor, "search_logs"):
                count_query = """
                    SELECT COUNT(*) AS count
                    FROM search_logs
                    WHERE user_id IN ({placeholders})
                """.format(placeholders=placeholders)
                count_params = list(visible_user_ids)

                if search:
                    search_pattern = f"%{search}%"
                    count_query += " AND (username LIKE %s OR search_term LIKE %s)"
                    count_params.extend([search_pattern, search_pattern])
                if from_date:
                    count_query += " AND DATE(searched_at) >= %s"
                    count_params.append(from_date)
                if to_date:
                    count_query += " AND DATE(searched_at) <= %s"
                    count_params.append(to_date)

                cursor.execute(count_query, count_params)
                total_logs = cursor.fetchone()["count"]

                data_query = """
                    SELECT id, user_id, username, search_term AS action, searched_at AS created_at
                    FROM search_logs
                    WHERE user_id IN ({placeholders})
                """.format(placeholders=placeholders)
                data_params = list(visible_user_ids)

                if search:
                    data_query += " AND (username LIKE %s OR search_term LIKE %s)"
                    data_params.extend([search_pattern, search_pattern])
                if from_date:
                    data_query += " AND DATE(searched_at) >= %s"
                    data_params.append(from_date)
                if to_date:
                    data_query += " AND DATE(searched_at) <= %s"
                    data_params.append(to_date)

                data_query += " ORDER BY searched_at DESC LIMIT %s OFFSET %s"
                data_params.extend([per_page, offset])

                cursor.execute(data_query, data_params)
                return cursor.fetchall(), total_logs
        except Exception as exc:
            _logger.warning("Search log query failed, falling back to logs table: %s", exc)

        count_query = f"""
            SELECT COUNT(*) AS count
            FROM logs
            JOIN users ON logs.user_id = users.id
            WHERE logs.user_id IN ({placeholders})
              AND logs.action LIKE %s
        """
        count_params = list(visible_user_ids) + ["Searched:%"]

        if search:
            search_pattern = f"%{search}%"
            count_query += " AND (users.username LIKE %s OR logs.action LIKE %s)"
            count_params.extend([search_pattern, search_pattern])
        if from_date:
            count_query += " AND DATE(logs.created_at) >= %s"
            count_params.append(from_date)
        if to_date:
            count_query += " AND DATE(logs.created_at) <= %s"
            count_params.append(to_date)

        cursor.execute(count_query, count_params)
        total_logs = cursor.fetchone()["count"]

        data_query = f"""
            SELECT logs.id, logs.user_id, users.username, logs.action, logs.created_at
            FROM logs
            JOIN users ON logs.user_id = users.id
            WHERE logs.user_id IN ({placeholders})
              AND logs.action LIKE %s
        """
        data_params = list(visible_user_ids) + ["Searched:%"]

        if search:
            data_query += " AND (users.username LIKE %s OR logs.action LIKE %s)"
            data_params.extend([search_pattern, search_pattern])
        if from_date:
            data_query += " AND DATE(logs.created_at) >= %s"
            data_params.append(from_date)
        if to_date:
            data_query += " AND DATE(logs.created_at) <= %s"
            data_params.append(to_date)

        data_query += " ORDER BY logs.created_at DESC LIMIT %s OFFSET %s"
        data_params.extend([per_page, offset])

        cursor.execute(data_query, data_params)
        return cursor.fetchall(), total_logs

    count_query = f"""
        SELECT COUNT(*) AS count
        FROM logs
        JOIN users ON logs.user_id = users.id
        WHERE logs.user_id IN ({placeholders})
    """
    count_params = list(visible_user_ids)

    if search:
        search_pattern = f"%{search}%"
        count_query += " AND (users.username LIKE %s OR logs.action LIKE %s)"
        count_params.extend([search_pattern, search_pattern])
    if log_type == "login":
        count_query += " AND ("
        count_query += " logs.action LIKE %s OR logs.action LIKE %s OR logs.action LIKE %s OR logs.action LIKE %s"
        count_params.extend([
            "%Logged in%",
            "%Logged out%",
            "%Failed login%",
            "%Session expired%",
        ])
        count_query += " )"
    elif log_type == "cleaning":
        count_query += " AND ("
        count_query += " logs.action LIKE %s OR logs.action LIKE %s OR logs.action LIKE %s OR logs.action LIKE %s OR logs.action LIKE %s OR logs.action LIKE %s"
        count_params.extend([
            "%Uploaded file%",
            "%Cleaned file%",
            "%Downloaded file%",
            "%Removed file%",
            "%Saved preset%",
            "%Loaded preset%",
        ])
        count_query += " )"
    if from_date:
        count_query += " AND DATE(logs.created_at) >= %s"
        count_params.append(from_date)
    if to_date:
        count_query += " AND DATE(logs.created_at) <= %s"
        count_params.append(to_date)

    cursor.execute(count_query, count_params)
    total_logs = cursor.fetchone()["count"]

    data_query = f"""
        SELECT logs.*, users.username
        FROM logs
        JOIN users ON logs.user_id = users.id
        WHERE logs.user_id IN ({placeholders})
    """
    data_params = list(visible_user_ids)

    if search:
        data_query += " AND (users.username LIKE %s OR logs.action LIKE %s)"
        data_params.extend([search_pattern, search_pattern])
    if log_type == "login":
        data_query += " AND ("
        data_query += " logs.action LIKE %s OR logs.action LIKE %s OR logs.action LIKE %s OR logs.action LIKE %s"
        data_params.extend([
            "%Logged in%",
            "%Logged out%",
            "%Failed login%",
            "%Session expired%",
        ])
        data_query += " )"
    elif log_type == "cleaning":
        data_query += " AND ("
        data_query += " logs.action LIKE %s OR logs.action LIKE %s OR logs.action LIKE %s OR logs.action LIKE %s OR logs.action LIKE %s OR logs.action LIKE %s"
        data_params.extend([
            "%Uploaded file%",
            "%Cleaned file%",
            "%Downloaded file%",
            "%Removed file%",
            "%Saved preset%",
            "%Loaded preset%",
        ])
        data_query += " )"
    if from_date:
        data_query += " AND DATE(logs.created_at) >= %s"
        data_params.append(from_date)
    if to_date:
        data_query += " AND DATE(logs.created_at) <= %s"
        data_params.append(to_date)

    data_query += " ORDER BY logs.created_at DESC LIMIT %s OFFSET %s"
    data_params.extend([per_page, offset])

    cursor.execute(data_query, data_params)
    logs = cursor.fetchall()
    return logs, total_logs


# ── Misc helpers ──────────────────────────────────────────────────────────────

def detect_identifier_columns(df):
    identifier_keywords = [
        "id", "user_id", "customer_id", "employee_id",
        "account_id", "serial", "serial_no", "s_no", "sno", "record_id", "s.no"
    ]
    detected = []
    for column in df.columns:
        col_lower = column.lower().replace(" ", "_")
        for keyword in identifier_keywords:
            if keyword in col_lower:
                detected.append(column)
                break
    return detected


def cleanup_old_session_files():
    old_files = [
        session.get("cleaned_file"),
        session.get("invalid_file"),
        session.get("removed_file")
    ]
    for file in old_files:
        if file and os.path.exists(file):
            try:
                os.remove(file)
            except Exception:
                pass


def validate_password(password):
    errors = []
    if len(password) < 8 or len(password) > 64:
        errors.append("Password must be between 8 and 64 characters long")
    if " " in password:
        errors.append("Password must not contain spaces")
    if not re.search(r"[A-Z]", password):
        errors.append("Password must contain at least one uppercase letter")
    if not re.search(r"[a-z]", password):
        errors.append("Password must contain at least one lowercase letter")
    if not re.search(r"[0-9]", password):
        errors.append("Password must contain at least one number")
    if not re.search(r"[^A-Za-z0-9]", password):
        errors.append("Password must contain at least one special character")
    return errors


# ── Browser session decorator ─────────────────────────────────────────────────

def login_required(role=None):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("login"))

            if "last_active" not in session:
                session["last_active"] = datetime.utcnow().isoformat()

            if "last_active" in session:
                last_active = datetime.fromisoformat(session["last_active"])
                if datetime.utcnow() - last_active > INACTIVITY_LIMIT:
                    from flask import request as _req
                    if _req.endpoint != "logout":
                        flash("Your session expired due to inactivity. Please log in again.", "warning")
                        log_action(session["user_id"], "Session expired due to inactivity")
                    session.pop("user_id", None)
                    session.pop("role", None)
                    session.pop("last_active", None)
                    return redirect(url_for("login"))

            session["last_active"] = datetime.utcnow().isoformat()

            if role and session.get("role") != role:
                flash("Unauthorized access.", "danger")
                return redirect(url_for("login"))

            return f(*args, **kwargs)
        return wrapper
    return decorator


# ── API token functions ───────────────────────────────────────────────────────

def generate_api_token(user_id, expires_hours=24):
    """
    Generate a secure random token, store it in api_tokens, return
    (token_string, expires_at_datetime).
    """
    import hashlib
    token      = secrets.token_hex(32)   # raw 64-char hex string
    token_hash = hashlib.sha256(token.encode()).hexdigest() #stored in db
    expires_at = datetime.utcnow() + timedelta(hours=expires_hours)

    conn   = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO api_tokens (user_id, token, expires_at)
        VALUES (%s, %s, %s)
    """, (user_id, token_hash, expires_at))
    
    conn.commit()
    conn.close()

    return token, expires_at #return raw token to caller - never stored again


def resolve_token(token_str):
    """
    Validate a Bearer token. Returns user info dict if valid, None otherwise.
    Checks: exists, token is_active, user is_active, not expired.
    """
    import hashlib
    token_hash = hashlib.sha256(token_str.encode()).hexdigest()

    conn   = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT t.id AS token_id, t.user_id, t.expires_at,
               t.is_active  AS token_active,
               u.role,
               u.is_active  AS user_active,
               u.username, u.manager_id
        FROM api_tokens t
        JOIN users u ON t.user_id = u.id
        WHERE t.token = %s
    """, (token_hash,))
    
    row = cursor.fetchone()
    conn.close()

    if not row:                   return None
    if not row["token_active"]:   return None
    if not row["user_active"]:    return None
    if datetime.utcnow() > row["expires_at"]: return None

    return row


def revoke_api_token(token_str):
    """Mark a token inactive so it can no longer be used."""
    import hashlib
    token_hash = hashlib.sha256(token_str.encode()).hexdigest()

    conn   = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE api_tokens SET is_active = 0 WHERE token = %s",
        (token_hash,)
    )
    conn.commit()
    conn.close()


def refresh_api_token(token_str, extends_hours=24):
    """
    Extend an existing valid token's expiry by `extends_hours` from now.
    Returns new expires_at datetime if successful, None if token not found/inactive.
    Does NOT issue a new token string — same token, new expiry.
    """
    import hashlib
    token_hash = hashlib.sha256(token_str.encode()).hexdigest()

    conn   = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        "SELECT id, is_active, expires_at FROM api_tokens WHERE token = %s",
        (token_hash,)
    )
    row = cursor.fetchone()

    if not row or not row["is_active"]:
        conn.close()
        return None

    new_expiry = datetime.utcnow() + timedelta(hours=extends_hours)
    cursor.execute(
        "UPDATE api_tokens SET expires_at = %s WHERE token = %s",
        (new_expiry, token_hash)
    )
    conn.commit()
    conn.close()
    return new_expiry


# ── Login rate limiting ───────────────────────────────────────────────────────

def check_login_rate_limit(username):
    """
    Returns (is_blocked, minutes_remaining).
    Blocks after 5 failed attempts within any rolling 10-minute window.
    """
    import math
    conn   = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # We use the database's own time for the interval check
    cursor.execute("""
        SELECT COUNT(*) AS fails, MIN(attempted_at) AS first_fail
        FROM login_attempts
        WHERE username = %s
          AND success  = 0
          AND attempted_at > NOW() - INTERVAL 10 MINUTE
    """, (username,))
    row = cursor.fetchone()
    conn.close()

    if row["fails"] >= 5:
        first_fail = row["first_fail"]
        
        # FIX: Ensure we are comparing the same "type" of time.
        # If your MySQL is set to a specific timezone, first_fail comes back aware.
        # We strip tzinfo to compare against a naive 'now'.
        if first_fail and hasattr(first_fail, "tzinfo") and first_fail.tzinfo is not None:
            first_fail = first_fail.replace(tzinfo=None)
            
        # Use datetime.now() instead of utcnow() if your DB is following system local time
        # or stick to utcnow() but ensure the logic is consistent.
        unblock_at = first_fail + timedelta(minutes=10)
        now = datetime.now() # Match the likely local/server time of the DB
        
        diff = (unblock_at - now).total_seconds()
        remaining = math.ceil(diff / 60)
        
        return True, max(remaining, 1)
    
    return False, 0

def clear_login_attempts(username):
    """Deletes failed login attempts for a user (used after password reset)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "DELETE FROM login_attempts WHERE username = %s",
        (username,)
    )
    conn.commit()
    conn.close()

def record_login_attempt(username, success):
    """Insert one row into login_attempts."""
    conn   = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO login_attempts (username, success) VALUES (%s, %s)",
        (username, 1 if success else 0)
    )
    conn.commit()
    conn.close()


# ── API token decorator ───────────────────────────────────────────────────────

def api_login_required(f):
    """
    Decorator for API routes. Validates the Bearer token in the
    Authorization header and populates Flask's g with:
        g.api_user_id, g.api_role, g.api_username
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")

        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid Authorization header. "
                                     "Expected: Authorization: Bearer <token>"}), 401

        token_str = auth_header.split(" ", 1)[1].strip()
        user      = resolve_token(token_str)

        if not user:
            return jsonify({"error": "Invalid or expired token"}), 401

        g.api_user_id  = user["user_id"]
        g.api_role     = user["role"]
        g.api_username = user["username"]
        g.api_manager_id = user.get("manager_id")

        return f(*args, **kwargs)
    return decorated


# ── API cleaning_jobs state (replaces _api_state dict) ─────────────────────────────────────────────

def get_job_state(user_id):
    """Load the current API job state for this user from the DB."""
    import json as _json
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM cleaning_jobs WHERE user_id = %s", (user_id,))
    row = cursor.fetchone()
    conn.close()
    return row or {}

def set_job_state(user_id, **fields):
    """
    Upsert job state for this user. Pass keyboard args for any fields to update.
    Valid fields: temp_file, uploaded_file, cleaned_file, invalid_file, removed_file, rules_json
    """

    import json as _json

    #Serialise any list/dict values
    for k, v in fields.items():
        if isinstance(v, (list, dict)):
            fields[k] = _json.dumps(v)

    col_names = ", ".join(fields.keys())
    placeholders = ", ".join(["%s"]*len(fields))
    updates = ", ".join(f"{k} = VALUES({k})" for k in fields.keys())
    values =  list(fields.values())

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        f"""INSERT INTO cleaning_jobs (user_id, {col_names})
        VALUES (%s, {placeholders})
        ON DUPLICATE KEY UPDATE {updates}""",
        [user_id] + values
    )
    conn.commit()
    conn.close()


def clear_job_files(user_id):
    """Delete the output files on disk for this user's last job."""
    state = get_job_state(user_id)
    for key in ("clened_file", "invalid_file", "removed_file"):
        filepath = state.get(key)
        if filepath and os.path.exists(filepath):
            try:
                os.remove(filepath)
            except Exception:
                pass

def log_search(user_id, username, search_term):
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        if _table_exists(cursor, "search_logs"):
            cursor.execute("""
                INSERT INTO search_logs
                (user_id, username, search_term)
                VALUES (%s, %s, %s)
            """, (user_id, username, search_term))
        else:
            cursor.execute("""
                INSERT INTO logs (user_id, action)
                VALUES (%s, %s)
            """, (user_id, f"Searched: {search_term}"))

        conn.commit()
    except Exception as exc:
        _logger.warning("Unable to record search activity for user %s: %s", user_id, exc)
    finally:
        if conn is not None:
            conn.close()

# ── Hybrid Database Ingestion ──────────────────────────────────────────────────

MASTER_COLUMNS = {
    'full_name', 'email_address', 'primary_phone_number', 'alternate_phone_number',
    'company_name', 'job_title', 'department', 'website_url', 'address_line_1', 'address_line_2',
    'city', 'state_province', 'postal_zip_code', 'country', 'linkedin_profile_url', 'industry',
    'lead_source', 'record_status', 'date_of_birth', 'gender', 'company_size', 'annual_revenue',
    'imported_by'
}

def normalize_header(header_name):
    name = str(header_name).strip().lower()
    name = re.sub(r'[^a-z0-9\s_\-]', '', name)
    name = re.sub(r'[\s_\-]+', '_', name)
    return name.strip('_')

def ingest_uploaded_file(file_id, file_path, username):
    import pandas as pd
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        # Read file headers
        if file_path.endswith('.csv'):
            try:
                df = pd.read_csv(file_path)
            except Exception:
                df = pd.read_csv(file_path, sep=None, engine='python')
        else:
            df = pd.read_excel(file_path)
            
        headers = df.columns.tolist()
        if not headers:
            return
            
        # 1. Fetch existing aliases & registry fields
        cursor.execute("SELECT alias, target_type, target_identifier FROM field_aliases")
        aliases = {row['alias'].strip().lower().replace(" ", "_"): row for row in cursor.fetchall()}
        
        cursor.execute("SELECT id, normalized_name FROM field_registry")
        registry = {row['normalized_name']: row['id'] for row in cursor.fetchall()}
        
        header_mapping = {}
        for header in headers:
            norm = normalize_header(header)
            if not norm:
                continue
                
            # Check 1: Direct Master Column match
            if norm in MASTER_COLUMNS:
                header_mapping[header] = {'type': 'master', 'target': norm}
                continue
                
            # Check 2: Match aliases
            if norm in aliases:
                alias = aliases[norm]
                header_mapping[header] = {
                    'type': alias['target_type'],
                    'target': alias['target_identifier']
                }
                if alias['target_type'] == 'custom':
                    cursor.execute(
                        "UPDATE field_registry SET usage_count = usage_count + 1 WHERE id = %s",
                        (int(alias['target_identifier']),)
                    )
                continue
                
            # Check 3: Check Registry
            if norm in registry:
                reg_id = registry[norm]
                header_mapping[header] = {'type': 'custom', 'target': str(reg_id)}
                cursor.execute(
                    "UPDATE field_registry SET usage_count = usage_count + 1 WHERE id = %s",
                    (reg_id,)
                )
                continue
                
            # Check 4: Create new registry field
            cursor.execute(
                "INSERT INTO field_registry (field_name, normalized_name, data_type, usage_count) VALUES (%s, %s, %s, %s)",
                (header, norm, 'VARCHAR', 1)
            )
            new_id = cursor.lastrowid
            registry[norm] = new_id
            header_mapping[header] = {'type': 'custom', 'target': str(new_id)}
            
        conn.commit()
        
        # 2. Ingest Rows
        records_to_insert = []
        for _, row in df.iterrows():
            record_dict = {
                'file_id': file_id,
                'full_name': None,
                'email_address': None,
                'primary_phone_number': None,
                'alternate_phone_number': None,
                'company_name': None,
                'job_title': None,
                'department': None,
                'website_url': None,
                'address_line_1': None,
                'address_line_2': None,
                'city': None,
                'state_province': None,
                'postal_zip_code': None,
                'country': None,
                'linkedin_profile_url': None,
                'industry': None,
                'lead_source': None,
                'record_status': None,
                'date_of_birth': None,
                'gender': None,
                'company_size': None,
                'annual_revenue': None,
                'imported_by': username,
                'custom_fields': {}
            }
            
            for header, val in row.items():
                if header not in header_mapping:
                    continue
                    
                if pd.isnull(val) or str(val).strip().lower() in ('nan', 'nat', 'null'):
                    cleaned_val = None
                else:
                    cleaned_val = val
                    
                if cleaned_val is None:
                    continue
                    
                mapping = header_mapping[header]
                if mapping['type'] == 'master':
                    record_dict[mapping['target']] = str(cleaned_val)
                else:
                    record_dict['custom_fields'][mapping['target']] = str(cleaned_val)
                    
            if record_dict['custom_fields']:
                record_dict['custom_fields'] = json.dumps(record_dict['custom_fields'])
            else:
                record_dict['custom_fields'] = None
                
            records_to_insert.append(record_dict)
            
        # Bulk insert records
        if records_to_insert:
            columns_list = [
                'file_id', 'full_name', 'email_address', 'primary_phone_number', 'alternate_phone_number',
                'company_name', 'job_title', 'department', 'website_url', 'address_line_1', 'address_line_2',
                'city', 'state_province', 'postal_zip_code', 'country', 'linkedin_profile_url', 'industry',
                'lead_source', 'record_status', 'date_of_birth', 'gender', 'company_size', 'annual_revenue',
                'imported_by', 'custom_fields'
            ]
            insert_query = f"""
                INSERT INTO master_records ({', '.join(columns_list)})
                VALUES ({', '.join(['%s'] * len(columns_list))})
            """
            
            insert_data = [
                tuple(r[col] for col in columns_list)
                for r in records_to_insert
            ]
            
            cursor.executemany(insert_query, insert_data)
            
            # Update file status and row count
            cursor.execute(
                "UPDATE uploaded_files SET total_rows = %s, status = 'completed' WHERE id = %s",
                (len(records_to_insert), file_id)
            )
            conn.commit()
            
    except Exception as e:
        conn.rollback()
        try:
            cursor.execute("UPDATE uploaded_files SET status = 'failed' WHERE id = %s", (file_id,))
            conn.commit()
        except Exception:
            pass
        _logger.exception("Error ingesting file ID %s:", file_id)
        raise e
    finally:
        cursor.close()
        conn.close()

def ingest_uploaded_file_with_mapping(file_id, file_path, username, mapping_config):
    """
    Ingests spreadsheet data based on user-configured column mapping layout.
    Also rejects duplicate rows where every mapped value matches an existing database entry.
    """
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        # 1. Read Excel/CSV file
        if file_path.endswith('.csv'):
            try:
                df = pd.read_csv(file_path)
            except Exception:
                df = pd.read_csv(file_path, sep=None, engine='python')
        else:
            df = pd.read_excel(file_path)
            
        headers = df.columns.tolist()
        if not headers:
            cursor.execute("UPDATE uploaded_files SET status = 'failed' WHERE id = %s", (file_id,))
            conn.commit()
            return
            
        # 2. Handle dynamic dynamic creation of new custom fields
        final_mapping = {}
        for header, target in mapping_config.items():
            if target == 'create_new':
                norm = normalize_header(header)
                # Check if it already exists in the registry
                cursor.execute("SELECT id FROM field_registry WHERE normalized_name = %s", (norm,))
                reg_row = cursor.fetchone()
                if reg_row:
                    final_mapping[header] = f"custom:{reg_row['id']}"
                else:
                    cursor.execute(
                        "INSERT INTO field_registry (field_name, normalized_name, data_type, usage_count) VALUES (%s, %s, %s, %s)",
                        (header, norm, 'VARCHAR', 1)
                    )
                    new_id = cursor.lastrowid
                    final_mapping[header] = f"custom:{new_id}"
            elif target == 'ignore' or not target:
                continue
            else:
                final_mapping[header] = target
                
        # 3. Process Rows and Check for Duplicates
        records_to_insert = []
        rejected_count = 0
        seen_in_batch = set()
        
        # Get list of all columns in master_records dynamically to ensure safety
        cursor.execute("DESCRIBE master_records")
        all_db_columns = [row['Field'] for row in cursor.fetchall()]
        
        for _, row in df.iterrows():
            record_dict = {
                'file_id': file_id,
                'imported_by': username,
                'custom_fields': {}
            }
            # Initialize all other DB columns to None
            for col in all_db_columns:
                if col not in ('id', 'file_id', 'custom_fields', 'created_at', 'updated_at', 'imported_by'):
                    record_dict[col] = None
                    
            has_any_value = False
            for header, val in row.items():
                if header not in final_mapping:
                    continue
                    
                if pd.isnull(val) or str(val).strip().lower() in ('nan', 'nat', 'null'):
                    cleaned_val = None
                else:
                    cleaned_val = str(val).strip()
                    
                if cleaned_val is None:
                    continue
                    
                has_any_value = True
                target = final_mapping[header]
                if target.startswith("master:"):
                    col_name = target.split("master:")[1]
                    if col_name in record_dict:
                        record_dict[col_name] = cleaned_val
                elif target.startswith("custom:"):
                    field_id = target.split("custom:")[1]
                    record_dict['custom_fields'][field_id] = cleaned_val
                    
            if not has_any_value:
                continue # Skip completely empty row
                
            # Perform Duplicate Check: if row master column and custom field value totally match, then reject them
            dup_query = ["1=1"]
            dup_params = []
            
            for header, target in final_mapping.items():
                if target.startswith("master:"):
                    col_name = target.split("master:")[1]
                    if col_name in record_dict:
                        val = record_dict[col_name]
                        if val is not None:
                            dup_query.append(f"TRIM(LOWER(`{col_name}`)) = TRIM(LOWER(%s))")
                            dup_params.append(val)
                        else:
                            dup_query.append(f"(`{col_name}` IS NULL OR `{col_name}` = '')")
                elif target.startswith("custom:"):
                    field_id = target.split("custom:")[1]
                    val = record_dict['custom_fields'].get(field_id)
                    if val is not None:
                        dup_query.append("TRIM(LOWER(JSON_UNQUOTE(JSON_EXTRACT(custom_fields, %s)))) = TRIM(LOWER(%s))")
                        dup_params.append(f"$.\"{field_id}\"")
                        dup_params.append(val)
                    else:
                        dup_query.append("(custom_fields IS NULL OR JSON_EXTRACT(custom_fields, %s) IS NULL OR JSON_UNQUOTE(JSON_EXTRACT(custom_fields, %s)) = '')")
                        dup_params.append(f"$.\"{field_id}\"")
                        dup_params.append(f"$.\"{field_id}\"")
                        
            # Check in-memory duplicates for the current ingestion batch
            seen_tuple_list = []
            for h, t in sorted(final_mapping.items()):
                if t.startswith("master:"):
                    col_name = t.split("master:")[1]
                    v = record_dict.get(col_name)
                    seen_tuple_list.append((t, v.strip().lower() if v else ""))
                elif t.startswith("custom:"):
                    field_id = t.split("custom:")[1]
                    v = record_dict['custom_fields'].get(field_id)
                    seen_tuple_list.append((t, v.strip().lower() if v else ""))
            seen_tuple = tuple(seen_tuple_list)
            
            is_dup = False
            if seen_tuple in seen_in_batch:
                is_dup = True
            else:
                cursor.execute(f"SELECT COUNT(*) as count FROM master_records WHERE {' AND '.join(dup_query)}", dup_params)
                dup_row = cursor.fetchone()
                if dup_row and dup_row['count'] > 0:
                    is_dup = True
                    
            if is_dup:
                rejected_count += 1
                # Save duplicate records to rejected_records table for subsequent history review
                row_json = json.dumps(record_dict)
                cursor.execute(
                    "INSERT INTO rejected_records (file_id, row_data) VALUES (%s, %s)",
                    (file_id, row_json)
                )
            else:
                records_to_insert.append(record_dict)
                seen_in_batch.add(seen_tuple)
                
        # 4. Insert dynamic inserts
        if records_to_insert:
            # We construct a dynamic insert query for whichever columns are in all_db_columns
            cols_to_insert = [c for c in all_db_columns if c not in ('id', 'created_at', 'updated_at')]
            
            insert_query = f"""
                INSERT INTO master_records ({', '.join([f'`{c}`' for c in cols_to_insert])})
                VALUES ({', '.join(['%s'] * len(cols_to_insert))})
            """
            
            insert_data = []
            for r in records_to_insert:
                row_tuple = []
                for col in cols_to_insert:
                    if col == 'custom_fields':
                        # Convert dict to JSON string or None
                        row_tuple.append(json.dumps(r['custom_fields']) if r['custom_fields'] else None)
                    else:
                        row_tuple.append(r.get(col))
                insert_data.append(tuple(row_tuple))
                
            cursor.executemany(insert_query, insert_data)
            
            # Increment usage counts for custom fields
            for header, target in final_mapping.items():
                if target.startswith("custom:"):
                    fid = int(target.split("custom:")[1])
                    cursor.execute("UPDATE field_registry SET usage_count = usage_count + 1 WHERE id = %s", (fid,))
                    
        # Update uploaded_files table stats
        cursor.execute(
            "UPDATE uploaded_files SET total_rows = %s, rows_imported = %s, rows_rejected = %s, status = 'completed' WHERE id = %s",
            (len(df), len(records_to_insert), rejected_count, file_id)
        )
        conn.commit()
        
        # Log the completed ingestion action
        cursor.execute("SELECT user_id, original_filename FROM uploaded_files WHERE id = %s", (file_id,))
        u_info = cursor.fetchone()
        if u_info:
            log_action(
                u_info['user_id'],
                f"Ingested spreadsheet: {u_info['original_filename']}",
                total=len(df),
                valid=len(records_to_insert),
                removed=rejected_count
            )
        
    except Exception as e:
        conn.rollback()
        try:
            cursor.execute("UPDATE uploaded_files SET status = 'failed' WHERE id = %s", (file_id,))
            conn.commit()
        except Exception:
            pass
        _logger.exception("Error ingesting file ID %s:", file_id)
        raise e
    finally:
        cursor.close()
        conn.close()