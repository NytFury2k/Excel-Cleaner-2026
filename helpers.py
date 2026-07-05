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
import psycopg2
import psycopg2.extras
from dotenv import load_dotenv
from flask import session, redirect, url_for, flash, request, jsonify, g
import logging

# Explicitly load .env file using its absolute path relative to helpers.py
load_dotenv(os.path.join(os.path.dirname(__file__), ".env"), override=True)

_logger=logging.getLogger(__name__)

MAX_PAGE_SIZE = 100

INACTIVITY_LIMIT = timedelta(minutes=60)


# ── Database ──────────────────────────────────────────────────────────────────

class PostgresCursorWrapper:
    def __init__(self, cursor):
        self._cursor = cursor

    def execute(self, query, params=None):
        self._cursor.execute(query, params)

    def fetchone(self):
        return self._cursor.fetchone()

    def fetchall(self):
        return self._cursor.fetchall()

    @property
    def rowcount(self):
        return self._cursor.rowcount

    @property
    def description(self):
        return self._cursor.description

    @property
    def lastrowid(self):
        raise NotImplementedError("Postgres uses RETURNING id instead of lastrowid.")

    def close(self):
        self._cursor.close()

    def __iter__(self):
        return iter(self._cursor)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

from psycopg2.pool import ThreadedConnectionPool

_db_pool = None

def init_pool():
    global _db_pool
    if _db_pool is None:
        db_uri = os.getenv("DATABASE_URL")
        if not db_uri:
            db_uri = "postgresql://postgres:excelapppass@localhost:5432/excel_cleaner_db"
        # Minimum 2 connections, maximum 20 connections in the pool
        _db_pool = ThreadedConnectionPool(2, 20, dsn=db_uri)

class PostgresConnectionWrapper:
    def __init__(self, conn, pool=None):
        self._conn = conn
        self._pool = pool

    def cursor(self, dictionary=False):
        if dictionary:
            return PostgresCursorWrapper(self._conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor))
        return PostgresCursorWrapper(self._conn.cursor())

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        if self._pool:
            # Check if connection was closed or broken, if so discard from pool
            try:
                if self._conn.closed != 0:
                    self._pool.putconn(self._conn, close=True)
                else:
                    self._pool.putconn(self._conn)
            except Exception:
                try:
                    self._pool.putconn(self._conn, close=True)
                except Exception:
                    pass
        else:
            self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

def get_db_connection():
    init_pool()
    max_retries = 3
    for _ in range(max_retries):
        try:
            conn = _db_pool.getconn()
            # Verify connection is still open
            if conn.closed == 0:
                return PostgresConnectionWrapper(conn, pool=_db_pool)
            # If closed, discard it
            _db_pool.putconn(conn, close=True)
        except Exception:
            pass
            
    # Fallback to a brand new connection if pool fails or returns dead connections
    db_uri = os.getenv("DATABASE_URL")
    if not db_uri:
        db_uri = "postgresql://postgres:excelapppass@localhost:5432/excel_cleaner_db"
    conn = psycopg2.connect(db_uri)
    return PostgresConnectionWrapper(conn)


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
        cursor.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name = %s
            )
        """, (table_name,))
        row = cursor.fetchone()
        if not row:
            return False
        return row[0] if isinstance(row, tuple) else row.get("exists", False)
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
        "UPDATE api_tokens SET is_active = FALSE WHERE token = %s",
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
          AND success  = FALSE
          AND attempted_at > NOW() - INTERVAL '10 MINUTE'
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
        (username, success)
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
    updates = ", ".join(f"{k} = EXCLUDED.{k}" for k in fields.keys())
    values =  list(fields.values())

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        f"""INSERT INTO cleaning_jobs (user_id, {col_names})
        VALUES (%s, {placeholders})
        ON CONFLICT (user_id) DO UPDATE SET {updates}""",
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


def ingest_cleaning_results(cleaned_df, invalid_df, removed_rows, detailed_errors, user_id):
    """
    Ingests cleaned records into master_records, invalid/removed rows into quarantine,
    and warnings/errors into validation_results.
    """
    import json
    import uuid
    import psycopg2
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    CORE_COLUMNS = {
        'company': ['company', 'company name', 'firm', 'organisation', 'organization', 'org'],
        'email': ['email', 'email address', 'e-mail', 'mail'],
        'phone': ['phone', 'phone number', 'mobile', 'telephone', 'number', 'contact'],
        'source': ['source', 'lead source'],
        'issue': ['issue', 'problem', 'ticket'],
        'integrity': ['integrity', 'data integrity'],
        'match_score': ['match_score', 'score']
    }
    
    def map_columns(df_cols):
        mapping = {}
        for db_col, aliases in CORE_COLUMNS.items():
            for df_col in df_cols:
                if df_col.strip().lower() in aliases:
                    mapping[db_col] = df_col
                    break
        return mapping

    try:
        col_map = map_columns(cleaned_df.columns)
        mapped_df_cols = set(col_map.values())
        extra_cols = [c for c in cleaned_df.columns if c not in mapped_df_cols]
        
        # 1. Ingest cleaned records
        for idx, row in cleaned_df.iterrows():
            email_val = row.get(col_map.get('email')) if 'email' in col_map else None
            if email_val is None or (isinstance(email_val, float) and (email_val != email_val or str(email_val).lower() == 'nan')) or str(email_val).strip() == '':
                email_val = None
                
            company_val = row.get(col_map.get('company')) if 'company' in col_map else None
            phone_val = row.get(col_map.get('phone')) if 'phone' in col_map else None
            source_val = row.get(col_map.get('source')) if 'source' in col_map else None
            issue_val = row.get(col_map.get('issue')) if 'issue' in col_map else None
            integrity_val = row.get(col_map.get('integrity')) if 'integrity' in col_map else 'Clean'
            match_score_val = row.get(col_map.get('match_score')) if 'match_score' in col_map else None
            
            extra_dict = {}
            for col in extra_cols:
                val = row[col]
                if val != val or str(val).lower() == 'nan' or val is None:
                    extra_dict[col] = None
                else:
                    extra_dict[col] = val
            
            extra_json = json.dumps(extra_dict)
            cust_uuid = str(uuid.uuid4())
            
            existing_id = None
            if email_val:
                cursor.execute("SELECT customer_id FROM master_records WHERE email = %s AND survivor_id IS NULL LIMIT 1", (email_val,))
                row_exists = cursor.fetchone()
                if row_exists:
                    existing_id = row_exists[0]
            
            if existing_id:
                cursor.execute("""
                    UPDATE master_records 
                    SET company = COALESCE(%s, company),
                        phone = COALESCE(%s, phone),
                        source = COALESCE(%s, source),
                        issue = COALESCE(%s, issue),
                        integrity = %s,
                        match_score = %s,
                        extra_fields = extra_fields || %s::jsonb,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE customer_id = %s
                """, (
                    company_val, phone_val, source_val, issue_val, 
                    integrity_val, match_score_val, extra_json, existing_id
                ))
                cust_id = existing_id
            else:
                cursor.execute("""
                    INSERT INTO master_records 
                    (customer_id, company, email, phone, source, issue, integrity, match_score, extra_fields) 
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING customer_id
                """, (
                    cust_uuid, company_val, email_val, phone_val, source_val, 
                    issue_val, integrity_val, match_score_val, extra_json
                ))
                cust_id = cursor.fetchone()[0]
            
            row_errors = [e for e in detailed_errors if e.get("row_index") == idx]
            for err in row_errors:
                cursor.execute("""
                    INSERT INTO validation_results (rule_id, customer_id, column_name, status)
                    VALUES (%s, %s, %s, %s)
                """, (
                    err.get("rule", "Unknown"), cust_id, err.get("column", "Unknown"), err.get("message", "Validation error")
                ))

        # 2. Ingest into quarantine (both fully removed rows and fully invalid rows)
        cursor.execute("SELECT username FROM users WHERE id = %s", (user_id,))
        username_row = cursor.fetchone()
        flagged_by = username_row[0] if username_row else 'system'
        file_uuid = str(uuid.uuid4())
        
        if not invalid_df.empty:
            for idx, row in invalid_df.iterrows():
                row_dict = {}
                for col in invalid_df.columns:
                    val = row[col]
                    if val != val or str(val).lower() == 'nan' or val is None:
                        row_dict[col] = None
                    else:
                        row_dict[col] = val
                row_json = json.dumps(row_dict)
                
                row_errs = [e.get("message") for e in detailed_errors if e.get("row_index") == idx]
                reason = "; ".join(row_errs) if row_errs else "Validation failure"
                
                cursor.execute("""
                    INSERT INTO quarantine (file_id, raw_payload, reason, flagged_by)
                    VALUES (%s, %s, %s, %s)
                """, (file_uuid, row_json, reason, flagged_by))
                
        if not removed_rows.empty:
            for idx, row in removed_rows.iterrows():
                row_dict = {}
                for col in removed_rows.columns:
                    val = row[col]
                    if val != val or str(val).lower() == 'nan' or val is None:
                        row_dict[col] = None
                    else:
                        row_dict[col] = val
                row_json = json.dumps(row_dict)
                reason = row.get("Removal Reason") or "Duplicate record"
                
                cursor.execute("""
                    INSERT INTO quarantine (file_id, raw_payload, reason, flagged_by)
                    VALUES (%s, %s, %s, %s)
                """, (file_uuid, row_json, reason, flagged_by))

        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()


# ── Custom Fields & Mapping Ingestion (Rishi Branch) ──────────────────────────

MASTER_COLUMNS = {
    'full_name', 'email_address', 'primary_phone_number', 'alternate_phone_number',
    'company_name', 'job_title', 'department', 'website_url', 'address_line_1',
    'address_line_2', 'city', 'state_province', 'postal_zip_code', 'country',
    'linkedin_profile_url', 'industry', 'lead_source', 'record_status', 'date_of_birth',
    'gender', 'company_size', 'annual_revenue', 'imported_by'
}

def normalize_header(header_name):
    name = str(header_name).strip().lower()
    name = re.sub(r'[^a-z0-9\s_\-]', '', name)
    name = re.sub(r'[\s_\-]+', '_', name)
    return name.strip('_')

def suggest_column_mapping(columns, cursor):
    master_cols = [
        ("full_name", "Full Name"),
        ("email_address", "Email Address"),
        ("primary_phone_number", "Primary Phone Number"),
        ("alternate_phone_number", "Alternate Phone Number"),
        ("company_name", "Company Name"),
        ("job_title", "Job Title"),
        ("department", "Department"),
        ("website_url", "Website URL"),
        ("address_line_1", "Address Line 1"),
        ("address_line_2", "Address Line 2"),
        ("city", "City"),
        ("state_province", "State / Province"),
        ("postal_zip_code", "Postal / ZIP Code"),
        ("country", "Country"),
        ("linkedin_profile_url", "LinkedIn Profile URL"),
        ("industry", "Industry"),
        ("lead_source", "Lead Source"),
        ("record_status", "Record Status"),
        ("date_of_birth", "Date of Birth"),
        ("gender", "Gender"),
        ("company_size", "Company Size"),
        ("annual_revenue", "Annual Revenue")
    ]
    
    cursor.execute("SELECT id, field_name FROM field_registry WHERE is_active = TRUE")
    custom_fields = cursor.fetchall()
    
    cursor.execute("SELECT alias, target_type, target_identifier FROM field_aliases")
    aliases = cursor.fetchall()
    
    suggestions = {}
    
    for col in columns:
        col_norm = normalize_header(col)
        matched = False
        
        # 1. Aliases check
        for a in aliases:
            if a['alias'].lower().strip() == col.lower().strip() or normalize_header(a['alias']) == col_norm:
                suggestions[col] = f"{a['target_type']}:{a['target_identifier']}"
                matched = True
                break
        if matched:
            continue
            
        # 2. Master columns check
        for mc_norm, mc_name in master_cols:
            if mc_norm == col_norm or mc_name.lower().strip() == col.lower().strip() or normalize_header(mc_name) == col_norm:
                suggestions[col] = f"master:{mc_norm}"
                matched = True
                break
        if matched:
            continue
            
        # 3. Custom fields check
        for cf in custom_fields:
            if cf['normalized_name'] == col_norm or cf['field_name'].lower().strip() == col.lower().strip() or normalize_header(cf['field_name']) == col_norm:
                suggestions[col] = f"custom:{cf['id']}"
                matched = True
                break
        if matched:
            continue
            
        suggestions[col] = "create_new"
        
    return suggestions

def ingest_uploaded_file(file_id, file_path, username):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    import pandas as pd
    
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
                "INSERT INTO field_registry (field_name, normalized_name, data_type, usage_count) VALUES (%s, %s, %s, %s) RETURNING id",
                (header, norm, 'VARCHAR', 1)
            )
            row = cursor.fetchone()
            new_id = row['id'] if isinstance(row, dict) else row[0]
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
                'extra_fields': {}
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
                    record_dict['extra_fields'][mapping['target']] = str(cleaned_val)
                    
            if record_dict['extra_fields']:
                record_dict['extra_fields'] = json.dumps(record_dict['extra_fields'])
            else:
                record_dict['extra_fields'] = None
                
            records_to_insert.append(record_dict)
            
        # Bulk insert records
        if records_to_insert:
            columns_list = [
                'file_id', 'full_name', 'email_address', 'primary_phone_number', 'alternate_phone_number',
                'company_name', 'job_title', 'department', 'website_url', 'address_line_1', 'address_line_2',
                'city', 'state_province', 'postal_zip_code', 'country', 'linkedin_profile_url', 'industry',
                'lead_source', 'record_status', 'date_of_birth', 'gender', 'company_size', 'annual_revenue',
                'imported_by', 'extra_fields'
            ]
            insert_query = f"""
                INSERT INTO master_records ({', '.join([f'"{col}"' for col in columns_list])})
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
    import pandas as pd
    
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
            
        # 2. Handle dynamic creation of new custom fields
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
                        "INSERT INTO field_registry (field_name, normalized_name, data_type, usage_count) VALUES (%s, %s, %s, %s) RETURNING id",
                        (header, norm, 'VARCHAR', 1)
                    )
                    row = cursor.fetchone()
                    new_id = row['id'] if isinstance(row, dict) else row[0]
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
        cursor.execute("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'master_records'
        """)
        all_db_columns = [row['column_name'] if isinstance(row, dict) else row[0] for row in cursor.fetchall()]
        
        for _, row in df.iterrows():
            record_dict = {
                'file_id': file_id,
                'imported_by': username,
                'extra_fields': {}
            }
            # Initialize all other DB columns to None
            for col in all_db_columns:
                if col not in ('id', 'file_id', 'extra_fields', 'created_at', 'updated_at', 'imported_by'):
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
                    record_dict['extra_fields'][field_id] = cleaned_val
                    
            if not has_any_value:
                continue # Skip completely empty row
                
            # Perform Duplicate Check: if every mapped field matches an existing row
            dup_query = ["1=1"]
            dup_params = []
            
            # Add checks for master columns mapped
            for header, target in final_mapping.items():
                if target.startswith("master:"):
                    col_name = target.split("master:")[1]
                    if col_name in record_dict:
                        val = record_dict[col_name]
                        if val is not None:
                            dup_query.append(f'"{col_name}" = %s')
                            dup_params.append(val)
                        else:
                            dup_query.append(f'("{col_name}" IS NULL OR "{col_name}" = \'\')')
                elif target.startswith("custom:"):
                    field_id = target.split("custom:")[1]
                    val = record_dict['extra_fields'].get(field_id)
                    if val is not None:
                        dup_query.append("extra_fields->>%s = %s")
                        dup_params.append(str(field_id))
                        dup_params.append(val)
                    else:
                        dup_query.append("(extra_fields IS NULL OR extra_fields->>%s IS NULL)")
                        dup_params.append(str(field_id))
                        
            # Check in-memory duplicates for the current ingestion batch
            seen_tuple_list = []
            for h, t in sorted(final_mapping.items()):
                if t.startswith("master:"):
                    col_name = t.split("master:")[1]
                    seen_tuple_list.append((t, record_dict.get(col_name)))
                elif t.startswith("custom:"):
                    field_id = t.split("custom:")[1]
                    seen_tuple_list.append((t, record_dict['extra_fields'].get(field_id)))
            seen_tuple = tuple(seen_tuple_list)
            
            if seen_tuple in seen_in_batch:
                rejected_count += 1
                continue
                
            # Execute duplicate query against database
            cursor.execute(f"SELECT COUNT(*) as count FROM master_records WHERE {' AND '.join(dup_query)}", dup_params)
            dup_row = cursor.fetchone()
            if dup_row and (dup_row.get('count') or 0 if isinstance(dup_row, dict) else dup_row[0] or 0) > 0:
                rejected_count += 1
            else:
                records_to_insert.append(record_dict)
                seen_in_batch.add(seen_tuple)
                
        # 4. Insert dynamic inserts
        if records_to_insert:
            cols_to_insert = [c for c in all_db_columns if c not in ('id', 'created_at', 'updated_at')]
            
            insert_query = f"""
                INSERT INTO master_records ({', '.join([f'"{c}"' for c in cols_to_insert])})
                VALUES ({', '.join(['%s'] * len(cols_to_insert))})
            """
            
            insert_data = []
            for r in records_to_insert:
                row_tuple = []
                for col in cols_to_insert:
                    if col == 'extra_fields':
                        # Convert dict to JSON string or None
                        row_tuple.append(json.dumps(r['extra_fields']) if r['extra_fields'] else None)
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