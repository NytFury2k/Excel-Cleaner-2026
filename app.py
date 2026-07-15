from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, abort, get_flashed_messages, jsonify
import json
import bcrypt
import pandas as pd
from io import BytesIO
import re
import os
import uuid
import secrets
from rbac import has_permission, ROLE_PERMISSIONS
from functools import wraps
from datetime import datetime, timedelta
import json
# mysql.connector is mocked via helpers.py — import helpers first to activate the mock
from helpers import (
    get_db_connection, log_action, login_required,
    get_visible_user_ids, generate_api_token,
    resolve_token, revoke_api_token, refresh_api_token,
    set_job_state, get_job_state, clear_job_files,
    ingest_uploaded_file_with_mapping, check_login_rate_limit,
    clear_login_attempts, record_login_attempt, api_login_required,
    log_search, load_permissions_from_db, fetch_visible_logs
)
import mysql.connector
from mysql.connector import Error, IntegrityError

from collections import Counter
import time
import numpy as np

from dotenv import load_dotenv

load_dotenv(override=True)
import os
# print("SECRET KEY VALUE: ", repr(os.environ.get("FLASK_SECRET_KEY")))


from cleaning.engine import run_cleaning_pipeline
from cleaning.reporting import generate_summary
from cleaning.schema_mapper import map_column_to_type
from cleaning.column_metadata import COLUMN_METADATA
from cleaning.column_types import infer_column_type
from cleaning.type_resolver import resolve_column_type
from collections import defaultdict
from cleaning.rules_registry import RULES_REGISTRY

from helpers import (
    get_db_connection, log_action, get_visible_user_ids,
    fetch_visible_logs, detect_identifier_columns,
    cleanup_old_session_files, validate_password,
    login_required, INACTIVITY_LIMIT, generate_api_token, 
    resolve_token, revoke_api_token, api_login_required,
    refresh_api_token, check_login_rate_limit, record_login_attempt,
    load_permissions_from_db, log_search
)

import logging
from logging.handlers import RotatingFileHandler

#Create logs directory
os.makedirs("logs", exist_ok=True)

#Set up rotating file handler- 5MB per file, keep last 5 files
file_handler = RotatingFileHandler(
    "logs/data_manager.log",
    maxBytes=5 *1024 *1024, #5MB
    backupCount=5
)
file_handler.setFormatter(logging.Formatter(
    "[%(asctime)s] %(levelname)s in %(module)s: %(message)s"
))
file_handler.setLevel(logging.WARNING)

#Also log to strderr at WARNING level
stream_handler=logging.StreamHandler()
stream_handler.setLevel(logging.WARNING)

def _validate_env():
    """Crash at startup if critical environment variables are missing or insecure"""
    errors=[]

    secret_key = os.environ.get("FLASK_SECRET_KEY", "")
    if not secret_key: 
        errors.append("FLASK_SECRET_KEY is not set in .env")
    elif secret_key == "dev-only-fallback-change-in-prod":
        if os.environ.get("FLASK_ENV")=="production":
            errors.append("FLASK_SECRET_KEY is still using the insecure default value")

    if os.environ.get("FLASK_ENV") == "production":
        required=["MAIL_USERNAME","MAIL_PASSWORD"]
        for var in required:
            if not os.environ.get(var):
                errors.append(f"{var} is not set (required in production)")
    if errors:
        for err in errors:
            print(f"[STARTUP ERROR] {err}")
        raise SystemExit("Cannot start: fix the above .env errors first.")
    
_validate_env()



INACTIVITY_LIMIT = timedelta(minutes=30)

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50 MB upload limit


from flask_mail import Mail, Message
from werkzeug.exceptions import RequestEntityTooLarge

@app.errorhandler(413)
@app.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(e):
    flash("File too large. Maximum upload size is 50 MB.", "danger")
    return redirect(request.referrer or url_for('upload')), 302

app.config["MAIL_SERVER"] = os.environ.get("MAIL_SERVER", "smtp.gmail.com")
app.config["MAIL_PORT"] = int(os.environ.get("MAIL_PORT", 587))
app.config["MAIL_USE_TLS"] = os.environ.get("MAIL_USE_TLS", "True") == "True"
app.config["MAIL_USERNAME"] = os.environ.get("MAIL_USERNAME", "")
app.config["MAIL_PASSWORD"] = os.environ.get("MAIL_PASSWORD", "")
app.config["MAIL_DEFAULT_SENDER"] = os.environ.get("MAIL_DEFAULT_SENDER", "")
mail = Mail(app)


app.logger.addHandler(file_handler)
app.logger.addHandler(stream_handler)
app.logger.setLevel(logging.WARNING)
    
from api_routes import api_bp, limiter as api_limiter

api_limiter.init_app(app)
app.register_blueprint(api_bp)

for _folder in ["Generated_Files/Cleaned", "Generated_Files/Invalid", "Generated_Files/Removed"]:
    os.makedirs(_folder, exist_ok=True)

app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-only-fallback-change-in-prod")
app.config["SESSION_PERMANENT"] = False
#Security cookie settings
app.config["SESSION_COOKIE_SECURE"]=os.environ.get("FLASK_ENV") == "production"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# HTTPS redirect in production
if os.environ.get("FLASK_ENV") == "production":
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app=ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

#error handler
@app.errorhandler(403)
def forbidden(e):
    return render_template("session_expired.html"), 403

import traceback

@app.errorhandler(Exception)
def handle_exceptions(e):
    # Log every unhandled exception to the file
    app.logger.error(f"Unhandled exception: {traceback.format_exc()}")
    # If it's an HTTP exception (404, 403 etc), re-raise it
    from werkzeug.exceptions import HTTPException
    if isinstance(e, HTTPException):
        return e
    return "Internal server error", 500


#after request
@app.after_request
def add_response_headers(response):
    #Cache control for authenticated pages
    if "user_id" in session:
        response.headers["Cache-Control"]="no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"]="no-cache"
        response.headers["Expires"]="0"

    #Security headers - applied to ALL responses
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    #HTTPS-only header in production
    if os.environ.get("FLASK_ENV") == "production":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    return response


def _send_lockout_alert(username):
    """
    Sends an email to the user's admin/manager when their account gets locked
    due to too many failed login attempts. Best-effort — never raises.
    """
    try:
        conn   = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Get the locked user and their manager's email
        cursor.execute("""
            SELECT u.id, u.username, u.email, u.manager_id,
                   m.email AS manager_email, m.username AS manager_username
            FROM users u
            LEFT JOIN users m ON m.id = u.manager_id
            WHERE u.username = %s
        """, (username,))
        row = cursor.fetchone()
        conn.close()

        if not row:
            return  # Unknown username — nothing to alert

        # Find who to notify: manager if set, otherwise all admins
        notify_emails = []
        if row.get("manager_email"):
            notify_emails.append(row["manager_email"])
        else:
            # No manager — notify all admins who have an email set
            conn2   = get_db_connection()
            cursor2 = conn2.cursor(dictionary=True)
            cursor2.execute("SELECT email FROM users WHERE role='admin' AND email IS NOT NULL AND is_active=1")
            for admin in cursor2.fetchall():
                notify_emails.append(admin["email"])
            conn2.close()

        if not notify_emails:
            return  # No one to notify

        msg = Message(
            subject=f"[Data Manager] Login lockout: {username}",
            recipients=notify_emails,
            body=(
                f"This is an automated security alert.\n\n"
                f"User '{username}' has been temporarily locked out after "
                f"5 failed login attempts in 10 minutes.\n\n"
                f"If this was not them, their password may need to be reset. "
                f"You can do this from the User Management page.\n\n"
                f"— Data Manager (automated)"
            )
        )
        mail.send(msg)
        app.logger.info(f"Lockout alert sent for '{username}' to {notify_emails}")

    except Exception as e:
        app.logger.warning(f"Failed to send lockout alert for '{username}': {e}")




def _email_already_exists(email, exclude_user_id=None):
    """Returns True if the email is already registered to another user."""
    if not email:
        return False
    conn   = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    if exclude_user_id:
        cursor.execute(
            "SELECT id FROM users WHERE email = %s AND id != %s",
            (email, exclude_user_id)
        )
    else:
        cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
    exists = cursor.fetchone() is not None
    conn.close()
    return exists

#full logs page
@app.route("/admin/logs")
@login_required()
def admin_logs():
    if session.get("role") not in ("admin", "manager", "team_lead"):
        flash("Access denied.", "warning")
        return redirect(url_for("upload"))
        
    # Search keyword from query params
    search = request.args.get("search", "").strip()
    from_date = request.args.get("from_date","")           
    to_date = request.args.get("to_date","") 
    log_type = (request.args.get("log_type", "all") or "all").strip().lower()
    selected_user_id = request.args.get("user_id", "")
    if log_type not in {"login", "cleaning", "search", "export", "all"}:
        log_type = "all"

    if not from_date or not from_date.strip():
        from_date=""
    else:
        from_date = from_date.strip()

    if not to_date or not to_date.strip():
        to_date=""
    else:
        to_date = to_date.strip()
        
    page = request.args.get("page", 1, type=int)
    
    if (log_type == "search" and search and page == 1 and session.get("role") in ["admin", "manager"]):
        log_search(session["user_id"], session["username"], search)

    per_page = 15

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Fetch all users for user selector (admin sees all, manager sees their team)
    if session.get("role") == "admin":
        cursor.execute("SELECT id, username, role, status FROM users WHERE status != 'deleted' ORDER BY username")
    else:
        cursor.execute("SELECT id, username, role, status FROM users WHERE (id = %s OR manager_id = %s) AND status != 'deleted' ORDER BY username",
                       (session["user_id"], session["user_id"]))
    all_users = cursor.fetchall()

    # Build user filter clause
    user_filter_sql = ""
    user_filter_params = []
    selected_user = None
    deactivated_days = None
    active_dates = []

    if selected_user_id and selected_user_id.isdigit():
        user_filter_sql = " AND l.user_id = %s"
        user_filter_params = [int(selected_user_id)]
        
        # Fetch details for the selected user
        cursor.execute("SELECT id, username, role, status, deactivated_at, is_active FROM users WHERE id = %s", (int(selected_user_id),))
        selected_user = cursor.fetchone()
        if selected_user:
            if selected_user["status"] == "deactivated" and selected_user["deactivated_at"]:
                from datetime import datetime
                delta = datetime.utcnow() - selected_user["deactivated_at"]
                deactivated_days = max(0, delta.days)
                
            # Fetch last active history dates
            cursor.execute("""
                SELECT DISTINCT DATE(created_at) as active_date
                FROM logs
                WHERE user_id = %s
                ORDER BY active_date DESC
                LIMIT 50
            """, (int(selected_user_id),))
            active_dates = [r["active_date"].strftime("%d %b %Y") for r in cursor.fetchall() if r.get("active_date")]

    # --- ANALYTICS STATS ---
    # Total counts per action category
    cursor.execute(f"""
        SELECT
            COUNT(*) AS total_events,
            SUM(CASE WHEN LOWER(l.action) LIKE '%%export%%' THEN 1 ELSE 0 END) AS total_exports,
            SUM(CASE WHEN LOWER(l.action) LIKE '%%upload%%' OR LOWER(l.action) LIKE '%%ingest%%' OR (LOWER(l.action) LIKE '%%import%%' AND LOWER(l.action) NOT LIKE '%%export%%') THEN 1 ELSE 0 END) AS total_imports,
            SUM(CASE WHEN LOWER(l.action) LIKE '%%cleaned file%%' THEN 1 ELSE 0 END) AS total_cleans,
            SUM(CASE WHEN LOWER(l.action) LIKE '%%search%%' OR LOWER(l.action) LIKE '%%filter%%' THEN 1 ELSE 0 END) AS total_searches,
            SUM(CASE WHEN LOWER(l.action) LIKE '%%login%%' THEN 1 ELSE 0 END) AS total_logins,
            SUM(CASE WHEN LOWER(l.action) LIKE '%%delete%%' OR LOWER(l.action) LIKE '%%removed%%' THEN 1 ELSE 0 END) AS total_deletes,
            COUNT(DISTINCT l.user_id) AS unique_users
        FROM logs l
        JOIN users u ON u.id = l.user_id
        WHERE 1=1 {user_filter_sql}
    """, user_filter_params)
    stats = cursor.fetchone() or {}

    # Today's export count (from user_daily_exports)
    try:
        cursor.execute(f"""
            SELECT COALESCE(SUM(ude.rows_count), 0) AS rows_today
            FROM user_daily_exports ude
            WHERE ude.export_date = CURRENT_DATE
            {"AND ude.user_id = %s" if selected_user_id and selected_user_id.isdigit() else ""}
        """, [int(selected_user_id)] if selected_user_id and selected_user_id.isdigit() else [])
        today_row = cursor.fetchone()
        rows_exported_today = int(today_row["rows_today"]) if today_row else 0
    except Exception:
        rows_exported_today = 0

    # Top 5 most active users
    cursor.execute("""
        SELECT u.username, COUNT(l.id) AS event_count
        FROM logs l
        JOIN users u ON u.id = l.user_id
        GROUP BY l.user_id, u.username
        ORDER BY event_count DESC
        LIMIT 5
    """)
    top_users = cursor.fetchall()

    logs, total_logs = fetch_visible_logs(cursor, search=search, from_date=from_date, to_date=to_date,
                                          log_type=log_type, page=page, per_page=per_page,
                                          user_id=int(selected_user_id) if selected_user_id and selected_user_id.isdigit() else None)
    conn.close()

    total_pages = (total_logs + per_page - 1) // per_page

    if total_logs > 0:
        start = (page - 1) * per_page + 1
        end = min(page * per_page, total_logs)
    else:
        start = 0
        end = 0

    return render_template("admin_logs.html",
                           logs=logs,
                           page=page,
                           total_pages=total_pages,
                           total_logs=total_logs,
                           start=start,
                           end=end,
                           search=search,
                           from_date=from_date,
                           to_date=to_date,
                           log_type=log_type,
                           offset=(page-1) * per_page,
                           form_action=url_for("admin_logs"),
                           export_url=url_for("export_logs"),
                           all_users=all_users,
                           selected_user_id=selected_user_id,
                           stats=stats,
                           top_users=top_users,
                           rows_exported_today=rows_exported_today,
                           selected_user=selected_user,
                           deactivated_days=deactivated_days,
                           active_dates=active_dates,
                           pagination_url=lambda p: url_for(
                               "admin_logs",
                               page=p,
                               search=search,
                               from_date=from_date,
                               to_date=to_date,
                               log_type=log_type,
                               user_id=selected_user_id
                           ))


@app.route("/api/admin/logs/chart-data")
@login_required()
def logs_chart_data():
    """API endpoint returning time-series chart data for activity logs with complete label coverage."""
    if session.get("role") not in ("admin", "manager", "team_lead"):
        return jsonify({"error": "Access denied"}), 403

    from datetime import timedelta, date as date_cls, datetime

    period = request.args.get("period", "week")  # week, month, year, custom
    from_date_str = request.args.get("from_date", "")
    to_date_str = request.args.get("to_date", "")
    user_id_filter = request.args.get("user_id", "")

    today = date_cls.today()

    # Build complete label list and date range
    all_labels = []
    all_dates = []   # list of (label, date_key_str) to fill zeros
    group_by = "day"

    if period == "week":
        # Last 7 days including today
        start_date = today - timedelta(days=6)
        end_date = today
        group_by = "day"
        d = start_date
        while d <= end_date:
            all_labels.append(d.strftime("%a %d %b"))   # e.g. "Wed 03 Jul"
            all_dates.append(str(d))
            d += timedelta(days=1)

    elif period == "month":
        # Last 30 days, grouped into 4-5 week buckets
        start_date = today - timedelta(days=29)
        end_date = today
        group_by = "week"
        # Generate each ISO week start within range
        from datetime import timedelta
        cur = start_date - timedelta(days=start_date.weekday())  # Monday of start week
        seen = set()
        while cur <= end_date:
            if cur >= start_date or (cur + timedelta(days=6)) >= start_date:
                week_key = str(cur)
                if week_key not in seen:
                    seen.add(week_key)
                    all_labels.append(f"{cur.strftime('%d %b')}–{(cur + timedelta(days=6)).strftime('%d %b')}")
                    all_dates.append(week_key)
            cur += timedelta(weeks=1)

    elif period == "year":
        # Last 12 calendar months
        group_by = "month"
        from datetime import datetime
        start_date = date_cls(today.year - 1, today.month, 1) if today.month > 1 else date_cls(today.year - 1, 1, 1)
        end_date = today
        for i in range(11, -1, -1):
            # Go back i months from current month
            yr = today.year
            mo = today.month - i
            while mo <= 0:
                mo += 12
                yr -= 1
            month_start = date_cls(yr, mo, 1)
            all_labels.append(month_start.strftime("%b %Y"))
            all_dates.append(str(month_start))
        # Use first date of first month label as start
        if all_dates:
            start_date = date_cls.fromisoformat(all_dates[0])

    elif period == "custom" and from_date_str and to_date_str:
        try:
            start_date = datetime.strptime(from_date_str, "%Y-%m-%d").date()
            end_date = datetime.strptime(to_date_str, "%Y-%m-%d").date()
            delta = (end_date - start_date).days
            if delta > 89:
                group_by = "month"
                from datetime import datetime
                cur = date_cls(start_date.year, start_date.month, 1)
                while cur <= end_date:
                    all_labels.append(cur.strftime("%b %Y"))
                    all_dates.append(str(cur))
                    # Next month
                    yr, mo = (cur.year, cur.month + 1) if cur.month < 12 else (cur.year + 1, 1)
                    cur = date_cls(yr, mo, 1)
            elif delta > 14:
                group_by = "week"
                cur = start_date - timedelta(days=start_date.weekday())
                seen = set()
                while cur <= end_date:
                    if (cur + timedelta(days=6)) >= start_date:
                        week_key = str(cur)
                        if week_key not in seen:
                            seen.add(week_key)
                            all_labels.append(f"{cur.strftime('%d %b')}–{(cur + timedelta(days=6)).strftime('%d %b')}")
                            all_dates.append(week_key)
                    cur += timedelta(weeks=1)
            else:
                group_by = "day"
                d = start_date
                while d <= end_date:
                    all_labels.append(d.strftime("%a %d %b"))
                    all_dates.append(str(d))
                    d += timedelta(days=1)
            start_date = datetime.strptime(from_date_str, "%Y-%m-%d").date()
            end_date = datetime.strptime(to_date_str, "%Y-%m-%d").date()
        except Exception:
            period = "week"
            start_date = today - timedelta(days=6)
            end_date = today
    else:
        # default: week
        start_date = today - timedelta(days=6)
        end_date = today
        group_by = "day"
        d = start_date
        while d <= end_date:
            all_labels.append(d.strftime("%a %d %b"))
            all_dates.append(str(d))
            d += timedelta(days=1)

    if not all_dates:
        return jsonify({"labels": [], "totals": [], "exports": [], "imports": [], "searches": [], "logins": []})

    user_clause = ""
    params = [str(all_dates[0]), str(end_date if period != "custom" else to_date_str)]
    if user_id_filter and user_id_filter.isdigit():
        user_clause = " AND l.user_id = %s"
        params.append(int(user_id_filter))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    if group_by == "day":
        date_expr = "DATE(l.created_at AT TIME ZONE 'Asia/Kolkata')"
    elif group_by == "week":
        date_expr = "DATE_TRUNC('week', l.created_at AT TIME ZONE 'Asia/Kolkata')::date"
    else:
        date_expr = "DATE_TRUNC('month', l.created_at AT TIME ZONE 'Asia/Kolkata')::date"

    query = f"""
        SELECT
            {date_expr} AS period_date,
            COUNT(*) AS total,
            SUM(CASE WHEN LOWER(l.action) LIKE '%%export%%' THEN 1 ELSE 0 END) AS exports,
            SUM(CASE WHEN LOWER(l.action) LIKE '%%upload%%' OR LOWER(l.action) LIKE '%%ingest%%' OR (LOWER(l.action) LIKE '%%import%%' AND LOWER(l.action) NOT LIKE '%%export%%') THEN 1 ELSE 0 END) AS imports,
            SUM(CASE WHEN LOWER(l.action) LIKE '%%cleaned file%%' THEN 1 ELSE 0 END) AS cleans,
            SUM(CASE WHEN LOWER(l.action) LIKE '%%search%%' OR LOWER(l.action) LIKE '%%filter%%' THEN 1 ELSE 0 END) AS searches,
            SUM(CASE WHEN LOWER(l.action) LIKE '%%login%%' THEN 1 ELSE 0 END) AS logins
        FROM logs l
        WHERE DATE(l.created_at AT TIME ZONE 'Asia/Kolkata') BETWEEN %s AND %s
        {user_clause}
        GROUP BY period_date
        ORDER BY period_date ASC
    """

    try:
        cursor.execute(query, params)
        rows = cursor.fetchall()
    except Exception as e:
        conn.close()
        return jsonify({"error": str(e)}), 500

    conn.close()

    # Build lookup dict from DB rows
    db_lookup = {}
    for row in rows:
        d = row["period_date"]
        if hasattr(d, "strftime"):
            db_lookup[str(d)] = row

    # Fill ALL labels with zeros for missing dates
    labels = []
    totals = []
    exports = []
    imports = []
    cleans = []
    searches = []
    logins = []

    for date_key, label in zip(all_dates, all_labels):
        labels.append(label)
        row = db_lookup.get(date_key, {})
        totals.append(int(row.get("total", 0)))
        exports.append(int(row.get("exports", 0)))
        imports.append(int(row.get("imports", 0)))
        cleans.append(int(row.get("cleans", 0)))
        searches.append(int(row.get("searches", 0)))
        logins.append(int(row.get("logins", 0)))

    return jsonify({
        "labels":   labels,
        "totals":   totals,
        "exports":  exports,
        "imports":  imports,
        "cleans":   cleans,
        "searches": searches,
        "logins":   logins
    })


@app.route("/api/admin/logs/period-stats")
@login_required()
def logs_period_stats():
    """API: Summary stats filtered by a period (week/month/year/custom)."""
    if session.get("role") not in ("admin", "manager", "team_lead"):
        return jsonify({"error": "Access denied"}), 403

    from datetime import timedelta, date as date_cls, datetime

    period = request.args.get("period", "week")
    from_date_str = request.args.get("from_date", "")
    to_date_str = request.args.get("to_date", "")
    user_id_filter = request.args.get("user_id", "")

    today = date_cls.today()

    if period == "week":
        start_date = today - timedelta(days=6)
        end_date = today
    elif period == "month":
        start_date = today - timedelta(days=29)
        end_date = today
    elif period == "year":
        start_date = date_cls(today.year, 1, 1)
        end_date = today
    elif period == "custom" and from_date_str and to_date_str:
        try:
            start_date = datetime.strptime(from_date_str, "%Y-%m-%d").date()
            end_date = datetime.strptime(to_date_str, "%Y-%m-%d").date()
        except Exception:
            start_date = today - timedelta(days=6)
            end_date = today
    else:
        start_date = today - timedelta(days=6)
        end_date = today

    user_clause = ""
    params = [str(start_date), str(end_date)]
    if user_id_filter and user_id_filter.isdigit():
        user_clause = " AND l.user_id = %s"
        params.append(int(user_id_filter))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute(f"""
            SELECT
                COUNT(*) AS total_events,
                SUM(CASE WHEN LOWER(l.action) LIKE '%%export%%' THEN 1 ELSE 0 END) AS total_exports,
                SUM(CASE WHEN LOWER(l.action) LIKE '%%upload%%' OR LOWER(l.action) LIKE '%%ingest%%' OR (LOWER(l.action) LIKE '%%import%%' AND LOWER(l.action) NOT LIKE '%%export%%') THEN 1 ELSE 0 END) AS total_imports,
                SUM(CASE WHEN LOWER(l.action) LIKE '%%cleaned file%%' THEN 1 ELSE 0 END) AS total_cleans,
                SUM(CASE WHEN LOWER(l.action) LIKE '%%search%%' OR LOWER(l.action) LIKE '%%filter%%' THEN 1 ELSE 0 END) AS total_searches,
                SUM(CASE WHEN LOWER(l.action) LIKE '%%login%%' THEN 1 ELSE 0 END) AS total_logins,
                SUM(CASE WHEN LOWER(l.action) LIKE '%%delete%%' OR LOWER(l.action) LIKE '%%removed%%' THEN 1 ELSE 0 END) AS total_deletes,
                COUNT(DISTINCT l.user_id) AS unique_users
            FROM logs l
            WHERE DATE(l.created_at AT TIME ZONE 'Asia/Kolkata') BETWEEN %s AND %s
            {user_clause}
        """, params)
        stats = cursor.fetchone() or {}

        # Rows exported in this period
        ue_params = [str(start_date), str(end_date)]
        ue_clause = ""
        if user_id_filter and user_id_filter.isdigit():
            ue_clause = " AND user_id = %s"
            ue_params.append(int(user_id_filter))
        cursor.execute(f"""
            SELECT COALESCE(SUM(rows_count), 0) AS rows_exported
            FROM user_daily_exports
            WHERE export_date BETWEEN %s AND %s {ue_clause}
        """, ue_params)
        ue_row = cursor.fetchone()
        rows_exported = int(ue_row["rows_exported"]) if ue_row else 0
    except Exception as e:
        conn.close()
        return jsonify({"error": str(e)}), 500

    conn.close()

    return jsonify({
        "total_events":   int(stats.get("total_events") or 0),
        "total_exports":  int(stats.get("total_exports") or 0),
        "total_imports":  int(stats.get("total_imports") or 0),
        "total_cleans":   int(stats.get("total_cleans") or 0),
        "total_searches": int(stats.get("total_searches") or 0),
        "total_logins":   int(stats.get("total_logins") or 0),
        "total_deletes":  int(stats.get("total_deletes") or 0),
        "unique_users":   int(stats.get("unique_users") or 0),
        "rows_exported":  rows_exported,
    })


@app.route("/api/admin/users/<int:user_id>/calendar-data")
@login_required()
def user_calendar_data(user_id):
    if session.get("role") not in ("admin", "manager", "team_lead"):
        return jsonify({"error": "Access denied"}), 403

    from datetime import datetime, timedelta

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # 1. Fetch user metadata
    cursor.execute("SELECT id, username, status, deactivated_at, created_at FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        return jsonify({"error": "User not found"}), 404

    # 2. Fetch all activity logs (work done)
    cursor.execute("""
        SELECT created_at, action
        FROM logs
        WHERE user_id = %s
        ORDER BY created_at ASC
    """, (user_id,))
    logs = cursor.fetchall()

    # 3. Fetch status change logs (Deactivated / Activated)
    cursor.execute("""
        SELECT action, created_at
        FROM logs
        WHERE (action LIKE 'Deactivated user%%(id=%s)' OR action LIKE 'Activated user%%(id=%s)' 
           OR action LIKE 'Deactivated user%%(id=%s)%%' OR action LIKE 'Activated user%%(id=%s)%%')
        ORDER BY created_at ASC
    """, (user_id, user_id, user_id, user_id))
    status_logs = cursor.fetchall()

    conn.close()

    # Calculate status for the last 365 days
    today = datetime.utcnow().date()
    start_date = today - timedelta(days=365)

    # Map work days
    work_days = {} # YYYY-MM-DD -> list of actions
    for log in logs:
        if log["created_at"]:
            day_str = log["created_at"].date().strftime("%Y-%m-%d")
            if day_str not in work_days:
                work_days[day_str] = []
            work_days[day_str].append(log["action"])

    # Map status updates timeline
    # We parse the timeline of status changes: YYYY-MM-DD -> status ('active' or 'deactivated')
    status_timeline = [] # list of (date, status)
    for slog in status_logs:
        action = slog["action"].lower()
        if "deactivated" in action:
            status_timeline.append((slog["created_at"].date(), "deactivated"))
        elif "activated" in action:
            status_timeline.append((slog["created_at"].date(), "active"))

    # Also append the current status and deactivated_at if active/deactivated
    if user["status"] == "deactivated" and user["deactivated_at"]:
        status_timeline.append((user["deactivated_at"].date(), "deactivated"))

    status_timeline.sort(key=lambda x: x[0])

    daily_status = {}
    current_date = start_date
    while current_date <= today:
        day_str = current_date.strftime("%Y-%m-%d")
        
        # User account state before creation is "not_created"
        if user["created_at"] and current_date < user["created_at"].date():
            daily_status[day_str] = "not_created"
        else:
            # Determine status by finding the last status log before or on current_date
            day_status = "active" # default starting status
            for change_date, state in status_timeline:
                if change_date <= current_date:
                    day_status = state
                else:
                    break
            
            # If there was work done, it is "work"
            if day_str in work_days:
                daily_status[day_str] = "work"
            else:
                daily_status[day_str] = day_status

        current_date += timedelta(days=1)

    return jsonify({
        "user_id": user_id,
        "username": user["username"],
        "daily_status": daily_status,
        "work_details": work_days,
        "work_days_count": len(work_days),
        "deactivated_at": user["deactivated_at"].strftime("%Y-%m-%d %H:%M:%S") if user["deactivated_at"] else None
    })


@app.route("/admin/users/<int:user_id>/calendar-export")
@login_required()
def user_calendar_export(user_id):
    if session.get("role") not in ("admin", "manager", "team_lead"):
        flash("Access denied.", "warning")
        return redirect(url_for("admin_logs"))

    from datetime import datetime, timedelta
    import pandas as pd

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Fetch user metadata
    cursor.execute("SELECT id, username, status, deactivated_at, created_at FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        flash("User not found.", "danger")
        return redirect(url_for("admin_logs"))

    # Fetch logs
    cursor.execute("SELECT created_at, action FROM logs WHERE user_id = %s ORDER BY created_at ASC", (user_id,))
    logs = cursor.fetchall()

    # Fetch status logs
    cursor.execute("""
        SELECT action, created_at
        FROM logs
        WHERE (action LIKE 'Deactivated user%%(id=%s)' OR action LIKE 'Activated user%%(id=%s)'
           OR action LIKE 'Deactivated user%%(id=%s)%%' OR action LIKE 'Activated user%%(id=%s)%%')
        ORDER BY created_at ASC
    """, (user_id, user_id, user_id, user_id))
    status_logs = cursor.fetchall()

    conn.close()

    # Read date range parameters
    from_date_str = request.args.get("from_date", "").strip()
    to_date_str = request.args.get("to_date", "").strip()

    today = datetime.utcnow().date()
    
    if from_date_str:
        try:
            start_date = datetime.strptime(from_date_str, "%Y-%m-%d").date()
        except ValueError:
            start_date = today - timedelta(days=365)
    else:
        start_date = today - timedelta(days=365)

    if to_date_str:
        try:
            end_date = datetime.strptime(to_date_str, "%Y-%m-%d").date()
        except ValueError:
            end_date = today
    else:
        end_date = today

    # Work mapping
    work_days = {}
    for log in logs:
        if log["created_at"]:
            day_str = log["created_at"].date().strftime("%Y-%m-%d")
            if day_str not in work_days:
                work_days[day_str] = []
            work_days[day_str].append(log["action"])

    # Status timeline
    status_timeline = []
    for slog in status_logs:
        action = slog["action"].lower()
        if "deactivated" in action:
            status_timeline.append((slog["created_at"].date(), "deactivated"))
        elif "activated" in action:
            status_timeline.append((slog["created_at"].date(), "active"))

    if user["status"] == "deactivated" and user["deactivated_at"]:
        status_timeline.append((user["deactivated_at"].date(), "deactivated"))

    status_timeline.sort(key=lambda x: x[0])

    rows = []
    current_date = start_date
    while current_date <= end_date:
        day_str = current_date.strftime("%Y-%m-%d")
        
        if user["created_at"] and current_date < user["created_at"].date():
            current_date += timedelta(days=1)
            continue # skip days before user existed
            
        day_status = "Active"
        for change_date, state in status_timeline:
            if change_date <= current_date:
                day_status = "Deactivated" if state == "deactivated" else "Active"
            else:
                break
                
        has_work = "Yes" if day_str in work_days else "No"
        actions_list = ", ".join(work_days[day_str]) if day_str in work_days else ""

        rows.append({
            "Date": day_str,
            "User Status": day_status,
            "Work Done": has_work,
            "Activities Recorded": actions_list
        })
        current_date += timedelta(days=1)

    # Reverse rows so newest are on top
    rows.reverse()

    df_export = pd.DataFrame(rows)
    
    # Save to buffer and send
    import io
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df_export.to_excel(writer, sheet_name="Active History", index=False)
    output.seek(0)

    # Log action
    log_action(session["user_id"], f"Exported active history calendar data for user '{user['username']}' (id={user_id})")

    filename = f"active_history_{user['username']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
    from flask import send_file
    return send_file(
        output,
        download_name=filename,
        as_attachment=True,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )





# --- ROUTES ---


# --- ROUTES ---

#register route (public self-registration — always creates a plain 'user')
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username         = request.form["username"].strip()
        password         = request.form["password"]
        confirm_password = request.form["confirm_password"]
        role             = "user"  # prevent escalation; public registration is always 'user'
        email = request.form.get("email", "").strip() or None

        if email and _email_already_exists(email):
            flash("That email address is already registered to another account.","danger")
            return render_template("register.html", username=username, email=email, public=True)

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("register.html", username=username, email=email, public=True)

        errors = validate_password(password)
        if errors:
            flash("• " + "<br>• ".join(errors), "danger")
            return render_template("register.html", username=username, email=email, public=True)

        hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

        try:
            conn   = get_db_connection()
            cursor = conn.cursor(dictionary=True)

            # Public self-registration: no creator, no manager assignment
            cursor.execute(
                "INSERT INTO users (username, password, role, email, manager_id, created_by) VALUES (%s, %s, %s, %s, NULL, NULL)",
                (username, hashed, role, email)
            )
            new_user_id = cursor.lastrowid

            # Set role_id
            cursor.execute("SELECT id FROM roles WHERE name = %s", (role,))
            role_row = cursor.fetchone()
            if role_row:
                cursor.execute("UPDATE users SET role_id = %s WHERE id = %s", (role_row["id"], new_user_id))

            conn.commit()

            try:
                log_action(new_user_id, "Self registered")
            except Exception as e:
                app.logger.warning(f"Logging failed after self-registration: {e}")

            flash("Account created successfully! Please log in.", "success")
            return redirect(url_for("login"))

        except IntegrityError as e:
            if e.errno == 1062:
                flash("Username already exists!", "danger")
            else:
                flash(f"Integrity error: {e.msg}", "danger")
        except Error as e:
            flash(f"Database error: {e.msg}", "danger")
        except Exception as e:
            flash("Unexpected error occurred.", "danger")

        finally:
            if 'cursor' in locals(): cursor.close()
            if 'conn'   in locals(): conn.close()

    # GET or fallthrough from failed POST
    saved_username = request.form.get("username", "").strip() if request.method == "POST" else ""
    saved_email    = request.form.get("email", "").strip()    if request.method == "POST" else ""
    return render_template("register.html", public=True,
                           username=saved_username, email=saved_email)



#route to create user (admin)
@app.route("/admin/create-user", methods=["GET", "POST"])
@login_required()
def admin_create_user():

    caller_role = session.get("role")
    if caller_role not in ["admin", "manager"]:
        flash("Access denied.", "warning")
        return redirect(url_for("upload"))

    if caller_role == "admin":
        roles = ["user", "team_lead", "manager", "admin"]
    else:
        # manager: cannot create managers or admins
        roles = ["user", "team_lead"]

    email = ""
    selected_role = ""

    # Fetch managers for the assign-manager dropdown (admin only)
    available_managers = []
    available_tls=[]
    if caller_role == "admin":
        _conn   = get_db_connection()
        _cursor = _conn.cursor(dictionary=True)
        _cursor.execute("SELECT id, username FROM users WHERE role='manager' AND is_active=1 ORDER BY username ASC")
        available_managers = _cursor.fetchall()
        _cursor.execute("SELECT id, username FROM users WHERE role='team_lead' AND is_active=1 ORDER BY username ASC")
        available_tls=_cursor.fetchall()
        _cursor.close()
        _conn.close()

    if caller_role == "manager":
        _conn   = get_db_connection()
        _cursor = _conn.cursor(dictionary=True)
        _cursor.execute("SELECT id, username FROM users WHERE role='team_lead' AND manager_id=%s AND is_active=1 ORDER BY username ASC", (session.get("user_id"),))
        available_tls=_cursor.fetchall()
        _cursor.close()
        _conn.close()

    if request.method == "POST":
        username         = request.form.get("username", "").strip()
        password         = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        role             = request.form.get("role", "")
        email            = request.form.get("email", "").strip() or None
        selected_role = role

        if not username:
            flash("Username is required.", "danger")
            return render_template(
                "register.html",
                roles=roles,
                admin_mode=True,
                available_managers=available_managers,
                available_tls=available_tls,
                email=email,
                username=username,
                selected_role=selected_role,
            )


        if email and _email_already_exists(email):
            flash("That email address is already registered to another account.", "danger")
            return render_template(
                "register.html",
                roles=roles,
                admin_mode=True,
                available_managers=available_managers,
                available_tls=available_tls,
                email=email,
                username=username,
                selected_role=selected_role,
            )

        # Determine manager_id from the form
        # - admin creating a manager        → manager_id = NULL
        # - admin creating a team_lead/user → use the assign_manager_id dropdown
        # - manager creating a team_lead    → manager_id = the manager themselves
        # - manager creating a user         → manager_id picked from a TL dropdown (future);
        #                                     for now, assign to the manager themselves
        if role == "manager":
            new_manager_id = None
        elif role == "team_lead":
            if caller_role == "admin":
                raw=request.form.get("assign_manager_id", "").strip()
                new_manager_id=int(raw) if raw else None
            else:
                new_manager_id=session.get("user_id")
        elif role=="user":
            if caller_role in ["admin", "manager"]:
                raw=request.form.get("assign_tl_id","").strip()
                new_manager_id=int(raw) if raw else None
        else:
            new_manager_id=None

        created_by = session.get("user_id")

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template(
                "register.html",
                roles=roles,
                admin_mode=True,
                available_managers=available_managers,
                available_tls=available_tls,
                username=username,
                email=email,
                selected_role=selected_role,
            )
        
        errors = validate_password(password)
        if errors:
            flash("• " + "<br>• ".join(errors), "danger")
            return render_template(
                "register.html",
                roles=roles,
                admin_mode=True,
                available_managers=available_managers,
                available_tls=available_tls,
                username=username,
                email=email,
                selected_role=selected_role,
            )
        # Hash password
        hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

        try:
            conn   = get_db_connection()
            cursor = conn.cursor(dictionary=True)

            cursor.execute(
                "INSERT INTO users (username, password, role, email, manager_id, created_by) VALUES (%s, %s, %s, %s, %s, %s)",
                (username, hashed, role, email, new_manager_id, created_by)
            )
            conn.commit()
            new_user_id = cursor.lastrowid

            # Backfill role_id
            cursor.execute("SELECT id FROM roles WHERE name = %s", (role,))
            role_row = cursor.fetchone()
            if role_row:
                cursor.execute("UPDATE users SET role_id = %s WHERE id = %s", (role_row["id"], new_user_id))
                conn.commit()

            # Logging
            try:
                log_action(created_by, f"Created user ID {new_user_id} ('{username}') with role '{role}'")
            except Exception as e:
                app.logger.warning(f"Logging failed after user creation: {e}")

            flash("User registered successfully!", "success")
            if session.get("role") == "admin":
                return redirect(url_for("manage_users"))
            else:
                return redirect(url_for("list_users"))

        except IntegrityError as e:
            if e.errno == 1062:
                flash("Username already exists!", "danger")
            else:
                flash(f"Integrity error: {e.msg}", "danger")
        except Error as e:
            flash(f"Database error: {e.msg}", "danger")
        except Exception as e:
            flash("Unexpected error occurred.", "danger")

        finally:
            if 'cursor' in locals(): cursor.close()
            if 'conn'   in locals(): conn.close()

    return render_template(
        "register.html",
        roles=roles,
        email=email,
        selected_role=selected_role,
        admin_mode=True,
        available_managers=available_managers,
        available_tls=available_tls,
    )

#login route
@app.route("/", methods=["GET", "POST"])
def login():
    # 1. GET Request Logic
    if request.method == "GET":
        if "user_id" in session:
            return redirect(url_for("dashboard"))
        
        session.pop("user_id", None)
        session.pop("role", None)
        session.pop("last_active", None)
        session["csrf"] = secrets.token_hex(16)
        return render_template("login.html")
    
    # 2. POST Request - CSRF Validation
    form_csrf = request.form.get("csrf")
    session_csrf = session.get("csrf")
    if not form_csrf or not session_csrf or form_csrf != session_csrf:
        session.clear()
        return redirect(url_for("login"))

    # 3. Capture Credentials
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").encode("utf-8")

    try:
        # 4. THE PERSISTENCE FIX: Check lockout IMMEDIATELY
        # We do this before checking if the user even exists in the 'users' table.
        is_blocked, mins_left = check_login_rate_limit(username)
        if is_blocked:
            flash(f"Too many failed attempts. Try again in {mins_left} minute(s).", "danger")
            session["csrf"] = secrets.token_hex(16)
            # We return the template here to stop the execution entirely.
            return render_template("login.html", saved_username=username, lockout_mins=mins_left)

        # 5. Database Lookup
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute(
                "SELECT id, username, password, role, is_active, manager_id, email, requires_password_change, status FROM users WHERE username=%s",
                (username,)
            )
            user = cursor.fetchone()
        finally:
            cursor.close()
            conn.close()
    except Error as e:
        app.logger.error(f"Login database error for username '{username}': {e}")
        flash("Database is temporarily unavailable. Please try again later.", "danger")
        session["csrf"] = secrets.token_hex(16)
        return render_template("login.html", saved_username=username), 503

    # 6. Handle Missing User
    if not user:
        record_login_attempt(username, success=False)
        is_blocked, mins_left = check_login_rate_limit(username)
        if is_blocked:
            _send_lockout_alert(username)
            flash(f"Too many failed attempts. Try again in {mins_left} minute(s).", "danger")
            session["csrf"] = secrets.token_hex(16)
            return render_template("login.html", saved_username=username, lockout_mins=mins_left)
        
        flash("Invalid credentials", "danger")
        session["csrf"] = secrets.token_hex(16)
        return render_template("login.html", saved_username=username)

    # 7. Handle Disabled / Sleep / Deleted status
    user_status = user.get("status") or "active"
    if user_status == "deleted":
        flash("Invalid credentials", "danger")
        session["csrf"] = secrets.token_hex(16)
        return render_template("login.html", saved_username=username)

    if user_status in ["disabled", "deactivated"] or not user["is_active"]:
        flash("Account is deactivated. Contact admin.", "danger")
        session["csrf"] = secrets.token_hex(16)
        return render_template("login.html", saved_username=username)

    # 8. Password Validation
    if bcrypt.checkpw(password, user["password"].encode("utf-8")):
        # Login Success
        session.pop("csrf", None) # Clean up CSRF
        session["user_id"]    = user["id"]
        session["role"]       = user["role"]
        session["username"]   = user["username"]
        session["user_email"] = user.get("email")
        session["manager_id"] = user.get("manager_id")
        session["last_active"] = datetime.utcnow().isoformat()
        
        record_login_attempt(username, success=True)
        log_action(user["id"], "Logged in")

        if user.get("requires_password_change"):
            flash("Your password was reset. Please set a new password immediately for security.", "warning")

        flash("Login successful", "success")
        if user["role"] in ["team_lead", "user"]:
            return redirect(url_for("upload"))
        return redirect(url_for("dashboard"))
    
    else:
        # Password Failure
        record_login_attempt(username, success=False)
        log_action(user["id"], f"Failed login attempt for username: {username}")
        
        is_blocked, mins_left = check_login_rate_limit(username)
        if is_blocked:
            _send_lockout_alert(username)
            flash(f"Too many failed attempts. Try again in {mins_left} minute(s).", "danger")
            session["csrf"] = secrets.token_hex(16)
            return render_template("login.html", saved_username=username, lockout_mins=mins_left)
            
        flash("Invalid credentials", "danger")
        session["csrf"] = secrets.token_hex(16)
        return render_template("login.html", saved_username=username)
    

#dashboard route
@app.route("/dashboard")
@login_required()
def dashboard():
    # print("SESSION CONTENTS:", dict(session))         #debug statement
    if "user_id" not in session:
        return redirect(url_for("login"))
    
    if session.get("role") not in ROLE_PERMISSIONS:
        return redirect(url_for("login"))

    # Search keyword from query params
    search = request.args.get("search", "").strip()
    from_date = request.args.get("from_date", "")      
    to_date = request.args.get("to_date","") 

    if not from_date or not from_date.strip():
        from_date=""
    else:
        from_date = from_date.strip()

    if not to_date or not to_date.strip():
        to_date=""
    else:
        to_date = to_date.strip()
    
    page = request.args.get("page", 1, type=int)

    per_page = 10 

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    #fetch user info
    cursor.execute("SELECT username, role FROM users WHERE id = %s", (session["user_id"],))
    user=cursor.fetchone()

    # If user not found, session is invalid — redirect to login
    if user is None:
        session.clear()
        conn.close()
        flash("Session invalid. Please log in again.", "warning")
        return redirect(url_for("login"))

    # Log dashboard search activity
    if search and page == 1 and session.get("role") in ["admin", "manager"]:
        log_search(session["user_id"], session["username"], f"Logs query: {search}")

    #helper
    logs, total_logs= fetch_visible_logs(cursor,search=search, from_date=from_date, to_date=to_date, page=page, per_page=per_page)

    # Fetch dashboard metrics
    cursor.execute("SELECT COUNT(*) as count FROM logs WHERE action LIKE 'Cleaned file%'")
    total_files_row = cursor.fetchone()
    total_files = total_files_row['count'] if total_files_row else 0

    cursor.execute("SELECT SUM(total_rows) as total FROM logs")
    row_stats = cursor.fetchone()
    total_rows = (row_stats['total'] or 0) if row_stats else 0

    cursor.execute("SELECT COUNT(*) as count FROM users WHERE is_active = 1")
    active_users_row = cursor.fetchone()
    active_users = active_users_row['count'] if active_users_row else 0

    cursor.execute("SELECT COUNT(*) as count FROM logs WHERE action LIKE 'Uploaded file%' AND DATE(created_at) = CURRENT_DATE")
    uploads_today_row = cursor.fetchone()
    uploads_today = uploads_today_row['count'] if uploads_today_row else 0

    cursor.execute("SELECT created_at FROM logs WHERE action LIKE 'Uploaded file%' ORDER BY id DESC LIMIT 1")
    last_upload_row = cursor.fetchone()
    if last_upload_row and last_upload_row['created_at']:
        last_upload = last_upload_row['created_at'].strftime("%Y-%m-%d %H:%M")
    else:
        last_upload = "No recent uploads"

    cursor.execute("SELECT id, field_name FROM field_registry WHERE is_active = 1")
    custom_fields = cursor.fetchall()

    conn.close()

    total_pages = (total_logs + per_page -1 )//per_page # ceiling division
    if total_logs > 0:
        start=(page -1 ) * per_page + 1
        end = min (page * per_page, total_logs)
    else:
        start=0
        end=0

    return render_template("dashboard.html", 
                           role=session["role"],
                           logs=logs, 
                           page=page, 
                           total_pages=total_pages,
                           total_logs=total_logs,
                           start=start,
                           end=end,
                           search=search,
                           from_date=from_date,
                           to_date=to_date,
                           offset=(page-1)* per_page,
                           user=user,
                           username=user["username"],
                           current_role=user["role"],
                           form_action=url_for("dashboard"),
                           export_url=url_for("export_logs"),
                           pagination_url=lambda p: url_for(
                               "dashboard",
                               page=p,
                               search=search,
                               from_date=from_date,
                               to_date=to_date
                           ),
                           total_files=total_files,
                           total_rows=total_rows,
                           active_users=active_users,
                           uploads_today=uploads_today,
                           last_upload=last_upload,
                           custom_fields=custom_fields
                           )


@app.route("/data-health")
@login_required()
def data_health():
    role = session.get("role")
    if role in ["team_lead", "user"]:
        return redirect(url_for("upload"))
    user_id = session.get("user_id")
    page = request.args.get("page", 1, type=int) or 1
    per_page = 10

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    visible_ids = get_visible_user_ids(cursor, role=role, user_id=user_id)
    if visible_ids:
        placeholders = ", ".join(["%s"] * len(visible_ids))
        cursor.execute(
            f"""
            SELECT action, total_rows, valid_rows, invalid_rows, removed_rows,
                   rules_applied, rule_counts, created_at
            FROM logs
            WHERE action LIKE 'Cleaned file%%'
              AND user_id IN ({placeholders})
            ORDER BY created_at DESC
            """,
            visible_ids,
        )
        health_rows = cursor.fetchall()
    else:
        health_rows = []

    conn.close()

    entries = []
    for row in health_rows:
        action = row.get("action", "") or ""
        file_name = re.sub(r"^Cleaned file\s+", "", action).split(" using rules:", 1)[0].strip()

        try:
            rule_counts = json.loads(row.get("rule_counts") or "{}") or {}
        except Exception:
            rule_counts = {}

        total_rows = int(row.get("total_rows") or 0)
        valid_rows = int(row.get("valid_rows") or 0)
        invalid_rows = int(row.get("invalid_rows") or 0)
        removed_rows = int(row.get("removed_rows") or 0)

        blank_required = int(rule_counts.get("validate_not_empty", 0)) + int(rule_counts.get("handle_missing", 0))
        duplicates_flagged = int(rule_counts.get("duplicate_identifier", 0)) + int(rule_counts.get("fuzzy_duplicate", 0)) + int(rule_counts.get("duplicate_removal", 0))
        format_errors = sum(
            int(v) for k, v in rule_counts.items()
            if k.startswith("validate_") and k not in {"validate_not_empty"}
        )

        issue_labels = []
        issue_map = {
            "validate_not_empty": "Blank required field",
            "handle_missing": "Blank required field",
            "duplicate_identifier": "Duplicates flagged",
            "fuzzy_duplicate": "Duplicates flagged",
            "duplicate_removal": "Duplicates flagged",
            "validate_email": "Format errors",
            "validate_email_domain": "Format errors",
            "validate_phone": "Format errors",
            "validate_url": "Format errors",
            "validate_numeric": "Format errors",
            "validate_date": "Format errors",
        }

        for key, value in sorted(rule_counts.items()):
            if int(value or 0) > 0:
                issue_labels.append(f"{issue_map.get(key, key.replace('_', ' ').title())} ({int(value)})")

        score = round((valid_rows / total_rows) * 100, 1) if total_rows else 0
        processed_at = row.get("created_at")
        if hasattr(processed_at, "strftime"):
            processed_at_display = processed_at.strftime("%Y-%m-%d %H:%M")
        else:
            processed_at_display = str(processed_at) if processed_at else "N/A"

        entries.append({
            "file_name": file_name or "Unknown file",
            "processed_at": processed_at_display,
            "created_at": processed_at,
            "total_rows": total_rows,
            "valid_rows": valid_rows,
            "invalid_rows": invalid_rows,
            "removed_rows": removed_rows,
            "score": score,
            "blank_required": blank_required,
            "duplicates_flagged": duplicates_flagged,
            "format_errors": format_errors,
            "issues": issue_labels,
        })

    issue_entries = [e for e in entries if e.get("issues")]
    total_issue_files = len(issue_entries)
    total_pages = max(1, (total_issue_files + per_page - 1) // per_page)
    page = max(1, min(page, total_pages))
    start = (page - 1) * per_page
    paginated_entries = issue_entries[start:start + per_page]

    overall_total = sum(e["total_rows"] for e in entries)
    overall_valid = sum(e["valid_rows"] for e in entries)
    overall_score = round((overall_valid / overall_total) * 100, 1) if overall_total else 0

    now = datetime.now()
    current_period_start = now - timedelta(days=7)
    previous_period_start = now - timedelta(days=14)

    current_entries = [e for e in entries if isinstance(e.get("created_at"), datetime) and e["created_at"] >= current_period_start]
    previous_entries = [e for e in entries if isinstance(e.get("created_at"), datetime) and previous_period_start <= e["created_at"] < current_period_start]

    def compare_period(current_value, previous_value):
        if previous_value is None:
            return {
                "icon": "bi-dash",
                "color": "text-warning",
                "label": "No last week data",
            }
        if current_value < previous_value:
            return {
                "icon": "bi-arrow-down-short",
                "color": "text-success",
                "label": f"{current_value} vs last week",
            }
        if current_value == previous_value:
            return {
                "icon": "bi-dash",
                "color": "text-warning",
                "label": f"{current_value} vs last week",
            }
        return {
            "icon": "bi-arrow-up-short",
            "color": "text-danger",
            "label": f"{current_value} vs last week",
        }

    current_blank_required = sum(e["blank_required"] for e in current_entries)
    previous_blank_required = sum(e["blank_required"] for e in previous_entries) if previous_entries else None
    blank_compare = compare_period(current_blank_required, previous_blank_required)

    current_duplicates = sum(e["duplicates_flagged"] for e in current_entries)
    previous_duplicates = sum(e["duplicates_flagged"] for e in previous_entries) if previous_entries else None
    duplicates_compare = compare_period(current_duplicates, previous_duplicates)

    current_format_errors = sum(e["format_errors"] for e in current_entries)
    previous_format_errors = sum(e["format_errors"] for e in previous_entries) if previous_entries else None
    format_errors_compare = compare_period(current_format_errors, previous_format_errors)

    return render_template(
        "data_health.html",
        entries=paginated_entries,
        overall_score=overall_score,
        target_score=85,
        blank_required_total=sum(e["blank_required"] for e in entries),
        duplicates_total=sum(e["duplicates_flagged"] for e in entries),
        format_error_total=sum(e["format_errors"] for e in entries),
        blank_compare=blank_compare,
        duplicates_compare=duplicates_compare,
        format_errors_compare=format_errors_compare,
        total_files=total_issue_files,
        page=page,
        total_pages=total_pages,
        pagination_url=lambda p: url_for("data_health", page=p),
    )


#Data cleaning

@app.route('/api/clean-existing-data', methods=['GET'])
@login_required()
def api_clean_existing_data():
    if session.get("role") != "admin":
        flash("Access denied.", "warning")
        return redirect(url_for("upload"))
        
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Get physical columns dynamically
        cursor.execute("DESCRIBE master_records")
        cols = [row['Field'] for row in cursor.fetchall() if row['Field'] not in ('id', 'file_id', 'created_at', 'updated_at')]
        
        # Fetch rows
        cursor.execute("SELECT * FROM master_records")
        rows = cursor.fetchall()
        
        if not rows:
            flash("No existing database records found to clean.", "warning")
            return redirect(url_for("upload"))
            
        cursor.execute("SELECT id, field_name FROM field_registry WHERE is_active = 1")
        custom_registry = {str(r['id']): r['field_name'] for r in cursor.fetchall()}
        
        flat_rows = []
        for r in rows:
            flat_r = {}
            for col in cols:
                if col == 'custom_fields':
                    continue
                # Map to human-readable names for master fields so automapping works
                master_pretty = col.replace('_', ' ').title()
                flat_r[master_pretty] = r[col]
            if r['custom_fields']:
                try:
                    cf_dict = json.loads(r['custom_fields']) if isinstance(r['custom_fields'], str) else r['custom_fields']
                    for fid, val in cf_dict.items():
                        header_name = custom_registry.get(str(fid), f"Custom Field {fid}")
                        flat_r[header_name] = val
                except Exception:
                    pass
            flat_rows.append(flat_r)
            
        df = pd.DataFrame(flat_rows)
        
        # Save temp file as CSV for high speed (Excel export is very slow for large datasets)
        unique_filename = f"existing_db_{uuid.uuid4().hex}.csv"
        upload_folder = "Generated_Files/Uploaded"
        os.makedirs(upload_folder, exist_ok=True)
        file_path = os.path.join(upload_folder, unique_filename)
        df.to_csv(file_path, index=False)
        
        session["temp_file"] = file_path
        session["uploaded_file"] = "Existing Database Records"
        
        conn.close()
        return redirect(url_for("choose_rules"))
        
    except Exception as e:
        flash(f"Failed to load existing database data: {str(e)}", "danger")
        return redirect(url_for("upload"))

#Step 1: Upload & Show Columns
@app.route("/upload", methods=["GET", "POST"])
@login_required()
def upload():
    if "user_id" not in session or session.get("role") not in ROLE_PERMISSIONS:
        return redirect(url_for("login"))

    if request.method == "POST":
        import uuid
        import re
        import requests

        google_sheet_url = request.form.get("google_sheet_url", "").strip()
        files = []

        if google_sheet_url:
            match = re.search(r'https://docs\.google\.com/spreadsheets/d/([a-zA-Z0-9-_]+)', google_sheet_url)
            if not match:
                flash("Invalid Google Sheets URL format. Make sure it follows: https://docs.google.com/spreadsheets/d/SPREADSHEET_ID/edit...", "danger")
                return render_template("upload.html")
            
            spreadsheet_id = match.group(1)
            download_url = f"https://docs.google.com/spreadsheets/d/{spreadsheet_id}/export?format=xlsx"
            
            try:
                resp = requests.get(download_url, timeout=30)
                if resp.status_code != 200:
                    flash(f"Failed to access Google Sheet (HTTP {resp.status_code}). Please verify sharing is set to 'Anyone with the link can view'.", "danger")
                    return render_template("upload.html")
                file_content = resp.content
            except Exception as e:
                flash(f"Failed to download Google Sheet: {e}", "danger")
                return render_template("upload.html")
                
            safe_filename = "Google_Sheet.xlsx"
            ext = ".xlsx"
            unique_prefix = uuid.uuid4().hex[:8]
            temp_file_path = f"temp_{session['user_id']}_{unique_prefix}{ext}"
            with open(temp_file_path, "wb") as f:
                f.write(file_content)
                
            class MockFile:
                def __init__(self, path, name):
                    self.filename = name
                    self.path = path
                def save(self, dest):
                    import shutil
                    # Avoid copying onto itself
                    if os.path.abspath(self.path) != os.path.abspath(dest):
                        shutil.copy2(self.path, dest)
                def seek(self, offset, whence=0):
                    pass
                def tell(self):
                    return os.path.getsize(self.path)
            
            files = [MockFile(temp_file_path, safe_filename)]
        else:
            files = request.files.getlist("file")
            if not files or all(f.filename == "" for f in files):
                flash("Please select an Excel/CSV file or enter a public Google Sheets URL.", "danger")
                return render_template("upload.html")
            
        uploaded_sheets = []
        ALLOWED_EXTENSIONS = ('.xls', '.xlsx', '.csv')
        
        # User details for DB logging & background thread
        conn_user = get_db_connection()
        cursor_user = conn_user.cursor(dictionary=True)
        cursor_user.execute("SELECT username FROM users WHERE id = %s", (session["user_id"],))
        u_row = cursor_user.fetchone()
        username = u_row["username"] if u_row else "unknown"
        conn_user.close()

        total_files_processed = 0
        total_rows_all_sheets = 0
        
        for file in files:
            if not file or not file.filename.endswith(ALLOWED_EXTENSIONS):
                continue
                
            # Check file size (limit: 50MB per file)
            file.seek(0, 2)
            file_size = file.tell()
            file.seek(0)
            if file_size > 50 * 1024 * 1024:
                flash(f"File too large: {file.filename}. Maximum size is 50MB.", "danger")
                return render_template("upload.html")
                
            safe_filename = os.path.basename(file.filename)
            ext = os.path.splitext(safe_filename)[1].lower()
            
            # Save original file with distinct name to avoid collisions
            unique_prefix = uuid.uuid4().hex[:8]
            temp_file_path = f"temp_{session['user_id']}_{unique_prefix}{ext}"
            file.save(temp_file_path)
            total_files_processed += 1
            
            # Extract worksheets
            try:
                if ext == ".csv":
                    # CSV: treat as single sheet
                    try:
                        df = pd.read_csv(temp_file_path)
                    except Exception:
                        df = pd.read_csv(temp_file_path, sep=None, engine="python")
                    
                    sheet_name = "CSV"
                    safe_sheet_name = os.path.splitext(safe_filename)[0][:30]
                    # Clean special chars not allowed in sheet names
                    for c in r":\/?*[]":
                        safe_sheet_name = safe_sheet_name.replace(c, "_")
                        
                    # Save this sheet to a distinct CSV temp file
                    sheet_temp_path = f"temp_sheet_{session['user_id']}_{uuid.uuid4().hex[:8]}.csv"
                    df.to_csv(sheet_temp_path, index=False)
                    
                    # Log in uploaded_files DB
                    conn_upload = get_db_connection()
                    cursor_upload = conn_upload.cursor()
                    cursor_upload.execute(
                        "INSERT INTO uploaded_files (user_id, filename, original_filename, total_rows, status, uploaded_at) VALUES (%s, %s, %s, %s, %s, %s)",
                        (session["user_id"], sheet_temp_path, f"{safe_filename} [{sheet_name}]", len(df), 'processing', datetime.utcnow())
                    )
                    file_id = cursor_upload.lastrowid
                    conn_upload.commit()
                    conn_upload.close()
                    
                    # Background Ingestion
                    import threading
                    from helpers import ingest_uploaded_file
                    
                    def run_background_ingestion(fid, fpath, uname):
                        try:
                            ingest_uploaded_file(fid, fpath, uname)
                        except Exception:
                            pass
                    t = threading.Thread(target=run_background_ingestion, args=(file_id, sheet_temp_path, username))
                    t.daemon = True
                    t.start()
                    
                    total_rows_all_sheets += len(df)
                    uploaded_sheets.append({
                        "sheet_id": f"s_{unique_prefix}_0",
                        "original_filename": safe_filename,
                        "sheet_name": sheet_name,
                        "safe_sheet_name": safe_sheet_name,
                        "temp_path": sheet_temp_path,
                        "columns": df.columns.tolist(),
                        "total_rows": len(df),
                        "file_id": file_id
                    })
                else:
                    # Excel workbook: extract all worksheets
                    sheet_dict = pd.read_excel(temp_file_path, sheet_name=None)
                    sheet_idx = 0
                    for sheet_name, df in sheet_dict.items():
                        if df.empty or len(df.columns) == 0:
                            continue # skip empty sheets
                            
                        # Clean and format safe sheet name
                        base_name = os.path.splitext(safe_filename)[0]
                        merged_name = f"{base_name}_{sheet_name}"
                        for c in r":\/?*[]":
                            merged_name = merged_name.replace(c, "_")
                        safe_sheet_name = merged_name[:30]
                        
                        # Save this sheet to a distinct XLSX temp file
                        sheet_temp_path = f"temp_sheet_{session['user_id']}_{uuid.uuid4().hex[:8]}.xlsx"
                        df.to_excel(sheet_temp_path, index=False)
                        
                        # Log in uploaded_files DB
                        conn_upload = get_db_connection()
                        cursor_upload = conn_upload.cursor()
                        cursor_upload.execute(
                            "INSERT INTO uploaded_files (user_id, filename, original_filename, total_rows, status, uploaded_at) VALUES (%s, %s, %s, %s, %s, %s)",
                            (session["user_id"], sheet_temp_path, f"{safe_filename} [{sheet_name}]", len(df), 'processing', datetime.utcnow())
                        )
                        file_id = cursor_upload.lastrowid
                        conn_upload.commit()
                        conn_upload.close()
                        
                        # Background Ingestion
                        import threading
                        from helpers import ingest_uploaded_file
                        
                        def run_background_ingestion(fid, fpath, uname):
                            try:
                                ingest_uploaded_file(fid, fpath, uname)
                            except Exception:
                                pass
                        t = threading.Thread(target=run_background_ingestion, args=(file_id, sheet_temp_path, username))
                        t.daemon = True
                        t.start()
                        
                        total_rows_all_sheets += len(df)
                        uploaded_sheets.append({
                            "sheet_id": f"s_{unique_prefix}_{sheet_idx}",
                            "original_filename": safe_filename,
                            "sheet_name": sheet_name,
                            "safe_sheet_name": safe_sheet_name,
                            "temp_path": sheet_temp_path,
                            "columns": df.columns.tolist(),
                            "total_rows": len(df),
                            "file_id": file_id
                        })
                        sheet_idx += 1
            except Exception as e:
                flash(f"Could not read file {safe_filename}: {e}", "danger")
                return render_template("upload.html")
                
        if not uploaded_sheets:
            flash("No valid worksheets with data found to process.", "danger")
            return render_template("upload.html")
            
        session["uploaded_sheets"] = uploaded_sheets
        # For backwards compatibility with other screens
        session["uploaded_file"] = uploaded_sheets[0]["original_filename"] if len(uploaded_sheets) == 1 else f"{total_files_processed} files ({len(uploaded_sheets)} sheets)"
        session["temp_file"] = uploaded_sheets[0]["temp_path"]
        session.pop("selected_rules", None) # Clear old rules
        
        # Log general action
        log_action(session["user_id"], f"Uploaded {total_files_processed} files with {len(uploaded_sheets)} sheets ({total_rows_all_sheets} total rows)")
        
        # Notify team lead
        try:
            from helpers import notify_team_lead_action
            notify_team_lead_action(session["user_id"], "upload", session["uploaded_file"])
        except Exception:
            pass
            
        return redirect(url_for("choose_rules"))
    
    return render_template("upload.html")


#Step 2: Choose cleaning rules (helps in re-selecting rules)
from collections import defaultdict

@app.route("/choose_rules", methods=["GET"])
@login_required()
def choose_rules():
    if "user_id" not in session or session.get("role") not in ROLE_PERMISSIONS:
        return redirect(url_for("login"))
   
    uploaded_sheets = session.get("uploaded_sheets", [])
    if not uploaded_sheets:
        temp_path = session.get("temp_file")
        if temp_path and os.path.exists(temp_path):
            safe_filename = session.get("uploaded_file", "data_file")
            ext = os.path.splitext(temp_path)[1].lower()
            sheet_name = "CSV" if ext == ".csv" else "Sheet1"
            import uuid
            uploaded_sheets = [{
                "sheet_id": f"s_legacy_{uuid.uuid4().hex[:8]}",
                "original_filename": safe_filename,
                "sheet_name": sheet_name,
                "safe_sheet_name": "legacy_sheet",
                "temp_path": temp_path,
                "columns": [],
                "total_rows": 0,
                "file_id": 0
            }]
            session["uploaded_sheets"] = uploaded_sheets
            
    if not uploaded_sheets:
        flash("No file uploaded. Please upload first.", "warning")
        return redirect(url_for("upload"))

    selected_rules = session.get("selected_rules", [])
    column_rule_map = defaultdict(list)
    selected_strategy_map = {}

    for rule_tuple in selected_rules:
        rule_name = rule_tuple[0]
        column = rule_tuple[1]
        column_rule_map[column].append(rule_name)
        if rule_name == "handle_missing" and len(rule_tuple) > 2:
            selected_strategy_map[column] = rule_tuple[2]

    presets = []
    custom_fields_registry = []
    master_fields = [
        {"name": "Full Name", "identifier": "full_name", "type": "text"},
        {"name": "Email Address", "identifier": "email_address", "type": "email"},
        {"name": "Primary Phone Number", "identifier": "primary_phone_number", "type": "phone"},
        {"name": "Alternate Phone Number", "identifier": "alternate_phone_number", "type": "phone"},
        {"name": "Company Name", "identifier": "company_name", "type": "text"},
        {"name": "Job Title", "identifier": "job_title", "type": "text"},
        {"name": "Department", "identifier": "department", "type": "text"},
        {"name": "Website URL", "identifier": "website_url", "type": "url"},
        {"name": "Address Line 1", "identifier": "address_line_1", "type": "text"},
        {"name": "Address Line 2", "identifier": "address_line_2", "type": "text"},
        {"name": "City", "identifier": "city", "type": "text"},
        {"name": "State / Province", "identifier": "state_province", "type": "text"},
        {"name": "Postal / ZIP Code", "identifier": "postal_zip_code", "type": "text"},
        {"name": "Country", "identifier": "country", "type": "text"},
        {"name": "LinkedIn Profile URL", "identifier": "linkedin_profile_url", "type": "url"},
        {"name": "Industry", "identifier": "industry", "type": "text"},
        {"name": "Lead Source", "identifier": "lead_source", "type": "text"},
        {"name": "Record Status", "identifier": "record_status", "type": "text"},
        {"name": "Date of Birth", "identifier": "date_of_birth", "type": "date"},
        {"name": "Gender", "identifier": "gender", "type": "text"},
        {"name": "Company Size", "identifier": "company_size", "type": "text"},
        {"name": "Annual Revenue", "identifier": "annual_revenue", "type": "numeric"}
    ]

    sheet_data = []
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT id, name FROM rule_presets WHERE user_id = %s ORDER By name",
            (session["user_id"],)
        )
        presets = cursor.fetchall()
        
        # Load active custom fields
        cursor.execute("SELECT id, field_name FROM field_registry WHERE is_active = 1")
        custom_fields_registry = cursor.fetchall()
        
        # Populate sheet details
        for sheet in uploaded_sheets:
            spath = sheet["temp_path"]
            if spath.endswith(".csv"):
                df = pd.read_csv(spath)
            else:
                df = pd.read_excel(spath)
                
            cols = df.columns.tolist()
            # Update columns list in sheet dict
            sheet["columns"] = cols
            
            column_type_map = {
                c: resolve_column_type(df, c)
                for c in cols
            }
            
            column_rule_options = {}
            for c in cols:
                col_type = column_type_map[c]
                allowed_rules = []
                for rule_key, rule_meta in RULES_REGISTRY.items():
                    if col_type in rule_meta.get("allowed_types", []):
                        allowed_rules.append(rule_key)
                column_rule_options[c] = allowed_rules
                
            identifier_columns = detect_identifier_columns(df)
            suggestions = suggest_column_mapping(cols, cursor)
            
            sheet_data.append({
                "sheet_id": sheet["sheet_id"],
                "original_filename": sheet["original_filename"],
                "sheet_name": sheet["sheet_name"],
                "safe_sheet_name": sheet["safe_sheet_name"],
                "columns": cols,
                "column_type_map": column_type_map,
                "column_rule_options": column_rule_options,
                "identifier_columns": identifier_columns,
                "suggestions": suggestions
            })
            
    except Exception as e:
        app.logger.error(f"Error preparing choose_rules sheet metadata: {e}")
        flash("Error reading uploaded sheets.", "danger")
        return redirect(url_for("upload"))
    finally:
        if conn is not None:
            conn.close()

    # Backwards compatibility fields for first sheet
    first_sheet = sheet_data[0] if sheet_data else {}
    
    return render_template("choose_rules.html",
                           columns=first_sheet.get("columns", []),
                           selected_rule_map=column_rule_map,
                           selected_rules=selected_rules,
                           selected_strategy_map=selected_strategy_map,
                           uploaded_file=session.get("uploaded_file"),
                           column_rule_options=first_sheet.get("column_rule_options", {}),
                           RULES_REGISTRY=RULES_REGISTRY,
                           presets=presets,
                           column_type_map=first_sheet.get("column_type_map", {}),
                           identifier_columns=first_sheet.get("identifier_columns", []),
                           master_fields=master_fields,
                           custom_fields_registry=custom_fields_registry,
                           suggestions=first_sheet.get("suggestions", {}),
                           sheet_data=sheet_data)

import os
import glob




#Step 3: Apply rules -> Preview cleaned data
@app.route("/clean", methods=["POST"])
@login_required()
def clean_data():
    if "user_id" not in session or session.get("role") not in ROLE_PERMISSIONS:
        return redirect(url_for("login"))
    
    uploaded_sheets = session.get("uploaded_sheets", [])
    if not uploaded_sheets:
        temp_path = session.get("temp_file")
        if temp_path and os.path.exists(temp_path):
            safe_filename = session.get("uploaded_file", "data_file")
            ext = os.path.splitext(temp_path)[1].lower()
            sheet_name = "CSV" if ext == ".csv" else "Sheet1"
            import uuid
            uploaded_sheets = [{
                "sheet_id": f"s_legacy_{uuid.uuid4().hex[:8]}",
                "original_filename": safe_filename,
                "sheet_name": sheet_name,
                "safe_sheet_name": "legacy_sheet",
                "temp_path": temp_path,
                "columns": [],
                "total_rows": 0,
                "file_id": 0
            }]
            session["uploaded_sheets"] = uploaded_sheets

    if not uploaded_sheets:
        flash("No files found to clean. Please upload again.", "danger")
        return redirect(url_for("upload"))

    # Read master rules configurations from form
    master_rules_saved = {}
    master_fields_ids = [
        "full_name", "email_address", "primary_phone_number", "alternate_phone_number",
        "company_name", "job_title", "department", "website_url", "address_line_1",
        "address_line_2", "city", "state_province", "postal_zip_code", "country",
        "linkedin_profile_url", "industry", "lead_source", "record_status", "date_of_birth",
        "gender", "company_size", "annual_revenue"
    ]
    for col_name in master_fields_ids:
        rules_list = request.form.getlist(f"rules_master_{col_name}[]")
        strategy = request.form.get(f"strategy_master_{col_name}", "flag")
        if rules_list:
            master_rules_saved[col_name] = {"rules": rules_list, "strategy": strategy}

    # Read custom rules by field id
    custom_rules_by_field_id = {}
    for x in range(100):
        target_cf = request.form.get(f"custom_field_target_{x}")
        if target_cf:
            rules = request.form.getlist(f"rules_custom_{x}[]")
            strategy = request.form.get(f"strategy_custom_{x}", "flag")
            custom_rules_by_field_id[target_cf] = {"rules": rules, "strategy": strategy}

    session["master_rules_saved"] = master_rules_saved
    session["custom_rules_saved"] = custom_rules_by_field_id

    # We will run cleaning on each sheet separately
    results = []
    total_before = 0
    valid_after = 0
    invalid_after = 0
    removed_count = 0
    
    all_detailed_errors = []
    all_system_warnings = []
    
    # Combined rules applied list for logging
    combined_selected_rules = []
    
    # Type overrides maps per sheet column (mostly empty but supported)
    type_overrides = {}
    
    for sheet in uploaded_sheets:
        sheet_id = sheet["sheet_id"]
        spath = sheet["temp_path"]
        
        if spath.endswith(".csv"):
            df = pd.read_csv(spath)
        else:
            df = pd.read_excel(spath)
            
        sheet_total_before = len(df)
        total_before += sheet_total_before
        
        # Build mapping rules for this sheet
        sheet_selected_rules = []
        for column in df.columns:
            safe_col = column.replace(" ", "_")
            # Try to get map target scoped by sheet_id first
            target = request.form.get(f"map_col_{sheet_id}_{safe_col}")
            if not target:
                # Backwards compatibility fallback
                target = request.form.get(f"map_col_{safe_col}")
                
            if not target or target == 'ignore':
                continue
                
            rules_list = []
            strategy = "flag"
            
            if target.startswith("master:"):
                col_name = target.split("master:")[1]
                rules_list = master_rules_saved.get(col_name, {}).get("rules", [])
                strategy = master_rules_saved.get(col_name, {}).get("strategy", "flag")
            elif target.startswith("custom:"):
                fid = target.split("custom:")[1]
                rules_list = custom_rules_by_field_id.get(fid, {}).get("rules", [])
                strategy = custom_rules_by_field_id.get(fid, {}).get("strategy", "flag")
                
            for rule_name in rules_list:
                rule_name = rule_name.strip()
                rule_tuple = (rule_name, column, strategy) if rule_name == "handle_missing" else (rule_name, column)
                sheet_selected_rules.append(rule_tuple)
                combined_selected_rules.append(rule_tuple)

        # Build Engine Rule List for this sheet
        engine_rules = []
        dup_columns = []
        for rule_tuple in sheet_selected_rules:
            rule_name = rule_tuple[0]
            column = rule_tuple[1]
            if rule_name == "drop_duplicates":
                dup_columns.append(column)
            else:
                engine_rules.append(rule_tuple)

        # Run Cleaning Engine on this sheet
        cleaned_df, invalid_df, removed_rows, detailed_errors, incompatibility_errors, cleaning_summary = run_cleaning_pipeline(
            df=df,
            selected_rules=engine_rules,
            duplicate_columns=dup_columns,
            type_overrides=type_overrides
        )
        
        valid_after += len(cleaned_df)
        invalid_after += len(invalid_df)
        removed_count += len(removed_rows)
        
        all_detailed_errors.extend(detailed_errors)
        all_system_warnings.extend(incompatibility_errors)
        
        results.append({
            "safe_sheet_name": sheet["safe_sheet_name"],
            "cleaned_df": cleaned_df,
            "invalid_df": invalid_df,
            "removed_rows": removed_rows
        })

    session["selected_rules"] = combined_selected_rules

    if total_before == 0:
        flash("Please upload files containing records.", "warning")
        return redirect(url_for("choose_rules"))

    # Cleanup previous run files
    cleanup_old_session_files()
    
    # Save Files
    from datetime import datetime
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    raw_uploaded = session.get("uploaded_file", "data_file")
    base_name = "".join(c for c in raw_uploaded if c.isalnum() or c in "._- ").strip()
    if not base_name or len(base_name) > 60:
        base_name = "data_file"

    cleaned_file = os.path.join("Generated_Files","Cleaned",f"{session['user_id']}_{base_name}_cleaned_{timestamp}.xlsx")
    with pd.ExcelWriter(cleaned_file, engine='openpyxl') as writer:
        for r in results:
            r["cleaned_df"].to_excel(writer, sheet_name=r["safe_sheet_name"], index=False)

    invalid_file = None
    any_invalid = any(not r["invalid_df"].empty for r in results)
    if any_invalid:
        invalid_file = os.path.join("Generated_Files","Invalid",f"{session['user_id']}_{base_name}_invalid_{timestamp}.xlsx")
        with pd.ExcelWriter(invalid_file, engine='openpyxl') as writer:
            for r in results:
                r["invalid_df"].to_excel(writer, sheet_name=r["safe_sheet_name"], index=False)

    removed_file = None
    any_removed = any(not r["removed_rows"].empty for r in results)
    if any_removed:
        removed_file = os.path.join("Generated_Files","Removed",f"{session['user_id']}_{base_name}_removed_{timestamp}.xlsx")
        with pd.ExcelWriter(removed_file, engine='openpyxl') as writer:
            for r in results:
                r["removed_rows"].to_excel(writer, sheet_name=r["safe_sheet_name"], index=False)

    # Generate Preview Table (Concatenate cleaned rows from all sheets for preview)
    preview_dfs = [r["cleaned_df"] for r in results if not r["cleaned_df"].empty]
    if preview_dfs:
        merged_preview_df = pd.concat(preview_dfs, ignore_index=True)
    else:
        merged_preview_df = results[0]["cleaned_df"]
        
    preview = merged_preview_df.reset_index(drop=True).head(15).to_html(
        classes="table table-hover align-middle",
        index=False,
        header=True,
        border=0,
        justify="left"
    )

    # Generate Summary
    summary = generate_summary(
        total_before,
        valid_after,
        [e.get("message", "Unknown error") for e in all_detailed_errors]
    )

    # Group Errors
    grouped_errors = defaultdict(list)
    for error in all_detailed_errors:
        grouped_errors[error["rule"]].append(error)
    
    # Logging
    column_rule_map = defaultdict(list)
    for rule_tuple in combined_selected_rules:
        rule_name = rule_tuple[0]
        column = rule_tuple[1]
        rule_meta = RULES_REGISTRY.get(rule_name, {})
        display_name = rule_meta.get("label") or rule_name
        column_rule_map[column].append(display_name)

    selected_filters_display = [
        {
            "column": column,
            "rule": ", ".join(rules)
        }
        for column, rules in column_rule_map.items()
    ]
    
    filters_count = sum(len(rules) for rules in column_rule_map.values())
    rules_applied = [
        f"{column} ({', '.join(rules)})"
        for column, rules in column_rule_map.items()
    ]

    log_action(
        session["user_id"],
        f"Cleaned file {session['uploaded_file']} using rules: {', '.join(rules_applied)}",
        total=total_before,
        valid=valid_after,
        invalid=invalid_after,
        removed=removed_count,
        rules_applied=[(r[0],r[1]) for r in combined_selected_rules],
        rule_counts={}
    )

    session["cleaned_file"] = cleaned_file
    session["invalid_file"] = invalid_file
    session["removed_file"] = removed_file

    # Notify team lead
    try:
        from helpers import notify_team_lead_action
        notify_team_lead_action(session["user_id"], "clean", session["uploaded_file"])
    except Exception:
        pass

    # ── Store in DB if requested ──────────────────────────────────────────────
    store_in_db = request.form.get("store_in_db", "0") == "1"
    db_stored_count = 0
    db_store_error  = None

    if store_in_db:
        # Master field identifier → DB column name (1-to-1 match by convention)
        MASTER_FIELD_IDENTIFIERS = {
            "full_name", "email_address", "primary_phone_number", "alternate_phone_number",
            "company_name", "job_title", "department", "website_url", "address_line_1",
            "address_line_2", "city", "state_province", "postal_zip_code", "country",
            "linkedin_profile_url", "industry", "lead_source", "record_status",
            "date_of_birth", "gender", "company_size", "annual_revenue"
        }

        # Build per-sheet column → master_field mapping from form data
        # map_col_{sheet_id}_{safe_col} = "master:<identifier>" or "custom:<id>" or "ignore"
        sheet_col_mappings = {}  # { sheet_id: { original_col: master_identifier or None } }
        for sheet in uploaded_sheets:
            sid = sheet["sheet_id"]
            sheet_col_mappings[sid] = {}
            # Read columns from results to get actual df columns
            for res in results:
                if res.get("safe_sheet_name") == sheet["safe_sheet_name"]:
                    for col in res["cleaned_df"].columns:
                        safe_col = col.replace(" ", "_")
                        target = request.form.get(f"map_col_{sid}_{safe_col}") or \
                                 request.form.get(f"map_col_{safe_col}")
                        if target and target.startswith("master:"):
                            master_id = target.split("master:")[1]
                            if master_id in MASTER_FIELD_IDENTIFIERS:
                                sheet_col_mappings[sid][col] = master_id

        try:
            conn_store = get_db_connection()
            cursor_store = conn_store.cursor()
            from datetime import datetime as _dt
            imported_by = session.get("username") or str(session.get("user_id", "unknown"))
            now = _dt.utcnow()

            for sheet, res in zip(uploaded_sheets, results):
                sid = sheet["sheet_id"]
                mapping = sheet_col_mappings.get(sid, {})
                if not mapping:
                    continue  # no master columns mapped for this sheet — skip

                cleaned = res["cleaned_df"]
                for _, row in cleaned.iterrows():
                    record = {field: None for field in MASTER_FIELD_IDENTIFIERS}
                    for col, master_id in mapping.items():
                        val = row.get(col)
                        if val is not None and str(val).strip() not in ("", "nan", "NaT"):
                            record[master_id] = str(val).strip()

                    cursor_store.execute("""
                        INSERT INTO master_records (
                            file_id, full_name, email_address, primary_phone_number,
                            alternate_phone_number, company_name, job_title, department,
                            website_url, address_line_1, address_line_2, city, state_province,
                            postal_zip_code, country, linkedin_profile_url, industry,
                            lead_source, record_status, date_of_birth, gender,
                            company_size, annual_revenue, created_at, updated_at, imported_by
                        ) VALUES (
                            %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s
                        )
                    """, (
                        sheet.get("file_id", 0),
                        record["full_name"], record["email_address"],
                        record["primary_phone_number"], record["alternate_phone_number"],
                        record["company_name"], record["job_title"], record["department"],
                        record["website_url"], record["address_line_1"], record["address_line_2"],
                        record["city"], record["state_province"], record["postal_zip_code"],
                        record["country"], record["linkedin_profile_url"], record["industry"],
                        record["lead_source"], record["record_status"], record["date_of_birth"],
                        record["gender"], record["company_size"], record["annual_revenue"],
                        now, now, imported_by
                    ))
                    db_stored_count += 1

            conn_store.commit()
            conn_store.close()
            flash(f"✅ {db_stored_count} cleaned record(s) saved to the database successfully.", "success")
            log_action(session["user_id"], f"Stored {db_stored_count} cleaned records to master_records DB")

        except Exception as _db_err:
            db_store_error = str(_db_err)
            app.logger.error(f"DB store error during clean: {_db_err}")
            flash(f"Cleaning completed but DB storage failed: {_db_err}", "warning")
            try:
                conn_store.rollback()
                conn_store.close()
            except Exception:
                pass
    # ─────────────────────────────────────────────────────────────────────────

    if valid_after == 0:
        all_detailed_errors.append({
            "rule" : "dataset_empty",
            "column" : None,
            "row_index" : None,
            "message" : "All rows removed after applying filters."
        })

    # FINAL RENDER
    return render_template(
        "preview.html",
        preview_table=preview,
        file=cleaned_file,
        uploaded_file=session.get("uploaded_file"),
        invalid_file=invalid_file,
        removed_file=removed_file,
        summary=summary,
        total=total_before,
        valid=valid_after,
        invalid=invalid_after,
        grouped_errors=grouped_errors,
        selected_filters=selected_filters_display,
        filters_count=filters_count,
        system_warnings=all_system_warnings,
        cleaning_summary={},
        cleaned_rows=valid_after,
        invalid_rows=invalid_after,
        removed=removed_count,
        store_in_db=store_in_db,
        db_stored_count=db_stored_count
    )


# Step 4: Download cleaned file and invalid rows after preview
@app.route("/download/<path:filename>")
@login_required()
def download(filename):

    filename=filename.strip()

    if "user_id" not in session or session.get("role") not in ROLE_PERMISSIONS:
        return redirect(url_for("login"))
        
    if session.get("role") in ["team_lead", "user"]:
        flash("Access denied.", "danger")
        return redirect(url_for("upload"))
    
    #only allow downloading files generated in this session

    session_files= {
        f for f in [
            session.get("cleaned_file"),
            session.get("invalid_file"),
            session.get("removed_file")
        ] if f
    }

    if filename not in session_files:
        flash("Unauthorized file access.", "danger")
        return redirect(url_for("upload"))
    
    if os.path.exists(filename):
        log_action(session["user_id"], f"Downloaded file {filename}")
        return send_file(filename, as_attachment=True, download_name=filename)
    
    flash("File not found.", "danger")
    return redirect(url_for("upload"))


# ── Downloads page ─────────────────────────────────────────────────────────────

@app.route("/downloads")
@login_required()
def downloads():
    role = session.get("role")
    user_id = session.get("user_id")

    if role not in ("admin", "manager"):
        flash("Access denied.", "warning")
        return redirect(url_for("upload"))

    # --- Filter params ---
    selected_types = request.args.getlist("types") or ["cleaned", "invalid", "removed"]
    selected_user  = request.args.get("user_id", "").strip()
    from_date      = request.args.get("from_date", "").strip()
    to_date        = request.args.get("to_date", "").strip()
    search         = request.args.get("search", "").strip()
    hist_page      = request.args.get("hist_page", 1, type=int)
    hist_per_page  = 12

    # --- Fetch visible users for filter dropdown ---
    conn   = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    visible_ids = get_visible_user_ids(cursor, role=role, user_id=user_id)
    if role == "admin":
        visible_ids = visible_ids  # all users
    # Include the caller themselves
    if user_id not in visible_ids:
        visible_ids.append(user_id)

    if visible_ids:
        placeholders = ", ".join(["%s"] * len(visible_ids))
        cursor.execute(
            f"SELECT id, username, role FROM users WHERE id IN ({placeholders}) ORDER BY username",
            visible_ids
        )
        visible_users = cursor.fetchall()
    else:
        visible_users = []

    # --- Narrow visible_ids if a specific user is selected ---
    if selected_user and selected_user.isdigit():
        filter_ids = [int(selected_user)] if int(selected_user) in visible_ids else []
    else:
        filter_ids = visible_ids

    # --- Scan Generated_Files directory for files belonging to visible users ---
    import glob as _glob
    from datetime import datetime as _dt

    base_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Generated_Files")
    type_dirs = {"cleaned": "Cleaned", "invalid": "Invalid", "removed": "Removed"}

    all_files = []
    for ftype, subdir in type_dirs.items():
        if ftype not in selected_types:
            continue
        pattern = os.path.join(base_dir, subdir, "*.xlsx")
        for fpath in _glob.glob(pattern):
            fname = os.path.basename(fpath)
            rel   = os.path.join("Generated_Files", subdir, fname)

            # Check ownership via user_id prefix in filename
            fn_parts = fname.split("_", 1)
            if len(fn_parts) == 2 and fn_parts[0].isdigit():
                file_owner_id = int(fn_parts[0])
                display_name = fn_parts[1]
            else:
                file_owner_id = None
                display_name = fname

            # Skip files not owned by visible users / self, unless admin
            if role != "admin" and file_owner_id is not None and file_owner_id not in visible_ids:
                continue

            # Date filter from filename timestamp (format: name_YYYYMMDD_HHMMSS.xlsx)
            try:
                parts    = display_name.rsplit("_", 2)
                file_dt  = _dt.strptime(parts[-2] + parts[-1].replace(".xlsx", ""), "%Y%m%d%H%M%S")
            except Exception:
                file_dt = _dt.fromtimestamp(os.path.getmtime(fpath))

            if from_date:
                try:
                    if file_dt.date() < _dt.strptime(from_date, "%Y-%m-%d").date():
                        continue
                except Exception:
                    pass
            if to_date:
                try:
                    if file_dt.date() > _dt.strptime(to_date, "%Y-%m-%d").date():
                        continue
                except Exception:
                    pass
            if search and search.lower() not in display_name.lower():
                continue

            size_kb = round(os.path.getsize(fpath) / 1024, 1)
            all_files.append({
                "rel_path":    rel,
                "display_name": display_name,
                "type":        ftype,
                "size_kb":     size_kb,
                "date":        file_dt.strftime("%Y-%m-%d %H:%M"),
                "sort_key":    file_dt,
            })

    all_files.sort(key=lambda x: x["sort_key"], reverse=True)
    total_files = len(all_files)

    # --- Export history from logs table ---
    # Download logs have action text starting with "Downloaded file"
    if filter_ids:
        ph2 = ", ".join(["%s"] * len(filter_ids))
        cursor.execute(f"""
            SELECT l.id, l.user_id, l.action, l.created_at,
                   u.username, u.role
            FROM logs l
            JOIN users u ON l.user_id = u.id
            WHERE l.action LIKE 'Downloaded file%%'
              AND l.user_id IN ({ph2})
            ORDER BY l.created_at DESC
            LIMIT %s OFFSET %s
        """, filter_ids + [hist_per_page, (hist_page - 1) * hist_per_page])
        export_rows = cursor.fetchall()

        cursor.execute(f"""
            SELECT COUNT(*) AS cnt FROM logs l
            WHERE l.action LIKE 'Downloaded file%%'
              AND l.user_id IN ({ph2})
        """, filter_ids)
        total_exports = (cursor.fetchone() or {}).get("cnt", 0)
    else:
        export_rows   = []
        total_exports = 0

    conn.close()

    # Enrich export rows
    for row in export_rows:
        # Extract filename from action text
        raw = row["action"].replace("Downloaded file ", "").strip()
        row["rel_path"]     = raw
        row["display_name"] = os.path.basename(raw)
        row["file_exists"]  = os.path.exists(raw)

        # Derive file type from directory path
        lower = raw.lower()
        if "cleaned" in lower:
            row["file_type"] = "cleaned"
        elif "invalid" in lower:
            row["file_type"] = "invalid"
        elif "removed" in lower:
            row["file_type"] = "removed"
        else:
            row["file_type"] = "logs"

    hist_total_pages = max(1, (total_exports + hist_per_page - 1) // hist_per_page)
    hist_start = (hist_page - 1) * hist_per_page + 1 if total_exports > 0 else 0
    hist_end   = min(hist_page * hist_per_page, total_exports)

    return render_template(
        "downloads.html",
        files=all_files,
        total_files=total_files,
        visible_users=visible_users,
        selected_types=selected_types,
        selected_user=selected_user,
        from_date=from_date,
        to_date=to_date,
        search=search,
        export_logs=export_rows,
        total_exports=total_exports,
        hist_page=hist_page,
        hist_total_pages=hist_total_pages,
        hist_start=hist_start,
        hist_end=hist_end,
        hist_page_url=lambda p: url_for(
            "downloads",
            hist_page=p,
            types=selected_types,
            user_id=selected_user,
            from_date=from_date,
            to_date=to_date,
            search=search,
        ),
    )


@app.route("/downloads/selected", methods=["POST"])
@login_required()
def download_selected():
    """Package selected Generated_Files into a ZIP and stream it."""
    role = session.get("role")
    if role not in ("admin", "manager", "team_lead"):
        flash("Access denied.", "warning")
        return redirect(url_for("dashboard"))

    filenames = request.form.getlist("filenames")
    if not filenames:
        flash("No files selected.", "warning")
        return redirect(url_for("downloads"))

    # Enforce RBAC for checking ownership on list
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    visible_ids = get_visible_user_ids(cursor, role=role, user_id=session.get("user_id"))
    conn.close()

    if session.get("user_id") not in visible_ids:
        visible_ids.append(session.get("user_id"))

    # Safety: only allow paths inside Generated_Files
    allowed_base = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Generated_Files")
    safe_files   = []
    for rel in filenames:
        abs_path = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), rel))
        if abs_path.startswith(allowed_base) and os.path.exists(abs_path):
            # Authorize: check user ID prefix
            fname = os.path.basename(abs_path)
            parts = fname.split("_", 1)
            if len(parts) == 2 and parts[0].isdigit():
                file_owner_id = int(parts[0])
                if role != "admin" and file_owner_id not in visible_ids:
                    # skip unauthorized file access
                    continue
            safe_files.append((rel, abs_path))

    if not safe_files:
        flash("None of the selected files could be found or you lack permission to download them.", "danger")
        return redirect(url_for("downloads"))

    import zipfile as _zf
    buf = BytesIO()
    with _zf.ZipFile(buf, "w", _zf.ZIP_DEFLATED) as zf:
        for rel, abs_path in safe_files:
            fname = os.path.basename(abs_path)
            parts = fname.split("_", 1)
            zip_member_name = parts[1] if (len(parts) == 2 and parts[0].isdigit()) else fname
            zf.write(abs_path, zip_member_name)
            log_action(session["user_id"], f"Downloaded file {rel}")

    buf.seek(0)
    zip_name = f"paramantra_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
    return send_file(buf, as_attachment=True, download_name=zip_name,
                     mimetype="application/zip")


@app.route("/downloads/admin/<path:filename>")
@login_required()
def download_admin(filename):
    """Re-download any Generated_File by relative path (admin/manager/team_lead only)."""
    role = session.get("role")
    if role not in ("admin", "manager", "team_lead"):
        flash("Access denied.", "warning")
        return redirect(url_for("dashboard"))

    abs_path = os.path.normpath(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
    )
    allowed_base = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Generated_Files")

    if not abs_path.startswith(allowed_base):
        flash("Invalid file path.", "danger")
        return redirect(url_for("downloads"))

    if not os.path.exists(abs_path):
        flash("File no longer exists on disk.", "warning")
        return redirect(url_for("downloads"))

    # Authorize: check user ID prefix against visible IDs
    fname = os.path.basename(abs_path)
    parts = fname.split("_", 1)
    if len(parts) == 2 and parts[0].isdigit():
        file_owner_id = int(parts[0])
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        visible_ids = get_visible_user_ids(cursor, role=role, user_id=session.get("user_id"))
        conn.close()

        if session.get("user_id") not in visible_ids:
            visible_ids.append(session.get("user_id"))

        if role != "admin" and file_owner_id not in visible_ids:
            flash("Access denied. You cannot download files uploaded by other users.", "warning")
            return redirect(url_for("downloads"))

        download_name = parts[1]
    else:
        download_name = fname

    log_action(session["user_id"], f"Downloaded file {filename}")
    return send_file(abs_path, as_attachment=True, download_name=download_name)


#logout route

@app.route("/logout")
@login_required()
def logout():
    if "user_id" in session:
        log_action(session["user_id"], "Logged out")

    session.clear()
    session.modified = True

    resp= redirect(url_for("login"))
    resp.headers["Cache-Control"]="no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"]="no-cache"
    resp.headers["Expires"]="0"

    return resp


#export logs route
@app.route("/admin/logs/export")
@app.route("/api/logs/export")
@login_required()
def export_logs():
    if "user_id" not in session:
        flash("Please log in to continue.", "warning")
        return redirect(url_for("login"))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    visible_user_ids = get_visible_user_ids(cursor)

    if not visible_user_ids:
        conn.close()
        flash("No data available.", "info")
        return redirect(url_for("dashboard"))

    placeholders = ",".join(["%s"] * len(visible_user_ids))
    query = f"""
        SELECT logs.id, users.username, logs.action, logs.total_rows,
               logs.valid_rows, logs.invalid_rows, logs.created_at
        FROM logs
        JOIN users ON logs.user_id = users.id
        WHERE logs.user_id IN ({placeholders})
        ORDER BY logs.created_at DESC
    """
    cursor.execute(query + " LIMIT 10000", tuple(visible_user_ids))
    logs = cursor.fetchall()
    conn.close()

    # Log action
    log_action(session["user_id"], f"Exported {len(logs)} system activity logs to Excel")

    # Format dates
    formatted_logs = []
    for l in logs:
        formatted_logs.append({
            "Log ID": l["id"],
            "Username": l["username"],
            "Action Performed": l["action"],
            "Total Rows": l["total_rows"],
            "Valid Rows": l["valid_rows"],
            "Invalid Rows": l["invalid_rows"],
            "Timestamp": l["created_at"].isoformat() if l["created_at"] else ""
        })

    import pandas as pd
    import io
    df = pd.DataFrame(formatted_logs)
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, sheet_name='System Logs', index=False)
    output.seek(0)

    filename = f"system_logs_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name=filename
    )


@app.route('/api/history/file-records/export', methods=['GET'])
@login_required()
def export_file_records():
    file_id = request.args.get('file_id')
    record_type = request.args.get('type')
    
    if not file_id or not record_type:
        return jsonify({"error": "Missing file_id or type parameter"}), 400
        
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("DESCRIBE master_records")
        cols = [row['Field'] for row in cursor.fetchall() if row['Field'] not in ('id', 'file_id', 'created_at', 'updated_at')]
        
        cursor.execute("SELECT id, field_name FROM field_registry WHERE is_active = 1")
        custom_registry = {str(r['id']): r['field_name'] for r in cursor.fetchall()}
        
        records_list = []
        
        if record_type == 'imported':
            cursor.execute("SELECT * FROM master_records WHERE file_id = %s ORDER BY id ASC", (file_id,))
            rows = cursor.fetchall()
            for r in rows:
                flat_r = {}
                for col in cols:
                    if col == 'custom_fields':
                        continue
                    flat_r[col.replace('_', ' ').title()] = r[col]
                if r['custom_fields']:
                    try:
                        cf_dict = json.loads(r['custom_fields']) if isinstance(r['custom_fields'], str) else r['custom_fields']
                        for fid, val in cf_dict.items():
                            flat_r[custom_registry.get(str(fid), f"Custom Field {fid}")] = val
                    except Exception:
                        pass
                records_list.append(flat_r)
                
        elif record_type == 'rejected':
            cursor.execute("SELECT row_data FROM rejected_records WHERE file_id = %s ORDER BY id ASC", (file_id,))
            rows = cursor.fetchall()
            for r in rows:
                if r['row_data']:
                    try:
                        item = json.loads(r['row_data']) if isinstance(r['row_data'], str) else r['row_data']
                        flat_r = {}
                        for col in cols:
                            if col == 'custom_fields':
                                continue
                            flat_r[col.replace('_', ' ').title()] = item.get(col)
                        cfields = item.get('custom_fields') or {}
                        for fid, val in cfields.items():
                            flat_r[custom_registry.get(str(fid), f"Custom Field {fid}")] = val
                        records_list.append(flat_r)
                    except Exception:
                        pass
        conn.close()
        
        if not records_list:
            return jsonify({"error": "No records found to export"}), 400
            
        df = pd.DataFrame(records_list)
        import io
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name='Preview Records', index=False)
        output.seek(0)
        
        log_action(session["user_id"], f"Exported file #{file_id} {record_type} records to Excel")
        
        filename = f"file_{file_id}_{record_type}_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/history/export', methods=['GET'])
@login_required()
def export_import_history():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT uf.id, u.username, uf.filename, uf.original_filename, uf.uploaded_at, uf.total_rows, uf.rows_imported, uf.rows_rejected, uf.status 
            FROM uploaded_files uf 
            JOIN users u ON uf.user_id = u.id 
            ORDER BY uf.id DESC
        """)
        rows = cursor.fetchall()
        conn.close()
        
        flat_rows = []
        for r in rows:
            flat_rows.append({
                "Log ID": r["id"],
                "Uploaded By": r["username"],
                "Original Filename": r["original_filename"],
                "Storage Filename": r["filename"],
                "Uploaded At": r["uploaded_at"].isoformat() if r["uploaded_at"] else "",
                "Total Rows": r["total_rows"],
                "Rows Imported": r["rows_imported"],
                "Rows Rejected": r["rows_rejected"],
                "Status": r["status"]
            })
            
        df = pd.DataFrame(flat_rows)
        import io
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name='Import History', index=False)
        output.seek(0)
        
        log_action(session["user_id"], "Exported Spreadsheet Ingestion History to Excel")
        
        filename = f"import_history_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/registry/export', methods=['GET'])
@login_required()
def export_registry():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, field_name, normalized_name, data_type, usage_count, created_at FROM field_registry ORDER BY id ASC")
        rows = cursor.fetchall()
        conn.close()
        
        flat_rows = []
        for r in rows:
            flat_rows.append({
                "Field ID": r["id"],
                "Display Name": r["field_name"],
                "Normalized Name": r["normalized_name"],
                "Data Type": r["data_type"],
                "Usage Count": r["usage_count"],
                "Created At": r["created_at"].isoformat() if r["created_at"] else ""
            })
            
        df = pd.DataFrame(flat_rows)
        import io
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name='Field Registry', index=False)
        output.seek(0)
        
        log_action(session["user_id"], "Exported Custom Fields Registry to Excel")
        
        filename = f"field_registry_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/aliases/export', methods=['GET'])
@login_required()
def export_aliases():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, alias, normalized_alias, target_type, target_identifier FROM field_aliases ORDER BY id ASC")
        rows = cursor.fetchall()
        conn.close()
        
        flat_rows = []
        for r in rows:
            flat_rows.append({
                "Alias ID": r["id"],
                "Header Alias": r["alias"],
                "Normalized Alias": r["normalized_alias"],
                "Target System Layer": r["target_type"],
                "Mapped Identifier": r["target_identifier"]
            })
            
        df = pd.DataFrame(flat_rows)
        import io
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name='Header Aliases', index=False)
        output.seek(0)
        
        log_action(session["user_id"], "Exported Header Schema Aliases to Excel")
        
        filename = f"header_aliases_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/users/export', methods=['GET'])
@login_required()
def export_users():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, username, role, is_active, manager_id, email FROM users ORDER BY id ASC")
        rows = cursor.fetchall()
        conn.close()
        
        flat_rows = []
        for r in rows:
            flat_rows.append({
                "User ID": r["id"],
                "Username": r["username"],
                "Role": r["role"],
                "Is Active": "Yes" if r["is_active"] else "No",
                "Manager ID": r["manager_id"] or "--",
                "Email Address": r["email"] or "--"
            })
            
        df = pd.DataFrame(flat_rows)
        import io
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name='Users Directory', index=False)
        output.seek(0)
        
        log_action(session["user_id"], "Exported Users Directory to Excel")
        
        filename = f"users_directory_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


#list registered users route
@app.route("/users")
@login_required()
def list_users():
    if session.get("role") not in ["admin", "manager"]:
        flash("Access denied.", "warning")
        return redirect(url_for("upload"))

    caller_role     = session.get("role")
    caller_id       = session.get("user_id")
    caller_username = session.get("username")

    search        = request.args.get("search", "").strip()
    role_filter   = request.args.get("role", "").strip()
    status_filter = request.args.get("status", "").strip()
    sort          = request.args.get("sort", "").strip()
    page          = request.args.get("page", 1, type=int)
    per_page      = 10
    offset        = (page - 1) * per_page

    conn   = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    base_select = """
        SELECT
            u.id, u.username, u.role, u.is_active,
            u.manager_id,
            mgr.username    AS manager_username,
            mgr.role        AS manager_role,
            gmgr.username   AS grandmanager_username,
            gmgr.role       AS grandmanager_role,
            NULL            AS created_by_username
        FROM users u
        LEFT JOIN users mgr  ON u.manager_id  = mgr.id
        LEFT JOIN users gmgr ON mgr.manager_id = gmgr.id
    """

    conditions = ["1=1"]
    params     = []

    # Scope by role
    if caller_role == "admin":
        pass  # sees everyone
    elif caller_role in ("manager", "team_lead"):
        visible_ids = get_visible_user_ids(cursor, role=caller_role, user_id=caller_id)
        if visible_ids:
            placeholders = ",".join(["%s"] * len(visible_ids))
            conditions.append(f"u.id IN ({placeholders})")
            params.extend(visible_ids)
        else:
            conditions.append("1=0")
    else:
        # plain user: only self
        conditions.append("u.id = %s")
        params.append(caller_id)

    if search:
        conditions.append("u.username LIKE %s")
        params.append(f"%{search}%")
    if role_filter:
        conditions.append("u.role = %s")
        params.append(role_filter)
    if status_filter == "active":
        conditions.append("u.is_active = 1")
    elif status_filter == "inactive":
        conditions.append("u.is_active = 0")

    where_clause = " WHERE " + " AND ".join(conditions)

    order_map = {
        "username_desc": "u.username DESC",
        "newest":        "u.id DESC",
        "oldest":        "u.id ASC",
        "role":          "u.role ASC",
    }
    order_clause = " ORDER BY " + order_map.get(sort, "u.username ASC")

    try:
        cursor.execute(f"SELECT COUNT(*) AS total FROM users u {where_clause}", params)
        total_users = cursor.fetchone()["total"]

        cursor.execute(
            f"{base_select} {where_clause} {order_clause} LIMIT %s OFFSET %s",
            params + [per_page, offset]
        )
        users = cursor.fetchall()
    except Exception as exc:
        app.logger.exception("Failed to load users list")
        flash("The users page could not be loaded right now.", "danger")
        users = []
        total_users = 0
        total_pages = 1
        start = 0
        end = 0
    finally:
        conn.close()

    if total_users >= 0:
        total_pages = max(1, (total_users + per_page - 1) // per_page)
        start = (page - 1) * per_page + 1 if total_users > 0 else 0
        end   = min(page * per_page, total_users)

    return render_template(
        "users.html",
        users=users,
        search=search, role_filter=role_filter,
        status_filter=status_filter, sort=sort,
        page=page, total_pages=total_pages,
        total_users=total_users, start=start, end=end,
        caller_role=caller_role,
        caller_id=caller_id,
        caller_username=caller_username,
    )


#permissions route
@app.route("/access-control")
@login_required()
def access_control():
    if session.get("role") != "admin":
        flash("Access denied.", "warning")
        return redirect(url_for("upload"))

    # Try to load from DB; fall back to hardcoded map if tables don't exist yet
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
                SELECT r.name AS role, p.name AS permission
                FROM role_permissions rp
                JOIN roles r ON rp.role_id = r.id
                JOIN permissions p ON rp.permission_id = p.id
                ORDER BY r.name, p.name
            """)
        rows = cursor.fetchall()
        conn.close()

        from collections import defaultdict
        db_perms = defaultdict(list)
        for row in rows:
            db_perms[row["role"]].append(row["permission"])
        role_permissions = dict(db_perms)

    except Exception:
        # Tables not yet created — use the hardcoded fallback from rbac.py
        role_permissions = {
            role: sorted(perms)
            for role, perms in ROLE_PERMISSIONS.items()
        }

    return render_template("access_control.html", role_permissions=role_permissions)



@app.route("/admin/users")
@login_required()
def manage_users():
    caller_role     = session.get("role")
    caller_id       = session.get("user_id")
    caller_username = session.get("username")

    if caller_role not in ["admin", "manager"]:
        flash("Access denied.", "warning")
        return redirect(url_for("dashboard"))

    users = []
    available_admins = []
    available_managers = []
    available_tls = []
    role_limits_error = False
    role_limits = {
        "admin": 1000000,
        "manager": 100000,
        "team_lead": 50000,
        "user": 50000,
    }

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        base_select = """
            SELECT
                u.id, u.username, u.role, u.is_active, u.status, u.email,
                u.manager_id, u.export_limit, u.created_at,
                mgr.username   AS manager_username,
                mgr.role       AS manager_role
            FROM users u
            LEFT JOIN users mgr ON u.manager_id = mgr.id
        """

        if caller_role == "admin":
            cursor.execute(f"{base_select} ORDER BY u.username ASC")
            users = cursor.fetchall()
        else:  # manager
            visible_ids = get_visible_user_ids(cursor, role="manager", user_id=caller_id)
            if visible_ids:
                placeholders = ",".join(["%s"] * len(visible_ids))
                cursor.execute(f"{base_select} WHERE u.id IN ({placeholders}) ORDER BY u.username ASC", visible_ids)
                users = cursor.fetchall()
            else:
                users = []

        # Dropdown lists for management form
        if caller_role == "admin":
            cursor.execute("SELECT id, username FROM users WHERE role='admin' AND is_active=1 ORDER BY username")
            available_admins = cursor.fetchall()
            cursor.execute("SELECT id, username FROM users WHERE role='manager' AND is_active=1 ORDER BY username")
            available_managers = cursor.fetchall()
            cursor.execute("SELECT id, username FROM users WHERE role='team_lead' AND is_active=1 ORDER BY username")
            available_tls = cursor.fetchall()
        else:
            available_admins = []
            cursor.execute("SELECT id, username FROM users WHERE id=%s", (caller_id,))
            available_managers = cursor.fetchall()
            cursor.execute(
                "SELECT id, username FROM users WHERE role='team_lead' AND manager_id=%s AND is_active=1 ORDER BY username",
                (caller_id,)
            )
            available_tls = cursor.fetchall()

        # Fetch global role default limits
        try:
            cursor.execute("SELECT role_name, default_limit FROM role_export_limits")
            fetched_limits = cursor.fetchall()
            if fetched_limits:
                role_limits = {r['role_name']: r['default_limit'] for r in fetched_limits}
        except Exception:
            role_limits_error = True
            role_limits = {
                "admin": 1000000,
                "manager": 100000,
                "team_lead": 50000,
                "user": 50000,
            }

        for r in ['admin', 'manager', 'team_lead', 'user']:
            if r not in role_limits:
                role_limits[r] = 1000000 if r == 'admin' else (100000 if r == 'manager' else 50000)

    except Exception as exc:
        app.logger.exception("Failed to load manage users page")
        flash("The manage users page could not be loaded right now.", "danger")
        role_limits_error = True
        users = []
        available_admins = []
        available_managers = []
        available_tls = []
        role_limits = {
            "admin": 1000000,
            "manager": 100000,
            "team_lead": 50000,
            "user": 50000,
        }
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass

    return render_template(
        "admin_users.html",
        users=users,
        available_admins=available_admins,
        available_managers=available_managers,
        available_tls=available_tls,
        caller_role=caller_role,
        caller_id=caller_id,
        caller_username=caller_username,
        role_limits=role_limits,
        role_limits_error=role_limits_error,
    )


# Update user details route (handles role, status, export limit, manager, etc.)
@app.route("/admin/users/update/<int:user_id>", methods=["POST"])
@login_required()
def update_user_details(user_id):
    caller_role = session.get("role")
    caller_id = session.get("user_id")
    if caller_role not in ["admin", "manager"]:
        return jsonify({"ok": False, "error": "Access denied."}), 403

    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip()
    role = request.form.get("role", "").strip()
    new_manager_id_raw = request.form.get("manager_id", "").strip()
    
    # Handle "no_manager" representation
    if new_manager_id_raw == "none" or not new_manager_id_raw:
        new_manager_id = None
    else:
        new_manager_id = int(new_manager_id_raw)

    export_limit_raw = request.form.get("export_limit", "").strip()
    export_limit = int(export_limit_raw) if export_limit_raw else None
    new_status = request.form.get("status", "").strip()

    if not username:
        return jsonify({"ok": False, "error": "Username cannot be empty."}), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Fetch target user details
    cursor.execute("SELECT id, username, role, manager_id FROM users WHERE id = %s", (user_id,))
    target_user = cursor.fetchone()

    if not target_user:
        conn.close()
        return jsonify({"ok": False, "error": "User not found."}), 404

    # Role level authorization check
    ROLE_RANK = {"admin": 4, "manager": 3, "team_lead": 2, "user": 1}
    if ROLE_RANK.get(target_user["role"], 0) >= ROLE_RANK.get(caller_role, 0) and user_id != caller_id:
        conn.close()
        return jsonify({"ok": False, "error": "You cannot modify details of a user at or above your role level."}), 403

    # Manager visibility checks
    if caller_role == "manager":
        visible_ids = get_visible_user_ids(cursor, role="manager", user_id=caller_id)
        if user_id not in visible_ids:
            conn.close()
            return jsonify({"ok": False, "error": "Unauthorized: user is not in your team."}), 403
        if role and role in ["admin", "manager"]:
            conn.close()
            return jsonify({"ok": False, "error": "Managers can only assign team_lead or user roles."}), 403

    # Prevent target user status updates on self unless allowed
    is_active = 1
    if new_status:
        if new_status not in ["active", "deactivated", "deleted"]:
            conn.close()
            return jsonify({"ok": False, "error": "Invalid status value."}), 400
        if user_id == caller_id and new_status in ["deactivated", "deleted"]:
            conn.close()
            return jsonify({"ok": False, "error": "You cannot deactivate or delete your own account."}), 400
        is_active = 1 if new_status == "active" else 0

    # Execute Update
    update_fields = ["username = %s", "email = %s"]
    params = [username, email]

    if caller_role == "admin" and role:
        update_fields.append("role = %s")
        params.append(role)
        
    if new_manager_id_raw != "no_change":
        update_fields.append("manager_id = %s")
        params.append(new_manager_id)

    if caller_role == "admin" or (caller_role == "manager" and target_user["role"] == "user"):
        update_fields.append("export_limit = %s")
        params.append(export_limit)

    if new_status:
        update_fields.append("status = %s")
        params.append(new_status)
        update_fields.append("is_active = %s")
        params.append(is_active)
        if new_status == "deactivated":
            from datetime import datetime as _dt
            update_fields.append("deactivated_at = %s")
            params.append(_dt.utcnow())
        elif new_status == "active":
            update_fields.append("deactivated_at = NULL")

    params.append(user_id)
    query = f"UPDATE users SET {', '.join(update_fields)} WHERE id = %s"
    cursor.execute(query, params)
    conn.commit()
    conn.close()

    log_action(caller_id, f"Updated user details for username '{username}' (id={user_id})")
    if new_status == "deactivated":
        log_action(caller_id, f"Deactivated user '{username}' (id={user_id})")
    elif new_status == "active":
        log_action(caller_id, f"Activated user '{username}' (id={user_id})")

    return jsonify({"ok": True, "message": "User details successfully updated."})



@app.route('/admin/set_export_limit/<int:user_id>', methods=['POST'])
@login_required()
def set_export_limit(user_id):
    if session.get("role") != "admin":
        flash("Access denied.", "warning")
        return redirect(url_for("upload"))
        
    limit_val = request.form.get("export_limit", "").strip()
    if limit_val == "":
        limit = None
    else:
        try:
            limit = int(limit_val)
            if limit < 0:
                raise ValueError()
        except ValueError:
            flash("Invalid limit value.", "danger")
            return redirect(url_for("manage_users"))
            
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET export_limit = %s WHERE id = %s", (limit, user_id))
        conn.commit()
        conn.close()
        flash("Export limit updated successfully.", "success")
    except Exception as e:
        flash(f"Error: {str(e)}", "danger")
        
    return redirect(url_for(
        "manage_users",
        search=request.form.get("_search", ""),
        role=request.form.get("_role_filter", ""),
        status=request.form.get("_status_filter", ""),
        sort=request.form.get("_sort", ""),
        page=request.form.get("_page", 1)
    ))


@app.route('/admin/update_role_limits', methods=['POST'])
@login_required()
def update_role_limits():
    if session.get("role") != "admin":
        flash("Access denied.", "warning")
        return redirect(url_for("upload"))
        
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        for role in ['admin', 'manager', 'team_lead', 'user']:
            limit_val = request.form.get(f"limit_{role}", "").strip()
            if limit_val != "":
                try:
                    limit = int(limit_val)
                    if limit >= 0:
                        cursor.execute("""
                            INSERT INTO role_export_limits (role_name, default_limit)
                            VALUES (%s, %s)
                            ON DUPLICATE KEY UPDATE default_limit = %s
                        """, (role, limit, limit))
                except ValueError:
                    pass
        conn.commit()
        conn.close()
        flash("Role default limits updated successfully.", "success")
    except Exception as e:
        flash(f"Error: {str(e)}", "danger")
        
    return redirect(url_for("manage_users"))


# ── Get TLs under a manager (AJAX endpoint for reassign modal) ────────────────
@app.route("/admin/tls_for_manager/<int:manager_id>")
@login_required()
def tls_for_manager(manager_id):
    caller_role = session.get("role")
    caller_id   = session.get("user_id")
    if caller_role not in ["admin", "manager"]:
        return jsonify({"error": "Forbidden"}), 403
    if caller_role == "manager" and manager_id != caller_id:
        return jsonify({"error": "Forbidden"}), 403
    conn   = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        "SELECT id, username FROM users WHERE role='team_lead' AND manager_id=%s AND is_active=1 ORDER BY username",
        (manager_id,)
    )
    tls = cursor.fetchall()
    conn.close()
    return jsonify({"team_leads": tls})


# ── Reassign manager_id for any user/TL/manager ───────────────────────────────
@app.route("/admin/reassign_manager/<int:target_id>", methods=["POST"])
@login_required()
def reassign_manager(target_id):
    caller_role = session.get("role")
    caller_id   = session.get("user_id")
    if caller_role not in ["admin", "manager"]:
        abort(403)

    new_manager_id_raw = request.form.get("new_manager_id", "").strip()
    new_manager_id = int(new_manager_id_raw) if new_manager_id_raw else None

    conn   = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, username, role, manager_id FROM users WHERE id=%s", (target_id,))
    target = cursor.fetchone()

    if not target:
        conn.close()
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"ok": False, "error": "User not found"}), 404
        flash("User not found.", "danger")
        return redirect(url_for("manage_users"))

    if caller_role == "manager":
        visible_ids = get_visible_user_ids(cursor, role="manager", user_id=caller_id)
        if target_id not in visible_ids:
            conn.close()
            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify({"ok": False, "error": "Forbidden"}), 403
            flash("You can only reassign users under you.", "warning")
            return redirect(url_for("manage_users"))

    cursor.execute("UPDATE users SET manager_id=%s WHERE id=%s", (new_manager_id, target_id))
    conn.commit()
    log_action(caller_id, f"Reassigned '{target['username']}' (id={target_id}) manager_id -> {new_manager_id}")
    conn.close()

    # AJAX response (sent when called from orphan warning box)
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({"ok": True, "username": target["username"]})

    flash(f"Hierarchy updated for '{target['username']}'.", "success")
    return redirect(url_for("manage_users",
                    search=request.form.get("_search",""),
                    role=request.form.get("_role_filter",""),
                    status=request.form.get("_status_filter", ""),
                    sort=request.form.get("_sort",""),
                    page=request.form.get("_page", 1),
                    ))


# ── Dismiss orphan warning from session ───────────────────────────────────────
@app.route("/admin/dismiss_orphan_warning")
@login_required()
def dismiss_orphan_warning():
    session.pop("role_change_warning", None)
    session.modified = True
    return "", 204


@app.route("/account/change_email", methods=["POST"])
@login_required()
def change_email():
    new_email = request.form.get("email", "").strip() or None

    if new_email and _email_already_exists(new_email, exclude_user_id=session["user_id"]):
        flash("That email address is already registered to another account.", "danger")
        return redirect(url_for("dashboard"))

    conn   = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET email = %s WHERE id = %s", (new_email, session["user_id"]))
    conn.commit()
    conn.close()

    session["user_email"] = new_email
    log_action(session["user_id"], "Updated own email" if new_email else "Removed own email")
    flash("Email updated successfully." if new_email else "Email removed.", "success")
    return redirect(url_for("dashboard"))


#change role route (admin)
#change role route (admin)
@app.route("/admin/change_role/<int:user_id>", methods=["POST"])
@login_required()
def change_role(user_id):
    caller_role = session.get("role")
    caller_id   = session.get("user_id")

    if caller_role not in ["admin", "manager"]:
        abort(403)

    new_role = request.form.get("new_role", "").strip()
    allowed_roles = ["user", "team_lead", "manager", "admin"] if caller_role == "admin" else ["user", "team_lead"]

    if new_role not in allowed_roles:
        flash("Invalid role selected.", "danger")
        return redirect(url_for("manage_users"))

    conn   = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, role, username, manager_id FROM users WHERE id=%s", (user_id,))
    user = cursor.fetchone()

    if not user:
        conn.close()
        flash("User not found.", "danger")
        return redirect(url_for("manage_users"))

    if user["username"] == session.get("username"):
        conn.close()
        flash("You cannot change your own role.", "danger")
        return redirect(url_for("manage_users"))

    ROLE_RANK = {"admin":4, "manager":3, "team_lead":2, "user":1}
    if ROLE_RANK.get(user["role"], 0) >= ROLE_RANK.get(caller_role, 0):
        conn.close()
        flash("Cannot modify a user at or above your own role level.", "danger")
        return redirect(url_for("manage_users"))

    if user["role"] == new_role:
        conn.close()
        flash("User already has this role.", "info")
        return redirect(url_for("manage_users"))

    old_role = user["role"]

    # Check who depended on this user BEFORE changing
    cursor.execute(
        "SELECT id, username, role, manager_id FROM users WHERE manager_id=%s", (user_id,)
    )
    raw_deps = cursor.fetchall()
    full_dependents = []
    for dep in raw_deps:
        cursor.execute("SELECT id, username, role FROM users WHERE manager_id=%s", (dep["id"],))
        sub = cursor.fetchall()
        full_dependents.append({
            "user": {"id": dep["id"], "username": dep["username"],
                     "role": dep["role"], "manager_id": dep["manager_id"]},
            "sub_dependents": [{"id":s["id"],"username":s["username"],"role":s["role"]} for s in sub]
        })

    # Perform role change
    cursor.execute("UPDATE users SET role=%s WHERE id=%s", (new_role, user_id))

    # Update role_id if roles table exists
    try:
        cursor.execute("SELECT id FROM roles WHERE name=%s", (new_role,))
        role_row = cursor.fetchone()
        if role_row:
            cursor.execute("UPDATE users SET role_id=%s WHERE id=%s", (role_row["id"], user_id))
    except Exception:
        pass

    # Auto-set manager_id based on who is promoting
    if new_role == "team_lead" and caller_role == "manager":
        cursor.execute("UPDATE users SET manager_id=%s WHERE id=%s", (caller_id, user_id))
    elif new_role == "manager" and caller_role == "admin":
        cursor.execute("UPDATE users SET manager_id=%s WHERE id=%s", (caller_id, user_id))
    elif new_role == "user" and caller_role == "manager":
        cursor.execute("UPDATE users SET manager_id=%s WHERE id=%s", (caller_id, user_id))

    conn.commit()
    conn.close()

    log_action(caller_id, f"Changed role of '{user['username']}' from {old_role} to {new_role}")

    if full_dependents:
        session["role_change_warning"] = {
            "changed_user": user["username"],
            "old_role":     old_role,
            "new_role":     new_role,
            "dependents":   full_dependents,
        }
        session.modified = True
        flash(
            f"Role updated to {new_role.replace('_',' ').title()}. "
            f"WARNING: '{user['username']}' had users assigned — please reassign them in the warning box below.",
            "warning"
        )
    else:
        flash(f"Role updated to {new_role.replace('_',' ').title()} successfully.", "success")

    return redirect(url_for("manage_users",
                            search=request.form.get("_search", ""),
                            role=request.form.get("_role_filter", ""),
                            status=request.form.get("_status_filter",""),
                            sort=request.form.get("_sort",""),
                            page=request.form.get("_page",1),
                            ))
                                                   

#user status route (admin)
@app.route("/admin/users/toggle/<int:user_id>")
@login_required()
def toggle_user(user_id):
    caller_role=session.get("role")
    if caller_role not in ["admin","manager"]:
        flash("Access denied.","warning")
        abort(403)
        # return redirect(url_for("dashboard"))

    conn=get_db_connection()
    cursor=conn.cursor(dictionary=True)

    #check if target is admin or self (protect against disabling self)
    cursor.execute("SELECT username, role FROM users WHERE id= %s", (user_id,))
    target_user=cursor.fetchone()

    if not target_user:
        conn.close()
        flash("User not found.", "danger")
        return redirect(url_for("manage_users"))

    if user_id == session.get("user_id"):
        conn.close()
        flash("Cannot disable your own account.", "warning")
        return redirect(url_for("manage_users"))

    ROLE_RANK = {"admin":4, "manager": 3, "team_lead":2, "user":1}
    if ROLE_RANK.get(target_user["role"], 0) >= ROLE_RANK.get(caller_role, 0):
        conn.close()
        flash("You cannot toggle a user at or above your own role level.","warning")
        return redirect(url_for("manage_users"))


    #1) Read current state
    cursor.execute("SELECT username, `is_active` FROM users WHERE id = %s", (user_id,))
    row=cursor.fetchone()

    new_status=0 if row["is_active"] else 1

    #2) Update to flipped value
    cursor.execute(
        "UPDATE users SET `is_active` = %s WHERE id = %s",
        (new_status, user_id),
    )

    conn.commit()
    conn.close()

    action_text = "Disabled" if new_status == 0 else "Enabled"

    log_action(
        session["user_id"],
        f"{action_text} user (id={user_id}, username={row['username']})",
        total=0,valid=0,invalid=0,
    )

    flash("User status updated", "success")
    return redirect(url_for("manage_users",
                            search=request.args.get("_search", ""),
                            role=request.args.get("_role_filter", ""),
                            status=request.args.get("_status_filter",""),
                            sort=request.args.get("_sort",""),
                            page=request.args.get("_page",1),
                            ))

# Profile page (any role)
@app.route("/profile")
@login_required()
def profile():
    conn   = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT id, username, email, role, is_active, created_at, phone_number, address
        FROM users WHERE id = %s
    """, (session["user_id"],))
    user_data = cursor.fetchone()

    # Fetch user's own recent activity
    cursor.execute("""
        SELECT action, created_at FROM logs
        WHERE user_id = %s
        ORDER BY created_at DESC LIMIT 10
    """, (session["user_id"],))
    recent_activity = cursor.fetchall()

    # Counts for the user's own activity
    cursor.execute("""
        SELECT
            COUNT(*) AS total_events,
            SUM(CASE WHEN LOWER(action) LIKE '%%cleaned file%%' THEN 1 ELSE 0 END) AS total_cleans,
            SUM(CASE WHEN LOWER(action) LIKE '%%upload%%' THEN 1 ELSE 0 END) AS total_uploads,
            SUM(CASE WHEN LOWER(action) LIKE '%%export%%' THEN 1 ELSE 0 END) AS total_exports
        FROM logs WHERE user_id = %s
    """, (session["user_id"],))
    my_stats = cursor.fetchone() or {}

    # Check for user's pending change requests
    cursor.execute("""
        SELECT * FROM public.user_change_requests
        WHERE user_id = %s AND status = 'pending'
    """, (session["user_id"],))
    pending_request = cursor.fetchone()

    conn.close()

    return render_template("profile.html",
                           user_data=user_data,
                           recent_activity=recent_activity,
                           my_stats=my_stats,
                           pending_request=pending_request)


@app.context_processor
def inject_pending_requests_count():
    if "user_id" not in session:
        return {}
    role = session.get("role")
    if role not in ["admin", "team_lead"]:
        return {}
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Pending requests count
        if role == "admin":
            cursor.execute("SELECT COUNT(*) FROM public.user_change_requests WHERE status = 'pending'")
        else: # team_lead
            cursor.execute("""
                SELECT COUNT(*) FROM public.user_change_requests r
                JOIN public.users u ON r.user_id = u.id
                WHERE u.manager_id = %s AND r.status = 'pending'
            """, (session["user_id"],))
        row_req = cursor.fetchone()
        req_count = row_req[0] if row_req else 0

        # Unread notifications count
        cursor.execute("""
            SELECT COUNT(*) FROM public.user_notifications 
            WHERE recipient_id = %s AND is_read = FALSE
        """, (session["user_id"],))
        row_notif = cursor.fetchone()
        notif_count = row_notif[0] if row_notif else 0
        
        conn.close()
        return {
            "pending_requests_count": req_count,
            "unread_notifications_count": notif_count
        }
    except Exception:
        return {}


# API: Get preview of requests and notifications for inbox dropdown
@app.route("/api/inbox/preview")
@login_required()
def inbox_preview():
    role = session.get("role")
    if role not in ["admin", "team_lead"]:
        return jsonify({"ok": False, "error": "Unauthorized"}), 403

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # 1. Fetch pending requests
    if role == "admin":
        cursor.execute("""
            SELECT r.id, r.username, r.requested_at, u.username as current_username
            FROM public.user_change_requests r
            JOIN public.users u ON r.user_id = u.id
            WHERE r.status = 'pending'
            ORDER BY r.requested_at DESC
        """)
    else: # team_lead
        cursor.execute("""
            SELECT r.id, r.username, r.requested_at, u.username as current_username
            FROM public.user_change_requests r
            JOIN public.users u ON r.user_id = u.id
            WHERE u.manager_id = %s AND r.status = 'pending'
            ORDER BY r.requested_at DESC
        """, (session["user_id"],))
    requests_list = cursor.fetchall()

    # 2. Fetch notifications
    cursor.execute("""
        SELECT n.id, n.message, n.action_type, n.created_at, n.is_read, u.username as sender_name
        FROM public.user_notifications n
        JOIN public.users u ON n.sender_id = u.id
        WHERE n.recipient_id = %s
        ORDER BY n.created_at DESC LIMIT 15
    """, (session["user_id"],))
    notifications_list = cursor.fetchall()

    conn.close()

    # Serialize datetimes
    for r in requests_list:
        r["requested_at"] = r["requested_at"].isoformat() if hasattr(r["requested_at"], "isoformat") else str(r["requested_at"])
    for n in notifications_list:
        n["created_at"] = n["created_at"].isoformat() if hasattr(n["created_at"], "isoformat") else str(n["created_at"])

    return jsonify({
        "ok": True,
        "requests": requests_list,
        "notifications": notifications_list
    })


# API: Mark all notifications read
@app.route("/api/notifications/read", methods=["POST"])
@login_required()
def mark_notifications_read():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE public.user_notifications
        SET is_read = TRUE
        WHERE recipient_id = %s
    """, (session["user_id"],))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})



# Update profile details change request (creates request for TL/Admin approval)
@app.route("/profile/update", methods=["POST"])
@login_required()
def profile_update():
    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest"
    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip()
    phone_number = request.form.get("phone_number", "").strip()
    address = request.form.get("address", "").strip()

    if not username:
        if is_ajax:
            return jsonify({"ok": False, "error": "Username cannot be empty."})
        flash("Username cannot be empty.", "danger")
        return redirect(url_for("profile"))

    # Fetch current values
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT username, email, phone_number, address FROM public.users WHERE id = %s
    """, (session["user_id"],))
    curr = cursor.fetchone()

    if not curr:
        conn.close()
        if is_ajax:
            return jsonify({"ok": False, "error": "User not found."})
        flash("User not found.", "danger")
        return redirect(url_for("profile"))

    # Check if there are any actual changes
    has_changes = (
        username != (curr["username"] or "") or
        email != (curr["email"] or "") or
        phone_number != (curr["phone_number"] or "") or
        address != (curr["address"] or "")
    )

    if not has_changes:
        conn.close()
        if is_ajax:
            return jsonify({"ok": False, "error": "No changes detected."})
        flash("No changes detected.", "info")
        return redirect(url_for("profile"))

    # If the user is admin, they don't need approval! Apply changes immediately.
    if session.get("role") == "admin":
        cursor.execute("""
            UPDATE public.users
            SET username = %s, email = %s, phone_number = %s, address = %s
            WHERE id = %s
        """, (username, email, phone_number, address, session["user_id"]))
        conn.commit()
        conn.close()
        
        # Update session username in case it changed
        session["username"] = username

        log_action(session["user_id"], f"Updated own profile details immediately (Username: {username}, Email: {email})")
        msg = "Profile details updated successfully."
        if is_ajax:
            return jsonify({"ok": True, "message": msg})
        flash(msg, "success")
        return redirect(url_for("profile"))

    # Check for existing pending request
    cursor.execute("""
        SELECT id FROM public.user_change_requests 
        WHERE user_id = %s AND status = 'pending'
    """, (session["user_id"],))
    pending = cursor.fetchone()

    if pending:
        # Update existing pending request
        cursor.execute("""
            UPDATE public.user_change_requests
            SET username = %s, email = %s, phone_number = %s, address = %s, requested_at = CURRENT_TIMESTAMP
            WHERE id = %s
        """, (username, email, phone_number, address, pending["id"]))
    else:
        # Create new pending request
        cursor.execute("""
            INSERT INTO public.user_change_requests (user_id, username, email, phone_number, address)
            VALUES (%s, %s, %s, %s, %s)
        """, (session["user_id"], username, email, phone_number, address))

    conn.commit()
    conn.close()

    log_action(session["user_id"], f"Submitted profile change request (Username: {username}, Email: {email})")

    msg = "Profile update request submitted successfully. It is pending approval from your Team Leader or Admin."
    if is_ajax:
        return jsonify({"ok": True, "message": msg})
    flash(msg, "success")
    return redirect(url_for("profile"))



# Inbox for Team Leaders and Admins to approve/reject profile change requests
@app.route("/inbox")
@login_required()
def inbox():
    role = session.get("role")
    if role not in ["admin", "team_lead"]:
        abort(403)

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # 1. Fetch change requests
    if role == "admin":
        cursor.execute("""
            SELECT r.*, u.username AS current_username, u.email AS current_email, 
                   u.phone_number AS current_phone_number, u.address AS current_address,
                   u.role AS user_role, reviewer.username AS reviewer_name
            FROM public.user_change_requests r
            JOIN public.users u ON r.user_id = u.id
            LEFT JOIN public.users reviewer ON r.reviewed_by = reviewer.id
            WHERE r.status = 'pending'
            ORDER BY r.requested_at DESC
        """)
    else: # team_lead
        cursor.execute("""
            SELECT r.*, u.username AS current_username, u.email AS current_email, 
                   u.phone_number AS current_phone_number, u.address AS current_address,
                   u.role AS user_role, reviewer.username AS reviewer_name
            FROM public.user_change_requests r
            JOIN public.users u ON r.user_id = u.id
            LEFT JOIN public.users reviewer ON r.reviewed_by = reviewer.id
            WHERE u.manager_id = %s AND r.status = 'pending'
            ORDER BY r.requested_at DESC
        """, (session["user_id"],))
    requests_raw = cursor.fetchall()

    # 2. Fetch notifications
    cursor.execute("""
        SELECT n.id, n.message, n.action_type, n.created_at, n.is_read, 
               u.username as sender_name, u.role as user_role
        FROM public.user_notifications n
        JOIN public.users u ON n.sender_id = u.id
        WHERE n.recipient_id = %s
        ORDER BY n.created_at DESC
    """, (session["user_id"],))
    notifications_raw = cursor.fetchall()

    conn.close()

    # Combine into a single feed
    feed = []
    
    # Process requests
    for r in requests_raw:
        feed.append({
            "type": "request",
            "id": r["id"],
            "user_id": r["user_id"],
            "timestamp": r["requested_at"],
            "status": r["status"],
            
            "username": r["username"],
            "email": r["email"],
            "phone_number": r["phone_number"],
            "address": r["address"],
            
            "current_username": r["current_username"],
            "current_email": r["current_email"],
            "current_phone_number": r["current_phone_number"],
            "current_address": r["current_address"],
            
            "user_role": r["user_role"],
            "reviewer_name": r["reviewer_name"],
            "reviewed_at": r["reviewed_at"],
            "rejection_reason": r["rejection_reason"]
        })
        
    # Process notifications
    for n in notifications_raw:
        feed.append({
            "type": "notification",
            "id": n["id"],
            "timestamp": n["created_at"],
            "message": n["message"],
            "action_type": n["action_type"],
            "is_read": n["is_read"],
            "sender_name": n["sender_name"],
            "user_role": n["user_role"]
        })
        
    # Sort feed descending by timestamp
    feed.sort(key=lambda x: x["timestamp"], reverse=True)

    return render_template("inbox.html", feed=feed)



# Approve profile change request
@app.route("/inbox/approve/<int:req_id>", methods=["POST"])
@login_required()
def approve_request(req_id):
    role = session.get("role")
    if role not in ["admin", "team_lead"]:
        return jsonify({"ok": False, "error": "Unauthorized"}), 403

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Fetch change request
    cursor.execute("""
        SELECT r.*, u.manager_id 
        FROM public.user_change_requests r
        JOIN public.users u ON r.user_id = u.id
        WHERE r.id = %s AND r.status = 'pending'
    """, (req_id,))
    req = cursor.fetchone()

    if not req:
        conn.close()
        return jsonify({"ok": False, "error": "Request not found or already processed."})

    # If team_lead, check if user is in their team
    if role == "team_lead" and req["manager_id"] != session["user_id"]:
        conn.close()
        return jsonify({"ok": False, "error": "Unauthorized to approve this request."}), 403

    # Update user details
    cursor.execute("""
        UPDATE public.users
        SET username = %s, email = %s, phone_number = %s, address = %s
        WHERE id = %s
    """, (req["username"], req["email"], req["phone_number"], req["address"], req["user_id"]))

    # Update change request status
    cursor.execute("""
        UPDATE public.user_change_requests
        SET status = 'approved', reviewed_by = %s, reviewed_at = CURRENT_TIMESTAMP
        WHERE id = %s
    """, (session["user_id"], req_id))

    conn.commit()
    conn.close()

    log_action(session["user_id"], f"Approved profile update request #{req_id} for user #{req['user_id']}")

    return jsonify({"ok": True})


# Reject profile change request
@app.route("/inbox/reject/<int:req_id>", methods=["POST"])
@login_required()
def reject_request(req_id):
    role = session.get("role")
    if role not in ["admin", "team_lead"]:
        return jsonify({"ok": False, "error": "Unauthorized"}), 403

    reason = request.form.get("reason", "").strip()

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Fetch change request
    cursor.execute("""
        SELECT r.*, u.manager_id 
        FROM public.user_change_requests r
        JOIN public.users u ON r.user_id = u.id
        WHERE r.id = %s AND r.status = 'pending'
    """, (req_id,))
    req = cursor.fetchone()

    if not req:
        conn.close()
        return jsonify({"ok": False, "error": "Request not found or already processed."})

    # If team_lead, check if user is in their team
    if role == "team_lead" and req["manager_id"] != session["user_id"]:
        conn.close()
        return jsonify({"ok": False, "error": "Unauthorized to reject this request."}), 403

    # Update change request status
    cursor.execute("""
        UPDATE public.user_change_requests
        SET status = 'rejected', reviewed_by = %s, reviewed_at = CURRENT_TIMESTAMP, rejection_reason = %s
        WHERE id = %s
    """, (session["user_id"], reason, req_id))

    conn.commit()
    conn.close()

    log_action(session["user_id"], f"Rejected profile update request #{req_id} for user #{req['user_id']} Reason: {reason}")

    return jsonify({"ok": True})


#Change password
@app.route("/account/change_password", methods=["POST"])
@login_required()
def change_password():
    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest"

    current_password = request.form.get("current_password", "")
    new_password     = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    conn   = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT password FROM users WHERE id = %s", (session["user_id"],))
    user = cursor.fetchone()
    conn.close()

    if not bcrypt.checkpw(current_password.encode("utf-8"), user["password"].encode("utf-8")):
        if is_ajax:
            return jsonify({"ok": False, "error": "Current password is incorrect."})
        flash("Current password is incorrect.", "danger")
        return redirect(request.referrer or url_for("dashboard"))

    if new_password != confirm_password:
        if is_ajax:
            return jsonify({"ok": False, "error": "New passwords do not match."})
        flash("New passwords do not match.", "danger")
        return redirect(request.referrer or url_for("dashboard"))

    errors = validate_password(new_password)
    if errors:
        if is_ajax:
            return jsonify({"ok": False, "error": "• " + "<br>• ".join(errors)})
        flash("• " + "<br>• ".join(errors), "danger")
        return redirect(request.referrer or url_for("dashboard"))

    hashed = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    conn   = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET password = %s WHERE id = %s", (hashed, session["user_id"]))
    conn.commit()
    conn.close()

    log_action(session["user_id"], "Changed own password")
    if is_ajax:
        return jsonify({"ok": True})
    flash("Password changed successfully.", "success")
    return redirect(url_for("dashboard"))


#Reset password
@app.route("/admin/users/reset_password/<int:user_id>", methods=["POST"])
@login_required()
def reset_password(user_id):
    caller_role = session.get("role")
    if caller_role not in ["admin", "manager"]:
        abort(403)

    conn   = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT username, role, email FROM users WHERE id = %s", (user_id,))
    target_user = cursor.fetchone()

    if not target_user:
        conn.close()
        flash("User not found.", "danger")
        return redirect(url_for("manage_users"))

    # Hierarchy protection
    ROLE_RANK = {"admin": 4, "manager": 3, "team_lead": 2, "user": 1}
    if ROLE_RANK.get(target_user["role"], 0) >= ROLE_RANK.get(caller_role, 0):
        conn.close()
        flash("You cannot reset the password of a user at or above your own role level.", "warning")
        return redirect(url_for("manage_users"))

    # Password Generation
    import string
    chars = string.ascii_letters + string.digits + "!@#$"
    while True:
        temp_list = (
            [secrets.choice(string.ascii_uppercase)] +
            [secrets.choice(string.ascii_lowercase)] +
            [secrets.choice(string.digits)] +
            [secrets.choice("!@#$")] +
            [secrets.choice(chars) for _ in range(6)]
        )
        secrets.SystemRandom().shuffle(temp_list)
        temp_password = "".join(temp_list)
        if not validate_password(temp_password):
            break

    hashed = bcrypt.hashpw(temp_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    
    # 1. Update password AND set reset flag
    cursor.execute("UPDATE users SET password = %s, requires_password_change = 1 WHERE id = %s", (hashed, user_id))

    # 2. Clear lockout
    cursor.execute("DELETE FROM login_attempts WHERE username = %s AND success = 0", (target_user["username"],))
    
    conn.commit()
    conn.close()

    log_action(session["user_id"], f"Reset password for user '{target_user['username']}' (id={user_id})")
    flash(f"Password for '{target_user['username']}' reset. Temporary password: {temp_password}", "success")

    # Email Logic
    if target_user.get("email"):
        try:
            from flask_mail import Message
            msg = Message(
                subject="Your Data Manager password has been reset",
                recipients=[target_user["email"]],
                body=(
                    f"Hello {target_user['username']},\n\n"
                    f"An administrator has reset your Data Manager password.\n\n"
                    f"Your temporary password is: {temp_password}\n\n"
                    f"Please log in and change this password immediately.\n\n"
                    f"— Data Manager"
                )
            )
            mail.send(msg) 
            log_action(session["user_id"], f"Sent password reset email to '{target_user['username']}'")
        except Exception as e:
            flash("Password reset but email notification failed. Please share the password manually.", "warning")

    return redirect(url_for("manage_users",
                            search=request.args.get("_search", ""),
                            role=request.args.get("_role_filter", ""),
                            status=request.args.get("_status_filter",""),
                            sort=request.args.get("_sort",""),
                            page=request.args.get("_page",1)))



@app.route("/health")
def health():
    return jsonify({"status":"ok"}), 200
 

import glob
import threading

def cleanup_temp_files():
    """Delete temp_*.xlsx files older than 2 hours."""
    import time
    import glob
    cutoff= time.time() - (2 * 60 *60) # 2 hours for temp files

    # Clean temp upload files (2-hour cutoff)
    for f in glob.glob("temp_*.xlsx") + glob.glob("temp_api_*.xlsx"):
        try:
            if os.path.getmtime(f) < cutoff:
                os.remove(f)
                app.logger.info(f"[cleanup] Removed temp file: {f}")
        except Exception as e:
            app.logger.warning(f"[cleanup] Could not remove {f}: {e}")

    #Clean output files older than 24 hours
    output_cutoff = time.time() - (24*60*60)
    for pattern in [
        "Generated_Files/Cleaned/*.xlsx",
        "Generated_Files/Invalid/*.xlsx",
        "Generated_Files/Removed/*.xlsx",
    ]:
        for f in glob.glob(pattern):
            try:
                if os.path.getmtime(f) < output_cutoff:
                    os.remove(f)
                    app.logger.info(f"[cleanup] Removed output file: {f}")
            except Exception as e:
                app.logger.warning(f"[cleanup] Could not remove {f}: {e}")


def schedule_cleanup():
    """Run cleanup every hour in a background thread"""
    import time
    while True:
        cleanup_temp_files()
        time.sleep(60 * 60)

cleanup_thread = threading.Thread(target=schedule_cleanup, daemon=True)
cleanup_thread.start()


@app.route("/presets/save", methods=["POST"])
@login_required()
def save_preset():
    import json
    name = request.form.get("preset_name","").strip()
    rules_json = request.form.get("rules_json", "{}")
    if not name:
        flash("Preset name cannot be empty.","warning")
        return redirect(url_for("choose_rules"))
    try:
        json.loads(rules_json)
    except Exception:
        flash("Could not save preset - invalid rule data.","danger")
        return redirect(url_for("choose_rules"))
    conn=get_db_connection()
    cursor=conn.cursor()
    cursor.execute("""
                   INSERT INTO rule_presets (user_id, name, rules_json)
                   VALUES (%s, %s, %s)
                   ON CONFLICT (user_id, name) DO UPDATE SET rules_json = EXCLUDED.rules_json
                   """,(session["user_id"], name, rules_json))
    conn.commit()
    conn.close()
    flash(f"Preset '{name}' saved.","success")
    return redirect(url_for("choose_rules"))


@app.route("/presets/load/<int:preset_id>")
@login_required()
def load_preset(preset_id):
    import json
    conn=get_db_connection()
    cursor=conn.cursor(dictionary=True)
    cursor.execute(
        "SELECT rules_json FROM rule_presets WHERE id = %s AND user_id = %s",
        (preset_id, session["user_id"])
    )
    preset = cursor.fetchone()
    conn.close()
    if not preset:
        flash("Preset not found.","danger")
        return redirect(url_for("choose_rules"))
    
    rules_dict = json.loads(preset["rules_json"])

    # Handle both old format (just rules dict) and new format (rules + strategies)
    if "rules" in rules_dict and "strategies" in rules_dict:
        rules   = rules_dict["rules"]
        strategies = rules_dict["strategies"]
    else:
        # Old preset saved without strategies
        rules      = rules_dict
        strategies = {}

    session["selected_rules"] = [
        (rule, column, strategies.get(column, "flag"))
        if rule == "handle_missing"
        else (rule, column)
        for column, rule_list in rules.items()
        for rule in rule_list
    ]
    flash("Preset loaded.", "success")
    return redirect(url_for("choose_rules"))



@app.route("/presets/delete/<int:preset_id>", methods=["POST"])
@login_required()
def delete_preset(preset_id):
    conn=get_db_connection()
    cursor=conn.cursor()
    cursor.execute(
        "DELETE FROM rule_presets WHERE id = %s AND user_id = %s",
        (preset_id, session["user_id"])
    )
    conn.commit()
    conn.close()
    flash("Preset deleted.","success")
    return redirect(url_for("choose_rules"))


@app.route("/preview/page")
@login_required()
def preview_page():
    """Returns a page of cleaned/invalid/removed data as JSON for the preview tabs."""
    import math
    page     = int(request.args.get("page", 1))
    per_page = 20
    tab      = request.args.get("type", "cleaned")  # cleaned | invalid | removed

    file_key_map = {
        "cleaned": "cleaned_file",
        "invalid": "invalid_file",
        "removed": "removed_file",
    }
    if tab not in file_key_map:
        tab = "cleaned"

    target_file = session.get(file_key_map[tab])

    if not target_file or not os.path.exists(target_file):
        return jsonify({"rows": [], "columns": [], "total": 0,
                        "page": 1, "per_page": per_page, "total_pages": 0,
                        "empty": True, "tab": tab}), 200

    if target_file.endswith(".csv"):
        df = pd.read_csv(target_file)
    else:
        df = pd.read_excel(target_file)

    total       = len(df)
    start       = (page - 1) * per_page
    chunk       = df.iloc[start:start + per_page].fillna("").astype(str)

    return jsonify({
        "rows":        chunk.to_dict(orient="records"),
        "columns":     df.columns.tolist(),
        "total":       total,
        "page":        page,
        "per_page":    per_page,
        "total_pages": math.ceil(total / per_page) if total else 0,
        "tab":         tab,
    })


@app.route("/test-mail")
def test_mail():
    try:
        msg = Message("Test", recipients=["ruhinz26@gmail.com"], body="Test email from Data Manager")
        mail.send(msg)
        return "Email sent successfully"
    except Exception as e:
        return f"Failed: {e}"

# ── REST API Endpoints for Hybrid Database ─────────────────────────────────────

@app.route('/api/records', methods=['GET'])
@login_required()
def get_records():
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 25))
    except ValueError:
        page = 1
        per_page = 25
        
    offset = (page - 1) * per_page
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Dynamically resolve columns of master_records
    cursor.execute("DESCRIBE master_records")
    cols = [row['Field'] for row in cursor.fetchall()]
    
    query_parts = ["1=1"]
    params = []
    
    # Support basic mappings
    search_mappings = {
        'name': 'full_name',
        'email': 'email_address',
        'phone': 'primary_phone_number',
        'company': 'company_name',
        'city': 'city'
    }
    for arg_name, col_name in search_mappings.items():
        val = request.args.get(arg_name, '').strip()
        if val and col_name in cols:
            query_parts.append(f"`{col_name}` LIKE %s")
            params.append(f"%{val}%")
            
    # Support dynamic search on other master columns
    for c in cols:
        if c in ('id', 'file_id', 'custom_fields', 'created_at', 'updated_at', 'imported_by') or c in search_mappings.values():
            continue
        val = request.args.get(c, '').strip()
        if val:
            query_parts.append(f"`{c}` LIKE %s")
            params.append(f"%{val}%")
            
    # Support dynamic search on multiple custom JSON field values
    custom_filters_str = request.args.get('custom_filters', '[]')
    try:
        custom_filters = json.loads(custom_filters_str)
        for f in custom_filters:
            fid = str(f.get('id', '')).strip()
            fval = str(f.get('val', '')).strip()
            if fid and fval:
                query_parts.append("custom_fields ->> %s LIKE %s")
                params.append(fid)
                params.append(f"%{fval}%")
    except Exception as e:
        app.logger.warning(f"Error parsing custom_filters: {e}")
        
    # Support missing_field filter
    missing_field = request.args.get('missing_field', '').strip()
    if missing_field and missing_field in cols:
        query_parts.append(f"({missing_field} IS NULL OR {missing_field} = '')")

    where_clause = " AND ".join(query_parts)

    # Log records search query activity
    if page == 1 and session.get("role") in ["admin", "manager"]:
        search_terms = []
        for arg_name, col_name in search_mappings.items():
            val = request.args.get(arg_name, '').strip()
            if val:
                search_terms.append(f"{arg_name.capitalize()}: {val}")
        for c in cols:
            if c in ('id', 'file_id', 'custom_fields', 'created_at', 'updated_at', 'imported_by') or c in search_mappings.values():
                continue
            val = request.args.get(c, '').strip()
            if val:
                search_terms.append(f"{c.replace('_', ' ').title()}: {val}")
        try:
            custom_filters = json.loads(custom_filters_str)
            for f in custom_filters:
                fid = str(f.get('id', '')).strip()
                fval = str(f.get('val', '')).strip()
                if fid and fval:
                    search_terms.append(f"{fid}: {fval}")
        except Exception:
            pass
        if missing_field:
            search_terms.append(f"Missing: {missing_field}")
        if search_terms:
            search_summary = ", ".join(search_terms)
            log_search(session["user_id"], session["username"], f"Records query: {search_summary}")
    
    # Query total matching records
    count_query = f"SELECT COUNT(*) as total FROM master_records WHERE {where_clause}"
    cursor.execute(count_query, params)
    total_row = cursor.fetchone()
    total = total_row['total'] if total_row else 0
    
    # Query paginated rows
    select_query = f"SELECT {', '.join([f'`{c}`' for c in cols])} FROM master_records WHERE {where_clause} ORDER BY id DESC LIMIT %s OFFSET %s"
    cursor.execute(select_query, params + [per_page, offset])
    items = cursor.fetchall()
    
    # Serialize records list
    records_list = []
    for item in items:
        cfields = item['custom_fields']
        if isinstance(cfields, str):
            try:
                cfields = json.loads(cfields)
            except Exception:
                cfields = {}
        elif not cfields:
            cfields = {}
            
        record_data = {}
        for c in cols:
            val = item[c]
            if c == 'custom_fields':
                record_data[c] = cfields
            elif isinstance(val, datetime):
                record_data[c] = val.isoformat()
            else:
                record_data[c] = val
                
        # Compatibility mapping properties for UI rendering
        record_data["name"] = item.get("full_name") or "--"
        record_data["email"] = item.get("email_address") or "--"
        record_data["phone"] = item.get("primary_phone_number") or "--"
        record_data["company"] = item.get("company_name") or "--"
        record_data["state"] = item.get("state_province") or "--"
        
        records_list.append(record_data)
        
    pages = (total + per_page - 1) // per_page
    
    # Calculate missing stats over matching records dynamically
    missing_stats = {}
    if total > 0:
        missing_cols = [c for c in cols if c not in ('id', 'file_id', 'custom_fields', 'created_at', 'updated_at', 'imported_by')]
        cases = ", ".join([f"COUNT(CASE WHEN `{col}` IS NULL OR `{col}` = '' THEN 1 END) AS `{col}`" for col in missing_cols])
        stats_query = f"SELECT {cases} FROM master_records WHERE {where_clause}"
        
        cursor.execute(stats_query, params)
        stats_row = cursor.fetchone()
        if stats_row:
            for col in missing_cols:
                missing_count = stats_row[col] or 0
                pct = round((missing_count / total) * 100, 1)
                missing_stats[col] = {
                    "count": missing_count,
                    "percentage": pct
                }

    conn.close()
    
    return jsonify({
        "records": records_list,
        "total": total,
        "page": page,
        "pages": pages,
        "per_page": per_page,
        "missing_stats": missing_stats
    })

@app.route('/api/records/export', methods=['GET'])
@login_required()
def export_records():
    if "user_id" not in session or session.get("role") not in ROLE_PERMISSIONS:
        return redirect(url_for("login"))
        
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Get physical columns dynamically
        cursor.execute("DESCRIBE master_records")
        cols = [row['Field'] for row in cursor.fetchall()]
        
        query_parts = ["1=1"]
        params = []
        
        # Support basic mappings
        search_mappings = {
            'name': 'full_name',
            'email': 'email_address',
            'phone': 'primary_phone_number',
            'company': 'company_name',
            'city': 'city'
        }
        for arg_name, col_name in search_mappings.items():
            val = request.args.get(arg_name, '').strip()
            if val and col_name in cols:
                query_parts.append(f"`{col_name}` LIKE %s")
                params.append(f"%{val}%")
                
        # Support dynamic search on other master columns
        for c in cols:
            if c in ('id', 'file_id', 'custom_fields', 'created_at', 'updated_at', 'imported_by') or c in search_mappings.values():
                continue
            val = request.args.get(c, '').strip()
            if val:
                query_parts.append(f"`{c}` LIKE %s")
                params.append(f"%{val}%")
                
        # Support dynamic search on multiple custom JSON field values
        custom_filters_str = request.args.get('custom_filters', '[]')
        try:
            custom_filters = json.loads(custom_filters_str)
            for f in custom_filters:
                fid = str(f.get('id', '')).strip()
                fval = str(f.get('val', '')).strip()
                if fid and fval:
                    query_parts.append("custom_fields ->> %s LIKE %s")
                    params.append(fid)
                    params.append(f"%{fval}%")
        except Exception as e:
            app.logger.warning(f"Error parsing custom_filters: {e}")
            
        # Support missing_field filter
        missing_field = request.args.get('missing_field', '').strip()
        if missing_field and missing_field in cols:
            query_parts.append(f"({missing_field} IS NULL OR {missing_field} = '')")
    
        where_clause = " AND ".join(query_parts)
        
        # Check daily export limits before querying full records
        user_id = session["user_id"]
        user_role = session["role"]
        
        cursor.execute("SELECT export_limit, role FROM users WHERE id = %s", (user_id,))
        user_db_info = cursor.fetchone()
        custom_limit = user_db_info['export_limit'] if user_db_info else None
        
        if custom_limit is not None:
            active_limit = custom_limit
        else:
            cursor.execute("SELECT default_limit FROM role_export_limits WHERE role_name = %s", (user_role,))
            role_limit_row = cursor.fetchone()
            if role_limit_row:
                active_limit = role_limit_row['default_limit']
            else:
                if user_role == 'admin':
                    active_limit = 1000000
                elif user_role == 'manager':
                    active_limit = 100000
                else:
                    active_limit = 50000
                    
        cursor.execute("SELECT SUM(rows_count) AS total_exported FROM user_daily_exports WHERE user_id = %s AND export_date = CURRENT_DATE", (user_id,))
        usage_row = cursor.fetchone()
        today_usage = usage_row['total_exported'] if usage_row and usage_row['total_exported'] is not None else 0
        
        # Count matching records
        cursor.execute(f"SELECT COUNT(*) as count FROM master_records WHERE {where_clause}", params)
        records_count = cursor.fetchone()['count']
        
        if today_usage + records_count > active_limit:
            conn.close()
            return jsonify({
                "error": f"Daily export limit exceeded. You have already exported {today_usage:,} rows today. This request contains {records_count:,} rows, which exceeds your daily limit of {active_limit:,} rows."
            }), 400
            
        # Query matching records
        select_query = f"SELECT * FROM master_records WHERE {where_clause} ORDER BY id DESC"
        cursor.execute(select_query, params)
        rows = cursor.fetchall()
        
        # Update user's daily exports count
        cursor.execute("""
            INSERT INTO user_daily_exports (user_id, export_date, rows_count)
            VALUES (%s, CURRENT_DATE, %s)
            ON CONFLICT (user_id, export_date) DO UPDATE SET rows_count = user_daily_exports.rows_count + EXCLUDED.rows_count
        """, (user_id, records_count))
        conn.commit()

        # Log the export activity with filters state
        search_terms = []
        for arg_name, col_name in search_mappings.items():
            val = request.args.get(arg_name, '').strip()
            if val:
                search_terms.append(f"{arg_name.capitalize()}: {val}")
        for c in cols:
            if c in ('id', 'file_id', 'custom_fields', 'created_at', 'updated_at', 'imported_by') or c in search_mappings.values():
                continue
            val = request.args.get(c, '').strip()
            if val:
                search_terms.append(f"{c.replace('_', ' ').title()}: {val}")
        try:
            custom_filters = json.loads(custom_filters_str)
            for f in custom_filters:
                fid = str(f.get('id', '')).strip()
                fval = str(f.get('val', '')).strip()
                if fid and fval:
                    search_terms.append(f"{fid}: {fval}")
        except Exception:
            pass
        if missing_field:
            search_terms.append(f"Missing: {missing_field}")
            
        filters_desc = ", ".join(search_terms) if search_terms else "No filters"
        action_msg = f"Exported {records_count} records. Filters: {filters_desc}"
        
        from helpers import log_action
        log_action(user_id, action_msg, total=records_count)
        
        # Fetch active custom fields from registry to resolve names
        cursor.execute("SELECT id, field_name FROM field_registry WHERE is_active = 1")
        custom_registry = {str(r['id']): r['field_name'] for r in cursor.fetchall()}
        
        flat_rows = []
        for r in rows:
            flat_r = {}
            for col in cols:
                if col == 'custom_fields':
                    continue
                pretty_name = col.replace('_', ' ').title()
                flat_r[pretty_name] = r[col]
            
            if r['custom_fields']:
                try:
                    cf_dict = json.loads(r['custom_fields']) if isinstance(r['custom_fields'], str) else r['custom_fields']
                    for fid, val in cf_dict.items():
                        header_name = custom_registry.get(str(fid), f"Custom Field {fid}")
                        flat_r[header_name] = val
                except Exception:
                    pass
            flat_rows.append(flat_r)
            
        conn.close()
        
        # Log the export action
        log_action(session["user_id"], f"Exported filtered search query data ({len(rows)} rows) to Excel")
        
        # Output DataFrame
        df = pd.DataFrame(flat_rows)
        
        import io
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name='Filtered Results', index=False)
        output.seek(0)
        
        filename = f"filtered_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/history/file-records', methods=['GET'])
@login_required()
def get_file_records():
    file_id = request.args.get('file_id')
    record_type = request.args.get('type') # 'imported' or 'rejected'
    
    if not file_id:
        return jsonify({"error": "Missing file_id parameter"}), 400
        
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Get physical columns dynamically
        cursor.execute("DESCRIBE master_records")
        cols = [row['Field'] for row in cursor.fetchall() if row['Field'] not in ('id', 'file_id', 'created_at', 'updated_at')]
        
        # Fetch active custom fields from registry to resolve names
        cursor.execute("SELECT id, field_name FROM field_registry WHERE is_active = 1")
        custom_registry = {str(r['id']): r['field_name'] for r in cursor.fetchall()}
        
        records_list = []
        
        if record_type == 'imported':
            cursor.execute("SELECT * FROM master_records WHERE file_id = %s ORDER BY id ASC", (file_id,))
            rows = cursor.fetchall()
            
            for r in rows:
                flat_r = {}
                for col in cols:
                    if col == 'custom_fields':
                        continue
                    pretty_name = col.replace('_', ' ').title()
                    flat_r[pretty_name] = r[col]
                
                if r['custom_fields']:
                    try:
                        cf_dict = json.loads(r['custom_fields']) if isinstance(r['custom_fields'], str) else r['custom_fields']
                        for fid, val in cf_dict.items():
                            header_name = custom_registry.get(str(fid), f"Custom Field {fid}")
                            flat_r[header_name] = val
                    except Exception:
                        pass
                records_list.append(flat_r)
                
        elif record_type == 'rejected':
            cursor.execute("SELECT row_data FROM rejected_records WHERE file_id = %s ORDER BY id ASC", (file_id,))
            rows = cursor.fetchall()
            
            for r in rows:
                if r['row_data']:
                    try:
                        item = json.loads(r['row_data']) if isinstance(r['row_data'], str) else r['row_data']
                        
                        flat_r = {}
                        for col in cols:
                            if col == 'custom_fields':
                                continue
                            pretty_name = col.replace('_', ' ').title()
                            flat_r[pretty_name] = item.get(col)
                            
                        # Extract custom JSON fields
                        cfields = item.get('custom_fields') or {}
                        for fid, val in cfields.items():
                            header_name = custom_registry.get(str(fid), f"Custom Field {fid}")
                            flat_r[header_name] = val
                            
                        records_list.append(flat_r)
                    except Exception:
                        pass
                        
        conn.close()
        
        headers = []
        if records_list:
            seen_headers = set()
            for r in records_list:
                for k in r.keys():
                    if k not in seen_headers:
                        seen_headers.add(k)
                        headers.append(k)
        
        return jsonify({
            "headers": headers,
            "records": records_list
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/custom-fields', methods=['GET'])
@login_required()
def get_custom_fields():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, field_name, normalized_name, data_type, is_active, searchable, filterable FROM field_registry WHERE is_active = 1")
    fields = cursor.fetchall()
    conn.close()
    return jsonify(fields)

@app.route('/api/records/<int:record_id>/custom', methods=['GET'])
@login_required()
def get_record_custom_fields(record_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM master_records WHERE id = %s", (record_id,))
    row = cursor.fetchone()
    
    if not row:
        conn.close()
        return jsonify({"error": "Record not found"}), 404
        
    cfields = row['custom_fields']
    if isinstance(cfields, str):
        try:
            cfields = json.loads(cfields)
        except Exception:
            cfields = {}
    elif not cfields:
        cfields = {}
        
    resolved_data = {}
    
    # 1. Resolve JSON custom fields
    for key_id_str, val in cfields.items():
        try:
            cursor.execute("SELECT field_name FROM field_registry WHERE id = %s", (int(key_id_str),))
            f_row = cursor.fetchone()
            if f_row:
                resolved_data[f_row['field_name']] = val
            else:
                resolved_data[f"Unregistered Field #{key_id_str}"] = val
        except (ValueError, TypeError):
            resolved_data[key_id_str] = val
            
    # 2. Add other populated columns that aren't metadata or main table columns
    for col, val in row.items():
        if col in ('id', 'file_id', 'custom_fields', 'created_at', 'updated_at', 'imported_by',
                   'full_name', 'email_address', 'primary_phone_number', 'company_name', 'city', 'state_province'):
            continue
        if val is not None and str(val).strip() != '':
            label = " ".join([w.capitalize() for w in col.split("_")])
            resolved_data[label] = val
            
    conn.close()
    return jsonify(resolved_data)

# ── Registry, Aliases, and Ingestion Routes ───────────────────────────────────

@app.route('/registry')
@login_required()
def registry():
    if session.get("role") != "admin":
        flash("Access denied.", "warning")
        return redirect(url_for("upload"))
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, field_name, normalized_name, data_type, is_active, searchable, usage_count, created_at FROM field_registry ORDER BY id ASC")
    fields = cursor.fetchall()
    
    # Calculate usage count dynamically from master_records JSON
    for f in fields:
        field_id = f['id']
        cursor.execute("SELECT COUNT(*) as count FROM master_records WHERE custom_fields ->> %s IS NOT NULL", (str(field_id),))
        cnt_row = cursor.fetchone()
        f['usage_count'] = cnt_row['count'] if cnt_row else 0
        
        if f['created_at'] and isinstance(f['created_at'], datetime):
            f['created_at'] = f['created_at'].strftime('%Y-%m-%d %H:%M')
            
    conn.close()
    return render_template('registry.html', fields=fields)

@app.route('/aliases')
@login_required()
def aliases_view():
    if session.get("role") != "admin":
        flash("Access denied.", "warning")
        return redirect(url_for("upload"))
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, alias, target_type, target_identifier FROM field_aliases ORDER BY id ASC")
    aliases = cursor.fetchall()
    
    cursor.execute("SELECT id, field_name FROM field_registry WHERE is_active = 1")
    custom_fields = cursor.fetchall()
    
    conn.close()
    return render_template('aliases.html', aliases=aliases, custom_fields=custom_fields)

@app.route('/history')
@login_required()
def history_view():
    if session.get("role") != "admin":
        flash("Access denied.", "warning")
        return redirect(url_for("upload"))

    page = request.args.get("page", 1, type=int) or 1
    per_page = 25
    page = max(1, page)

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Clean up any stale processing records (created > 5 minutes ago)
    from datetime import datetime, timedelta
    stale_time = datetime.utcnow() - timedelta(minutes=5)
    try:
        cursor.execute(
            "UPDATE uploaded_files SET status = 'failed' WHERE status = 'processing' AND uploaded_at < %s",
            (stale_time,)
        )
        conn.commit()
    except Exception as e:
        app.logger.error(f"Error clearing stale uploads: {e}")

    cursor.execute("SELECT COUNT(*) AS total FROM uploaded_files")
    total_row = cursor.fetchone() or {}
    total_uploads = int(total_row.get("total") or 0)

    total_pages = max(1, (total_uploads + per_page - 1) // per_page)
    page = min(page, total_pages)

    offset = (page - 1) * per_page
    cursor.execute("""
        SELECT id, user_id, filename, original_filename, uploaded_at, total_rows,
               rows_imported, rows_rejected, status
        FROM uploaded_files
        ORDER BY id DESC
        LIMIT %s OFFSET %s
    """, (per_page, offset))
    uploads = cursor.fetchall()

    for u in uploads:
        if u['uploaded_at'] and isinstance(u['uploaded_at'], datetime):
            u['uploaded_at'] = u['uploaded_at'].strftime('%Y-%m-%d %H:%M:%S')

    conn.close()
    return render_template(
        'history.html',
        uploads=uploads,
        page=page,
        total_pages=total_pages,
        pagination_url=lambda p: url_for('history_view', page=p)
    )

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
    
    cursor.execute("SELECT id, field_name, normalized_name FROM field_registry WHERE is_active = 1")
    custom_fields = cursor.fetchall()
    
    cursor.execute("SELECT alias, target_type, target_identifier FROM field_aliases")
    aliases = cursor.fetchall()
    
    suggestions = {}
    
    for col in columns:
        from helpers import normalize_header
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

@app.route('/api/upload-draft', methods=['POST'])
@login_required()
def api_upload_draft():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
        
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in ('.xlsx', '.xls', '.csv'):
        return jsonify({"error": "Only Excel and CSV files are allowed"}), 400
        
    try:
        # Save temp file securely
        safe_filename = os.path.basename(file.filename)
        unique_filename = f"{uuid.uuid4().hex}_{safe_filename}"
        upload_folder = "Generated_Files/Uploaded"
        os.makedirs(upload_folder, exist_ok=True)
        file_path = os.path.join(upload_folder, unique_filename)
        file.save(file_path)
        
        # Read columns
        if ext == '.csv':
            try:
                df = pd.read_csv(file_path, nrows=5)
            except Exception:
                df = pd.read_csv(file_path, sep=None, engine='python', nrows=5)
        else:
            df = pd.read_excel(file_path, nrows=5)
            
        columns = df.columns.tolist()
        
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        suggestions = suggest_column_mapping(columns, cursor)
        
        cursor.execute("SELECT id, field_name FROM field_registry WHERE is_active = 1")
        custom_fields = cursor.fetchall()
        conn.close()
        
        return jsonify({
            "filename": unique_filename,
            "original_filename": safe_filename,
            "columns": columns,
            "suggestions": suggestions,
            "custom_fields": custom_fields
        }), 200
        
    except Exception as e:
        return jsonify({"error": f"Failed to parse file: {str(e)}"}), 500

@app.route('/api/browser/proceed-ingestion', methods=['POST'])
@login_required()
def api_proceed_ingestion():
    data = request.get_json() or {}
    filename = data.get('filename')
    original_filename = data.get('original_filename')
    mapping = data.get('mapping')
    
    if not filename or not mapping:
        return jsonify({"error": "Missing filename or mapping details"}), 400
        
    file_path = os.path.join("Generated_Files/Uploaded", filename)
    if not os.path.exists(file_path):
        return jsonify({"error": "Temp file not found on server"}), 404
        
    try:
        # Determine total rows
        ext = os.path.splitext(filename)[1].lower()
        if ext == '.csv':
            try:
                df = pd.read_csv(file_path)
            except Exception:
                df = pd.read_csv(file_path, sep=None, engine='python')
        else:
            df = pd.read_excel(file_path)
        row_count = len(df)
        
        # Log database row for upload history
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "INSERT INTO uploaded_files (user_id, filename, original_filename, total_rows, status, uploaded_at) VALUES (%s, %s, %s, %s, %s, %s)",
            (session['user_id'], filename, original_filename, row_count, 'processing', datetime.utcnow())
        )
        file_id = cursor.lastrowid
        conn.commit()
        
        cursor.execute("SELECT username FROM users WHERE id = %s", (session["user_id"],))
        u_row = cursor.fetchone()
        username = u_row["username"] if u_row else "unknown"
        conn.close()
        
        # Run mapping ingestion in background
        import threading
        from helpers import ingest_uploaded_file_with_mapping
        
        def process_upload_with_mapping():
            try:
                ingest_uploaded_file_with_mapping(file_id, file_path, username, mapping)
            except Exception:
                pass
                
        thread = threading.Thread(target=process_upload_with_mapping)
        thread.daemon = True
        thread.start()
        
        return jsonify({
            "message": "Ingestion initiated successfully!",
            "file_id": file_id
        }), 200
        
    except Exception as e:
        return jsonify({"error": f"Failed to proceed with ingestion: {str(e)}"}), 500

@app.route('/api/browser/upload', methods=['POST'])
@login_required()
def api_upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part in request"}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected for upload"}), 400
        
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in ('.xlsx', '.xls', '.csv'):
        return jsonify({"error": "Only Excel files (.xlsx, .xls) and CSV (.csv) are allowed"}), 400
        
    try:
        # Save file securely with UUID to prevent overlaps
        safe_filename = os.path.basename(file.filename)
        unique_filename = f"{uuid.uuid4().hex}_{safe_filename}"
        
        # Ensure upload folder exists
        upload_folder = "Generated_Files/Uploaded"
        os.makedirs(upload_folder, exist_ok=True)
        
        file_path = os.path.join(upload_folder, unique_filename)
        file.save(file_path)
        
        # Log database row for upload history
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Check size or length (quick load to check length)
        try:
            if ext == '.csv':
                df = pd.read_csv(file_path)
            else:
                df = pd.read_excel(file_path)
            row_count = len(df)
        except Exception:
            row_count = 0
            
        cursor.execute(
            "INSERT INTO uploaded_files (user_id, filename, original_filename, total_rows, status, uploaded_at) VALUES (%s, %s, %s, %s, %s, %s)",
            (session['user_id'], unique_filename, safe_filename, row_count, 'processing', datetime.utcnow())
        )
        file_id = cursor.lastrowid
        conn.commit()
        
        # Get username
        cursor.execute("SELECT username FROM users WHERE id = %s", (session["user_id"],))
        u_row = cursor.fetchone()
        username = u_row["username"] if u_row else "unknown"
        conn.close()
        
        # Execute parsing pipeline in a background thread to prevent gateway timeout
        import threading
        from helpers import ingest_uploaded_file
        
        def process_upload():
            try:
                ingest_uploaded_file(file_id, file_path, username)
            except Exception:
                pass
                
        thread = threading.Thread(target=process_upload)
        thread.daemon = True
        thread.start()
        
        return jsonify({
            "message": "Upload successful! Ingestion pipeline started.",
            "file": {
                "id": file_id,
                "user_id": session['user_id'],
                "filename": unique_filename,
                "original_filename": safe_filename,
                "total_rows": row_count,
                "status": "processing"
            }
        }), 202
        
    except Exception as e:
        return jsonify({"error": f"Failed to upload file: {str(e)}"}), 500

@app.route('/api/aliases', methods=['POST'])
@login_required()
def api_create_alias():
    alias = request.form.get('alias', '').strip()
    target_type = request.form.get('target_type', '').strip()
    target_identifier = request.form.get('target_identifier', '').strip()
    
    if not alias:
        return jsonify({"error": "Alias string cannot be empty"}), 400
    if target_type not in ('master', 'custom'):
        return jsonify({"error": "Target type must be 'master' or 'custom'"}), 400
    if not target_identifier:
        return jsonify({"error": "Target identifier cannot be empty"}), 400
        
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Check if alias already exists
        cursor.execute("SELECT id FROM field_aliases WHERE alias = %s", (alias,))
        if cursor.fetchone():
            conn.close()
            return jsonify({"error": f"Alias '{alias}' is already mapped."}), 400
            
        norm_alias = alias.strip().lower().replace(" ", "_")
        cursor.execute(
            "INSERT INTO field_aliases (alias, normalized_alias, target_type, target_identifier) VALUES (%s, %s, %s, %s)",
            (alias, norm_alias, target_type, target_identifier)
        )
        conn.commit()
        conn.close()
        
        return jsonify({"message": "Alias mapped successfully!"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/aliases/<int:alias_id>/delete', methods=['POST'])
@login_required()
def api_delete_alias(alias_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM field_aliases WHERE id = %s", (alias_id,))
        conn.commit()
        conn.close()
        return jsonify({"message": "Alias mapping deleted"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/fields/<int:field_id>/status', methods=['POST'])
@login_required()
def api_update_field_status(field_id):
    data = request.json or {}
    
    is_active = data.get('is_active')
    searchable = data.get('searchable')
    filterable = data.get('filterable')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        if is_active is not None:
            cursor.execute("UPDATE field_registry SET is_active = %s WHERE id = %s", (1 if is_active else 0, field_id))
        if searchable is not None:
            cursor.execute("UPDATE field_registry SET searchable = %s WHERE id = %s", (1 if searchable else 0, field_id))
        if filterable is not None:
            cursor.execute("UPDATE field_registry SET filterable = %s WHERE id = %s", (1 if filterable else 0, field_id))
            
        conn.commit()
        conn.close()
        return jsonify({"message": "Field status updated successfully"}), 200
    except Exception as e:
        conn.rollback()
        conn.close()
        return jsonify({"error": str(e)}), 500

@app.route('/api/fields/<int:field_id>/convert-to-master', methods=['POST'])
@login_required()
def api_convert_to_master(field_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # 1. Fetch registry field info
        cursor.execute("SELECT field_name, normalized_name FROM field_registry WHERE id = %s", (field_id,))
        field = cursor.fetchone()
        if not field:
            conn.close()
            return jsonify({"error": "Registry field not found"}), 404
            
        c_name = field['normalized_name']
        f_name = field['field_name']
        
        # 2. Add column to master_records table
        try:
            cursor.execute(f"ALTER TABLE master_records ADD COLUMN IF NOT EXISTS `{c_name}` VARCHAR(255) NULL")
            conn.commit()
        except Exception as alter_err:
            # Column might already exist, log warning and roll back to reset aborted transaction state
            app.logger.warning(f"ALTER TABLE column warning: {alter_err}")
            try:
                conn.rollback()
            except Exception:
                pass
            
        # 3. Migrate data from custom_fields JSON to the new column
        # Select all records having this custom field
        cursor.execute("SELECT id, custom_fields FROM master_records WHERE custom_fields ->> %s IS NOT NULL", (str(field_id),))
        records = cursor.fetchall()
        
        for r in records:
            cfields = r['custom_fields']
            if isinstance(cfields, str):
                try:
                    cfields = json.loads(cfields)
                except Exception:
                    cfields = {}
            elif not cfields:
                cfields = {}
                
            val = cfields.pop(str(field_id), None)
            new_json = json.dumps(cfields) if cfields else None
            
            cursor.execute(
                f"UPDATE master_records SET `{c_name}` = %s, custom_fields = %s WHERE id = %s",
                (val, new_json, r['id'])
            )
            
        # 4. Update field_aliases target
        cursor.execute(
            "UPDATE field_aliases SET target_type = 'master', target_identifier = %s WHERE target_type = 'custom' AND target_identifier = %s",
            (c_name, str(field_id))
        )
        
        # 5. Delete from field_registry
        cursor.execute("DELETE FROM field_registry WHERE id = %s", (field_id,))
        
        conn.commit()
        conn.close()
        
        return jsonify({"message": f"Successfully converted '{f_name}' custom field to a Master Column!"}), 200
        
    except Exception as e:
        if 'conn' in locals() and conn:
            conn.rollback()
            conn.close()
        return jsonify({"error": f"Migration failed: {str(e)}"}), 500

if __name__ == "__main__":
    app.run(debug=True)
