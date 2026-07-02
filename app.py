from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, abort, get_flashed_messages, jsonify
import mysql.connector
import bcrypt
import pandas as pd
from io import BytesIO
import re
import os
from mysql.connector import Error, IntegrityError
import uuid
import secrets
from rbac import has_permission, ROLE_PERMISSIONS
from functools import wraps
from datetime import datetime, timedelta
import json

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


from flask_mail import Mail, Message

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
    if "user_id" not in session:
        return redirect(url_for("login"))
        
    # Search keyword from query params
    search = request.args.get("search", "").strip()
    from_date = request.args.get("from_date","")           
    to_date = request.args.get("to_date","") 
    log_type = (request.args.get("log_type", "login") or "login").strip().lower()
    if log_type not in {"login", "cleaning", "search"}:
        log_type = "login"

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

    per_page = 10

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    logs, total_logs = fetch_visible_logs(cursor,search = search, from_date = from_date, to_date = to_date,
                                          log_type = log_type, page = page, per_page = per_page)
    conn.close()

    total_pages = (total_logs + per_page -1 )//per_page 

    if total_logs > 0:
        start=(page -1 ) * per_page + 1
        end = min (page * per_page, total_logs)
    else:
        start=0
        end=0

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
                           pagination_url=lambda p: url_for(
                               "admin_logs",
                               page=p,
                               search=search,
                               from_date=from_date,
                               to_date=to_date,
                               log_type = log_type
                           ))




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
        abort(403)

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
            if caller_role == "admin":
                raw=request.form.get("assign_tl_id","").strip()
                new_manager_id=int(raw) if raw else None
            else:
                new_manager_id=session.get("user_id")
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
            return redirect(url_for("manage_users"))

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
                "SELECT id, username, password, role, is_active, manager_id, email, requires_password_change FROM users WHERE username=%s",
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

    # 7. Handle Disabled Account
    if not user["is_active"]:
        flash("Account is disabled. Contact admin.", "danger")
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

    cursor.execute("SELECT COUNT(*) as count FROM logs WHERE action LIKE 'Uploaded file%' AND DATE(created_at) = CURDATE()")
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


#Data cleaning

#Step 1: Upload & Show Columns
@app.route("/upload", methods=["GET", "POST"])
@login_required()
def upload():
    if "user_id" not in session or session.get("role") not in ROLE_PERMISSIONS:
        return redirect(url_for("login"))

    if request.method == "POST":
        file = request.files["file"]
        
        ALLOWED_EXTENSIONS = (".xls", ".xlsx", ".csv")
        if file and file.filename.endswith(ALLOWED_EXTENSIONS):
            #Check file size before doing anything else (limit: 10MB for now)
            file.seek(0,2)              #seek to end
            file_size =file.tell()      #get position = size in bytes
            file.seek(0)                #reset to start
            if file_size > 10 * 1024 * 1024:
                flash("File too large. Maximum size is 10MB.","danger")
                return render_template("upload.html")
            
            safe_filename = os.path.basename(file.filename)  #strips any path traversal
            ext = os.path.splitext(safe_filename)[1].lower()
            temp_path = f"temp_{session['user_id']}{ext}"
            file.save(temp_path)

            try:
                if ext==".csv":
                    #Try comma first, fall back to auto-detection
                    try:
                        df = pd.read_csv(temp_path)
                    except Exception:
                        df = pd.read_csv(temp_path, sep=None, engine="python")
                else:
                    df = pd.read_excel(temp_path)
            except Exception as e:
                flash(f"Could not read file: {e}", "danger")
                return render_template("upload.html")
           
            session["temp_file"] = temp_path
            session["uploaded_file"] = safe_filename
            session.pop("selected_rules", None)  # Clear old rules
           
            # Create a row in uploaded_files and start ingestion pipeline
            try:
                conn_upload = get_db_connection()
                cursor_upload = conn_upload.cursor()
                cursor_upload.execute(
                    "INSERT INTO uploaded_files (user_id, filename, original_filename, total_rows, status, uploaded_at) VALUES (%s, %s, %s, %s, %s, %s)",
                    (session["user_id"], temp_path, safe_filename, len(df), 'processing', datetime.utcnow())
                )
                file_id = cursor_upload.lastrowid
                conn_upload.commit()
                conn_upload.close()

                # Get user name
                conn_user = get_db_connection()
                cursor_user = conn_user.cursor(dictionary=True)
                cursor_user.execute("SELECT username FROM users WHERE id = %s", (session["user_id"],))
                u_row = cursor_user.fetchone()
                username = u_row["username"] if u_row else "unknown"
                conn_user.close()

                import threading
                from helpers import ingest_uploaded_file
                
                def run_background_ingestion(fid, fpath, uname):
                    try:
                        ingest_uploaded_file(fid, fpath, uname)
                    except Exception:
                        pass

                t = threading.Thread(target=run_background_ingestion, args=(file_id, temp_path, username))
                t.daemon = True
                t.start()
            except Exception as e:
                app.logger.error(f"Failed to kick off background ingestion: {e}")

            log_action(session["user_id"], f"Uploaded file {session['uploaded_file']} ({len(df)} rows)")
            return redirect(url_for("choose_rules"))
        else:
            flash("Invalid file format. Please upload an Excel (.xlsx/.xls) or CSV file.", "danger")
   
    return render_template("upload.html")


#Step 2: Choose cleaning rules (helps in re-selecting rules)
from collections import defaultdict

@app.route("/choose_rules", methods=["GET"])
@login_required()
def choose_rules():
    if "user_id" not in session or session.get("role") not in ROLE_PERMISSIONS:
        return redirect(url_for("login"))
   

    temp_path = session.get("temp_file")
    selected_rules = session.get("selected_rules", [])

    column_rule_map = defaultdict(list)
    selected_strategy_map = {}

    for rule_tuple in selected_rules:
        rule_name = rule_tuple[0]
        column = rule_tuple[1]
        column_rule_map[column].append(rule_name)
        if rule_name == "handle_missing" and len(rule_tuple) > 2:
            selected_strategy_map[column] = rule_tuple[2]

    if not temp_path or not os.path.exists(temp_path):
        flash("No file uploaded. Please upload first.", "warning")
        return redirect(url_for("upload"))

    if temp_path.endswith(".csv"):
        df = pd.read_csv(temp_path)
    else:
        df=pd.read_excel(temp_path)
    columns = df.columns.tolist()

    column_rule_options = {}

    column_type_map = {
        column: resolve_column_type(df, column)
        for column in df.columns
    }

    for column in df.columns:
        col_type = column_type_map[column]
        allowed_rules = []
        for rule_key, rule_meta in RULES_REGISTRY.items():
            if col_type in rule_meta.get("allowed_types", []):
                allowed_rules.append(rule_key)
        column_rule_options[column] = allowed_rules

    identifier_columns = detect_identifier_columns(df)
    presets = []
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT id, name FROM rule_presets WHERE user_id = %s ORDER By name",
            (session["user_id"],)
        )
        presets = cursor.fetchall()
    except Exception:
        app.logger.warning(
            "Unable to load rule presets for user %s; continuing without presets.",
            session.get("user_id"),
            exc_info=True,
        )
        presets = []
    finally:
        if conn is not None:
            conn.close()

    return render_template("choose_rules.html",
                         columns=df.columns,
                         selected_rule_map=column_rule_map,
                         selected_rules=selected_rules,
                         selected_strategy_map=selected_strategy_map,
                         uploaded_file=session.get("uploaded_file"),
                         column_rule_options=column_rule_options,
                         RULES_REGISTRY=RULES_REGISTRY,
                         presets=presets,
                         column_type_map=column_type_map,
                         identifier_columns=identifier_columns)

import os
import glob




#Step 3: Apply rules -> Preview cleaned data
@app.route("/clean", methods=["POST"])
@login_required()
def clean_data():

    # print("RAW FORM: ", request.form)    #debug statement

    
    if "user_id" not in session or session.get("role") not in ROLE_PERMISSIONS:
        return redirect(url_for("login"))
    
    temp_path = session.get("temp_file")

    if not temp_path or not os.path.exists(temp_path):
        flash("No file found. Please upload again.", "danger")
        return redirect(url_for("upload"))
    
    if temp_path.endswith(".csv"):
        df= pd.read_csv(temp_path)
    else:
        df = pd.read_excel(temp_path)

    total_before = len(df)

    #Read any column type overrides the user submitted
    type_overrides = {}
    for column in df.columns:
        safe_col = column.replace(" ", "_")
        override = request.form.get(f"type_override_{safe_col}", "").strip()
        if override:
            type_overrides[column] = override
    session["type_overrides"] = type_overrides

    #STEP 1: Store selected rules in session
    selected_rules = []

    for column in df.columns:
        safe_col = column.replace(" ","_")
        rules = request.form.getlist(f"rules_{safe_col}[]")

        for rule_name in rules:
            rule_name = rule_name.strip()
            if rule_name == "handle_missing":
                strategy = request.form.get(f"strategy_{column.replace(' ','_')}","flag")
                selected_rules.append((rule_name, column, strategy))
            else:
                selected_rules.append((rule_name, column))

    # print("PARSED SELECTED RULES: ", selected_rules)    #debug statement
        
    session["selected_rules"] = selected_rules


    #STEP 2: Build Engine Rule List
    engine_rules=[]
    dup_columns=[]

    for rule_tuple in selected_rules:
        rule_name = rule_tuple[0]
        column = rule_tuple[1]
        if rule_name == "drop_duplicates":
            dup_columns.append(column)
        else:
            engine_rules.append(rule_tuple)

    # print("DUP COLS: ", dup_columns)    #debug statement

    if not selected_rules:
        flash("Please select at least one cleaning rule.", "warning")
        return redirect(url_for("choose_rules"))

    #STEP 3: Run Cleaning Engine
    cleaned_df, invalid_df, removed_rows, detailed_errors, incompatibility_errors, cleaning_summary = run_cleaning_pipeline(
        df=df,
        selected_rules=engine_rules,
        duplicate_columns=dup_columns,
        type_overrides=type_overrides
    )

    system_warnings = incompatibility_errors

    
    # print("SELECTED RULES RAW:", selected_rules)    #debug statement
    # print("TYPE: ", type(selected_rules))           #debug statement

    removed_count = len(removed_rows)

    #STEP 6: Final Counts
    valid_after = len(cleaned_df)
    invalid_after= len(invalid_df)

    if cleaned_df.empty:
        flash("All rows removed. please adjust rules.", "warning")

    #Cleanup previous run files
    cleanup_old_session_files()
    #STEP 7: Save Files

    from datetime import datetime

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name=os.path.splitext(os.path.basename(session["uploaded_file"]))[0]

    cleaned_file = os.path.join("Generated_Files","Cleaned",f"{base_name}_cleaned_{timestamp}.xlsx")
    cleaned_df.to_excel(cleaned_file, index=False)

    invalid_file=None
    if not invalid_df.empty:
        invalid_file= os.path.join("Generated_Files","Invalid",f"{base_name}_invalid_{timestamp}.xlsx")
        invalid_df.to_excel(invalid_file, index=False)

    removed_file=None
    if not removed_rows.empty:
        removed_file= os.path.join("Generated_Files","Removed",f"{base_name}_removed_{timestamp}.xlsx")
        removed_rows.to_excel(removed_file, index=False)

    
    #STEP 8: Generate Preview
    preview = cleaned_df.reset_index(drop=True).head(15).to_html(
        classes="table table-hover align-middle",
        index=False,
        header=True,
        border=0,
        justify="left"
    )
    # print("Preview",preview)    #debug statement

    #STEP 9: Summary
    summary= generate_summary(
        total_before,
        valid_after,
        [e.get("message", "Unknown error") for e in detailed_errors]
    )

    #STEP 10: Group Errors
    from collections import defaultdict
    grouped_errors= defaultdict(list)

    for error in detailed_errors:
        grouped_errors[error["rule"]].append(error)
    
    #STEP 11: Logging
    column_rule_map = defaultdict(list)
    # print("COLUMN RULE MAP RAW: ", dict(column_rule_map))   #debug

    for rule_tuple in selected_rules:
        rule_name=rule_tuple[0]
        column=rule_tuple[1]
        rule_meta = RULES_REGISTRY.get(rule_name, {})
        display_name = rule_meta.get("label") or rule_name
        # print("ADDING: ", column, "->", display_name)    #debug statement
        column_rule_map[column].append(display_name)

    # print("COLUMN RULE MAP: ", column_rule_map)     #debug statement
    # for col, rules in column_rule_map.items():
    #     print("COLUMN: ", col, "RULES LIST: ", rules, "TYPE: ", type(rules))  #debug statement

    #for group
    selected_filters_display=[
        {
            "column":column,
            "rule": ", ".join(rules)
        }
        for column, rules in column_rule_map.items()
    ]
    
    filters_count = sum(len(rules) for rules in column_rule_map.values())

    # print("SELECTED FILTERS DISPLAY: ", selected_filters_display)    #debug statement
    # print("FILTER COUNT: ", filters_count)    #debug statement

    rules_applied = [
        f"{column} ({', '.join(rules)})"
        for column, rules in column_rule_map.items()
    ]

    log_action(
        session["user_id"],
        f"Cleaned file {session['uploaded_file']} using rules: {', '.join(rules_applied)} | summary:{cleaning_summary}",
        total=total_before,
        valid=valid_after,
        invalid=invalid_after,
        removed=removed_count,
        rules_applied=[(r[0],r[1]) for r in selected_rules],
        rule_counts=cleaning_summary.get("rules_trigger_counts",{}),
    )

    session["cleaned_file"] = cleaned_file
    session["invalid_file"] = invalid_file
    session["removed_file"] = removed_file

    if cleaned_df.empty:
        detailed_errors.append({
            "rule" : "dataset_empty",
            "column" : None,
            "row_index" : None,
            "message" : "All rows removed after applying filters."
        })

    #FINAL RENDER
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
        system_warnings=system_warnings,
        cleaning_summary=cleaning_summary,
        cleaned_rows=len(cleaned_df),
        invalid_rows=len(invalid_df),
        removed=removed_count

    )


# Step 4: Download cleaned file and invalid rows after preview
@app.route("/download/<path:filename>")
@login_required()
def download(filename):

    filename=filename.strip()

    if "user_id" not in session or session.get("role") not in ROLE_PERMISSIONS:
        return redirect(url_for("login"))
    
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
@login_required()
def export_logs():
    if "user_id" not in session:
        flash("Please log in to continue.", "warning")
        return redirect(url_for("login"))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    visible_user_ids=get_visible_user_ids(cursor)

    if not visible_user_ids:
        flash("No data available.", "info")
        return redirect(url_for("dashboard"))

    if visible_user_ids:
        placeholders=",".join(["%s"] * len(visible_user_ids))
        query= f"""
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

    import pandas as pd
    df = pd.DataFrame(logs)

    file_path = "logs_export.xlsx"
    df.to_excel(file_path, index=False)

    return send_file(file_path, as_attachment=True)


#list registered users route
@app.route("/users")
@login_required()
def list_users():
    if not (
        has_permission("view_all_users") or
        has_permission("view_team_users") or
        has_permission("view_self")
    ):
        flash("Access denied", "warning")
        return redirect(url_for('dashboard'))

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
def access_control():
    if not has_permission("manage_roles"):
        flash("Admin permissions required","warning")
        return redirect(url_for('dashboard'))
    
    conn =  get_db_connection()
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

    return render_template("access_control.html", role_permissions=dict(db_perms))


@app.route("/admin/users")
@login_required()
def manage_users():
    caller_role     = session.get("role")
    caller_id       = session.get("user_id")
    caller_username = session.get("username")

    if caller_role not in ["admin", "manager"]:
        flash("Access denied.", "warning")
        return redirect(url_for("dashboard"))

    search        = request.args.get("search", "").strip()
    role_filter   = request.args.get("role",   "").strip()
    status_filter = request.args.get("status", "").strip()
    sort          = request.args.get("sort",   "").strip()
    page          = request.args.get("page", 1, type=int)
    per_page      = 10
    offset        = (page - 1) * per_page

    conn   = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    base_select = """
        SELECT
            u.id, u.username, u.role, u.is_active,
            u.manager_id,
            mgr.username   AS manager_username,
            mgr.role       AS manager_role,
            gmgr.username  AS grandmanager_username,
            gmgr.role      AS grandmanager_role
        FROM users u
        LEFT JOIN users mgr  ON u.manager_id  = mgr.id
        LEFT JOIN users gmgr ON mgr.manager_id = gmgr.id
    """

    conditions = ["1=1"]
    params     = []

    if caller_role == "manager":
        visible_ids = get_visible_user_ids(cursor, role="manager", user_id=caller_id)
        if visible_ids:
            placeholders = ",".join(["%s"] * len(visible_ids))
            conditions.append(f"u.id IN ({placeholders})")
            params.extend(visible_ids)
        else:
            conditions.append("1=0")

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

    order_map = {
        "username_desc": "u.username DESC",
        "newest":        "u.id DESC",
        "oldest":        "u.id ASC",
        "role":          "u.role ASC",
    }
    order_clause = " ORDER BY " + order_map.get(sort, "u.username ASC")
    where_clause = " WHERE " + " AND ".join(conditions)

    cursor.execute(f"SELECT COUNT(*) AS total FROM users u {where_clause}", params)
    total_users = cursor.fetchone()["total"]

    cursor.execute(
        f"{base_select} {where_clause} {order_clause} LIMIT %s OFFSET %s",
        params + [per_page, offset]
    )
    users = cursor.fetchall()

    # Dropdown lists for the reassign modal
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

    conn.close()

    total_pages = max(1, (total_users + per_page - 1) // per_page)
    start = (page - 1) * per_page + 1 if total_users > 0 else 0
    end   = min(page * per_page, total_users)

    return render_template(
        "admin_users.html",
        users=users,
        search=search, role_filter=role_filter,
        status_filter=status_filter, sort=sort,
        page=page, total_pages=total_pages,
        total_users=total_users, start=start, end=end,
        available_admins=available_admins,
        available_managers=available_managers,
        available_tls=available_tls,
        caller_role=caller_role,
        caller_id=caller_id,
        caller_username=caller_username,
    )


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
                   ON DUPLICATE KEY UPDATE rules_json = VALUES(rules_json)
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
        return "Email sent sucessfully"
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
            
    # Support dynamic search on custom JSON field values
    custom_field_id = request.args.get('custom_field_id', '').strip()
    custom_field_value = request.args.get('custom_field_value', '').strip()
    if custom_field_id and custom_field_value:
        query_parts.append("JSON_UNQUOTE(JSON_EXTRACT(custom_fields, %s)) LIKE %s")
        params.append(f"$.\"{custom_field_id}\"")
        params.append(f"%{custom_field_value}%")
        
    # Support missing_field filter
    missing_field = request.args.get('missing_field', '').strip()
    if missing_field and missing_field in cols:
        query_parts.append(f"({missing_field} IS NULL OR {missing_field} = '')")

    where_clause = " AND ".join(query_parts)
    
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
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, field_name, normalized_name, data_type, is_active, searchable, usage_count, created_at FROM field_registry ORDER BY id ASC")
    fields = cursor.fetchall()
    
    # Calculate usage count dynamically from master_records JSON
    for f in fields:
        field_id = f['id']
        cursor.execute("SELECT COUNT(*) as count FROM master_records WHERE JSON_EXTRACT(custom_fields, %s) IS NOT NULL", (f'$."{field_id}"',))
        cnt_row = cursor.fetchone()
        f['usage_count'] = cnt_row['count'] if cnt_row else 0
        
        if f['created_at'] and isinstance(f['created_at'], datetime):
            f['created_at'] = f['created_at'].strftime('%Y-%m-%d %H:%M')
            
    conn.close()
    return render_template('registry.html', fields=fields)

@app.route('/aliases')
@login_required()
def aliases_view():
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
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, user_id, filename, original_filename, uploaded_at, total_rows, status FROM uploaded_files ORDER BY id DESC")
    uploads = cursor.fetchall()
    
    for u in uploads:
        if u['uploaded_at'] and isinstance(u['uploaded_at'], datetime):
            u['uploaded_at'] = u['uploaded_at'].strftime('%Y-%m-%d %H:%M:%S')
            
    conn.close()
    return render_template('history.html', uploads=uploads)

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
            cursor.execute(f"ALTER TABLE master_records ADD COLUMN `{c_name}` VARCHAR(255) NULL")
            conn.commit()
        except Exception as alter_err:
            # Column might already exist, log warning and proceed
            app.logger.warning(f"ALTER TABLE column warning: {alter_err}")
            
        # 3. Migrate data from custom_fields JSON to the new column
        json_path = f'$."{field_id}"'
        
        # Select all records having this custom field
        cursor.execute("SELECT id, custom_fields FROM master_records WHERE JSON_EXTRACT(custom_fields, %s) IS NOT NULL", (json_path,))
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


