import os
import uuid
import re
import bcrypt
import time
import pandas as pd
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, jsonify, abort, send_from_directory
from dotenv import load_dotenv
from celery import Celery
import json
from pathlib import Path
from datetime import timedelta
from psycopg2 import pool
from psycopg2.extras import RealDictCursor
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from werkzeug.utils import secure_filename
import phonenumbers

# Load secrets from .env
load_dotenv()

def clean_and_standardize_phone(phone_str, default_region="US"):
    if not phone_str:
        return ""
    phone_str = str(phone_str).strip()
    if not phone_str:
        return ""
    try:
        if phone_str.startswith('+'):
            parsed = phonenumbers.parse(phone_str, None)
        else:
            parsed = phonenumbers.parse(phone_str, default_region)
        
        if phonenumbers.is_valid_number(parsed):
            return phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    except Exception:
        pass
    return None


def predict_rules_for_column(col_name):
    col_clean = str(col_name).strip().lower()
    suggested = []
    
    # Email rules
    if 'email' in col_clean or 'mail' in col_clean:
        suggested.append('validate_email')
        suggested.append('drop_duplicates')
        suggested.append('drop_nulls')
        
    # Phone rules
    elif any(p in col_clean for p in ['phone', 'mobile', 'tel', 'contact', 'cell']):
        suggested.append('validate_phone')
        suggested.append('drop_duplicates')
        suggested.append('drop_nulls')
        
    # Name rules
    elif any(n in col_clean for n in ['name', 'fname', 'lname', 'first', 'last']):
        suggested.append('remove_specials')
        suggested.append('drop_nulls')
        
    # ID / Key / Code rules
    elif any(i in col_clean for i in ['id', 'uuid', 'key', 'code', 'number', 'no']):
        suggested.append('drop_duplicates')
        suggested.append('drop_nulls')
        
    # Company / Organization
    elif any(c in col_clean for c in ['company', 'org', 'firm', 'business']):
        suggested.append('remove_specials')
        
    return suggested


REQUIRED_COLUMNS = ['first_name', 'last_name', 'email', 'phone', 'company']

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY") or "dev-only-change-me"
if app.secret_key == "dev-only-change-me":
    print("Warning: FLASK_SECRET_KEY is not set; using an insecure development fallback.")
# Session timeout (minutes) - configurable via env var
session_timeout = int(os.getenv('SESSION_TIMEOUT_MINUTES', '30'))
app.permanent_session_lifetime = timedelta(minutes=session_timeout)

# Directory to store user presets (simple file-based store)
PRESETS_DIR = Path('presets')
PRESETS_DIR.mkdir(exist_ok=True)
UPLOADS_DIR = Path('uploads')
UPLOADS_DIR.mkdir(exist_ok=True)

# --- CELERY CONFIGURATION ---
def make_celery(app):
    celery = Celery(
        'app',
        backend='redis://localhost:6379/0',
        broker='redis://localhost:6379/0'
    )
    celery.conf.update(app.config)
    return celery

celery_app = make_celery(app)

# --- SCHEDULED CLEANUP CONFIGURATION ---
celery_app.conf.beat_schedule = {
    'delete-old-files-every-day': {
        'task': 'app.cleanup_old_files',
        'schedule': 86400.0,
    },
}
celery_app.conf.timezone = 'UTC'

# --- DATABASE POOLING (PostgreSQL / Neon) ---
db_pool = None
database_url = os.getenv("DATABASE_URL") or os.getenv("NEON_DATABASE_URL")

def normalize_database_url(raw_url):
    """Return a psycopg2-compatible Postgres URL with Neon-friendly defaults."""
    if not raw_url:
        return None

    raw_url = raw_url.strip()
    if raw_url.startswith("postgres://"):
        raw_url = "postgresql://" + raw_url[len("postgres://"):]

    parsed = urlsplit(raw_url)
    if parsed.scheme not in {"postgresql", "postgres"}:
        raise ValueError(
            "DATABASE_URL must be a PostgreSQL/Neon URL, for example "
            "postgresql://USER:PASSWORD@HOST/DBNAME?sslmode=require"
        )

    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query.setdefault("sslmode", os.getenv("DB_SSLMODE", "require"))
    query.setdefault("connect_timeout", os.getenv("DB_CONNECT_TIMEOUT", "10"))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), parsed.fragment))

def init_db_schema():
    if os.getenv("AUTO_INIT_SCHEMA", "1") != "1" or db_pool is None:
        return

    schema_path = Path(__file__).with_name("schema.sql")
    if not schema_path.exists():
        print("Warning: schema.sql not found; skipping database schema initialization.")
        return

    conn = None
    cursor = None
    try:
        conn = db_pool.getconn()
        cursor = conn.cursor()
        cursor.execute(schema_path.read_text(encoding="utf-8"))
        conn.commit()
    except Exception as e:
        if conn:
            conn.rollback()
        print(f"Warning: could not initialize DB schema: {e}")
    finally:
        if cursor:
            cursor.close()
        if db_pool is not None and conn is not None:
            db_pool.putconn(conn)

# Allow tests or environments to skip DB initialization by setting SKIP_DB_INIT=1
if os.getenv("SKIP_DB_INIT") != "1" and database_url:
    try:
        database_url = normalize_database_url(database_url)
        db_pool = pool.SimpleConnectionPool(
            1,
            5,
            dsn=database_url,
        )
        init_db_schema()
    except Exception as e:
        print(f"Warning: could not initialize DB pool: {e}")
elif os.getenv("SKIP_DB_INIT") != "1":
    print("Warning: DATABASE_URL/NEON_DATABASE_URL is not set; database access is disabled until it is provided.")

def get_db_connection():
    if os.getenv("SKIP_DB_INIT") == "1" or db_pool is None:
        raise RuntimeError("DB not initialized in this environment")
    return db_pool.getconn()

def release_db_connection(conn):
    if db_pool is not None and conn is not None:
        db_pool.putconn(conn)

def fetch_all(query, params=()):
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute(query, params)
        return cursor.fetchall()
    finally:
        if cursor:
            cursor.close()
        release_db_connection(conn)

def fetch_one(query, params=()):
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute(query, params)
        return cursor.fetchone()
    finally:
        if cursor:
            cursor.close()
        release_db_connection(conn)

def execute_db(query, params=()):
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(query, params)
        conn.commit()
    except Exception:
        if conn:
            conn.rollback()
        raise
    finally:
        if cursor:
            cursor.close()
        release_db_connection(conn)

def count_users():
    row = fetch_one("SELECT COUNT(*) AS count FROM users")
    return row["count"] if row else 0

def is_safe_upload_name(filename):
    return bool(filename) and Path(filename).name == filename and not Path(filename).is_absolute()

def log_action(user_id, action, total=None, valid=None, invalid=None):
    # Skip DB logging when running in test or environments that opt-out
    if os.getenv("SKIP_DB_INIT") == "1":
        print(f"log_action skipped (test mode): user={user_id}, action={action}")
        return
    try:
        execute_db("""
            INSERT INTO logs (user_id, action, total_rows, valid_rows, invalid_rows)
            VALUES (%s, %s, %s, %s, %s)
        """, (user_id, action, total, valid, invalid))
    except Exception as e:   
        print(f"Logging error: {e}")

# --- SCHEDULED TASK: FILE CLEANUP ---
@celery_app.task(name='app.cleanup_old_files')
def cleanup_old_files():
    current_time = time.time()
    folder = "uploads"
    max_age = 24 * 60 * 60 
    if os.path.exists(folder):
        for filename in os.listdir(folder):
            file_path = os.path.join(folder, filename)
            if (current_time - os.path.getmtime(file_path)) > max_age:
                try:
                    os.remove(file_path)
                except Exception as e:
                    print(f"Cleanup error: {e}")

# --- BACKGROUND TASK: DATA CLEANING ---
@celery_app.task(bind=True, name='app.process_cleaning_task')
def process_cleaning_task(self, filepath, rules_dict, cols_to_drop, uploaded_name, user_id):
    try:
        self.update_state(state='PROGRESS', meta={'status': 'Reading Excel file...', 'percent': 20})
        df = pd.read_excel(filepath)
        total_before = len(df)
        failed_indices = set()

        self.update_state(state='PROGRESS', meta={'status': 'Applying cleaning rules...', 'percent': 40})
        
        for column, rules in rules_dict.items():
            if not rules or column not in df.columns:
                continue
            
            df[column] = df[column].fillna('').astype(str).str.strip()

            # --- NULL HANDLING RULE ---
            if "drop_nulls" in rules:
                null_indices = df[df[column] == ""].index
                failed_indices.update(null_indices)

            if "remove_specials" in rules:
                df[column] = df[column].apply(lambda x: re.sub(r'[^A-Za-z0-9@.\s+]', '', x))
            
            if "validate_email" in rules:
                email_pattern = re.compile(r'^[\w\.-]+@[\w\.-]+\.\w+$')
                for idx, val in df[column].items():
                    if val != "" and not bool(email_pattern.match(val)):
                        failed_indices.add(idx)

            if "validate_phone" in rules:
                for idx, val in df[column].items():
                    if val != "":
                        standardized = clean_and_standardize_phone(val)
                        if standardized is not None:
                            df.at[idx, column] = standardized
                        else:
                            failed_indices.add(idx)

        # --- DUPLICATE DETECTION LOGIC ---
        dup_columns = [col for col, rules in rules_dict.items() if "drop_duplicates" in rules and col in df.columns]
        if dup_columns:
            # Identify unique identifier columns (email, phone/mobile/tel)
            unique_cols = [c for c in dup_columns if any(u in c.lower() for u in ['email', 'phone', 'mobile', 'tel'])]
            non_unique_cols = [c for c in dup_columns if c not in unique_cols]
            
            # Check unique columns individually (ignoring empty strings)
            for col in unique_cols:
                folded = df[col].astype(str).str.strip().str.lower()
                non_empty_mask = folded != ''
                dup_mask = folded[non_empty_mask].duplicated(keep='first')
                failed_indices.update(dup_mask[dup_mask].index)
            
            # Check non-unique columns row-wise
            if non_unique_cols:
                has_first = 'first_name' in df.columns
                has_last = 'last_name' in df.columns
                
                if has_first and has_last and ('first_name' in non_unique_cols or 'last_name' in non_unique_cols):
                    # Create a combined name series
                    first_clean = df['first_name'].astype(str).str.strip().str.lower()
                    last_clean = df['last_name'].astype(str).str.strip().str.lower()
                    combined_name = first_clean + " " + last_clean
                    
                    other_cols = [c for c in non_unique_cols if c not in ('first_name', 'last_name')]
                    if other_cols:
                        combined_series = combined_name + " | " + df[other_cols].astype(str).apply(
                            lambda row: " | ".join(row.str.strip().str.lower()), axis=1
                        )
                    else:
                        combined_series = combined_name
                else:
                    combined_series = df[non_unique_cols].astype(str).apply(
                        lambda row: " | ".join(row.str.strip().str.lower()), axis=1
                    )
                
                # Determine non-empty rows for non-unique columns
                cols_to_check = []
                if has_first and has_last and ('first_name' in non_unique_cols or 'last_name' in non_unique_cols):
                    cols_to_check.extend(['first_name', 'last_name'])
                    cols_to_check.extend([c for c in non_unique_cols if c not in ('first_name', 'last_name')])
                else:
                    cols_to_check.extend(non_unique_cols)
                    
                non_empty_mask = df[cols_to_check].astype(str).apply(
                    lambda row: any(val.strip() != '' for val in row), axis=1
                )
                
                dup_mask = combined_series[non_empty_mask].duplicated(keep='first')
                failed_indices.update(dup_mask[dup_mask].index)

        # Separate data
        invalid_rows = df.loc[list(failed_indices)]
        df = df.drop(index=list(failed_indices))

        self.update_state(state='PROGRESS', meta={'status': 'Finalizing columns...', 'percent': 70})
        if cols_to_drop:
            df = df.drop(columns=cols_to_drop, errors='ignore')
            invalid_rows = invalid_rows.drop(columns=cols_to_drop, errors='ignore')

        self.update_state(state='PROGRESS', meta={'status': 'Saving outputs...', 'percent': 90})
        
        # --- HEALTH SCORE CALCULATION ---
        health_score = round((len(df) / total_before) * 100, 1) if total_before > 0 else 0

        unique_id = str(uuid.uuid4())
        cleaned_filename = f"cleaned_{unique_id}.xlsx"
        df.to_excel(os.path.join("uploads", cleaned_filename), index=False)

        invalid_filename = None
        if not invalid_rows.empty:
            invalid_filename = f"invalid_{unique_id}.xlsx"
            invalid_rows.to_excel(os.path.join("uploads", invalid_filename), index=False)

        log_action(user_id, f"Cleaned file {uploaded_name}", 
                   total=total_before, valid=len(df), invalid=len(invalid_rows))

        return {
            'total': total_before,
            'valid': len(df),
            'invalid': len(invalid_rows),
            'health_score': health_score,  # Add score to result
            'file': cleaned_filename,
            'invalid_file': invalid_filename,
            'preview_table': df.head(10).to_html(classes="table table-bordered", index=False)
        }
    except Exception as e:
        self.update_state(state='FAILURE', meta={'error': str(e)})
        return {'error': str(e)}

# --- AUTH & DASHBOARD ---

@app.route("/register", methods=["GET", "POST"])
def register():
    try:
        is_first_user = count_users() == 0
    except Exception as e:
        flash(f"Database is not ready: {e}", "danger")
        return render_template("register.html")

    if not is_first_user and session.get("role") != "admin":
        return redirect(url_for("login"))

    if request.method == "POST":
        username, pw, role = request.form["username"], request.form["password"].encode("utf-8"), request.form["role"]
        if is_first_user:
            role = "admin"
        hashed = bcrypt.hashpw(pw, bcrypt.gensalt()).decode("utf-8")
        try:
            execute_db("INSERT INTO users (username, password, role) VALUES (%s, %s, %s)", (username, hashed, role))
            return redirect(url_for("login"))
        except Exception as e:
            flash(f"Could not create user: {e}", "danger")
    return render_template("register.html", is_first_user=is_first_user)

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username, pw = request.form["username"], request.form["password"].encode("utf-8")
        try:
            user = fetch_one("SELECT id, password, role FROM users WHERE username=%s", (username,))
        except Exception as e:
            flash(f"Database is not ready: {e}", "danger")
            return render_template("login.html")
        if user and bcrypt.checkpw(pw, user["password"].encode("utf-8")):
            # store username in session for display in templates
            session.update({"user_id": user["id"], "role": user["role"], "username": username})
            # make session permanent so the configured timeout applies
            session.permanent = True
            log_action(user["id"], "Logged in")
            return redirect(url_for("choose_page"))
        flash("Invalid credentials", "danger")
    return render_template("login.html")


@app.route("/choose-page")
def choose_page():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("choose_page.html", role=session.get("role", "user"))

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session: return redirect(url_for("login"))
    page = request.args.get("page", 1, type=int)
    search = request.args.get("search", "")
    offset = (page - 1) * 10
    if search:
        q = ("SELECT logs.*, users.username FROM logs JOIN users ON logs.user_id = users.id "
             "WHERE (logs.action ILIKE %s OR users.username ILIKE %s) "
             "ORDER BY logs.created_at DESC LIMIT 10 OFFSET %s")
        params = (f"%{search}%", f"%{search}%", offset)
        count_query = ("SELECT COUNT(*) AS count FROM logs JOIN users ON logs.user_id = users.id "
                       "WHERE (logs.action ILIKE %s OR users.username ILIKE %s)")
        logs = fetch_all(q, params)
        total_rows = fetch_one(count_query, params[:2])["count"]
    else:
        logs = fetch_all("SELECT logs.*, users.username FROM logs JOIN users ON logs.user_id = users.id ORDER BY logs.created_at DESC LIMIT 10 OFFSET %s", (offset,))
        total_rows = fetch_one("SELECT COUNT(*) AS count FROM logs")["count"]
    total_pages = max(1, (total_rows + 9) // 10)
    return render_template("dashboard.html", role=session["role"], logs=logs, page=page, total_pages=total_pages, search=search)

# --- ADMIN ROUTES ---

@app.route("/admin/logs")
def admin_logs():
    if "user_id" not in session or session.get("role") != "admin": 
        return redirect(url_for("login"))
    page = request.args.get("page", 1, type=int)
    search = request.args.get("search", "")
    offset = (page - 1) * 10
    if search:
        q = ("SELECT logs.*, users.username FROM logs JOIN users ON logs.user_id = users.id "
             "WHERE (logs.action ILIKE %s OR users.username ILIKE %s) "
             "ORDER BY logs.created_at DESC LIMIT 10 OFFSET %s")
        params = (f"%{search}%", f"%{search}%", offset)
        count_query = ("SELECT COUNT(*) AS count FROM logs JOIN users ON logs.user_id = users.id "
                       "WHERE (logs.action ILIKE %s OR users.username ILIKE %s)")
        logs = fetch_all(q, params)
        total_rows = fetch_one(count_query, params[:2])["count"]
    else:
        logs = fetch_all("SELECT logs.*, users.username FROM logs JOIN users ON logs.user_id = users.id ORDER BY logs.created_at DESC LIMIT 10 OFFSET %s", (offset,))
        total_rows = fetch_one("SELECT COUNT(*) AS count FROM logs")["count"]
    total_pages = max(1, (total_rows + 9) // 10)
    return render_template("admin_logs.html", logs=logs, page=page, total_pages=total_pages, search=search)

@app.route("/admin/logs/export")
def export_logs():
    if session.get("role") != "admin": return redirect(url_for("login"))
    logs = fetch_all("SELECT logs.*, users.username FROM logs JOIN users ON logs.user_id = users.id ORDER BY logs.created_at DESC")
    df = pd.DataFrame(logs); df.to_excel("logs_export.xlsx", index=False)
    return send_file("logs_export.xlsx", as_attachment=True)

# --- CORE UTILITIES ---

@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "user_id" not in session: return redirect(url_for("login"))
    if request.method == "POST":
        file = request.files.get("file")
        if file and file.filename.endswith((".xls", ".xlsx")):
            df = pd.read_excel(file)
            
            # --- SCHEMA CHECK LOGIC ---
            df.columns = [str(c).strip().lower() for c in df.columns]
            missing = [col for col in REQUIRED_COLUMNS if col not in df.columns]
            if missing:
                flash(f"Note: Missing suggested columns: {', '.join(missing)}", "warning")
            # ------------------------------

            unique_id = str(uuid.uuid4())
            uploaded_filename = secure_filename(file.filename)
            filepath = UPLOADS_DIR / f"{unique_id}_{uploaded_filename}"
            df.to_excel(filepath, index=False)
            
            session.update({"current_file": str(filepath), "uploaded_file_name": uploaded_filename})
            suggestions = {col: predict_rules_for_column(col) for col in df.columns}
            return render_template("choose_rules.html", columns=df.columns.tolist(), suggestions=suggestions)
    return render_template("upload.html")

@app.route("/clean", methods=["POST"])
def clean():
    if "user_id" not in session: return redirect(url_for("login"))
    rules_dict = {k.replace("rules_", ""): request.form.getlist(k) for k in request.form if k.startswith("rules_")}
    cols_to_drop = [k.replace("delete_", "") for k in request.form if k.startswith("delete_")]
    task = process_cleaning_task.delay(session.get("current_file"), rules_dict, cols_to_drop, session.get('uploaded_file_name'), session.get('user_id'))
    return render_template("processing.html", task_id=task.id)

@app.route("/task_status/<task_id>")
def task_status(task_id):
    # Use the Celery app to fetch task status reliably
    task = celery_app.AsyncResult(task_id)
    result = None
    if task.state == 'SUCCESS':
        result = task.result
    else:
        # progress/error metadata is stored in task.info
        result = task.info
    return jsonify({'state': task.state, 'result': result})

@app.route("/preview_results")
def preview_results():
    if "user_id" not in session:
        return redirect(url_for("login"))

    file_name = request.args.get('file')
    if not is_safe_upload_name(file_name) or file_name == 'null':
        flash("Result file not found.", "danger")
        return redirect(url_for('dashboard'))

    result_path = UPLOADS_DIR / file_name
    if not result_path.exists():
        flash("Result file not found.", "danger")
        return redirect(url_for('dashboard'))
    
    # Cast variables securely for Jinja template math
    args = dict(request.args)
    args['health_score'] = float(args.get('health_score', 0))
    args['total'] = int(args.get('total', 0))
    args['valid'] = int(args.get('valid', 0))
    args['invalid'] = int(args.get('invalid', 0))
    args['preview_table'] = pd.read_excel(result_path).head(10).to_html(classes="table table-bordered", index=False)
        
    return render_template("preview.html", **args)


@app.route('/presets', methods=['GET'])
def get_presets():
    if 'user_id' not in session:
        return jsonify([])
    user_id = session['user_id']
    path = PRESETS_DIR / f"{user_id}.json"
    if not path.exists():
        return jsonify([])
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            data = json.load(fh)
        return jsonify(data)
    except Exception:
        return jsonify([])


@app.route('/presets', methods=['POST'])
def save_preset():
    if 'user_id' not in session:
        return jsonify({'error': 'unauthenticated'}), 401
    payload = request.get_json() or {}
    name = payload.get('name')
    rules = payload.get('rules')
    deletes = payload.get('deletes', [])
    if not name or not rules:
        return jsonify({'error': 'name and rules required'}), 400
    user_id = session['user_id']
    path = PRESETS_DIR / f"{user_id}.json"
    presets = []
    if path.exists():
        try:
            with open(path, 'r', encoding='utf-8') as fh:
                presets = json.load(fh)
        except Exception:
            presets = []
    # replace if exists
    existing = next((p for p in presets if p.get('name') == name), None)
    entry = {'name': name, 'rules': rules, 'deletes': deletes}
    if existing:
        presets = [entry if p.get('name') == name else p for p in presets]
    else:
        presets.append(entry)
    try:
        with open(path, 'w', encoding='utf-8') as fh:
            json.dump(presets, fh, indent=2)
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route("/download/<filename>")
def download(filename):
    if "user_id" not in session:
        return redirect(url_for("login"))
    if not is_safe_upload_name(filename):
        abort(404)
    return send_from_directory(UPLOADS_DIR, filename, as_attachment=True)

@app.route("/fetch_columns", methods=["GET", "POST"])
def fetch_columns():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    if request.method == "POST":
        payload = request.get_json() or {}
        filename = payload.get("file")
        columns = payload.get("columns", [])
    else:
        filename = request.args.get("file")
        columns_param = request.args.get("columns", "")
        columns = [c.strip() for c in columns_param.split(",") if c.strip()] if columns_param else []
    
    if not filename or not is_safe_upload_name(filename):
        return jsonify({"error": "Invalid or missing file parameter"}), 400
    
    filepath = UPLOADS_DIR / filename
    if not filepath.exists():
        return jsonify({"error": "File not found"}), 404
    
    try:
        df = pd.read_excel(filepath)
        
        if not columns:
            columns = df.columns.tolist()
            
        valid_columns = [col for col in columns if col in df.columns]
        missing_columns = [col for col in columns if col not in df.columns]
        
        if not valid_columns:
            return jsonify({
                "error": "None of the requested columns exist in the dataset",
                "available_columns": df.columns.tolist()
            }), 400
            
        result_df = df[valid_columns]
        result_df = result_df.replace({pd.NA: None}).where(pd.notnull(result_df), None)
        data = result_df.to_dict(orient="records")
        
        response = {
            "file": filename,
            "requested_columns": columns,
            "fetched_columns": valid_columns,
            "data": data
        }
        if missing_columns:
            response["missing_columns"] = missing_columns
            
        return jsonify(response)
    except Exception as e:
        return jsonify({"error": f"Failed to fetch columns: {str(e)}"}), 500


@app.route("/logout")
def logout():
    session.clear(); return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)