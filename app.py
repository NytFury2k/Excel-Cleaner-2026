import os
import uuid
import re
import bcrypt
import time
import pandas as pd
import mysql.connector
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, jsonify
from mysql.connector import pooling
from io import BytesIO
from dotenv import load_dotenv
from celery import Celery

# Load secrets from .env
load_dotenv()

REQUIRED_COLUMNS = ['first_name', 'last_name', 'email', 'phone', 'company']

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")

# --- CELERY CONFIGURATION ---
def make_celery(app):
    celery = Celery(
        'app',  # <--- CHANGED THIS from app.import_name
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

# --- DATABASE POOLING ---
db_pool = pooling.MySQLConnectionPool(
    pool_name="mypool",
    pool_size=5, 
    host=os.getenv("DB_HOST"),
    user=os.getenv("DB_USER"),
    password=os.getenv("DB_PASSWORD"),
    database=os.getenv("DB_NAME")
)

def get_db_connection():
    return db_pool.get_connection()

def log_action(user_id, action, total=None, valid=None, invalid=None):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO logs (user_id, action, total_rows, valid_rows, invalid_rows)
            VALUES (%s, %s, %s, %s, %s)
        """, (user_id, action, total, valid, invalid))
        conn.commit()
        cursor.close()
        conn.close()
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
                phone_pattern = re.compile(r'^\+?[0-9]{7,15}$')
                for idx, val in df[column].items():
                    if val != "" and not bool(phone_pattern.match(val)):
                        failed_indices.add(idx)

            if "drop_duplicates" in rules:
                duplicates = df[df.duplicated(subset=[column], keep='first')].index
                failed_indices.update(duplicates)

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
    if request.method == "POST":
        username, pw, role = request.form["username"], request.form["password"].encode("utf-8"), request.form["role"]
        hashed = bcrypt.hashpw(pw, bcrypt.gensalt()).decode("utf-8")
        try:
            conn = get_db_connection(); cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password, role) VALUES (%s, %s, %s)", (username, hashed, role))
            conn.commit(); conn.close()
            return redirect(url_for("login"))
        except: flash("Username exists!", "danger")
    return render_template("register.html")

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username, pw = request.form["username"], request.form["password"].encode("utf-8")
        conn = get_db_connection(); cursor = conn.cursor()
        cursor.execute("SELECT id, password, role FROM users WHERE username=%s", (username,))
        user = cursor.fetchone(); conn.close()
        if user and bcrypt.checkpw(pw, user[1].encode("utf-8")):
            session.update({"user_id": user[0], "role": user[2]})
            log_action(user[0], "Logged in")
            return redirect(url_for("dashboard"))
        flash("Invalid credentials", "danger")
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session: return redirect(url_for("login"))
    page = request.args.get("page", 1, type=int)
    offset = (page - 1) * 10
    conn = get_db_connection(); cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT logs.*, users.username FROM logs JOIN users ON logs.user_id = users.id ORDER BY logs.created_at DESC LIMIT 10 OFFSET %s", (offset,))
    logs = cursor.fetchall(); conn.close()
    return render_template("dashboard.html", role=session["role"], logs=logs, page=page, total_pages=10)

# --- ADMIN ROUTES ---

@app.route("/admin/logs")
def admin_logs():
    if "user_id" not in session or session.get("role") != "admin": 
        return redirect(url_for("login"))
    page = request.args.get("page", 1, type=int)
    offset = (page - 1) * 10
    conn = get_db_connection(); cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT logs.*, users.username FROM logs JOIN users ON logs.user_id = users.id ORDER BY logs.created_at DESC LIMIT 10 OFFSET %s", (offset,))
    logs = cursor.fetchall(); conn.close()
    return render_template("admin_logs.html", logs=logs, page=page, total_pages=10)

@app.route("/admin/logs/export")
def export_logs():
    if session.get("role") != "admin": return redirect(url_for("login"))
    conn = get_db_connection(); cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM logs"); logs = cursor.fetchall(); conn.close()
    df = pd.DataFrame(logs); df.to_excel("logs_export.xlsx", index=False)
    return send_file("logs_export.xlsx", as_attachment=True)

# --- CORE UTILITIES ---

@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "user_id" not in session: return redirect(url_for("login"))
    if request.method == "POST":
        file = request.files.get("file")
        if file and file.filename.endswith((".xls", ".xlsx")):
            if not os.path.exists("uploads"): os.makedirs("uploads")
            df = pd.read_excel(file)
            
            # --- SCHEMA CHECK LOGIC ---
            df.columns = [str(c).strip().lower() for c in df.columns]
            missing = [col for col in REQUIRED_COLUMNS if col not in df.columns]
            if missing:
                flash(f"Note: Missing suggested columns: {', '.join(missing)}", "warning")
            # ------------------------------

            unique_id = str(uuid.uuid4())
            filepath = os.path.join("uploads", f"{unique_id}_{file.filename}")
            df.to_excel(filepath, index=False)
            
            session.update({"current_file": filepath, "uploaded_file_name": file.filename})
            return render_template("choose_rules.html", columns=df.columns.tolist())
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
    task = process_cleaning_task.AsyncResult(task_id)
    return jsonify({'state': task.state, 'result': task.result if task.state == 'SUCCESS' else task.info})

@app.route("/preview_results")
def preview_results():
    file_name = request.args.get('file')
    if not file_name or file_name == 'null':
        flash("Result file not found.", "danger")
        return redirect(url_for('dashboard'))
    
    # Cast variables securely for Jinja template math
    args = dict(request.args)
    args['health_score'] = float(args.get('health_score', 0))
    args['total'] = int(args.get('total', 0))
    args['valid'] = int(args.get('valid', 0))
    args['invalid'] = int(args.get('invalid', 0))
        
    return render_template("preview.html", **args)

@app.route("/download/<filename>")
def download(filename):
    return send_file(os.path.join("uploads", filename), as_attachment=True)

@app.route("/logout")
def logout():
    session.clear(); return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)