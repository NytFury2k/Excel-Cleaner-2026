import os
import psycopg2
import mysql.connector
from dotenv import load_dotenv

# Load env variables
load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

# Local MySQL connection info (falls back to values in code)
MYSQL_HOST = "127.0.0.1"
MYSQL_USER = "excel_cleaner_app"
MYSQL_PASSWORD = "excelapppass"
MYSQL_DATABASE = "excel_cleaner_db"

if not DATABASE_URL:
    print("Error: DATABASE_URL not found in .env file.")
    exit(1)

def migrate():
    print("Connecting to source MySQL database...")
    try:
        mysql_conn = mysql.connector.connect(
            host=MYSQL_HOST,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
            database=MYSQL_DATABASE
        )
        mysql_cur = mysql_conn.cursor(dictionary=True)
    except Exception as e:
        print(f"Failed to connect to local MySQL database: {e}")
        print("Skipping data migration. You can initialize a clean database on Supabase using init_supabase.py.")
        return

    print("Connecting to target Supabase (PostgreSQL) database...")
    try:
        pg_conn = psycopg2.connect(DATABASE_URL)
        pg_cur = pg_conn.cursor()
    except Exception as e:
        print(f"Failed to connect to Supabase: {e}")
        mysql_conn.close()
        return

    try:
        # Disable foreign key checks / truncate tables in target
        print("Clearing target tables to avoid duplicates...")
        tables_to_clear = ["logs", "login_attempts", "api_tokens", "cleaning_jobs", "rule_presets", "users", "role_permissions", "permissions", "roles"]
        for table in tables_to_clear:
            pg_cur.execute(f"TRUNCATE TABLE {table} CASCADE;")
        pg_conn.commit()

        # 1. Migrate roles
        print("Migrating roles...")
        mysql_cur.execute("SELECT id, name FROM roles")
        for row in mysql_cur.fetchall():
            pg_cur.execute("INSERT INTO roles (id, name) VALUES (%s, %s)", (row['id'], row['name']))
        pg_conn.commit()

        # 2. Migrate permissions
        print("Migrating permissions...")
        mysql_cur.execute("SELECT id, name, description FROM permissions")
        for row in mysql_cur.fetchall():
            pg_cur.execute("INSERT INTO permissions (id, name, description) VALUES (%s, %s, %s)", (row['id'], row['name'], row['description']))
        pg_conn.commit()

        # 3. Migrate role_permissions
        print("Migrating role_permissions...")
        mysql_cur.execute("SELECT role_id, permission_id FROM role_permissions")
        for row in mysql_cur.fetchall():
            pg_cur.execute("INSERT INTO role_permissions (role_id, permission_id) VALUES (%s, %s)", (row['role_id'], row['permission_id']))
        pg_conn.commit()

        # 4. Migrate users
        print("Migrating users...")
        mysql_cur.execute("SELECT id, username, password, role, is_active, manager_id, created_by, created_at, role_id, email, requires_password_change FROM users")
        users_data = mysql_cur.fetchall()
        
        # Phase 1: Insert all users without self-referential foreign keys
        for row in users_data:
            is_active = bool(row['is_active'])
            requires_password_change = bool(row['requires_password_change'])
            
            pg_cur.execute(
                """INSERT INTO users 
                (id, username, password, role, is_active, manager_id, created_by, created_at, role_id, email, requires_password_change) 
                VALUES (%s, %s, %s, %s, %s, NULL, NULL, %s, %s, %s, %s)""",
                (
                    row['id'], row['username'], row['password'], row['role'], is_active,
                    row['created_at'], row['role_id'], row['email'], requires_password_change
                )
            )
            
        # Phase 2: Update manager_id and created_by now that all rows exist
        for row in users_data:
            if row['manager_id'] is not None or row['created_by'] is not None:
                pg_cur.execute(
                    "UPDATE users SET manager_id = %s, created_by = %s WHERE id = %s",
                    (row['manager_id'], row['created_by'], row['id'])
                )
        pg_conn.commit()

        # Reset serial sequence for users
        pg_cur.execute("SELECT setval('users_id_seq', COALESCE((SELECT MAX(id)+1 FROM users), 1), false)")

        # 5. Migrate api_tokens
        print("Migrating api_tokens...")
        mysql_cur.execute("SELECT id, user_id, token, created_at, expires_at, is_active FROM api_tokens")
        for row in mysql_cur.fetchall():
            is_active = bool(row['is_active'])
            pg_cur.execute(
                "INSERT INTO api_tokens (id, user_id, token, created_at, expires_at, is_active) VALUES (%s, %s, %s, %s, %s, %s)",
                (row['id'], row['user_id'], row['token'], row['created_at'], row['expires_at'], is_active)
            )
        pg_conn.commit()
        pg_cur.execute("SELECT setval('api_tokens_id_seq', COALESCE((SELECT MAX(id)+1 FROM api_tokens), 1), false)")

        # 6. Migrate cleaning_jobs
        print("Migrating cleaning_jobs...")
        mysql_cur.execute("SELECT id, user_id, temp_file, uploaded_file, cleaned_file, invalid_file, removed_file, rules_json, created_at, updated_at FROM cleaning_jobs")
        for row in mysql_cur.fetchall():
            pg_cur.execute(
                """INSERT INTO cleaning_jobs 
                (id, user_id, temp_file, uploaded_file, cleaned_file, invalid_file, removed_file, rules_json, created_at, updated_at) 
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (
                    row['id'], row['user_id'], row['temp_file'], row['uploaded_file'], row['cleaned_file'],
                    row['invalid_file'], row['removed_file'], row['rules_json'], row['created_at'], row['updated_at']
                )
            )
        pg_conn.commit()
        pg_cur.execute("SELECT setval('cleaning_jobs_id_seq', COALESCE((SELECT MAX(id)+1 FROM cleaning_jobs), 1), false)")

        # 7. Migrate rule_presets
        print("Migrating rule_presets...")
        mysql_cur.execute("SELECT id, user_id, name, rules_json, created_at FROM rule_presets")
        for row in mysql_cur.fetchall():
            pg_cur.execute(
                "INSERT INTO rule_presets (id, user_id, name, rules_json, created_at) VALUES (%s, %s, %s, %s, %s)",
                (row['id'], row['user_id'], row['name'], row['rules_json'], row['created_at'])
            )
        pg_conn.commit()
        pg_cur.execute("SELECT setval('rule_presets_id_seq', COALESCE((SELECT MAX(id)+1 FROM rule_presets), 1), false)")

        # 8. Migrate logs
        print("Migrating logs...")
        mysql_cur.execute("SELECT id, user_id, action, total_rows, valid_rows, invalid_rows, removed_rows, created_at, rules_applied, rule_counts FROM logs")
        for row in mysql_cur.fetchall():
            pg_cur.execute(
                """INSERT INTO logs 
                (id, user_id, action, total_rows, valid_rows, invalid_rows, removed_rows, created_at, rules_applied, rule_counts) 
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (
                    row['id'], row['user_id'], row['action'], row['total_rows'], row['valid_rows'],
                    row['invalid_rows'], row['removed_rows'], row['created_at'], row['rules_applied'], row['rule_counts']
                )
            )
        pg_conn.commit()
        pg_cur.execute("SELECT setval('logs_id_seq', COALESCE((SELECT MAX(id)+1 FROM logs), 1), false)")

        # 9. Migrate login_attempts
        print("Migrating login_attempts...")
        mysql_cur.execute("SELECT id, username, attempted_at, success FROM login_attempts")
        for row in mysql_cur.fetchall():
            success = bool(row['success'])
            pg_cur.execute(
                "INSERT INTO login_attempts (id, username, attempted_at, success) VALUES (%s, %s, %s, %s)",
                (row['id'], row['username'], row['attempted_at'], success)
            )
        pg_conn.commit()
        pg_cur.execute("SELECT setval('login_attempts_id_seq', COALESCE((SELECT MAX(id)+1 FROM login_attempts), 1), false)")

        print("Data migration completed successfully! All tables, records, and auto-increment sequences have been copied.")

    except Exception as e:
        pg_conn.rollback()
        print(f"Error during migration: {e}")
    finally:
        mysql_conn.close()
        pg_conn.close()

if __name__ == "__main__":
    migrate()
