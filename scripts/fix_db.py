import psycopg2
from psycopg2 import Error
import traceback
import os
from dotenv import load_dotenv

load_dotenv()

HOST = os.environ.get("POSTGRES_DB_HOST") or os.environ.get("SUPABASE_DB_HOST") or os.environ.get("DB_HOST", "127.0.0.1")
USER = os.environ.get("POSTGRES_DB_USER") or os.environ.get("SUPABASE_DB_USER") or os.environ.get("DB_USER", "postgres")
PASSWORD = os.environ.get("POSTGRES_DB_PASSWORD") or os.environ.get("SUPABASE_DB_PASSWORD") or os.environ.get("DB_PASSWORD", "")
DATABASE = os.environ.get("POSTGRES_DB_NAME") or os.environ.get("SUPABASE_DB_NAME") or os.environ.get("DB_NAME", "excel_cleaner_db")
PORT = os.environ.get("POSTGRES_DB_PORT") or os.environ.get("SUPABASE_DB_PORT") or os.environ.get("DB_PORT", "5432")

sql_statements = [
    """
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        role VARCHAR(50) NOT NULL DEFAULT 'user',
        is_active SMALLINT NOT NULL DEFAULT 1,
        manager_id INT NULL,
        email VARCHAR(255) NULL,
        requires_password_change SMALLINT NOT NULL DEFAULT 0,
        created_by INT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        status VARCHAR(50) DEFAULT 'active',
        deactivated_at TIMESTAMP NULL,
        phone_number VARCHAR(100) NULL,
        address TEXT NULL,
        export_limit INT DEFAULT 50000
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS logs (
        id SERIAL PRIMARY KEY,
        user_id INT NOT NULL,
        action TEXT NULL,
        total_rows INT NOT NULL DEFAULT 0,
        valid_rows INT NOT NULL DEFAULT 0,
        invalid_rows INT NOT NULL DEFAULT 0,
        removed_rows INT NOT NULL DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        rules_applied TEXT NULL,
        rule_counts TEXT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS login_attempts (
        id SERIAL PRIMARY KEY,
        username VARCHAR(100) NOT NULL,
        attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        success SMALLINT DEFAULT 0
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS api_tokens (
        id SERIAL PRIMARY KEY,
        user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token VARCHAR(64) NOT NULL UNIQUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP NOT NULL,
        is_active SMALLINT DEFAULT 1
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS uploaded_files (
        id SERIAL PRIMARY KEY,
        user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        filename VARCHAR(255) NOT NULL,
        original_filename VARCHAR(255) NOT NULL,
        uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        total_rows INT DEFAULT 0,
        rows_imported INT DEFAULT 0,
        rows_rejected INT DEFAULT 0,
        status VARCHAR(50) NOT NULL DEFAULT 'pending'
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS field_registry (
        id SERIAL PRIMARY KEY,
        field_name VARCHAR(150) NOT NULL UNIQUE,
        normalized_name VARCHAR(150) NOT NULL UNIQUE,
        data_type VARCHAR(50) NOT NULL DEFAULT 'VARCHAR',
        is_active SMALLINT DEFAULT 1,
        searchable SMALLINT DEFAULT 1,
        filterable SMALLINT DEFAULT 1,
        usage_count INT DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS field_aliases (
        id SERIAL PRIMARY KEY,
        alias VARCHAR(150) NOT NULL UNIQUE,
        normalized_alias VARCHAR(150) NOT NULL,
        target_type VARCHAR(50) NOT NULL,
        target_identifier VARCHAR(150) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS master_records (
        id SERIAL PRIMARY KEY,
        file_id INT NOT NULL REFERENCES uploaded_files(id) ON DELETE CASCADE,
        first_name VARCHAR(255) NULL,
        last_name VARCHAR(255) NULL,
        custom_fields JSONB NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        imported_by VARCHAR(255) NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS rejected_records (
        id SERIAL PRIMARY KEY,
        file_id INT NOT NULL REFERENCES uploaded_files(id) ON DELETE CASCADE,
        row_data JSONB NULL,
        rejected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS cleaning_jobs (
        id SERIAL PRIMARY KEY,
        user_id INT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
        temp_file VARCHAR(500) DEFAULT NULL,
        uploaded_file VARCHAR(500) DEFAULT NULL,
        cleaned_file VARCHAR(500) DEFAULT NULL,
        invalid_file VARCHAR(500) DEFAULT NULL,
        removed_file VARCHAR(500) DEFAULT NULL,
        rules_json TEXT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS rule_presets (
        id SERIAL PRIMARY KEY,
        user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(100) NOT NULL,
        rules_json TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (user_id, name)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS search_logs (
        id SERIAL PRIMARY KEY,
        user_id INT NOT NULL,
        username VARCHAR(255) NOT NULL,
        search_term TEXT NOT NULL,
        searched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS roles (
        id SERIAL PRIMARY KEY,
        name VARCHAR(50) NOT NULL UNIQUE
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS permissions (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL UNIQUE,
        description TEXT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS role_permissions (
        id SERIAL PRIMARY KEY,
        role_id INT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
        permission_id INT NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
        UNIQUE (role_id, permission_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS user_change_requests (
        id SERIAL PRIMARY KEY,
        user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        username VARCHAR(255) NULL,
        email VARCHAR(255) NULL,
        phone_number VARCHAR(100) NULL,
        address TEXT NULL,
        status VARCHAR(50) DEFAULT 'pending',
        requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        approved_by INT NULL,
        approved_at TIMESTAMP NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS user_notifications (
        id SERIAL PRIMARY KEY,
        recipient_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        sender_id INT NULL REFERENCES users(id) ON DELETE SET NULL,
        message TEXT NOT NULL,
        action_type VARCHAR(100) NULL,
        is_read BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS role_export_limits (
        role_name VARCHAR(50) PRIMARY KEY,
        default_limit INT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS user_daily_exports (
        user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        export_date DATE NOT NULL,
        rows_count INT NOT NULL,
        PRIMARY KEY (user_id, export_date)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS client_api_keys (
        id SERIAL PRIMARY KEY,
        user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        key_name VARCHAR(255) NOT NULL,
        key_type VARCHAR(100) NULL,
        api_key VARCHAR(255) NOT NULL UNIQUE,
        filters_json TEXT NULL,
        requested_rows_limit INT NULL,
        max_rows_limit INT NULL,
        requested_expiry_date DATE NULL,
        expires_at TIMESTAMP NULL,
        status VARCHAR(50) DEFAULT 'pending',
        is_active SMALLINT DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        approved_by INT NULL,
        approved_at TIMESTAMP NULL
    )
    """
]

# Separate index and trigger statements (Postgres doesn't support inline INDEX in CREATE TABLE)
sql_statements.extend([
    "CREATE INDEX IF NOT EXISTS idx_first_name ON master_records(first_name)",
    "CREATE INDEX IF NOT EXISTS idx_last_name ON master_records(last_name)",
    "CREATE INDEX IF NOT EXISTS idx_login_username_time ON login_attempts(username, attempted_at)",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS role_id INT NULL REFERENCES roles(id) ON DELETE SET NULL",
    # Trigger function for auto-updating updated_at columns
    """
    CREATE OR REPLACE FUNCTION update_modified_column()
    RETURNS TRIGGER AS $$
    BEGIN
        NEW.updated_at = now();
        RETURN NEW;
    END;
    $$ language 'plpgsql'
    """,
    "DROP TRIGGER IF EXISTS update_master_records_modtime ON master_records",
    """
    CREATE TRIGGER update_master_records_modtime
        BEFORE UPDATE ON master_records
        FOR EACH ROW
        EXECUTE FUNCTION update_modified_column()
    """,
    "DROP TRIGGER IF EXISTS update_cleaning_jobs_modtime ON cleaning_jobs",
    """
    CREATE TRIGGER update_cleaning_jobs_modtime
        BEFORE UPDATE ON cleaning_jobs
        FOR EACH ROW
        EXECUTE FUNCTION update_modified_column()
    """
])

conn = None
try:
    conn = psycopg2.connect(
        host=HOST,
        database=DATABASE,
        user=USER,
        password=PASSWORD,
        port=PORT
    )
    cur = conn.cursor()

    # Drop tables cleanly (CASCADE handles FK dependencies)
    try:
        cur.execute("DROP TABLE IF EXISTS master_records CASCADE")
        cur.execute("DROP TABLE IF EXISTS rejected_records CASCADE")
        cur.execute("DROP TABLE IF EXISTS uploaded_files CASCADE")
        cur.execute("DROP TABLE IF EXISTS field_registry CASCADE")
        cur.execute("DROP TABLE IF EXISTS field_aliases CASCADE")
        cur.execute("DROP TABLE IF EXISTS rule_presets CASCADE")
        cur.execute("DROP TABLE IF EXISTS api_tokens CASCADE")
        cur.execute("DROP TABLE IF EXISTS logs CASCADE")
        cur.execute("DROP TABLE IF EXISTS login_attempts CASCADE")
        cur.execute("DROP TABLE IF EXISTS cleaning_jobs CASCADE")
        cur.execute("DROP TABLE IF EXISTS search_logs CASCADE")
        cur.execute("DROP TABLE IF EXISTS user_change_requests CASCADE")
        cur.execute("DROP TABLE IF EXISTS user_notifications CASCADE")
        cur.execute("DROP TABLE IF EXISTS role_export_limits CASCADE")
        cur.execute("DROP TABLE IF EXISTS user_daily_exports CASCADE")
        cur.execute("DROP TABLE IF EXISTS client_api_keys CASCADE")
        cur.execute("DROP TABLE IF EXISTS users CASCADE")
        conn.commit()
    except Exception:
        conn.rollback()

    for stmt in sql_statements:
        cur.execute(stmt)
    conn.commit()

    # Ensure the admin user exists with the expected password hash.
    cur.execute("SELECT COUNT(*) FROM users WHERE username = %s", ('admin',))
    if cur.fetchone()[0] == 0:
        cur.execute(
            "INSERT INTO users (username, password, role) VALUES (%s, %s, %s)",
            ('admin', '$2b$12$UOQzAAufKsipUFuIlH8JHu2RZHYQ7rL6Xe9fHC27F6SYn1iOTZvRi', 'admin')
        )

    # Seed default role export limits
    default_limits = [
        ('admin', 50000),
        ('manager', 50000),
        ('team_lead', 50000),
        ('user', 50000),
        ('client', 50000)
    ]
    for role, limit in default_limits:
        cur.execute("SELECT COUNT(*) FROM role_export_limits WHERE role_name = %s", (role,))
        if cur.fetchone()[0] == 0:
            cur.execute(
                "INSERT INTO role_export_limits (role_name, default_limit) VALUES (%s, %s)",
                (role, limit)
            )

    # Seed Default Custom Fields in Registry
    default_fields = [
        {"name": "Email Address", "norm": "email_address", "type": "VARCHAR"},
        {"name": "Primary Phone Number", "norm": "primary_phone_number", "type": "VARCHAR"},
        {"name": "Alternate Phone Number", "norm": "alternate_phone_number", "type": "VARCHAR"},
        {"name": "Company Name", "norm": "company_name", "type": "VARCHAR"},
        {"name": "Job Title", "norm": "job_title", "type": "VARCHAR"},
        {"name": "Department", "norm": "department", "type": "VARCHAR"},
        {"name": "Website URL", "norm": "website_url", "type": "VARCHAR"},
        {"name": "Address Line 1", "norm": "address_line_1", "type": "VARCHAR"},
        {"name": "Address Line 2", "norm": "address_line_2", "type": "VARCHAR"},
        {"name": "City", "norm": "city", "type": "VARCHAR"},
        {"name": "State / Province", "norm": "state_province", "type": "VARCHAR"},
        {"name": "Postal / ZIP Code", "norm": "postal_zip_code", "type": "VARCHAR"},
        {"name": "Country", "norm": "country", "type": "VARCHAR"},
        {"name": "LinkedIn Profile URL", "norm": "linkedin_profile_url", "type": "VARCHAR"},
        {"name": "Industry", "norm": "industry", "type": "VARCHAR"},
        {"name": "Lead Source", "norm": "lead_source", "type": "VARCHAR"},
        {"name": "Record Status", "norm": "record_status", "type": "VARCHAR"},
        {"name": "Date of Birth", "norm": "date_of_birth", "type": "VARCHAR"},
        {"name": "Gender", "norm": "gender", "type": "VARCHAR"},
        {"name": "Company Size", "norm": "company_size", "type": "VARCHAR"},
        {"name": "Annual Revenue", "norm": "annual_revenue", "type": "VARCHAR"}
    ]
    
    registered_fields = {}
    for f in default_fields:
        cur.execute("SELECT id FROM field_registry WHERE normalized_name = %s", (f["norm"],))
        res = cur.fetchone()
        if not res:
            cur.execute(
                "INSERT INTO field_registry (field_name, normalized_name, data_type, usage_count) VALUES (%s, %s, %s, %s) RETURNING id",
                (f["name"], f["norm"], f["type"], 0)
            )
            registered_fields[f["norm"]] = cur.fetchone()[0]
        else:
            registered_fields[f["norm"]] = res[0]

    # Seed Default Field Aliases
    default_aliases = [
        ("First Name", "master", "first_name"),
        ("Last Name", "master", "last_name"),
        ("FirstName", "master", "first_name"),
        ("LastName", "master", "last_name"),
        ("First_Name", "master", "first_name"),
        ("Last_Name", "master", "last_name"),
        ("Full Name", "master", "full_name"),
        ("Name", "master", "full_name"),
        
        ("Email Address", "custom", "email_address"),
        ("E-mail", "custom", "email_address"),
        ("Primary Phone Number", "custom", "primary_phone_number"),
        ("Contact Number", "custom", "primary_phone_number"),
        ("Mobile No", "custom", "primary_phone_number"),
        ("Mobile Number", "custom", "primary_phone_number"),
        ("Alternate Phone Number", "custom", "alternate_phone_number"),
        ("Company Name", "custom", "company_name"),
        ("Company", "custom", "company_name"),
        ("Organization", "custom", "company_name"),
        ("Job Title", "custom", "job_title"),
        ("Department", "custom", "department"),
        ("Website URL", "custom", "website_url"),
        ("Website", "custom", "website_url"),
        ("Address Line 1", "custom", "address_line_1"),
        ("Address Line 2", "custom", "address_line_2"),
        ("City", "custom", "city"),
        ("State / Province", "custom", "state_province"),
        ("State Name", "custom", "state_province"),
        ("State", "custom", "state_province"),
        ("Postal / ZIP Code", "custom", "postal_zip_code"),
        ("ZIP Code", "custom", "postal_zip_code"),
        ("Postal Code", "custom", "postal_zip_code"),
        ("Country", "custom", "country"),
        ("Country Name", "custom", "country"),
        ("LinkedIn Profile URL", "custom", "linkedin_profile_url"),
        ("LinkedIn", "custom", "linkedin_profile_url"),
        ("Industry", "custom", "industry"),
        ("Lead Source", "custom", "lead_source"),
        ("Record Status", "custom", "record_status"),
        ("Date of Birth", "custom", "date_of_birth"),
        ("DOB", "custom", "date_of_birth"),
        ("Gender", "custom", "gender"),
        ("Company Size", "custom", "company_size"),
        ("Annual Revenue", "custom", "annual_revenue"),
        ("Imported By", "master", "imported_by")
    ]

    for alias, t_type, t_id in default_aliases:
        norm = alias.strip().lower().replace(" ", "_") # simple norm
        cur.execute("SELECT id FROM field_aliases WHERE alias = %s", (alias,))
        if not cur.fetchone():
            resolved_id = t_id
            if t_type == "custom":
                resolved_id = str(registered_fields.get(t_id, ''))
                if not resolved_id:
                    continue
            try:
                cur.execute(
                    "INSERT INTO field_aliases (alias, normalized_alias, target_type, target_identifier) VALUES (%s, %s, %s, %s)",
                    (alias, norm, t_type, resolved_id)
                )
            except Error:
                conn.rollback()

    conn.commit()
    print('Database schema setup completed successfully.')
    cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'")
    print('Tables:', [row[0] for row in cur.fetchall()])
except Error as e:
    if conn is not None:
        conn.rollback()
    print(f'Database error: {e}')
    traceback.print_exc()
except Exception as e:
    if conn is not None:
        conn.rollback()
    print(f'Unexpected error: {e}')
    traceback.print_exc()
finally:
    if conn is not None:
        conn.close()
