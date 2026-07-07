import psycopg2
from psycopg2 import Error
import traceback
import os
from dotenv import load_dotenv

load_dotenv()

HOST = os.environ.get("SUPABASE_DB_HOST", "127.0.0.1")
USER = os.environ.get("SUPABASE_DB_USER", "postgres")
PASSWORD = os.environ.get("SUPABASE_DB_PASSWORD", "")
DATABASE = os.environ.get("SUPABASE_DB_NAME", "postgres")
PORT = os.environ.get("SUPABASE_DB_PORT", "5432")

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
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
        full_name VARCHAR(255) NULL,
        email_address VARCHAR(255) NULL,
        primary_phone_number VARCHAR(100) NULL,
        alternate_phone_number VARCHAR(100) NULL,
        company_name VARCHAR(255) NULL,
        job_title VARCHAR(255) NULL,
        department VARCHAR(255) NULL,
        website_url VARCHAR(255) NULL,
        address_line_1 VARCHAR(255) NULL,
        address_line_2 VARCHAR(255) NULL,
        city VARCHAR(255) NULL,
        state_province VARCHAR(255) NULL,
        postal_zip_code VARCHAR(100) NULL,
        country VARCHAR(255) NULL,
        linkedin_profile_url VARCHAR(255) NULL,
        industry VARCHAR(255) NULL,
        lead_source VARCHAR(255) NULL,
        record_status VARCHAR(100) NULL,
        date_of_birth VARCHAR(100) NULL,
        gender VARCHAR(50) NULL,
        company_size VARCHAR(100) NULL,
        annual_revenue VARCHAR(100) NULL,
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
    """
]

# Separate index and trigger statements (Postgres doesn't support inline INDEX in CREATE TABLE)
sql_statements.extend([
    "CREATE INDEX IF NOT EXISTS idx_full_name ON master_records(full_name)",
    "CREATE INDEX IF NOT EXISTS idx_email ON master_records(email_address)",
    "CREATE INDEX IF NOT EXISTS idx_phone ON master_records(primary_phone_number)",
    "CREATE INDEX IF NOT EXISTS idx_company ON master_records(company_name)",
    "CREATE INDEX IF NOT EXISTS idx_city ON master_records(city)",
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

    # Seed Default Custom Fields in Registry
    default_fields = [
        {"name": "Passport Number", "norm": "passport_number", "type": "VARCHAR"},
        {"name": "Blood Group", "norm": "blood_group", "type": "VARCHAR"},
        {"name": "National ID", "norm": "national_id", "type": "VARCHAR"}
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
        ("Full Name", "master", "full_name"),
        ("Name", "master", "full_name"),
        ("Email Address", "master", "email_address"),
        ("E-mail", "master", "email_address"),
        ("Primary Phone Number", "master", "primary_phone_number"),
        ("Contact Number", "master", "primary_phone_number"),
        ("Mobile No", "master", "primary_phone_number"),
        ("Mobile Number", "master", "primary_phone_number"),
        ("Alternate Phone Number", "master", "alternate_phone_number"),
        ("Company Name", "master", "company_name"),
        ("Company", "master", "company_name"),
        ("Organization", "master", "company_name"),
        ("Job Title", "master", "job_title"),
        ("Department", "master", "department"),
        ("Website URL", "master", "website_url"),
        ("Website", "master", "website_url"),
        ("Address Line 1", "master", "address_line_1"),
        ("Address Line 2", "master", "address_line_2"),
        ("City", "master", "city"),
        ("State / Province", "master", "state_province"),
        ("State Name", "master", "state_province"),
        ("State", "master", "state_province"),
        ("Postal / ZIP Code", "master", "postal_zip_code"),
        ("ZIP Code", "master", "postal_zip_code"),
        ("Postal Code", "master", "postal_zip_code"),
        ("Country", "master", "country"),
        ("Country Name", "master", "country"),
        ("LinkedIn Profile URL", "master", "linkedin_profile_url"),
        ("LinkedIn", "master", "linkedin_profile_url"),
        ("Industry", "master", "industry"),
        ("Lead Source", "master", "lead_source"),
        ("Record Status", "master", "record_status"),
        ("Date of Birth", "master", "date_of_birth"),
        ("DOB", "master", "date_of_birth"),
        ("Gender", "master", "gender"),
        ("Company Size", "master", "company_size"),
        ("Annual Revenue", "master", "annual_revenue"),
        ("Imported By", "master", "imported_by"),
        ("Passport No", "custom", "passport_number"),
        ("Passport", "custom", "passport_number"),
        ("Blood Type", "custom", "blood_group")
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
