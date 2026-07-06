import mysql.connector
from mysql.connector import Error
import traceback

HOST = '127.0.0.1'
USER = 'excel_cleaner_app'
PASSWORD = 'excelapppass'
DATABASE = 'excel_cleaner_db'

sql_statements = [
    """
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        role VARCHAR(50) NOT NULL DEFAULT 'user',
        is_active TINYINT(1) NOT NULL DEFAULT 1,
        manager_id INT NULL,
        email VARCHAR(255) NULL,
        requires_password_change TINYINT(1) NOT NULL DEFAULT 0
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
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
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(100) NOT NULL,
        attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        success TINYINT(1) DEFAULT 0,
        INDEX idx_username_time (username, attempted_at)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS api_tokens (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        token VARCHAR(64) NOT NULL UNIQUE,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        expires_at DATETIME NOT NULL,
        is_active TINYINT(1) DEFAULT 1,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS uploaded_files (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        filename VARCHAR(255) NOT NULL,
        original_filename VARCHAR(255) NOT NULL,
        uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        total_rows INT DEFAULT 0,
        rows_imported INT DEFAULT 0,
        rows_rejected INT DEFAULT 0,
        status VARCHAR(50) NOT NULL DEFAULT 'pending',
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS field_registry (
        id INT AUTO_INCREMENT PRIMARY KEY,
        field_name VARCHAR(150) NOT NULL UNIQUE,
        normalized_name VARCHAR(150) NOT NULL UNIQUE,
        data_type VARCHAR(50) NOT NULL DEFAULT 'VARCHAR',
        is_active TINYINT(1) DEFAULT 1,
        searchable TINYINT(1) DEFAULT 1,
        filterable TINYINT(1) DEFAULT 1,
        usage_count INT DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS field_aliases (
        id INT AUTO_INCREMENT PRIMARY KEY,
        alias VARCHAR(150) NOT NULL UNIQUE,
        normalized_alias VARCHAR(150) NOT NULL,
        target_type VARCHAR(50) NOT NULL,
        target_identifier VARCHAR(150) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS master_records (
        id INT AUTO_INCREMENT PRIMARY KEY,
        file_id INT NOT NULL,
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
        custom_fields JSON NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        imported_by VARCHAR(255) NULL,
        FOREIGN KEY (file_id) REFERENCES uploaded_files(id) ON DELETE CASCADE,
        INDEX idx_full_name (full_name),
        INDEX idx_email (email_address),
        INDEX idx_phone (primary_phone_number),
        INDEX idx_company (company_name),
        INDEX idx_city (city)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS rejected_records (
        id INT AUTO_INCREMENT PRIMARY KEY,
        file_id INT NOT NULL,
        row_data JSON NULL,
        rejected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (file_id) REFERENCES uploaded_files(id) ON DELETE CASCADE
    )
    """
]

conn = None
try:
    conn = mysql.connector.connect(
        host=HOST,
        user=USER,
        password=PASSWORD,
        database=DATABASE,
        auth_plugin='mysql_native_password',
        connect_timeout=5,
    )
    cur = conn.cursor()

    # Drop master_records, uploaded_files, and custom registry tables to align schemas cleanly
    try:
        cur.execute("SET FOREIGN_KEY_CHECKS = 0")
        cur.execute("DROP TABLE IF EXISTS master_records")
        cur.execute("DROP TABLE IF EXISTS rejected_records")
        cur.execute("DROP TABLE IF EXISTS uploaded_files")
        cur.execute("DROP TABLE IF EXISTS field_registry")
        cur.execute("DROP TABLE IF EXISTS field_aliases")
        cur.execute("SET FOREIGN_KEY_CHECKS = 1")
    except Exception:
        pass

    for stmt in sql_statements:
        cur.execute(stmt)

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
                "INSERT INTO field_registry (field_name, normalized_name, data_type, usage_count) VALUES (%s, %s, %s, %s)",
                (f["name"], f["norm"], f["type"], 0)
            )
            registered_fields[f["norm"]] = cur.lastrowid
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
                pass

    conn.commit()
    print('Database schema setup completed successfully.')
    cur.execute("SHOW TABLES")
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
    if conn is not None and conn.is_connected():
        conn.close()
