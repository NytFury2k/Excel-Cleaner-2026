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

    for stmt in sql_statements:
        cur.execute(stmt)

    # Ensure the admin user exists with the expected password hash.
    cur.execute("SELECT COUNT(*) FROM users WHERE username = %s", ('admin',))
    if cur.fetchone()[0] == 0:
        cur.execute(
            "INSERT INTO users (username, password, role) VALUES (%s, %s, %s)",
            ('admin', '$2b$12$UOQzAAufKsipUFuIlH8JHu2RZHYQ7rL6Xe9fHC27F6SYn1iOTZvRi', 'admin')
        )

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
