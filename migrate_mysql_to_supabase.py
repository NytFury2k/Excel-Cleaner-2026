"""Migrate data from the legacy MySQL database into Supabase/PostgreSQL.

The application now reads from PostgreSQL using the SUPABASE_DB_* environment
variables, but the existing data still lives in MySQL. Run this script once to
copy the current data across.

The script creates the target schema if needed, clears existing target rows by
default, copies the data table-by-table in dependency order, and then resets
PostgreSQL sequences.
"""

from __future__ import annotations

import argparse
import os
from contextlib import closing

import mysql.connector
import psycopg2
import psycopg2.extras
from dotenv import load_dotenv


load_dotenv()


TABLE_ORDER = [
    "roles",
    "permissions",
    "users",
    "role_permissions",
    "uploaded_files",
    "field_registry",
    "field_aliases",
    "master_records",
    "rejected_records",
    "logs",
    "login_attempts",
    "api_tokens",
    "cleaning_jobs",
    "rule_presets",
    "search_logs",
]


SCHEMA_SQL = [
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
        description VARCHAR(255)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        role VARCHAR(20) DEFAULT 'user',
        is_active SMALLINT NOT NULL DEFAULT 1,
        manager_id INT,
        created_by INT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        role_id INT,
        email VARCHAR(255),
        requires_password_change SMALLINT NOT NULL DEFAULT 0
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS role_permissions (
        role_id INT NOT NULL,
        permission_id INT NOT NULL,
        PRIMARY KEY (role_id, permission_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS uploaded_files (
        id SERIAL PRIMARY KEY,
        user_id INT NOT NULL,
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
        file_id INT NOT NULL,
        full_name VARCHAR(255),
        email_address VARCHAR(255),
        primary_phone_number VARCHAR(100),
        alternate_phone_number VARCHAR(100),
        company_name VARCHAR(255),
        job_title VARCHAR(255),
        department VARCHAR(255),
        website_url VARCHAR(255),
        address_line_1 VARCHAR(255),
        address_line_2 VARCHAR(255),
        city VARCHAR(255),
        state_province VARCHAR(255),
        postal_zip_code VARCHAR(100),
        country VARCHAR(255),
        linkedin_profile_url VARCHAR(255),
        industry VARCHAR(255),
        lead_source VARCHAR(255),
        record_status VARCHAR(100),
        date_of_birth VARCHAR(100),
        gender VARCHAR(50),
        company_size VARCHAR(100),
        annual_revenue VARCHAR(100),
        custom_fields JSONB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        imported_by VARCHAR(255)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS rejected_records (
        id SERIAL PRIMARY KEY,
        file_id INT NOT NULL,
        row_data JSONB,
        rejected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS logs (
        id SERIAL PRIMARY KEY,
        user_id INT NOT NULL,
        action TEXT,
        total_rows INT NOT NULL DEFAULT 0,
        valid_rows INT NOT NULL DEFAULT 0,
        invalid_rows INT NOT NULL DEFAULT 0,
        removed_rows INT NOT NULL DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        rules_applied TEXT,
        rule_counts TEXT
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
        user_id INT NOT NULL,
        token VARCHAR(64) NOT NULL UNIQUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP NOT NULL,
        is_active SMALLINT DEFAULT 1
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS cleaning_jobs (
        id SERIAL PRIMARY KEY,
        user_id INT NOT NULL UNIQUE,
        temp_file VARCHAR(500),
        uploaded_file VARCHAR(500),
        cleaned_file VARCHAR(500),
        invalid_file VARCHAR(500),
        removed_file VARCHAR(500),
        rules_json TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS rule_presets (
        id SERIAL PRIMARY KEY,
        user_id INT NOT NULL,
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
    "CREATE INDEX IF NOT EXISTS idx_login_username_time ON login_attempts(username, attempted_at)",
    "CREATE INDEX IF NOT EXISTS idx_full_name ON master_records(full_name)",
    "CREATE INDEX IF NOT EXISTS idx_email ON master_records(email_address)",
    "CREATE INDEX IF NOT EXISTS idx_phone ON master_records(primary_phone_number)",
    "CREATE INDEX IF NOT EXISTS idx_company ON master_records(company_name)",
    "CREATE INDEX IF NOT EXISTS idx_city ON master_records(city)",
]


def connect_mysql(args):
    return mysql.connector.connect(
        host=args.mysql_host,
        port=args.mysql_port,
        user=args.mysql_user,
        password=args.mysql_password,
        database=args.mysql_database,
    )


def connect_postgres(args):
    return psycopg2.connect(
        host=args.pg_host,
        port=args.pg_port,
        user=args.pg_user,
        password=args.pg_password,
        dbname=args.pg_database,
    )


def table_exists(mysql_cursor, table_name):
    mysql_cursor.execute("SHOW TABLES LIKE %s", (table_name,))
    return mysql_cursor.fetchone() is not None


def discover_source_tables(mysql_cursor):
    mysql_cursor.execute("SHOW TABLES")
    tables = []
    for row in mysql_cursor.fetchall():
        if isinstance(row, dict):
            tables.append(next(iter(row.values())))
        else:
            tables.append(row[0])
    return tables


def ensure_schema(pg_conn):
    with pg_conn.cursor() as cursor:
        for statement in SCHEMA_SQL:
            cursor.execute(statement)
    pg_conn.commit()


def truncate_target_tables(pg_conn):
    with pg_conn.cursor() as cursor:
        cursor.execute("SET session_replication_role = replica")
        for table_name in reversed(TABLE_ORDER):
            cursor.execute(f'TRUNCATE TABLE "{table_name}" RESTART IDENTITY CASCADE')
        cursor.execute("SET session_replication_role = DEFAULT")
    pg_conn.commit()


def copy_rows(mysql_cursor, pg_conn, table_name, column_names=None):
    mysql_cursor.execute(f"SELECT * FROM `{table_name}`")
    rows = mysql_cursor.fetchall()
    if not rows:
        return 0

    source_columns = [column[0] for column in mysql_cursor.description]
    if column_names is None:
        column_names = source_columns

    insert_sql = f'INSERT INTO "{table_name}" ({", ".join(f"\"{name}\"" for name in column_names)}) VALUES %s'
    values = []
    for row in rows:
        row_values = []
        for column_name in column_names:
            value = row[column_name] if isinstance(row, dict) else row[source_columns.index(column_name)]
            row_values.append(value)
        values.append(tuple(row_values))

    with pg_conn.cursor() as cursor:
        psycopg2.extras.execute_values(cursor, insert_sql, values, page_size=500)
    pg_conn.commit()
    return len(values)


def copy_master_records(mysql_cursor, pg_conn):
    mysql_cursor.execute("SELECT * FROM `master_records`")
    rows = mysql_cursor.fetchall()
    if not rows:
        return 0

    columns = [
        "id", "file_id", "full_name", "email_address", "primary_phone_number",
        "alternate_phone_number", "company_name", "job_title", "department",
        "website_url", "address_line_1", "address_line_2", "city", "state_province",
        "postal_zip_code", "country", "linkedin_profile_url", "industry",
        "lead_source", "record_status", "date_of_birth", "gender", "company_size",
        "annual_revenue", "custom_fields", "created_at", "updated_at", "imported_by",
    ]
    insert_sql = f'INSERT INTO "master_records" ({", ".join(f"\"{name}\"" for name in columns)}) VALUES %s'
    values = []

    for row in rows:
        row_dict = dict(row) if not isinstance(row, dict) else row
        values.append(tuple(row_dict.get(column) for column in columns))

    with pg_conn.cursor() as cursor:
        psycopg2.extras.execute_values(cursor, insert_sql, values, page_size=250)
    pg_conn.commit()
    return len(values)


def reset_sequences(pg_conn):
    sequence_tables = [
        "roles", "permissions", "users", "uploaded_files", "field_registry",
        "field_aliases", "master_records", "rejected_records", "logs",
        "login_attempts", "api_tokens", "cleaning_jobs", "rule_presets",
        "search_logs",
    ]
    with pg_conn.cursor() as cursor:
        for table_name in sequence_tables:
            cursor.execute(f'SELECT COALESCE(MAX(id), 0) FROM "{table_name}"')
            max_id = cursor.fetchone()[0]
            cursor.execute("SELECT pg_get_serial_sequence(%s, %s)", (table_name, "id"))
            sequence_name = cursor.fetchone()[0]
            if sequence_name:
                if max_id > 0:
                    cursor.execute("SELECT setval(%s, %s, true)", (sequence_name, max_id))
                else:
                    cursor.execute("SELECT setval(%s, 1, false)", (sequence_name,))
    pg_conn.commit()


def parse_args():
    parser = argparse.ArgumentParser(description="Migrate MySQL data to Supabase/PostgreSQL.")
    parser.add_argument("--mysql-host", default=os.environ.get("MYSQL_HOST", "127.0.0.1"))
    parser.add_argument("--mysql-port", type=int, default=int(os.environ.get("MYSQL_PORT", "3306")))
    parser.add_argument("--mysql-user", default=os.environ.get("MYSQL_USER", "root"))
    parser.add_argument("--mysql-password", default=os.environ.get("MYSQL_PASSWORD", ""))
    parser.add_argument("--mysql-database", default=os.environ.get("MYSQL_DATABASE", "excel_cleaner_db"))
    parser.add_argument("--pg-host", default=os.environ.get("SUPABASE_DB_HOST", "127.0.0.1"))
    parser.add_argument("--pg-port", type=int, default=int(os.environ.get("SUPABASE_DB_PORT", "5432")))
    parser.add_argument("--pg-user", default=os.environ.get("SUPABASE_DB_USER", "postgres"))
    parser.add_argument("--pg-password", default=os.environ.get("SUPABASE_DB_PASSWORD", ""))
    parser.add_argument("--pg-database", default=os.environ.get("SUPABASE_DB_NAME", "postgres"))
    parser.add_argument(
        "--no-truncate",
        action="store_true",
        help="Do not clear the destination tables before importing.",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    with closing(connect_mysql(args)) as mysql_conn, closing(connect_postgres(args)) as pg_conn:
        mysql_cursor = mysql_conn.cursor(dictionary=True)

        source_tables = discover_source_tables(mysql_cursor)
        ordered_tables = [table_name for table_name in TABLE_ORDER if table_name in source_tables]
        ordered_tables.extend(table_name for table_name in source_tables if table_name not in ordered_tables)

        ensure_schema(pg_conn)
        if not args.no_truncate:
            truncate_target_tables(pg_conn)

        total = 0
        for table_name in ordered_tables:
            if table_name == "master_records":
                total += copy_master_records(mysql_cursor, pg_conn)
            elif table_name == "role_permissions":
                total += copy_rows(mysql_cursor, pg_conn, table_name, ["role_id", "permission_id"])
            else:
                total += copy_rows(mysql_cursor, pg_conn, table_name)

        reset_sequences(pg_conn)

    print(f"Migration completed successfully. Imported {total} row(s).")


if __name__ == "__main__":
    main()