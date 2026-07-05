-- Final Integrated Schema for Supabase (PostgreSQL)
-- This script creates the missing security, access control, and application state tables,
-- and configures indexes/rules on your existing CDP tables.

-- =========================================================================
-- 1. SECURITY & ACCESS CONTROL
-- =========================================================================

-- Roles table
CREATE TABLE IF NOT EXISTS roles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL
);

INSERT INTO roles (name) VALUES ('admin'), ('manager'), ('team_lead'), ('user')
ON CONFLICT (name) DO NOTHING;

-- Permissions table
CREATE TABLE IF NOT EXISTS permissions (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    description VARCHAR(255) NULL
);

INSERT INTO permissions (name, description) VALUES 
('view_all_users', 'See all users in the system'),
('create_user', 'Create new user accounts'),
('manage_roles', 'Change any user roles'),
('toggle_user', 'Enable/disable user accounts'),
('reset_password', 'Reset any user password'),
('view_all_logs', 'See logs from all users'),
('view_team_logs', 'See logs from visible team members'),
('view_team_users', 'See users in own hierarchy'),
('view_own_logs', 'See own activity logs'),
('view_self', 'See own profile info'),
('export_logs', 'Export logs to file'),
('upload_file', 'Upload an Excel file for cleaning'),
('select_rules', 'Choose cleaning rules'),
('run_cleaning', 'Execute the cleaning pipeline'),
('download_results', 'Download cleaned/invalid/removed files'),
('manage_presets', 'Save, load, delete own rule presets'),
('change_own_password', 'Change own password'),
('manage_api_tokens', 'Generate/revoke personal API tokens')
ON CONFLICT (name) DO NOTHING;

-- Junction table mapping roles to permissions
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id INT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id INT NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- Admin gets every permission
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'admin'
ON CONFLICT DO NOTHING;

-- Manager permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r
JOIN permissions p ON p.name IN (
    'view_team_users', 'create_user', 'toggle_user', 'reset_password', 
    'view_team_logs', 'export_logs', 'upload_file', 'select_rules', 
    'run_cleaning', 'download_results', 'manage_presets', 
    'change_own_password', 'manage_api_tokens'
)
WHERE r.name = 'manager'
ON CONFLICT DO NOTHING;

-- Team Lead permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r
JOIN permissions p ON p.name IN (
    'view_team_users', 'view_team_logs', 'export_logs', 'upload_file', 
    'select_rules', 'run_cleaning', 'download_results', 'manage_presets', 
    'change_own_password', 'manage_api_tokens'
)
WHERE r.name = 'team_lead'
ON CONFLICT DO NOTHING;

-- User permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r
JOIN permissions p ON p.name IN (
    'view_self', 'view_own_logs', 'export_logs', 'upload_file', 
    'select_rules', 'run_cleaning', 'download_results', 'manage_presets', 
    'change_own_password', 'manage_api_tokens'
)
WHERE r.name = 'user'
ON CONFLICT DO NOTHING;

-- Recreate Users
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(20) DEFAULT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    manager_id INT DEFAULT NULL REFERENCES users(id) ON DELETE SET NULL,
    created_by INT DEFAULT NULL REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    role_id INT REFERENCES roles(id),
    email VARCHAR(255) DEFAULT NULL,
    requires_password_change BOOLEAN DEFAULT FALSE
);

-- =========================================================================
-- 2. ACTIVE APPLICATION METADATA & JOB STATE
-- =========================================================================

-- Current active cleaning workspace state per user session
CREATE TABLE IF NOT EXISTS cleaning_jobs (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    temp_file VARCHAR(500) NULL,
    uploaded_file VARCHAR(500) NULL,
    cleaned_file VARCHAR(500) NULL,
    invalid_file VARCHAR(500) NULL,
    removed_file VARCHAR(500) NULL,
    rules_json TEXT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- User-defined cleaning rules presets
CREATE TABLE IF NOT EXISTS rule_presets (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    rules_json TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT unique_user_preset UNIQUE (user_id, name)
);

-- High-level processing action summaries
CREATE TABLE IF NOT EXISTS logs (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    action TEXT NULL,
    total_rows INT NOT NULL DEFAULT 0,
    valid_rows INT NOT NULL DEFAULT 0,
    invalid_rows INT NOT NULL DEFAULT 0,
    removed_rows INT DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    rules_applied TEXT NULL,
    rule_counts TEXT NULL
);

-- Recreate API Tokens
CREATE TABLE IF NOT EXISTS api_tokens (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(64) NOT NULL UNIQUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    is_active BOOLEAN DEFAULT TRUE
);

-- Recreate Login Attempts
CREATE TABLE IF NOT EXISTS login_attempts (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    attempted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    success BOOLEAN DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_username_time ON login_attempts (username, attempted_at);

-- =========================================================================
-- 3. INDEXES AND RULES ON EXISTING BUSINESS TABLES
-- =========================================================================

-- Indexes on master_records
CREATE INDEX IF NOT EXISTS idx_master_email ON master_records (LOWER(email));
CREATE INDEX IF NOT EXISTS idx_master_phone ON master_records (phone);

-- GIN Index on quarantine table raw_payload (JSONB column name matches Supabase table)
CREATE INDEX IF NOT EXISTS idx_quarantine_raw_payload ON quarantine USING GIN (raw_payload);

-- GIN Index on merge_audit table before_snapshot (JSONB column name matches Supabase table)
CREATE INDEX IF NOT EXISTS idx_merge_audit_snapshot ON merge_audit USING GIN (before_snapshot);

-- Restrict updates and deletes on merge_audit table to maintain audit integrity
CREATE OR REPLACE RULE merge_audit_prevent_updates AS ON UPDATE TO merge_audit DO INSTEAD NOTHING;
CREATE OR REPLACE RULE merge_audit_prevent_deletes AS ON DELETE TO merge_audit DO INSTEAD NOTHING;

-- =========================================================================
-- 4. UPLOADS HISTORY & CUSTOM FIELDS REGISTRY
-- =========================================================================

-- Ingestion file history
CREATE TABLE IF NOT EXISTS uploaded_files (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    filename VARCHAR(500) NOT NULL,
    original_filename VARCHAR(500) NOT NULL,
    uploaded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    total_rows INT DEFAULT 0,
    rows_imported INT DEFAULT 0,
    rows_rejected INT DEFAULT 0,
    status VARCHAR(50) NOT NULL DEFAULT 'pending'
);

-- Custom fields registry
CREATE TABLE IF NOT EXISTS field_registry (
    id SERIAL PRIMARY KEY,
    field_name VARCHAR(150) NOT NULL UNIQUE,
    normalized_name VARCHAR(150) NOT NULL UNIQUE,
    data_type VARCHAR(50) NOT NULL DEFAULT 'VARCHAR',
    is_active BOOLEAN DEFAULT TRUE,
    searchable BOOLEAN DEFAULT TRUE,
    filterable BOOLEAN DEFAULT TRUE,
    usage_count INT DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Field aliases mapping table
CREATE TABLE IF NOT EXISTS field_aliases (
    id SERIAL PRIMARY KEY,
    alias VARCHAR(150) NOT NULL UNIQUE,
    normalized_alias VARCHAR(150) NOT NULL,
    target_type VARCHAR(50) NOT NULL,
    target_identifier VARCHAR(150) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
