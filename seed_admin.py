import os
import psycopg2
import bcrypt
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    print("Error: DATABASE_URL not found in .env file.")
    exit(1)

def seed_admin_only():
    print("Connecting to Supabase (PostgreSQL)...")
    try:
        conn = psycopg2.connect(DATABASE_URL)
        cur = conn.cursor()
        
        # 1. Ensure the roles exist
        roles_to_ensure = ['admin', 'manager', 'team_lead', 'user']
        print("Ensuring roles exist in 'roles' table...")
        for role_name in roles_to_ensure:
            # Check if role exists
            cur.execute("SELECT id FROM roles WHERE name = %s", (role_name,))
            row = cur.fetchone()
            if not row:
                cur.execute("INSERT INTO roles (name) VALUES (%s) RETURNING id", (role_name,))
                role_id = cur.fetchone()[0]
                print(f"  Created role: '{role_name}' (ID: {role_id})")
            else:
                print(f"  Role '{role_name}' already exists.")
        conn.commit()

        # 2. Ensure permissions exist
        permissions_to_ensure = [
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
        ]
        
        print("Ensuring permissions exist in 'permissions' table...")
        for perm_name, perm_desc in permissions_to_ensure:
            cur.execute("SELECT id FROM permissions WHERE name = %s", (perm_name,))
            row = cur.fetchone()
            if not row:
                cur.execute("INSERT INTO permissions (name, description) VALUES (%s, %s)", (perm_name, perm_desc))
        conn.commit()

        # 3. Associate all permissions with the admin role
        print("Mapping all permissions to 'admin' role in 'role_permissions'...")
        cur.execute("SELECT id FROM roles WHERE name = 'admin'")
        admin_role_row = cur.fetchone()
        if admin_role_row:
            admin_role_id = admin_role_row[0]
            cur.execute("SELECT id FROM permissions")
            perm_ids = [r[0] for r in cur.fetchall()]
            for p_id in perm_ids:
                cur.execute(
                    "INSERT INTO role_permissions (role_id, permission_id) VALUES (%s, %s) ON CONFLICT DO NOTHING",
                    (admin_role_id, p_id)
                )
            conn.commit()

        # 4. Check/Insert the admin user
        print("Checking if admin user exists in 'users' table...")
        cur.execute("SELECT id FROM users WHERE username = %s", ("admin",))
        user_row = cur.fetchone()
        
        # Default password is 'Admin@123' hashed with bcrypt
        admin_password_hash = bcrypt.hashpw("Admin@123".encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        
        cur.execute("SELECT id FROM roles WHERE name = 'admin'")
        role_row = cur.fetchone()
        role_id = role_row[0] if role_row else None
        
        if not user_row:
            print("Creating 'admin' user...")
            cur.execute(
                "INSERT INTO users (username, password, role, role_id, is_active, requires_password_change) VALUES (%s, %s, %s, %s, %s, %s) RETURNING id",
                ("admin", admin_password_hash, "admin", role_id, True, False)
            )
            new_admin_id = cur.fetchone()[0]
            print(f"  Successfully created 'admin' user (ID: {new_admin_id}, Password: Admin@123)")
        else:
            admin_id = user_row[0]
            print(f"  'admin' user already exists (ID: {admin_id}). Updating password and role to ensure correct admin setup...")
            cur.execute(
                "UPDATE users SET password = %s, role = %s, role_id = %s, is_active = %s WHERE id = %s",
                (admin_password_hash, "admin", role_id, True, admin_id)
            )
            print("  Admin password and role updated successfully.")
            
        conn.commit()
        cur.close()
        conn.close()
        print("Supabase database seeding completed successfully!")
        
    except Exception as e:
        print(f"Error seeding Supabase database: {e}")

if __name__ == "__main__":
    seed_admin_only()
