import os
import sys
import psycopg2
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def migrate():
    db_host = os.environ.get("SUPABASE_DB_HOST", "127.0.0.1")
    db_name = os.environ.get("SUPABASE_DB_NAME", "postgres")
    db_user = os.environ.get("SUPABASE_DB_USER", "postgres")
    db_port = os.environ.get("SUPABASE_DB_PORT", "5432")
    db_pass = os.environ.get("SUPABASE_DB_PASSWORD", "")

    print(f"Connecting to database {db_name} on {db_host}...")
    try:
        conn = psycopg2.connect(
            host=db_host,
            database=db_name,
            user=db_user,
            password=db_pass,
            port=db_port
        )
        cur = conn.cursor()
        
        # Check if full_name exists
        cur.execute("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'master_records' AND column_name = 'full_name'
        """)
        has_full_name = cur.fetchone()
        
        if not has_full_name:
            print("Table 'master_records' already migrated or does not contain 'full_name'. checking first_name...")
            cur.execute("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = 'master_records' AND column_name = 'first_name'
            """)
            if cur.fetchone():
                print("Migration already applied! Columns first_name and last_name exist.")
            else:
                # Add columns anyway just in case table is empty or newly created
                print("Adding first_name and last_name columns to master_records...")
                cur.execute("ALTER TABLE master_records ADD COLUMN IF NOT EXISTS first_name VARCHAR(255) NULL")
                cur.execute("ALTER TABLE master_records ADD COLUMN IF NOT EXISTS last_name VARCHAR(255) NULL")
                conn.commit()
            return

        print("Adding first_name and last_name columns...")
        cur.execute("ALTER TABLE master_records ADD COLUMN IF NOT EXISTS first_name VARCHAR(255) NULL")
        cur.execute("ALTER TABLE master_records ADD COLUMN IF NOT EXISTS last_name VARCHAR(255) NULL")
        conn.commit()

        # Fetch records
        print("Fetching existing records to split full name...")
        cur.execute("SELECT id, full_name FROM master_records")
        rows = cur.fetchall()
        print(f"Found {len(rows)} records. Splitting names...")

        updated_count = 0
        for rid, full_name in rows:
            if not full_name:
                continue
            parts = full_name.strip().split(None, 1)
            first_name = parts[0] if len(parts) > 0 else ""
            last_name = parts[1] if len(parts) > 1 else ""
            
            cur.execute(
                "UPDATE master_records SET first_name = %s, last_name = %s WHERE id = %s",
                (first_name, last_name, rid)
            )
            updated_count += 1

        print(f"Updated {updated_count} records with split names.")
        conn.commit()

        # Drop old column and index
        print("Dropping old full_name column and index...")
        cur.execute("DROP INDEX IF EXISTS idx_full_name")
        cur.execute("ALTER TABLE master_records DROP COLUMN IF EXISTS full_name")
        conn.commit()

        # Create new indexes
        print("Creating indexes for first_name and last_name...")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_first_name ON master_records(first_name)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_last_name ON master_records(last_name)")
        conn.commit()

        print("Database migration completed successfully!")
        
    except Exception as e:
        print(f"Error executing migration: {e}")
        if 'conn' in locals() and conn:
            conn.rollback()
    finally:
        if 'cur' in locals() and cur:
            cur.close()
        if 'conn' in locals() and conn:
            conn.close()

if __name__ == "__main__":
    migrate()
