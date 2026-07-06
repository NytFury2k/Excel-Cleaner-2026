import os
import pytest
import psycopg2
import app as app_module
from datetime import datetime

class FakeCursor:
    def __init__(self, uploaded_files_results=None):
        self.uploaded_files_results = uploaded_files_results or []
        self.queries = []
        self.params = []

    def execute(self, query, params=None):
        self.queries.append(query)
        self.params.append(params)

    def fetchone(self):
        if "SELECT 1" in self.queries[-1]:
            return {"1": 1} if self.uploaded_files_results else None
        return {"total": 0}

    def fetchall(self):
        return []

class FakeConnection:
    def __init__(self, uploaded_files_results=None):
        self.uploaded_files_results = uploaded_files_results

    def cursor(self, dictionary=True):
        return FakeCursor(self.uploaded_files_results)

    def close(self):
        return None

def test_download_admin_denied_when_not_visible(monkeypatch, tmp_path):
    # Set up mock files and directories inside tmp_path
    generated_dir = tmp_path / "Generated_Files"
    cleaned_dir = generated_dir / "Cleaned"
    cleaned_dir.mkdir(parents=True, exist_ok=True)
    
    unauthorized_uuid = "12345678901234567890123456789012"
    dummy_file = cleaned_dir / f"{unauthorized_uuid}_test_cleaned_20260705_120000.xlsx"
    dummy_file.write_text("Dummy content")

    # Mock get_db_connection to return no records for check
    monkeypatch.setattr(app_module, "get_db_connection", lambda: FakeConnection(uploaded_files_results=False))
    monkeypatch.setattr(app_module, "get_visible_user_ids", lambda cursor, role=None, user_id=None: [1])
    
    # Direct search on file paths to match our dummy directory
    app_module_dir = os.path.dirname(os.path.abspath(app_module.__file__))
    original_exists = os.path.exists
    
    def mock_exists(path):
        if "Generated_Files" in path:
            return True
        return original_exists(path)

    monkeypatch.setattr(os.path, "exists", mock_exists)

    client = app_module.app.test_client()
    with client.session_transaction() as session:
        session["user_id"] = 1
        session["role"] = "manager"
        session["username"] = "manager_user"
        session["last_active"] = datetime.utcnow().isoformat()

    rel_filename = f"Generated_Files/Cleaned/{dummy_file.name}"
    response = client.get(f"/downloads/admin/{rel_filename}", follow_redirects=False)

    assert response.status_code == 302
    assert "/downloads" in response.headers["Location"]
