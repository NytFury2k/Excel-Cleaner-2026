import pytest
import json
import app as app_module
from flask import session

@pytest.fixture
def client(monkeypatch):
    class FakeCursor:
        def __init__(self):
            self.results = []
            self.one_result = None
            
        def execute(self, query, params=None):
            # Dynamic mock response based on query content
            if "information_schema.columns" in query:
                self.results = [{"column_name": "backup_email"}, {"column_name": "first_name"}]
            elif "SELECT id FROM field_registry WHERE normalized_name" in query:
                self.one_result = None
            elif "SELECT id FROM field_registry WHERE id" in query:
                self.one_result = {"id": 3}
            elif "SELECT COUNT(*) as count FROM field_aliases" in query:
                self.one_result = {"count": 0}
            elif "SELECT field_name FROM field_registry" in query:
                self.one_result = {"field_name": "Designation"}
            else:
                self.one_result = {"id": 1, "column_name": "first_name", "field_name": "First Name", "normalized_name": "first_name", "cnt": 0, "count": 0}
                
        def fetchall(self):
            return self.results
            
        def fetchone(self):
            return self.one_result
            
        def close(self):
            return None
            
    class FakeConnection:
        def cursor(self, dictionary=True, dict=False):
            return FakeCursor()
        def commit(self):
            pass
        def rollback(self):
            pass
        def close(self):
            pass

    monkeypatch.setattr(app_module, "get_db_connection", lambda: FakeConnection())
    app_module.app.config["TESTING"] = True
    with app_module.app.test_client() as client:
        yield client

def test_add_master_column_admin(client):
    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["role"] = "admin"
        
    res = client.post("/api/fields/master/add", json={"field_name": "Alternate Phone", "data_type": "VARCHAR(255)"})
    assert res.status_code == 200
    assert b"Successfully added master column" in res.data

def test_add_master_column_unauthorized(client):
    with client.session_transaction() as sess:
        sess["user_id"] = 2
        sess["role"] = "user"
        
    res = client.post("/api/fields/master/add", json={"field_name": "Alternate Phone"})
    assert res.status_code == 403

def test_delete_master_column_admin(client):
    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["role"] = "admin"
        
    res = client.post("/api/fields/master/backup_email/delete")
    assert res.status_code == 200
    assert b"Successfully deleted Master column" in res.data

def test_add_custom_field_admin(client):
    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["role"] = "admin"
        
    res = client.post("/api/fields/custom/add", json={"field_name": "Designation", "data_type": "VARCHAR"})
    assert res.status_code == 200
    assert b"Successfully registered custom field" in res.data

def test_delete_custom_field_admin(client):
    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["role"] = "admin"
        
    res = client.post("/api/fields/custom/3/delete")
    assert res.status_code == 200
    assert b"Successfully deleted custom field" in res.data

def test_rename_field_admin(client):
    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["role"] = "admin"
        
    res = client.post("/api/fields/rename", json={"type": "custom", "id": 3, "new_name": "Office Email"})
    assert res.status_code == 200
    assert b"Successfully renamed field" in res.data
