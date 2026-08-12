import pytest
import json
import app as app_module
import api_routes
from flask import session
from datetime import datetime

@pytest.fixture
def client(monkeypatch):
    class FakeCursor:
        def __init__(self):
            self.results = []
            self.one_result = None
            self.lastrowid = 1
            self.queries = []
            self.params = []

        def execute(self, query, params=None):
            self.queries.append(query)
            self.params.append(params)
            # Mock client api key retrieval
            if "client_api_keys" in query:
                self.one_result = {
                    "id": 1,
                    "user_id": 99,
                    "key_name": "Test Key",
                    "key_type": "export",
                    "api_key": "test_key_123",
                    "filters_json": '{"country": "USA"}',
                    "max_rows_limit": 50,
                    "rows_retrieved": 40,
                    "is_active": 1,
                    "status": "approved",
                    "expires_at": None,
                    "username": "clientuser"
                }
            elif "field_registry" in query:
                self.results = [{"id": 1, "field_name": "country"}]
            elif "COUNT(*)" in query:
                self.one_result = {"total": 100}
            elif "SELECT * FROM master_records" in query:
                # Return 5 mock rows
                self.results = [{"id": i, "first_name": f"User{i}", "custom_fields": None} for i in range(1, 6)]

        def fetchall(self):
            return self.results

        def fetchone(self):
            return self.one_result

        def close(self):
            pass

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
    monkeypatch.setattr(api_routes, "get_db_connection", lambda: FakeConnection())
    app_module.app.config["TESTING"] = True
    with app_module.app.test_client() as client:
        yield client

def test_api_key_limits_under_allowance(client):
    # Test exporting when remaining limit is positive (limit=50, retrieved=40 -> remaining=10)
    # Requesting per_page=5
    res = client.get("/api/v1/client/export?api_key=test_key_123&per_page=5")
    assert res.status_code == 200
    data = json.loads(res.data)
    assert data["success"] is True
    assert len(data["records"]) == 5

def test_api_key_limits_exceeded(client, monkeypatch):
    # Mock where limit is fully reached (limit=50, retrieved=50 -> remaining=0)
    class FakeCursorExceeded:
        def __init__(self):
            self.one_result = None
            self.results = []
        def execute(self, query, params=None):
            if "client_api_keys" in query:
                self.one_result = {
                    "id": 1,
                    "user_id": 99,
                    "key_name": "Test Key",
                    "key_type": "export",
                    "api_key": "test_key_123",
                    "filters_json": '{}',
                    "max_rows_limit": 50,
                    "rows_retrieved": 50,
                    "is_active": 1,
                    "status": "approved",
                    "expires_at": None,
                    "username": "clientuser"
                }
        def fetchone(self):
            return self.one_result
        def fetchall(self):
            return self.results
        def close(self):
            pass

    class FakeConnectionExceeded:
        def cursor(self, dictionary=True, dict=False):
            return FakeCursorExceeded()
        def commit(self):
            pass
        def rollback(self):
            pass
        def close(self):
            pass

    monkeypatch.setattr(app_module, "get_db_connection", lambda: FakeConnectionExceeded())
    monkeypatch.setattr(api_routes, "get_db_connection", lambda: FakeConnectionExceeded())
    res = client.get("/api/v1/client/export?api_key=test_key_123")
    assert res.status_code == 400
    data = json.loads(res.data)
    assert "limit" in data["error"]
