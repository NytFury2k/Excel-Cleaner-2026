import pytest
from flask import session
import app as app_module

@pytest.fixture
def client():
    app_module.app.config["TESTING"] = True
    with app_module.app.test_client() as client:
        yield client

def test_upload_downloads_privilege_enforcement(client):
    # 1. Test user with full privileges
    with client.session_transaction() as sess:
        sess["user_id"] = 99
        sess["username"] = "stduser"
        sess["role"] = "user"
        sess["upload_access"] = 1
        sess["download_access"] = 1
        sess["permissions"] = ["upload_file", "download_results", "view_own_logs"]

    res = client.get("/upload")
    assert res.status_code == 200 # Access allowed

    res = client.get("/downloads")
    assert res.status_code == 200 # Access allowed

    # 2. Test user with upload disabled
    with client.session_transaction() as sess:
        sess["user_id"] = 99
        sess["username"] = "stduser"
        sess["role"] = "user"
        sess["upload_access"] = 0
        sess["download_access"] = 1
        sess["permissions"] = ["download_results", "view_own_logs"]

    res = client.get("/upload")
    assert res.status_code == 302 # Redirected / blocked
    assert "/dashboard" in res.headers["Location"]

    # 3. Test user with download disabled
    with client.session_transaction() as sess:
        sess["user_id"] = 99
        sess["username"] = "stduser"
        sess["role"] = "user"
        sess["upload_access"] = 1
        sess["download_access"] = 0
        sess["permissions"] = ["upload_file", "view_own_logs"]

    res = client.get("/downloads")
    assert res.status_code == 302 # Redirected / blocked
    assert "/dashboard" in res.headers["Location"]

from helpers import get_visible_user_ids

class MockCursor:
    def __init__(self, data):
        self.data = data
        self.queries = []
        self.call_count = 0
    def execute(self, query, params=None):
        self.queries.append((query, params))
    def fetchall(self):
        return self.data
    def fetchone(self):
        self.call_count += 1
        if self.call_count == 1:
            return {"manager_id": 10, "role": "user"}
        else:
            return {"manager_id": None, "role": "manager"}

def test_get_visible_user_ids_scoped_by_manager():
    # Test standard user that reports to manager (manager_id = 10)
    cursor = MockCursor([{"id": 10}, {"id": 20}, {"id": 30}])
    visible = get_visible_user_ids(cursor, role="user", user_id=99)
    # The visible list should include 99 (self), 10 (manager), 20 and 30 (peers/sub-reports)
    assert 99 in visible
    assert 10 in visible
    assert 20 in visible
    assert 30 in visible

def test_inbox_access_for_all_roles(client):
    # Test admin role can access /inbox
    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["username"] = "admin"
        sess["role"] = "admin"
    res = client.get("/inbox")
    assert res.status_code == 200

    # Test manager role can access /inbox
    with client.session_transaction() as sess:
        sess["user_id"] = 2
        sess["username"] = "manager1"
        sess["role"] = "manager"
    res = client.get("/inbox")
    assert res.status_code == 200

    # Test team_lead role can access /inbox
    with client.session_transaction() as sess:
        sess["user_id"] = 3
        sess["username"] = "lead1"
        sess["role"] = "team_lead"
    res = client.get("/inbox")
    assert res.status_code == 200

    # Test standard user role can access /inbox
    with client.session_transaction() as sess:
        sess["user_id"] = 4
        sess["username"] = "user1"
        sess["role"] = "user"
    res = client.get("/inbox")
    assert res.status_code == 200

def test_custom_merge_access_all_roles(client):
    for role_name in ["admin", "manager", "team_lead", "user"]:
        with client.session_transaction() as sess:
            sess["user_id"] = 100
            sess["username"] = f"test_{role_name}"
            sess["role"] = role_name
            sess["permissions"] = ["upload_file", "download_results", "view_own_logs"]

        res = client.get("/custom/merge-excel")
        assert res.status_code == 200, f"Role {role_name} should be able to access /custom/merge-excel"

def test_custom_merge_unauthenticated_blocked(client):
    with client.session_transaction() as sess:
        sess.clear()

    res = client.get("/custom/merge-excel")
    assert res.status_code == 302
    assert res.headers["Location"] == "/"



