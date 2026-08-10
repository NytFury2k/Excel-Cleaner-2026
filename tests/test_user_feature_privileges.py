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
