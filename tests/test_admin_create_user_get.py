import app as app_module


def test_admin_create_user_get_renders(monkeypatch):
    class FakeCursor:
        def execute(self, *args, **kwargs):
            return None

        def fetchall(self):
            return []

        def fetchone(self):
            return None

        def close(self):
            return None

    class FakeConnection:
        def cursor(self, dictionary=True):
            return FakeCursor()

        def close(self):
            return None

    monkeypatch.setattr(app_module, "get_db_connection", lambda: FakeConnection())

    client = app_module.app.test_client()
    from datetime import datetime
    with client.session_transaction() as session:
        session["user_id"] = 1
        session["role"] = "admin"
        session["username"] = "admin"
        session["last_active"] = datetime.utcnow().isoformat()

    response = client.get("/admin/create-user", follow_redirects=False)

    assert response.status_code == 200
    assert b"Create account" in response.data
