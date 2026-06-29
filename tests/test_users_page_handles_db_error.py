import mysql.connector
import app as app_module


def test_users_page_returns_200_when_db_query_fails(monkeypatch):
    class FakeCursor:
        def execute(self, *args, **kwargs):
            raise mysql.connector.errors.ProgrammingError("boom")

        def fetchone(self):
            return {"total": 0}

        def fetchall(self):
            return []

    class FakeConnection:
        def cursor(self, dictionary=True):
            return FakeCursor()

        def close(self):
            return None

    monkeypatch.setattr(app_module, "get_db_connection", lambda: FakeConnection())
    monkeypatch.setattr(app_module, "has_permission", lambda permission: True)
    monkeypatch.setattr(app_module, "get_visible_user_ids", lambda cursor, role=None, user_id=None: [1])

    client = app_module.app.test_client()
    with client.session_transaction() as session:
        session["user_id"] = 1
        session["role"] = "admin"
        session["username"] = "admin"
        session["last_active"] = "2026-06-25T00:00:00"

    response = client.get("/users", follow_redirects=False)

    assert response.status_code == 200
    assert b"The users page could not be loaded right now" in response.data
