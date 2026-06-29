import mysql.connector
import app as app_module


def test_login_returns_service_unavailable_when_db_is_down(monkeypatch):
    client = app_module.app.test_client()

    def fail_login_check(username):
        raise mysql.connector.DatabaseError("DB unavailable")

    monkeypatch.setattr(app_module, "check_login_rate_limit", fail_login_check)

    response = client.get("/")
    assert response.status_code == 200

    with client.session_transaction() as session:
        csrf = session.get("csrf")

    response = client.post(
        "/",
        data={
            "username": "admin",
            "password": "Admin@123",
            "csrf": csrf,
        },
        follow_redirects=False,
    )

    assert response.status_code == 503
    assert b"Database is temporarily unavailable" in response.data
