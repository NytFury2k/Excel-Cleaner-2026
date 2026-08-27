import app as app_module
from datetime import datetime

def test_dashboard_analytics_endpoint(monkeypatch):
    class FakeCursor:
        def execute(self, *args, **kwargs):
            return None

        def fetchall(self):
            # We return mock values that mimic multiple calls to fetchall in the route
            return [
                {"month": "2026-08", "count": 10}
            ]

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
    with client.session_transaction() as session:
        session["user_id"] = 1
        session["role"] = "admin"
        session["username"] = "admin"
        session["last_active"] = datetime.utcnow().isoformat()

    response = client.get("/api/dashboard/analytics")

    assert response.status_code == 200
    json_data = response.get_json()
    assert "monthly_leads" in json_data
    assert "leads_userwise" in json_data
    assert "user_uploads" in json_data
    assert "monthly_uploads" in json_data
