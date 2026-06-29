from mysql.connector import ProgrammingError

from helpers import fetch_visible_logs


class FakeCursor:
    def __init__(self):
        self.queries = []
        self.show_tables_calls = 0
        self._show_tables = False

    def execute(self, query, params=None):
        self.queries.append((query, params))
        if isinstance(query, str) and query.upper().startswith("SHOW TABLES"):
            self.show_tables_calls += 1
            self._show_tables = True
            return
        if "search_logs" in query.lower():
            raise ProgrammingError("1146", "1146 (42S02): Table 'excel_cleaner_db.search_logs' doesn't exist", "42S02")

    def fetchone(self):
        if self._show_tables:
            self._show_tables = False
            return None
        return {"count": 0}

    def fetchall(self):
        return []


def test_fetch_visible_logs_falls_back_when_search_log_table_missing(monkeypatch):
    cursor = FakeCursor()
    monkeypatch.setattr(
        "helpers.get_visible_user_ids",
        lambda cursor, role=None, user_id=None: [42],
    )

    logs, total = fetch_visible_logs(
        cursor,
        search="upload",
        log_type="search",
        page=1,
        per_page=10,
    )

    assert logs == []
    assert total == 0
    assert cursor.show_tables_calls >= 1
    assert any("logs" in (query.lower() if isinstance(query, str) else "") for query, _ in cursor.queries)
