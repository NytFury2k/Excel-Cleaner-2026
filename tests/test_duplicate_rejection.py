from helpers import ingest_uploaded_file_with_mapping

class FakeCursor:
    def __init__(self, existing_rows=None):
        self.existing_rows = existing_rows or []
        self.inserted_master = []
        self.inserted_rejected = []
        self.queries = []

    def close(self):
        pass

    def execute(self, query, params=None):
        self.queries.append((query, params))
        if "DESCRIBE master_records" in query or "information_schema" in query:
            return
        if "field_aliases" in query or "field_registry" in query:
            return
        if "uploaded_files" in query:
            self._u_info_call = True
            return
        if "SELECT COUNT(*)" in query:
            matched = False
            if params:
                for row in self.existing_rows:
                    all_matched = True
                    for p in params:
                        if isinstance(p, str):
                            p_clean = p.strip().lower()
                            row_vals = [str(v).strip().lower() for v in row.values() if v is not None]
                            if p_clean not in row_vals:
                                all_matched = False
                                break
                    if all_matched:
                        matched = True
                        break
            self._last_count = 1 if matched else 0

    def fetchone(self):
        if getattr(self, "_u_info_call", False):
            self._u_info_call = False
            return {"user_id": 1, "original_filename": "test_leads.xlsx"}
        if hasattr(self, "_last_count"):
            cnt = self._last_count
            del self._last_count
            return {"count": cnt}
        return {"Field": "id"}

    def fetchall(self):
        return [
            {"Field": "id"},
            {"Field": "file_id"},
            {"Field": "first_name"},
            {"Field": "last_name"},
            {"Field": "email"},
            {"Field": "created_at"},
            {"Field": "updated_at"},
            {"Field": "imported_by"},
            {"Field": "custom_fields"}
        ]

    def executemany(self, query, params_list):
        if "master_records" in query:
            self.inserted_master.extend(params_list)

class FakeConn:
    def __init__(self, cursor_obj):
        self._cursor = cursor_obj

    def cursor(self, dictionary=True):
        return self._cursor

    def commit(self):
        pass

    def rollback(self):
        pass

    def close(self):
        pass

def test_ingest_duplicate_rejection_against_db(monkeypatch, tmp_path):
    import pandas as pd
    
    df = pd.DataFrame({
        "first_name": ["John", "John", "Alice"],
        "last_name": ["Doe", "Doe", "Smith"],
        "email": ["john@example.com", "john@example.com", "alice@example.com"]
    })
    
    test_file = tmp_path / "test_leads.xlsx"
    df.to_excel(test_file, index=False)
    
    existing_db_data = [
        {"first_name": "John", "last_name": "Doe", "email": "john@example.com"}
    ]
    
    fake_cursor = FakeCursor(existing_rows=existing_db_data)
    fake_conn = FakeConn(fake_cursor)
    
    monkeypatch.setattr("helpers.get_db_connection", lambda: fake_conn)
    
    ingest_uploaded_file_with_mapping(
        file_id=1,
        file_path=str(test_file),
        username="admin",
        mapping_config={
            "first_name": "master:first_name",
            "last_name": "master:last_name",
            "email": "master:email"
        }
    )
    
    assert len(fake_cursor.inserted_master) == 1
