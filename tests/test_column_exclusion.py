import pytest
import os
import pandas as pd
import json
import app as app_module
from flask import session

@pytest.fixture
def client(monkeypatch):
    app_module.app.config["TESTING"] = True
    with app_module.app.test_client() as client:
        yield client

def test_clean_data_drops_discarded_columns(client, tmp_path):
    # 1. Create a dummy CSV file to clean
    csv_file = tmp_path / "test_data.csv"
    df = pd.DataFrame({
        "first_name": ["Alice", "Bob"],
        "ignored_col": ["delete_me", "delete_me_too"]
    })
    df.to_csv(csv_file, index=False)
    
    # 2. Set up session
    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["role"] = "admin"
        sess["uploaded_file"] = "test_data.csv"
        sess["uploaded_sheets"] = [{
            "sheet_id": "s_test_123",
            "original_filename": "test_data.csv",
            "sheet_name": "CSV",
            "safe_sheet_name": "CSV",
            "temp_path": str(csv_file),
            "columns": ["first_name", "ignored_col"],
            "total_rows": 2,
            "file_id": 1
        }]
        
    # 3. Post to /clean with "ignored_col" mapped to "__discard__"
    form_data = {
        "map_col_s_test_123_first_name": "master:first_name",
        "map_col_s_test_123_ignored_col": "__discard__",
        "rules_master_first_name[]": ["required"],
        "strategy_master_first_name": "flag"
    }
    
    res = client.post("/clean", data=form_data)
    assert res.status_code == 200
    
    # 4. Verify that generated cleaned file does NOT have the ignored column
    cleaned_file_path = session.get("cleaned_file")
    assert cleaned_file_path is not None
    assert os.path.exists(cleaned_file_path)
    
    df_cleaned = pd.read_excel(cleaned_file_path)
    assert "first_name" in df_cleaned.columns
    assert "ignored_col" not in df_cleaned.columns
    
    # Clean up file
    if os.path.exists(cleaned_file_path):
        os.remove(cleaned_file_path)

def test_lazy_custom_fields_registration(client, tmp_path):
    # 1. Create a dummy CSV file with a new column
    csv_file = tmp_path / "test_lazy.csv"
    df = pd.DataFrame({
        "first_name": ["Dave"],
        "brand_new_custom_col": ["some_value"]
    })
    df.to_csv(csv_file, index=False)
    
    # Check that this brand new field is not in the registry yet
    conn = app_module.get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM field_registry WHERE normalized_name = 'brand_new_custom_col'")
    cursor.execute("DELETE FROM field_aliases WHERE normalized_alias = 'brand_new_custom_col'")
    conn.commit()
    conn.close()
    
    # 2. Set up session
    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["role"] = "admin"
        sess["uploaded_file"] = "test_lazy.csv"
        sess["uploaded_sheets"] = [{
            "sheet_id": "s_lazy_999",
            "original_filename": "test_lazy.csv",
            "sheet_name": "CSV",
            "safe_sheet_name": "CSV",
            "temp_path": str(csv_file),
            "columns": ["first_name", "brand_new_custom_col"],
            "total_rows": 1,
            "file_id": 1
        }]
        
    # 3. Post to /clean with brand_new_custom_col mapped to "ignore" (Keep As Is)
    form_data = {
        "map_col_s_lazy_999_first_name": "master:first_name",
        "map_col_s_lazy_999_brand_new_custom_col": "ignore",
        "store_in_db": "1"
    }
    
    res = client.post("/clean", data=form_data)
    assert res.status_code == 200
    
    # 4. Verify that registry now contains brand_new_custom_col
    conn = app_module.get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, field_name FROM field_registry WHERE normalized_name = 'brand_new_custom_col'")
    reg_row = cursor.fetchone()
    assert reg_row is not None
    assert reg_row["field_name"] == "brand_new_custom_col"
    
    # Cleanup database
    cursor.execute("DELETE FROM field_registry WHERE normalized_name = 'brand_new_custom_col'")
    cursor.execute("DELETE FROM field_aliases WHERE normalized_alias = 'brand_new_custom_col'")
    conn.commit()
    conn.close()


def test_clean_multiple_sheets_and_files(client, tmp_path):
    # 1. Create two dummy files representing multiple sheets/files
    file1 = tmp_path / "file1.csv"
    pd.DataFrame({
        "first_name": ["Alice"],
        "email_address": ["ALICE@example.com"]
    }).to_csv(file1, index=False)
    
    file2 = tmp_path / "file2.csv"
    pd.DataFrame({
        "first_name": ["Bob"],
        "email_address": ["BOB@example.com"]
    }).to_csv(file2, index=False)
    
    # 2. Set up session with multiple sheets
    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["role"] = "admin"
        sess["uploaded_file"] = "2 files"
        sess["uploaded_sheets"] = [
            {
                "sheet_id": "s_file1",
                "original_filename": "file1.csv",
                "sheet_name": "CSV",
                "safe_sheet_name": "file1",
                "temp_path": str(file1),
                "columns": ["first_name", "email_address"],
                "total_rows": 1,
                "file_id": 1
            },
            {
                "sheet_id": "s_file2",
                "original_filename": "file2.csv",
                "sheet_name": "CSV",
                "safe_sheet_name": "file2",
                "temp_path": str(file2),
                "columns": ["first_name", "email_address"],
                "total_rows": 1,
                "file_id": 2
            }
        ]
        
    # 3. Post mapping data for BOTH sheets
    form_data = {
        "map_col_s_file1_first_name": "master:first_name",
        "map_col_s_file1_email_address": "custom:1",
        "map_col_s_file2_first_name": "master:first_name",
        "map_col_s_file2_email_address": "custom:1",
        "rules_master_first_name[]": ["trim_whitespace"],
        "custom_field_target_0": "1",
        "rules_custom_0[]": ["validate_email", "lowercase_email"],
        "strategy_custom_0": "flag"
    }
    
    res = client.post("/clean", data=form_data)
    assert res.status_code == 200
    
    # 4. Verify clean output contains sheets for both files
    cleaned_file_path = session.get("cleaned_file")
    assert cleaned_file_path is not None
    assert os.path.exists(cleaned_file_path)
    
    xl = pd.ExcelFile(cleaned_file_path)
    assert "file1" in xl.sheet_names
    assert "file2" in xl.sheet_names
    
    df1 = xl.parse("file1")
    assert df1.loc[0, "first_name"] == "Alice"
    assert df1.loc[0, "email_address"] == "alice@example.com"
    
    df2 = xl.parse("file2")
    assert df2.loc[0, "first_name"] == "Bob"
    assert df2.loc[0, "email_address"] == "bob@example.com"
    
    xl.close()
    
    # Clean up
    if os.path.exists(cleaned_file_path):
        os.remove(cleaned_file_path)

def test_drop_unnamed_columns():
    from helpers import drop_unnamed_columns
    df = pd.DataFrame({
        "first_name": ["Alice", "Bob"],
        "Unnamed: 0": ["x", "y"],
        "Unnamed: 1": [1, 2],
        "unnamed": [3, 4],
        "": ["a", "b"]
    })
    df_cleaned = drop_unnamed_columns(df)
    assert "first_name" in df_cleaned.columns
    assert "Unnamed: 0" not in df_cleaned.columns
    assert "Unnamed: 1" not in df_cleaned.columns
    assert "unnamed" not in df_cleaned.columns
    assert "" not in df_cleaned.columns

def test_clean_data_uses_excel_specific_rules(client, tmp_path):
    csv_file = tmp_path / "excel_rules_test.csv"
    df = pd.DataFrame({
        "first_name": ["  Alice  ", "Bob"],
    })
    df.to_csv(csv_file, index=False)
    
    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["role"] = "admin"
        sess["uploaded_file"] = "excel_rules_test.csv"
        sess["uploaded_sheets"] = [{
            "sheet_id": "s_excel_123",
            "original_filename": "excel_rules_test.csv",
            "sheet_name": "CSV",
            "safe_sheet_name": "CSV",
            "temp_path": str(csv_file),
            "columns": ["first_name"],
            "total_rows": 2,
            "file_id": 1
        }]
        
    form_data = {
        "map_col_s_excel_123_first_name": "master:first_name",
        "rules_excel_first_name[]": ["trim_whitespace"]
    }
    
    res = client.post("/clean", data=form_data)
    assert res.status_code == 200
    
    cleaned_file_path = session.get("cleaned_file")
    assert cleaned_file_path is not None
    assert os.path.exists(cleaned_file_path)
    
    df_cleaned = pd.read_excel(cleaned_file_path)
    assert df_cleaned["first_name"][0] == "Alice"
    
    if os.path.exists(cleaned_file_path):
        os.remove(cleaned_file_path)

def test_clean_data_type_override_and_predefined_email(client, tmp_path):
    csv_file = tmp_path / "email_override_test.csv"
    df = pd.DataFrame({
        "my_field": ["Rishi#jhjb.com", "valid@example.com"],
    })
    df.to_csv(csv_file, index=False)
    
    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["role"] = "admin"
        sess["uploaded_file"] = "email_override_test.csv"
        sess["uploaded_sheets"] = [{
            "sheet_id": "s_email_123",
            "original_filename": "email_override_test.csv",
            "sheet_name": "CSV",
            "safe_sheet_name": "CSV",
            "temp_path": str(csv_file),
            "columns": ["my_field"],
            "total_rows": 2,
            "file_id": 1
        }]
        
    form_data = {
        "map_col_s_email_123_my_field": "master:email_address",
        "type_override_excel_my_field": "email",
        "rules_excel_my_field[]": ["predefined_email"]
    }
    
    res = client.post("/clean", data=form_data)
    assert res.status_code == 200
    
    cleaned_file_path = session.get("cleaned_file")
    invalid_file_path = session.get("invalid_file")
    
    assert cleaned_file_path is not None
    assert invalid_file_path is not None
    
    df_cleaned = pd.read_excel(cleaned_file_path)
    df_invalid = pd.read_excel(invalid_file_path)
    
    assert "valid@example.com" in df_cleaned["my_field"].values
    assert "Rishi#jhjb.com" not in df_cleaned["my_field"].values
    assert "rishi#jhjb.com" in df_invalid["my_field"].values
    
    if os.path.exists(cleaned_file_path):
        os.remove(cleaned_file_path)
    if os.path.exists(invalid_file_path):
        os.remove(invalid_file_path)

def test_clean_data_predefined_phone_rules(client, tmp_path):
    csv_file = tmp_path / "phone_predefined_test.csv"
    df = pd.DataFrame({
        "my_phone": ["919876543210", "9876543210", "123"],
    })
    df.to_csv(csv_file, index=False)
    
    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["role"] = "admin"
        sess["uploaded_file"] = "phone_predefined_test.csv"
        sess["uploaded_sheets"] = [{
            "sheet_id": "s_phone_123",
            "original_filename": "phone_predefined_test.csv",
            "sheet_name": "CSV",
            "safe_sheet_name": "CSV",
            "temp_path": str(csv_file),
            "columns": ["my_phone"],
            "total_rows": 3,
            "file_id": 1
        }]
        
    form_data = {
        "map_col_s_phone_123_my_phone": "master:primary_phone_number",
        "type_override_excel_my_phone": "phone",
        "rules_excel_my_phone[]": ["predefined_phone"]
    }
    
    res = client.post("/clean", data=form_data)
    assert res.status_code == 200
    
    cleaned_file_path = session.get("cleaned_file")
    invalid_file_path = session.get("invalid_file")
    
    assert cleaned_file_path is not None
    assert invalid_file_path is not None
    
    df_cleaned = pd.read_excel(cleaned_file_path)
    df_invalid = pd.read_excel(invalid_file_path)
    
    assert "(987) 654-3210" in df_cleaned["my_phone"].values
    assert len(df_cleaned) == 2
    assert "123" in df_invalid["my_phone"].astype(str).values
    
    if os.path.exists(cleaned_file_path):
        os.remove(cleaned_file_path)
    if os.path.exists(invalid_file_path):
        os.remove(invalid_file_path)

def test_clean_data_unmapped_column_rules(client, tmp_path):
    csv_file = tmp_path / "unmapped_rules_test.csv"
    df = pd.DataFrame({
        "my_field": ["  Alice  ", "Bob"],
    })
    df.to_csv(csv_file, index=False)
    
    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["role"] = "admin"
        sess["uploaded_file"] = "unmapped_rules_test.csv"
        sess["uploaded_sheets"] = [{
            "sheet_id": "s_unmapped_123",
            "original_filename": "unmapped_rules_test.csv",
            "sheet_name": "CSV",
            "safe_sheet_name": "CSV",
            "temp_path": str(csv_file),
            "columns": ["my_field"],
            "total_rows": 2,
            "file_id": 1
        }]
        
    form_data = {
        "map_col_s_unmapped_123_my_field": "ignore",
        "rules_excel_my_field[]": ["trim_whitespace"]
    }
    
    res = client.post("/clean", data=form_data)
    assert res.status_code == 200
    
    cleaned_file_path = session.get("cleaned_file")
    assert cleaned_file_path is not None
    
    df_cleaned = pd.read_excel(cleaned_file_path)
    assert df_cleaned["my_field"][0] == "Alice"
    
    if os.path.exists(cleaned_file_path):
        os.remove(cleaned_file_path)

def test_store_endpoints(client, tmp_path):
    csv_file = tmp_path / "store_test.csv"
    df = pd.DataFrame({
        "name": ["Alice", "Bob"],
        "email": ["alice@gmail.com", "bob#invalid.com"]
    })
    df.to_csv(csv_file, index=False)
    
    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["role"] = "admin"
        sess["uploaded_file"] = "store_test.csv"
        sess["uploaded_sheets"] = [{
            "sheet_id": "s_store_123",
            "original_filename": "store_test.csv",
            "sheet_name": "CSV",
            "safe_sheet_name": "CSV",
            "temp_path": str(csv_file),
            "columns": ["name", "email"],
            "total_rows": 2,
            "file_id": 1
        }]
        
    form_data = {
        "map_col_s_store_123_name": "master:first_name",
        "map_col_s_store_123_email": "master:email",
        "rules_excel_email[]": ["predefined_email"]
    }
    
    res = client.post("/clean", data=form_data)
    assert res.status_code == 200
    
    with client.session_transaction() as sess:
        assert sess.get("stored_cleaned") is False
        assert sess.get("stored_invalid") is False
        
    res_store = client.post("/api/store-cleaned")
    assert res_store.status_code == 302
    
    with client.session_transaction() as sess:
        assert sess.get("stored_cleaned") is True
        
    res_invalid = client.post("/api/store-invalid")
    assert res_invalid.status_code == 302
    
    with client.session_transaction() as sess:
        assert sess.get("stored_invalid") is True
        
    # Query database to confirm records are stored in DB
    from helpers import get_db_connection
    import json
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT row_data FROM rejected_records WHERE file_id = 1")
    db_rows = cursor.fetchall()
    conn.close()
    
    assert len(db_rows) > 0
    stored_item = json.loads(db_rows[0]["row_data"])
    assert "email" in stored_item or "email_address" in stored_item or "first_name" in stored_item
        
    cleaned_file_path = session.get("cleaned_file")
    invalid_file_path = session.get("invalid_file")
    if cleaned_file_path and os.path.exists(cleaned_file_path):
        os.remove(cleaned_file_path)
    if invalid_file_path and os.path.exists(invalid_file_path):
        os.remove(invalid_file_path)
