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
