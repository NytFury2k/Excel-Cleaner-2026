import io
import os
import sys
import pandas as pd
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import app as app_module

def get_auth_client():
    client = app_module.app.test_client()
    with client.session_transaction() as session:
        session["user_id"] = 1
        session["role"] = "admin"
        session["username"] = "admin"
        session["last_active"] = datetime.utcnow().isoformat()
    return client

def create_excel_bytes(data):
    df = pd.DataFrame(data)
    bio = io.BytesIO()
    with pd.ExcelWriter(bio, engine="openpyxl") as writer:
        df.to_excel(writer, index=False)
    bio.seek(0)
    return bio

def test_custom_merge_excel_page_get():
    client = get_auth_client()
    response = client.get("/custom/merge-excel")
    assert response.status_code == 200
    assert b"Merge Excel Files" in response.data

def test_api_custom_merge_inspect_success():
    client = get_auth_client()

    f1_data = {
        "Employee ID": [101, 102, 103],
        "Name": ["Rishikesh", "Rahul", "Amit"],
        "Department": ["Engineering", "HR", "Sales"]
    }
    f2_data = {
        "Employee ID": [101, 103, 104],
        "Salary": [80000, 70000, 90000],
        "Location": ["Bangalore", "Mumbai", "Delhi"]
    }

    f1_bytes = create_excel_bytes(f1_data)
    f2_bytes = create_excel_bytes(f2_data)

    data = {
        "file1": (f1_bytes, "file1.xlsx"),
        "file2": (f2_bytes, "file2.xlsx")
    }

    res = client.post("/api/custom/merge/inspect", data=data, content_type="multipart/form-data")
    assert res.status_code == 200
    json_res = res.get_json()
    assert json_res["ok"] is True
    assert json_res["file1_row_count"] == 3
    assert json_res["file2_row_count"] == 3
    assert "Employee ID" in json_res["common_columns"]

def test_api_custom_merge_inspect_no_common_columns():
    client = get_auth_client()
    f1_bytes = create_excel_bytes({"ID1": [1, 2], "Val1": ["A", "B"]})
    f2_bytes = create_excel_bytes({"ID2": [3, 4], "Val2": ["C", "D"]})

    data = {
        "file1": (f1_bytes, "file1.xlsx"),
        "file2": (f2_bytes, "file2.xlsx")
    }

    res = client.post("/api/custom/merge/inspect", data=data, content_type="multipart/form-data")
    assert res.status_code == 200
    json_res = res.get_json()
    assert json_res["ok"] is True
    assert json_res["common_columns"] == []

def test_api_custom_merge_inspect_invalid_file_format():
    client = get_auth_client()
    data = {
        "file1": (io.BytesIO(b"dummy content"), "file1.txt"),
        "file2": (create_excel_bytes({"ID": [1]}), "file2.xlsx")
    }

    res = client.post("/api/custom/merge/inspect", data=data, content_type="multipart/form-data")
    assert res.status_code == 400
    json_res = res.get_json()
    assert json_res["ok"] is False
    assert "Invalid file format" in json_res["error"]

def test_api_custom_merge_preview_sql_inner_join():
    client = get_auth_client()

    f1_data = {
        "Employee ID": [101, 102, 103],
        "Name": ["Rishikesh", "Rahul", "Amit"],
        "Department": ["Engineering", "HR", "Sales"]
    }
    f2_data = {
        "Employee ID": [" 101 ", 103, 104],
        "Salary": [80000, 70000, 90000],
        "Location": ["Bangalore", "Mumbai", "Delhi"]
    }

    f1_bytes = create_excel_bytes(f1_data)
    f2_bytes = create_excel_bytes(f2_data)

    data = {
        "file1": (f1_bytes, "file1.xlsx"),
        "file2": (f2_bytes, "file2.xlsx"),
        "merge_key": "Employee ID"
    }

    res = client.post("/api/custom/merge/preview", data=data, content_type="multipart/form-data")
    assert res.status_code == 200
    json_res = res.get_json()
    assert json_res["ok"] is True
    assert json_res["matched_rows_count"] == 2
    
    # Check returned rows
    matched_ids = [str(r["Employee ID"]) for r in json_res["preview_rows"]]
    assert "101" in matched_ids
    assert "103" in matched_ids
    assert "102" not in matched_ids
    assert "104" not in matched_ids

def test_api_custom_merge_preview_no_matching_rows():
    client = get_auth_client()

    f1_data = {"Employee ID": [101, 102], "Name": ["A", "B"]}
    f2_data = {"Employee ID": [201, 202], "Salary": [5000, 6000]}

    f1_bytes = create_excel_bytes(f1_data)
    f2_bytes = create_excel_bytes(f2_data)

    data = {
        "file1": (f1_bytes, "file1.xlsx"),
        "file2": (f2_bytes, "file2.xlsx"),
        "merge_key": "Employee ID"
    }

    res = client.post("/api/custom/merge/preview", data=data, content_type="multipart/form-data")
    assert res.status_code == 200
    json_res = res.get_json()
    assert json_res["ok"] is True
    assert json_res["matched_rows_count"] == 0
    assert json_res["preview_rows"] == []

def test_api_custom_merge_download_success():
    client = get_auth_client()

    f1_data = {"Employee ID": [101, 103], "Name": ["Rishikesh", "Amit"]}
    f2_data = {"Employee ID": [101, 103], "Salary": [80000, 70000]}

    f1_bytes = create_excel_bytes(f1_data)
    f2_bytes = create_excel_bytes(f2_data)

    data = {
        "file1": (f1_bytes, "file1.xlsx"),
        "file2": (f2_bytes, "file2.xlsx"),
        "merge_key": "Employee ID"
    }

    res = client.post("/api/custom/merge/download", data=data, content_type="multipart/form-data")
    assert res.status_code == 200
    assert res.mimetype == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    
    # Parse downloaded Excel stream to verify contents
    downloaded_df = pd.read_excel(io.BytesIO(res.data))
    assert len(downloaded_df) == 2
    assert "Employee ID" in downloaded_df.columns
    assert "Name" in downloaded_df.columns
    assert "Salary" in downloaded_df.columns

def test_api_custom_merge_download_no_matching_rows_error():
    client = get_auth_client()

    f1_data = {"Employee ID": [101], "Name": ["A"]}
    f2_data = {"Employee ID": [201], "Salary": [5000]}

    f1_bytes = create_excel_bytes(f1_data)
    f2_bytes = create_excel_bytes(f2_data)

    data = {
        "file1": (f1_bytes, "file1.xlsx"),
        "file2": (f2_bytes, "file2.xlsx"),
        "merge_key": "Employee ID"
    }

    res = client.post("/api/custom/merge/download", data=data, content_type="multipart/form-data")
    assert res.status_code == 400
    json_res = res.get_json()
    assert json_res["ok"] is False
    assert "No matching records found" in json_res["error"]
