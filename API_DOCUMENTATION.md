# Paramantra Data Manager — Public REST API Documentation

Comprehensive technical documentation for external callers, integrations, and developers interacting with the **Paramantra Data Manager REST API**.

---

## 1. Overview & Authentication Architecture

- **Base URL**: `http://<host>:<port>/api`
- **Content Types**:
  - `application/json` (Standard API payload requests and JSON responses)
  - `multipart/form-data` (File upload and merge endpoints)
- **Authentication**: Stateless Bearer Token Authorization.
  - Callers must pass the token in the `Authorization` HTTP header for all protected endpoints:
    ```http
    Authorization: Bearer <YOUR_API_TOKEN>
    ```

### Rate Limiting & Lockout Safety
- Failed authentication attempts (`/api/auth/token`) are rate-limited (5 failed attempts within 10 minutes results in a temporary 10-minute lockout).

---

## 2. Authentication Endpoints

### 2.1 Obtain API Token
Exchanges user credentials for a Bearer token (valid for 24 hours).

- **Endpoint**: `POST /api/auth/token`
- **Authentication**: None (Public)
- **Request Body** (`application/json`):
  ```json
  {
    "username": "admin",
    "password": "YourSecurePassword123!"
  }
  ```
- **Response `200 OK`**:
  ```json
  {
    "token": "3a7b9f12c4d8e5f6...",
    "expires_at": "2026-09-05T12:00:00.000Z",
    "role": "admin",
    "username": "admin"
  }
  ```
- **Response `401 Unauthorized`**:
  ```json
  { "error": "Invalid credentials" }
  ```
- **Response `429 Too Many Requests`**:
  ```json
  { "error": "Too many failed attempts. Try again in 10 minute(s)." }
  ```

---

### 2.2 Refresh Token
Extends an active Bearer token's expiration time by 24 hours without re-supplying credentials.

- **Endpoint**: `POST /api/auth/refresh`
- **Authentication**: Bearer Token
- **Response `200 OK`**:
  ```json
  {
    "token": "3a7b9f12c4d8e5f6...",
    "expires_at": "2026-09-06T12:00:00.000Z"
  }
  ```

---

### 2.3 Revoke Token
Invalidates the current Bearer token upon caller logout or task completion.

- **Endpoint**: `POST /api/auth/revoke`
- **Authentication**: Bearer Token
- **Response `200 OK`**:
  ```json
  { "message": "Token revoked successfully" }
  ```

---

## 3. Data Cleaning & Inspection Pipeline

### 3.1 Upload File
Uploads an Excel (`.xlsx`, `.xls`) or CSV file to initialize a cleaning job session.

- **Endpoint**: `POST /api/upload`
- **Authentication**: Bearer Token (`upload_file` permission required)
- **Request Format**: `multipart/form-data` or `application/json` (Base64)
- **Form Data Fields**:
  - `file`: Spreadsheet file binary.
- **Response `200 OK`**:
  ```json
  {
    "ok": true,
    "job_id": "job_9a8b7c6d",
    "filename": "leads_2026.xlsx",
    "row_count": 1500,
    "columns": ["Employee ID", "Full Name", "Email Address", "Phone Number", "Joined Date"]
  }
  ```

---

### 3.2 List Available Cleaning Rules
Lists all supported data validation and cleaning rules, grouped by data type.

- **Endpoint**: `GET /api/rules`
- **Authentication**: Bearer Token
- **Query Parameters**:
  - `type` *(optional)*: Filter rules by column data type (e.g., `text`, `email`, `phone`, `date`, `numeric`, `url`).
- **Response `200 OK`**:
  ```json
  {
    "ok": true,
    "rules": {
      "email": [
        { "id": "validate_email", "name": "Validate Email Format", "description": "Flags invalid email addresses" },
        { "id": "lowercase_email", "name": "Lowercase Email", "description": "Converts emails to lowercase" }
      ],
      "phone": [
        { "id": "validate_phone", "name": "Validate Phone Number", "description": "Validates 10-digit phone format" },
        { "id": "format_phone_number", "name": "Format Phone Number", "description": "Standardizes format to +91-XXXXX-XXXXX" }
      ]
    }
  }
  ```

---

### 3.3 Execute Cleaning Pipeline
Applies selected rules to an active uploaded spreadsheet dataset.

- **Endpoint**: `POST /api/clean`
- **Authentication**: Bearer Token (`run_cleaning` permission required)
- **Request Body** (`application/json`):
  ```json
  {
    "job_id": "job_9a8b7c6d",
    "selected_rules": {
      "Email Address": ["validate_email", "lowercase_email"],
      "Phone Number": ["validate_phone", "format_phone_number"],
      "Full Name": ["trim_whitespace", "title_case_text"]
    }
  }
  ```
- **Response `200 OK`**:
  ```json
  {
    "ok": true,
    "job_id": "job_9a8b7c6d",
    "summary": {
      "total_rows": 1500,
      "valid_rows": 1420,
      "invalid_rows": 80,
      "removed_rows": 0,
      "clean_rate": "94.67%"
    }
  }
  ```

---

### 3.4 Preview Cleaned Job Results
Retrieves paginated cleaned rows for preview before storing or downloading.

- **Endpoint**: `GET /api/preview/<job_id>`
- **Authentication**: Bearer Token
- **Query Parameters**:
  - `page` *(optional, default=1)*: Page index.
  - `page_size` *(optional, default=50)*: Items per page.
  - `view` *(optional, default="valid")*: Dataset view (`valid`, `invalid`, `removed`).
- **Response `200 OK`**:
  ```json
  {
    "ok": true,
    "page": 1,
    "page_size": 50,
    "total_records": 1420,
    "total_pages": 29,
    "columns": ["Employee ID", "Full Name", "Email Address", "Phone Number"],
    "data": [
      {
        "Employee ID": 101,
        "Full Name": "Rishikesh Sharma",
        "Email Address": "rishikesh@example.com",
        "Phone Number": "+91-9876543210"
      }
    ]
  }
  ```

---

### 3.5 Download Cleaned Dataset File
Exports the valid, invalid, or removed dataset as an Excel file download or Base64 payload.

- **Endpoint**: `GET /api/download/<file_type>/<job_id>`
- **Authentication**: Bearer Token (`download_results` permission required)
- **Path Parameters**:
  - `file_type`: `cleaned`, `invalid`, or `removed`.
  - `job_id`: Active cleaning job ID.
- **Query Parameters**:
  - `format` *(optional, default="binary")*: Set to `base64` to receive a JSON object containing the base64-encoded string instead of binary download.
- **Response `200 OK`**: Returns spreadsheet file stream (`application/vnd.openxmlformats-officedocument.spreadsheetml.sheet`).

---

## 4. Custom Features — Excel Merge (SQL Inner Join)

Allows callers to perform an **SQL INNER JOIN** merge on two Excel files in memory without database persistence.

### 4.1 Inspect Excel Files
Uploads two files and returns column metadata, row counts, and identified common columns.

- **Endpoint**: `POST /api/custom/merge/inspect`
- **Authentication**: Bearer Token
- **Request Format**: `multipart/form-data`
- **Form Fields**:
  - `file1`: Primary Excel / CSV file.
  - `file2`: Secondary Excel / CSV file.
- **Response `200 OK`**:
  ```json
  {
    "ok": true,
    "file1_row_count": 3,
    "file2_row_count": 3,
    "file1_columns": ["Employee ID", "Name", "Department"],
    "file2_columns": ["Employee ID", "Salary", "Location"],
    "common_columns": ["Employee ID"]
  }
  ```
- **Response `400 Bad Request`** *(Invalid file or no common columns)*:
  ```json
  {
    "ok": false,
    "error": "Invalid file format: .txt. Only Excel (.xlsx, .xls) and CSV files are allowed."
  }
  ```

---

### 4.2 Preview Merged Results
Calculates the inner join match stats and returns a preview of top merged rows.

- **Endpoint**: `POST /api/custom/merge/preview`
- **Authentication**: Bearer Token
- **Request Format**: `multipart/form-data`
- **Form Fields**:
  - `file1`: Primary Excel / CSV file.
  - `file2`: Secondary Excel / CSV file.
  - `merge_key`: Common column name chosen as join key (e.g. `Employee ID`).
- **Response `200 OK`**:
  ```json
  {
    "ok": true,
    "matched_rows_count": 2,
    "columns": ["Employee ID", "Name", "Department", "Salary", "Location"],
    "preview_rows": [
      {
        "Employee ID": 101,
        "Name": "Rishikesh",
        "Department": "Engineering",
        "Salary": 80000,
        "Location": "Bangalore"
      },
      {
        "Employee ID": 103,
        "Name": "Amit",
        "Department": "Sales",
        "Salary": 70000,
        "Location": "Mumbai"
      }
    ]
  }
  ```

---

### 4.3 Download Merged Excel File
Generates and downloads the dynamically merged Excel binary file.

- **Endpoint**: `POST /api/custom/merge/download`
- **Authentication**: Bearer Token
- **Request Format**: `multipart/form-data`
- **Form Fields**:
  - `file1`: Primary Excel / CSV file.
  - `file2`: Secondary Excel / CSV file.
  - `merge_key`: Selected join column name.
- **Response `200 OK`**: Binary Excel spreadsheet stream attachment (`merged_Employee_ID.xlsx`).
- **Response `400 Bad Request`** *(Zero rows matched)*:
  ```json
  {
    "ok": false,
    "error": "No matching records found. The selected column does not contain any values that exist in both files."
  }
  ```

---

## 5. Master Data Records Query API (v1)

Queries and filters master database records stored in the system.

- **Endpoint**: `GET /api/v1/records/query`
- **Authentication**: Bearer Token
- **Query Parameters**:
  - `page` *(default=1)*: Page number.
  - `limit` *(default=20, max=500)*: Records per page.
  - `search` *(optional)*: Full-text search across records.
  - `from_date` *(optional, YYYY-MM-DD)*: Filter records imported on or after date.
  - `to_date` *(optional, YYYY-MM-DD)*: Filter records imported on or before date.
  - `imported_by` *(optional)*: Filter by user ID / username.
- **Response `200 OK`**:
  ```json
  {
    "ok": true,
    "page": 1,
    "limit": 20,
    "total_records": 1250,
    "total_pages": 63,
    "data": [
      {
        "id": 1,
        "imported_by": "admin",
        "custom_fields": {
          "Name": "Rishikesh",
          "Email": "rishikesh@example.com"
        },
        "created_at": "2026-09-04T10:00:00Z"
      }
    ]
  }
  ```

---

## 6. Saved Rule Presets

### 6.1 List Presets
- **Endpoint**: `GET /api/presets`
- **Authentication**: Bearer Token
- **Response `200 OK`**:
  ```json
  {
    "ok": true,
    "presets": [
      { "id": 1, "preset_name": "Standard Lead Cleaning", "created_at": "2026-08-15T08:30:00Z" }
    ]
  }
  ```

### 6.2 Save Preset
- **Endpoint**: `POST /api/presets/save`
- **Authentication**: Bearer Token
- **Request Body** (`application/json`):
  ```json
  {
    "preset_name": "Standard Lead Cleaning",
    "rules_config": {
      "Email": ["validate_email", "lowercase_email"],
      "Phone": ["validate_phone"]
    }
  }
  ```
- **Response `200 OK`**:
  ```json
  { "ok": true, "preset_id": 1, "message": "Preset saved successfully" }
  ```

---

## 7. User Management (RBAC Admin & Manager Only)

### 7.1 List Users
- **Endpoint**: `GET /api/users`
- **Authentication**: Bearer Token (`view_all_users` or `view_team_users`)
- **Response `200 OK`**:
  ```json
  {
    "ok": true,
    "users": [
      {
        "id": 1,
        "username": "admin",
        "email": "admin@example.com",
        "role": "admin",
        "is_active": 1
      }
    ]
  }
  ```

### 7.2 Create User
- **Endpoint**: `POST /api/users/create`
- **Authentication**: Bearer Token (`create_user` permission required)
- **Request Body**:
  ```json
  {
    "username": "john_doe",
    "email": "john@example.com",
    "password": "Password123!",
    "role": "user",
    "manager_id": 2
  }
  ```
- **Response `200 OK`**:
  ```json
  { "ok": true, "user_id": 15, "message": "User created successfully" }
  ```

---

## 8. Activity Audit Logs

- **Endpoint**: `GET /api/logs`
- **Authentication**: Bearer Token (`view_all_logs`, `view_team_logs`, or `view_own_logs`)
- **Query Parameters**:
  - `page` *(default=1)*: Page number.
  - `log_type` *(default="all")*: Filter by `login`, `cleaning`, `search`, `export`, or `all`.
  - `search` *(optional)*: Search term.
- **Response `200 OK`**:
  ```json
  {
    "ok": true,
    "page": 1,
    "total_logs": 340,
    "logs": [
      {
        "id": 1021,
        "username": "admin",
        "action": "Cleaned dataset with 1500 rows",
        "timestamp": "2026-09-04T11:00:00Z"
      }
    ]
  }
  ```

---

## 9. Dashboard Analytics

- **Endpoint**: `GET /api/dashboard/analytics`
- **Authentication**: Bearer Token
- **Response `200 OK`**:
  ```json
  {
    "ok": true,
    "metrics": {
      "total_records_cleaned": 45200,
      "total_uploads": 128,
      "valid_records_rate": "96.4%",
      "active_users": 12
    }
  }
  ```
