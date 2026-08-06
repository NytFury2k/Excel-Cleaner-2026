# Local Project Setup Guide: Excel Cleaner 2026 (MySQL Edition)

This document provides a comprehensive step-by-step guide to set up and run the **Excel Cleaner 2026** web application locally on your laptop using a local **MySQL** database.

---

## 📋 Table of Contents
1. [Prerequisites](#1-prerequisites)
2. [Step 1: Obtain the Project Code](#step-1-obtain-the-project-code)
3. [Step 2: Set Up Python Virtual Environment](#step-2-set-up-python-virtual-environment)
4. [Step 3: Install Required Dependencies](#step-3-install-required-dependencies)
5. [Step 4: Configure Local Environment Variables (.env)](#step-4-configure-local-environment-variables-env)
6. [Step 5: Initialize MySQL Schema & Seed Data](#step-5-initialize-mysql-schema--seed-data)
7. [Step 6: Launch the Web Application](#step-6-launch-the-web-application)
8. [Step 7: Default Credentials & Initial Login](#step-7-default-credentials--initial-login)
9. [🛠️ Troubleshooting & Common Issues](#🛠️-troubleshooting--common-issues)

---

## 1. Prerequisites

Before beginning, ensure the following software is installed on your laptop:

* **Git**: [Download Git](https://git-scm.com/)
* **Python**: Version 3.10 or higher. [Download Python](https://www.python.org/downloads/)
  * *Important:* Ensure the option **"Add Python to PATH"** is checked during installation on Windows.
* **MySQL Server**: Version 8.0 or higher. [Download MySQL Installer](https://dev.mysql.com/downloads/installer/) (Or use MySQL running on a Docker container / XAMPP / WampServer).
* **Code Editor / Terminal**: E.g., Visual Studio Code, PowerShell, or Git Bash.

---

## Step 1: Obtain the Project Code

Open a terminal or command prompt and clone the repository, or copy the project files to the target laptop:

```bash
git clone <your-repository-url>
cd Excel-Cleaner-2026
```

---

## Step 2: Set Up Python Virtual Environment

Isolate project dependencies by creating a dedicated Python virtual environment:

### On Windows (PowerShell):
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```
*(If PowerShell blocks execution policies, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` first).*

### On Windows (Command Prompt):
```cmd
python -m venv .venv
\.venv\Scripts\activate.bat
```

### On macOS / Linux:
```bash
python3 -m venv .venv
source .venv/bin/activate
```

---

## Step 3: Install Required Dependencies

Upgrade `pip` and install all required Python packages:

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

---

## Step 4: Configure Local Environment Variables (`.env`)

Create a local environment configuration file from the template provided.

### Copy the template file:

* **Windows (PowerShell)**:
  ```powershell
  Copy-Item .env.example .env
  ```
* **macOS / Linux / Git Bash**:
  ```bash
  cp .env.example .env
  ```

### Customize `.env`:

Open the newly created `.env` file in your editor and update the MySQL configurations matching your local MySQL credentials:

```env
# Flask Secret Key (replace with a secure random key in production)
FLASK_SECRET_KEY=bec16071429b40e09435226c1b91e5e4f94839488191131b6759dfcfe5639ea5

# Local MySQL Database Credentials
DB_HOST=127.0.0.1
DB_PORT=3306
DB_NAME=excel_cleaner_db
DB_USER=root
DB_PASSWORD=your_local_mysql_password

# Mail SMTP settings (Optional for basic local development)
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
MAIL_DEFAULT_SENDER=your-email@gmail.com
```

---

## Step 5: Initialize MySQL Schema & Seed Data

Run the database setup script. This script automatically checks if the database specified by `DB_NAME` exists in MySQL, auto-creates it if missing, creates all required tables (`users`, `logs`, `master_records`, `field_registry`, etc.), and seeds the default administrator account:

```bash
python fix_db.py
```

---

## Step 6: Launch the Web Application

Start the Flask development server:

```bash
python app.py
```

Once started, open your web browser and navigate to:
👉 **`http://127.0.0.1:5000`**

---

## Step 7: Default Credentials & Initial Login

Use the default administrative credentials to log in:

* **Username**: `admin`
* **Password**: `Admin@123`

---

## 🛠️ Troubleshooting & Common Issues

| Issue / Symptom | Possible Cause | Solution |
| :--- | :--- | :--- |
| `mysql.connector.errors.InterfaceError: 2003: Can't connect to MySQL server` | MySQL Server is not running or incorrect port. | Ensure your local MySQL service is started (e.g. via Services panel on Windows or `mysql.server start` on macOS). Check `.env` `DB_PORT` is `3306` (or matching custom port). |
| `Access denied for user 'root'@'localhost'` | Incorrect database user or password in `.env`. | Double-check your local MySQL password and update the `DB_PASSWORD` configuration in `.env`. |
| `FLASK_SECRET_KEY is not set in .env` | Missing `.env` file. | Create `.env` by copying `.env.example`. |
| PowerShell script activation error | Windows execution policy restriction. | Run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` in PowerShell before activating `.venv`. |
| Port 5000 already in use | Another application or Flask instance is using port 5000. | Stop the process using port 5000 or change port in `app.py`. |

---
