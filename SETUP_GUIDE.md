# Local Project Setup Guide: Excel Cleaner 2026

This document provides a comprehensive step-by-step walkthrough to set up and run the **Excel Cleaner 2026** web application locally on a new or different laptop.

---

## 📋 Table of Contents
1. [Prerequisites](#1-prerequisites)
2. [Step 1: Obtain the Project Code](#step-1-obtain-the-project-code)
3. [Step 2: Set Up Python Virtual Environment](#step-2-set-up-python-virtual-environment)
4. [Step 3: Install Required Dependencies](#step-3-install-required-dependencies)
5. [Step 4: Configure Environment Variables (.env)](#step-4-configure-environment-variables-env)
6. [Step 5: Start Local PostgreSQL Database (Docker)](#step-5-start-local-postgresql-database-docker)
7. [Step 6: Initialize Database Schema & Seed Data](#step-6-initialize-database-schema--seed-data)
8. [Step 7: Launch the Web Application](#step-7-launch-the-web-application)
9. [Step 8: Default Credentials & Initial Login](#step-8-default-credentials--initial-login)
10. [Troubleshooting & Common Issues](#troubleshooting--common-issues)

---

## 1. Prerequisites

Before beginning, ensure the following software is installed on the target laptop:

* **Git**: [Download Git](https://git-scm.com/)
* **Python**: Version 3.10 or higher. [Download Python](https://www.python.org/downloads/)
  * *Important:* Ensure `Add Python to PATH` is checked during installation on Windows.
* **Docker Desktop**: [Download Docker Desktop](https://www.docker.com/products/docker-desktop/) (Required for local PostgreSQL database container).
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

## Step 4: Configure Environment Variables (`.env`)

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

Open `.env` in your editor and ensure key configurations match your setup:

```env
# Flask Secret Key (replace with a secure random key in production)
FLASK_SECRET_KEY=bec16071429b40e09435226c1b91e5e4f94839488191131b6759dfcfe5639ea5

# Local PostgreSQL Database Credentials (matching docker-compose.yml)
SUPABASE_DB_HOST=127.0.0.1
SUPABASE_DB_PORT=5433
SUPABASE_DB_NAME=postgres_db
SUPABASE_DB_USER=postgres
SUPABASE_DB_PASSWORD=mylocalpassword

# Mail SMTP settings (Optional for basic local development)
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
MAIL_DEFAULT_SENDER=your-email@gmail.com
```

---

## Step 5: Start Local PostgreSQL Database (Docker)

1. Make sure **Docker Desktop** is open and running on your laptop.
2. In your terminal (inside project directory), start the database container:

```bash
docker-compose up -d
```

3. Verify the container status:
```bash
docker ps
```
You should see `local-postgres` running on port `5433`.

---

## Step 6: Initialize Database Schema & Seed Data

Run the database setup script to automatically create all required tables (`users`, `logs`, `master_records`, `api_tokens`, `rule_presets`, etc.) and seed the default administrator account:

```bash
python fix_db.py
```

---

## Step 7: Launch the Web Application

Start the Flask development server:

```bash
python app.py
```

Once started, open your web browser and navigate to:
👉 **`http://127.0.0.1:5000`**

---

## Step 8: Default Credentials & Initial Login

Use the default administrative credentials to log in:

* **Username**: `admin`
* **Password**: `Admin@123`

---

## 🛠️ Troubleshooting & Common Issues

| Issue / Symptom | Possible Cause | Solution |
| :--- | :--- | :--- |
| `psycopg2.OperationalError: could not connect to server` | Docker database container is not running or incorrect port. | Ensure Docker Desktop is running and execute `docker-compose up -d`. Check `.env` `SUPABASE_DB_PORT` is `5433`. |
| `FLASK_SECRET_KEY is not set in .env` | Missing `.env` file. | Create `.env` by copying `.env.example`. |
| PowerShell script activation error | Windows execution policy restriction. | Run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` in PowerShell before activating `.venv`. |
| Port 5000 already in use | Another application or Flask instance is using port 5000. | Stop the process using port 5000 or change port in `app.py`. |

---
