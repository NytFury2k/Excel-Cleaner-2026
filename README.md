# ExcelCleaner

Lightweight data sanitization pipeline: Flask + Celery + Pandas.

A web application for uploading Excel files, applying configurable cleaning rules, processing files asynchronously via Celery with real-time progress, and downloading cleaned results.

---

## Features

- ✅ User authentication (bcrypt, role-based: user / admin)
- ✅ First-registered user auto-becomes admin
- ✅ Upload `.xls` / `.xlsx` files with schema validation
- ✅ 5 cleaning rules per column: Remove Specials, Validate Email, Validate Phone, Drop Nulls, Drop Duplicates
- ✅ Global bulk toggle for rules across all columns
- ✅ Save/load rule presets per user (JSON file-based)
- ✅ Async background processing via Celery with real-time progress bar
- ✅ Data health score (% clean)
- ✅ Results preview (donut chart, stats, top-10 table)
- ✅ Download cleaned file + rejected rows separately
- ✅ Activity dashboard with paginated logs and search
- ✅ Admin panel (create users, export logs to Excel)
- ✅ Auto-cleanup of uploaded files older than 24 hours (Celery Beat)

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Web Framework | Flask 3.1.2 |
| Task Queue | Celery 5.3.1 (Redis broker) |
| Database | PostgreSQL / Neon (psycopg2) |
| Data Processing | Pandas + openpyxl |
| Auth | bcrypt password hashing |
| Frontend | Bootstrap 5.3, Chart.js, Bootstrap Icons |
| Testing | pytest |

---

## Quick Setup (Windows)

### Prerequisites

- Python 3.12+
- Redis (required for Celery background jobs)
- PostgreSQL database or [Neon](https://neon.tech) account (free tier works)

### 1. Clone & Setup Virtual Environment

```powershell
git clone <repo-url>
cd excel_cleaner_web
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure Environment Variables

Copy `.env.example` to `.env` and fill in your values:

```powershell
copy .env.example .env
```

Required variables in `.env`:

| Variable | Description | Example |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL/Neon connection string | `postgresql://user:pass@host/db?sslmode=require` |
| `FLASK_SECRET_KEY` | Secret key for session signing | Generate with: `python -c "import secrets; print(secrets.token_hex(32))"` |
| `SESSION_TIMEOUT_MINUTES` | Session expiry (default: 30) | `30` |
| `DB_SSLMODE` | SSL mode for DB | `require` |
| `AUTO_INIT_SCHEMA` | Auto-create tables on startup | `1` (enabled) |

> **⚠️ IMPORTANT:** Never commit `.env` to the repository. It contains sensitive credentials.

### 3. Start Redis

```powershell
docker run -d --name redis -p 6379:6379 redis:7
# For later runs:
docker start redis
```

### 4. Start the Application Stack

Run these in **3 separate terminals**:

```powershell
# Terminal 1 - Celery Worker
.\.venv\Scripts\python -m celery -A app.celery_app worker --loglevel=info -P solo

# Terminal 2 - Celery Beat (scheduled cleanup - optional)
.\.venv\Scripts\python -m celery -A app.celery_app beat --loglevel=info

# Terminal 3 - Flask Web App
.\.venv\Scripts\python app.py
```

Or use the batch script to start all three at once:

```powershell
.\start_excel_cleaner.bat
```

### 5. Access the App

Open [http://127.0.0.1:5000](http://127.0.0.1:5000)

The first user registered automatically becomes **admin**. All subsequent registrations require admin privileges.

---

## Running Tests

```powershell
.\.venv\Scripts\activate
pytest -q
```

Tests use `SKIP_DB_INIT=1` environment variable to run without a database.

---

## Smoke Test (No Database)

```powershell
$env:SKIP_DB_INIT = '1'
.\.venv\Scripts\python app.py
```

This starts Flask without database connectivity — useful for checking template rendering.

---

## Database Schema

**`users` table:**
| Column | Type | Notes |
|--------|------|-------|
| id | BIGSERIAL | Primary key (auto-increment) |
| username | VARCHAR(255) | Unique |
| password | TEXT | bcrypt-hashed |
| role | VARCHAR(50) | `'user'` or `'admin'` (default: `'user'`) |

**`logs` table:**
| Column | Type | Notes |
|--------|------|-------|
| id | BIGSERIAL | Primary key |
| user_id | BIGINT | Foreign Key → users(id) |
| action | TEXT | Log entry description |
| total_rows | INTEGER | Total rows processed |
| valid_rows | INTEGER | Rows passing validation |
| invalid_rows | INTEGER | Rows failing validation |
| created_at | TIMESTAMP | Auto-generated (CURRENT_TIMESTAMP) |

---

## Project Structure

```
excel_cleaner_web/
├── app.py                      # Main Flask application (routes, auth, Celery tasks, DB)
├── requirements.txt            # Python dependencies
├── schema.sql                  # PostgreSQL schema (users + logs tables)
├── .env.example                # Environment variable template (NEVER commit .env)
├── .gitignore                  # Git ignore rules
├── .dockerignore               # Docker build ignore rules
├── README.md                   # This file
├── start_excel_cleaner.bat     # Windows startup script
├── presets/                    # User rule presets (per-user JSON files)
│   └── 1.json                  # Example preset for user ID 1
├── templates/                  # Jinja2 HTML templates
│   ├── login.html              # Sign-in page
│   ├── register.html           # Registration page (admin only, except first user)
│   ├── choose_page.html        # Landing page with action cards
│   ├── upload.html             # File upload page
│   ├── choose_rules.html       # Rule selection UI (per-column + global toggles + presets)
│   ├── processing.html         # Progress bar with Celery task polling
│   ├── preview.html            # Results page (Chart.js, stats, download buttons)
│   ├── dashboard.html          # User activity logs dashboard
│   ├── logs.html               # Simple logs view
│   └── admin_logs.html         # Admin logs with search & pagination
├── tests/                      # Unit tests
│   └── test_cleaning_task.py   # Tests core cleaning logic
└── static/                     # Static assets (currently empty - CDN-based)
```

---

## For Contributors / Team Members

### Required tools to install:
1. **Python 3.12+**
2. **Redis** (via Docker or Windows Subsystem for Linux)
3. **PostgreSQL** or a **Neon** account (free at neon.tech)

### After cloning, each teammate must:
1. Create `.venv` and `pip install -r requirements.txt`
2. Copy `.env.example` → `.env` and fill in **their own** credentials
3. Ensure Redis is running (`docker start redis`)
4. Start the stack (Celery Worker + Flask, optionally Celery Beat)
5. First user to register becomes admin

### What NOT to commit (already in `.gitignore`):
- `.env` — contains your database password and secret key
- `uploads/` — user-uploaded files and generated Excel outputs
- `venv/` / `.venv/` — virtual environment (each teammate creates their own)
- `__pycache__/` — compiled Python bytecode
- `*.xlsx` / `*.xls` — generated Excel files
- `celerybeat-schedule*` — Celery schedule database
- `.vscode/` / `.idea/` — IDE settings (personal preference)