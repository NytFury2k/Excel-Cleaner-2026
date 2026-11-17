# 🧹 Excel Cleaner 2026

A multi-user web platform for cleaning messy spreadsheets. Upload a CSV or Excel file, pick cleaning rules per column, and download a cleaned file plus an error report. It has role-based access, audit logging and a REST API.

<!-- TODO: add a screenshot or demo GIF here -->
<!-- ![Demo](docs/demo.gif) -->

**Live demo:** _coming soon_ · **Stack:** Python · Flask · PostgreSQL (Supabase) · pandas · Docker

---

## ✨ Features

### Cleaning engine
- **Automatic column-type detection:** email, phone, URL, numeric, date, text
- **Rule-based pipeline:** trim whitespace, strip special characters, normalize currency, handle missing values
- **Validation:** email format/domain, phone, URL, numeric ranges, dates, required fields; failures are attached as error columns
- **Smart deduplication:** composite-key and fuzzy matching, Gmail alias/dot canonicalization, and *survivorship* merging that keeps the most complete record per duplicate cluster
- **Data health dashboard**, plus a cleaning history with downloadable outputs

### Access control & auditing
- **4-tier RBAC** (admin → manager → team lead → user), enforced server-side on every route
- bcrypt password hashing and session auth, with backend checks that prevent privilege escalation
- **Audit trail** of logins, registrations, admin actions and cleaning runs, with charts, filters and CSV export
- Soft-delete accounts so history is never lost

### REST API
- Token auth (`/auth/token`, `/auth/refresh`, `/auth/revoke`) with API-key requests approved by admins
- Endpoints for upload → list rules → clean → job status → preview → download
- Rate limiting via Flask-Limiter

---

## 🏗️ Architecture

```
Browser / API client
        │
   Flask app (app.py, api_routes.py)
        │── rbac.py ─────────── permission checks
        │── cleaning/ ───────── type resolver → rules → validations → dedup/survivorship → report
        │
   PostgreSQL (Supabase) ── users, roles, logs, jobs, registry
```

```
├── app.py               # Web routes
├── api_routes.py        # REST API blueprint
├── rbac.py              # Role → permission mapping
├── cleaning/            # Modular cleaning engine
├── templates/           # Jinja2 UI
├── tests/               # pytest suite
├── scripts/             # One-off DB maintenance/migration scripts
└── docs/                # Design docs, audit report
```

---

## 🚀 Quick start

```bash
git clone https://github.com/NytFury2k/Excel-Cleaner-2026.git
cd Excel-Cleaner-2026
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env                                  # fill in your values
docker compose up -d                                  # local PostgreSQL
python scripts/fix_db.py                              # create schema
python app.py                                         # http://127.0.0.1:5000
```

Full walkthrough: [SETUP_GUIDE.md](SETUP_GUIDE.md)

## 🧪 Tests

```bash
pytest tests/
```

---

## 🛣️ Roadmap
- Natural-language cleaning rules (LLM → rule pipeline)
- MCP server so AI assistants can call the cleaner as a tool
- Versioned DB migrations (Alembic)

## 👤 Author
**Vaishnav Shetty**, CS (AI & ML) @ PES University
