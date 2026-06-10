# ExcelCleaner

Lightweight data sanitization pipeline: Flask + Celery + Pandas.

Quick setup (Windows)

1. Install docker 
2. Create virtual environment and install dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

3. Ensure MySQL and Redis are running. (Docker easiest):

```powershell
# Redis (first time)
docker run -d --name redis -p 6379:6379 redis:7 
"""you can continue to run redis either directly from docker or use the command 
docker start redis
"""
# MySQL (run in docker)
docker run -d --name mysql -e MYSQL_ROOT_PASSWORD=Paramantra -e MYSQL_DATABASE=excel_cleaner -p 3306:3306 mysql:8
```

4. Apply database schema:

```powershell
mysql -u root -p excel_cleaner < schema.sql
```

5. Start the app using the bundled script or run components manually:

```powershell
# bundled (opens separate terminals)
double-click start_excel_cleaner.bat

# or run manually in separate terminals
.\.venv\Scripts\python -m celery -A app.celery_app worker --loglevel=info -P solo
.\.venv\Scripts\python -m celery -A app.celery_app beat --loglevel=info
.\.venv\Scripts\python app.py
```

Notes
- The repository should not contain a real `.env`; replace with `.env.example` and add `.env` to `.gitignore`.
- For production, run Flask with a WSGI server and secure secrets.

Running tests
----------------
1. Create and activate your virtual environment and install dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

2. Run the unit tests with `pytest`:

```powershell
pytest -q
```

Docker Compose (local dev)
---------------------------
Start Redis and MySQL locally using Docker Compose (helps avoid manual installs):

```powershell
docker-compose up -d
# Wait for DB to initialize, then apply schema:
docker exec -i <db_container_name> sh -c 'exec mysql -u root -p"change_me" excel_cleaner' < schema.sql
```

Notes
- If you use Docker, update `.env` to point at the container addresses or use the provided defaults.
- The `tests` directory contains a basic test for the cleaning task which runs with `SKIP_DB_INIT=1` to avoid requiring a MySQL server.

Run full application with web, Celery worker and beat
----------------------------------------------------
After creating your `.env` (copy `.env.example`) you can build and run the full stack:

```powershell
docker-compose up --build -d

# View logs (web):
docker-compose logs -f web

# Apply DB schema if needed (example):
docker-compose exec db sh -c 'exec mysql -u root -p"change_me" excel_cleaner' < schema.sql
```

Stop and remove containers:

```powershell
docker-compose down
```
