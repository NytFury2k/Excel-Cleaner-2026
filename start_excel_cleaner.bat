@echo off
title ExcelCleaner Startup Manager
:: This line ensures the script runs in the exact folder where you saved it
cd /d "%~dp0"

echo ===================================================
echo   Starting the ExcelCleaner Application Suite...
echo ===================================================
echo.

:: 1. Auto-Detect the Virtual Environment Python Executable
set PYTHON_EXE=
if exist "venv\Scripts\python.exe" set PYTHON_EXE=venv\Scripts\python.exe
if exist ".venv\Scripts\python.exe" set PYTHON_EXE=.venv\Scripts\python.exe
if exist "env\Scripts\python.exe" set PYTHON_EXE=env\Scripts\python.exe

:: Safety check
if "%PYTHON_EXE%"=="" (
    echo [ERROR] Could not find your virtual environment!
    echo Are you sure your environment is named "venv", ".venv", or "env"?
    echo Please run this script from inside the excel_cleaner_web folder.
    pause
    exit /b
)

echo [SUCCESS] Using Python from: %PYTHON_EXE%
echo Redis is already running as a Windows service.
echo.

echo [1/3] Initializing Celery Worker...
start "Celery Worker" cmd /k "set PYTHONPATH=. && %PYTHON_EXE% -m celery -A app.celery_app worker --loglevel=info -P solo"
timeout /t 2 /nobreak > NUL

echo [2/3] Initializing Celery Beat...
start "Celery Beat" cmd /k "set PYTHONPATH=. && %PYTHON_EXE% -m celery -A app.celery_app beat --loglevel=info"
timeout /t 2 /nobreak > NUL

echo [3/3] Starting Flask Web Server...
start "Flask Web App" cmd /k "%PYTHON_EXE% app.py"

echo.
echo ===================================================
echo All systems initialized! 
echo Dashboard available at: http://127.0.0.1:5000
echo ===================================================
pause