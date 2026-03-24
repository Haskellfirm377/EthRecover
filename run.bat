@echo off
setlocal enabledelayedexpansion

echo =======================================================
echo          EthRecover v2.0 - Easy Runner
echo =======================================================
echo.

:: Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH.
    echo Please install Python 3.8+ from https://www.python.org/downloads/
    pause
    exit /b 1
)

:: Check if virtual environment exists
if not exist ".venv" (
    echo [*] Creating virtual environment...
    python -m venv .venv
    if !errorlevel! neq 0 (
        echo [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
)

:: Activate virtual environment
echo [*] Activating virtual environment...
call .venv\Scripts\activate.bat

:: Install requirements if not installed
echo [*] Checking dependencies...
pip install -r requirements.txt -q
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install dependencies.
    pause
    exit /b 1
)

echo.
echo [*] Starting EthRecover...
echo.

:: Run the main script
python main.py

echo.
echo =======================================================
echo Finished.
pause
