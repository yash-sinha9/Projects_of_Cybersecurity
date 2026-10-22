@echo off
title CyberGuard SIEM Dashboard Setup
echo ========================================================
echo        CyberGuard SOC SIEM Dashboard Setup
echo ========================================================
echo.
echo [1/3] Checking Python installation...
python --version
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH. Please install Python 3.
    pause
    exit /b 1
)

echo.
echo [2/3] Installing dependencies (Flask)...
python -m pip install -r requirements.txt

echo.
echo [3/3] Starting SIEM Application Server...
echo SIEM Dashboard will be available at: http://127.0.0.1:5000
start http://127.0.0.1:5000
python app.py
pause
