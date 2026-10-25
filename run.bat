@echo off
setlocal enabledelayedexpansion

echo ===============================================================================
echo  QUANTUM-SHIELD // CYBER THREAT DETECTION FOR DIGITAL SIGNATURE SECURITY
echo ===============================================================================
echo.

:: Detect Python executable
set "PYTHON_EXE="
where python >nul 2>nul
if %errorlevel% equ 0 (
    set "PYTHON_EXE=python"
) else (
    where py >nul 2>nul
    if %errorlevel% equ 0 (
        set "PYTHON_EXE=py"
    ) else (
        if exist "%LOCALAPPDATA%\Programs\Python\Python313\python.exe" (
            set "PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
        ) else if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" (
            set "PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
        ) else if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" (
            set "PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
        )
    )
)

if "%PYTHON_EXE%"=="" (
    echo [ERROR] Python 3.11+ was not found on PATH or standard install paths.
    echo Please install Python 3.11+ from https://python.org and add it to PATH.
    pause
    exit /b 1
)

echo [INFO] Using Python: %PYTHON_EXE%

:: Initialize database & seed demo telemetry
echo [INFO] Verifying database schema and seeding demo account...
"%PYTHON_EXE%" seed.py
if %errorlevel% neq 0 (
    echo [WARNING] Database seed encountered an issue. Proceeding...
)

:: Start the application
echo.
echo ===============================================================================
echo  Starting local security web server on http://127.0.0.1:5000
echo  Default Demo Credentials: demo_analyst / CyberSec#2026!
echo  Press CTRL+C to terminate
echo ===============================================================================
echo.

"%PYTHON_EXE%" run.py

pause
