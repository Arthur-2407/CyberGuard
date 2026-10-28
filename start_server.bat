@echo off
setlocal

:: Set the project root to the directory containing this script
set "PROJECT_ROOT=%~dp0"
if "%PROJECT_ROOT:~-1%"=="\" set "PROJECT_ROOT=%PROJECT_ROOT:~0,-1%"

:: Define the venv Python executable
set "PYTHON_EXE=%PROJECT_ROOT%\venv\Scripts\python.exe"

if not exist "%PYTHON_EXE%" (
    echo [ERROR] Virtual environment Python not found at: %PYTHON_EXE%
    echo Please ensure the venv is correctly created.
    exit /b 1
)

set PYTHONPATH=
set PYTHONHOME=

set PORT=%1
if "%PORT%"=="" (
    if defined PORT (
        rem use existing PORT env var
    ) else (
        set PORT=3000
    )
)

:: Check if port is in use
netstat -ano | findstr /R /C:":%PORT% .*LISTENING" >nul 2>&1
if not errorlevel 1 (
    echo [WARN] Port %PORT% is currently occupied.
    if "%PORT%"=="3000" (
        set PORT=8000
        echo [INFO] Falling back to port 8000 to prevent collision with Docker.
    )
)

:: Check and start clamd in background if installed and not already running
tasklist /FI "IMAGENAME eq clamd.exe" 2>NUL | find /I /N "clamd.exe">NUL
if errorlevel 1 (
    if exist "C:\Program Files\ClamAV\clamd.exe" (
        if exist "C:\ProgramData\ClamAV\clamd.conf" (
            echo [INFO] Starting ClamAV daemon in background...
            start /B "" "C:\Program Files\ClamAV\clamd.exe" -F -c "C:\ProgramData\ClamAV\clamd.conf" >nul 2>&1
        )
    )
)

echo [INFO] Starting CyberGuard server on port %PORT% using isolated venv Python:
echo %PYTHON_EXE%
echo Frontend URL: http://127.0.0.1:%PORT%
echo.

"%PYTHON_EXE%" -m uvicorn backend.main:app --host 0.0.0.0 --port %PORT% --reload
