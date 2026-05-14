@echo off
setlocal EnableExtensions

REM Storage Analyzer source runner for Windows.
REM This script self-elevates to Administrator, creates a local .venv,
REM installs the required Python packages, and starts the application.
REM It does not build an EXE and does not modify user data.

cd /d "%~dp0"

title Storage Analyzer - Setup and Run

echo ================================================
echo Storage Analyzer - Setup and Run
echo ================================================
echo.

REM Check for Administrator privileges.
fltmc >nul 2>&1
if not "%ERRORLEVEL%"=="0" (
    echo Administrator privileges are required.
    echo Requesting elevation through UAC...
    echo.
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs -WorkingDirectory '%~dp0'"
    exit /b
)

echo Running as Administrator: OK
echo.

REM Detect Python launcher or python.exe.
set "PYTHON_CMD="
where py >nul 2>&1
if "%ERRORLEVEL%"=="0" (
    set "PYTHON_CMD=py -3"
) else (
    where python >nul 2>&1
    if "%ERRORLEVEL%"=="0" (
        set "PYTHON_CMD=python"
    )
)

if not defined PYTHON_CMD (
    echo ERROR: Python was not found.
    echo Install Python 3.10 or newer, then run this script again.
    echo Make sure Python is added to PATH during installation.
    echo.
    pause
    exit /b 1
)

echo Python command: %PYTHON_CMD%
%PYTHON_CMD% --version
if not "%ERRORLEVEL%"=="0" (
    echo ERROR: Python exists but could not run correctly.
    echo.
    pause
    exit /b 1
)

echo.

REM Create local virtual environment if missing.
if not exist ".venv\Scripts\python.exe" (
    echo Creating local virtual environment: .venv
    %PYTHON_CMD% -m venv .venv
    if not "%ERRORLEVEL%"=="0" (
        echo ERROR: Could not create Python virtual environment.
        echo.
        pause
        exit /b 1
    )
) else (
    echo Local virtual environment already exists: .venv
)

echo.

echo Upgrading pip/setuptools/wheel...
".venv\Scripts\python.exe" -m pip install --upgrade pip setuptools wheel
if not "%ERRORLEVEL%"=="0" (
    echo ERROR: pip upgrade failed.
    echo.
    pause
    exit /b 1
)

echo.

echo Installing application requirements...
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if not "%ERRORLEVEL%"=="0" (
    echo ERROR: Dependency installation failed.
    echo.
    pause
    exit /b 1
)

echo.
echo Starting Storage Analyzer...
echo.
".venv\Scripts\python.exe" storage_analyzer.py
set "APP_EXIT=%ERRORLEVEL%"

if not "%APP_EXIT%"=="0" (
    echo.
    echo Storage Analyzer exited with error code %APP_EXIT%.
    echo.
    pause
    exit /b %APP_EXIT%
)

endlocal
exit /b 0
