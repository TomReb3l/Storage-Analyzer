@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title Storage Analyzer - Setup and Run

echo ================================================
echo Storage Analyzer - Setup and Run
echo ================================================
echo.

fltmc >nul 2>&1
if not "%ERRORLEVEL%"=="0" (
    echo Administrator privileges are required.
    echo Requesting elevation through Windows Shell...
    echo.
    mshta "vbscript:CreateObject(""Shell.Application"").ShellExecute(""%~f0"",""" ,""%~dp0"",""runas"",1)(window.close)"
    exit /b
)

echo Running as Administrator: OK
echo.

set "PYTHON_CMD="
where py >nul 2>&1
if "%ERRORLEVEL%"=="0" set "PYTHON_CMD=py -3"
if not defined PYTHON_CMD (
    where python >nul 2>&1
    if "%ERRORLEVEL%"=="0" set "PYTHON_CMD=python"
)
if not defined PYTHON_CMD (
    echo ERROR: Python 3.10+ was not found.
    pause
    exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
    echo Creating local virtual environment: .venv
    %PYTHON_CMD% -m venv .venv
    if not "%ERRORLEVEL%"=="0" goto :fail
)

echo Installing/updating requirements...
".venv\Scripts\python.exe" -m pip install --upgrade pip setuptools wheel
if not "%ERRORLEVEL%"=="0" goto :fail
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if not "%ERRORLEVEL%"=="0" goto :fail

echo Starting Storage Analyzer...
".venv\Scripts\python.exe" storage_analyzer.py
exit /b %ERRORLEVEL%

:fail
echo.
echo ERROR: Setup/run failed.
pause
exit /b 1
