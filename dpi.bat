@echo off
setlocal
:: DPI Launcher for Windows Command Prompt
set "SCRIPT_DIR=%~dp0"
set "ENGINE=%SCRIPT_DIR%dpi_engine.py"

:: Check if Python is installed
where python >nul 2>nul
if %ERRORLEVEL% equ 0 (
    python "%ENGINE%" %*
    exit /b %ERRORLEVEL%
)

where py >nul 2>nul
if %ERRORLEVEL% equ 0 (
    py -3 "%ENGINE%" %*
    exit /b %ERRORLEVEL%
)

echo [ERROR] Python was not found in your PATH.
echo Please install Python 3 from https://www.python.org/ or the Microsoft Store.
exit /b 1
