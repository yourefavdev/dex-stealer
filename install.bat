@echo off
:: Batch script to install all dependencies for the project

echo Installing required dependencies...

:: Check if Python is installed
python --version >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo Python is not installed. Please install Python 3.7 or higher and try again.
    exit /b
)

:: Upgrade pip
echo Upgrading pip...
python -m pip install --upgrade pip

:: Install required libraries
echo Installing pycryptodome...
pip install pycryptodome

echo Installing psutil...
pip install psutil

echo Installing requests...
pip install requests

echo Installing pywin32...
pip install pywin32

echo All dependencies have been successfully installed.

pause
