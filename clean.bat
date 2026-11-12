@echo off
color 0B
echo ====================================================
echo Cleaning Python Cache and Build Files...
echo ====================================================

:: 1. Delete __pycache__ folders
echo Removing __pycache__ folders...
for /d /r . %%d in (__pycache__) do @if exist "%%d" (
    rd /s /q "%%d"
)

:: 2. Delete .pyc files
echo Removing .pyc files...
del /s /q *.pyc >nul 2>&1

:: 3. Delete old spec files
echo Removing *.spec files...
del /s /q *.spec >nul 2>&1

:: 4. Delete old build and dist folders (IMPORTANT for a clean build)
echo Removing build and dist folders...
if exist "build" rmdir /s /q "build"
if exist "dist" rmdir /s /q "dist"

echo.
echo ====================================================
echo Building EXE Files...
echo ====================================================

:: Install required libraries (just in case)
pip install pyinstaller openpyxl xlsxwriter PyQt6 jdatetime pytz matplotlib

echo.
echo [1/3] Building Main App (MatrixScore)...
pyinstaller --noconfirm --windowed --icon="assets/icon.ico" ^
 --add-data "assets;assets" ^
 --add-data "ui/style.qss;ui" ^
 --add-data "config.json;." ^
 --hidden-import="xlsxwriter" ^
 --hidden-import="openpyxl" ^
 --hidden-import="jdatetime" ^
 --hidden-import="pytz" ^
 --collect-all xlsxwriter ^
 --collect-all openpyxl ^
 --name="MatrixScore" main.py

echo.
echo [2/3] Building Emergency Backup Tool...
pyinstaller --noconfirm --windowed --icon="assets/icon.ico" ^
 --hidden-import="xlsxwriter" ^
 --collect-all xlsxwriter ^
 --name="Emergency_Backup" Emergency_Backup.py

echo.
echo [3/3] Building Database Reset Tool...
pyinstaller --noconfirm --windowed --icon="assets/icon.ico" ^
 --name="Reset_DB" Reset_DB.py

echo.
echo ====================================================
echo Build Complete! Check the 'dist' folder.
echo ====================================================
pause