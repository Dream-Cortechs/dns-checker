@echo off
echo =============================================
echo  DNS CHECKER — Build Windows .exe
echo  Cortechs (c) 2026
echo =============================================
echo.

REM === Prérequis ===
echo [1/4] Installation des dependances...
pip install --quiet dnspython pyinstaller

REM === Build ===
echo [2/4] Build PyInstaller...
pyinstaller --clean --onefile --noconsole --name "DNS-Checker" ^
  --add-data "static;static" ^
  dns_checker.py

echo [3/4] Copie du .exe...
if exist "dist\DNS-Checker.exe" (
    copy /Y "dist\DNS-Checker.exe" "DNS-Checker.exe"
    echo [OK] DNS-Checker.exe cree !
) else (
    echo [ERREUR] Le build a echoue.
    pause
    exit /b 1
)

echo [4/4] Nettoyage...
rmdir /S /Q build 2>nul
rmdir /S /Q dist 2>nul
del /Q DNS-Checker.spec 2>nul

echo.
echo =============================================
echo  BUILD TERMINE !
echo  Executable : DNS-Checker.exe
echo =============================================
pause
