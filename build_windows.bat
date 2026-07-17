@echo off
REM DocScrub Windows build — run this ON the Windows machine (double-click works).
REM Requires: Python 3.11+ from python.org (check "Add python.exe to PATH").
REM Optional: Inno Setup 6 (jrsoftware.org) to produce a real Setup.exe.
setlocal
cd /d "%~dp0"

echo ==^> Checking Python
py -3 --version || (echo Python 3 not found - install from python.org & pause & exit /b 1)

echo ==^> Creating build venv
if not exist .buildvenv py -3 -m venv .buildvenv || (pause & exit /b 1)
call .buildvenv\Scripts\activate.bat

echo ==^> Installing dependencies
pip install -q --upgrade pip
pip install -q presidio-analyzer presidio-anonymizer python-docx pypdf flask openpyxl olefile pywebview pyinstaller

echo ==^> Installing spaCy NER model (bundled into the app)
python -m spacy download en_core_web_sm

echo ==^> Building the app
pyinstaller docscrub.spec --noconfirm || (pause & exit /b 1)

for /f %%v in ('python -c "from docscrub import __version__; print(__version__)"') do set VERSION=%%v
echo ==^> Built DocScrub %VERSION%

echo ==^> Looking for Inno Setup (for the installer)
set "ISCC="
if exist "%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe" set "ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
if exist "%ProgramFiles%\Inno Setup 6\ISCC.exe" set "ISCC=%ProgramFiles%\Inno Setup 6\ISCC.exe"
where iscc >nul 2>&1 && set "ISCC=iscc"

if defined ISCC (
  echo ==^> Compiling installer
  "%ISCC%" /DMyAppVersion=%VERSION% docscrub.iss || (pause & exit /b 1)
  echo.
  echo Done! Installer: installer\DocScrub-Setup-%VERSION%.exe
  echo Run it to install with Start Menu shortcut and uninstaller.
) else (
  echo.
  echo Inno Setup not found - skipping installer.
  echo   App still built: dist\DocScrub\DocScrub.exe  ^(double-click to run^)
  echo   For a proper Setup.exe: install Inno Setup 6 from jrsoftware.org
  echo   then re-run this script.
)

echo.
echo Note: unsigned build - SmartScreen may warn on the Setup.exe.
echo Click "More info" then "Run anyway". Code signing is on the roadmap.
pause
