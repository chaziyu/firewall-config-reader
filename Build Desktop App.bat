@echo off
setlocal EnableExtensions
cd /d "%~dp0"

set "PYTHON=%~dp0.venv\Scripts\python.exe"
if "%APP_VERSION%"=="" set "APP_VERSION=2.3.1"

if not exist "%PYTHON%" (
    echo Creating the Python environment...
    python -m venv .venv
    if errorlevel 1 (
        echo Install Python 3.11 or newer and add it to PATH, then retry.
        goto :failed
    )
)

echo Installing/updating application and desktop packaging dependencies...
"%PYTHON%" -m pip install -r requirements.txt pyinstaller pywebview
if errorlevel 1 goto :failed

set "PYINSTALLER_ARGS=--noconfirm --clean --onedir --windowed --noupx --name FirewallConfigReader --icon "%~dp0scripts\assets\app.ico" --splash "%~dp0scripts\assets\splash.png" --specpath build --add-data "%~dp0assets;assets" --add-data "%~dp0templates;templates" --add-data "%~dp0static;static" --collect-submodules backend --collect-submodules parsers --collect-submodules tsf --collect-submodules uvicorn --hidden-import server --collect-all webview --exclude-module streamlit --exclude-module pandas --exclude-module pydeck --exclude-module altair --exclude-module pytest --exclude-module _pytest --exclude-module pip --exclude-module setuptools --exclude-module wheel --exclude-module webview.platforms.cocoa --exclude-module webview.platforms.gtk --exclude-module webview.platforms.qt --exclude-module webview.platforms.android --exclude-module webview.platforms.cef"

echo.
echo Packaging --onedir desktop bundle ^(version %APP_VERSION%^)...
"%PYTHON%" -m PyInstaller %PYINSTALLER_ARGS% scripts\desktop_launcher.py
if errorlevel 1 goto :failed
echo Bundle build complete: "%~dp0dist\FirewallConfigReader\FirewallConfigReader.exe"

set "ISCC="
for %%P in (
    "%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
    "%ProgramFiles%\Inno Setup 6\ISCC.exe"
    "%LocalAppData%\Programs\Inno Setup 6\ISCC.exe"
) do (
    if exist "%%~P" (
        set "ISCC=%%~P"
        goto :found_iscc
    )
)
for /f "delims=" %%P in ('where ISCC.exe 2^>nul') do (
    set "ISCC=%%~P"
    goto :found_iscc
)

:found_iscc
if "%ISCC%"=="" (
    echo.
    echo Inno Setup 6 ^(ISCC.exe^) was not found.
    echo Install it with: winget install JRSoftware.InnoSetup
    echo The --onedir desktop app is ready at: "%~dp0dist\FirewallConfigReader\FirewallConfigReader.exe"
    goto :failed
)

echo.
echo Building Windows installer...
"%ISCC%" /DAppVersion=%APP_VERSION% "%~dp0scripts\installer\FirewallConfigReader.iss"
if errorlevel 1 goto :failed

echo.
echo Installer build complete: "%~dp0dist\FirewallConfigReader-Setup-%APP_VERSION%.exe"
exit /b 0

:failed
echo.
echo Desktop build failed.
exit /b 1
