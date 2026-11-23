@echo off
setlocal EnableExtensions
cd /d "%~dp0"

set "PYTHON=%~dp0.venv\Scripts\python.exe"
if "%FW_PORT%"=="" set "FW_PORT=8501"

if not exist "%PYTHON%" (
    echo Creating the Python environment...
    python -m venv .venv
    if errorlevel 1 (
        echo Install Python 3.11 or newer and add it to PATH, then retry.
        goto :failed
    )
    echo Installing dependencies from requirements.txt...
    "%PYTHON%" -m pip install -r requirements.txt
    if errorlevel 1 goto :failed
)

"%PYTHON%" -c "import fastapi, uvicorn, jinja2, multipart, parsers.fortigate, parsers.paloalto, tsf.extractor, server"
if errorlevel 1 (
    echo Startup dependency check failed. See the error above.
    echo To install dependencies, run:
    echo   .venv\Scripts\python.exe -m pip install -r requirements.txt
    goto :failed
)

echo Starting Firewall Config Reader ^(FastAPI^) on http://127.0.0.1:%FW_PORT%/
echo Press Ctrl+C in this window to stop the server.
start "" /b powershell -NoProfile -WindowStyle Hidden -Command "Start-Sleep -Seconds 1; $port = %FW_PORT%; $deadline = (Get-Date).AddSeconds(30); while ((Get-Date) -lt $deadline) { try { $r = Invoke-WebRequest -UseBasicParsing -Uri \"http://127.0.0.1:$port/health\" -TimeoutSec 3; if ($r.StatusCode -eq 200) { Start-Process \"http://127.0.0.1:$port/\"; exit 0 } } catch { Start-Sleep -Milliseconds 300 } }"
"%PYTHON%" -m uvicorn server:app --host 127.0.0.1 --port %FW_PORT%
if errorlevel 1 goto :failed
exit /b 0

:failed
echo Local startup failed.
pause
exit /b 1
