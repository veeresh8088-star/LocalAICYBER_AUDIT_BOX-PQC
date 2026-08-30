@echo off
REM Offline installer -- AICyberAuditBox (Windows).
REM
REM Loads every image from the single images tar beside this script, then starts
REM the stack. Nothing is downloaded: the machine never needs to reach a
REM registry, which is the point of an air-gapped install.
setlocal enabledelayedexpansion
set VERSION=3.22
set IMAGES=aicyberauditbox-images-%VERSION%.tar
set COMPOSE=docker-compose.yml

echo ===========================================================
echo   AICyberAuditBox %VERSION% -- offline install
echo ===========================================================

docker info >nul 2>&1
if errorlevel 1 (
  echo ERROR: Docker is not running. Start Docker Desktop first.
  exit /b 1
)
if not exist "%IMAGES%" (
  echo ERROR: %IMAGES% is not in this folder. Run the installer from the
  echo        folder the bundle extracted into.
  exit /b 1
)

echo.
echo --^> Loading all images from %IMAGES%
echo     ^(~8GB; several minutes, and it prints nothing while it works^)
docker load -i "%IMAGES%"
if errorlevel 1 (
  echo ERROR: docker load failed.
  exit /b 1
)

echo.
echo --^> Verifying every image the stack needs is present
set MISSING=0
for %%I in (
  aicyberauditbox-app:%VERSION%
  aicyberauditbox-llm:%VERSION%
  aicyberauditbox-llm-embed:%VERSION%
  aicyberauditbox-shakthidb:3.10
  redis:7-alpine
) do (
  docker image inspect %%I >nul 2>&1
  if errorlevel 1 (
    echo     MISSING  %%I
    set MISSING=1
  ) else (
    echo     ok   %%I
  )
)
if "%MISSING%"=="1" (
  echo Aborting: the images above did not load.
  exit /b 1
)

echo.
echo --^> Starting the stack
docker compose -f %COMPOSE% up -d
if errorlevel 1 (
  echo Failed to start. Check: docker compose -f %COMPOSE% logs
  exit /b 1
)

echo.
echo --^> Waiting for the application to answer ^(up to 5 minutes^)
for /L %%N in (1,1,100) do (
  curl -s -o nul -w "%%{http_code}" http://localhost:8000/ 2>nul | findstr /C:"200" >nul 2>&1
  if !errorlevel! equ 0 (
    echo.
    echo ===========================================================
    echo   Ready.  Open http://localhost:8000/
    echo ===========================================================
    echo.
    echo Confirm the LLM sized itself correctly for this machine:
    echo   docker compose -f %COMPOSE% logs llm ^| findstr "LLM ENTRYPOINT"
    echo.
    echo The last line must read "= 32768 tokens per request". A lower number
    echo means the machine has less RAM than the LLM expected, and evidence
    echo would be truncated before the model sees it -- see INSTALL_%VERSION%.md.
    exit /b 0
  )
  timeout /t 3 /nobreak >nul
)

echo The app did not answer in time. Check:
echo   docker compose -f %COMPOSE% ps
echo   docker compose -f %COMPOSE% logs app
exit /b 1
