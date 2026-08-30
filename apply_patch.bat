@echo off
REM Applies an AICyberAuditBox code patch to an existing install (Windows).
REM
REM Rebuilds the app image on top of the one already installed, so the Python
REM packages and the ~1.6GB of OCR model caches are reused untouched -- nothing
REM is downloaded and the install stays air-gapped. Takes seconds.
setlocal enabledelayedexpansion
set FROM_VERSION=__FROM__
set TO_VERSION=__TO__
set COMPOSE=docker-compose.yml

echo ===========================================================
echo   AICyberAuditBox patch  %FROM_VERSION% -^> %TO_VERSION%
echo ===========================================================

docker info >nul 2>&1
if errorlevel 1 (
  echo ERROR: Docker is not running.
  exit /b 1
)
docker image inspect aicyberauditbox-app:%FROM_VERSION% >nul 2>&1
if errorlevel 1 (
  echo ERROR: aicyberauditbox-app:%FROM_VERSION% is not installed on this machine.
  echo        This patch builds on top of it. Installed app images:
  docker images aicyberauditbox-app --format "         {{.Repository}}:{{.Tag}}"
  exit /b 1
)
if not exist "%COMPOSE%" (
  echo ERROR: %COMPOSE% not found. Run this from your install folder
  echo        ^(the one you extracted the original bundle into^).
  exit /b 1
)

echo.
echo --^> Building aicyberauditbox-app:%TO_VERSION% from %FROM_VERSION%
docker build -f Dockerfile.app.rebase --build-arg APP_BASE_IMAGE=aicyberauditbox-app:%FROM_VERSION% -t aicyberauditbox-app:%TO_VERSION% .
if errorlevel 1 (
  echo ERROR: build failed. Nothing has been changed.
  exit /b 1
)

echo.
echo --^> Pointing %COMPOSE% at the new image
copy /y "%COMPOSE%" "%COMPOSE%.bak" >nul
powershell -NoProfile -Command "(Get-Content '%COMPOSE%') -replace 'aicyberauditbox-app:%FROM_VERSION%','aicyberauditbox-app:%TO_VERSION%' | Set-Content '%COMPOSE%' -Encoding utf8"
findstr /C:"aicyberauditbox-app:%TO_VERSION%" "%COMPOSE%" >nul 2>&1
if errorlevel 1 (
  echo ERROR: could not update the image tag. Restoring %COMPOSE%.
  copy /y "%COMPOSE%.bak" "%COMPOSE%" >nul
  exit /b 1
)
echo     previous file kept as %COMPOSE%.bak

echo.
echo --^> Restarting the application ^(database and LLM keep running^)
docker compose up -d app
if errorlevel 1 (
  echo ERROR: restart failed. Roll back with:
  echo   copy /y "%COMPOSE%.bak" "%COMPOSE%" ^&^& docker compose up -d app
  exit /b 1
)

echo.
echo --^> Waiting for it to answer
for /L %%N in (1,1,60) do (
  REM -f makes curl exit non-zero on any HTTP error, so a zero exit IS the
  REM readiness signal. Piping %%{http_code} into findstr was fragile: it
  REM matched "200" anywhere in the output, and curl's own failures left
  REM partial text behind.
  curl -fs --max-time 5 http://localhost:8000/ >nul 2>&1
  if !errorlevel! equ 0 (
    echo.
    echo ===========================================================
    echo   Patched to %TO_VERSION%.  http://localhost:8000/
    echo ===========================================================
    exit /b 0
  )
  timeout /t 3 /nobreak >nul
)

echo The app did not answer. Roll back with:
echo   copy /y "%COMPOSE%.bak" "%COMPOSE%" ^&^& docker compose up -d app
exit /b 1
