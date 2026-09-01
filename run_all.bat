@echo off
cd /d "%~dp0"
set "PYTHONPATH=%~dp0;%PYTHONPATH%"
title AISecurityAudit - Start All Local Services
echo ==================================================
echo   AISecurityAudit: Unified Single-Click Launcher
echo ==================================================

echo.
echo [1/6] Installing/updating Python dependencies...
python -m pip install -r requirements.txt --disable-pip-version-check -q
if errorlevel 1 (
    echo [!] Dependency install failed or skipped ^(no internet / offline run^) -- continuing with existing packages.
) else (
    echo [v] Python dependencies up to date.
)

echo.
echo [2/6] Stopping any existing backend server instances (excluding Docker)...
taskkill /F /IM python.exe /T >nul 2>&1
taskkill /F /IM uvicorn.exe /T >nul 2>&1
taskkill /F /IM llama-server* /T >nul 2>&1
taskkill /F /IM ollama* /T >nul 2>&1
powershell -NoProfile -Command "Get-NetTCPConnection -LocalPort 8000,11434,11435,443 -State Listen -ErrorAction SilentlyContinue | ForEach-Object { $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; if ($p -and $p.ProcessName -notlike '*docker*') { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } }" >nul 2>&1

:: Verify port 8000 is actually free before continuing. A crash on the PREVIOUS
:: run can leave the OS socket held a moment longer than the kill above accounts
:: for, so the next launch fails to bind: [Errno 10048] only one usage of each
:: socket address is normally permitted. Retry with a short wait instead of
:: assuming one taskkill pass was enough.
set PORT8000_RETRY=0
:CHECK_PORT_8000
set PORT8000_STATE=FREE
for /f %%s in ('powershell -NoProfile -Command "if (Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue) { 'BUSY' } else { 'FREE' }"') do set PORT8000_STATE=%%s
if "%PORT8000_STATE%"=="BUSY" (
    set /a PORT8000_RETRY+=1
    if %PORT8000_RETRY% GEQ 5 (
        echo [!] Port 8000 still in use after 5 cleanup attempts -- continuing anyway, launch may fail.
        goto PORT8000_DONE
    )
    echo [i] Port 8000 still busy, retrying cleanup ^(attempt %PORT8000_RETRY%/5^)...
    powershell -NoProfile -Command "Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }" >nul 2>&1
    timeout /t 1 >nul
    goto CHECK_PORT_8000
)
:PORT8000_DONE
echo [v] Ports 8000, 11434 ^& 11435 cleared safely without stopping Docker.


:: Ensure SSL Certificate Exists
if not exist cert.pem (
    echo [SSL] Generating local SSL Certificate...
    python generate_self_ssl.py
)

:: Locate llama-server.exe — MUST be in a folder with ALL companion DLLs:
::   llama-server-impl.dll, llama.dll, llama-common.dll, llama-completion-impl.dll, etc.
::   Pointing to a lone .exe without its DLLs causes "llama-server-impl.dll was not found".
::
:: CRITICAL: LLAMA_DIR must be set to the folder containing llama-server.exe AND its DLLs.
::   The start /d flag sets the working directory for that exact folder, so Windows can
::   find all side-by-side DLLs. Using a different /d (e.g. the project root) causes the
::   DLL-not-found crash even if the EXE path itself is correct.
set "LLAMA_SERVER_EXE="
set "LLAMA_DIR="
if exist "C:\Users\veeresh988V\Desktop\all tesing audit box\audit_loacl_shakthi_!\llama-server.exe" (
    set "LLAMA_DIR=C:\Users\veeresh988V\Desktop\all tesing audit box\audit_loacl_shakthi_!"
    set "LLAMA_SERVER_EXE=C:\Users\veeresh988V\Desktop\all tesing audit box\audit_loacl_shakthi_!\llama-server.exe"
) else if exist "C:\Users\veeresh988V\Desktop\all tesing audit box\current vaptiso\llama-server.exe" (
    set "LLAMA_DIR=C:\Users\veeresh988V\Desktop\all tesing audit box\current vaptiso"
    set "LLAMA_SERVER_EXE=C:\Users\veeresh988V\Desktop\all tesing audit box\current vaptiso\llama-server.exe"
) else if exist "C:\Users\veeresh988V\Desktop\llama\llama-server.exe" (
    set "LLAMA_DIR=C:\Users\veeresh988V\Desktop\llama"
    set "LLAMA_SERVER_EXE=C:\Users\veeresh988V\Desktop\llama\llama-server.exe"
) else if exist "C:\Users\HP\Downloads\llama,,ccppp mode\llama-server.exe" (
    set "LLAMA_DIR=C:\Users\HP\Downloads\llama,,ccppp mode"
    set "LLAMA_SERVER_EXE=C:\Users\HP\Downloads\llama,,ccppp mode\llama-server.exe"
) else (
    set "LLAMA_DIR=%~dp0"
    set "LLAMA_SERVER_EXE=%~dp0llama-server.exe"
)
echo [i] Using llama binary folder : %LLAMA_DIR%
echo [i] Using llama-server.exe    : %LLAMA_SERVER_EXE%


:: Calculate Physical Cores using WMI/CIM (or fallback to logical/2) for accurate thread/slot distribution
set "PHYSICAL_CORES="
for /f "tokens=*" %%c in ('powershell -NoProfile -Command "(Get-CimInstance Win32_Processor).NumberOfCores" 2^>nul') do set PHYSICAL_CORES=%%c
if "%PHYSICAL_CORES%"=="" set /a PHYSICAL_CORES=%NUMBER_OF_PROCESSORS% / 2
if %PHYSICAL_CORES% LSS 1 set PHYSICAL_CORES=4

set /a LLM_THREADS=%NUMBER_OF_PROCESSORS%
if %LLM_THREADS% LSS 1 set LLM_THREADS=4

set /a EMBED_THREADS=%NUMBER_OF_PROCESSORS%
if %EMBED_THREADS% LSS 1 set EMBED_THREADS=4

:: Calculate parallel LLM slots and the total context pool.
::
:: -c is now DERIVED (slots x MIN_CTX_PER_REQUEST) instead of being pinned at
:: 131072. With a fixed -c, llama.cpp gives each of the -np slots only
:: (-c / -np) tokens, so per-request context SHRANK as the machine got bigger:
:: 32,768 on a 4-core box, 8,192 on 16 cores, and 2,048 on a 64-core server --
:: far below the ~29,000 tokens a 30-chunk retrieval needs, which would have
:: silently starved the model of evidence on exactly the hardware being quoted
:: to customers. Deriving -c keeps every request at MIN_CTX_PER_REQUEST no
:: matter how many cores are present.
::
:: Slots are capped by RAM as well as cores, using the same arithmetic as
:: docker/llm-entrypoint.sh (keep the two in sync): each slot costs
:: (ctx/1024) x 0.12 x 0.5 GB with 8-bit KV, on top of ~4.5GB of model and OS.
if "%MIN_CTX_PER_REQUEST%"=="" set MIN_CTX_PER_REQUEST=32768

for /f "usebackq delims=" %%R in (`powershell -NoProfile -Command ^
  "$gb=[math]::Round((Get-CIMInstance Win32_ComputerSystem).TotalPhysicalMemory/1GB,2);" ^
  "$perSlot=(%MIN_CTX_PER_REQUEST%/1024)*0.12*0.5;" ^
  "$usable=($gb*0.85)-4.5;" ^
  "$s=[math]::Floor($usable/$perSlot); if($s -lt 1){$s=1};" ^
  "Write-Output $s"`) do set RAM_SLOTS=%%R
if "%RAM_SLOTS%"=="" set RAM_SLOTS=2

if "%LLM_SLOTS%"=="" set LLM_SLOTS=%PHYSICAL_CORES%
if "%LLM_SLOTS%"=="" set LLM_SLOTS=4
if %RAM_SLOTS% LSS %LLM_SLOTS% set LLM_SLOTS=%RAM_SLOTS%
if %LLM_SLOTS% LSS 1 set LLM_SLOTS=1

set /a LLM_TOTAL_CTX=%LLM_SLOTS% * %MIN_CTX_PER_REQUEST%

:: --kv-unified makes -c one shared buffer instead of -np fixed partitions, so an
:: idle slot's tokens are reusable by a busy one. This is the "fluid shared pool"
:: this launcher has always claimed in its banner but never actually enabled.
:: Because llama-server then reports the WHOLE pool as each slot's n_ctx,
:: LLM_NUM_CTX is pinned below so the app budgets prompts against the real
:: per-request share rather than the full pool.
set LLM_NUM_CTX=%MIN_CTX_PER_REQUEST%




set "MODEL_FILE=%~dp0gemma-4-12B-it-Q8_0.gguf"
if not exist "%MODEL_FILE%" set "MODEL_FILE=%~dp0gemma-4-12b-it-Q8_0.gguf"
if not exist "%MODEL_FILE%" set "MODEL_FILE=%~dp0gemma-2-9b-it-Q8_0.gguf"
if not exist "%MODEL_FILE%" set "MODEL_FILE=%~dp0google_gemma-4-E4B-it-Q4_K_M.gguf"

echo.
echo [3/6] Starting llama.cpp LLM Server (%PHYSICAL_CORES% Physical Cores -> %LLM_SLOTS% Slots x %MIN_CTX_PER_REQUEST% tokens = %LLM_TOTAL_CTX% Fluid Shared Pool / 8-bit KV Cache)...
start "Llama LLM Server" /d "%LLAMA_DIR%" /min "%LLAMA_SERVER_EXE%" --port 11434 -m "%MODEL_FILE%" -c %LLM_TOTAL_CTX% -np %LLM_SLOTS% -t %LLM_THREADS% -b 2048 -ub 512 --flash-attn on --cont-batching --kv-unified -ctk q8_0 -ctv q8_0

echo.
echo [4/6] Starting llama.cpp Embedding Server (Port 11435 with %EMBED_THREADS% threads)...
start "Llama Embedding Server" /d "%LLAMA_DIR%" /min "%LLAMA_SERVER_EXE%" --port 11435 -m "%~dp0nomic-embed-text-v1.5.f16.gguf" -t %EMBED_THREADS% --embedding

echo.
echo [5/6] Starting Database ^& Live Telemetry (SQLite / PostgreSQL ^& Redis Port 6380)...
if exist "%~dp0tools\redis\redis-server.exe" (
    start "Windows Redis Server" /d "%~dp0tools\redis" /min "%~dp0tools\redis\redis-server.exe" --port 6380
)
docker ps > nul 2>&1
if %errorlevel% equ 0 (
    echo [v] Docker detected. Starting ShaktiDB PostgreSQL container (port 15234 only -- port 8000 stays for native uvicorn^)...
    docker start shakthidb_service > nul 2>&1
    if errorlevel 1 (
        docker stop shakthidb_service > nul 2>&1
        docker rm   shakthidb_service > nul 2>&1
        docker run -d --name shakthidb_service -e POSTGRES_PASSWORD=ShakthiDB@2026 -e POSTGRES_DB=shakthidb -p 15234:5432 -v audittest_box_pgdata:/var/lib/postgresql/data --restart always aicyberauditbox-shakthidb:2.1 > nul 2>&1
    )
    call :DoBackup
) else (
    echo [i] Docker is offline/not running. Continuing with local SQLite fallback database.
)


echo.
echo Waiting 12 seconds for models to load in RAM...
timeout /t 12 >nul

set LLM_BACKEND=llama.cpp
set EMBEDDING_HOST=http://127.0.0.1:11435
set OLLAMA_KEEP_ALIVE=24h
set OLLAMA_NUM_PARALLEL=4
set OLLAMA_MAX_LOADED_MODELS=3
:: 2x LLM_SLOTS: LLM_SLOTS truly-parallel + the same again as a queue buffer,
:: rejected clearly past that instead of queuing indefinitely at the LLM server.
set /a MAX_CONCURRENT_AUDITS=%LLM_SLOTS%*2
set REDIS_URL=redis://127.0.0.1:6380/0
:: Resource guard thresholds: lowered so audits aren't paused or blocked prematurely on tight host RAM.
:: 2% free / 0.5GB absolute floor prevents OOM while avoiding false alarms on 16GB machines.
set RESOURCE_GUARD_CRITICAL_PERCENT=2
set RESOURCE_GUARD_CRITICAL_FLOOR_GB=0.5
set RESOURCE_GUARD_WARN_PERCENT=5
:: JWT_SECRET intentionally not set here -- that hardcoded value was a real,
:: exploitable credential (forge any session, including admin) once committed
:: to source control. src/api/endpoints/auth.py generates and persists a
:: random secret to data/.jwt_secret on first run if JWT_SECRET isn't set;
:: set it explicitly here only for a production/multi-instance deployment.

if not exist "%~dp0logs" mkdir "%~dp0logs"
for /f "tokens=*" %%t in ('powershell -NoProfile -Command "Get-Date -Format yyyyMMdd_HHmmss"') do set RUN_TIMESTAMP=%%t
set RUN_LOG=%~dp0logs\run_all_%RUN_TIMESTAMP%.log

echo.
echo [6/6] Launching AISecurityAudit Web Dashboard...
echo ==================================================
echo   AICyberAuditBox Local Web Dashboard Active
echo   Local URL: http://localhost:8000/
echo   Press Ctrl+C in this terminal to stop server.
echo   Full output also saved to: %RUN_LOG%
echo ==================================================

:: Safety net: stop any Docker container that is still occupying port 8000.
:: This covers the case where shakthidb_service was already running with the
:: old port mapping (before this script restarted it with the override), or
:: the aicyberauditbox_app container is running and inheriting that binding.
:: We stop those specific containers rather than killing Docker wholesale.
docker ps --format "{{.Names}} {{.Ports}}" 2>nul | findstr /C:"->8000" >nul 2>&1
if %errorlevel% equ 0 (
    echo [i] Found Docker container^(s^) still bound to port 8000 -- stopping them so native uvicorn can bind...
    for /f "tokens=1" %%c in ('docker ps --format "{{.Names}} {{.Ports}}" 2^>nul ^| findstr /C:"->8000"') do (
        echo     Stopping container: %%c
        docker stop %%c > nul 2>&1
    )
    echo [v] Port 8000 freed from Docker.
    timeout /t 2 >nul
)

start http://localhost:8000/
:: PYTHONUNBUFFERED so output stays real-time in the console even though it's
:: piped through Tee-Object below -- Python defaults to block-buffered stdout
:: when it isn't a real terminal, which would otherwise delay/batch log lines.
:: Tee-Object mirrors everything to the log file so a crash that closes this
:: window (or a native crash with no Python traceback) still leaves a full
:: record to read afterward, instead of vanishing with the window.
set PYTHONUNBUFFERED=1
python -u -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000 2>&1 | powershell -NoProfile -Command "$input | Tee-Object -FilePath '%RUN_LOG%'"
echo.
echo [i] Server process stopped. Press any key to close this window...
pause
exit /b

:: ── AUTO-BACKUP: snapshot shakthidb_master BEFORE anything else touches it ──
:: This exists because the live database was found completely empty on 2026-08-15
:: with no working backup to recover from -- every user account and every audit
:: report/finding was unrecoverably gone. Runs once per launch, right after Docker
:: starts and before the app (and its schema-reconciliation step) ever connects,
:: so there's always a same-day recovery point regardless of what happens after.
::
:: Written as a `call`-able subroutine, not inlined at its call site, because
:: goto/labels used directly inside a parenthesized if-block (...) reliably
:: break cmd.exe's parser ("X was unexpected at this time") -- confirmed
:: reproducible, and almost certainly what caused an earlier unrelated
:: "'tive' is not recognized" launch failure. `call` is immune to that; it
:: works correctly from anywhere, including inside a parenthesized block.
:DoBackup
if not exist "%~dp0backups" mkdir "%~dp0backups"
set PG_READY_RETRY=0
:WAIT_PG_READY
docker exec shakthidb_service pg_isready -p 15234 -U postgres >nul 2>&1
if errorlevel 1 (
    set /a PG_READY_RETRY+=1
    if %PG_READY_RETRY% GEQ 15 (
        echo [!] PostgreSQL not ready after 15s -- skipping today's backup, continuing startup.
        exit /b
    )
    timeout /t 1 >nul
    goto WAIT_PG_READY
)
for /f "tokens=*" %%t in ('powershell -NoProfile -Command "Get-Date -Format yyyyMMdd_HHmmss"') do set BACKUP_TIMESTAMP=%%t
set BACKUP_FILE=%~dp0backups\shakthidb_master_%BACKUP_TIMESTAMP%.sql
docker exec shakthidb_service pg_dump -p 15234 -U postgres shakthidb_master > "%BACKUP_FILE%" 2>nul
if errorlevel 1 (
    echo [!] Backup attempt failed -- continuing startup anyway ^(app availability isn't gated on this^).
    del "%BACKUP_FILE%" >nul 2>&1
) else (
    echo [v] Database backed up to: %BACKUP_FILE%
    :: Keep only the 20 most recent backups so this doesn't grow unbounded.
    powershell -NoProfile -Command "Get-ChildItem '%~dp0backups\shakthidb_master_*.sql' | Sort-Object LastWriteTime -Descending | Select-Object -Skip 20 | Remove-Item -Force" >nul 2>&1
)
exit /b

