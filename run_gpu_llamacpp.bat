@echo off
title AICyberAuditBox GPU Dedicated Launcher
echo ==================================================
echo   Starting AICyberAuditBox (100%% GPU Accelerated)
echo ==================================================

echo.
echo [1/5] Stopping any existing Ollama or llama-server processes...
taskkill /F /IM ollama* /T >nul 2>&1
taskkill /F /IM llama-server* /T >nul 2>&1
powershell -NoProfile -Command "Get-NetTCPConnection -LocalPort 11434,11435,11436 -State Listen -ErrorAction SilentlyContinue | ForEach-Object { $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; if ($p -and $p.ProcessName -notlike '*docker*') { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } }" >nul 2>&1
echo [v] Ports 11434, 11435 and 11436 cleared safely.

echo.
set "LLAMA_SERVER_EXE="
if exist "C:\Users\veeresh988V\Desktop\llama\llama-server.exe" (
    set "LLAMA_SERVER_EXE=C:\Users\veeresh988V\Desktop\llama\llama-server.exe"
) else (
    set "LLAMA_SERVER_EXE=%~dp0llama-server.exe"
)

echo [2/5] Starting LLM Instance 1 on GPU (port 11434, -ngl 99)...
start "Llama LLM Server 1 (GPU)" /d "%~dp0" /min "%LLAMA_SERVER_EXE%" --port 11434 -m "%~dp0google_gemma-4-E4B-it-Q4_K_M.gguf" -c 16384 -ngl 99 -b 2048 -ub 512 --mlock --flash-attn on

echo.
echo [3/5] Starting LLM Instance 2 on GPU (port 11436, -ngl 99)...
start "Llama LLM Server 2 (GPU)" /d "%~dp0" /min "%LLAMA_SERVER_EXE%" --port 11436 -m "%~dp0google_gemma-4-E4B-it-Q4_K_M.gguf" -c 16384 -ngl 99 -b 2048 -ub 512 --mlock --flash-attn on

echo.
echo [4/5] Starting Embedding Server on GPU (port 11435, -ngl 99)...
start "Llama Embedding Server (GPU)" /d "%~dp0" /min "%LLAMA_SERVER_EXE%" --port 11435 -m "%~dp0nomic-embed-text-v1.5.f16.gguf" -ngl 99 --mlock --embedding

echo.
echo Waiting 15 seconds for GPU VRAM allocation ^& initialization...
timeout /t 15 >nul

echo.
echo [5/5] Launching Fast API HTTP Dashboard...
set LLM_BACKEND=llama.cpp
set LLM_HOSTS=11434,11436
set EMBEDDING_HOST=http://127.0.0.1:11435
set CUDA_VISIBLE_DEVICES=0

call run_demo.bat
