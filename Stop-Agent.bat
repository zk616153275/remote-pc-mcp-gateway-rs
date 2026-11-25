@echo off
setlocal
cd /d "%~dp0"
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Stop-Agent.ps1"
if %ERRORLEVEL% NEQ 0 (
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Stop-Agent.ps1"
)
exit /b 0
