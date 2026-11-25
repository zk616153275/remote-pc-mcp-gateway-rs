@echo off
setlocal
cd /d "%~dp0"
if exist "%~dp0target\release\rpc-mcp-gui.exe" (
    start "" "%~dp0target\release\rpc-mcp-gui.exe"
) else (
    echo [ERROR] rpc-mcp-gui.exe not found in target\release. Please run: cargo build --release -p rpc-mcp-gui
    pause
)
exit /b 0
