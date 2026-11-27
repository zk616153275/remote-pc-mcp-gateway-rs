@echo off
setlocal
cd /d "%~dp0"
if exist "%~dp0rpc-mcp-gui.exe" (
    start "" "%~dp0rpc-mcp-gui.exe"
) else if exist "%~dp0target\release\rpc-mcp-gui.exe" (
    start "" "%~dp0target\release\rpc-mcp-gui.exe"
) else (
    echo [ERROR] rpc-mcp-gui.exe not found in current folder or target\release.
    echo Please extract the official Release zip or run: cargo build-gui
    pause
)
exit /b 0
