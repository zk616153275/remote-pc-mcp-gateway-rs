# Remote PC MCP Gateway (Rust Core) - Unified Service Launcher
# Launches `rpc-mcp up` so FS, Workbench, Chrome Broker, and SSH/Cloudflare tunnels
# all share the same Rust supervisor (Windows Job Object lifetime + auto-reconnect).
$ErrorActionPreference = 'Stop'
$repoRoot = $PSScriptRoot
$configPath = Join-Path $repoRoot 'config\config.local.json'
if (-not (Test-Path $configPath)) {
    throw "Config file not found at $configPath"
}
$cfg = Get-Content -Raw $configPath | ConvertFrom-Json
$stateDir = Join-Path $repoRoot 'state'
$logsDir = Join-Path $stateDir 'logs'
New-Item -ItemType Directory -Force -Path $logsDir | Out-Null

$exe = Join-Path $repoRoot 'target\release\rpc-mcp.exe'
if (-not (Test-Path $exe)) {
    throw "Binary not found at $exe. Please run cargo build --release first."
}

# 1. Stop any already running instance cleanly
. (Join-Path $repoRoot 'Stop-Agent.ps1')

Write-Host "Starting Rust rpc-mcp unified stack (up)..." -ForegroundColor Cyan

# 2. Launch `rpc-mcp up` detached (owns SSH/Cloudflare tunnel under Windows Job Object + auto-reconnect)
$upArgs = "up --config `"$configPath`" --state-dir `"$stateDir`""
if ($cfg.connectionMode -eq 'cloudflare-quick' -or $cfg.connectionMode -eq 'cloudflare-named' -or $cfg.connectionMode -eq 'cloudflare') {
    $cfCmd = Get-Command cloudflared -ErrorAction SilentlyContinue
    $cfPath = if ($cfCmd) { $cfCmd.Source } else {
        @('C:\Program Files (x86)\cloudflared\cloudflared.exe', 'C:\Program Files\cloudflared\cloudflared.exe') |
            Where-Object { Test-Path $_ } | Select-Object -First 1
    }
    if ($cfPath) {
        $upArgs += " --cloudflared `"$cfPath`""
    }
}
$psiUp = [System.Diagnostics.ProcessStartInfo]::new()
$psiUp.FileName = $exe
$psiUp.Arguments = $upArgs
$psiUp.UseShellExecute = $true
$psiUp.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
$psiUp.WorkingDirectory = $repoRoot
$upProc = [System.Diagnostics.Process]::Start($psiUp)

Start-Sleep -Seconds 2

# 3. Verify local health
$fsPort = if ($cfg.localPorts.fsBearer) { [int]$cfg.localPorts.fsBearer } else { 18849 }
$wbPort = if ($cfg.localPorts.workbench) { [int]$cfg.localPorts.workbench } else { 18623 }

if ($upProc.HasExited) {
    throw "rpc-mcp up exited prematurely with code $($upProc.ExitCode)"
}

try {
    $fsH = Invoke-RestMethod -Uri "http://127.0.0.1:$fsPort/healthz" -TimeoutSec 3
    $wbH = Invoke-RestMethod -Uri "http://127.0.0.1:$wbPort/healthz" -TimeoutSec 3
    Write-Host "Local Stack Ready (PID: $($upProc.Id)): FS=:$fsPort (ok=$($fsH.ok)), Workbench=:$wbPort (ok=$($wbH.ok))" -ForegroundColor Green
} catch {
    Write-Host "Warning: Failed to ping local agent healthz yet: $_" -ForegroundColor Yellow
}

if ($cfg.connectionMode -eq 'vps-ssh' -or $cfg.connectionMode -eq 'vps') {
    $sshUser = if ($cfg.vps.user) { [string]$cfg.vps.user } else { 'root' }
    $sshPort = if ($cfg.vps.sshPort) { [int]$cfg.vps.sshPort } else { 22 }
    Write-Host "VPS SSH reverse tunnel is supervised by rpc-mcp up -> $sshUser@$($cfg.vps.host):$sshPort (Job Object + auto-reconnect)" -ForegroundColor Green
}

Write-Host "Remote PC MCP Gateway (Rust) is now RUNNING!" -ForegroundColor Green
