# Remote PC MCP Gateway (Rust Core) - Service Launcher
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

# 1. Stop any already running instance
. (Join-Path $repoRoot 'Stop-Agent.ps1')

Write-Host "Starting Rust rpc-mcp agent..." -ForegroundColor Cyan

# 2. Launch rpc-mcp agent detached
$psiAgent = [System.Diagnostics.ProcessStartInfo]::new()
$psiAgent.FileName = $exe
$psiAgent.Arguments = "agent --config `"$configPath`" --workbench-state `"$stateDir\workbench`""
$psiAgent.UseShellExecute = $true
$psiAgent.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
$psiAgent.WorkingDirectory = $repoRoot
$agentProc = [System.Diagnostics.Process]::Start($psiAgent)

Start-Sleep -Seconds 2

# Verify local health
$fsPort = if ($cfg.localPorts.fsBearer) { [int]$cfg.localPorts.fsBearer } else { 18849 }
$wbPort = if ($cfg.localPorts.workbench) { [int]$cfg.localPorts.workbench } else { 18623 }

try {
    $fsH = Invoke-RestMethod -Uri "http://127.0.0.1:$fsPort/healthz" -TimeoutSec 3
    $wbH = Invoke-RestMethod -Uri "http://127.0.0.1:$wbPort/healthz" -TimeoutSec 3
    Write-Host "✅ Local Agent Ready: FS=:$fsPort (ok=$($fsH.ok)), Workbench=:$wbPort (ok=$($wbH.ok))" -ForegroundColor Green
} catch {
    Write-Host "⚠️ Warning: Failed to ping local agent healthz: $_" -ForegroundColor Yellow
}

# 3. If in VPS-SSH mode, launch SSH reverse tunnel
$sshPid = $null
$tunnelDetail = ''
if ($cfg.connectionMode -eq 'vps-ssh' -or $cfg.connectionMode -eq 'vps') {
    $vps = $cfg.vps
    $sshUser = if ($vps.user) { [string]$vps.user } else { 'root' }
    $target = "{0}@{1}" -f $sshUser, $vps.host
    $sshPort = if ($vps.sshPort) { [int]$vps.sshPort } else { 22 }
    $tunnelDetail = "ssh $sshUser@$($vps.host):$sshPort"
    $pem = [string]$vps.sshKeyPath
    $knownHosts = Join-Path (Split-Path -Parent $configPath) 'vps-known-hosts'

    $sshArgs = @(
        '-p', [string]$sshPort,
        '-o', 'BatchMode=yes',
        '-o', 'StrictHostKeyChecking=accept-new',
        '-o', "UserKnownHostsFile=$knownHosts",
        '-o', 'ExitOnForwardFailure=yes',
        '-o', 'ServerAliveInterval=15',
        '-o', 'ServerAliveCountMax=3',
        '-R', ("127.0.0.1:{0}:127.0.0.1:{1}" -f [int]$vps.remoteFsPort, $fsPort),
        '-R', ("127.0.0.1:{0}:127.0.0.1:{1}" -f [int]$vps.remoteWorkbenchPort, $wbPort)
    )
    if (-not [string]::IsNullOrWhiteSpace($pem)) {
        $sshArgs = @('-i', $pem, '-o', 'IdentitiesOnly=yes') + $sshArgs
    }
    if ($cfg.gateway.enableChrome) {
        $chromePort = if ($cfg.localPorts.chromeMcp) { [int]$cfg.localPorts.chromeMcp } else { 18619 }
        $sshArgs += @('-R', ("127.0.0.1:{0}:127.0.0.1:{1}" -f [int]$vps.remoteChromeMcpPort, $chromePort))
    }
    $sshArgs += @('-N', $target)

    Write-Host "Starting SSH Reverse Tunnel to $target..." -ForegroundColor Cyan
    $psiSsh = [System.Diagnostics.ProcessStartInfo]::new()
    $psiSsh.FileName = 'C:\Windows\System32\OpenSSH\ssh.exe'
    $psiSsh.Arguments = ($sshArgs | ForEach-Object { if ($_ -match '\s') { "`"$_`"" } else { $_ } }) -join ' '
    $psiSsh.UseShellExecute = $true
    $psiSsh.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
    $psiSsh.WorkingDirectory = $repoRoot
    $sshProc = [System.Diagnostics.Process]::Start($psiSsh)
    $sshPid = $sshProc.Id

    Start-Sleep -Seconds 2
    if ($sshProc.HasExited) {
        Write-Host "❌ SSH Tunnel exited prematurely!" -ForegroundColor Red
    } else {
        Write-Host "✅ SSH Reverse Tunnel Connected (PID: $sshPid) -> $target" -ForegroundColor Green
    }
}

# 4. Write runtime-status.json
$runtime = @{
    pid = $agentProc.Id
    sandbox = $false
    startedAt = (Get-Date -Format o)
    updatedAt = (Get-Date -Format o)
    mode = $cfg.connectionMode
    phase = 'running'
    publicOrigin = if ($cfg.vps.domain) { "https://$($cfg.vps.domain)" } else { '' }
    mcpUrl = if ($cfg.vps.domain) { "https://$($cfg.vps.domain)/$($cfg.gateway.secret)/mcp" } else { '' }
    approvalKey = $cfg.gateway.approvalKey
    deleteGuardEnabled = [bool]$cfg.guardsAndHooks.enableDeleteGuard
    trayNotificationsEnabled = [bool]$cfg.guardsAndHooks.enableTrayNotifications
    services = @{
        fsMcp = @{ ok = $true; port = $fsPort; pid = $agentProc.Id }
        workbench = @{ ok = $true; port = $wbPort; pid = $agentProc.Id }
        tunnel = @{ ok = ($sshPid -ne $null); detail = $tunnelDetail; pid = $sshPid }
    }
}
$runtimeJson = $runtime | ConvertTo-Json -Depth 5
[System.IO.File]::WriteAllText((Join-Path $stateDir 'runtime-status.json'), $runtimeJson)

Write-Host "🚀 Remote PC MCP Gateway (Rust) is now RUNNING!" -ForegroundColor Green
