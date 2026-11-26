# Remote PC MCP Gateway - Stop Script
# Stops control-plane services and SSH tunnel WITHOUT killing detached `rpc-mcp job-runner` supervisors.
$ErrorActionPreference = 'SilentlyContinue'
$repoRoot = $PSScriptRoot

$ports = [System.Collections.Generic.HashSet[int]]::new()
foreach ($p in @(18849, 18623, 18619, 18787)) { [void]$ports.Add($p) }
$configFile = Join-Path $repoRoot 'config\config.local.json'
if (Test-Path $configFile) {
    try {
        $cfg = Get-Content -Raw $configFile | ConvertFrom-Json
        if ($cfg.localPorts.fsBearer) { [void]$ports.Add([int]$cfg.localPorts.fsBearer) }
        if ($cfg.localPorts.workbench) { [void]$ports.Add([int]$cfg.localPorts.workbench) }
        if ($cfg.localPorts.chromeMcp) { [void]$ports.Add([int]$cfg.localPorts.chromeMcp) }
        if ($cfg.gateway.localPort) { [void]$ports.Add([int]$cfg.gateway.localPort) }
    } catch {}
}
$targetPids = [System.Collections.Generic.HashSet[int]]::new()

foreach ($conn in @(Get-NetTCPConnection -State Listen | Where-Object { $ports.Contains([int]$_.LocalPort) })) {
    if ($conn.OwningProcess -gt 0) {
        [void]$targetPids.Add([int]$conn.OwningProcess)
    }
}

# Read recorded control-plane / tunnel PIDs from runtime-status.json
$statusFile = Join-Path $repoRoot 'state\runtime-status.json'
$recordedSshPid = $null
if (Test-Path $statusFile) {
    try {
        $rt = Get-Content -Raw $statusFile | ConvertFrom-Json
        if ($rt.pid -and [int]$rt.pid -gt 0) { [void]$targetPids.Add([int]$rt.pid) }
        if ($rt.services.tunnel.pid -and [int]$rt.services.tunnel.pid -gt 0) {
            $recordedSshPid = [int]$rt.services.tunnel.pid
        }
    } catch {}
}

# Only stop rpc-mcp control-plane processes (agent/gateway/up/chrome-broker), NEVER `job-runner`
foreach ($proc in @(Get-CimInstance Win32_Process -Filter "Name='rpc-mcp.exe'")) {
    $cmd = [string]$proc.CommandLine
    if ($cmd -match '\bjob-runner\b') {
        continue
    }
    if ($proc.ProcessId -gt 0) {
        Stop-Process -Id $proc.ProcessId -Force
    }
}

# Stop only verified ssh / cloudflared tunnel process
if ($recordedSshPid) {
    $tunnelProc = Get-Process -Id $recordedSshPid -ErrorAction SilentlyContinue
    if ($tunnelProc -and ($tunnelProc.ProcessName -in @('ssh', 'cloudflared'))) {
        Stop-Process -Id $recordedSshPid -Force
    }
}

# Also stop any orphaned ssh reverse tunnel processes
Get-CimInstance Win32_Process -Filter "Name='ssh.exe'" -ErrorAction SilentlyContinue | Where-Object {
    $_.CommandLine -match '-R\s+'
} | ForEach-Object {
    Stop-Process -Id $_.ProcessId -Force
}

# Stop any remaining listener PIDs on gateway local ports (verify not job-runner)
foreach ($id in $targetPids) {
    $wmi = Get-CimInstance Win32_Process -Filter "ProcessId=$id"
    if ($wmi -and ([string]$wmi.CommandLine -match '\bjob-runner\b')) {
        continue
    }
    if ($wmi -and ($wmi.Name -in @('rpc-mcp.exe', 'node.exe', 'ssh.exe', 'cloudflared.exe'))) {
        Stop-Process -Id $id -Force
    }
}
