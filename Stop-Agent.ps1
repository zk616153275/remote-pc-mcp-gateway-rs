# Remote PC MCP Gateway - Stop Script
# Stops control-plane services and SSH tunnel WITHOUT killing detached `rpc-mcp job-runner` supervisors.
$ErrorActionPreference = 'SilentlyContinue'
$repoRoot = $PSScriptRoot

$ports = @(18849, 18623, 18619)
$targetPids = [System.Collections.Generic.HashSet[int]]::new()

foreach ($conn in @(Get-NetTCPConnection -State Listen | Where-Object { $_.LocalPort -in $ports })) {
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

# Stop only verified ssh tunnel process (check ProcessName is actually 'ssh')
if ($recordedSshPid) {
    $sshProc = Get-Process -Id $recordedSshPid -ErrorAction SilentlyContinue
    if ($sshProc -and $sshProc.ProcessName -eq 'ssh') {
        Stop-Process -Id $recordedSshPid -Force
    }
}

# Stop any remaining listener PIDs on gateway local ports (verify not job-runner)
foreach ($id in $targetPids) {
    $wmi = Get-CimInstance Win32_Process -Filter "ProcessId=$id"
    if ($wmi -and ([string]$wmi.CommandLine -match '\bjob-runner\b')) {
        continue
    }
    if ($wmi -and ($wmi.Name -in @('rpc-mcp.exe', 'node.exe', 'ssh.exe'))) {
        Stop-Process -Id $id -Force
    }
}
