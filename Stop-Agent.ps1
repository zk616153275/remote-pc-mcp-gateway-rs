# Remote PC MCP Gateway - Stop Script
$ErrorActionPreference = 'SilentlyContinue'
$repoRoot = $PSScriptRoot

$ports = @(18849, 18623, 18619)
$pids = Get-NetTCPConnection -State Listen | Where-Object { $_.LocalPort -in $ports } | Select-Object -ExpandProperty OwningProcess -Unique

# Also read runtime-status.json
$statusFile = Join-Path $repoRoot 'state\runtime-status.json'
if (Test-Path $statusFile) {
    try {
        $rt = Get-Content -Raw $statusFile | ConvertFrom-Json
        if ($rt.pid) { $pids += $rt.pid }
        if ($rt.services.tunnel.pid) { $pids += $rt.services.tunnel.pid }
    } catch {}
}

# Find all rpc-mcp or ssh processes related to gateway
$procs = Get-Process | Where-Object { $_.ProcessName -eq 'rpc-mcp' -or ($_.ProcessName -eq 'ssh' -and $_.Id -in $pids) }
foreach ($p in $procs) {
    Stop-Process -Id $p.Id -Force
}
foreach ($id in ($pids | Select-Object -Unique)) {
    if ($id -gt 0) {
        Stop-Process -Id $id -Force
    }
}
