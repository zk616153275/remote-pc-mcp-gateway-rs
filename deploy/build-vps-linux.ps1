# Build a static x86_64-unknown-linux-musl binary of `rpc-mcp` for Linux VPS deployment
param(
    [switch]$UseDocker
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot

if ($UseDocker) {
    docker run --rm -v "${repoRoot}:/work" -w /work rust:1-alpine sh -c `
        "apk add --no-cache musl-dev && cargo build --release --bin rpc-mcp --target x86_64-unknown-linux-musl"
} else {
    if (-not (Get-Command cargo-zigbuild -ErrorAction SilentlyContinue)) {
        Write-Error "cargo-zigbuild not found. Install via 'cargo install cargo-zigbuild' (plus Zig), or rerun with -UseDocker."
    }
    rustup target add x86_64-unknown-linux-musl
    Push-Location $repoRoot
    try {
        cargo zigbuild --release --bin rpc-mcp --target x86_64-unknown-linux-musl
    } finally {
        Pop-Location
    }
}

$out = Join-Path $repoRoot 'target\x86_64-unknown-linux-musl\release\rpc-mcp'
if (Test-Path $out) {
    $mb = [math]::Round((Get-Item $out).Length / 1MB, 2)
    Write-Host "Static Linux VPS binary ready: $out ($mb MB)" -ForegroundColor Green
}
