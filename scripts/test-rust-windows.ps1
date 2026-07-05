$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$gateway = Join-Path $repoRoot "src-tauri\target\debug\toolport-gateway.exe"
$resolvedGateway = if (Test-Path $gateway) { (Resolve-Path $gateway).Path } else { $null }

if ($resolvedGateway) {
  Get-Process toolport-gateway -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -and ((Resolve-Path $_.Path).Path -eq $resolvedGateway) } |
    ForEach-Object {
      Write-Host "Stopping debug gateway process $($_.Id) so cargo can rebuild $resolvedGateway"
      Stop-Process -Id $_.Id -Force
    }
}

cargo test --manifest-path (Join-Path $repoRoot "src-tauri\Cargo.toml") --lib --bins
