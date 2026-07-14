# Headless gateway security smoke tests (Windows).
# Run from repo root after: npm run build:gateway  (or release binary)
#
#   powershell -ExecutionPolicy Bypass -File scripts/smoke-headless.ps1

$ErrorActionPreference = "Stop"
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$bin = Join-Path $repoRoot "src-tauri\target\release\toolport-gateway.exe"
if (-not (Test-Path $bin)) {
    $bin = Join-Path $repoRoot "src-tauri\target\debug\toolport-gateway.exe"
}
if (-not (Test-Path $bin)) {
    Write-Error "Build toolport-gateway first: npm run build:gateway"
}

$smokeDir = Join-Path $repoRoot ".smoke-test"
New-Item -ItemType Directory -Force -Path $smokeDir | Out-Null

$registry = Join-Path $smokeDir "registry.json"
@'
{
  "version": 1,
  "humanApproval": false,
  "servers": [],
  "profiles": [{ "id": "default", "name": "Default", "enabledServerIds": [] }],
  "activeProfileId": "default"
}
'@ | Set-Content -Encoding utf8 $registry

$port = 18766
$token = "smoke-test-token-32chars-minimum!!"
$gatewayPid = $null
$failed = 0

function Pass($msg) { Write-Host "[PASS] $msg" -ForegroundColor Green }
function Fail($msg) { Write-Host "[FAIL] $msg" -ForegroundColor Red; $script:failed++ }

Write-Host "Using gateway: $bin"

# --- Test 1: non-loopback without token refuses start ---
$env:CONDUIT_REGISTRY = $registry
$env:CONDUIT_HTTP_HOST = "0.0.0.0"
Remove-Item Env:CONDUIT_HTTP_TOKEN -ErrorAction SilentlyContinue
$p1 = Start-Process -FilePath $bin -ArgumentList "--http", "18765" -PassThru -WindowStyle Hidden -RedirectStandardError (Join-Path $smokeDir "t1.err")
Start-Sleep -Seconds 2
if ($p1.HasExited -and $p1.ExitCode -ne 0) {
    $err = Get-Content (Join-Path $smokeDir "t1.err") -Raw -ErrorAction SilentlyContinue
    if ($err -match "refusing to bind.*without HTTP authentication") {
        Pass "non-loopback without token refuses start (exit $($p1.ExitCode))"
    } else {
        Fail "non-loopback without token exited $($p1.ExitCode) but message unexpected: $err"
    }
} else {
    if (-not $p1.HasExited) { Stop-Process -Id $p1.Id -Force -ErrorAction SilentlyContinue }
    Fail "non-loopback without token should refuse start"
}

# --- Test 2: loopback without auth also refuses start ---
$env:CONDUIT_HTTP_HOST = "127.0.0.1"
$p2 = Start-Process -FilePath $bin -ArgumentList "--http", "18764" -PassThru -WindowStyle Hidden -RedirectStandardError (Join-Path $smokeDir "t2.err")
Start-Sleep -Seconds 2
if ($p2.HasExited -and $p2.ExitCode -ne 0) {
    $err = Get-Content (Join-Path $smokeDir "t2.err") -Raw -ErrorAction SilentlyContinue
    if ($err -match "refusing to bind.*without HTTP authentication") {
        Pass "loopback without auth refuses start (exit $($p2.ExitCode))"
    } else {
        Fail "loopback without auth exited $($p2.ExitCode) but message unexpected: $err"
    }
} else {
    if (-not $p2.HasExited) { Stop-Process -Id $p2.Id -Force -ErrorAction SilentlyContinue }
    Fail "loopback without auth should refuse start"
}

# --- Test 3: explicit insecure loopback escape hatch works locally ---
$p3 = Start-Process -FilePath $bin -ArgumentList "--http", "18764", "--insecure-loopback" -PassThru -WindowStyle Hidden -RedirectStandardError (Join-Path $smokeDir "t3.err")
Start-Sleep -Seconds 2
if ($p3.HasExited) {
    $err = Get-Content (Join-Path $smokeDir "t3.err") -Raw -ErrorAction SilentlyContinue
    Fail "explicit insecure loopback exited unexpectedly: $err"
} else {
    $code = curl.exe -s -o NUL -w "%{http_code}" "http://127.0.0.1:18764/"
    if ($code -eq "200") { Pass "explicit insecure loopback starts locally" } else { Fail "explicit insecure loopback returned $code" }
    Stop-Process -Id $p3.Id -Force -ErrorAction SilentlyContinue
}

# --- Start authenticated gateway for tests 4-5 ---
$env:CONDUIT_HTTP_HOST = "127.0.0.1"
$env:CONDUIT_HTTP_TOKEN = $token
$gw = Start-Process -FilePath $bin -ArgumentList "--http", "$port" -PassThru -WindowStyle Hidden
$gatewayPid = $gw.Id
Set-Content -Path (Join-Path $smokeDir "gateway.pid") -Value $gatewayPid
Start-Sleep -Seconds 2

try {
    # --- Test 4: auth ---
    $codeNoAuth = curl.exe -s -o NUL -w "%{http_code}" "http://127.0.0.1:${port}/"
    if ($codeNoAuth -eq "401") { Pass "GET / without auth returns 401" } else { Fail "GET / without auth returned $codeNoAuth (expected 401)" }

    $codeAuth = curl.exe -s -o NUL -w "%{http_code}" -H "Authorization: Bearer $token" "http://127.0.0.1:${port}/"
    if ($codeAuth -eq "200") { Pass "GET / with bearer returns 200" } else { Fail "GET / with bearer returned $codeAuth (expected 200)" }

    # --- Test 5: MCP handshake ---
    $initReq = Join-Path $smokeDir "init-req.json"
    $initJson = '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}'
    [System.IO.File]::WriteAllText($initReq, $initJson)

    $initHdr = Join-Path $smokeDir "init.hdr"
    $initBody = Join-Path $smokeDir "init.json"
    curl.exe -sD $initHdr -o $initBody -X POST "http://127.0.0.1:${port}/mcp" `
        -H "Authorization: Bearer $token" -H "Content-Type: application/json" -H "Accept: application/json" `
        --data-binary "@$initReq" | Out-Null

    $hdr = Get-Content $initHdr -Raw
    if ($hdr -notmatch "HTTP/[\d.]+ 200") { Fail "MCP initialize not 200: $hdr" }
    elseif ($hdr -notmatch "Mcp-Session-Id:\s*(\S+)") { Fail "MCP initialize missing Mcp-Session-Id" }
    else {
        $sid = $Matches[1]
        Pass "MCP initialize returns 200 + Mcp-Session-Id"

        $listReq = Join-Path $smokeDir "list-req.json"
        [System.IO.File]::WriteAllText($listReq, '{"jsonrpc":"2.0","id":2,"method":"tools/list"}')
        $listOut = Join-Path $smokeDir "list.json"
        curl.exe -s -o $listOut -X POST "http://127.0.0.1:${port}/mcp" `
            -H "Authorization: Bearer $token" -H "Content-Type: application/json" `
            -H "Mcp-Session-Id: $sid" --data-binary "@$listReq" | Out-Null
        $listJson = Get-Content $listOut -Raw | ConvertFrom-Json
        $n = @($listJson.result.tools).Count
        if ($n -ge 4) { Pass "MCP tools/list returns $n tools" } else { Fail "MCP tools/list returned $n tools (expected >= 4)" }
    }
} finally {
    if ($gatewayPid) {
        Stop-Process -Id $gatewayPid -Force -ErrorAction SilentlyContinue
        Remove-Item (Join-Path $smokeDir "gateway.pid") -ErrorAction SilentlyContinue
    }
}

# --- Test 4: HITL fail-closed (unit test) ---
Write-Host "Running approval_broker_fails_closed unit test..."
Push-Location $repoRoot
cargo test --manifest-path src-tauri/Cargo.toml --no-default-features --bin toolport-gateway approval_broker_fails_closed 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) { Pass "HITL fail-closed when broker missing (unit test)" } else { Fail "approval_broker_fails_closed test failed" }
Pop-Location

Write-Host ""
if ($failed -eq 0) {
    Write-Host "All headless smoke tests passed." -ForegroundColor Green
    exit 0
} else {
    Write-Host "$failed test(s) failed." -ForegroundColor Red
    exit 1
}
