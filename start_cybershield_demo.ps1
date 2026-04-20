param(
    [switch]$RunSimulation = $false,
    [string]$SimulationLevel = "high",
    [string]$SimulationTarget = "E:\mandd\CyberAttack"
)

$ErrorActionPreference = "Stop"

$BACKEND_PORT = 5000
$FRONTEND_PORT = 5173
$HOST_IP = "10.253.172.187"
$SOCKET_API_KEY = "CYBERSHIELD_SECURE_KEY"

$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$BackendRoot = $RepoRoot
$PidFile = Join-Path $RepoRoot "cybershield_pids.txt"

$localFrontendCandidate = Join-Path $RepoRoot "frontend"
$siblingFrontendCandidate = Join-Path $RepoRoot "..\..\Cybersheildapp\cybershield-command-center\frontend"

if (Test-Path $localFrontendCandidate) {
    $FrontendRoot = (Resolve-Path $localFrontendCandidate).Path
} elseif (Test-Path $siblingFrontendCandidate) {
    $FrontendRoot = (Resolve-Path $siblingFrontendCandidate).Path
} else {
    throw "Frontend folder not found. Checked: '$localFrontendCandidate' and '$siblingFrontendCandidate'."
}

$backendCommand = @"
Set-Location '$BackendRoot'
`$env:HOST = '0.0.0.0'
`$env:PORT = '$BACKEND_PORT'
`$env:CYBERSHIELD_SOCKET_API_KEY = '$SOCKET_API_KEY'
if (Test-Path '.\.venv\Scripts\python.exe') {
    & '.\.venv\Scripts\python.exe' -m backend.app
} else {
    python -m backend.app
}
"@

$frontendCommand = @"
Set-Location '$FrontendRoot'
`$env:VITE_CYBERSHIELD_SOCKET_URL = 'http://${HOST_IP}:$BACKEND_PORT'
`$env:VITE_CYBERSHIELD_SOCKET_API_KEY = '$SOCKET_API_KEY'
npm run dev -- --host 0.0.0.0 --port $FRONTEND_PORT
"@

if (Test-Path $PidFile) {
    Remove-Item $PidFile -Force
}

$backendShell = Start-Process powershell -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-Command", $backendCommand -PassThru

Start-Sleep -Seconds 5

$frontendShell = Start-Process powershell -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-Command", $frontendCommand -PassThru

Start-Sleep -Seconds 5

@(
    "backend_shell_pid=$($backendShell.Id)"
    "frontend_shell_pid=$($frontendShell.Id)"
    "backend_port=$BACKEND_PORT"
    "frontend_port=$FRONTEND_PORT"
    "host_ip=$HOST_IP"
) | Set-Content -Path $PidFile -Encoding ascii

Write-Host ""
Write-Host "CyberShield Demo Running"
Write-Host "----------------------------------"
Write-Host "Backend: http://${HOST_IP}:$BACKEND_PORT"
Write-Host "Web Dashboard (Local): http://localhost:$FRONTEND_PORT"
Write-Host "Web Dashboard (LAN): http://${HOST_IP}:$FRONTEND_PORT"
Write-Host "Mobile should connect to: http://${HOST_IP}:$BACKEND_PORT"
Write-Host "PID file: $PidFile"
Write-Host "----------------------------------"

if ($RunSimulation) {
    Write-Host "Starting simulation in 10 seconds..."
    Start-Sleep -Seconds 10

    $simScript = Join-Path $RepoRoot "test_folder\demo_attack_simulator.py"
    if (-not (Test-Path $simScript)) {
        throw "Simulation script not found: $simScript"
    }

    if (Test-Path (Join-Path $RepoRoot ".venv\Scripts\python.exe")) {
        & (Join-Path $RepoRoot ".venv\Scripts\python.exe") $simScript $SimulationLevel --target $SimulationTarget
    } else {
        python $simScript $SimulationLevel --target $SimulationTarget
    }
}
