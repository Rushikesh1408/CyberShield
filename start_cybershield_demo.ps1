param(
    [switch]$RunSimulation = $false,
    [string]$SimulationLevel = "high",
    [string]$SimulationTarget = "E:\mandd\CyberAttack"
)

$ErrorActionPreference = "Stop"

$BACKEND_PORT = 5001
$FRONTEND_PORT = 5173
$SOCKET_API_KEY = "CYBERSHIELD_SECURE_KEY"

$backendStartedByScript = $false
$frontendStartedByScript = $false
$backendShell = $null
$frontendShell = $null

# ===== HELPER FUNCTIONS =====

# Get LISTEN state connections for a TCP port
function Get-ListeningConnections {
    param([int]$Port)

    try {
        return @(Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction Stop)
    } catch {
        return @()
    }
}

# Test if a local TCP port accepts connections
function Test-TcpPortOpen {
    param(
        [int]$Port,
        [string]$HostName = "127.0.0.1",
        [int]$TimeoutMs = 600
    )

    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect($HostName, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
            return $false
        }

        $client.EndConnect($async)
        return $true
    } catch {
        return $false
    } finally {
        $client.Close()
    }
}

# Check if a port is listening
function Test-PortInUse {
    param([int]$Port)

    return (Test-TcpPortOpen -Port $Port)
}

# Get PID bound to a TCP port (LISTEN owner)
function Get-PortOwnerPid {
    param([int]$Port)

    $listeners = Get-ListeningConnections -Port $Port
    foreach ($listener in $listeners) {
        $ownerProcessId = [int]$listener.OwningProcess
        if ($ownerProcessId -gt 0) {
            return $ownerProcessId
        }
    }

    # Fallback for environments where Get-NetTCPConnection intermittently
    # returns no objects despite an active listener.
    try {
        $lines = @(netstat -ano -p tcp 2>$null | findstr ":$Port")
        foreach ($line in $lines) {
            $parts = ($line -split '\s+') | Where-Object { $_ -ne "" }
            if ($parts.Count -lt 5) {
                continue
            }

            $state = $parts[-2]
            if ($state -ne "LISTENING") {
                continue
            }

            $ownerPid = 0
            if (-not [int]::TryParse($parts[-1], [ref]$ownerPid)) {
                continue
            }

            if ($ownerPid -gt 0) {
                return $ownerPid
            }
        }
    } catch {
        return $null
    }

    return $null
}

# Wait until a TCP port is listening
function Wait-ForListeningPort {
    param(
        [int]$Port,
        [int]$TimeoutSeconds = 30
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if (Test-PortInUse -Port $Port) {
            return $true
        }
        Start-Sleep -Milliseconds 500
    }

    return $false
}

# Return child process IDs for a parent PID
function Get-DescendantProcessIds {
    param([int]$ParentPid)

    $all = @(Get-CimInstance Win32_Process)
    $pending = New-Object System.Collections.Generic.Queue[int]
    $seen = New-Object System.Collections.Generic.HashSet[int]
    $results = New-Object System.Collections.Generic.List[int]

    $pending.Enqueue($ParentPid)

    while ($pending.Count -gt 0) {
        $current = $pending.Dequeue()
        if (-not $seen.Add($current)) {
            continue
        }

        $children = $all | Where-Object { $_.ParentProcessId -eq $current }
        foreach ($child in $children) {
            $childId = [int]$child.ProcessId
            if ($seen.Contains($childId)) {
                continue
            }
            $results.Add($childId)
            $pending.Enqueue($childId)
        }
    }

    return $results
}

# Stop parent process and all descendants
function Stop-ProcessTree {
    param(
        [int]$RootPid,
        [string]$Label
    )

    $targets = New-Object System.Collections.Generic.List[int]
    $targets.Add($RootPid)
    $children = Get-DescendantProcessIds -ParentPid $RootPid
    foreach ($childPid in $children) {
        $targets.Add([int]$childPid)
    }

    foreach ($procId in @($targets | Sort-Object -Descending -Unique)) {
        try {
            if (Get-Process -Id $procId -ErrorAction SilentlyContinue) {
                Stop-Process -Id $procId -Force -ErrorAction Stop
            }
        } catch {
            # Best effort cleanup
        }
    }

    Write-Host "       Cleaned up $Label process tree (root PID $RootPid)" -ForegroundColor DarkYellow
}

# Get the local LAN IP address
function Get-LocalIPAddress {
    try {
        $ipInfo = ipconfig | Select-String "IPv4 Address" | Select-Object -First 1
        if ($ipInfo) {
            $ip = $ipInfo.ToString().Split(":")[-1].Trim()
            return $ip
        }
    } catch {
        # Fallback
    }
    return "127.0.0.1"
}

# ===== SETUP PATHS =====

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

# Auto-detect local IP
$LOCAL_IP = Get-LocalIPAddress

$backendCommand = @"
Set-Location '$BackendRoot'
`$env:HOST = '0.0.0.0'
`$env:PORT = '$BACKEND_PORT'
`$env:CYBERSHIELD_MONITOR_PATHS = 'E:\mandd\CyberAttack'
`$env:CYBERSHIELD_SOCKET_API_KEY = '$SOCKET_API_KEY'
if (Test-Path '.\.venv\Scripts\python.exe') {
    & '.\.venv\Scripts\python.exe' -m backend.app
} else {
    python -m backend.app
}
"@

$frontendCommand = @"
Set-Location '$FrontendRoot'
`$env:VITE_CYBERSHIELD_SOCKET_URL = 'http://${LOCAL_IP}:$BACKEND_PORT'
`$env:VITE_CYBERSHIELD_SOCKET_API_KEY = '$SOCKET_API_KEY'
`$env:VITE_API_BASE_URL = 'http://${LOCAL_IP}:$BACKEND_PORT'
cmd /c npm run dev -- --host 0.0.0.0 --port $FRONTEND_PORT
"@

try {
    # ===== CLEAR OLD PID FILE =====
    if (Test-Path $PidFile) {
        Remove-Item $PidFile -Force
    }

    # ===== CHECK PORT 5000 AVAILABILITY =====
    $portInUse = Test-PortInUse -Port $BACKEND_PORT

    if ($portInUse) {
        Write-Host ""
        Write-Host "[WARN] Backend already running on port $BACKEND_PORT" -ForegroundColor Yellow
        Write-Host "       Reusing existing backend instance..." -ForegroundColor Yellow

        $existingBackendPid = Get-PortOwnerPid -Port $BACKEND_PORT
        if ($existingBackendPid) {
            $backendProc = Get-CimInstance Win32_Process -Filter "ProcessId = $existingBackendPid" -ErrorAction SilentlyContinue
            if ($backendProc -and $backendProc.Name -match "^python(\.exe)?$" -and $backendProc.CommandLine -like "*-m backend.app*") {
                $backendShell = @{ Id = $existingBackendPid }
                Write-Host "       Tracking existing backend PID: $existingBackendPid" -ForegroundColor Yellow
            } else {
                throw "Port $BACKEND_PORT is in use by a non-CyberShield process (PID $existingBackendPid). Stop it or change port."
            }
        } else {
            throw "Port $BACKEND_PORT is in use, but owning PID could not be resolved."
        }
    } else {
        Write-Host ""
        Write-Host "[INFO] Starting CyberShield backend..." -ForegroundColor Green

        $backendShell = Start-Process powershell -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", $backendCommand -PassThru
        $backendStartedByScript = $true
        Write-Host "       Backend PID: $($backendShell.Id)" -ForegroundColor Green

        if (-not (Wait-ForListeningPort -Port $BACKEND_PORT -TimeoutSeconds 45)) {
            throw "Backend failed to start listening on port $BACKEND_PORT within timeout."
        }
    }

    # ===== CHECK PORT 5173 AVAILABILITY =====
    $frontendPortInUse = Test-PortInUse -Port $FRONTEND_PORT
    if ($frontendPortInUse) {
        Write-Host ""
        Write-Host "[WARN] Frontend already running on port $FRONTEND_PORT" -ForegroundColor Yellow
        Write-Host "       Reusing existing frontend instance..." -ForegroundColor Yellow

        $existingFrontendPid = Get-PortOwnerPid -Port $FRONTEND_PORT
        if ($existingFrontendPid) {
            $frontendProc = Get-CimInstance Win32_Process -Filter "ProcessId = $existingFrontendPid" -ErrorAction SilentlyContinue
            if ($frontendProc -and $frontendProc.Name -match "^node(\.exe)?$" -and $frontendProc.CommandLine -like "*vite*") {
                $frontendShell = @{ Id = $existingFrontendPid }
                Write-Host "       Tracking existing frontend PID: $existingFrontendPid" -ForegroundColor Yellow
            } else {
                throw "Port $FRONTEND_PORT is in use by a non-CyberShield frontend process (PID $existingFrontendPid). Stop it or change port."
            }
        } else {
            throw "Port $FRONTEND_PORT is in use, but owning PID could not be resolved."
        }
    } else {
        Write-Host ""
        Write-Host "[INFO] Starting web frontend..." -ForegroundColor Green

        $frontendShell = Start-Process powershell -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", $frontendCommand -PassThru
        $frontendStartedByScript = $true
        Write-Host "       Frontend PID: $($frontendShell.Id)" -ForegroundColor Green

        if (-not (Wait-ForListeningPort -Port $FRONTEND_PORT -TimeoutSeconds 45)) {
            throw "Frontend failed to start listening on port $FRONTEND_PORT within timeout."
        }
    }
} catch {
    if ($frontendStartedByScript -and $frontendShell -and $frontendShell.Id) {
        Stop-ProcessTree -RootPid ([int]$frontendShell.Id) -Label "frontend"
    }

    if ($backendStartedByScript -and $backendShell -and $backendShell.Id) {
        Stop-ProcessTree -RootPid ([int]$backendShell.Id) -Label "backend"
    }

    throw
}

$startupMode = if ($backendStartedByScript -and $frontendStartedByScript) {
    "FRESH START"
} elseif ((-not $backendStartedByScript) -and (-not $frontendStartedByScript)) {
    "REUSED INSTANCE"
} else {
    "PARTIAL RESTART"
}

# ===== SAVE PID FILE =====
$pidFileContent = @(
    "backend_port=$BACKEND_PORT"
    "frontend_port=$FRONTEND_PORT"
    "local_ip=$LOCAL_IP"
)

if ($backendShell) {
    $pidFileContent += "backend_shell_pid=$($backendShell.Id)"
}

$pidFileContent += "frontend_shell_pid=$($frontendShell.Id)"

$pidFileContent | Set-Content -Path $PidFile -Encoding ascii

# ===== DISPLAY FINAL ACCESS LINKS =====
Write-Host ""
Write-Host "CyberShield Running Successfully" -ForegroundColor Cyan
Write-Host "----------------------------------" -ForegroundColor Cyan
Write-Host ""
Write-Host "🚀 Startup Mode: $startupMode" -ForegroundColor Cyan
Write-Host ""

Write-Host "Backend:" -ForegroundColor Yellow
Write-Host "   http://localhost:$BACKEND_PORT" -ForegroundColor White
Write-Host "   http://${LOCAL_IP}:$BACKEND_PORT" -ForegroundColor White
Write-Host ""

Write-Host "Web Dashboard:" -ForegroundColor Yellow
Write-Host "   http://localhost:$FRONTEND_PORT" -ForegroundColor White
Write-Host "   http://${LOCAL_IP}:$FRONTEND_PORT" -ForegroundColor White
Write-Host ""

Write-Host "Mobile App should connect to:" -ForegroundColor Yellow
Write-Host "   http://${LOCAL_IP}:$BACKEND_PORT" -ForegroundColor White
Write-Host ""

Write-Host "Configuration:" -ForegroundColor Yellow
Write-Host "   Local IP: $LOCAL_IP" -ForegroundColor White
Write-Host "   Backend Port: $BACKEND_PORT" -ForegroundColor White
Write-Host "   Frontend Port: $FRONTEND_PORT" -ForegroundColor White
Write-Host "   PID File: $PidFile" -ForegroundColor Gray
Write-Host ""
Write-Host "Run stop_cybershield_demo.ps1 to stop services." -ForegroundColor Cyan
Write-Host ""

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
