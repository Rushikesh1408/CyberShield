$ErrorActionPreference = "Stop"

$BACKEND_URL = "http://10.253.172.187:5000"
$FRONTEND_URL_LOCAL = "http://localhost:5173"
$FRONTEND_URL_LAN = "http://10.253.172.187:5173"

$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$PidFile = Join-Path $RepoRoot "cybershield_pids.txt"
$localFrontendCandidate = Join-Path $RepoRoot "frontend"
$siblingFrontendCandidate = Join-Path $RepoRoot "..\..\Cybersheildapp\cybershield-command-center\frontend"

$FrontendRoot = $null
if (Test-Path $localFrontendCandidate) {
    $FrontendRoot = (Resolve-Path $localFrontendCandidate).Path
} elseif (Test-Path $siblingFrontendCandidate) {
    $FrontendRoot = (Resolve-Path $siblingFrontendCandidate).Path
}

function Test-Url {
    param([Parameter(Mandatory = $true)][string]$Url)

    try {
        $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 2
        return ($response.StatusCode -eq 200)
    } catch {
        return $false
    }
}

function Get-TrackedPidMap {
    param([string]$Path)

    $map = @{}
    if (-not (Test-Path $Path)) {
        return $map
    }

    foreach ($line in Get-Content -Path $Path) {
        if ([string]::IsNullOrWhiteSpace($line) -or $line.IndexOf("=") -lt 1) {
            continue
        }

        $parts = $line -split "=", 2
        $map[$parts[0].Trim()] = $parts[1].Trim()
    }

    return $map
}

function Get-BackendDemoProcesses {
    param([string]$Repo)

    return @(
        Get-CimInstance Win32_Process |
            Where-Object {
                ($_.Name -match "^python(\.exe)?$") -and
                ($_.CommandLine -like "*-m backend.app*") -and
                ($_.CommandLine -like "*$Repo*")
            }
    )
}

function Get-FrontendDemoProcesses {
    param([string]$Frontend)

    if (-not $Frontend) {
        return @()
    }

    return @(
        Get-CimInstance Win32_Process |
            Where-Object {
                ($_.Name -match "^node(\.exe)?$") -and
                ($_.CommandLine -like "*vite*") -and
                ($_.CommandLine -like "*$Frontend*")
            }
    )
}

$backendProcesses = Get-BackendDemoProcesses -Repo $RepoRoot
$frontendProcesses = Get-FrontendDemoProcesses -Frontend $FrontendRoot

$backendRunning = $backendProcesses.Count -gt 0
$frontendRunning = $frontendProcesses.Count -gt 0

$backendUp = Test-Url -Url $BACKEND_URL
$frontendUpLocal = Test-Url -Url $FRONTEND_URL_LOCAL
$frontendUpLAN = Test-Url -Url $FRONTEND_URL_LAN

$tracked = Get-TrackedPidMap -Path $PidFile
$backendShellPid = $tracked["backend_shell_pid"]
$frontendShellPid = $tracked["frontend_shell_pid"]

Write-Host ""
Write-Host "CyberShield System Status"
Write-Host "----------------------------------"

if ($backendRunning) {
    Write-Host "[OK] Backend Process: RUNNING (python count: $($backendProcesses.Count))"
} else {
    Write-Host "[DOWN] Backend Process: NOT RUNNING"
}

if ($backendUp) {
    Write-Host "[OK] Backend URL: RUNNING ($BACKEND_URL)"
} else {
    Write-Host "[DOWN] Backend URL: NOT REACHABLE ($BACKEND_URL)"
}

if ($frontendRunning) {
    Write-Host "[OK] Web Process: RUNNING (node count: $($frontendProcesses.Count))"
} else {
    Write-Host "[DOWN] Web Process: NOT RUNNING"
}

if ($frontendUpLocal) {
    Write-Host "[OK] Web (Local): RUNNING ($FRONTEND_URL_LOCAL)"
} else {
    Write-Host "[DOWN] Web (Local): NOT REACHABLE ($FRONTEND_URL_LOCAL)"
}

if ($frontendUpLAN) {
    Write-Host "[OK] Web (LAN): RUNNING ($FRONTEND_URL_LAN)"
} else {
    Write-Host "[DOWN] Web (LAN): NOT REACHABLE ($FRONTEND_URL_LAN)"
}

$overallStatus = "DOWN"

if ($backendUp -and ($frontendUpLocal -or $frontendUpLAN) -and $backendRunning) {
    $overallStatus = "HEALTHY"
} elseif (
    $backendUp -or
    $frontendUpLocal -or
    $frontendUpLAN -or
    $backendRunning -or
    $frontendRunning
) {
    $overallStatus = "DEGRADED"
}

Write-Host "----------------------------------"
if ($tracked.Count -gt 0) {
    Write-Host "Tracked Demo Shell PIDs from file:"
    if ($backendShellPid) {
        Write-Host "- backend_shell_pid: $backendShellPid"
    }
    if ($frontendShellPid) {
        Write-Host "- frontend_shell_pid: $frontendShellPid"
    }
} else {
    Write-Host "No PID tracking file found at: $PidFile"
}
Write-Host "----------------------------------"

switch ($overallStatus) {
    "HEALTHY" {
        Write-Host "[OK] OVERALL STATUS: HEALTHY" -ForegroundColor Green
    }
    "DEGRADED" {
        Write-Host "[WARN] OVERALL STATUS: DEGRADED" -ForegroundColor Yellow
    }
    "DOWN" {
        Write-Host "[DOWN] OVERALL STATUS: DOWN" -ForegroundColor Red
    }
}

Write-Host "----------------------------------"
