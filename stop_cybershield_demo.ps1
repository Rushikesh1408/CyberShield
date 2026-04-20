$ErrorActionPreference = "Stop"

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

function Get-PidMapFromFile {
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

function Get-FallbackCyberShieldProcesses {
    param(
        [string]$Repo,
        [string]$Frontend
    )

    $procs = @(Get-CimInstance Win32_Process)

    $backend = $procs | Where-Object {
        ($_.Name -match "^python(\.exe)?$") -and
        ($_.CommandLine -like "*-m backend.app*") -and
        ($_.CommandLine -like "*$Repo*")
    }

    $frontend = @()
    if ($Frontend) {
        $frontend = $procs | Where-Object {
            ($_.Name -match "^node(\.exe)?$") -and
            ($_.CommandLine -like "*vite*") -and
            ($_.CommandLine -like "*$Frontend*")
        }
    }

    $matches = @($backend + $frontend)
    if ($matches.Count -eq 0) {
        return @()
    }

    return @(
        $matches |
            Where-Object { $_ -and $_.ProcessId } |
            ForEach-Object { [int]$_.ProcessId } |
            Sort-Object -Unique
    )
}

$targetPids = New-Object System.Collections.Generic.HashSet[int]
$pidMap = Get-PidMapFromFile -Path $PidFile

foreach ($key in @("backend_shell_pid", "frontend_shell_pid")) {
    if (-not $pidMap.ContainsKey($key)) {
        continue
    }

    $value = $pidMap[$key]
    $parentPid = 0
    if (-not [int]::TryParse($value, [ref]$parentPid)) {
        continue
    }

    if (Get-Process -Id $parentPid -ErrorAction SilentlyContinue) {
        [void]$targetPids.Add($parentPid)
        $children = Get-DescendantProcessIds -ParentPid $parentPid
        foreach ($childPid in $children) {
            [void]$targetPids.Add([int]$childPid)
        }
    }
}

$fallbackPids = Get-FallbackCyberShieldProcesses -Repo $RepoRoot -Frontend $FrontendRoot
foreach ($procId in $fallbackPids) {
    [void]$targetPids.Add([int]$procId)
}

$stopped = New-Object System.Collections.Generic.List[int]
$skipped = New-Object System.Collections.Generic.List[int]

foreach ($procId in @($targetPids | Sort-Object -Descending)) {
    try {
        if (Get-Process -Id $procId -ErrorAction SilentlyContinue) {
            Stop-Process -Id $procId -Force -ErrorAction Stop
            $stopped.Add($procId)
        } else {
            $skipped.Add($procId)
        }
    } catch {
        $skipped.Add($procId)
    }
}

if (Test-Path $PidFile) {
    Remove-Item $PidFile -Force
}

Write-Host ""
Write-Host "CyberShield Demo Stopped"
Write-Host "----------------------------------"
Write-Host "Stopped PIDs: $($stopped.Count)"
if ($stopped.Count -gt 0) {
    Write-Host "Stopped IDs: $($stopped -join ', ')"
}
Write-Host "Skipped IDs: $($skipped.Count)"
Write-Host "----------------------------------"
