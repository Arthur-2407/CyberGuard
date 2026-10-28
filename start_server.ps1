param(
    [int]$Port = 3000,
    [switch]$NoClamd
)

$ErrorActionPreference = "Stop"

# Get the directory of this script
$ProjectRoot = $PSScriptRoot

# Define the venv Python executable
$PythonExe = Join-Path $ProjectRoot "venv\Scripts\python.exe"

if (-Not (Test-Path $PythonExe)) {
    Write-Error "[ERROR] Virtual environment Python not found at: $PythonExe"
    exit 1
}

# Clear environment variables that might cause global Python bleeding
$env:PYTHONPATH = ""
$env:PYTHONHOME = ""

# 1. Port conflict detection (e.g. if Docker container is already binding port 3000)
$occupied = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
if ($occupied) {
    Write-Host "[WARN] Port $Port is already in use by another process (PID: $($occupied[0].OwningProcess))." -ForegroundColor Yellow
    if ($Port -eq 3000) {
        $Port = 8000
        Write-Host "[INFO] Automatically shifting native server to alternative port $Port to avoid port collision with Docker." -ForegroundColor Cyan
    }
}

# 2. Check and start local ClamAV daemon (clamd) for sub-millisecond scans if installed
if (-not $NoClamd) {
    $clamdExe = "C:\Program Files\ClamAV\clamd.exe"
    $clamdConf = "C:\ProgramData\ClamAV\clamd.conf"
    $clamdRunning = Get-Process clamd -ErrorAction SilentlyContinue
    if (-not $clamdRunning -and (Test-Path $clamdExe) -and (Test-Path $clamdConf)) {
        Write-Host "[INFO] Starting ClamAV daemon (clamd) in background for instant malware scans..." -ForegroundColor Cyan
        Start-Process $clamdExe -ArgumentList "-F", "-c", $clamdConf -WindowStyle Hidden
    }
}

Write-Host "[INFO] Starting CyberGuard server on port $Port using isolated venv Python:" -ForegroundColor Cyan
Write-Host $PythonExe -ForegroundColor Green
Write-Host "Frontend & API URL: http://127.0.0.1:$Port" -ForegroundColor Cyan
Write-Host ""

& $PythonExe -m uvicorn backend.main:app --host 0.0.0.0 --port $Port --reload
