<#
.SYNOPSIS
    CyberGuard Docker On-Demand Management CLI (PowerShell)

.DESCRIPTION
    Manages the lifecycle of the CyberGuard SOC backend container and optional secure
    Cloudflare Tunnel on your local laptop. Keeps your laptop battery & resources free
    when offline, and instantly exposes an authenticated, encrypted HTTPS endpoint for
    your Vercel and GitHub Pages frontends when you need it.

.EXAMPLE
    .\scripts\docker-manager.ps1 start
    .\scripts\docker-manager.ps1 start -Tunnel
    .\scripts\docker-manager.ps1 tunnel-url
    .\scripts\docker-manager.ps1 status
    .\scripts\docker-manager.ps1 stop
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0, Mandatory = $false)]
    [ValidateSet("start", "stop", "restart", "status", "tunnel-url", "logs", "health", "help")]
    [string]$Command = "status",

    [Parameter(Mandatory = $false)]
    [switch]$Tunnel,

    [Parameter(Mandatory = $false)]
    [switch]$Follow
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $ProjectRoot

function Write-CyberHeader {
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  CyberGuard SOC & AI Defense — Docker On-Demand Controller    " -ForegroundColor White
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
}

function Test-DockerEngine {
    try {
        $null = docker info 2>&1
        return $true
    } catch {
        return $false
    }
}

if (-not (Test-DockerEngine)) {
    Write-CyberHeader
    Write-Host "[ERROR] Docker engine is not running or not reachable." -ForegroundColor Red
    Write-Host "Please start Docker Desktop and run this command again." -ForegroundColor Yellow
    exit 1
}

switch ($Command) {
    "start" {
        Write-CyberHeader
        if ($Tunnel) {
            Write-Host "[INFO] Starting CyberGuard Backend + Cloudflare Secure Tunnel..." -ForegroundColor Green
            docker compose --profile tunnel up -d --build
            Write-Host ""
            Write-Host "[SUCCESS] Containers started! Waiting 5s for tunnel assignment..." -ForegroundColor Cyan
            Start-Sleep -Seconds 5
            & $PSCommandPath tunnel-url
        } else {
            Write-Host "[INFO] Starting CyberGuard Backend container (Local port 3000)..." -ForegroundColor Green
            docker compose up -d --build cyberguard-backend
            Write-Host ""
            Write-Host "[SUCCESS] Backend started at http://localhost:3000" -ForegroundColor Green
            Write-Host "Tip: To expose securely to Vercel/GitHub Pages, run: .\scripts\docker-manager.ps1 start -Tunnel" -ForegroundColor Gray
        }
    }

    "stop" {
        Write-CyberHeader
        Write-Host "[INFO] Stopping all CyberGuard containers..." -ForegroundColor Yellow
        docker compose --profile tunnel down
        Write-Host "[SUCCESS] CyberGuard backend and tunnel stopped. Laptop resources freed." -ForegroundColor Green
    }

    "restart" {
        Write-CyberHeader
        Write-Host "[INFO] Restarting CyberGuard containers..." -ForegroundColor Cyan
        docker compose --profile tunnel down
        if ($Tunnel) {
            docker compose --profile tunnel up -d
        } else {
            docker compose up -d cyberguard-backend
        }
        Write-Host "[SUCCESS] Restart complete." -ForegroundColor Green
    }

    "status" {
        Write-CyberHeader
        Write-Host "[CONTAINER STATUS]" -ForegroundColor White
        docker compose --profile tunnel ps
        Write-Host ""
        Write-Host "[LOCAL HEALTH CHECK]" -ForegroundColor White
        try {
            $resp = Invoke-RestMethod -Uri "http://localhost:3000/health" -TimeoutSec 3 -ErrorAction SilentlyContinue
            Write-Host "  Backend HTTP Health: " -NoNewline
            Write-Host "ONLINE ($($resp.service) v$($resp.version))" -ForegroundColor Green
        } catch {
            Write-Host "  Backend HTTP Health: " -NoNewline
            Write-Host "OFFLINE (Container stopped or initializing)" -ForegroundColor Red
        }

        # Check tunnel
        $tunnelRunning = docker ps --filter "name=cyberguard-tunnel" --filter "status=running" -q
        if ($tunnelRunning) {
            Write-Host ""
            Write-Host "[ACTIVE CLOUDFLARE TUNNEL]" -ForegroundColor White
            & $PSCommandPath tunnel-url
        }
    }

    "tunnel-url" {
        Write-Host "[INFO] Fetching Cloudflare Tunnel endpoint from logs..." -ForegroundColor Cyan
        $tunnelLogs = docker logs cyberguard-tunnel 2>&1
        $match = [regex]::Match($tunnelLogs, 'https://[a-zA-Z0-9\-]+\.trycloudflare\.com')
        if ($match.Success) {
            $url = $match.Value
            Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
            Write-Host "  LIVE SECURE TUNNEL URL:" -ForegroundColor White
            Write-Host "  $url" -ForegroundColor Yellow -BackgroundColor Black
            Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
            Write-Host "Copy and paste this URL into your Vercel or GitHub Pages frontend:" -ForegroundColor Gray
            Write-Host "  1. Open CyberGuard Console (Vercel or GitHub Pages)" -ForegroundColor Gray
            Write-Host "  2. Click the 'Backend Endpoint' pill in the top-right navbar" -ForegroundColor Gray
            Write-Host "  3. Paste the URL above and click 'Save & Test'" -ForegroundColor Gray
        } else {
            Write-Host "[WARN] Quick Tunnel URL not yet found in logs or named token tunnel is active." -ForegroundColor Yellow
            Write-Host "Run 'docker logs cyberguard-tunnel' to inspect tunnel connection output." -ForegroundColor Gray
        }
    }

    "logs" {
        Write-CyberHeader
        if ($Follow) {
            docker compose --profile tunnel logs -f
        } else {
            docker compose --profile tunnel logs --tail=100
        }
    }

    "health" {
        try {
            $resp = Invoke-RestMethod -Uri "http://localhost:3000/health" -TimeoutSec 4
            Write-Host (ConvertTo-Json $resp -Depth 3) -ForegroundColor Green
        } catch {
            Write-Host "[ERROR] Could not connect to http://localhost:3000/health: $_" -ForegroundColor Red
            exit 1
        }
    }

    "help" {
        Write-CyberHeader
        Write-Host "Available Commands:" -ForegroundColor White
        Write-Host "  start              Start backend container on http://localhost:3000"
        Write-Host "  start -Tunnel      Start backend + secure Cloudflare HTTPS Tunnel"
        Write-Host "  stop               Stop containers and release resources"
        Write-Host "  restart            Restart active containers"
        Write-Host "  status             Inspect container status & local health probe"
        Write-Host "  tunnel-url         Retrieve and print active trycloudflare.com URL"
        Write-Host "  logs [-Follow]     Display container logs"
        Write-Host "  health             Ping local health check endpoint"
    }
}
