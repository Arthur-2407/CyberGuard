@echo off
setlocal
cd /d "%~dp0\.."

if "%1"=="" goto status
if "%1"=="start" goto start
if "%1"=="start-tunnel" goto start_tunnel
if "%1"=="stop" goto stop
if "%1"=="restart" goto restart
if "%1"=="status" goto status
if "%1"=="tunnel-url" goto tunnel_url
if "%1"=="logs" goto logs
if "%1"=="health" goto health

echo [ERROR] Unknown command: %1
echo Usage: %0 {start^|start-tunnel^|stop^|restart^|status^|tunnel-url^|logs^|health}
exit /b 1

:start
powershell -ExecutionPolicy Bypass -File "%~dp0docker-manager.ps1" start
exit /b %errorlevel%

:start_tunnel
powershell -ExecutionPolicy Bypass -File "%~dp0docker-manager.ps1" start -Tunnel
exit /b %errorlevel%

:stop
powershell -ExecutionPolicy Bypass -File "%~dp0docker-manager.ps1" stop
exit /b %errorlevel%

:restart
powershell -ExecutionPolicy Bypass -File "%~dp0docker-manager.ps1" restart
exit /b %errorlevel%

:status
powershell -ExecutionPolicy Bypass -File "%~dp0docker-manager.ps1" status
exit /b %errorlevel%

:tunnel_url
powershell -ExecutionPolicy Bypass -File "%~dp0docker-manager.ps1" tunnel-url
exit /b %errorlevel%

:logs
powershell -ExecutionPolicy Bypass -File "%~dp0docker-manager.ps1" logs
exit /b %errorlevel%

:health
powershell -ExecutionPolicy Bypass -File "%~dp0docker-manager.ps1" health
exit /b %errorlevel%
