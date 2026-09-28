# SentinelFW installer for Windows 10/11 / Server. Run from an elevated PowerShell:  .\install.ps1
#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
$py = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $py -or $py -like '*WindowsApps*') { throw "Install Python 3.8+ for ALL USERS from python.org (the boot task runs as SYSTEM)." }
$dest = Join-Path $env:ProgramFiles 'SentinelFW'
New-Item -ItemType Directory -Force $dest | Out-Null
Remove-Item -Recurse -Force (Join-Path $dest 'sentinelfw') -ErrorAction SilentlyContinue
Copy-Item -Recurse -Force (Join-Path $PSScriptRoot 'sentinelfw'), (Join-Path $PSScriptRoot 'sfwctl.py'), (Join-Path $PSScriptRoot 'fw.cmd'), (Join-Path $PSScriptRoot 'fw.ps1') $dest

# Add to system PATH if not already present
$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
if ($machinePath -notlike "*$dest*") {
    [Environment]::SetEnvironmentVariable('Path', "$machinePath;$dest", 'Machine')
    $env:Path = "$env:Path;$dest"
}

$data = Join-Path $env:ProgramData 'SentinelFW'
New-Item -ItemType Directory -Force $data | Out-Null
if (-not (Test-Path (Join-Path $data 'config.json'))) { Copy-Item (Join-Path $PSScriptRoot 'config.example.json') (Join-Path $data 'config.json') }
& $py (Join-Path $dest 'sfwctl.py') update-lists
& $py (Join-Path $dest 'sfwctl.py') install-service
Write-Host "`n[OK] SentinelFW installed and running as permanent background service."
Write-Host "[OK] You can now run 'fw' from ANY PowerShell or CMD terminal (no admin required)."
Write-Host "Examples:"
Write-Host "  fw status"
Write-Host "  fw conns"
Write-Host "  fw block-ip 198.51.100.25 --duration 1h"
Write-Host "  fw honeypot"
Write-Host "`nWeb UI Dashboard: http://127.0.0.1:9443"
Write-Host "Logs: $data\logs\events.jsonl"

