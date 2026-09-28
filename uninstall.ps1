#Requires -RunAsAdministrator
$py = (Get-Command python).Source; $dest = Join-Path $env:ProgramFiles 'SentinelFW'
& $py (Join-Path $dest 'sfwctl.py') uninstall-service
& $py (Join-Path $dest 'sfwctl.py') cleanup
Remove-Item -Recurse -Force $dest
Write-Host "Removed. Config/lists/quarantine remain in $env:ProgramData\SentinelFW."
