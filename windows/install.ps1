#Requires -RunAsAdministrator
# Install the DeepWork service on Windows (experimental). Run it from an
# administrator PowerShell in the unpacked release folder:
#   powershell -ExecutionPolicy Bypass -File .\install.ps1
$ErrorActionPreference = 'Stop'

$dir = Join-Path $env:ProgramFiles 'DeepWork'
$data = Join-Path $env:ProgramData 'DeepWork'
$task = 'DeepWork'

# Stop a running copy before replacing it.
if (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $task
}
Get-Process deepwork-daemon -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 500

New-Item -ItemType Directory -Force $dir | Out-Null
Copy-Item -Force (Join-Path $PSScriptRoot 'deepwork-daemon.exe'), (Join-Path $PSScriptRoot 'deepworkctl.exe') $dir

# Only the installing user (and administrators) may control the service.
# Users are identified by the last number of their SID (see: whoami /user).
New-Item -ItemType Directory -Force $data | Out-Null
$config = Join-Path $data 'config.json'
if (-not (Test-Path $config)) {
    $rid = ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -split '-')[-1]
    Set-Content -Encoding ascii -Path $config -Value "{`r`n  `"allowed_users`": [$rid]`r`n}"
}

# The service runs as SYSTEM from a scheduled task that starts with Windows
# and is restarted if it stops.
$action = New-ScheduledTaskAction -Execute (Join-Path $dir 'deepwork-daemon.exe')
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
Register-ScheduledTask -TaskName $task -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $task

# Put deepworkctl on the PATH.
$path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
if (($path -split ';') -notcontains $dir) {
    [Environment]::SetEnvironmentVariable('Path', "$path;$dir", 'Machine')
}

Write-Host 'DeepWork is installed and running. Open a new terminal and try:'
Write-Host '  deepworkctl status'
Write-Host '  deepworkctl add Social list:social'
Write-Host '  deepworkctl start Social 60'
