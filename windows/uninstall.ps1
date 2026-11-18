# Remove DeepWork from Windows. Double-click uninstall.cmd, or run:
#   powershell -ExecutionPolicy Bypass -File .\uninstall.ps1 [-Purge]
# Refuses while a block is locked or a freeze is running.
param(
    # Also delete blocks, statistics and settings.
    [switch]$Purge,
    # Wait for Enter at the end (when started in its own window).
    [switch]$Pause
)
$ErrorActionPreference = 'Stop'

function Done([int]$code) {
    if ($Pause) { Read-Host 'Press Enter to close' | Out-Null }
    exit $code
}
trap {
    Write-Host "Removing DeepWork failed: $_" -ForegroundColor Red
    Done 1
}

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-Pause')
    if ($Purge) { $argList += '-Purge' }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $argList
    exit 0
}

$dir = Join-Path $env:ProgramFiles 'DeepWork'
$data = Join-Path $env:ProgramData 'DeepWork'
$task = 'DeepWork'
$ctl = Join-Path $dir 'deepworkctl.exe'

if (Test-Path $ctl) {
    # Native commands writing to stderr must not stop the script here.
    $ErrorActionPreference = 'Continue'
    & $ctl locked *> $null
    $locked = $LASTEXITCODE -eq 0
    $ErrorActionPreference = 'Stop'
    if ($locked) {
        & $ctl status
        Write-Host "A block is locked or a freeze is running. Uninstall again when it's over." -ForegroundColor Yellow
        Done 1
    }
}

Write-Host 'Stopping the service...'
if (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $task
    Unregister-ScheduledTask -TaskName $task -Confirm:$false
}
Get-Process deepwork, deepwork-daemon -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 500

# Remove our section from the hosts file and the browser policies.
$daemon = Join-Path $dir 'deepwork-daemon.exe'
if (Test-Path $daemon) { & $daemon --cleanup }

Write-Host 'Removing the programs...'
Remove-Item -Recurse -Force $dir -ErrorAction SilentlyContinue
$programs = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs'
Remove-Item -Force (Join-Path $programs 'DeepWork.lnk'), (Join-Path $programs 'StartUp\DeepWork.lnk') -ErrorAction SilentlyContinue
$path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
$rest = ($path -split ';' | Where-Object { $_ -and $_ -ne $dir }) -join ';'
[Environment]::SetEnvironmentVariable('Path', $rest, 'Machine')

Write-Host ''
if ($Purge) {
    Remove-Item -Recurse -Force $data -ErrorAction SilentlyContinue
    Write-Host 'DeepWork and all its data were removed.' -ForegroundColor Green
} else {
    Write-Host "DeepWork was removed. Your blocks are kept in $data (use -Purge to delete them)." -ForegroundColor Green
}
Done 0
