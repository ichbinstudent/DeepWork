#Requires -RunAsAdministrator
# Remove DeepWork from Windows. Refuses while a block is locked or a freeze
# is running.
#   -Purge   also delete blocks, statistics and settings
param([switch]$Purge)
$ErrorActionPreference = 'Stop'

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
        throw "A block is locked or a freeze is running. Uninstall again when it's over."
    }
}

if (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $task
    Unregister-ScheduledTask -TaskName $task -Confirm:$false
}
Get-Process deepwork-daemon -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 500

# Remove our section from the hosts file and the Firefox policies.
$daemon = Join-Path $dir 'deepwork-daemon.exe'
if (Test-Path $daemon) { & $daemon --cleanup }

Remove-Item -Recurse -Force $dir -ErrorAction SilentlyContinue
$path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
$rest = ($path -split ';' | Where-Object { $_ -and $_ -ne $dir }) -join ';'
[Environment]::SetEnvironmentVariable('Path', $rest, 'Machine')

if ($Purge) {
    Remove-Item -Recurse -Force $data -ErrorAction SilentlyContinue
    Write-Host 'DeepWork and all its data were removed.'
} else {
    Write-Host "DeepWork was removed. Your blocks are kept in $data (use -Purge to delete them)."
}
