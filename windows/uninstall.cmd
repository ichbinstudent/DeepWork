@echo off
rem Double-click to remove DeepWork (your blocks are kept). Asks for administrator rights.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0uninstall.ps1" -Pause
