@echo off
rem Double-click to install or update DeepWork. Asks for administrator rights.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" -Pause
