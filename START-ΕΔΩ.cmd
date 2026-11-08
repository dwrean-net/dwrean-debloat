@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"
echo ==============================================
echo    dwrean.net Debloat - Windows 11
echo ==============================================
powershell.exe -NoProfile -Command "Start-Process -FilePath powershell.exe -Verb RunAs -Wait -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -File ' + [char]34 + (Join-Path (Get-Location).Path 'dwrean-debloat.ps1') + [char]34)"
if errorlevel 1 (
    echo Δεν ήταν δυνατή η εκκίνηση. Δοκίμασε εκτέλεση ως διαχειριστής.
    pause
)
endlocal
