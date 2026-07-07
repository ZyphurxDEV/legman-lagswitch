@echo off
setlocal
title Legman LagSwitch Uninstaller

REM When relaunched elevated we pass DOWORK so we skip straight to the cleanup
REM instead of showing the intro and asking again.
if "%~1"=="DOWORK" goto :dowork

echo.
echo   Legman LagSwitch - Uninstaller
echo   ==============================
echo.
echo   This removes everything Legman LagSwitch created for the current
echo   user account:
echo.
echo     - the WinDivert driver service
echo     - the Windows Firewall rules it uses (LagSwitch_Block)
echo     - the app data folder  %%APPDATA%%\LegmanLagSwitch
echo       (your saved bind key, mode, and method)
echo.
echo   It needs administrator rights to remove the firewall rules, so
echo   Windows will show a UAC prompt. LagSwitch.exe is left alone -
echo   delete it yourself afterwards if you want.
echo.

choice /c YN /m "Remove Legman LagSwitch now"
if errorlevel 2 goto :cancel

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo   Requesting administrator rights...
    powershell -Command "Start-Process '%~f0' -ArgumentList 'DOWORK' -Verb RunAs"
    exit /b 0
)

:dowork
echo.
echo   [1/4] Closing LagSwitch if it's running...
taskkill /f /im LagSwitch.exe >nul 2>&1

echo   [2/4] Unloading the WinDivert driver...
sc stop WinDivert >nul 2>&1
sc delete WinDivert >nul 2>&1

echo   [3/4] Removing firewall rules...
netsh advfirewall firewall delete rule name=LagSwitch_Block >nul 2>&1
netsh advfirewall firewall delete rule name=LagSwitch_Block_Out >nul 2>&1
netsh advfirewall firewall delete rule name=LagSwitch_Block_In >nul 2>&1

echo   [4/4] Deleting app data folder...
if defined APPDATA (
    rmdir /s /q "%APPDATA%\LegmanLagSwitch" >nul 2>&1
) else (
    echo   Skipped: APPDATA is not set - not deleting to avoid removing the wrong folder.
)
del /q "%~dp0config.json" >nul 2>&1

echo.
echo   Done - Legman LagSwitch has been removed.
echo.
echo   (LagSwitch.exe was left in place - delete it yourself if you want.)
echo.
pause
exit /b 0

:cancel
echo.
echo   Cancelled - nothing was changed.
echo.
pause
exit /b 1
