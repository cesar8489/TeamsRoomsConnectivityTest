@echo off
REM ---------------------------------------------------------------------------
REM  Double-click launcher for the Teams Rooms connectivity test.
REM  Runs in the current user context - NO administrator rights required.
REM  Bypasses execution policy for this single run only (nothing is installed
REM  and no machine settings are changed).
REM ---------------------------------------------------------------------------
setlocal

echo.
echo  Microsoft Teams Rooms - Endpoint Connectivity Test v3.0
echo  ---------------------------------------------------
echo  Testing both platforms (Windows + Android), core Teams sign-in,
echo  and Commercial/Worldwide management endpoints only...
echo  Out of scope: GCC, GCC High, DoD, 21Vianet/China, and other government or sovereign clouds.
echo.

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Test-TeamsRoomsEndpoints-v3.0.ps1"

echo.
pause
endlocal

