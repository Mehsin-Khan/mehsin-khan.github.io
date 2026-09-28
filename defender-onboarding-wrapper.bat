@echo off
setlocal EnableExtensions
REM ==================================================================
REM  Self-service Microsoft Defender for Endpoint onboarding wrapper
REM  Portfolio reconstruction, rebuilt with AI assistance. Not the original.
REM  Placeholder share path. The real onboarding package is tenant-specific,
REM  downloaded from the Defender portal, and is NOT included here.
REM ==================================================================
set "SHARE=\\fileserver.example.local\DefenderOnboarding"
set "PKG=%SHARE%\WindowsDefenderATPLocalOnboardingScript.cmd"
set "LOG=%SHARE%\logs\onboarding-log.csv"

for /f %%t in ('powershell -NoProfile -Command "Get-Date -Format s"') do set "TS=%%t"
set "WHO=%USERDOMAIN%\%USERNAME%"

REM Who is running this, and with what rights?
net session >nul 2>&1
if %errorlevel%==0 (set "ADMIN=Yes") else (set "ADMIN=No")

if not exist "%LOG%" echo Timestamp,Computer,RunBy,Admin,Result>"%LOG%"

if "%ADMIN%"=="No" (
  echo %TS%,%COMPUTERNAME%,%WHO%,No,Refused - not run as administrator>>"%LOG%"
  echo This must be run as administrator. Your attempt has been logged.
  pause & exit /b 1
)

if not exist "%PKG%" (
  echo %TS%,%COMPUTERNAME%,%WHO%,Yes,Failed - onboarding package not found>>"%LOG%"
  echo Onboarding package not found. Contact the endpoint security team.
  pause & exit /b 2
)

echo %TS%,%COMPUTERNAME%,%WHO%,Yes,Started>>"%LOG%"
call "%PKG%"

REM Give the sensor time to start, then verify rather than assume
timeout /t 30 /nobreak >nul
set "SENSE=Not running"
sc query Sense | find "RUNNING" >nul && set "SENSE=Running"
set "ONBOARDED=No"
reg query "HKLM\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status" /v OnboardingState 2>nul | find "0x1" >nul && set "ONBOARDED=Yes"

for /f %%t in ('powershell -NoProfile -Command "Get-Date -Format s"') do set "TS=%%t"
echo %TS%,%COMPUTERNAME%,%WHO%,Yes,Finished - Sense %SENSE%; onboarded %ONBOARDED%>>"%LOG%"
echo.
echo Sense service: %SENSE%
echo Onboarded:     %ONBOARDED%
echo Result logged. If Onboarded says No, raise a ticket quoting this computer name.
pause
endlocal
