@echo off
setlocal EnableDelayedExpansion
title Adobe Isolate - block Adobe apps from the internet

rem ===========================================================================
rem  adobe-isolate.bat
rem
rem  Blocks Adobe Illustrator and its Creative Cloud helper processes from
rem  making OUTBOUND network connections, using Windows Firewall.
rem
rem  Nothing is hardcoded to one machine: it SCANS the Adobe install roots and
rem  builds a rule for every executable it actually finds, so it works whatever
rem  Illustrator version is installed and wherever Adobe put it.
rem
rem  Uses netsh (present on every Windows since XP SP2) rather than the
rem  NetSecurity PowerShell module (Windows 8+ only), so it also runs on 7.
rem
rem  Every rule shares ONE name, so removal is a single command and rules can
rem  never collide with each other.
rem
rem  Usage:
rem    adobe-isolate.bat            block (default)
rem    adobe-isolate.bat /scan      list what WOULD be blocked, change nothing
rem    adobe-isolate.bat /status    show the rules currently in force
rem    adobe-isolate.bat /undo      remove every rule this script created
rem ===========================================================================

set "RULE=AdobeIsolate"
set "MODE=%~1"
if "%MODE%"=="" set "MODE=/block"

echo.
echo  ================================================================
echo   Adobe Isolate
echo  ================================================================
echo.

rem --- /status and /scan need no admin rights ------------------------------
if /i "%MODE%"=="/status" goto :status
if /i "%MODE%"=="/scan"   goto :detect

rem --- everything else writes firewall rules, which needs elevation --------
net session >nul 2>&1
if errorlevel 1 (
    echo  [*] Administrator rights are required to change firewall rules.
    echo      Re-launching elevated - approve the UAC prompt...
    echo.
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '%MODE%' -Verb RunAs" >nul 2>&1
    if errorlevel 1 (
        echo  [X] Could not elevate. Right-click this file and pick
        echo      "Run as administrator".
        echo.
        pause
    )
    exit /b 0
)

if /i "%MODE%"=="/undo" goto :undo
goto :detect


rem ===========================================================================
:detect
rem  Find every Adobe executable worth blocking.
rem  ProgramW6432 is the REAL 64-bit Program Files even when this script is run
rem  from a 32-bit shell (where %ProgramFiles% is silently redirected to x86).
rem ===========================================================================
set "ROOTS="
call :addroot "%ProgramW6432%\Adobe"
call :addroot "%ProgramFiles%\Adobe"
call :addroot "%ProgramFiles(x86)%\Adobe"
call :addroot "%ProgramW6432%\Common Files\Adobe"
call :addroot "%ProgramFiles%\Common Files\Adobe"
call :addroot "%ProgramFiles(x86)%\Common Files\Adobe"
call :addroot "%CommonProgramFiles%\Adobe"
call :addroot "%CommonProgramFiles(x86)%\Adobe"

echo  Detected Adobe installations
echo  ----------------------------

rem --- report the Illustrator versions present (the "exact version") -------
set "FOUNDAI=0"
for %%R in (%ROOTS%) do (
    for /d %%D in ("%%~R\Adobe Illustrator*") do (
        if exist "%%~fD\Support Files\Contents\Windows\Illustrator.exe" (
            set "FOUNDAI=1"
            set "AIEXE=%%~fD\Support Files\Contents\Windows\Illustrator.exe"
            set "AIVER="
            for /f "usebackq delims=" %%V in (`powershell -NoProfile -Command ^
                "try{(Get-Item '!AIEXE!').VersionInfo.FileVersion}catch{''}" 2^>nul`) do set "AIVER=%%V"
            if defined AIVER (
                echo    * %%~nxD   [ version !AIVER! ]
            ) else (
                echo    * %%~nxD
            )
        )
    )
)
if "%FOUNDAI%"=="0" echo    * no Adobe Illustrator install found
echo.

rem --- collect every target executable ------------------------------------
set /a COUNT=0
set "TMPLIST=%TEMP%\adobe-isolate-targets.txt"
if exist "%TMPLIST%" del "%TMPLIST%" >nul 2>&1

call :find Illustrator.exe
call :find AdobeIPCBroker.exe
call :find CCXProcess.exe
call :find CCLibrary.exe
call :find CoreSync.exe
call :find CRWindowsClientService.exe
call :find AdobeNotificationClient.exe
call :find AdobeUpdateService.exe
call :find Creative Cloud.exe
call :find node.exe

echo  Executables found: %COUNT%
echo.
if %COUNT%==0 (
    echo  [*] Nothing found under the Adobe program folders.
    echo      Is Adobe installed on a different drive?
    echo.
    pause
    exit /b 1
)

if /i "%MODE%"=="/scan" (
    echo  These WOULD be blocked ^(scan mode - nothing changed^):
    echo.
    for /f "usebackq delims=" %%L in ("%TMPLIST%") do echo    %%L
    echo.
    pause
    exit /b 0
)
goto :block


rem ===========================================================================
:block
echo  Creating firewall rules
echo  -----------------------
rem Remove any previous run's rules first so repeat runs never stack up.
netsh advfirewall firewall delete rule name="%RULE%" >nul 2>&1

set /a OK=0
for /f "usebackq delims=" %%L in ("%TMPLIST%") do (
    netsh advfirewall firewall add rule name="%RULE%" dir=out action=block ^
        program="%%L" enable=yes profile=any description="%%L" >nul 2>&1
    if errorlevel 1 (
        echo    [FAIL] %%L
    ) else (
        set /a OK+=1
        echo    [OK]   %%L
    )
)
echo.
echo  %OK% outbound block rule^(s^) active under the name "%RULE%".
echo.
echo  NOTE: while these are active, expect Adobe to complain about
echo        sign-in / licensing, and Creative Cloud fonts, cloud
echo        documents and Libraries sync will not work. That is the
echo        block doing its job, not a broken install.
echo.
echo  To remove them all later:  adobe-isolate.bat /undo
echo.
pause
exit /b 0


rem ===========================================================================
:undo
echo  Removing rules named "%RULE%" ...
netsh advfirewall firewall delete rule name="%RULE%" 2>nul | find /i "Deleted" >nul
if errorlevel 1 (
    echo    nothing to remove - no "%RULE%" rules were present.
) else (
    echo    removed.
)
echo.
pause
exit /b 0


rem ===========================================================================
:status
echo  Rules currently in force
echo  ------------------------
set "STF=%TEMP%\adobe-isolate-status.txt"
netsh advfirewall firewall show rule name="%RULE%" verbose >"%STF%" 2>&1
findstr /i /c:"Program:" "%STF%" >nul 2>&1
if errorlevel 1 goto :statusnone
for /f "tokens=1,* delims=:" %%A in ('findstr /i /c:"Program:" "%STF%"') do echo    blocked:%%B
for /f %%C in ('findstr /i /c:"Program:" "%STF%" ^| find /c /v ""') do set "NBLK=%%C"
echo.
echo    %NBLK% programs blocked under rule name "%RULE%"
del "%STF%" >nul 2>&1
echo.
pause
exit /b 0

:statusnone
echo    none - Adobe is NOT isolated right now.
del "%STF%" >nul 2>&1
echo.
pause
exit /b 0


rem ===========================================================================
rem  helpers
rem ===========================================================================
:addroot
rem  Add a root only once. On x64, %ProgramW6432% and %ProgramFiles% are the
rem  same directory, so without this every install is reported twice.
if not exist "%~1" goto :eof
set "CAND=%~1"
if defined ROOTS echo !ROOTS! | findstr /i /c:"!CAND!" >nul 2>&1 && goto :eof
set "ROOTS=%ROOTS% "%~1""
goto :eof

:find
rem  %* = executable name (may contain spaces, e.g. "Creative Cloud.exe")
set "TARGET=%*"
for %%R in (%ROOTS%) do (
    for /f "usebackq delims=" %%F in (`dir /s /b "%%~R\!TARGET!" 2^^^>nul`) do (
        findstr /i /x /c:"%%~fF" "%TMPLIST%" >nul 2>&1
        if errorlevel 1 (
            >>"%TMPLIST%" echo %%~fF
            set /a COUNT+=1
        )
    )
)
goto :eof
