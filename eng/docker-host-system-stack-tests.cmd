@echo off
setlocal
set "SCRIPT_DIR=%~dp0"
rem An explicit selection never falls back to another host.
if defined TREEHAMMOCK_POWERSHELL_HOST (
    set "POWERSHELL_EXE=%TREEHAMMOCK_POWERSHELL_HOST%"
    goto selected
)
where pwsh.exe >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    set "POWERSHELL_EXE=pwsh.exe"
) else (
    set "POWERSHELL_EXE=powershell.exe"
)
:selected
if exist "%POWERSHELL_EXE%" goto launch
where "%POWERSHELL_EXE%" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo Selected PowerShell host unavailable. Install PowerShell 7 or Windows PowerShell 5.1. 1>&2
    exit /b 127
)
:launch
"%POWERSHELL_EXE%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%docker-host-system-stack-tests.ps1" %*
exit /b %ERRORLEVEL%
