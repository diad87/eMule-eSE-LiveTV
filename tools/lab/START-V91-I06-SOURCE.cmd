@echo off
setlocal
set "SCRIPT=%~dp0run_v91_i06_source_kit.ps1"
set "I06_LAUNCHER=%~f0"

if not exist "%SCRIPT%" (
  echo ERROR: no se encuentra "%SCRIPT%".
  pause
  exit /b 1
)

fltmc >nul 2>&1
if errorlevel 1 (
  powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
    "Start-Process -FilePath $env:I06_LAUNCHER -Verb RunAs"
  if errorlevel 1 (
    echo ERROR: no se pudo solicitar elevacion.
    pause
    exit /b 1
  )
  exit /b 0
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%"
if errorlevel 1 (
  echo.
  echo El kit V91-I06 termino con error.
  pause
  exit /b 1
)

exit /b 0
