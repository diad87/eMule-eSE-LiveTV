@echo off
setlocal
set "SCRIPT=%~dp0cleanup_v91_c01_vanilla_source.ps1"
set "C01_CLEANUP_LAUNCHER=%~f0"

if not exist "%SCRIPT%" (
  echo ERROR: no se encuentra "%SCRIPT%".
  pause
  exit /b 1
)

fltmc >nul 2>&1
if errorlevel 1 (
  powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
    "Start-Process -FilePath $env:C01_CLEANUP_LAUNCHER -Verb RunAs"
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
  echo El cleanup V91-C01 termino con error.
  pause
  exit /b 1
)
exit /b 0
