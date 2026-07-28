@echo off
setlocal
set "SCRIPT=%~dp0cleanup_v91_i05_downloader.ps1"
set "I05_DOWNLOADER_CLEANUP_LAUNCHER=%~f0"

if not exist "%SCRIPT%" (
  echo ERROR: no se encuentra "%SCRIPT%".
  pause
  exit /b 1
)

fltmc >nul 2>&1
if errorlevel 1 (
  powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
    "Start-Process -FilePath $env:I05_DOWNLOADER_CLEANUP_LAUNCHER -Verb RunAs"
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
  echo El cleanup V91-I05 termino con error.
  pause
  exit /b 1
)
exit /b 0
