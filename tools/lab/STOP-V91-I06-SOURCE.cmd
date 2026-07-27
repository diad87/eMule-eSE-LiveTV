@echo off
setlocal EnableExtensions EnableDelayedExpansion
set "SCRIPT=%~dp0cleanup_v91_i06_source.ps1"
set "I06_CLEANUP_LAUNCHER=%~f0"

if "%~1"=="" (
  set "RUNS_ROOT=%~dp0..\..\runs"
  set /a "MATCH_COUNT=0"
  for /d %%D in ("!RUNS_ROOT!\v91-i06-source-*") do (
    if exist "%%~fD\" (
      set /a "MATCH_COUNT+=1"
      set "I06_CLEANUP_RUNROOT=%%~fD"
    )
  )
  if not "!MATCH_COUNT!"=="1" (
    echo ERROR: se esperaba exactamente una ejecucion v91-i06-source-*
    echo bajo la carpeta runs del kit, pero se encontraron !MATCH_COUNT!.
    echo.
    echo Puede arrastrar la carpeta correcta sobre este archivo o usar:
    echo   STOP-V91-I06-SOURCE.cmd "RUTA_COMPLETA_AL_RUNROOT"
    pause
    exit /b 2
  )
) else (
  set "I06_CLEANUP_RUNROOT=%~f1"
)

if not exist "%SCRIPT%" (
  echo ERROR: no se encuentra "%SCRIPT%".
  pause
  exit /b 1
)
if not exist "%I06_CLEANUP_RUNROOT%\evidence\session.json" (
  echo ERROR: RunRoot no contiene evidence\session.json.
  pause
  exit /b 1
)

fltmc >nul 2>&1
if errorlevel 1 (
  powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
    "$arg='"""'+$env:I06_CLEANUP_RUNROOT+'"""'; Start-Process -FilePath $env:I06_CLEANUP_LAUNCHER -ArgumentList $arg -Verb RunAs"
  if errorlevel 1 (
    echo ERROR: no se pudo solicitar elevacion.
    pause
    exit /b 1
  )
  exit /b 0
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" ^
  -RunRoot "%I06_CLEANUP_RUNROOT%"
if errorlevel 1 (
  echo.
  echo El cleanup V91-I06 termino con error.
  pause
  exit /b 1
)

exit /b 0
