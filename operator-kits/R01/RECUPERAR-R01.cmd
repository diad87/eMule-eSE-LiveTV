@echo off
setlocal
fltmc >nul 2>&1
if errorlevel 1 (
  powershell.exe -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0RECUPERAR-R01.ps1"
set "RC=%ERRORLEVEL%"
echo.
if "%RC%"=="0" (
  echo RECUPERACION R01 COMPLETADA
) else (
  echo RECUPERACION R01 NO COMPLETADA. Codigo %RC%
)
pause
exit /b %RC%
