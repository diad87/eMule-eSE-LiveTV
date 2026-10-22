@echo off
setlocal EnableExtensions

rem One click: request elevation only when it is still missing.
fltmc >nul 2>&1
if errorlevel 1 (
  powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
    "Start-Process -FilePath '%~f0' -ArgumentList '--elevated' -Verb RunAs"
  exit /b
)

powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass ^
  -File "%~dp0REPARAR-AGENTE-R01.ps1"
set "RC=%ERRORLEVEL%"

echo.
if "%RC%"=="0" (
  echo AGENTE R01 REPARADO Y LISTO EN EL PUERTO 8015
) else (
  echo NO SE HA PODIDO REPARAR EL AGENTE R01. Codigo %RC%
  echo Consulte REPARAR-AGENTE-R01-RESULTADO.json en esta carpeta.
)
echo.
pause
exit /b %RC%
