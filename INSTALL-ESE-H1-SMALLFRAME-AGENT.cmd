@echo off
setlocal
if "%~1"=="" (
  echo USO: %~nx0 ^<IPv4-controlador^> [nombre-Taildrop-controlador]
  echo Ejemplo: %~nx0 192.0.2.10 equipo-controlador
  exit /b 2
)

net session >nul 2>&1
if not "%errorlevel%"=="0" (
  set "ESE_H1_INSTALLER=%~f0"
  set "ESE_H1_ALLOWED_SOURCE=%~1"
  set "ESE_H1_TAILDROP_NAME=%~2"
  powershell.exe -NoProfile -Command ^
    "$arguments=@($env:ESE_H1_ALLOWED_SOURCE); if($env:ESE_H1_TAILDROP_NAME){$arguments += $env:ESE_H1_TAILDROP_NAME}; Start-Process -FilePath $env:ESE_H1_INSTALLER -ArgumentList $arguments -Verb RunAs"
  exit /b
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\lab\install_ese_lab_smallframe_agent.ps1" ^
  -SourcePath "%~dp0tools\lab\run_ese_lab_smallframe_agent.ps1" ^
  -ControllerTaildropName "%~2" ^
  -AllowedSourceIPv4 "%~1" ^
  -Port 8016 ^
  -TaskName "eSE Lab H1 SmallFrame Agent" ^
  -FirewallName "eSE-Lab-H1-SmallFrame-Agent" ^
  -TokenDpapiPath "%LOCALAPPDATA%\eSE-Lab-Controller\h1-smallframe-token.dpapi"
if errorlevel 1 (
  echo.
  echo ERROR: no se pudo instalar el agente local H1.
  pause
  exit /b 1
)

echo.
echo Agente local H1 instalado. Puede cerrar esta ventana.
pause
