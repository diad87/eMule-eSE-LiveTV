@echo off
setlocal
if "%~5"=="" (
  echo USO: %~nx0 ^<run-base^> ^<candidate.zip^> ^<fixture^> ^<fixture-sha256^> ^<IPv4-H3^>
  exit /b 2
)

net session >nul 2>&1
if not "%errorlevel%"=="0" (
  echo ERROR: ejecute esta utilidad como administrador.
  exit /b 5
)

powershell.exe -NoProfile -ExecutionPolicy Bypass ^
  -File "%~dp0tools\lab\continue_v91_i05_h1.ps1" ^
  -RunBase "%~1" ^
  -CandidateZipPath "%~2" ^
  -FixturePath "%~3" ^
  -ExpectedFixtureSha256 "%~4" ^
  -H3IPv4 "%~5"
if errorlevel 1 (
  echo.
  echo No se pudo iniciar V91-I05. Deja esta ventana abierta.
  pause
)
