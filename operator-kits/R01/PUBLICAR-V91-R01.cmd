@echo off
setlocal
title Publicar v9.1 - R01
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0PUBLICAR-V91-R01.ps1"
exit /b %ERRORLEVEL%

