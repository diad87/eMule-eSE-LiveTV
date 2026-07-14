@echo off
REM libkad6 standalone build+run helper (no MFC, MSVC x64).
REM Usage:  make.bat <exeName> <src1.cpp> [src2.cpp ...]
REM Compiles the sources into build\<exeName>.exe at /W4 /std:c++17 and runs it.
setlocal enabledelayedexpansion
set "HERE=%~dp0"
if "%~1"=="" (
  echo Usage: make.bat ^<exeName^> ^<src1.cpp^> [src2.cpp ...]
  exit /b 2
)
set "EXE=%~1"
shift
set "SRCS="
:collect
if "%~1"=="" goto compile
set "SRCS=!SRCS! %~1"
shift
goto collect
:compile
set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" (
  echo ERROR: vcvars64 not found at "%VCVARS%"
  echo Edit make.bat VCVARS= to point at your Visual Studio 2022 install.
  exit /b 3
)
call "%VCVARS%" >nul 2>&1
REM vcvars64 changes cwd and shift moved %0, so cd to the folder captured up top.
cd /d "%HERE%"
if not exist build mkdir build
cl /nologo /EHsc /O2 /W4 /std:c++17 /Iinclude /Febuild\%EXE%.exe!SRCS!
if errorlevel 1 (echo BUILD FAILED & exit /b 1)
echo --- running build\%EXE%.exe ---
build\%EXE%.exe