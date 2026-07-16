@echo off
setlocal
set "HERE=%~dp0"
set "ROOT=%HERE%.."
set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" (echo ERROR: vcvars64 not found & exit /b 3)
call "%VCVARS%" >nul 2>&1
cd /d "%ROOT%"
if not exist tests\build mkdir tests\build

cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Fetests\build\test_livefec.exe tests\test_livefec.cpp LiveFec.cpp
if errorlevel 1 exit /b 1
tests\build\test_livefec.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Fetests\build\test_livebulk.exe tests\test_livebulk.cpp LiveBulk.cpp LiveFec.cpp
if errorlevel 1 exit /b 1
tests\build\test_livebulk.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Fetests\build\test_livepeerrefresh.exe tests\test_livepeerrefresh.cpp
if errorlevel 1 exit /b 1
tests\build\test_livepeerrefresh.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Fetests\build\test_liveratelimiter.exe tests\test_liveratelimiter.cpp
if errorlevel 1 exit /b 1
tests\build\test_liveratelimiter.exe
if errorlevel 1 exit /b 1

if not exist x64\Release\cryptlib.lib (echo ERROR: cryptlib.lib missing; build emule first & exit /b 2)
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /I.. /Fetests\build\test_holepunch_cookie.exe tests\test_holepunch_cookie.cpp x64\Release\cryptlib.lib
if errorlevel 1 exit /b 1
tests\build\test_holepunch_cookie.exe
if errorlevel 1 exit /b 1

echo srchybrid standalone gate: PASS
exit /b 0
