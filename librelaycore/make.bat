@echo off
REM Standalone P0 build/test for librelaycore (MSVC x64, no MFC).
setlocal
set "HERE=%~dp0"
set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" (echo ERROR: vcvars64 not found & exit /b 3)
call "%VCVARS%" >nul 2>&1
cd /d "%HERE%"
if not exist build mkdir build
set "EXTRA=/O2"
set "SUFFIX="
if "%RELAY_ASAN%"=="1" (
  set "EXTRA=/Od /Zi /fsanitize=address"
  set "SUFFIX=_asan"
  set "ASAN_OPTIONS=quarantine_size_mb=16:thread_local_quarantine_size_kb=64"
)
cl /nologo /EHsc %EXTRA% /W4 /WX /std:c++17 /Iinclude /c ^
  src\relay_core.cpp src\krp_control.cpp src\krp_tcp_wire.cpp src\krp_auth.cpp src\krp_session.cpp ^
  src\krp_authority.cpp src\krp_flow.cpp src\epr_lease.cpp
if errorlevel 1 (echo LIBRELAYCORE OBJECT BUILD FAILED & exit /b 1)
lib /nologo /OUT:build\relaycore%SUFFIX%.lib ^
  relay_core.obj krp_control.obj krp_tcp_wire.obj krp_auth.obj krp_session.obj ^
  krp_authority.obj krp_flow.obj epr_lease.obj
if errorlevel 1 (echo LIBRELAYCORE ARCHIVE BUILD FAILED & exit /b 1)
cl /nologo /EHsc %EXTRA% /W4 /WX /std:c++17 /Iinclude ^
  /Febuild\test_relay_core%SUFFIX%.exe tests\test_relay_core.cpp ^
  build\relaycore%SUFFIX%.lib
if errorlevel 1 (echo LIBRELAYCORE BUILD FAILED & exit /b 1)
build\test_relay_core%SUFFIX%.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc %EXTRA% /W4 /WX /std:c++17 /Iinclude ^
  /Febuild\test_krp_control%SUFFIX%.exe tests\test_krp_control.cpp ^
  build\relaycore%SUFFIX%.lib
if errorlevel 1 (echo KRP CONTROL BUILD FAILED & exit /b 1)
build\test_krp_control%SUFFIX%.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc %EXTRA% /W4 /WX /std:c++17 /Iinclude ^
  /Febuild\test_krp_tcp_wire%SUFFIX%.exe tests\test_krp_tcp_wire.cpp ^
  build\relaycore%SUFFIX%.lib
if errorlevel 1 (echo KRP TCP WIRE BUILD FAILED & exit /b 1)
build\test_krp_tcp_wire%SUFFIX%.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc %EXTRA% /W4 /WX /std:c++17 /Iinclude ^
  /Febuild\test_krp_session%SUFFIX%.exe tests\test_krp_session.cpp ^
  build\relaycore%SUFFIX%.lib
if errorlevel 1 (echo KRP SESSION BUILD FAILED & exit /b 1)
build\test_krp_session%SUFFIX%.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc %EXTRA% /W4 /WX /std:c++17 /Iinclude ^
  /Febuild\test_krp_auth%SUFFIX%.exe tests\test_krp_auth.cpp ^
  build\relaycore%SUFFIX%.lib
if errorlevel 1 (echo KRP AUTH BUILD FAILED & exit /b 1)
build\test_krp_auth%SUFFIX%.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc %EXTRA% /W4 /WX /std:c++17 /Iinclude ^
  /Febuild\test_krp_flow%SUFFIX%.exe tests\test_krp_flow.cpp ^
  build\relaycore%SUFFIX%.lib
if errorlevel 1 (echo KRP FLOW BUILD FAILED & exit /b 1)
build\test_krp_flow%SUFFIX%.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc %EXTRA% /W4 /WX /std:c++17 /Iinclude /I..\libkad6\include ^
  /Febuild\test_kad6_authority_adapter%SUFFIX%.exe ^
  tests\test_kad6_authority_adapter.cpp src\kad6_authority_adapter.cpp ^
  build\relaycore%SUFFIX%.lib ^
  ..\libkad6\src\kad6_ticket.cpp ..\libkad6\src\kad6_endpoint.cpp ^
  ..\libkad6\src\kad6_address.cpp
if errorlevel 1 (echo KAD6 AUTHORITY ADAPTER BUILD FAILED & exit /b 1)
build\test_kad6_authority_adapter%SUFFIX%.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc %EXTRA% /W4 /WX /std:c++17 /Iinclude ^
  /Febuild\test_epr_lease%SUFFIX%.exe tests\test_epr_lease.cpp ^
  build\relaycore%SUFFIX%.lib
if errorlevel 1 (echo EPR LEASE BUILD FAILED & exit /b 1)
build\test_epr_lease%SUFFIX%.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc %EXTRA% /W4 /WX /std:c++17 /Iinclude ^
  /Febuild\test_krp_p1_gate%SUFFIX%.exe tests\test_krp_p1_gate.cpp ^
  build\relaycore%SUFFIX%.lib
if errorlevel 1 (echo KRP P1 GATE BUILD FAILED & exit /b 1)
build\test_krp_p1_gate%SUFFIX%.exe
exit /b %errorlevel%
