@echo off
setlocal
set "HERE=%~dp0"
set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" (echo ERROR: vcvars64 not found & exit /b 3)
call "%VCVARS%" >nul 2>&1
cd /d "%HERE%"
if not exist build mkdir build

cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Iinclude /Febuild\test_reach_codec.exe tests\test_reach_codec.cpp src\reach_codec.cpp
if errorlevel 1 exit /b 1
build\test_reach_codec.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Iinclude /Febuild\test_reach_facade.exe tests\test_reach_facade.cpp src\reach_context.cpp src\reach_codec.cpp src\reach_cascade.cpp
if errorlevel 1 exit /b 1
build\test_reach_facade.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Iinclude /Febuild\test_reach_cascade.exe tests\test_reach_cascade.cpp src\reach_cascade.cpp
if errorlevel 1 exit /b 1
build\test_reach_cascade.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Iinclude /Febuild\test_reach_actuator.exe tests\test_reach_actuator.cpp src\reach_context.cpp src\reach_codec.cpp src\reach_cascade.cpp
if errorlevel 1 exit /b 1
build\test_reach_actuator.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Iinclude /Febuild\test_direct_attempt.exe tests\test_direct_attempt.cpp src\direct_attempt.cpp
if errorlevel 1 exit /b 1
build\test_direct_attempt.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Iinclude /Febuild\test_direct_session.exe tests\test_direct_session.cpp src\direct_session.cpp
if errorlevel 1 exit /b 1
build\test_direct_session.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Iinclude /Febuild\test_direct_coordinator.exe tests\test_direct_coordinator.cpp src\direct_coordinator.cpp src\direct_session.cpp
if errorlevel 1 exit /b 1
build\test_direct_coordinator.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Iinclude /Febuild\test_direct_event_queue.exe tests\test_direct_event_queue.cpp src\direct_event_queue.cpp src\direct_coordinator.cpp src\direct_session.cpp
if errorlevel 1 exit /b 1
build\test_direct_event_queue.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Iinclude /Febuild\test_direct_transport.exe tests\test_direct_transport.cpp src\direct_transport.cpp
if errorlevel 1 exit /b 1
build\test_direct_transport.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Iinclude /Febuild\test_part_owner_domain.exe tests\test_part_owner_domain.cpp
if errorlevel 1 exit /b 1
build\test_part_owner_domain.exe
if errorlevel 1 exit /b 1
echo libreach complete gate: PASS
exit /b 0
