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
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Fetests\build\test_upload_limit_policy.exe tests\test_upload_limit_policy.cpp
if errorlevel 1 exit /b 1
tests\build\test_upload_limit_policy.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Fetests\build\test_known2_offsets.exe tests\test_known2_offsets.cpp
if errorlevel 1 exit /b 1
tests\build\test_known2_offsets.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Fetests\build\test_partfile_io_policy.exe tests\test_partfile_io_policy.cpp
if errorlevel 1 exit /b 1
tests\build\test_partfile_io_policy.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Fetests\build\test_core_regression_policy.exe tests\test_core_regression_policy.cpp
if errorlevel 1 exit /b 1
tests\build\test_core_regression_policy.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Fetests\build\test_shared_file_intake_policy.exe tests\test_shared_file_intake_policy.cpp
if errorlevel 1 exit /b 1
tests\build\test_shared_file_intake_policy.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Fetests\build\test_shared_file_intake_policy_ab.exe tests\test_shared_file_intake_policy_ab.cpp
if errorlevel 1 exit /b 1
tests\build\test_shared_file_intake_policy_ab.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Fetests\build\test_kad_protocol_policy.exe tests\test_kad_protocol_policy.cpp
if errorlevel 1 exit /b 1
tests\build\test_kad_protocol_policy.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Fetests\build\test_kad_network_policy.exe tests\test_kad_network_policy.cpp
if errorlevel 1 exit /b 1
tests\build\test_kad_network_policy.exe
if errorlevel 1 exit /b 1

set "CRYPTLIB=%ROOT%\..\cryptopp\x64\Output\Release\cryptlib.lib"
if not exist "%CRYPTLIB%" (echo ERROR: cryptlib.lib missing; run the core gate or build emule first & exit /b 2)
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /I.. /Fetests\build\test_holepunch_cookie.exe tests\test_holepunch_cookie.cpp "%CRYPTLIB%"
if errorlevel 1 exit /b 1
tests\build\test_holepunch_cookie.exe
if errorlevel 1 exit /b 1

echo srchybrid standalone gate: PASS
exit /b 0
