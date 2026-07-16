@echo off
setlocal
set "HERE=%~dp0"
set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" (echo ERROR: vcvars64 not found & exit /b 3)
call "%VCVARS%" >nul 2>&1
cd /d "%HERE%"
if not exist build mkdir build

cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Iinclude /Febuild\test_d0_contracts.exe tests\test_d0_contracts.cpp
if errorlevel 1 exit /b 1
build\test_d0_contracts.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Iinclude /Febuild\test_state_machine.exe tests\test_state_machine.cpp src\natmap_state.cpp
if errorlevel 1 exit /b 1
build\test_state_machine.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Iinclude /Febuild\test_mapping_codecs.exe tests\test_mapping_codecs.cpp src\natpmp_codec.cpp src\pcp_codec.cpp
if errorlevel 1 exit /b 1
build\test_mapping_codecs.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Iinclude /Febuild\test_lease_policy.exe tests\test_lease_policy.cpp src\natmap_policy.cpp
if errorlevel 1 exit /b 1
build\test_lease_policy.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Iinclude /Febuild\test_nat_chain.exe tests\test_nat_chain.cpp src\natmap_policy.cpp src\natmap_chain.cpp
if errorlevel 1 exit /b 1
build\test_nat_chain.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Iinclude /Febuild\test_ownership_ledger.exe tests\test_ownership_ledger.cpp src\ownership_ledger.cpp
if errorlevel 1 exit /b 1
build\test_ownership_ledger.exe
if errorlevel 1 exit /b 1
echo libnatmap complete gate: PASS
exit /b 0
