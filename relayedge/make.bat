@echo off
REM P2 Release + AddressSanitizer build and real loopback TLS/WSS gate.
setlocal
set "HERE=%~dp0"
set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" (echo ERROR: vcvars64 not found & exit /b 3)
call "%VCVARS%" >nul 2>&1
cd /d "%HERE%"
if not exist build mkdir build

set "INCLUDES=/Iinclude /I..\librelaycore\include /I..\mbedtls\include /I..\mbedtls\tf-psa-crypto\include /I..\mbedtls\tf-psa-crypto\drivers\builtin\include"
set "DEFINES=/DMBEDTLS_THREADING_C /DMBEDTLS_THREADING_ALT"
set "BASE_SOURCES=src\edge_runtime.cpp src\edge_session_table.cpp src\edge_auth.cpp src\edge_policy.cpp src\edge_allocator.cpp src\edge_daemon.cpp src\wss_h1.cpp src\wss_carrier.cpp src\tls_tcp_carrier.cpp"
set "P4_SOURCES=src\krp_p4_crypto.cpp src\krp_tcp_session.cpp"
set "SOURCES=%BASE_SOURCES% %P4_SOURCES%"
set "BASE_LIBS=..\srchybrid\x64\Release\mbedTLS.lib bcrypt.lib ws2_32.lib"
set "LIBS=%BASE_LIBS% ..\srchybrid\x64\Release\cryptlib.lib"
set "CERT=..\mbedtls\framework\data_files\server2-sha256.crt"
set "KEY=..\mbedtls\framework\data_files\server2.key"
set "CA=..\mbedtls\framework\data_files\test-ca.crt"

cl /nologo /EHsc /O2 /W4 /WX /std:c++17 %DEFINES% %INCLUDES% ^
  /Febuild\relayedge.exe main.cpp %SOURCES% ..\librelaycore\build\relaycore.lib %LIBS% /link /LTCG
if errorlevel 1 (echo RELAYEDGE RELEASE BUILD FAILED & exit /b 1)

cl /nologo /EHsc /O2 /W4 /WX /std:c++17 %DEFINES% %INCLUDES% ^
  /Febuild\test_p2.exe tests\test_p2.cpp %SOURCES% ..\librelaycore\build\relaycore.lib %LIBS% /link /LTCG
if errorlevel 1 (echo RELAYEDGE P2 TEST BUILD FAILED & exit /b 1)

build\relayedge.exe --self-test
if errorlevel 1 exit /b 1
build\relayedge.exe --check-config lab-loopback.conf.example
if errorlevel 1 exit /b 1
build\relayedge.exe --lab-startup-check lab-loopback.conf.example
if errorlevel 1 exit /b 1
build\test_p2.exe "%CERT%" "%KEY%" "%CA%"
if errorlevel 1 exit /b 1

cl /nologo /EHsc /Od /Zi /W4 /WX /std:c++17 /fsanitize=address %DEFINES% %INCLUDES% ^
  /Febuild\test_p2_asan.exe tests\test_p2.cpp %BASE_SOURCES% ..\librelaycore\build\relaycore_asan.lib %BASE_LIBS% /link /INCREMENTAL:NO
if errorlevel 1 (echo RELAYEDGE P2 ASAN BUILD FAILED & exit /b 1)
build\test_p2_asan.exe "%CERT%" "%KEY%" "%CA%"
if errorlevel 1 exit /b 1

echo RELAYEDGE P2 GATE BUILD PASS
exit /b 0
