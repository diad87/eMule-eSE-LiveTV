@echo off
REM P3 Release + AddressSanitizer client state/lifetime gate.
setlocal
set "HERE=%~dp0"
set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" (echo ERROR: vcvars64 not found & exit /b 3)
call "%VCVARS%" >nul 2>&1
cd /d "%HERE%"
if not exist build mkdir build

set "INCLUDES=/Iinclude /I..\librelaycore\include"
set "SOURCES=src\relay_client.cpp"
set "EDGE_INCLUDES=/I..\relayedge\include /I..\mbedtls\include /I..\mbedtls\tf-psa-crypto\include /I..\mbedtls\tf-psa-crypto\drivers\builtin\include"
set "EDGE_DEFINES=/DMBEDTLS_THREADING_C /DMBEDTLS_THREADING_ALT"
set "EDGE_SOURCES=src\relay_wss_transport.cpp ..\relayedge\src\wss_h1.cpp ..\relayedge\src\wss_carrier.cpp ..\relayedge\src\tls_tcp_carrier.cpp ..\relayedge\src\krp_p4_crypto.cpp"
set "EDGE_LIBS=..\librelaycore\build\relaycore.lib ..\srchybrid\x64\Release\mbedTLS.lib ..\srchybrid\x64\Release\cryptlib.lib bcrypt.lib ws2_32.lib"
set "ASAN_EDGE_LIBS=..\librelaycore\build\relaycore_asan.lib ..\srchybrid\x64\Release\mbedTLS.lib bcrypt.lib ws2_32.lib"
set "P4_SERVICE_SOURCES=..\relayedge\src\edge_runtime.cpp ..\relayedge\src\edge_session_table.cpp ..\relayedge\src\edge_auth.cpp ..\relayedge\src\edge_policy.cpp ..\relayedge\src\edge_allocator.cpp ..\relayedge\src\edge_daemon.cpp ..\relayedge\src\krp_tcp_session.cpp"
set "CERT=..\mbedtls\framework\data_files\server2-sha256.crt"
set "KEY=..\mbedtls\framework\data_files\server2.key"
set "CA=..\mbedtls\framework\data_files\test-ca.crt"

cl /nologo /c /EHsc /O2 /W4 /WX /std:c++17 %INCLUDES% /Fo:build\relay_client.obj %SOURCES%
if errorlevel 1 (echo LIBRELAYCLIENT RELEASE COMPILE FAILED & exit /b 1)
lib /nologo /out:build\relayclient.lib build\relay_client.obj
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 %INCLUDES% /Febuild\test_relay_client.exe tests\test_relay_client.cpp build\relayclient.lib /link /LTCG
if errorlevel 1 (echo LIBRELAYCLIENT P3 TEST BUILD FAILED & exit /b 1)
build\test_relay_client.exe
if errorlevel 1 exit /b 1

cl /nologo /EHsc /O2 /W4 /WX /std:c++17 %EDGE_DEFINES% %INCLUDES% %EDGE_INCLUDES% ^
  /Febuild\test_relay_wss_transport.exe tests\test_relay_wss_transport.cpp %SOURCES% %EDGE_SOURCES% %EDGE_LIBS% /link /LTCG
if errorlevel 1 (echo LIBRELAYCLIENT P3 TLS/WSS TEST BUILD FAILED & exit /b 1)
build\test_relay_wss_transport.exe "%CERT%" "%KEY%" "%CA%"
if errorlevel 1 exit /b 1

cl /nologo /EHsc /O2 /W4 /WX /std:c++17 %EDGE_DEFINES% %INCLUDES% %EDGE_INCLUDES% ^
  /Febuild\test_p4_e2e.exe tests\test_p4_e2e.cpp %SOURCES% %EDGE_SOURCES% %P4_SERVICE_SOURCES% %EDGE_LIBS% /link /LTCG
if errorlevel 1 (echo LIBRELAYCLIENT P4 E2E BUILD FAILED & exit /b 1)
build\test_p4_e2e.exe "%CERT%" "%KEY%" "%CA%"
if errorlevel 1 exit /b 1

cl /nologo /EHsc /Od /Zi /W4 /WX /std:c++17 /fsanitize=address %INCLUDES% ^
  /Febuild\test_relay_client_asan.exe tests\test_relay_client.cpp %SOURCES% /link /INCREMENTAL:NO
if errorlevel 1 (echo LIBRELAYCLIENT P3 ASAN BUILD FAILED & exit /b 1)
build\test_relay_client_asan.exe
if errorlevel 1 exit /b 1

cl /nologo /EHsc /Od /Zi /W4 /WX /std:c++17 /fsanitize=address /DRELAYEDGE_DISABLE_ED25519 %EDGE_DEFINES% %INCLUDES% %EDGE_INCLUDES% ^
  /Febuild\test_relay_wss_transport_asan.exe tests\test_relay_wss_transport.cpp %SOURCES% %EDGE_SOURCES% %ASAN_EDGE_LIBS% /link /INCREMENTAL:NO
if errorlevel 1 (echo LIBRELAYCLIENT P3 TLS/WSS ASAN BUILD FAILED & exit /b 1)
build\test_relay_wss_transport_asan.exe "%CERT%" "%KEY%" "%CA%"
if errorlevel 1 exit /b 1

echo LIBRELAYCLIENT P3 GATE BUILD PASS
exit /b 0
