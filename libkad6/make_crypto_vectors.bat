@echo off
REM K6-0.9 normative crypto vectors against the vendored Crypto++ x64 library.
setlocal
set "HERE=%~dp0"
set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
set "CRYPTLIB=%HERE%..\cryptopp\x64\Output\Release\cryptlib.lib"
if not exist "%VCVARS%" (echo ERROR: vcvars64 not found & exit /b 3)
if not exist "%CRYPTLIB%" (echo ERROR: Crypto++ Release x64 library not found & exit /b 4)
call "%VCVARS%" >nul 2>&1
cd /d "%HERE%"
if not exist build mkdir build
cl /nologo /EHsc /O2 /W4 /std:c++17 /Iinclude /I.. ^
  /Febuild\test_kad6_crypto_vectors.exe tests\test_kad6_crypto_vectors.cpp ^
  tests\support\kad6_cryptopp_test_adapter.cpp src\kad6_address.cpp ^
  src\kad6_endpoint.cpp src\kad6_ticket.cpp src\kad6_records.cpp "%CRYPTLIB%"
if errorlevel 1 (echo CRYPTO VECTOR BUILD FAILED & exit /b 1)
echo --- running build\test_kad6_crypto_vectors.exe ---
build\test_kad6_crypto_vectors.exe
if errorlevel 1 exit /b 1

cl /nologo /EHsc /O2 /W4 /std:c++17 /Iinclude /I.. /I..\srchybrid ^
  /Febuild\test_kad6_quota_crypto.exe tests\test_kad6_quota_crypto.cpp ^
  ..\srchybrid\Kad6QuotaCrypto.cpp ..\srchybrid\NodeIdentityStorage.cpp ^
  src\kad6_quota.cpp "%CRYPTLIB%"
if errorlevel 1 (echo QUOTA CRYPTO VECTOR BUILD FAILED & exit /b 1)
echo --- running build\test_kad6_quota_crypto.exe ---
build\test_kad6_quota_crypto.exe
if errorlevel 1 exit /b 1

cl /nologo /EHsc /O2 /W4 /std:c++17 /Iinclude /I.. /I..\srchybrid ^
  /Febuild\test_kad6_exit_notice_server.exe tests\test_kad6_exit_notice_server.cpp ^
  ..\srchybrid\Kad6ExitNoticeServer.cpp ws2_32.lib
if errorlevel 1 (echo EXIT NOTICE SERVER BUILD FAILED & exit /b 1)
echo --- running build\test_kad6_exit_notice_server.exe ---
build\test_kad6_exit_notice_server.exe
exit /b %errorlevel%
