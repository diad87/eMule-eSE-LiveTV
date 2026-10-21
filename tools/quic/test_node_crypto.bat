@echo off
setlocal
set "ESE_TEST_ARCH=%~1"
if "%ESE_TEST_ARCH%"=="" set "ESE_TEST_ARCH=x64"
if "%ESE_TEST_ARCH%"=="x64" goto arch_ok
if "%ESE_TEST_ARCH%"=="Win32" goto arch_ok
echo ERROR: architecture must be x64 or Win32
exit /b 2
:arch_ok
set "ESE_VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if "%ESE_TEST_ARCH%"=="Win32" set "ESE_VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars32.bat"
call "%ESE_VCVARS%" >nul 2>&1
if errorlevel 1 exit /b 1
pushd "%~dp0\..\.."
if not exist "tools\quic\build-%ESE_TEST_ARCH%" mkdir "tools\quic\build-%ESE_TEST_ARCH%"
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /DESE_LIVECRYPTO_STANDALONE_TEST /Fo"tools\quic\build-%ESE_TEST_ARCH%\\" /Fe"tools\quic\build-%ESE_TEST_ARCH%\test_node_binding_crypto.exe" tools\quic\test_node_binding_crypto.cpp srchybrid\EseNodeBindingCrypto.cpp srchybrid\EseChannelBinding.cpp srchybrid\LiveCrypto.cpp "cryptopp\%ESE_TEST_ARCH%\Output\Release\cryptlib.lib"
if errorlevel 1 goto failed
"tools\quic\build-%ESE_TEST_ARCH%\test_node_binding_crypto.exe"
if errorlevel 1 goto failed
popd
exit /b 0
:failed
popd
exit /b 1
