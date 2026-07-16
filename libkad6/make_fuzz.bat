@echo off
REM K6-0.8 deterministic parser-fuzz gate (MSVC x64, standalone, no MFC).
REM Optional: set KAD6_ASAN=1 to compile with AddressSanitizer.
REM Optional: set KAD6_FUZZ_ITERATIONS=N (must be >= 100000).
setlocal
set "HERE=%~dp0"
set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" (
  echo ERROR: vcvars64 not found at "%VCVARS%"
  exit /b 3
)
if "%KAD6_FUZZ_ITERATIONS%"=="" set "KAD6_FUZZ_ITERATIONS=100000"
set "EXTRA=/O2"
set "SUFFIX="
if "%KAD6_ASAN%"=="1" (
  set "EXTRA=/Od /Zi /fsanitize=address /DKAD6_FUZZ_ASAN=1"
  set "SUFFIX=_asan"
  REM MSVC ASan has no LeakSanitizer; Release RSS below is the leak-growth gate.
  set "ASAN_OPTIONS=quarantine_size_mb=16:thread_local_quarantine_size_kb=64"
)
call "%VCVARS%" >nul 2>&1
cd /d "%HERE%"
if not exist build mkdir build
cl /nologo /EHsc /W4 /std:c++17 %EXTRA% /Iinclude /Febuild\fuzz_runner%SUFFIX%.exe ^
  tests\fuzz\fuzz_runner.cpp tests\fuzz\fuzz_address.cpp ^
  tests\fuzz\fuzz_asn.cpp tests\fuzz\fuzz_bootstrap.cpp ^
  tests\fuzz\fuzz_frame.cpp tests\fuzz\fuzz_gateway.cpp tests\fuzz\fuzz_lease.cpp tests\fuzz\fuzz_path.cpp tests\fuzz\fuzz_publish.cpp tests\fuzz\fuzz_store.cpp ^
  tests\fuzz\fuzz_tags.cpp ^
  tests\fuzz\fuzz_ticket.cpp tests\fuzz\fuzz_records.cpp ^
  tests\fuzz\fuzz_routing.cpp tests\fuzz\fuzz_shaped.cpp ^
  src\kad6_address.cpp src\kad6_asn.cpp src\kad6_bootstrap.cpp src\kad6_endpoint.cpp ^
  src\kad6_frame.cpp src\kad6_gateway.cpp src\kad6_hints.cpp src\kad6_vep.cpp src\kad6_ed2k_policy.cpp ^
  src\kad6_lease.cpp src\kad6_path.cpp src\kad6_publish.cpp src\kad6_store.cpp ^
  src\kad6_tags.cpp src\kad6_ticket.cpp ^
  src\kad6_records.cpp src\kad6_routing.cpp src\kad6_shaped_bulk.cpp psapi.lib
if errorlevel 1 (echo FUZZ BUILD FAILED & exit /b 1)
echo --- running build\fuzz_runner%SUFFIX%.exe ---
build\fuzz_runner%SUFFIX%.exe --iterations %KAD6_FUZZ_ITERATIONS% --seed 0x4b4144365f463030
exit /b %errorlevel%
