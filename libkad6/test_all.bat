@echo off
REM Complete standalone libkad6 gate. Every child returns non-zero on failure.
setlocal
set "HERE=%~dp0"
cd /d "%HERE%"

call make.bat test_kad6_smoke tests\test_kad6_smoke.cpp
if errorlevel 1 exit /b 1
call make.bat test_kad6_address tests\test_kad6_address.cpp src\kad6_address.cpp
if errorlevel 1 exit /b 1
call make.bat test_kad6_asn tests\test_kad6_asn.cpp src\kad6_asn.cpp src\kad6_address.cpp
if errorlevel 1 exit /b 1
call make.bat test_kad6_bootstrap tests\test_kad6_bootstrap.cpp src\kad6_bootstrap.cpp src\kad6_records.cpp src\kad6_endpoint.cpp src\kad6_address.cpp
if errorlevel 1 exit /b 1
call make.bat test_kad6_role tests\test_kad6_role.cpp src\kad6_role.cpp src\kad6_records.cpp src\kad6_endpoint.cpp src\kad6_address.cpp
if errorlevel 1 exit /b 1
call make.bat test_kad6_frame tests\test_kad6_frame.cpp src\kad6_frame.cpp
if errorlevel 1 exit /b 1
call make.bat test_kad6_gateway tests\test_kad6_gateway.cpp src\kad6_gateway.cpp src\kad6_hints.cpp src\kad6_vep.cpp src\kad6_ed2k_policy.cpp src\kad6_ticket.cpp src\kad6_endpoint.cpp src\kad6_address.cpp
if errorlevel 1 exit /b 1
call make.bat test_kad6_tags tests\test_kad6_tags.cpp src\kad6_tags.cpp src\kad6_address.cpp
if errorlevel 1 exit /b 1
call make.bat test_kad6_ticket tests\test_kad6_ticket.cpp src\kad6_ticket.cpp src\kad6_endpoint.cpp src\kad6_address.cpp
if errorlevel 1 exit /b 1
call make.bat test_kad6_records tests\test_kad6_records.cpp src\kad6_records.cpp src\kad6_endpoint.cpp src\kad6_address.cpp
if errorlevel 1 exit /b 1
call make.bat test_kad6_shaped_bulk tests\test_kad6_shaped_bulk.cpp src\kad6_shaped_bulk.cpp
if errorlevel 1 exit /b 1
call make.bat test_kad6_shaper tests\test_kad6_shaper.cpp src\kad6_shaper.cpp
if errorlevel 1 exit /b 1
call make.bat test_kad6_path tests\test_kad6_path.cpp src\kad6_path.cpp src\kad6_address.cpp
if errorlevel 1 exit /b 1
call make.bat test_kad6_search tests\test_kad6_search.cpp src\kad6_search.cpp src\kad6_tags.cpp src\kad6_ticket.cpp src\kad6_endpoint.cpp src\kad6_address.cpp
if errorlevel 1 exit /b 1
call make.bat test_kad6_live_search tests\test_kad6_live_search.cpp src\kad6_live_search.cpp src\kad6_search.cpp src\kad6_tags.cpp src\kad6_ticket.cpp src\kad6_endpoint.cpp src\kad6_address.cpp
if errorlevel 1 exit /b 1
call make.bat test_kad6_economy tests\test_kad6_economy.cpp src\kad6_economy.cpp
if errorlevel 1 exit /b 1
call make.bat test_kad6_quota tests\test_kad6_quota.cpp src\kad6_quota.cpp
if errorlevel 1 exit /b 1
call make.bat test_kad6_exit_notice tests\test_kad6_exit_notice.cpp src\kad6_exit_notice.cpp src\kad6_tags.cpp src\kad6_address.cpp
if errorlevel 1 exit /b 1
call make.bat test_kad6_hardening tests\test_kad6_hardening.cpp src\kad6_hardening.cpp
if errorlevel 1 exit /b 1
call make.bat test_kad6_release tests\test_kad6_release.cpp src\kad6_release.cpp
if errorlevel 1 exit /b 1
call make.bat test_kad6_lease tests\test_kad6_lease.cpp src\kad6_lease.cpp src\kad6_endpoint.cpp src\kad6_address.cpp
if errorlevel 1 exit /b 1
call make.bat test_kad6_frontdoor tests\test_kad6_frontdoor.cpp src\kad6_frontdoor.cpp
if errorlevel 1 exit /b 1
call make.bat test_kad6_publish tests\test_kad6_publish.cpp src\kad6_publish.cpp src\kad6_tags.cpp src\kad6_address.cpp
if errorlevel 1 exit /b 1
call make.bat test_kad6_store tests\test_kad6_store.cpp src\kad6_store.cpp src\kad6_routing.cpp src\kad6_records.cpp src\kad6_endpoint.cpp src\kad6_address.cpp
if errorlevel 1 exit /b 1
call make.bat test_kad6_routing tests\test_kad6_routing.cpp src\kad6_routing.cpp src\kad6_records.cpp src\kad6_endpoint.cpp src\kad6_address.cpp
if errorlevel 1 exit /b 1
call make.bat test_kad6_vectors tests\test_kad6_vectors.cpp src\kad6_address.cpp src\kad6_endpoint.cpp src\kad6_frame.cpp src\kad6_tags.cpp src\kad6_ticket.cpp src\kad6_records.cpp src\kad6_shaped_bulk.cpp
if errorlevel 1 exit /b 1
call make_crypto_vectors.bat
if errorlevel 1 exit /b 1

python tools\check_kad6_vectors.py
if errorlevel 1 exit /b 1

set "KAD6_ASAN="
call make_fuzz.bat
if errorlevel 1 exit /b 1
set "KAD6_ASAN=1"
call make_fuzz.bat
if errorlevel 1 exit /b 1
set "KAD6_ASAN="

cd /d "%HERE%.."
python tools\check_protocol_registry.py
if errorlevel 1 exit /b 1

echo libkad6 complete gate: PASS
exit /b 0
