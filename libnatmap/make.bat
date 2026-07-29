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
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Iinclude /Febuild\test_address_policy.exe tests\test_address_policy.cpp src\address_policy.cpp
if errorlevel 1 exit /b 1
build\test_address_policy.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Iinclude /Febuild\test_network_signature.exe tests\test_network_signature.cpp src\network_signature.cpp src\address_policy.cpp
if errorlevel 1 exit /b 1
build\test_network_signature.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Iinclude /Febuild\test_network_change.exe tests\test_network_change.cpp src\network_change.cpp src\natmap_state.cpp src\natmap_policy.cpp src\mapping_request.cpp src\mapper_result.cpp
if errorlevel 1 exit /b 1
build\test_network_change.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Iinclude /Febuild\test_mapping_recovery.exe tests\test_mapping_recovery.cpp src\natmap_policy.cpp
if errorlevel 1 exit /b 1
build\test_mapping_recovery.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Iinclude /Febuild\test_state_machine.exe tests\test_state_machine.cpp src\natmap_state.cpp
if errorlevel 1 exit /b 1
build\test_state_machine.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Iinclude /Febuild\test_false_highid.exe tests\test_false_highid.cpp src\natmap_state.cpp
if errorlevel 1 exit /b 1
build\test_false_highid.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Iinclude /Febuild\test_mapping_codecs.exe tests\test_mapping_codecs.cpp src\natpmp_codec.cpp src\pcp_codec.cpp
if errorlevel 1 exit /b 1
build\test_mapping_codecs.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Iinclude /Febuild\test_natpmp_gateway_policy.exe tests\test_natpmp_gateway_policy.cpp src\natpmp_gateway_policy.cpp src\natpmp_codec.cpp
if errorlevel 1 exit /b 1
build\test_natpmp_gateway_policy.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Iinclude /Febuild\test_natpmp_pair_transaction.exe tests\test_natpmp_pair_transaction.cpp src\natpmp_pair_transaction.cpp
if errorlevel 1 exit /b 1
build\test_natpmp_pair_transaction.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Iinclude /Febuild\test_natpmp_epoch_policy.exe tests\test_natpmp_epoch_policy.cpp src\natpmp_epoch_policy.cpp src\natpmp_codec.cpp
if errorlevel 1 exit /b 1
build\test_natpmp_epoch_policy.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Iinclude /Febuild\test_pcp_route_binding.exe tests\test_pcp_route_binding.cpp src\pcp_route_binding.cpp
if errorlevel 1 exit /b 1
build\test_pcp_route_binding.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Iinclude /Febuild\test_pcp_mapping_identity.exe tests\test_pcp_mapping_identity.cpp src\pcp_mapping_identity.cpp
if errorlevel 1 exit /b 1
build\test_pcp_mapping_identity.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Iinclude /Febuild\test_pcp_map_projection.exe tests\test_pcp_map_projection.cpp src\pcp_map_projection.cpp src\pcp_mapping_identity.cpp src\pcp_codec.cpp
if errorlevel 1 exit /b 1
build\test_pcp_map_projection.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Iinclude /Febuild\test_pcp_pair_transaction.exe tests\test_pcp_pair_transaction.cpp src\pcp_pair_transaction.cpp src\pcp_map_projection.cpp src\pcp_mapping_identity.cpp src\pcp_codec.cpp
if errorlevel 1 exit /b 1
build\test_pcp_pair_transaction.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Iinclude /Febuild\test_pcp_response_guard.exe tests\test_pcp_response_guard.cpp src\pcp_response_guard.cpp src\pcp_codec.cpp src\pcp_mapping_identity.cpp
if errorlevel 1 exit /b 1
build\test_pcp_response_guard.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Iinclude /Febuild\test_lease_policy.exe tests\test_lease_policy.cpp src\natmap_policy.cpp
if errorlevel 1 exit /b 1
build\test_lease_policy.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Iinclude /Febuild\test_nat_chain.exe tests\test_nat_chain.cpp src\natmap_policy.cpp src\natmap_chain.cpp src\address_policy.cpp
if errorlevel 1 exit /b 1
build\test_nat_chain.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Iinclude /Febuild\test_ownership_ledger.exe tests\test_ownership_ledger.cpp src\ownership_ledger.cpp
if errorlevel 1 exit /b 1
build\test_ownership_ledger.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Iinclude /Febuild\test_instance_isolation.exe tests\test_instance_isolation.cpp src\instance_isolation.cpp
if errorlevel 1 exit /b 1
build\test_instance_isolation.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Iinclude /Febuild\test_two_instance_isolation.exe tests\test_two_instance_isolation.cpp src\instance_isolation.cpp src\ownership_ledger.cpp src\pcp_mapping_identity.cpp src\natpmp_pair_transaction.cpp
if errorlevel 1 exit /b 1
build\test_two_instance_isolation.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Iinclude /Febuild\test_mapper_result.exe tests\test_mapper_result.cpp src\mapper_result.cpp
if errorlevel 1 exit /b 1
build\test_mapper_result.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Iinclude /Febuild\test_mapping_request.exe tests\test_mapping_request.cpp src\mapper_result.cpp src\mapping_request.cpp
if errorlevel 1 exit /b 1
build\test_mapping_request.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Iinclude /Febuild\test_legacy_mapper_projection.exe tests\test_legacy_mapper_projection.cpp src\mapper_result.cpp src\legacy_mapper_projection.cpp src\address_policy.cpp
if errorlevel 1 exit /b 1
build\test_legacy_mapper_projection.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Iinclude /Febuild\test_mapping_result_mailbox.exe tests\test_mapping_result_mailbox.cpp src\mapper_result.cpp src\mapping_request.cpp src\mapping_result_mailbox.cpp
if errorlevel 1 exit /b 1
build\test_mapping_result_mailbox.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Iinclude /Febuild\test_hostile_mapper_corpus.exe tests\test_hostile_mapper_corpus.cpp src\pcp_codec.cpp src\pcp_map_projection.cpp src\pcp_mapping_identity.cpp src\pcp_response_guard.cpp src\mapping_result_mailbox.cpp src\mapper_result.cpp src\mapping_request.cpp src\legacy_mapper_projection.cpp src\address_policy.cpp src\natpmp_epoch_policy.cpp src\natpmp_codec.cpp
if errorlevel 1 exit /b 1
build\test_hostile_mapper_corpus.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Iinclude /Febuild\test_upnp_discovery.exe tests\test_upnp_discovery.cpp src\upnp_discovery.cpp
if errorlevel 1 exit /b 1
build\test_upnp_discovery.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Iinclude /Febuild\test_upnp_mapping_result.exe tests\test_upnp_mapping_result.cpp src\mapper_result.cpp src\mapping_request.cpp src\upnp_mapping_result.cpp
if errorlevel 1 exit /b 1
build\test_upnp_mapping_result.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Iinclude /Febuild\test_upnp_lease_policy.exe tests\test_upnp_lease_policy.cpp src\upnp_lease_policy.cpp
if errorlevel 1 exit /b 1
build\test_upnp_lease_policy.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Iinclude /Febuild\test_upnp_recovery_policy.exe tests\test_upnp_recovery_policy.cpp src\ownership_ledger.cpp src\upnp_recovery_policy.cpp
if errorlevel 1 exit /b 1
build\test_upnp_recovery_policy.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /W4 /WX /std:c++17 /Febuild\test_miniupnpc_checked_copy.exe tests\test_miniupnpc_checked_copy.cpp
if errorlevel 1 exit /b 1
build\test_miniupnpc_checked_copy.exe
if errorlevel 1 exit /b 1
echo libnatmap complete gate: PASS
exit /b 0
