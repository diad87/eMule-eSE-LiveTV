# libnatmap

Pure C++17 contracts and deterministic policy for eMule direct reachability.
The library owns no sockets, threads, MFC objects, router credentials or UI.
Network effects are supplied by the host and represented as value results tied
to a monotonically increasing generation.

The D0 harness models IGD, PCP, NAT-PMP and an eD2K callback without touching
the network. Production integration remains disabled until D1.

## Standalone D0 test

From an MSVC developer prompt:

```powershell
New-Item -ItemType Directory -Force build | Out-Null
cl /nologo /EHsc /W4 /std:c++17 /Iinclude /Febuild\test_d0_contracts.exe tests\test_d0_contracts.cpp
build\test_d0_contracts.exe

cl /nologo /EHsc /W4 /std:c++17 /Iinclude /Febuild\test_state_machine.exe `
   tests\test_state_machine.cpp src\natmap_state.cpp
build\test_state_machine.exe

cl /nologo /EHsc /W4 /std:c++17 /Iinclude /Febuild\test_mapping_codecs.exe `
   tests\test_mapping_codecs.cpp src\natpmp_codec.cpp src\pcp_codec.cpp
build\test_mapping_codecs.exe

cl /nologo /EHsc /W4 /std:c++17 /Iinclude /Febuild\test_lease_policy.exe `
   tests\test_lease_policy.cpp src\natmap_policy.cpp
build\test_lease_policy.exe

cl /nologo /EHsc /W4 /std:c++17 /Iinclude /Febuild\test_nat_chain.exe `
   tests\test_nat_chain.cpp src\natmap_policy.cpp src\natmap_chain.cpp
build\test_nat_chain.exe

cl /nologo /EHsc /W4 /std:c++17 /Iinclude /Febuild\test_ownership_ledger.exe `
   tests\test_ownership_ledger.cpp src\ownership_ledger.cpp
build\test_ownership_ledger.exe

cl /nologo /EHsc /W4 /std:c++17 /Iinclude `
   /Fe..\tools\build\natmap_ownership_inspect.exe `
   ..\tools\natmap_ownership_inspect.cpp src\ownership_ledger.cpp
```
