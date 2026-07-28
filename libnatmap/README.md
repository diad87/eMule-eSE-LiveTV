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

cl /nologo /EHsc /W4 /std:c++17 /Iinclude /Febuild\test_mapper_result.exe `
   tests\test_mapper_result.cpp src\mapper_result.cpp
build\test_mapper_result.exe

cl /nologo /EHsc /W4 /std:c++17 /Iinclude /Febuild\test_mapping_request.exe `
   tests\test_mapping_request.cpp src\mapper_result.cpp `
   src\mapping_request.cpp
build\test_mapping_request.exe

cl /nologo /EHsc /W4 /std:c++17 /Iinclude `
   /Febuild\test_legacy_mapper_projection.exe `
   tests\test_legacy_mapper_projection.cpp src\mapper_result.cpp `
   src\legacy_mapper_projection.cpp
build\test_legacy_mapper_projection.exe

cl /nologo /EHsc /W4 /std:c++17 /Iinclude `
   /Febuild\test_mapping_result_mailbox.exe `
   tests\test_mapping_result_mailbox.cpp src\mapper_result.cpp `
   src\mapping_request.cpp src\mapping_result_mailbox.cpp
build\test_mapping_result_mailbox.exe

cl /nologo /EHsc /W4 /std:c++17 /Iinclude `
   /Febuild\test_upnp_discovery.exe `
   tests\test_upnp_discovery.cpp src\upnp_discovery.cpp
build\test_upnp_discovery.exe

cl /nologo /EHsc /W4 /std:c++17 /Iinclude `
   /Febuild\test_upnp_mapping_result.exe `
   tests\test_upnp_mapping_result.cpp src\mapper_result.cpp `
   src\mapping_request.cpp src\upnp_mapping_result.cpp
build\test_upnp_mapping_result.exe

cl /nologo /EHsc /W4 /std:c++17 /Iinclude `
   /Febuild\test_upnp_lease_policy.exe `
   tests\test_upnp_lease_policy.cpp src\upnp_lease_policy.cpp
build\test_upnp_lease_policy.exe

cl /nologo /EHsc /W4 /std:c++17 /Iinclude `
   /Febuild\test_upnp_recovery_policy.exe `
   tests\test_upnp_recovery_policy.cpp src\ownership_ledger.cpp `
   src\upnp_recovery_policy.cpp
build\test_upnp_recovery_policy.exe

cl /nologo /EHsc /W4 /std:c++17 /Iinclude `
   /Fe..\tools\build\natmap_ownership_inspect.exe `
   ..\tools\natmap_ownership_inspect.cpp src\ownership_ledger.cpp
```

`MapperResult` is the value-only worker-to-main-thread boundary shared by
UPnP IGD, PCP and NAT-PMP. It snapshots an atomic TCP/UDP result, request and
explicit topology generation, mapper/source, granted endpoints, lease/epoch,
ownership proof, verification evidence and normalized reason. Structural
validity is deliberately separate from publication: partial mappings, stale
generations and private/CGNAT external addresses remain diagnosable but can
never be advertised as a verified route.

The main-thread mapping coordinator owns exactly one non-copyable
`MappingRequestSequence`, which issues nonzero monotonically increasing request
IDs without wraparound. Its non-copyable `MappingResultGate` binds one pending
request to its topology generation and typed operation (initial, refresh or
delete), rejects stale/mismatched responses without displacing a newer request,
and consumes a matching result exactly once.

`ProjectLegacyMapperObservation` is the narrow G04 migration seam used while
the native mapper producers move to strict common results. It projects only
the fields consumed by the pre-v9.2 callback, never marks an endpoint verified,
and is removed after the UPnP, PCP and NAT-PMP integrations stop using the
legacy observer.

`MappingResultMailbox` is the bounded value mailbox used by G04. A mapper
publishes an immutable snapshot and receives a nonzero 31-bit delivery ID.
The UI takes that exact ID, so out-of-order messages or an implementation
switch cannot redirect a callback to another mapper. Delivery IDs never wrap.

`UpnpDiscoverySelection` is the pure H01 IGD-selection policy. It rejects
incomplete candidates, preserves the best usable fallback, stops at a
connected or private first-layer IGD, and makes exhausted discovery and
cancellation terminal. It owns no miniupnpc pointers; the mapper moves URLs
only after the policy accepts a candidate.

`BuildUpnpPairMapperResult` is the H02 atomic boundary. A created or renewed
result requires exact owned readback for both TCP and UDP, a nonzero ownership
identity digest, complete request/topology correlation and concrete local,
gateway and granted endpoints. Every other observation becomes a zero-mapping
failure. `ShouldRollbackUpnpMappingAfterAtomicFailure` authorizes rollback for
TCP or UDP only when exact owned readback and `created_by_operation` prove that
the current atomic operation created that mapping. Pre-existing or merely
renewed mappings are never rollback candidates.

`EvaluateUpnpExistingLease` and `EvaluateUpnpLeaseAttempt` are the pure H03
lease boundary. They keep the finite-then-permanent request sequence explicit,
reuse a readable permanent mapping as a health-probe success, renew an owned
finite mapping, and classify a missing or incompatible readback for recreation.

`OwnershipJournalCommit` is the fail-closed H04 persistence-order guard. The
Windows host encodes even an empty ledger, writes a temporary file, flushes and
closes it, replaces the final path atomically with write-through semantics, and
then reopens, byte-compares and decodes the final file. Persistence is reported
only after that final verification step.

`EvaluateUpnpRecovery` is the pure H05 crash-recovery gate. Only an exact
owned readback authorizes router deletion. An absent, mismatched or
different-gateway rule drops only the local proof through the durable journal
transaction; transient and unknown observations keep proof for a safe retry.

`IsUpnpCleanupAuthorized` is the H06 final delete boundary. It returns true
only when the local record is valid and gateway fingerprint, protocol,
external port, internal client, internal port and ownership description all
match the router readback. The Windows host also rejects unknown protocol
labels and retains proof when the current gateway identity is unavailable.

`SelectPcpRouteBinding` freezes the interface index, IPv4 client address and
gateway supplied by one host route snapshot. PCP uses that exact tuple for its
request body, socket interface, bind and destination; incomplete, malformed,
mixed-family or ambiguous tuples fail closed instead of triggering independent
rediscovery.

`PcpMappingIdentity` makes transport, internal port and the 96-bit MAP nonce
one immutable identity. Initialization rejects zero nonce material; renewal
must match the original transport and port and cannot silently replace or
cross-use the TCP and UDP nonces. A MAP with an ambiguous outcome or a failed
UNMAP retains that identity, and the Windows host blocks any replacement MAP
until exact cleanup is confirmed.
