#!/usr/bin/env python3
"""L03 host contracts for session-only NAT-PMP cleanup authority."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def source(relative_path: str) -> str:
    return (
        (ROOT / relative_path)
        .read_bytes()
        .decode("latin-1")
        .replace("\r\n", "\n")
    )


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


natpmp = source("srchybrid/UPnPImplNATPMP.cpp")
header = source("srchybrid/UPnPImplNATPMP.h")
policy = source("libnatmap/src/natpmp_pair_transaction.cpp")
result = natpmp[
    natpmp.index("natmap::MapperResultData CUPnPImplNATPMP::BuildMapperResultData(")
    : natpmp.index("void CUPnPImplNATPMP::StartDiscovery(")
]
delete = natpmp[
    natpmp.index("void CUPnPImplNATPMP::DeletePorts(")
    : natpmp.index("void CUPnPImplNATPMP::StartDiscovery(")
]

require(
    "natmap::NatPmpCleanupProof m_cleanupProof;" in header
    and "Load" not in header[header.index("m_cleanupProof") :],
    "NAT-PMP cleanup proof must be session memory, never persisted ownership",
)
require(
    "proof.in_process_proof = true;" in natpmp
    and "proof.IsValid()" in natpmp,
    "only a structurally valid in-process mapping result may publish proof",
)
require(
    "context.gateway_address = gatewayAddress;" in delete
    and "context.interface_index = m_dwInterfaceIndex;" in delete
    and "context.generation = natmap::ResolveNatPmpCleanupGeneration("
    in delete,
    "cleanup must bind the current gateway, interface and generation",
)
require(
    "context.observed_monotonic_seconds" in delete
    and "NatPmpMonotonicSeconds()" in delete,
    "cleanup authorization must observe the monotonic lease deadline",
)
require(
    "natmap::TakeNatPmpCleanupPlan(" in delete
    and delete.index("TakeNatPmpCleanupPlan(")
    < delete.index("UnmapPort("),
    "the consumed ownership plan must be built before every NAT-PMP DELETE",
)
require(
    "if (!candidate.IsValid()) {\n"
    "        proof = NatPmpCleanupProof{};\n"
    "        return plan;\n"
    "    }" in policy
    and policy.index("proof = NatPmpCleanupProof{};\n    for (")
    < policy.index("NatPmpCleanupRequest request{};"),
    "cleanup authority must be consumed before any plan can be returned",
)
require(
    "request.observed_monotonic_seconds >=" in policy
    and "proof.expires_monotonic_seconds" in policy,
    "expired proof must fail closed so the router can expire it naturally",
)
require(
    "natmap-ownership.dat" not in natpmp
    and "CreateFile(" not in natpmp
    and "ReadFile(" not in natpmp,
    "NAT-PMP must not infer crash ownership from disk or port coincidence",
)
require(
    result.count("CUPnPImpl::BuildMapperResultData(operation)") == 1
    and result.count("data.gateway.port = NATPMP_PORT;") == 1,
    "the NAT-PMP result must delegate once and set its service port once",
)
require(
    result.index("CUPnPImpl::BuildMapperResultData(operation)")
    < result.index("data.gateway.port = NATPMP_PORT;")
    < result.index("BuildNatPmpOwnershipPreimage("),
    "the gateway endpoint must be complete before ownership is applied",
)
require(
    "static const uint16 NATPMP_PORT = 5351;" in header,
    "the NAT-PMP result must use the protocol service port",
)

print("test_v92_l03_natpmp_ownership: 11 checks, 0 failures")
