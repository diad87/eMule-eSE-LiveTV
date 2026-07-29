#!/usr/bin/env python3
"""L02 host contracts for nonce- and gateway-bound PCP cleanup."""

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


pcp = source("srchybrid/UPnPImplPCP.cpp")
unmap = pcp[
    pcp.index("bool CUPnPImplPCP::UnmapPort(")
    : pcp.index("typedef CUPnPImplPCP::CStartDiscoveryThread")
]
exchange = pcp[
    pcp.index("bool CUPnPImplPCP::ExchangeMap(")
    : pcp.index("bool CUPnPImplPCP::MapPort(")
]
delete = pcp[
    pcp.index("bool CUPnPImplPCP::DeletePorts(bool bSkipLock)")
    : pcp.index("bool CUPnPImplPCP::GenerateNonce(")
]

require(
    "if (!identity.IsValid())" in unmap,
    "cleanup must reject missing or corrupt PCP ownership material",
)
require(
    "request.nonce = identity.nonce;" in unmap
    and "request.internal_port = identity.internal_port;" in unmap,
    "DELETE must use the exact owned nonce and internal port",
)
require(
    "ExchangeMap(\n"
    "\t\tnGatewayIP, nInterfaceIndex, bindAddress,\n"
    "\t\trequest, response, true)" in unmap,
    "DELETE must remain bound to its captured gateway, interface and LAN bind",
)
require(
    "expectation.source_address" in exchange
    and "expectation.nonce = request.nonce;" in exchange,
    "the response guard must bind source gateway and nonce",
)
require(
    "DecodePcpMapResponse(raw," in exchange
    and "ValidatePcpResponseObservation(" in exchange,
    "DELETE responses must pass codec correlation and the live guard",
)
require(
    "if (bDeletion) {\n"
    "\t\t\t\tsucceeded = natmap::EvaluatePcpCleanupCommit(" in exchange
    and "== natmap::PcpCleanupCommitStatus::Commit;" in exchange,
    "cleanup may mutate ownership only through the checked commit decision",
)
require(
    delete.count("ValidatePcpMappingIdentity(") == 5
    and delete.count("UnmapPort(") == 5,
    "both upstream and CPE transports plus optional web cleanup must each validate before unmapping",
)
require(
    "Refusing refresh because the route-bound gateway/client pair changed"
    in pcp,
    "a remap or refresh must reject a changed gateway/client route",
)

print("test_v92_l02_pcp_ownership: 8 checks, 0 failures")
