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
header = source("srchybrid/UPnPImplPCP.h")
result = pcp[
    pcp.index("natmap::MapperResultData CUPnPImplPCP::BuildMapperResultData(")
    : pcp.index("void CUPnPImplPCP::StopAsyncFind()")
]
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
require(
    "virtual natmap::MapperResultData BuildMapperResultData(" in header,
    "the public PCP result must pass through the ownership-aware override",
)
require(
    result.count("CUPnPImpl::BuildMapperResultData(operation)") == 1
    and result.count("data.gateway.port = PCP_PORT;") == 1,
    "the PCP result must delegate once and set its service port exactly once",
)
require(
    result.index("CUPnPImpl::BuildMapperResultData(operation)")
    < result.index("data.gateway.port = PCP_PORT;")
    < result.index("m_tcpIdentity.Matches("),
    "the gateway endpoint must be complete before ownership is considered",
)
require(
    "m_tcpIdentity.Matches(\n"
    "\t\t\tnatmap::Transport::Tcp, m_nTCPPort)" in result
    and "m_udpIdentity.Matches(\n"
    "\t\t\tnatmap::Transport::Udp, m_nUDPPort)" in result
    and "m_tcpExternalAddress != m_udpExternalAddress" in result,
    "ownership must correlate both identities and one atomic public address",
)
require(
    "data.ownership_nonce = m_tcpIdentity.nonce;" in result,
    "the PCP result must carry the TCP ownership nonce required by admission",
)
require(
    "data.ownership_identity_digest.fill(0);" in result
    and "std::copy(m_tcpIdentity.nonce.begin(), m_tcpIdentity.nonce.end(),"
    in result
    and "std::copy(m_udpIdentity.nonce.begin(), m_udpIdentity.nonce.end(),"
    in result,
    "the composite identity must bind the exact TCP and UDP nonces",
)
require(
    result.index("m_tcpIdentity.Matches(")
    < result.index("data.ownership = natmap::OwnershipState::OwnedByUs;")
    and result.index("m_udpIdentity.Matches(")
    < result.index("data.ownership = natmap::OwnershipState::OwnedByUs;"),
    "ownership must only be elevated after both correlations succeed",
)
require(
    "DebugLog" not in result and "AddLogLine" not in result,
    "PCP ownership material must never be written to logs",
)

print("test_v92_l02_pcp_ownership: 16 checks, 0 failures")
