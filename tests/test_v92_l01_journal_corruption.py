#!/usr/bin/env python3
"""L01 host contracts for fail-closed UPnP ownership journal loading."""

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


miniupnp = source("srchybrid/UPnPImplMiniLib.cpp")
load = miniupnp[
    miniupnp.index("void CUPnPImplMiniLib::LoadOwnershipLedger()")
    : miniupnp.index("bool CUPnPImplMiniLib::SaveOwnershipLedger()")
]

require(
    "kOwnershipLedgerMaxEncodedSize" in load
    and "size.QuadPart) <= bytes.size()" in load,
    "the host must reject an oversized journal before reading it",
)
require(
    "DecodeOwnershipLedger(bytes.data(), read, m_ownershipLedger)" in load,
    "the host must use the checked codec for every readable journal",
)
require(
    "m_ownershipLedger = natmap::OwnershipLedger{};" in load,
    "an invalid journal must leave no ownership proof in memory",
)
require(
    "invalid journal ignored (status=%u)" in load,
    "journal rejection must emit a diagnostic status",
)
require(
    "::DeleteFile(path);" in load,
    "an invalid journal must be quarantined from later recovery attempts",
)
require(
    "DeletePortsForGeneration" not in load
    and "DeletePorts(" not in load,
    "loading or rejecting a journal must never delete a router mapping",
)

print("test_v92_l01_journal_corruption: 6 checks, 0 failures")
