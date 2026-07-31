#!/usr/bin/env python3
"""Verify MOD-0.2 production-boundary characterization goldens.

This is intentionally a lexical structural verifier, not a replacement model
of C++ behavior. It reads the production translation units and fingerprints
the named function bodies using a comment/whitespace-insensitive token stream.
The separate source-bound production selftest is the executable golden; this
script is only its structural drift companion.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MATRIX = ROOT / "docs" / "architecture" / "mod02_characterization_matrix_v1.json"
INVENTORY = ROOT / "docs" / "architecture" / "mod01_architecture_inventory_v1.json"
GOLDENS = ROOT / "docs" / "architecture" / "mod02_characterization_goldens_v1.json"
BUILD_MANIFEST = ROOT / "docs" / "architecture" / "mod02_build_manifest_v1.json"
IDENTITY_HEADER = ROOT / "srchybrid" / "Mod02BuildIdentity.h"
CRITICAL_SOURCE_PATHS = [
    "srchybrid/EmuleDlg.cpp",
    "srchybrid/LiveTunnel.cpp", "srchybrid/LiveTunnel.h", "srchybrid/LiveTunnelBulkFacade.inl", "srchybrid/LiveTunnelBulkStatePort.h", "srchybrid/LiveTunnelBulkProxy.cpp", "srchybrid/LiveTunnelBulkProxy.h", "srchybrid/LiveTunnelBulkTransportAdapter.cpp", "srchybrid/LiveTunnelBulkTransportAdapter.h", "srchybrid/LiveTunnelSearchFacade.inl", "srchybrid/LiveTunnelSearchPort.h", "srchybrid/LiveTunnelSearchService.cpp", "srchybrid/LiveTunnelSearchService.h", "srchybrid/LiveTunnelCoordinatorFacade.cpp", "srchybrid/LiveTunnelCoordinatorFacade.h", "srchybrid/LiveTunnelCoordinatorMethods.inl", "srchybrid/LiveTunnelCoordinatorPort.h",
    "srchybrid/LiveCellQueue.cpp", "srchybrid/LiveCellQueue.h",
    "srchybrid/LiveTunnelFraming.cpp", "srchybrid/LiveTunnelFraming.h",
    "srchybrid/LiveHandshakeWire.cpp", "srchybrid/LiveHandshakeWire.h",
    "srchybrid/LiveRelayDispatcher.cpp", "srchybrid/LiveRelayDispatcher.h",
    "srchybrid/LiveExitServices.cpp", "srchybrid/LiveExitServices.h",
    "srchybrid/LiveRelayTypes.h",
    "srchybrid/LiveTunnelScheduler.cpp", "srchybrid/LiveTunnelScheduler.h",
    "srchybrid/LiveTunnelPeerState.cpp", "srchybrid/LiveTunnelPeerState.h",
    "srchybrid/LiveTunnelKadBridge.cpp", "srchybrid/LiveTunnelKadBridge.h",
    "srchybrid/LiveTunnelMetrics.cpp", "srchybrid/LiveTunnelMetrics.h",
    "srchybrid/LiveTunnelPending.cpp", "srchybrid/LiveTunnelPending.h",
    "srchybrid/LiveCircuitRegistry.cpp", "srchybrid/LiveCircuitRegistry.h",
    "srchybrid/LiveCircuitHandshake.cpp", "srchybrid/LiveCircuitHandshake.h",
    "srchybrid/LiveCircuit.cpp", "srchybrid/LiveCircuit.h",
    "srchybrid/WebServer.cpp", "srchybrid/WebServer.h",
    "srchybrid/WebSocket.cpp", "srchybrid/WebSocket.h",
    "srchybrid/WebRequestParser.cpp", "srchybrid/WebRequestParser.h",
    "srchybrid/WebAuthPolicy.cpp", "srchybrid/WebAuthPolicy.h",
    "srchybrid/WebRouteTable.cpp", "srchybrid/WebRouteTable.h",
    "srchybrid/WebRequestDispatch.cpp", "srchybrid/WebRequestDispatch.h",
    "srchybrid/WebTemplateRenderer.cpp", "srchybrid/WebTemplateRenderer.h", "srchybrid/WebHeaderFooter.cpp", "srchybrid/WebHeaderFooter.h",
    "srchybrid/WebServerListController.cpp", "srchybrid/WebServerListController.h",
    "srchybrid/WebApiSerializer.cpp", "srchybrid/WebApiSerializer.h",
    "srchybrid/WebTransferController.cpp", "srchybrid/WebTransferController.h",
    "srchybrid/WebSearchController.cpp", "srchybrid/WebSearchController.h",
    "srchybrid/WebSharedController.cpp", "srchybrid/WebSharedController.h",
    "srchybrid/WebStaticAssets.cpp", "srchybrid/WebStaticAssets.h",
    "srchybrid/WebSocketResponse.cpp", "srchybrid/WebSocketResponse.h",
    "srchybrid/WebDiagnostics.cpp", "srchybrid/WebDiagnostics.h",
    "srchybrid/eMule.tmpl",
    "srchybrid/ListenSocket.cpp",
    "srchybrid/LiveProtocol.h",
    "srchybrid/LivePackets.cpp", "srchybrid/LivePackets.h",
    "srchybrid/LiveStreamManager.cpp", "srchybrid/LiveStreamManager.h",
    "srchybrid/LiveBroadcastSession.cpp", "srchybrid/LiveBroadcastSession.h",
    "srchybrid/LiveViewerSession.cpp", "srchybrid/LiveViewerSession.h",
    "srchybrid/LivePeerSet.cpp", "srchybrid/LivePeerSet.h",
    "srchybrid/LiveChunkWindow.cpp", "srchybrid/LiveChunkWindow.h",
    "srchybrid/LiveStreamSecurity.cpp", "srchybrid/LiveStreamSecurity.h",
    "srchybrid/LiveStreamFanout.cpp", "srchybrid/LiveStreamFanout.h",
    "srchybrid/LiveFanoutTransportAdapter.cpp", "srchybrid/LiveFanoutTransportAdapter.h",
    "srchybrid/LiveStreamRecovery.cpp", "srchybrid/LiveStreamRecovery.h",
    "srchybrid/LiveRecoveryTransportAdapter.cpp", "srchybrid/LiveRecoveryTransportAdapter.h",
    "srchybrid/LiveStreamAnnouncer.cpp", "srchybrid/LiveStreamAnnouncer.h",
    "srchybrid/LiveAnnounceTransportAdapter.cpp", "srchybrid/LiveAnnounceTransportAdapter.h",
    "srchybrid/LiveStreamSnapshot.cpp", "srchybrid/LiveStreamSnapshot.h",
    "srchybrid/LiveStreamTrustAdapter.cpp", "srchybrid/LiveStreamTrustAdapter.h",
    "srchybrid/ClientList.cpp", "srchybrid/ClientList.h",
    "srchybrid/LiveMeshManager.cpp", "srchybrid/LiveMeshManager.h",
    "srchybrid/LiveBuddyRelay.cpp", "srchybrid/LiveBuddyRelay.h",
    "srchybrid/LiveStreamDlgUI.cpp", "srchybrid/LiveStreamDlg.h",
]


def normalize_source_bytes(raw: bytes) -> bytes:
    """Return source bytes with platform-independent line endings."""
    return raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def tokenize(text: str) -> list[str]:
    tokens, index = [], 0
    while index < len(text):
        if text.startswith("//", index):
            newline = text.find("\n", index)
            index = len(text) if newline < 0 else newline + 1
        elif text.startswith("/*", index):
            end = text.find("*/", index + 2)
            index = len(text) if end < 0 else end + 2
        elif text[index].isspace():
            index += 1
        elif text[index].isalnum() or text[index] == "_":
            end = index + 1
            while end < len(text) and (text[end].isalnum() or text[end] == "_"):
                end += 1
            tokens.append(text[index:end]); index = end
        elif text[index] in "\"'":
            quote, end = text[index], index + 1
            while end < len(text):
                if text[end] == "\\": end += 2; continue
                if text[end] == quote: end += 1; break
                end += 1
            # Literal bytes are part of a protocol/security contract. Keep the
            # complete source literal (including quote/escapes) in the hash.
            tokens.append(text[index:end]); index = end
        else:
            tokens.append(text[index]); index += 1
    return tokens


def function_body(text: str, symbol: str) -> str:
    start = text.find(symbol + "(")
    if start < 0:
        raise ValueError(f"production symbol missing: {symbol}")
    brace = text.find("{", start)
    if brace < 0:
        raise ValueError(f"production body missing: {symbol}")
    depth = 0
    for index in range(brace, len(text)):
        if text[index] == "{": depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0: return text[start:index + 1]
    raise ValueError(f"unclosed production body: {symbol}")


def fingerprint(path: str, symbols: list[str], source_override: dict[str, str] | None = None) -> dict[str, str]:
    text = (source_override or {}).get(path)
    if text is None:
        text = (ROOT / path).read_text(encoding="utf-8", errors="replace")
    result = {}
    for symbol in symbols:
        stream = "\x1f".join(tokenize(function_body(text, symbol))).encode("utf-8")
        result[symbol] = hashlib.sha256(stream).hexdigest()
    return result


def actual(goldens: dict, source_override: dict[str, str] | None = None) -> dict:
    return {
        key: fingerprint(spec["production_file"], spec["symbols"], source_override)
        for key, spec in goldens["goldens"].items()
    }


def source_identity() -> str:
    lines = [
        f"{path}={hashlib.sha256(normalize_source_bytes((ROOT / path).read_bytes())).hexdigest()}"
        for path in CRITICAL_SOURCE_PATHS
    ]
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def verify_build_identity() -> None:
    manifest = json.loads(BUILD_MANIFEST.read_text(encoding="utf-8"))
    if set(manifest) != {
        "schema", "source_commit", "source_identity_sha256", "executable_sha256",
    } or manifest["schema"] != "ese.mod02.build-manifest/v1":
        raise ValueError("MOD-0.2 build manifest schema is not exact")
    current = source_identity()
    if manifest["source_identity_sha256"] != current:
        raise ValueError("MOD-0.2 build manifest source identity is stale")
    header = IDENTITY_HEADER.read_text(encoding="utf-8")
    match = re.search(r'ESE_MOD02_CRITICAL_SOURCE_SHA256\s+"([0-9a-f]{64})"', header)
    if match is None or match.group(1) != current:
        raise ValueError("MOD-0.2 build identity header does not match critical sources")


def verify() -> None:
    matrix = json.loads(MATRIX.read_text(encoding="utf-8"))
    inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))
    goldens = json.loads(GOLDENS.read_text(encoding="utf-8"))
    rows = matrix["rows"]
    if len(rows) != 9 or {row["coordinator"] for row in rows} != {"CLiveTunnel", "CWebServer", "CLiveStreamManager"}:
        raise ValueError("MOD-0.2 must cover exactly the nine MOD-0.1 seams")
    if any(row["runner"] == "simple_regex" or row["execution_kind"] == "algorithm_replica" for row in rows):
        raise ValueError("MOD-0.2 rejects regex-only or duplicated-algorithm runners")
    expected_pairs = Counter(
        (record["owner"], seam["file"])
        for record in inventory["monoliths"]
        for seam in record["existing_test_seams"]
    )
    actual_pairs = Counter((row["coordinator"], row["seam"]) for row in rows)
    if actual_pairs != expected_pairs or any(count != 1 for count in actual_pairs.values()):
        raise ValueError("MOD-0.2 rows must be the exact owner/seam multiset from MOD-0.1")
    if any(row["golden"] not in goldens["goldens"] for row in rows):
        raise ValueError("MOD-0.2 row references a missing structural golden")
    verify_build_identity()
    if actual(goldens) != {key: spec["token_sha256"] for key, spec in goldens["goldens"].items()}:
        raise ValueError("production structural characterization drifted; regenerate only after review")


def negative() -> None:
    goldens = json.loads(GOLDENS.read_text(encoding="utf-8"))
    spec = goldens["goldens"]["web_live_dispatch"]
    path = spec["production_file"]
    original = (ROOT / path).read_text(encoding="utf-8", errors="replace")
    start = original.find("void CWebServer::_ProcessLiveAPI(")
    if start < 0:
        raise ValueError("negative fixture could not locate _ProcessLiveAPI")
    marker = "WebRouteId::ApiLiveStream"
    offset = original.find(marker, start)
    if offset < 0:
        raise ValueError("negative fixture could not alter live-stream route ID")
    mutated = (
        original[:offset]
        + "WebRouteId::ApiLiveDebug"
        + original[offset + len(marker):]
    )
    if fingerprint(path, spec["symbols"], {path: mutated}) == spec["token_sha256"]:
        raise ValueError("literal mutation escaped the characterization gate")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--negative-fixture", action="store_true")
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    if sum((args.verify, args.negative_fixture, args.write)) != 1:
        parser.error("choose exactly one mode")
    try:
        if args.write:
            goldens = json.loads(GOLDENS.read_text(encoding="utf-8"))
            for key, spec in goldens["goldens"].items():
                spec["token_sha256"] = fingerprint(spec["production_file"], spec["symbols"])
            GOLDENS.write_text(
                json.dumps(goldens, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
                newline="\n",
            )
        elif args.verify:
            verify()
        else:
            negative()
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"MOD-0.2 FAIL: {error}")
        return 1
    print("MOD-0.2 structural gate PASS; runtime verdict belongs to run_mod02_stream_selftest.ps1")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
