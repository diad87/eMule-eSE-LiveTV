from __future__ import annotations

import json
import pathlib
import subprocess
import unittest
import xml.etree.ElementTree as ET


ROOT = pathlib.Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "docs" / "architecture" / "mod36_live_stream_recovery_contract_v1.json"
HEADER = ROOT / "srchybrid" / "LiveStreamRecovery.h"
SOURCE = ROOT / "srchybrid" / "LiveStreamRecovery.cpp"
ADAPTER_HEADER = ROOT / "srchybrid" / "LiveRecoveryTransportAdapter.h"
ADAPTER_SOURCE = ROOT / "srchybrid" / "LiveRecoveryTransportAdapter.cpp"
MANAGER_HEADER = ROOT / "srchybrid" / "LiveStreamManager.h"
MANAGER_SOURCE = ROOT / "srchybrid" / "LiveStreamManager.cpp"
TUNNEL_SOURCE = ROOT / "srchybrid" / "LiveTunnel.cpp"
NATIVE_TEST = ROOT / "srchybrid" / "tests" / "test_live_stream_recovery.cpp"
MAKE = ROOT / "srchybrid" / "tests" / "make.bat"
PROJECT = ROOT / "srchybrid" / "emule.vcxproj"
SLICE_BASE = "03b8bb118d06b7d7407faaff0c7552b6ef51a2d1"


class Mod36LiveStreamRecoveryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))

    def test_contract_freezes_recovery_boundaries(self) -> None:
        self.assertEqual(
            self.contract["schema"],
            "ese.mod36.live-stream-recovery-contract/v1",
        )
        self.assertEqual(self.contract["baseline_commit"], SLICE_BASE)
        module = self.contract["module"]
        self.assertEqual(
            (module["name"], module["layer"], module["declared_direct_dependencies"]),
            ("LiveStreamRecovery", "application", []),
        )
        invariants = self.contract["invariants"]
        self.assertEqual(invariants["wire_format"], "byte_unchanged")
        self.assertEqual(invariants["inflight_capacity"], 64)
        self.assertEqual(invariants["missing_block_capacity"], 16)
        self.assertEqual(invariants["parity_range"], [2, 8])

    def test_module_is_portable_bounded_and_transport_free(self) -> None:
        text = HEADER.read_text(encoding="utf-8") + "\n" + SOURCE.read_text(
            encoding="utf-8"
        )
        for token in (
            "CString",
            "CArray",
            "CMap",
            "CSingleLock",
            "CCriticalSection",
            "CUpDownClient",
            "Packet",
            "CAddress",
            "LiveTunnel",
            "windows.h",
            "stdafx.h",
        ):
            self.assertNotIn(token, text)
        for marker in (
            "kInflightCapacity = 64u",
            "kMissingBlockCapacity = 16u",
            "kInflightTimeoutMs = 4000u",
            "kPeerLossGraceMs = 2000u",
            "kPeerRequestCooldownMs = 15000u",
            "kNackInitialDelayMs = 3000u",
            "kNackCooldownMs = 2000u",
            "inflight_.reserve(kInflightCapacity)",
            "InspectMissing(",
            "RecordRequest(",
            "CompleteRequest(",
            "ObservePeerHealth(",
            "MissingFecBlocks(",
            "AdvanceParity(",
            "NextAttempt(",
        ):
            self.assertIn(marker, text)

    def test_manager_delegates_retries_replenishment_and_emergency(self) -> None:
        header = MANAGER_HEADER.read_text(encoding="utf-8")
        source = MANAGER_SOURCE.read_text(encoding="utf-8")
        self.assertRegex(
            header,
            r"ese::live::LiveStreamRecovery\s+m_streamRecovery;",
        )
        for obsolete in (
            "m_peerRefreshPolicy",
            "m_inflightSegReqs",
            "m_bEmergencyMode",
            "m_dwEmergencyStart",
            "struct InflightSegReq",
        ):
            self.assertNotIn(obsolete, header + "\n" + source)
        for marker in (
            "m_streamRecovery.ResetViewer(",
            "m_streamRecovery.ShouldRequestPeers(",
            "m_streamRecovery.TakePeerCandidate(",
            "m_streamRecovery.OnSourceLost(",
            "m_streamRecovery.IsPeerRefreshPending(",
            "m_streamRecovery.ObservePeerHealth(",
            "m_streamRecovery.PruneRequests(",
            "m_streamRecovery.InspectMissing(",
            "m_streamRecovery.RecordRequest(",
            "m_streamRecovery.CompleteRequest(",
        ):
            self.assertIn(marker, source)
        self.assertIn("LiveRecoveryTransportAdapter::EndpointOf(", source)
        self.assertIn("CUpDownClient", ADAPTER_SOURCE.read_text(encoding="utf-8"))
        self.assertNotIn("CUpDownClient", HEADER.read_text(encoding="utf-8"))

    def test_tunnel_consumes_fec_and_nack_policy_without_wire_changes(self) -> None:
        tunnel = TUNNEL_SOURCE.read_text(encoding="utf-8")
        for marker in (
            "LiveStreamRecovery::ShouldSendNack(",
            "LiveStreamRecovery::MissingFecBlocks(",
            "LiveStreamRecovery::AdvanceParity(",
            "Bulk::BulkDecodeSegment(",
            "Bulk::BulkEncodeSegment(",
        ):
            self.assertIn(marker, tunnel)

    def test_native_cases_cover_loss_recovery_and_boundaries(self) -> None:
        native = NATIVE_TEST.read_text(encoding="utf-8")
        for marker in (
            "typed IPv4 and IPv6 recovery endpoints are bounded and distinct",
            "in-flight request is suppressed before its exact deadline",
            "timed-out edge request rotates away and charges exactly once",
            "repeated inspection never double-charges a timed-out request",
            "in-flight capacity failure is atomic",
            "request attempt counter saturates without wrapping",
            "in-flight deadline survives uint32 clock wrap",
            "source replenishment observes grace and cooldown",
            "source-loss grace survives uint32 clock wrap",
            "emergency exits even after every super-seeder disappears",
            "NACK initial delay and cooldown use strict wire-compatible boundaries",
            "missing FEC block plan is ordered and capped",
            "heavy NACK pressure saturates without overflow",
        ):
            self.assertIn(marker, native)

    def test_release_and_standalone_compile_the_exact_module(self) -> None:
        make = MAKE.read_text(encoding="utf-8")
        for name in (
            "LiveStreamRecovery.cpp",
            "test_live_stream_recovery.cpp",
            "test_live_stream_recovery.exe",
        ):
            self.assertIn(name, make)

        root = ET.parse(PROJECT).getroot()
        ns = {"m": "http://schemas.microsoft.com/developer/msbuild/2003"}
        compiles = {
            item.attrib["Include"]: item
            for item in root.findall(".//m:ClCompile", ns)
            if "Include" in item.attrib
        }
        includes = {
            item.attrib["Include"]
            for item in root.findall(".//m:ClInclude", ns)
            if "Include" in item.attrib
        }
        self.assertIn("LiveStreamRecovery.cpp", compiles)
        self.assertIn("LiveRecoveryTransportAdapter.cpp", compiles)
        xml = ET.tostring(compiles["LiveStreamRecovery.cpp"], encoding="unicode")
        for marker in ("NotUsing", "Level4", "true", "stdcpp17"):
            self.assertIn(marker, xml)
        self.assertIn("LiveStreamRecovery.h", includes)
        self.assertIn("LiveRecoveryTransportAdapter.h", includes)

    def test_coordinator_slice_shrinks_and_wire_is_identical(self) -> None:
        diff = subprocess.run(
            [
                "git",
                "diff",
                "--numstat",
                SLICE_BASE,
                "--",
                "srchybrid/LiveStreamManager.cpp",
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        added, removed, _ = diff.split("\t")
        self.assertLess(int(added), int(removed))
        for path in (
            "srchybrid/LiveProtocol.h",
            "srchybrid/LivePackets.cpp",
            "srchybrid/LivePackets.h",
            "srchybrid/LiveTunnel.h",
        ):
            baseline = subprocess.run(
                ["git", "show", f"{SLICE_BASE}:{path}"],
                cwd=ROOT,
                check=True,
                capture_output=True,
            ).stdout
            normalize = lambda data: data.replace(b"\r\n", b"\n").replace(
                b"\r", b"\n"
            )
            self.assertEqual(normalize((ROOT / path).read_bytes()), normalize(baseline))


if __name__ == "__main__":
    unittest.main()
