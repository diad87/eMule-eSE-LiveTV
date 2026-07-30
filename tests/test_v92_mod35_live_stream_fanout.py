from __future__ import annotations

import json
import pathlib
import subprocess
import unittest
import xml.etree.ElementTree as ET


ROOT = pathlib.Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "docs" / "architecture" / "mod35_live_stream_fanout_contract_v1.json"
HEADER = ROOT / "srchybrid" / "LiveStreamFanout.h"
SOURCE = ROOT / "srchybrid" / "LiveStreamFanout.cpp"
ADAPTER_HEADER = ROOT / "srchybrid" / "LiveFanoutTransportAdapter.h"
ADAPTER_SOURCE = ROOT / "srchybrid" / "LiveFanoutTransportAdapter.cpp"
MANAGER_HEADER = ROOT / "srchybrid" / "LiveStreamManager.h"
MANAGER_SOURCE = ROOT / "srchybrid" / "LiveStreamManager.cpp"
NATIVE_TEST = ROOT / "srchybrid" / "tests" / "test_live_stream_fanout.cpp"
MAKE = ROOT / "srchybrid" / "tests" / "make.bat"
PROJECT = ROOT / "srchybrid" / "emule.vcxproj"
SLICE_BASE = "c476950d1590fb7f337cc3010e1a86bdee10537d"


class Mod35LiveStreamFanoutTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))

    def test_contract_freezes_fanout_boundaries(self) -> None:
        self.assertEqual(
            self.contract["schema"],
            "ese.mod35.live-stream-fanout-contract/v1",
        )
        self.assertEqual(self.contract["baseline_commit"], SLICE_BASE)
        module = self.contract["module"]
        self.assertEqual(
            (module["name"], module["layer"], module["declared_direct_dependencies"]),
            ("LiveStreamFanout", "application", []),
        )
        invariants = self.contract["invariants"]
        self.assertEqual(invariants["wire_format"], "byte_unchanged")
        self.assertEqual(invariants["child_capacity"], 64)
        self.assertEqual(invariants["reservation_capacity"], 256)
        self.assertEqual(invariants["peer_queue_limit_bytes"], 8 * 1024 * 1024)

    def test_module_is_portable_bounded_and_overflow_safe(self) -> None:
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
            "LiveProtocol",
            "windows.h",
            "stdafx.h",
        ):
            self.assertNotIn(token, text)
        for marker in (
            "kChildCapacity = 64u",
            "kReservationCapacity = 256u",
            "kPeerQueueLimitBytes = 8u * 1024u * 1024u",
            "children_.reserve(kChildCapacity)",
            "reservations_.reserve(kReservationCapacity)",
            "std::mutex",
            "SelectRecipients(",
            "BeginDelivery(",
            "CompleteDelivery(",
            "ReplaceChild(",
            "ReleaseChild(",
        ):
            self.assertIn(marker, text)
        self.assertIn(
            "external_queued_bytes > kPeerQueueLimitBytes - wire_bytes",
            SOURCE.read_text(encoding="utf-8"),
        )

    def test_manager_delegates_selection_reservation_and_close(self) -> None:
        header = MANAGER_HEADER.read_text(encoding="utf-8")
        source = MANAGER_SOURCE.read_text(encoding="utf-8")
        adapter = ADAPTER_SOURCE.read_text(encoding="utf-8")
        self.assertRegex(
            header,
            r"ese::live::LiveStreamFanout\s+m_streamFanout;",
        )
        self.assertIn("m_streamFanout.Clear(", source)
        for marker in (
            "fanout.RegisterChild(",
            "fanout.SelectRecipients(",
            "fanout.BeginDelivery(",
            "fanout.CompleteDelivery(",
            "fanout.ReplaceChild(",
            "fanout.ReleaseChild(",
        ):
            self.assertIn(marker, adapter)
        relay = source[
            source.index("// Proactive child delivery") :
            source.index("void CLiveStreamManager::OnPeerBitmap(")
        ]
        self.assertNotIn(
            "child->GetSocketQueuedBytes() > ESE_LIVE_MAX_PEER_QUEUE_BYTES",
            relay,
        )
        self.assertLess(relay.index("PrepareRelayBatches("), relay.index("lock.Unlock()"))
        self.assertLess(
            relay.index("lock.Unlock()"),
            relay.index("SendReserved("),
        )

    def test_native_cases_cover_slow_close_capacity_and_concurrency(self) -> None:
        native = NATIVE_TEST.read_text(encoding="utf-8")
        for marker in (
            "selection preserves registration order and caps children not fragments",
            "selection excludes sender, blocked and duplicate children",
            "child capacity failure does not partially mutate state",
            "exact whole-batch queue boundary is accepted",
            "one byte beyond the queue boundary is rejected atomically",
            "oversize and overflow-like queue inputs fail closed",
            "duplicate pending delivery is rejected",
            "whole-batch identity accepts uint32 sequence wrap",
            "reservation capacity failure does not partially mutate state",
            "replacement preserves pending delivery ownership",
            "slow child does not block a healthy sibling",
            "release cancels pending work and rejects future delivery",
            "concurrent reservation accounting remains bounded",
            "clear reclaims every child and reservation",
        ):
            self.assertIn(marker, native)

    def test_release_and_standalone_compile_the_exact_module(self) -> None:
        make = MAKE.read_text(encoding="utf-8")
        for name in (
            "LiveStreamFanout.cpp",
            "test_live_stream_fanout.cpp",
            "test_live_stream_fanout.exe",
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
        self.assertIn("LiveStreamFanout.cpp", compiles)
        self.assertIn("LiveFanoutTransportAdapter.cpp", compiles)
        xml = ET.tostring(compiles["LiveStreamFanout.cpp"], encoding="unicode")
        for marker in ("NotUsing", "Level4", "true", "stdcpp17"):
            self.assertIn(marker, xml)
        self.assertIn("LiveStreamFanout.h", includes)
        self.assertIn("LiveFanoutTransportAdapter.h", includes)

    def test_wire_definition_files_remain_byte_identical(self) -> None:
        for path in (
            "srchybrid/LiveProtocol.h",
            "srchybrid/LivePackets.cpp",
            "srchybrid/LivePackets.h",
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
