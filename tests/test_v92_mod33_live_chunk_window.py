"""MOD-3.3 host contract for bounded chunk-window extraction."""

from __future__ import annotations

import json
import pathlib
import re
import subprocess
import unittest
import xml.etree.ElementTree as ET


ROOT = pathlib.Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "docs" / "architecture" / "mod33_live_chunk_window_contract_v1.json"
HEADER = ROOT / "srchybrid" / "LiveChunkWindow.h"
SOURCE = ROOT / "srchybrid" / "LiveChunkWindow.cpp"
LEGACY_HEADER = ROOT / "srchybrid" / "LiveChunkBuffer.h"
LEGACY_SOURCE = ROOT / "srchybrid" / "LiveChunkBuffer.cpp"
MANAGER_HEADER = ROOT / "srchybrid" / "LiveStreamManager.h"
MANAGER_SOURCE = ROOT / "srchybrid" / "LiveStreamManager.cpp"
MESH_SOURCE = ROOT / "srchybrid" / "LiveMeshManager.cpp"
NATIVE_TEST = ROOT / "srchybrid" / "tests" / "test_live_chunk_window.cpp"
MAKE = ROOT / "srchybrid" / "tests" / "make.bat"
PROJECT = ROOT / "srchybrid" / "emule.vcxproj"
SLICE_BASE = "d032418e65a2dc64c726c46a275e5841a9a34874"


class Mod33LiveChunkWindowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))

    def test_contract_freezes_scope_and_window_rules(self) -> None:
        self.assertEqual(
            self.contract["schema"],
            "ese.mod33.live-chunk-window-contract/v1",
        )
        self.assertEqual(self.contract["baseline_commit"], SLICE_BASE)
        module = self.contract["module"]
        self.assertEqual(
            (module["name"], module["layer"], module["declared_direct_dependencies"]),
            ("LiveChunkWindow", "domain_state", []),
        )
        invariants = self.contract["invariants"]
        self.assertEqual(invariants["capacity"], 15)
        self.assertEqual(invariants["maximum_chunk_bytes"], 12 * 1024 * 1024)
        self.assertEqual(
            invariants["expiry"],
            "every_chunk_outside_the_latest_15_serial_positions_is_unavailable",
        )
        self.assertEqual(invariants["wire_format"], "unchanged")

    def test_module_is_portable_immutable_and_callback_safe(self) -> None:
        text = HEADER.read_text(encoding="utf-8") + "\n" + SOURCE.read_text(
            encoding="utf-8"
        )
        for token in (
            "CString",
            "CCriticalSection",
            "CSingleLock",
            "CLiveStreamManager",
            "LiveProtocol",
            "LivePackets",
            "SOCKET",
            "HANDLE",
            "windows.h",
            "stdafx.h",
        ):
            self.assertNotIn(token, text)
        self.assertIn("std::shared_ptr<const LiveChunkRecord>", text)
        self.assertIn("std::mutex", text)
        self.assertIn("GetSegment(sequence_number)", text)
        self.assertLess(
            text.index("GetSegment(sequence_number)"),
            text.index("callback(*chunk)"),
        )
        self.assertLessEqual(len(HEADER.read_text(encoding="utf-8").splitlines()), 180)
        self.assertLessEqual(len(SOURCE.read_text(encoding="utf-8").splitlines()), 300)

    def test_manager_owns_two_windows_and_legacy_buffer_is_retired(self) -> None:
        header = MANAGER_HEADER.read_text(encoding="utf-8")
        source = MANAGER_SOURCE.read_text(encoding="utf-8")
        manager = header + "\n" + source
        self.assertRegex(
            header,
            r"ese::live::LiveChunkWindow\s+m_chunkBuffer;",
        )
        self.assertRegex(
            header,
            r"ese::live::LiveChunkWindow\s+m_broadcastChunkBuffer;",
        )
        self.assertNotIn("CLiveChunkBuffer", manager + MESH_SOURCE.read_text(encoding="utf-8"))
        self.assertFalse(LEGACY_HEADER.exists())
        self.assertFalse(LEGACY_SOURCE.exists())
        for call in (
            ".AddSegment(",
            ".WithSegment(",
            ".GetOldestSeq(",
            ".GetNewestSeq(",
            ".GetBitmap(",
            ".Clear(",
        ):
            self.assertIn(call, source)
        for bounded_marker in (
            "windowSpan",
            "pushSpan",
            "relaySpan",
            "requestSpan",
            "m_hasRelayedSeq",
            "LiveChunkWindow::IsNewerSequence(",
        ):
            self.assertIn(bounded_marker, manager)
        for unsafe_loop in (
            "seq <= newest",
            "seq <= newestSeq + lookahead",
            "seq <= newest + 2",
            "m_lastRelayedSeq == UINT_MAX",
        ):
            self.assertNotIn(unsafe_loop, manager + MESH_SOURCE.read_text(encoding="utf-8"))

    def test_release_and_standalone_build_the_exact_module(self) -> None:
        make = MAKE.read_text(encoding="utf-8")
        for name in (
            "LiveChunkWindow.cpp",
            "test_live_chunk_window.cpp",
            "test_live_chunk_window.exe",
        ):
            self.assertIn(name, make)

        root = ET.parse(PROJECT).getroot()
        namespace = {"m": "http://schemas.microsoft.com/developer/msbuild/2003"}
        compile_items = {
            item.attrib["Include"]: item
            for item in root.findall(".//m:ClCompile", namespace)
            if "Include" in item.attrib
        }
        include_items = {
            item.attrib["Include"]
            for item in root.findall(".//m:ClInclude", namespace)
            if "Include" in item.attrib
        }
        self.assertNotIn("LiveChunkBuffer.cpp", compile_items)
        self.assertIn("LiveChunkWindow.cpp", compile_items)
        xml = ET.tostring(compile_items["LiveChunkWindow.cpp"], encoding="unicode")
        for marker in ("NotUsing", "Level4", "true", "stdcpp17"):
            self.assertIn(marker, xml)
        self.assertNotIn("LiveChunkBuffer.h", include_items)
        self.assertIn("LiveChunkWindow.h", include_items)

    def test_native_cases_cover_reorder_expiry_jump_wrap_and_lifetime(self) -> None:
        native = NATIVE_TEST.read_text(encoding="utf-8")
        for marker in (
            "reordered chunk inside the serial window is accepted",
            "large jump expires every prior chunk",
            "serial order accepts uint32 wrap",
            "half-range serial ambiguity fails closed",
            "peer bitmap selects every advertised segment across uint32 wrap",
            "prior snapshots stay valid",
            "external callback runs without the internal lock",
            "oversized bytes fail before allocation",
        ):
            self.assertIn(marker, native)

    def test_wire_files_are_unchanged_and_coordinator_does_not_grow(self) -> None:
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
            normalize = lambda data: data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
            self.assertEqual(normalize((ROOT / path).read_bytes()), normalize(baseline))

    def test_peer_bitmap_and_request_path_are_serial_wrap_safe(self) -> None:
        protocol = (ROOT / "srchybrid/LiveProtocol.h").read_text(encoding="utf-8")
        manager = MANAGER_SOURCE.read_text(encoding="utf-8")
        mesh = MESH_SOURCE.read_text(encoding="utf-8")
        self.assertIn("if (seqNum < oldestSeq) return false;", protocol)
        self.assertNotIn(".Has(", manager + mesh)
        self.assertGreaterEqual(
            (manager + mesh).count("LiveChunkWindow::IsSequenceAvailable("),
            4,
        )
        for marker in (
            "IsNewerSequence(peerNewest, bestEdge)",
            "availableBeforeEdge = bestEdge - bestOldest",
            "(seq - oldestSeq) < ESE_LIVE_EDGE_GUARD",
            "serialSpan = snap.newestSeq - snap.oldestSeq + 1u",
        ):
            self.assertIn(marker, manager)

        mask = 0xFFFFFFFF
        anchor = mask - 1
        bitmap = 0x000F
        advertised = lambda seq: ((seq - anchor) & mask) < 16 and (
            bitmap & (1 << ((seq - anchor) & mask))
        ) != 0
        self.assertTrue(all(advertised(seq) for seq in (mask - 1, mask, 0, 1)))
        self.assertFalse(advertised(mask - 2))
        self.assertFalse(advertised(14))

        for path in ("srchybrid/LiveStreamManager.cpp", "srchybrid/LiveStreamManager.h"):
            baseline = subprocess.run(
                ["git", "show", f"{SLICE_BASE}:{path}"],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
            ).stdout
            current = (ROOT / path).read_text(encoding="utf-8")
            self.assertLessEqual(len(current.splitlines()), len(baseline.splitlines()))


if __name__ == "__main__":
    unittest.main()
