from __future__ import annotations

import json
import pathlib
import subprocess
import unittest
import xml.etree.ElementTree as ET


ROOT = pathlib.Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "docs" / "architecture" / "mod37_live_stream_facade_contract_v1.json"
ANNOUNCER_HEADER = ROOT / "srchybrid" / "LiveStreamAnnouncer.h"
ANNOUNCER_SOURCE = ROOT / "srchybrid" / "LiveStreamAnnouncer.cpp"
ANNOUNCER_ADAPTER = ROOT / "srchybrid" / "LiveAnnounceTransportAdapter.cpp"
SNAPSHOT_HEADER = ROOT / "srchybrid" / "LiveStreamSnapshot.h"
SNAPSHOT_SOURCE = ROOT / "srchybrid" / "LiveStreamSnapshot.cpp"
MANAGER_HEADER = ROOT / "srchybrid" / "LiveStreamManager.h"
MANAGER_SOURCE = ROOT / "srchybrid" / "LiveStreamManager.cpp"
KAD_HEADER = ROOT / "srchybrid" / "LiveKadBridge.h"
KAD_SOURCE = ROOT / "srchybrid" / "LiveKadBridge.cpp"
MAKE = ROOT / "srchybrid" / "tests" / "make.bat"
PROJECT = ROOT / "srchybrid" / "emule.vcxproj"
SLICE_BASE = "e5a5d138376fd78c50438931d591f42cbf02da59"


class Mod37LiveStreamFacadeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))

    def test_contract_freezes_facade_and_compatibility_boundaries(self) -> None:
        self.assertEqual(
            self.contract["schema"],
            "ese.mod37.live-stream-facade-contract/v1",
        )
        self.assertEqual(self.contract["baseline_commit"], SLICE_BASE)
        self.assertEqual(
            [(m["name"], m["layer"], m["declared_direct_dependencies"])
             for m in self.contract["modules"]],
            [
                ("LiveStreamAnnouncer", "adapters", []),
                ("LiveStreamSnapshot", "application", []),
            ],
        )
        invariants = self.contract["invariants"]
        self.assertEqual(invariants["wire_format"], "byte_unchanged")
        self.assertEqual(invariants["announce_interval_ms"], 2000)
        self.assertEqual(invariants["kad_publish_interval_ms"], 60000)
        self.assertEqual(invariants["snapshot_pointer_fields"], 0)
        self.assertEqual(invariants["manager_header_hard_stop_loc"], 700)

    def test_announcer_core_is_bounded_value_only_and_transport_isolated(self) -> None:
        core = ANNOUNCER_HEADER.read_text(encoding="utf-8") + "\n" + (
            ANNOUNCER_SOURCE.read_text(encoding="utf-8")
        )
        for token in (
            "CString",
            "CArray",
            "CMap",
            "CSingleLock",
            "CCriticalSection",
            "CUpDownClient",
            "Packet",
            "LiveStreamManager",
            "stdafx.h",
        ):
            self.assertNotIn(token, core)
        for marker in (
            "kAnnounceIntervalMs = 2000u",
            "kKadPublishIntervalMs = 60000u",
            "ResetKadPublish()",
            "Poll(",
            "Describe(",
            "std::array<std::uint8_t, 16u>",
            "std::array<std::uint8_t, 32u>",
        ):
            self.assertIn(marker, core)
        adapter = ANNOUNCER_ADAPTER.read_text(encoding="utf-8")
        self.assertIn("CreateAnnouncePacket(", adapter)
        self.assertIn("CUpDownClient", adapter)
        self.assertIn("if (peer->SendPacket(packet))", adapter)
        self.assertNotIn("peer->SendPacket(packet);\n\t\t++sent;", adapter)

    def test_manager_delegates_cadence_and_snapshot_projection(self) -> None:
        header = MANAGER_HEADER.read_text(encoding="utf-8")
        source = MANAGER_SOURCE.read_text(encoding="utf-8")
        self.assertIn(
            "ese::live::LiveStreamAnnouncer m_streamAnnouncer;", header
        )
        for obsolete in (
            "m_dwLastAnnounceSend",
            "m_dwLastKadPublish",
            "SendAnnounceToAll",
            "struct LiveDebugSnapshot",
            "struct KadDebugSnapshot",
            "struct LiveStreamCounters",
        ):
            self.assertNotIn(obsolete, header + "\n" + source)
        for marker in (
            "m_streamAnnouncer.ResetKadPublish()",
            "m_streamAnnouncer.Poll(",
            "LiveStreamAnnouncer::Describe(",
            "LiveAnnounceTransportAdapter::Send(",
            "LiveStreamSnapshot::Build(input)",
        ):
            self.assertIn(marker, source)
        self.assertLessEqual(len(header.splitlines()), 700)

    def test_snapshot_is_pointer_free_and_preserves_lock_order(self) -> None:
        snapshot = SNAPSHOT_HEADER.read_text(encoding="utf-8") + "\n" + (
            SNAPSHOT_SOURCE.read_text(encoding="utf-8")
        )
        for token in (
            "CUpDownClient",
            "Packet*",
            "LiveStreamManager",
            "CString",
            "CMap",
            "CSingleLock",
            "CCriticalSection",
            "stdafx.h",
        ):
            self.assertNotIn(token, snapshot)
        source = MANAGER_SOURCE.read_text(encoding="utf-8")
        kad_pos = source.index(
            "const KadDebugSnapshot kadSnap = "
            "m_kadBridge.BuildDebugKadSnapshot();"
        )
        manager_lock_pos = source.index(
            "CSingleLock lock(&m_lock, TRUE);", kad_pos
        )
        build_pos = source.index("LiveStreamSnapshot::Build(input)", manager_lock_pos)
        self.assertLess(kad_pos, manager_lock_pos)
        self.assertLess(manager_lock_pos, build_pos)
        self.assertIn('#include "LiveStreamSnapshot.h"', KAD_HEADER.read_text(
            encoding="utf-8"
        ))
        self.assertIn(
            '#include "LiveStreamManager.h"',
            KAD_SOURCE.read_text(encoding="utf-8"),
        )

    def test_native_cases_and_release_compile_the_exact_modules(self) -> None:
        make = MAKE.read_text(encoding="utf-8")
        for name in (
            "LiveStreamAnnouncer.cpp",
            "test_live_stream_announcer.cpp",
            "LiveStreamSnapshot.cpp",
            "test_live_stream_snapshot.cpp",
        ):
            self.assertIn(name, make)
        announcer_test = (
            ROOT / "srchybrid" / "tests" / "test_live_stream_announcer.cpp"
        ).read_text(encoding="utf-8")
        snapshot_test = (
            ROOT / "srchybrid" / "tests" / "test_live_stream_snapshot.cpp"
        ).read_text(encoding="utf-8")
        for marker in (
            "announce exact boundary survives uint32 wrap",
            "inactive polling neither announces nor consumes a deadline",
            "descriptor preserves wire fields and saturates bitrate",
        ):
            self.assertIn(marker, announcer_test)
        for marker in (
            "chunk gap projection is exact",
            "hostile serial gap saturates without signed overflow",
            "production snapshot never invents test-only peer detail",
            "uptime projection survives uint32 wrap",
        ):
            self.assertIn(marker, snapshot_test)

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
        for source in ("LiveStreamAnnouncer.cpp", "LiveStreamSnapshot.cpp"):
            self.assertIn(source, compiles)
            xml = ET.tostring(compiles[source], encoding="unicode")
            for marker in ("NotUsing", "Level4", "true", "stdcpp17"):
                self.assertIn(marker, xml)
        self.assertIn("LiveAnnounceTransportAdapter.cpp", compiles)
        for header in (
            "LiveStreamAnnouncer.h",
            "LiveStreamSnapshot.h",
            "LiveAnnounceTransportAdapter.h",
        ):
            self.assertIn(header, includes)

    def test_coordinator_shrinks_and_wire_files_are_identical(self) -> None:
        for path in (
            "srchybrid/LiveStreamManager.cpp",
            "srchybrid/LiveStreamManager.h",
        ):
            diff = subprocess.run(
                ["git", "diff", "--numstat", SLICE_BASE, "--", path],
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
            self.assertEqual(
                normalize((ROOT / path).read_bytes()),
                normalize(baseline),
            )


if __name__ == "__main__":
    unittest.main()
