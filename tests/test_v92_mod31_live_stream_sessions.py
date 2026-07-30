"""MOD-3.1 host contract for broadcaster/viewer lifecycle extraction."""

from __future__ import annotations

import json
import pathlib
import re
import subprocess
import unittest
import xml.etree.ElementTree as ET


ROOT = pathlib.Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "docs" / "architecture" / "mod31_live_stream_sessions_contract_v1.json"
BROADCAST_HEADER = ROOT / "srchybrid" / "LiveBroadcastSession.h"
BROADCAST_SOURCE = ROOT / "srchybrid" / "LiveBroadcastSession.cpp"
VIEWER_HEADER = ROOT / "srchybrid" / "LiveViewerSession.h"
VIEWER_SOURCE = ROOT / "srchybrid" / "LiveViewerSession.cpp"
MANAGER_HEADER = ROOT / "srchybrid" / "LiveStreamManager.h"
MANAGER_SOURCE = ROOT / "srchybrid" / "LiveStreamManager.cpp"
NATIVE_TEST = ROOT / "srchybrid" / "tests" / "test_live_stream_sessions.cpp"
MAKE = ROOT / "srchybrid" / "tests" / "make.bat"
PROJECT = ROOT / "srchybrid" / "emule.vcxproj"
SLICE_BASE = "a48445e560765fc68fc85b0e61a09e2e72b7f9de"


class Mod31LiveStreamSessionsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        cls.broadcast_header = BROADCAST_HEADER.read_text(encoding="utf-8")
        cls.broadcast_source = BROADCAST_SOURCE.read_text(encoding="utf-8")
        cls.viewer_header = VIEWER_HEADER.read_text(encoding="utf-8")
        cls.viewer_source = VIEWER_SOURCE.read_text(encoding="utf-8")
        cls.manager_header = MANAGER_HEADER.read_text(encoding="utf-8")
        cls.manager_source = MANAGER_SOURCE.read_text(encoding="utf-8")

    def test_contract_freezes_scope_and_invariants(self) -> None:
        self.assertEqual(
            self.contract["schema"],
            "ese.mod31.live-stream-sessions-contract/v1",
        )
        self.assertEqual(self.contract["baseline_commit"], SLICE_BASE)
        self.assertEqual(
            [(item["name"], item["layer"], item["declared_direct_dependencies"])
             for item in self.contract["modules"]],
            [
                ("LiveBroadcastSession", "domain_state", []),
                ("LiveViewerSession", "domain_state", []),
            ],
        )
        invariants = self.contract["invariants"]
        self.assertEqual(
            invariants["broadcast_and_viewer_roles"],
            "independent_and_simultaneously_active",
        )
        self.assertEqual(invariants["replacement"], "explicit_leave_required_before_join")
        self.assertEqual(invariants["tick_arithmetic"], "uint32_modular_and_zero_sentinel_preserved")
        self.assertEqual(invariants["broadcast_private_key"], "wiped_on_stop")
        self.assertEqual(invariants["wire_format"], "unchanged")

    def test_modules_are_portable_and_do_not_reach_coordinator_or_wire(self) -> None:
        module_text = "\n".join([
            self.broadcast_header,
            self.broadcast_source,
            self.viewer_header,
            self.viewer_source,
        ])
        forbidden = {
            "CString",
            "CWebServer",
            "CUpDownClient",
            "CLiveStreamManager",
            "LiveProtocol",
            "LivePackets",
            "SOCKET",
            "HANDLE",
            "windows.h",
            "stdafx.h",
        }
        for token in forbidden:
            self.assertNotIn(token, module_text)
        includes = re.findall(r'#\s*include\s*[<"]([^>"]+)[>"]', module_text)
        self.assertEqual(
            set(includes),
            {
                "LiveBroadcastSession.h",
                "LiveViewerSession.h",
                "array",
                "atomic",
                "cstddef",
                "cstdint",
                "cstring",
                "algorithm",
            },
        )
        for source in (BROADCAST_SOURCE, VIEWER_SOURCE):
            self.assertLessEqual(len(source.read_text(encoding="utf-8").splitlines()), 300)
        self.assertEqual(module_text.count("std::atomic<bool> active_{false}"), 2)
        self.assertGreaterEqual(module_text.count("std::memory_order_release"), 4)
        self.assertGreaterEqual(module_text.count("std::memory_order_acquire"), 2)

    def test_native_test_and_release_project_compile_the_exact_modules(self) -> None:
        self.assertTrue(NATIVE_TEST.is_file())
        make = MAKE.read_text(encoding="utf-8")
        for name in (
            "LiveBroadcastSession.cpp",
            "LiveViewerSession.cpp",
            "test_live_stream_sessions.cpp",
            "test_live_stream_sessions.exe",
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
        for name in ("LiveBroadcastSession.cpp", "LiveViewerSession.cpp"):
            self.assertIn(name, compile_items)
            xml = ET.tostring(compile_items[name], encoding="unicode")
            self.assertIn("NotUsing", xml)
            self.assertIn("Level4", xml)
            self.assertIn("true", xml)
            self.assertIn("stdcpp17", xml)
        self.assertTrue({
            "LiveBroadcastSession.h",
            "LiveViewerSession.h",
        }.issubset(include_items))

    def test_manager_delegates_lifecycle_and_old_scalar_owners_are_gone(self) -> None:
        manager = self.manager_header + "\n" + self.manager_source
        self.assertRegex(
            self.manager_header,
            r"ese::live::LiveBroadcastSession\s+m_broadcastSession;",
        )
        self.assertRegex(
            self.manager_header,
            r"ese::live::LiveViewerSession\s+m_viewerSession;",
        )
        self.assertIn("CopyBroadcastStreamKey(uchar outKey[16])", self.manager_header)
        self.assertIn("CopyViewerStreamKey(uchar outKey[16])", self.manager_header)
        self.assertNotIn("GetBroadcastStreamKey()", self.manager_header)
        self.assertNotIn("GetViewerStreamKey()", self.manager_header)
        for call in (
            "m_broadcastSession.Start(identity)",
            "m_broadcastSession.Stop()",
            "m_broadcastSession.NextSequence",
            "m_broadcastSession.PrivateKey()",
            "m_viewerSession.Join(",
            "m_viewerSession.Leave()",
            "m_viewerSession.RecordFirstChunk(",
            "m_viewerSession.SearchRetryDue(",
            "m_viewerSession.SecondaryPublishDue(",
            "m_viewerSession.TunnelResubscribeDue(",
        ):
            self.assertIn(call, self.manager_source)

        removed_fields = (
            "m_bBroadcasting",
            "m_bViewing",
            "m_broadcasterPrivkey",
            "m_nNextSeqNum",
            "m_dwLastLiveActivity",
            "m_dwLastSecondaryPublish",
            "m_dwLastJoinSearchTick",
            "m_nJoinSearchRetries",
            "m_dwJoinTick",
            "m_bFirstChunkLogged",
            "m_lastPlayerFetchTick",
            "m_bWebPlayerSession",
            "m_tunnelSourceIP",
            "m_tunnelSourcePort",
            "m_strictTunnelOnly",
            "m_tunnelSubscribeTick",
            "m_tunnelResubCount",
        )
        for field in removed_fields:
            self.assertNotIn(field, manager)

        consumers = "\n".join(
            (ROOT / path).read_text(encoding="utf-8")
            for path in (
                "srchybrid/EmuleDlg.cpp",
                "srchybrid/LiveBuddyRelay.cpp",
                "srchybrid/LiveStreamDlgUI.cpp",
                "srchybrid/LiveTunnel.cpp",
                "srchybrid/WebServer.cpp",
            )
        )
        self.assertNotIn("GetBroadcastStreamKey", consumers)
        self.assertNotIn("GetViewerStreamKey", consumers)
        self.assertIn("CopyBroadcastStreamKey", consumers)
        self.assertIn("CopyViewerStreamKey", consumers)

    def test_manager_commits_roles_last_and_remote_end_uses_full_leave_cleanup(self) -> None:
        start = self.manager_source[
            self.manager_source.index("bool CLiveStreamManager::StartBroadcast("):
            self.manager_source.index("bool CLiveStreamManager::StartBroadcastWithSource(")
        ]
        self.assertLess(
            start.index("m_broadcastStreamInfo.streamKey"),
            start.index("m_broadcastSession.Start(identity)"),
        )
        self.assertLess(
            start.index("m_broadcastChunkBuffer.Clear()"),
            start.index("m_broadcastSession.Start(identity)"),
        )
        self.assertLess(
            start.index("ResetBroadcasterEgress()"),
            start.index("m_broadcastSession.Start(identity)"),
        )

        join = self.manager_source[
            self.manager_source.index("bool CLiveStreamManager::JoinStream("):
            self.manager_source.index("void CLiveStreamManager::LeaveStream(")
        ]
        self.assertLess(join.index("streamKey == NULL"), join.index("LeaveStream()"))
        self.assertLess(
            join.index("memcpy(m_streamInfo.streamKey"),
            join.index("m_viewerSession.Join("),
        )
        self.assertLess(
            join.index("ResetViewerHlsOutput(true)"),
            join.index("m_viewerSession.Join("),
        )

        ended = self.manager_source[
            self.manager_source.index("void CLiveStreamManager::OnStreamEnded("):
            self.manager_source.index("bool CLiveStreamManager::IsStreamTombstoned(")
        ]
        self.assertIn("LeaveStream()", ended)

        cleanup_helper = self.manager_source[
            self.manager_source.index(
                "void CLiveStreamManager::ResetViewerCoordinatorState()"
            ):
            self.manager_source.index("void CLiveStreamManager::LeaveStream(")
        ]
        for cleanup in (
            "m_chunkBuffer.Clear()",
            "m_peerSet.ClearSources()",
            "m_meshManager.ResetSessionPeers()",
            "m_inflightSegReqs.RemoveAll()",
            "m_recentDials.RemoveAll()",
            "m_peerRefreshPolicy.Reset()",
            "ResetViewerHlsOutput(true)",
        ):
            self.assertIn(cleanup, cleanup_helper)
        self.assertRegex(
            cleanup_helper,
            r"m_broadcastSession\.IsActive\(\)[\s\S]{0,250}"
            r"m_meshManager\.AddMeshPeer",
        )

    def test_wire_files_are_byte_unchanged_and_coordinator_shrinks(self) -> None:
        subprocess.run(
            [
                "git", "diff", "--quiet", SLICE_BASE, "--",
                "srchybrid/LivePackets.cpp",
                "srchybrid/LivePackets.h",
                "srchybrid/LiveProtocol.h",
            ],
            cwd=ROOT,
            check=True,
        )
        result = subprocess.run(
            [
                "git", "diff", "--numstat", SLICE_BASE, "--",
                "srchybrid/LiveStreamManager.cpp",
                "srchybrid/LiveStreamManager.h",
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        rows = [line.split("\t") for line in result.stdout.splitlines() if line.strip()]
        self.assertEqual(len(rows), 2)
        total_added = 0
        total_removed = 0
        for added, removed, _path in rows:
            self.assertTrue(added.isdigit() and removed.isdigit())
            self.assertGreater(int(removed), int(added))
            total_added += int(added)
            total_removed += int(removed)
        self.assertGreater(total_removed, total_added)


if __name__ == "__main__":
    unittest.main(verbosity=2)
