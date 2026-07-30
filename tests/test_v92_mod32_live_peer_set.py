"""MOD-3.2 host contract for peer membership and diversity extraction."""

from __future__ import annotations

import json
import pathlib
import re
import subprocess
import unittest
import xml.etree.ElementTree as ET


ROOT = pathlib.Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "docs" / "architecture" / "mod32_live_peer_set_contract_v1.json"
HEADER = ROOT / "srchybrid" / "LivePeerSet.h"
SOURCE = ROOT / "srchybrid" / "LivePeerSet.cpp"
MANAGER_HEADER = ROOT / "srchybrid" / "LiveStreamManager.h"
MANAGER_SOURCE = ROOT / "srchybrid" / "LiveStreamManager.cpp"
FANOUT_ADAPTER_SOURCE = ROOT / "srchybrid" / "LiveFanoutTransportAdapter.cpp"
CLIENT_LIST_SOURCE = ROOT / "srchybrid" / "ClientList.cpp"
MESH_HEADER = ROOT / "srchybrid" / "LiveMeshManager.h"
MESH_SOURCE = ROOT / "srchybrid" / "LiveMeshManager.cpp"
TUNNEL_HEADER = ROOT / "srchybrid" / "LiveTunnel.h"
TUNNEL_SOURCE = ROOT / "srchybrid" / "LiveTunnel.cpp"
NATIVE_TEST = ROOT / "srchybrid" / "tests" / "test_live_peer_set.cpp"
MAKE = ROOT / "srchybrid" / "tests" / "make.bat"
PROJECT = ROOT / "srchybrid" / "emule.vcxproj"
SLICE_BASE = "e56166bc11bbd41c6f27978519bad4b6099a3952"


class Mod32LivePeerSetTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))

    def test_contract_freezes_scope_and_legacy_rules(self) -> None:
        self.assertEqual(
            self.contract["schema"],
            "ese.mod32.live-peer-set-contract/v1",
        )
        self.assertEqual(self.contract["baseline_commit"], SLICE_BASE)
        self.assertEqual(
            (
                self.contract["module"]["name"],
                self.contract["module"]["layer"],
                self.contract["module"]["declared_direct_dependencies"],
            ),
            ("LivePeerSet", "domain_state", []),
        )
        invariants = self.contract["invariants"]
        self.assertEqual(invariants["roles"], "source_and_downstream_are_independent")
        self.assertEqual(invariants["order"], "stable_insertion_order")
        self.assertEqual(
            invariants["limits"],
            "zero_is_unbounded_and_full_rejects_without_partial_state",
        )
        self.assertEqual(
            invariants["ipv4_diversity"],
            "maximum_five_existing_super_seeders_per_24_and_existing_20_percent_rule_per_16",
        )
        self.assertEqual(invariants["wire_format"], "unchanged")

    def test_module_is_portable_and_value_only(self) -> None:
        text = HEADER.read_text(encoding="utf-8") + "\n" + SOURCE.read_text(
            encoding="utf-8"
        )
        forbidden = {
            "CString",
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
            self.assertNotIn(token, text)
        includes = set(re.findall(r'#\s*include\s*[<"]([^>"]+)[>"]', text))
        self.assertEqual(
            includes,
            {
                "LivePeerSet.h",
                "algorithm",
                "cstddef",
                "cstdint",
                "vector",
            },
        )
        self.assertLessEqual(len(HEADER.read_text(encoding="utf-8").splitlines()), 180)
        self.assertLessEqual(len(SOURCE.read_text(encoding="utf-8").splitlines()), 260)

    def test_manager_delegates_membership_and_old_lists_are_gone(self) -> None:
        header = MANAGER_HEADER.read_text(encoding="utf-8")
        source = MANAGER_SOURCE.read_text(encoding="utf-8")
        membership_path = source + "\n" + FANOUT_ADAPTER_SOURCE.read_text(
            encoding="utf-8"
        )
        manager = header + "\n" + source
        self.assertRegex(header, r"ese::live::LivePeerSet\s+m_peerSet;")
        self.assertNotIn("m_broadcastPeers", manager)
        self.assertNotIn("m_viewPeers", manager)
        for call in (
            "m_peerSet.AddSource(",
            "m_peerSet.RemoveSource(",
            "m_peerSet.ClearSources(",
            "m_peerSet.ClearDownstreams(",
            "m_peerSet.SourceCount(",
            "m_peerSet.DownstreamCount(",
            "m_peerSet.HasSource(",
            "m_peerSet.HasDownstream(",
            "m_peerSet.SelectSource(",
            "EvaluateIpv4SuperSeederDiversity(",
        ):
            self.assertIn(call, source)
        for call in ("peers.AddDownstream(", "peers.RemoveDownstream("):
            self.assertIn(call, membership_path)

    def test_release_and_standalone_build_the_exact_module(self) -> None:
        make = MAKE.read_text(encoding="utf-8")
        for name in (
            "LivePeerSet.cpp",
            "test_live_peer_set.cpp",
            "test_live_peer_set.exe",
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
        self.assertIn("LivePeerSet.cpp", compile_items)
        xml = ET.tostring(compile_items["LivePeerSet.cpp"], encoding="unicode")
        self.assertIn("NotUsing", xml)
        self.assertIn("Level4", xml)
        self.assertIn("true", xml)
        self.assertIn("stdcpp17", xml)
        self.assertIn("LivePeerSet.h", include_items)

    def test_remote_lists_are_bounded_and_client_swap_is_atomic(self) -> None:
        manager = MANAGER_SOURCE.read_text(encoding="utf-8")
        client_list = CLIENT_LIST_SOURCE.read_text(encoding="utf-8")
        mesh = (
            MESH_HEADER.read_text(encoding="utf-8")
            + MESH_SOURCE.read_text(encoding="utf-8")
        )
        tunnel = (
            TUNNEL_HEADER.read_text(encoding="utf-8")
            + TUNNEL_SOURCE.read_text(encoding="utf-8")
        )
        self.assertIn("ESE_LIVE_MAX_SOURCE_PEERS = 8u", manager)
        self.assertIn(
            "peer != NULL && !m_peerSet.HasSource(PeerHandleOf(peer))",
            manager,
        )
        for marker in (
            "m_peerSet.AddSource(PeerHandleOf(newClient), sourceLimit)",
            "sourceAdd != LivePeerAddResult::Added",
        ):
            self.assertGreaterEqual(manager.count(marker), 2)
        self.assertNotRegex(
            manager,
            r"m_peerSet\.AddSource\([\s\S]{0,120}0u\)",
        )

        replace_call = (
            "theApp.liveStreamManager->OnPeerReplaced(tocheck, found_client);"
        )
        self.assertIn(replace_call, client_list)
        self.assertLess(client_list.index(replace_call), client_list.index("delete tocheck;"))
        replacement = manager[
            manager.index("void CLiveStreamManager::OnPeerReplaced("):
            manager.index("void CLiveStreamManager::OnPeerDisconnected(")
        ]
        for call in ("m_peerSet.ReplaceSource(", "m_meshManager.ReplaceMeshPeer("):
            self.assertIn(call, replacement)
        self.assertIn("LiveStreamFanoutAdapter::ReplaceChild(", replacement)
        self.assertIn(
            "peers.ReplaceDownstream(",
            FANOUT_ADAPTER_SOURCE.read_text(encoding="utf-8"),
        )
        self.assertIn("ReplaceMeshPeer(", mesh)
        self.assertIn("m_pendingRequests[i].peer = replacement", mesh)
        self.assertIn("m_uploadTracker[replacement]", mesh)
        relay = tunnel[
            tunnel.index("void CLiveTunnel::ExitRelayPeerList("):
            tunnel.index("void CLiveTunnel::FinishDueSearchJobs(")
        ]
        for check in (
            "it->second.bIP != upstreamIP",
            "it->second.bPort != upstreamPort",
        ):
            self.assertIn(check, relay)
            self.assertLess(relay.index(check), relay.index("lastSeen = nowT"))
        self.assertIn("peer->GetIP(), peer->GetUserPort()", manager)

    def test_wire_files_are_unchanged_and_coordinator_shrinks(self) -> None:
        for path in ("srchybrid/LiveProtocol.h", "srchybrid/LivePackets.cpp"):
            baseline = subprocess.run(
                ["git", "show", f"{SLICE_BASE}:{path}"],
                cwd=ROOT,
                check=True,
                capture_output=True,
            ).stdout
            normalize = lambda data: data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
            self.assertEqual(normalize((ROOT / path).read_bytes()), normalize(baseline))

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
            self.assertLess(len(current.splitlines()), len(baseline.splitlines()))


if __name__ == "__main__":
    unittest.main()
