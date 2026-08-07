from __future__ import annotations

import json
import pathlib
import re
import subprocess
import unittest
import xml.etree.ElementTree as ET


ROOT = pathlib.Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "docs" / "architecture" / "mod34_live_stream_security_contract_v1.json"
HEADER = ROOT / "srchybrid" / "LiveStreamSecurity.h"
SOURCE = ROOT / "srchybrid" / "LiveStreamSecurity.cpp"
MANAGER_HEADER = ROOT / "srchybrid" / "LiveStreamManager.h"
MANAGER_SOURCE = ROOT / "srchybrid" / "LiveStreamManager.cpp"
TRUST_ADAPTER = ROOT / "srchybrid" / "LiveStreamTrustAdapter.cpp"
TRUST_ADAPTER_HEADER = ROOT / "srchybrid" / "LiveStreamTrustAdapter.h"
LISTEN_SOURCE = ROOT / "srchybrid" / "ListenSocket.cpp"
NATIVE_TEST = ROOT / "srchybrid" / "tests" / "test_live_stream_security.cpp"
MAKE = ROOT / "srchybrid" / "tests" / "make.bat"
PROJECT = ROOT / "srchybrid" / "emule.vcxproj"
SLICE_BASE = "05c815444d106e305908ee076bd3c2bf62f24883"
WIRE_BASE = "d08f8b07"  # v9.1 final: ESE_FRAG_REASM_TTL is normatively 15000 ms.


class Mod34LiveStreamSecurityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))

    def test_contract_freezes_security_boundaries(self) -> None:
        self.assertEqual(
            self.contract["schema"],
            "ese.mod34.live-stream-security-contract/v1",
        )
        self.assertEqual(self.contract["baseline_commit"], SLICE_BASE)
        module = self.contract["module"]
        self.assertEqual(
            (module["name"], module["layer"], module["declared_direct_dependencies"]),
            ("LiveStreamSecurity", "domain_state", []),
        )
        invariants = self.contract["invariants"]
        self.assertEqual(invariants["wire_format"], "byte_unchanged")
        self.assertEqual(invariants["pin_capacity"], 256)
        self.assertEqual(invariants["replay_window_sequences"], 64)
        self.assertEqual(invariants["trust_capacity"], 1024)
        self.assertEqual(invariants["trust_failure_cap"], 10)
        self.assertEqual(
            invariants["replay"],
            "only_a_cryptographically_verified_sequence_may_advance_the_replay_window",
        )

    def test_module_is_portable_bounded_and_fail_closed(self) -> None:
        text = HEADER.read_text(encoding="utf-8") + "\n" + SOURCE.read_text(
            encoding="utf-8"
        )
        for token in (
            "CString",
            "CMap",
            "CSingleLock",
            "CCriticalSection",
            "CUpDownClient",
            "LiveProtocol",
            "LivePackets",
            "CryptoPP",
            "windows.h",
            "stdafx.h",
        ):
            self.assertNotIn(token, text)
        for marker in (
            "kPinCapacity = 256u",
            "kReplayCapacity = 256u",
            "kTrustCapacity = 1024u",
            "kReplayWindowSequences = 64u",
            "UnpinnedStream",
            "AmbiguousSequence",
            "pins_.reserve(kPinCapacity)",
            "replay_.reserve(kReplayCapacity)",
            "trust_.reserve(kTrustCapacity)",
            "std::mutex",
            "EvaluateTrust(",
            "ShouldBan(",
            "ShouldDemote(",
            "ChargeFailure(",
        ):
            self.assertIn(marker, text)

    def test_manager_delegates_pins_and_verified_replay(self) -> None:
        header = MANAGER_HEADER.read_text(encoding="utf-8")
        source = MANAGER_SOURCE.read_text(encoding="utf-8")
        adapter = TRUST_ADAPTER.read_text(encoding="utf-8")
        listen = LISTEN_SOURCE.read_text(encoding="utf-8")
        self.assertRegex(
            header,
            r"ese::live::LiveStreamSecurity\s+m_streamSecurity;",
        )
        self.assertNotIn("m_streamPubkeyPin", header + source)
        self.assertNotIn("struct PubkeyPin", header)
        self.assertNotIn("m_peerTrust", header + source + adapter)
        self.assertNotIn("DWORD_PTR p =", source + adapter)
        self.assertIn("PinValidatedPublicKey(", source)
        self.assertIn("GetPinnedPublicKey(", source)
        self.assertIn("ClassifyVerifiedSequence(", source)
        self.assertIn("CommitVerifiedSequence(", source)
        self.assertIn("EvaluateTrust(", source)
        self.assertIn("ShouldBan(", source)
        self.assertIn("ShouldDemote(", source)
        self.assertIn("ChargeFailure(", source)
        self.assertIn("RewardCriticalDelivery(", source)
        self.assertIn("m_viewerSession.Matches(streamKey, 16u)", source)
        self.assertIn("m_streamSecurity.ReleaseStream(", source)
        self.assertIn("security_->TouchTrust(", adapter)
        self.assertIn("security_->PruneTrust(", adapter)
        self.assertRegex(
            source,
            r"OnChunkReceived\(peer, streamKey, seqNum, timestamp, "
            r"chunkData, chunkSize, true\);",
        )
        self.assertGreaterEqual(listen.count("IngestChunkPayload("), 2)
        chunk_cases = listen[
            listen.index("case OP_LIVE_CHUNK:") :
            listen.index("case OP_LIVE_CHUNK_FRAG:")
        ]
        self.assertNotIn("VerifySignature(", chunk_cases)
        self.assertNotIn("CryptoPP::SHA256", chunk_cases)
        on_chunk = source[
            source.index("void CLiveStreamManager::OnChunkReceived(") :
            source.index("void CLiveStreamManager::OnPeerBitmap(")
        ]
        self.assertLess(
            on_chunk.index("ClassifyVerifiedSequence("),
            on_chunk.index("m_chunkBuffer.AddSegment("),
        )
        self.assertLess(
            on_chunk.index("m_chunkBuffer.AddSegment("),
            on_chunk.index("CommitVerifiedSequence("),
        )
        peer_join = source[
            source.index("void CLiveStreamManager::OnPeerJoin(") :
            source.index("void CLiveStreamManager::OnPeerRequest(")
        ]
        send = peer_join.index("LiveStreamFanoutAdapter::SendReserved(")
        relock = peer_join.index("lock.Lock()", send)
        resolved = peer_join.index(
            "LiveStreamFanoutAdapter::ResolveDeliveredChild(", relock
        )
        credit = peer_join.index("trust.requestsServed +=")
        self.assertLess(relock, resolved)
        self.assertLess(resolved, credit)
        self.assertLess(credit, peer_join.index("SetTrustById(", credit))

    def test_native_cases_cover_pin_replay_wrap_and_capacity(self) -> None:
        native = NATIVE_TEST.read_text(encoding="utf-8")
        for marker in (
            "unverified or unpinned input cannot poison replay state",
            "same public key is idempotent",
            "public key switch fails closed",
            "bounded reorder is accepted once",
            "verified replay window accepts uint32 wrap",
            "half-range serial ambiguity fails closed",
            "pin capacity fails closed",
            "pin and replay capacity rejection does not partially mutate state",
            "session release reclaims both pin and replay state",
            "replay preflight does not mutate state before storage",
            "responsive peer reaches middle at the exact threshold",
            "responsive peer reaches super-seeder with diversity approval",
            "response rate below twenty percent after ten requests bans",
            "failure charge is capped and critical reward cannot underflow",
            "trust survives replacement object projection with the same identity",
            "trust capacity failure is atomic",
            "stale trust pruning is bounded and preserves fresh records",
            "zero identities fail closed",
            "concurrent replay mutation accepts exactly one verified sequence",
            "clear atomically removes all security state",
        ):
            self.assertIn(marker, native)

    def test_release_and_standalone_compile_the_exact_module(self) -> None:
        make = MAKE.read_text(encoding="utf-8")
        for name in (
            "LiveStreamSecurity.cpp",
            "test_live_stream_security.cpp",
            "test_live_stream_security.exe",
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
        self.assertIn("LiveStreamSecurity.cpp", compiles)
        self.assertIn("LiveStreamTrustAdapter.cpp", compiles)
        self.assertIn("LiveStreamTrustAdapter.h", includes)
        xml = ET.tostring(compiles["LiveStreamSecurity.cpp"], encoding="unicode")
        for marker in ("NotUsing", "Level4", "true", "stdcpp17"):
            self.assertIn(marker, xml)
        self.assertIn("LiveStreamSecurity.h", includes)

    def test_wire_definition_files_remain_byte_identical(self) -> None:
        for path in (
            "srchybrid/LiveProtocol.h",
            "srchybrid/LivePackets.cpp",
            "srchybrid/LivePackets.h",
        ):
            baseline = subprocess.run(
                ["git", "show", f"{WIRE_BASE}:{path}"],
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
