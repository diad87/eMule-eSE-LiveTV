"""MOD-1.3 host contract for circuit registry ownership and state."""

from __future__ import annotations

import pathlib
import re
import unittest
import xml.etree.ElementTree as ET


ROOT = pathlib.Path(__file__).resolve().parents[1]
HEADER = ROOT / "srchybrid" / "LiveCircuitRegistry.h"
SOURCE = ROOT / "srchybrid" / "LiveCircuitRegistry.cpp"
TUNNEL_HEADER = ROOT / "srchybrid" / "LiveTunnel.h"
TUNNEL_SOURCE = ROOT / "srchybrid" / "LiveTunnel.cpp"
PROJECT = ROOT / "srchybrid" / "emule.vcxproj"


class Mod13LiveCircuitRegistryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.header = HEADER.read_text(encoding="utf-8")
        cls.source = SOURCE.read_text(encoding="utf-8")
        cls.tunnel_header = TUNNEL_HEADER.read_text(encoding="utf-8")
        cls.tunnel_source = TUNNEL_SOURCE.read_text(encoding="utf-8")

    def test_public_contract_is_portable_and_has_no_second_lock(self) -> None:
        includes = set(re.findall(
            r'#\s*include\s*[<"]([^>"]+)[>"]',
            self.header,
        ))
        self.assertEqual(includes, {
            "cstddef", "cstdint", "memory", "set", "vector",
        })
        for forbidden in (
            "LiveTunnel.h",
            "windows.h",
            "afx",
            "CUpDownClient",
            "Kad",
            "Socket",
        ):
            self.assertNotIn(forbidden, self.header)
        combined = self.header + self.source
        for forbidden in (
            "CCriticalSection",
            "CSingleLock",
            "std::mutex",
            "condition_variable",
        ):
            self.assertNotIn(forbidden, combined)
        self.assertIn("adds no\n// second mutex", self.header)

    def test_registry_owns_collection_cursor_identity_lookup_and_state(self) -> None:
        for required in (
            "Snapshot m_circuits;",
            "std::size_t m_roundRobinIndex = 0;",
            "LiveCircuitRegistry::Add",
            "LiveCircuitRegistry::Clear",
            "LiveCircuitRegistry::RemoveDestroyed",
            "LiveCircuitRegistry::ContainsIncomingId",
            "LiveCircuitRegistry::ContainsAnyLegId",
            "LiveCircuitRegistry::FindById",
            "LiveCircuitRegistry::FindRelayByOutgoingId",
            "LiveCircuitRegistry::NextRoundRobin",
            "LiveCircuitRegistry::Transition",
            "LiveCircuitRegistry::CanTransition",
            "const LiveCircuitRegistry::Snapshot&",
        ):
            self.assertIn(required, self.header + self.source)
        self.assertNotIn("std::function", self.header + self.source)

    def test_coordinator_no_longer_owns_raw_registry_or_state_writes(self) -> None:
        combined = self.tunnel_header + self.tunnel_source
        circuit_header = (ROOT / "srchybrid" / "LiveCircuit.h").read_text(
            encoding="utf-8",
        )
        self.assertIn("LiveCircuitRegistry m_circuitRegistry;", self.tunnel_header)
        self.assertNotIn("m_circuits", combined)
        self.assertNotIn("m_rrNextIdx", combined)
        self.assertNotRegex(
            self.tunnel_source,
            r"->SetState\s*\(\s*CircuitState::",
        )
        self.assertIn("m_circuitRegistry.NextRoundRobin()", self.tunnel_source)
        self.assertIn("m_circuitRegistry.RemoveDestroyed(", self.tunnel_source)
        zero_preflight = self.tunnel_source.index(
            "if (circId == 0 || m_circuitRegistry.ContainsAnyLegId(circId))",
        )
        create_crypto = self.tunnel_source.index(
            "if (!X25519GenerateKeypair(erPub, erPriv))",
            zero_preflight,
        )
        created_wire = self.tunnel_source.index(
            "if (!SendCellToPeer(fromPeer, cell))",
            create_crypto,
        )
        self.assertLess(zero_preflight, create_crypto)
        self.assertLess(zero_preflight, created_wire)
        self.assertIn(
            "circ->State() != CircuitState::Pending",
            self.tunnel_source,
        )
        self.assertIn(
            "circ->State() != CircuitState::HalfBuilt",
            self.tunnel_source,
        )
        self.assertIn(
            "if (!m_circuitRegistry.Transition(circ, CircuitState::Active))",
            self.tunnel_source,
        )
        transition_before_wire = self.tunnel_source.index(
            "if (!m_circuitRegistry.Transition(circ, CircuitState::HalfBuilt))",
        )
        extend_wire = self.tunnel_source.index(
            "if (!circ->m_firstHopClient || !SendCellToPeer",
            transition_before_wire,
        )
        self.assertLess(transition_before_wire, extend_wire)
        self.assertIn("friend class LiveCircuitRegistry;", circuit_header)
        private_tail = circuit_header[circuit_header.rindex("private:"):]
        self.assertIn("void SetState(CircuitState state)", private_tail)

    def test_production_selftest_exercises_fail_closed_registry(self) -> None:
        for required in (
            "RunCircuitRegistryCharacterizationSelfTest",
            "IdentityFenceFailed",
            "RoundRobinFailed",
            "TransitionFailed",
            "TerminalStateFailed",
            "RemovalFailed",
            "ClearFailed",
        ):
            self.assertIn(required, self.header + self.source)
        self.assertIn(
            "RunCircuitRegistryCharacterizationSelfTest()",
            self.tunnel_source,
        )
        self.assertIn(
            "registry.Add(outgoingCollision, CircuitState::Pending)",
            self.source,
        )
        self.assertIn(
            "registry.Add(pending, CircuitState::Active)",
            self.source,
        )
        self.assertIn(
            "registry.Transition(directHalfBuilt, CircuitState::Active)",
            self.source,
        )
        self.assertIn(
            "!CanTransition(circuit->State(), initial_state)",
            self.source,
        )
        self.assertNotIn(
            "Transition(activeRelay, CircuitState::Active)",
            self.source,
        )

    def test_project_compiles_registry_with_shared_wall_configuration(self) -> None:
        tree = ET.parse(PROJECT)
        namespace = {"m": "http://schemas.microsoft.com/developer/msbuild/2003"}
        items = tree.findall(
            ".//m:ClCompile[@Include='LiveCircuitRegistry.cpp']",
            namespace,
        )
        self.assertEqual(len(items), 1)
        item = items[0]
        self.assertEqual(
            item.findtext("m:PrecompiledHeader", namespaces=namespace),
            "Use",
        )
        self.assertEqual(
            item.findtext("m:PrecompiledHeaderFile", namespaces=namespace),
            "stdafx.h",
        )
        # The file must inherit the eMule compiler dialect and /Wall level
        # used to create stdafx.pch; per-file overrides invalidate that PCH.
        self.assertIsNone(
            item.find("m:LanguageStandard", namespace),
        )
        self.assertIsNone(
            item.find("m:WarningLevel", namespace),
        )
        headers = tree.findall(
            ".//m:ClInclude[@Include='LiveCircuitRegistry.h']",
            namespace,
        )
        self.assertEqual(len(headers), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
