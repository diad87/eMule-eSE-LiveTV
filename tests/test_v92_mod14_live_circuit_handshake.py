"""MOD-1.4 pre-move characterization of the production handshake."""

from __future__ import annotations

import importlib.util
import json
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
COORDINATOR = ROOT / "srchybrid" / "LiveTunnel.cpp"
GOLDENS = ROOT / "docs" / "architecture" / "mod02_characterization_goldens_v1.json"
PROJECT = ROOT / "srchybrid" / "emule.vcxproj"
INTERFACE = ROOT / "srchybrid" / "LiveCircuitHandshake.h"
VERIFIER_PATH = ROOT / "tools" / "architecture" / "verify_mod02_characterization.py"

SPEC = importlib.util.spec_from_file_location("mod02_handshake_verifier", VERIFIER_PATH)
assert SPEC is not None and SPEC.loader is not None
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


class Mod14LiveCircuitHandshakeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.golden = json.loads(GOLDENS.read_text(encoding="utf-8"))[
            "goldens"
        ]["live_circuit_handshake"]
        cls.source_path = ROOT / cls.golden["production_file"]
        cls.source = cls.source_path.read_text(encoding="utf-8")
        cls.coordinator = COORDINATOR.read_text(encoding="utf-8")

    def body(self, start: str, end: str) -> str:
        del end
        symbol = start.split(" ", 1)[1]
        return VERIFIER.function_body(self.source, symbol)

    def test_all_nine_production_functions_are_token_frozen(self) -> None:
        self.assertEqual(
            VERIFIER.fingerprint(
                self.golden["production_file"],
                self.golden["symbols"],
            ),
            self.golden["token_sha256"],
        )
        self.assertEqual(len(self.golden["symbols"]), 9)

    def test_handshake_is_physically_owned_by_the_new_module(self) -> None:
        self.assertEqual(
            self.golden["production_file"],
            "srchybrid/LiveCircuitHandshake.cpp",
        )
        for symbol in self.golden["symbols"]:
            self.assertIn(symbol, self.source)
            self.assertNotIn(symbol, self.coordinator)
        project = PROJECT.read_text(encoding="utf-8")
        self.assertIn('ClCompile Include="LiveCircuitHandshake.cpp"', project)
        self.assertIn('ClInclude Include="LiveCircuitHandshake.h"', project)

    def test_created_rejects_stale_state_and_verifies_before_deriving(self) -> None:
        body = self.body(
            "bool LiveCircuitHandshake::HandleCreatedOriginator",
            "namespace {\nCString EseK6GuardPath",
        )
        self.assertLess(
            body.index("circ->State() != CircuitState::Pending"),
            body.index("X25519SharedSecret"),
        )
        self.assertLess(
            body.index("if (!VerifySignature"),
            body.index("X25519SharedSecret"),
        )
        self.assertLess(body.index("circ->AddHop(hop)"), body.index("SecureWipe(okm"))

    def test_create_rejects_identity_before_crypto_and_wire(self) -> None:
        body = self.body(
            "bool LiveCircuitHandshake::HandleCreateRelay",
            "// === DoS hardening",
        )
        zero = body.index("circId == 0")
        crypto = body.index("X25519GenerateKeypair")
        wire = body.index("m_host.SendHandshakeCell(fromPeer, cell)")
        publish = body.index("m_host.HandshakeCircuitRegistry().Add")
        self.assertLess(zero, crypto)
        self.assertLess(crypto, wire)
        self.assertLess(wire, publish)

    def test_extend_commits_state_before_wire_and_extended_verifies_first(self) -> None:
        extend = self.body(
            "bool LiveCircuitHandshake::BuildExtend",
            "bool LiveCircuitHandshake::HandleExtendRelay",
        )
        self.assertLess(
            extend.index("Transition(circ, CircuitState::HalfBuilt)"),
            extend.index(
                "m_host.SendHandshakeCell(circ->m_firstHopClient, cell)"
            ),
        )
        extended = self.body(
            "bool LiveCircuitHandshake::HandleExtendedOriginator",
            "uint32_t CLiveTunnel::BuildTestCircuit2Hop",
        )
        self.assertLess(
            extended.index("circ->State() != CircuitState::HalfBuilt"),
            extended.index("OnionDecryptAll"),
        )
        self.assertLess(
            extended.index("if (!VerifySignature"),
            extended.index("X25519SharedSecret"),
        )

    def test_wire_and_transcript_width_tripwires_are_present(self) -> None:
        contract = self.source + INTERFACE.read_text(encoding="utf-8")
        for required in (
            "TUN_TRANSCRIPT_LEN == 150",
            "TUN_HKDF_INFO_LEN == 120",
            "TUN_TRANSCRIPT_V3_LEN == 190",
            "TUN_HKDF_INFO_V3_LEN == 159",
            "TUN_CREATE_V3_LEN = 140",
            "TUN_EXTEND_V3_LEN = 158",
            "69u  <= CELL_PAYLOAD_MAX",
            "133u <= CELL_PAYLOAD_MAX",
            "149u <= CELL_PAYLOAD_MAX",
        ):
            self.assertIn(required, contract)


if __name__ == "__main__":
    unittest.main(verbosity=2)
