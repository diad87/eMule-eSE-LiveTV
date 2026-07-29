"""MOD-1.4 pre-move characterization of the production handshake."""

from __future__ import annotations

import importlib.util
import json
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / "srchybrid" / "LiveTunnel.cpp"
GOLDENS = ROOT / "docs" / "architecture" / "mod02_characterization_goldens_v1.json"
VERIFIER_PATH = ROOT / "tools" / "architecture" / "verify_mod02_characterization.py"

SPEC = importlib.util.spec_from_file_location("mod02_handshake_verifier", VERIFIER_PATH)
assert SPEC is not None and SPEC.loader is not None
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


class Mod14LiveCircuitHandshakeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = SOURCE.read_text(encoding="utf-8")
        cls.golden = json.loads(GOLDENS.read_text(encoding="utf-8"))[
            "goldens"
        ]["live_circuit_handshake"]

    def body(self, start: str, end: str) -> str:
        begin = self.source.index(start)
        finish = self.source.index(end, begin)
        return self.source[begin:finish]

    def test_all_eight_production_functions_are_token_frozen(self) -> None:
        self.assertEqual(
            VERIFIER.fingerprint(
                self.golden["production_file"],
                self.golden["symbols"],
            ),
            self.golden["token_sha256"],
        )
        self.assertEqual(len(self.golden["symbols"]), 8)

    def test_created_rejects_stale_state_and_verifies_before_deriving(self) -> None:
        body = self.body(
            "bool CLiveTunnel::HandleCreated_Originator",
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
            "bool CLiveTunnel::HandleCreate_Relay",
            "// === DoS hardening",
        )
        zero = body.index("circId == 0")
        crypto = body.index("X25519GenerateKeypair")
        wire = body.index("SendCellToPeer(fromPeer, cell)")
        publish = body.index("m_circuitRegistry.Add")
        self.assertLess(zero, crypto)
        self.assertLess(crypto, wire)
        self.assertLess(wire, publish)

    def test_extend_commits_state_before_wire_and_extended_verifies_first(self) -> None:
        extend = self.body(
            "bool CLiveTunnel::BuildExtend",
            "bool CLiveTunnel::HandleExtend_Relay",
        )
        self.assertLess(
            extend.index("Transition(circ, CircuitState::HalfBuilt)"),
            extend.index("SendCellToPeer(circ->m_firstHopClient, cell)"),
        )
        extended = self.body(
            "bool CLiveTunnel::HandleExtended_Originator",
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
            self.assertIn(required, self.source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
