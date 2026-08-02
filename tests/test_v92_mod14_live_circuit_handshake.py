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
WIRE_INTERFACE = ROOT / "srchybrid" / "LiveHandshakeWire.h"
WIRE_SOURCE = ROOT / "srchybrid" / "LiveHandshakeWire.cpp"
UPDOWN_INTERFACE = ROOT / "srchybrid" / "UpdownClient.h"
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

    def test_public_boundary_is_opaque_and_wire_dependency_is_explicit(self) -> None:
        interface = INTERFACE.read_text(encoding="utf-8")
        wire_interface = WIRE_INTERFACE.read_text(encoding="utf-8")
        wire_source = WIRE_SOURCE.read_text(encoding="utf-8")
        project = PROJECT.read_text(encoding="utf-8")

        self.assertNotIn("CUpDownClient", interface)
        self.assertIn("using LiveHandshakePeerHandle = void*;", wire_interface)
        self.assertIn('#include "LiveTunnelFraming.h"', wire_source)
        self.assertIn("SecureRandomBytes(", wire_source)
        self.assertIn('ClCompile Include="LiveHandshakeWire.cpp"', project)
        self.assertIn('ClInclude Include="LiveHandshakeWire.h"', project)

    def test_shaping_limit_and_capability_masks_have_one_canonical_owner(self) -> None:
        wire_interface = WIRE_INTERFACE.read_text(encoding="utf-8")
        updown_interface = UPDOWN_INTERFACE.read_text(encoding="utf-8")

        self.assertIn(
            "constexpr std::uint16_t K6_SHAPE_RUNTIME_MAX_BUCKET_KIB = 1024;",
            wire_interface,
        )
        self.assertNotIn(
            "K6_SHAPE_RUNTIME_MAX_BUCKET_KIB =",
            self.source + self.coordinator,
        )
        for capability in (
            "ESE_CAP_TUNNEL_AUTH",
            "ESE_CAP_TUNNEL_STRICT3",
            "ESE_CAP_TUNNEL_SHAPED",
        ):
            self.assertIn(
                f"m_uEseCapabilities & {capability}",
                updown_interface,
            )
        for duplicated_mask in ("0x00040000", "0x02000000", "0x04000000"):
            self.assertNotIn(duplicated_mask, updown_interface)

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
        contract = (
            self.source
            + INTERFACE.read_text(encoding="utf-8")
            + WIRE_INTERFACE.read_text(encoding="utf-8")
            + WIRE_SOURCE.read_text(encoding="utf-8")
        )
        for required in (
            "TUN_TRANSCRIPT_LEN == 150",
            "TUN_HKDF_INFO_LEN == 120",
            "TUN_TRANSCRIPT_V3_LEN == 190",
            "TUN_HKDF_INFO_V3_LEN == 159",
            "TUN_CREATE_V3_LEN = 140",
            "TUN_EXTEND_V3_LEN = 158",
            "69u  <= HANDSHAKE_CELL_PAYLOAD_MAX",
            "133u <= HANDSHAKE_CELL_PAYLOAD_MAX",
            "149u <= HANDSHAKE_CELL_PAYLOAD_MAX",
        ):
            self.assertIn(required, contract)


if __name__ == "__main__":
    unittest.main(verbosity=2)
