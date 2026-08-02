"""Final LiveTunnel coordinator/header closure for M2A-LT10."""
from __future__ import annotations

import importlib.util
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / "srchybrid"
TOOLS = ROOT / "tools" / "architecture"
sys.path.insert(0, str(TOOLS))
SPEC = importlib.util.spec_from_file_location(
    "m2a00_lt10", TOOLS / "verify_m2a00_migration_ratchet.py"
)
assert SPEC and SPEC.loader
GATE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = GATE
SPEC.loader.exec_module(GATE)


class LT10CanonicalEvidenceTest(unittest.TestCase):
    def test_m2a_151d898fd2a40d09(self):
        self.assertLessEqual(
            len(
                (SOURCE / "LiveTunnel.h")
                .read_text(encoding="utf-8")
                .splitlines()
            ),
            900,
        )
        self.assertNotIn(
            "struct TunnelEndpoint",
            (SOURCE / "LiveTunnel.h").read_text(encoding="utf-8"),
        )


class LT10CoordinatorCloseTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.header = (SOURCE / "LiveTunnel.h").read_text(encoding="utf-8")
        cls.source = (SOURCE / "LiveTunnel.cpp").read_text(encoding="utf-8")
        cls.framing = (SOURCE / "LiveTunnelFraming.h").read_text(encoding="utf-8")
        cls.metrics = GATE.metrics()["coordinators"]["LiveTunnel"]

    def test_final_physical_loc_limits(self):
        self.assertLessEqual(len(self.header.splitlines()), 900)
        self.assertLessEqual(len(self.source.splitlines()), 4000)

    def test_final_real_field_limit(self):
        self.assertLessEqual(len(self.metrics["fields"]), 20)
        self.assertEqual(
            set(self.metrics["fields"]),
            {
                "m_circuitRegistry",
                "m_exitServices",
                "m_handshake",
                "m_kadBridge",
                "m_lock",
                "m_metrics",
                "m_peerState",
                "m_pendingLock",
                "m_pendingRequests",
                "m_relayDispatcher",
                "m_scheduler",
            },
        )

    def test_no_oversized_coordinator_function_remains(self):
        self.assertEqual(self.metrics["oversized_functions"], [])

    def test_wire_opcode_dto_is_owned_by_framing_module(self):
        self.assertIn("enum LiveTunnelOpCmd", self.framing)
        self.assertNotIn("enum TunnelOpCmd", self.header)
        for name in (
            "TUN_OP_PING",
            "TUN_OP_KAD_SEARCH_V2",
            "TUN_OP_BULK_SUBSCRIBE",
            "TUN_OP_KAD6_GATEWAY",
        ):
            self.assertIn(name, self.framing)
            self.assertNotIn(f"CLiveTunnel::{name}", self.header)

    def test_unused_endpoint_dto_is_absent_from_coordinator(self):
        self.assertNotIn("struct TunnelEndpoint", self.header)

    def test_final_architecture_gates_remain_wired(self):
        workflow = (ROOT / ".github" / "workflows" / "build.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("test_v92_mod*.py", workflow)
        self.assertIn("test_v92_m2a*.py", workflow)

if __name__ == "__main__":
    unittest.main()
