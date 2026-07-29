"""MOD-1.5 pre-move characterization of relay dispatch and exit lifecycle."""

from __future__ import annotations

import importlib.util
import json
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
COORDINATOR = ROOT / "srchybrid" / "LiveTunnel.cpp"
INTERFACE = ROOT / "srchybrid" / "LiveTunnel.h"
GOLDENS = ROOT / "docs" / "architecture" / "mod02_characterization_goldens_v1.json"
VERIFIER_PATH = ROOT / "tools" / "architecture" / "verify_mod02_characterization.py"

SPEC = importlib.util.spec_from_file_location("mod02_relay_exit_verifier", VERIFIER_PATH)
assert SPEC is not None and SPEC.loader is not None
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


class Mod15RelayExitTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.golden = json.loads(GOLDENS.read_text(encoding="utf-8"))[
            "goldens"
        ]["live_relay_exit"]
        cls.source = COORDINATOR.read_text(encoding="utf-8")
        cls.interface = INTERFACE.read_text(encoding="utf-8")

    def body(self, symbol: str) -> str:
        return VERIFIER.function_body(self.source, symbol)

    def test_seven_production_functions_are_token_frozen(self) -> None:
        self.assertEqual(
            VERIFIER.fingerprint(
                self.golden["production_file"],
                self.golden["symbols"],
            ),
            self.golden["token_sha256"],
        )
        self.assertEqual(len(self.golden["symbols"]), 7)

    def test_exit_dispatch_validates_before_publication(self) -> None:
        body = self.body("CLiveTunnel::HandleRelay_Exit")
        self.assertLess(body.index("OnionDecryptAll"), body.index("ParseSubHeader"))
        self.assertLess(body.index("ParseSubHeader"), body.index("ParseFragHeader"))
        self.assertLess(body.index("ParseFragHeader"), body.index("ReassemblyIngest"))
        self.assertLess(body.index("ReassemblyIngest"), body.index("DispatchExitRequest"))
        self.assertIn("ReassemblyResult::Incomplete", body)
        self.assertIn("ReassemblyResult::Error", body)
        self.assertIn("m_reassembly.erase(rkey)", body)

    def test_unknown_or_absent_handler_is_a_silent_fail_closed_drop(self) -> None:
        body = self.body("CLiveTunnel::DispatchExitRequest")
        self.assertIn("m_exitHandlers.find(ctx.sub_cmd)", body)
        self.assertIn("it != m_exitHandlers.end() && it->second", body)
        self.assertNotIn("operator[]", body)

    def test_completion_consumes_before_external_reply(self) -> None:
        body = self.body("CLiveTunnel::CompleteExitOperation")
        self.assertLess(body.index("m_exitOps.find"), body.index("m_exitOps.erase(it)"))
        self.assertLess(body.index("m_exitOps.erase(it)"), body.index("SendReply("))
        self.assertIn("if (!circ) return false", body)

    def test_partial_reply_is_non_consuming_and_abort_is_idempotent(self) -> None:
        partial = self.body("CLiveTunnel::SendExitOperationPart")
        abort = self.body("CLiveTunnel::AbortExitOperation")
        self.assertIn("m_exitOps.find", partial)
        self.assertNotIn("m_exitOps.erase", partial)
        self.assertIn("m_exitOps.erase(ExitOpKey(circ_id, req_id))", abort)

    def test_registry_and_lifecycle_share_the_declared_pending_lock(self) -> None:
        lifecycle = (
            self.body("CLiveTunnel::BeginExitOperation")
            + self.body("CLiveTunnel::CompleteExitOperation")
            + self.body("CLiveTunnel::SendExitOperationPart")
            + self.body("CLiveTunnel::AbortExitOperation")
        )
        self.assertGreaterEqual(lifecycle.count("CSingleLock pl(&m_pendingLock, TRUE)"), 4)
        self.assertIn("std::map<uint8_t, TunnelOpHandler> m_exitHandlers", self.interface)
        self.assertIn("std::map<uint64_t, ExitOperation> m_exitOps", self.interface)


if __name__ == "__main__":
    unittest.main(verbosity=2)
