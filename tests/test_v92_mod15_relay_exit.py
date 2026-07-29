"""MOD-1.5 ownership and fail-closed relay/exit lifecycle contract."""

from __future__ import annotations

import importlib.util
import json
import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
COORDINATOR = ROOT / "srchybrid" / "LiveTunnel.cpp"
COORDINATOR_INTERFACE = ROOT / "srchybrid" / "LiveTunnel.h"
DISPATCHER = ROOT / "srchybrid" / "LiveRelayDispatcher.cpp"
DISPATCHER_INTERFACE = ROOT / "srchybrid" / "LiveRelayDispatcher.h"
EXIT_SERVICES = ROOT / "srchybrid" / "LiveExitServices.cpp"
EXIT_INTERFACE = ROOT / "srchybrid" / "LiveExitServices.h"
TYPES_INTERFACE = ROOT / "srchybrid" / "LiveRelayTypes.h"
PROJECT = ROOT / "srchybrid" / "emule.vcxproj"
GOLDENS = ROOT / "docs" / "architecture" / "mod02_characterization_goldens_v1.json"
VERIFIER_PATH = ROOT / "tools" / "architecture" / "verify_mod02_characterization.py"

SPEC = importlib.util.spec_from_file_location("mod02_relay_exit_verifier", VERIFIER_PATH)
assert SPEC is not None and SPEC.loader is not None
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


class Mod15RelayExitTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.goldens = json.loads(GOLDENS.read_text(encoding="utf-8"))["goldens"]
        cls.coordinator = COORDINATOR.read_text(encoding="utf-8")
        cls.coordinator_interface = COORDINATOR_INTERFACE.read_text(encoding="utf-8")
        cls.dispatcher = DISPATCHER.read_text(encoding="utf-8")
        cls.exit_services = EXIT_SERVICES.read_text(encoding="utf-8")
        cls.exit_interface = EXIT_INTERFACE.read_text(encoding="utf-8")

    def body(self, source: str, symbol: str) -> str:
        return VERIFIER.function_body(source, symbol)

    def test_production_functions_are_token_frozen_in_new_owners(self) -> None:
        for golden_name in ("live_relay_dispatcher", "live_exit_services"):
            golden = self.goldens[golden_name]
            self.assertEqual(
                VERIFIER.fingerprint(
                    golden["production_file"],
                    golden["symbols"],
                ),
                golden["token_sha256"],
            )
        self.assertEqual(
            self.goldens["live_relay_dispatcher"]["production_file"],
            "srchybrid/LiveRelayDispatcher.cpp",
        )
        self.assertEqual(
            self.goldens["live_exit_services"]["production_file"],
            "srchybrid/LiveExitServices.cpp",
        )

    def test_dispatch_validates_before_state_or_handler_publication(self) -> None:
        body = self.body(
            self.dispatcher,
            "LiveRelayDispatcher::DispatchExitPlain",
        )
        self.assertLess(
            body.index("ParseRelaySubHeader"),
            body.index("ParseRelayFragmentHeader"),
        )
        self.assertLess(
            body.index("ParseRelayFragmentHeader"),
            body.index("IngestRelayFragment"),
        )
        self.assertLess(
            body.index("IngestRelayFragment"),
            body.rindex("DispatchRelayExit"),
        )
        self.assertIn("result != LiveRelayFragmentResult::Complete", body)

    def test_unknown_or_absent_handler_is_a_silent_fail_closed_drop(self) -> None:
        dispatch = self.body(
            self.exit_services,
            "LiveExitServices::Dispatch",
        )
        relay = self.body(
            self.dispatcher,
            "LiveRelayDispatcher::DispatchExitPlain",
        )
        self.assertIn("m_handlers.find(subCommand)", dispatch)
        self.assertIn(
            "handler == m_handlers.end() || !handler->second",
            dispatch,
        )
        self.assertIn("(void)port.DispatchRelayExit(context)", relay)

    def test_replay_is_rejected_without_overwriting_live_state(self) -> None:
        begin = self.body(self.exit_services, "LiveExitServices::Begin")
        self.assertIn("circuit->Id() == 0 || requestId == 0", begin)
        self.assertIn("m_operations.emplace", begin)
        self.assertIn(".second", begin)
        self.assertNotIn("m_operations[", begin)
        search = self.body(
            self.coordinator,
            "CLiveTunnel::ExitHandle_KadSearchV2",
        )
        echo = self.body(
            self.coordinator,
            "CLiveTunnel::ExitHandle_EchoLarge",
        )
        self.assertIn(
            "if (!BeginExitOperation(ctx, TUN_OP_KAD_RESULT_V2))",
            search,
        )
        self.assertLess(
            search.index("BeginExitOperation"),
            search.index("TunnelSearchJob job"),
        )
        self.assertIn(
            "if (!BeginExitOperation(ctx, TUN_OP_ECHO_LARGE_REPLY))",
            echo,
        )
        self.assertLess(
            echo.index("BeginExitOperation"),
            echo.index("CompleteExitOperation"),
        )

    def test_completion_consumes_before_external_reply(self) -> None:
        take = self.body(
            self.exit_services,
            "LiveExitServices::TakeCompletion",
        )
        wrapper = self.body(
            self.coordinator,
            "CLiveTunnel::CompleteExitOperation",
        )
        self.assertLess(
            take.index("m_operations.find"),
            take.index("m_operations.erase(operation)"),
        )
        self.assertLess(
            wrapper.index("TakeCompletion"),
            wrapper.index("SendReply("),
        )

    def test_partial_reply_is_non_consuming_and_abort_is_idempotent(self) -> None:
        partial = self.body(
            self.exit_services,
            "LiveExitServices::FindPart",
        )
        abort = self.body(
            self.exit_services,
            "LiveExitServices::Abort",
        )
        self.assertIn("m_operations.find", partial)
        self.assertNotIn("m_operations.erase", partial)
        self.assertIn("m_operations.erase(LiveRequestKey", abort)

    def test_state_ownership_moved_and_facade_keeps_existing_lock_rank(self) -> None:
        for removed in ("m_exitHandlers", "m_exitOps", "struct ExitOperation"):
            self.assertNotIn(removed, self.coordinator_interface)
        self.assertIn(
            "std::map<std::uint8_t, LiveTunnelOpHandler> m_handlers",
            self.exit_interface,
        )
        self.assertIn(
            "std::map<std::uint64_t, Operation> m_operations",
            self.exit_interface,
        )
        lifecycle = "".join(
            self.body(self.coordinator, symbol)
            for symbol in (
                "CLiveTunnel::BeginExitOperation",
                "CLiveTunnel::CompleteExitOperation",
                "CLiveTunnel::SendExitOperationPart",
                "CLiveTunnel::AbortExitOperation",
            )
        )
        self.assertGreaterEqual(
            lifecycle.count("CSingleLock pl(&m_pendingLock, TRUE)"),
            4,
        )

    def test_shutdown_and_circuit_teardown_release_owned_operations(self) -> None:
        stop = self.body(self.coordinator, "CLiveTunnel::Stop")
        destroy = self.body(
            self.coordinator,
            "CLiveTunnel::DestroyCircuitFailClosed",
        )
        transition = self.body(
            self.coordinator,
            "CLiveTunnel::TransitionCircuitDestroyed",
        )
        self.assertIn("m_exitServices.Clear()", stop)
        self.assertIn("TransitionCircuitDestroyed(circ)", destroy)
        self.assertIn("m_exitServices.AbortCircuit(circuitId)", transition)
        self.assertIn("m_reassembly.begin()", transition)
        self.assertIn("entry->first >> 32", transition)
        direct_destroy_transitions = re.findall(
            r"m_circuitRegistry\.Transition\([^;]{0,160}"
            r"CircuitState::Destroyed\);",
            self.coordinator,
        )
        self.assertEqual(len(direct_destroy_transitions), 1)
        self.assertIn(direct_destroy_transitions[0], transition)

    def test_modules_are_project_owned_and_do_not_include_the_coordinator(self) -> None:
        project = PROJECT.read_text(encoding="utf-8")
        for required in (
            'ClCompile Include="LiveRelayDispatcher.cpp"',
            'ClCompile Include="LiveExitServices.cpp"',
            'ClInclude Include="LiveRelayDispatcher.h"',
            'ClInclude Include="LiveExitServices.h"',
            'ClInclude Include="LiveRelayTypes.h"',
        ):
            self.assertIn(required, project)
        module_text = (
            self.dispatcher
            + DISPATCHER_INTERFACE.read_text(encoding="utf-8")
            + self.exit_services
            + self.exit_interface
            + TYPES_INTERFACE.read_text(encoding="utf-8")
        )
        self.assertNotIn('#include "LiveTunnel.h"', module_text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
