"""MOD-0.4 must keep future modularization slices mechanically honest."""

from __future__ import annotations

import copy
import importlib.util
import json
import pathlib
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
BASELINE = ROOT / "docs" / "architecture" / "mod04_architecture_gate_baseline_v1.json"
CONTRACT = ROOT / "docs" / "architecture" / "mod03_ownership_layering_contract_v1.json"
SCRIPT = ROOT / "tools" / "architecture" / "verify_mod04_architecture_gate.py"
WORKFLOW = ROOT / ".github" / "workflows" / "build.yml"

SPEC = importlib.util.spec_from_file_location("mod04_verifier", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


class Mod04ArchitectureGateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config = json.loads(BASELINE.read_text(encoding="utf-8"))
        cls.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))

    def test_baseline_is_reproducible_and_final_limits_are_not_premature(self) -> None:
        messages = VERIFIER.validate(self.config, self.contract)
        self.assertTrue(any(
            message.startswith("slice LiveTunnelFraming:")
            for message in messages
        ))
        self.assertTrue(any(
            message.startswith("slice LiveTunnelPending:")
            for message in messages
        ))
        self.assertTrue(any(
            message.startswith("slice LiveCircuitRegistry:")
            for message in messages
        ))
        self.assertTrue(any(
            message.startswith("slice LiveCircuitHandshake:")
            for message in messages
        ))
        self.assertTrue(any(
            message.startswith("slice LiveRelayDispatcher:")
            for message in messages
        ))
        self.assertTrue(any(
            message.startswith("slice LiveExitServices:")
            for message in messages
        ))
        self.assertTrue(any(
            message.startswith("slice LiveTunnelScheduler:")
            for message in messages
        ))
        self.assertFalse(self.config["final_limits"]["enforced_now"])
        self.assertEqual(self.config["baseline_commit"], "161d948281682d39acdcea796b1edddc6d68904c")
        self.assertEqual(len(self.config["coordinator_files"]), 6)
        web_header = next(item for item in self.config["coordinator_files"]
                          if item["path"] == "srchybrid/WebServer.h")
        self.assertEqual(
            (web_header["final_target_loc_max"], web_header["final_hard_stop_loc"],
             web_header["final_limit_status"]),
            (None, None, "not_specified_by_plan"),
        )
        self.assertEqual(self.config["module_catalog"], {
            "state": "EXTRACTION_ACTIVE",
            "entries": [{
                "name": "LiveTunnelFraming",
                "owner": "CLiveTunnel",
                "layer": "foundation",
                "implementation_files": ["srchybrid/LiveTunnelFraming.cpp"],
                "interface_files": ["srchybrid/LiveTunnelFraming.h"],
                "declared_direct_dependencies": [],
            }, {
                "name": "LiveHandshakeWire",
                "owner": "CLiveTunnel",
                "layer": "ports",
                "implementation_files": ["srchybrid/LiveHandshakeWire.cpp"],
                "interface_files": ["srchybrid/LiveHandshakeWire.h"],
                "declared_direct_dependencies": ["LiveTunnelFraming"],
            }, {
                "name": "LiveTunnelPending",
                "owner": "CLiveTunnel",
                "layer": "domain_state",
                "implementation_files": ["srchybrid/LiveTunnelPending.cpp"],
                "interface_files": ["srchybrid/LiveTunnelPending.h"],
                "declared_direct_dependencies": [],
            }, {
                "name": "LiveCircuitRegistry",
                "owner": "CLiveTunnel",
                "layer": "domain_state",
                "implementation_files": ["srchybrid/LiveCircuitRegistry.cpp"],
                "interface_files": ["srchybrid/LiveCircuitRegistry.h"],
                "declared_direct_dependencies": [],
            }, {
                "name": "LiveCircuitHandshake",
                "owner": "CLiveTunnel",
                "layer": "application",
                "implementation_files": ["srchybrid/LiveCircuitHandshake.cpp"],
                "interface_files": ["srchybrid/LiveCircuitHandshake.h"],
                "declared_direct_dependencies": [
                    "LiveCircuitRegistry",
                    "LiveHandshakeWire",
                ],
            }, {
                "name": "LiveRelayDispatcher",
                "owner": "CLiveTunnel",
                "layer": "application",
                "implementation_files": ["srchybrid/LiveRelayDispatcher.cpp"],
                "interface_files": ["srchybrid/LiveRelayDispatcher.h"],
                "declared_direct_dependencies": [],
            }, {
                "name": "LiveExitServices",
                "owner": "CLiveTunnel",
                "layer": "application",
                "implementation_files": ["srchybrid/LiveExitServices.cpp"],
                "interface_files": ["srchybrid/LiveExitServices.h"],
                "declared_direct_dependencies": [],
            }, {
                "name": "LiveTunnelScheduler",
                "owner": "CLiveTunnel",
                "layer": "application",
                "implementation_files": ["srchybrid/LiveTunnelScheduler.cpp"],
                "interface_files": ["srchybrid/LiveTunnelScheduler.h"],
                "declared_direct_dependencies": [],
            }, {
                "name": "LiveTunnelPeerState",
                "owner": "CLiveTunnel",
                "layer": "domain_state",
                "implementation_files": ["srchybrid/LiveTunnelPeerState.cpp"],
                "interface_files": ["srchybrid/LiveTunnelPeerState.h"],
                "declared_direct_dependencies": [],
            }, {
                "name": "LiveTunnelKadBridge",
                "owner": "CLiveTunnel",
                "layer": "adapters",
                "implementation_files": ["srchybrid/LiveTunnelKadBridge.cpp"],
                "interface_files": ["srchybrid/LiveTunnelKadBridge.h"],
                "declared_direct_dependencies": [],
            }, {
                "name": "LiveTunnelMetrics",
                "owner": "CLiveTunnel",
                "layer": "application",
                "implementation_files": ["srchybrid/LiveTunnelMetrics.cpp"],
                "interface_files": ["srchybrid/LiveTunnelMetrics.h"],
                "declared_direct_dependencies": [],
            }, {
                "name": "WebRequestParser",
                "owner": "CWebServer",
                "layer": "application",
                "implementation_files": ["srchybrid/WebRequestParser.cpp"],
                "interface_files": ["srchybrid/WebRequestParser.h"],
                "declared_direct_dependencies": [],
            }, {
                "name": "WebAuthPolicy",
                "owner": "CWebServer",
                "layer": "application",
                "implementation_files": ["srchybrid/WebAuthPolicy.cpp"],
                "interface_files": ["srchybrid/WebAuthPolicy.h"],
                "declared_direct_dependencies": [],
            }, {
                "name": "WebRouteTable",
                "owner": "CWebServer",
                "layer": "application",
                "implementation_files": ["srchybrid/WebRouteTable.cpp"],
                "interface_files": ["srchybrid/WebRouteTable.h"],
                "declared_direct_dependencies": [],
            }, {
                "name": "WebApiSerializer",
                "owner": "CWebServer",
                "layer": "application",
                "implementation_files": ["srchybrid/WebApiSerializer.cpp"],
                "interface_files": ["srchybrid/WebApiSerializer.h"],
                "declared_direct_dependencies": [],
            }],
        })
        self.assertEqual(self.config["approved_non_module_code"], [
            {
                "path": "srchybrid/tests/test_live_tunnel_framing.cpp",
                "reason": (
                    "Standalone byte-exact executable test for MOD-1.1 pure "
                    "framing extraction."
                ),
                "adr": "docs/architecture/ADR_MOD03_OWNERSHIP_AND_LAYERING_V1.md",
            },
            {
                "path": "srchybrid/tests/test_live_tunnel_pending.cpp",
                "reason": (
                    "Standalone concurrency and retry executable test for "
                    "MOD-1.2 pending-state extraction."
                ),
                "adr": "docs/architecture/ADR_MOD03_OWNERSHIP_AND_LAYERING_V1.md",
            },
            {
                "path": "srchybrid/LiveRelayTypes.h",
                "reason": (
                    "Narrow immutable DTO and handler signature shared by the "
                    "two MOD-1.5 application modules without creating an "
                    "application-to-application dependency."
                ),
                "adr": "docs/architecture/ADR_MOD03_OWNERSHIP_AND_LAYERING_V1.md",
            },
            {
                "path": "srchybrid/tests/test_live_tunnel_peer_kad.cpp",
                "reason": (
                    "Standalone policy, source-history and fake-port executable "
                    "test for the MOD-1.7 peer-state and Kad-boundary extraction."
                ),
                "adr": "docs/architecture/ADR_MOD03_OWNERSHIP_AND_LAYERING_V1.md",
            },
            {
                "path": "srchybrid/tests/test_live_tunnel_metrics.cpp",
                "reason": (
                    "Standalone concurrency, immutable-copy and exact-counter "
                    "executable test for the MOD-1.8 metrics/facade extraction."
                ),
                "adr": "docs/architecture/ADR_MOD03_OWNERSHIP_AND_LAYERING_V1.md",
            },
            {
                "path": "srchybrid/tests/test_web_request_parser.cpp",
                "reason": (
                    "Standalone request, query, cookie and hostile-limit "
                    "executable test for the MOD-2.1 parser extraction."
                ),
                "adr": "docs/architecture/ADR_MOD03_OWNERSHIP_AND_LAYERING_V1.md",
            },
            {
                "path": "srchybrid/tests/test_web_auth_policy.cpp",
                "reason": (
                    "Standalone concurrent session, challenge replay, CSRF, "
                    "permission and rate-limit executable test for the "
                    "MOD-2.2 auth-policy extraction."
                ),
                "adr": "docs/architecture/ADR_MOD03_OWNERSHIP_AND_LAYERING_V1.md",
            },
            {
                "path": "srchybrid/tests/test_web_route_table.cpp",
                "reason": (
                    "Standalone exact, dynamic, method-matrix and hostile-route "
                    "executable test for the MOD-2.3 route-table extraction."
                ),
                "adr": "docs/architecture/ADR_MOD03_OWNERSHIP_AND_LAYERING_V1.md",
            },
            {
                "path": "srchybrid/tests/test_web_api_serializer.cpp",
                "reason": (
                    "Standalone byte/code-unit exact JSON, HTML and XML "
                    "escaping test for the MOD-2.4 serializer extraction."
                ),
                "adr": "docs/architecture/ADR_MOD03_OWNERSHIP_AND_LAYERING_V1.md",
            },
        ])
        self.assertEqual(self.config["slice_evidence"], {
            "state": "EXTRACTION_ACTIVE",
            "entries": [{
                "module": "LiveTunnelFraming",
                "slice_base_commit": "3a1ccf5faec81ea8fa60cf9b084cb76be98f2074",
                "source_coordinator": "srchybrid/LiveTunnel.cpp",
            }, {
                "module": "LiveHandshakeWire",
                "slice_base_commit": "0a173aa306963c7c8a1ed4478456c1fc20f79d05",
                "source_coordinator": "srchybrid/LiveTunnel.cpp",
            }, {
                "module": "LiveTunnelPending",
                "slice_base_commit": "778631c0559880be06e62146a5bae44623536383",
                "source_coordinator": "srchybrid/LiveTunnel.cpp",
            }, {
                "module": "LiveCircuitRegistry",
                "slice_base_commit": "948e4e93815c6b3bd028316040e1b1c447c86c57",
                "source_coordinator": "srchybrid/LiveTunnel.cpp",
            }, {
                "module": "LiveCircuitHandshake",
                "slice_base_commit": "0a173aa306963c7c8a1ed4478456c1fc20f79d05",
                "source_coordinator": "srchybrid/LiveTunnel.cpp",
            }, {
                "module": "LiveRelayDispatcher",
                "slice_base_commit": "e99303ba2377122cd173016f5f91a006c0ddcf41",
                "source_coordinator": "srchybrid/LiveTunnel.cpp",
            }, {
                "module": "LiveExitServices",
                "slice_base_commit": "e99303ba2377122cd173016f5f91a006c0ddcf41",
                "source_coordinator": "srchybrid/LiveTunnel.cpp",
            }, {
                "module": "LiveTunnelScheduler",
                "slice_base_commit": "ed017dd19423618cfc9d138724cdc091bdcf4525",
                "source_coordinator": "srchybrid/LiveTunnel.cpp",
            }, {
                "module": "LiveTunnelPeerState",
                "slice_base_commit": "8748a666f9881b6343e8ed866198feb21c1dcad9",
                "source_coordinator": "srchybrid/LiveTunnel.cpp",
            }, {
                "module": "LiveTunnelKadBridge",
                "slice_base_commit": "8748a666f9881b6343e8ed866198feb21c1dcad9",
                "source_coordinator": "srchybrid/LiveTunnel.cpp",
            }, {
                "module": "LiveTunnelMetrics",
                "slice_base_commit": "1f2e155551d5a5ab7a934e2f6bab34d0da804209",
                "source_coordinator": "srchybrid/LiveTunnel.cpp",
            }, {
                "module": "WebRequestParser",
                "slice_base_commit": "beb494b9907877a100d728ae87a029e9e8d11330",
                "source_coordinator": "srchybrid/WebServer.cpp",
            }, {
                "module": "WebAuthPolicy",
                "slice_base_commit": "630ef1cc6dac053006582714ace613670d8dc658",
                "source_coordinator": "srchybrid/WebServer.cpp",
            }, {
                "module": "WebRouteTable",
                "slice_base_commit": "f6f9d700d7682bb4b228d259f69107d69b066a85",
                "source_coordinator": "srchybrid/WebServer.cpp",
            }, {
                "module": "WebApiSerializer",
                "slice_base_commit": "12b60647c2cd6c76e014cd0d1fda3463ed56640c",
                "source_coordinator": "srchybrid/WebServer.cpp",
            }],
        })

    def test_only_completed_extractions_are_claimed(self) -> None:
        self.assertEqual(self.config["mod03_contract"]["planned_module_count"], 30)
        self.assertEqual(len(VERIFIER._planned_modules(self.contract)), 30)
        self.assertEqual(
            [entry["name"] for entry in self.config["module_catalog"]["entries"]],
            [
                "LiveTunnelFraming",
                "LiveHandshakeWire",
                "LiveTunnelPending",
                "LiveCircuitRegistry",
                "LiveCircuitHandshake",
                "LiveRelayDispatcher",
                "LiveExitServices",
                "LiveTunnelScheduler",
                "LiveTunnelPeerState",
                "LiveTunnelKadBridge",
                "LiveTunnelMetrics",
                "WebRequestParser",
                "WebAuthPolicy",
                "WebRouteTable",
                "WebApiSerializer",
            ],
        )

    def test_growth_limit_is_binding_while_final_targets_remain_end_state_only(self) -> None:
        path = self.config["coordinator_files"][0]["path"]
        raw = (ROOT / path).read_bytes()
        baseline = self.config["coordinator_files"][0]["baseline_loc_physical"]
        lines_to_exceed_baseline = baseline - VERIFIER.loc_physical(raw) + 1
        grown = raw + (b"// coordinator growth fixture\n" * lines_to_exceed_baseline)
        with self.assertRaisesRegex(VERIFIER.GateError, "coordinator LOC grew over baseline"):
            VERIFIER.validate(self.config, self.contract, {path: grown})

    def test_baseline_mapping_scope_rule_and_limits_are_immutable(self) -> None:
        mutations = (
            ("baseline_commit", "drift", "baseline_commit drift"),
            ("scope", "drift", "baseline scope drift"),
            ("slice_rule", "drift", "slice_rule drift"),
        )
        for field, value, reason in mutations:
            config = copy.deepcopy(self.config)
            config[field] = value
            with self.assertRaisesRegex(VERIFIER.GateError, reason):
                VERIFIER.validate(config, self.contract, check_git_baseline=False)
        metric = copy.deepcopy(self.config)
        metric["coordinator_files"][0]["baseline_loc_physical"] += 1
        with self.assertRaisesRegex(VERIFIER.GateError, "coordinator baseline metric drift"):
            VERIFIER.validate(metric, self.contract, check_git_baseline=False)
        limit = copy.deepcopy(self.config)
        limit["coordinator_files"][0]["final_target_loc_max"] += 1
        with self.assertRaisesRegex(VERIFIER.GateError, "coordinator final limit drift"):
            VERIFIER.validate(limit, self.contract, check_git_baseline=False)

    def test_closed_discovery_and_allowlist_schema_are_enforced(self) -> None:
        with self.assertRaisesRegex(VERIFIER.GateError, r"new or renamed C/C\+\+ file is uncatalogued"):
            VERIFIER.validate(
                self.config, self.contract,
                overrides={"srchybrid/LiveTunnelFramingImpl.cpp": b""},
                discovery_overrides={"srchybrid/LiveTunnelFramingImpl.cpp"},
            )
        allowed = copy.deepcopy(self.config)
        allowed["approved_non_module_code"] = copy.deepcopy(
            self.config["approved_non_module_code"]
        ) + [{
            "path": "srchybrid/NewHelper.h", "reason": "fixture",
            "adr": "docs/architecture/ADR_MOD03_OWNERSHIP_AND_LAYERING_V1.md",
        }]
        messages = VERIFIER.validate(
            allowed, self.contract,
            overrides={"srchybrid/NewHelper.h": b""},
            discovery_overrides={"srchybrid/NewHelper.h"},
        )
        self.assertTrue(
            any(message.startswith("slice LiveTunnelFraming:") for message in messages),
            messages,
        )

    def test_cli_positive_and_exact_negative_fixtures(self) -> None:
        for mode, needle in (
            ("--verify", "slice LiveTunnelFraming:"),
            ("--negative-fixtures", "41 negative fixtures"),
        ):
            completed = subprocess.run([sys.executable, str(SCRIPT), mode], cwd=ROOT,
                                       text=True, capture_output=True, check=False)
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertIn(needle, completed.stdout)

    def test_workflow_binds_the_modularization_suite_before_build(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("Architecture gates (MOD-0.1 through MOD-0.4)", workflow)
        self.assertIn('python -m unittest discover -s tests -p "test_v92_mod*.py"', workflow)
        self.assertIn("actions/setup-python@v6", workflow)
        self.assertIn("python-version: '3.12'", workflow)
        self.assertIn("fetch-depth: 0", workflow)
        self.assertLess(workflow.index("Setup Python 3.12"),
                        workflow.index("Architecture gates (MOD-0.1 through MOD-0.4)"))
        self.assertLess(workflow.index("Architecture gates (MOD-0.1 through MOD-0.4)"),
                        workflow.index("Build ese-server.exe (pkg)"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
