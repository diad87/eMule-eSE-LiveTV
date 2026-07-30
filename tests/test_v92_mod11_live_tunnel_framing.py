"""MOD-1.1 host contract for the byte-exact LiveTunnel framing extraction."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import pathlib
import re
import subprocess
import unittest
import xml.etree.ElementTree as ET


ROOT = pathlib.Path(__file__).resolve().parents[1]
HEADER = ROOT / "srchybrid" / "LiveTunnelFraming.h"
SOURCE = ROOT / "srchybrid" / "LiveTunnelFraming.cpp"
QUEUE_HEADER = ROOT / "srchybrid" / "LiveCellQueue.h"
QUEUE_SOURCE = ROOT / "srchybrid" / "LiveCellQueue.cpp"
TUNNEL_SOURCE = ROOT / "srchybrid" / "LiveTunnel.cpp"
NATIVE_TEST = ROOT / "srchybrid" / "tests" / "test_live_tunnel_framing.cpp"
MAKE = ROOT / "srchybrid" / "tests" / "make.bat"
PROJECT = ROOT / "srchybrid" / "emule.vcxproj"
MOD01_OVERLAYS = ROOT / "docs" / "architecture" / "mod01_approved_overlays_v1.json"
MOD02_GOLDENS = ROOT / "docs" / "architecture" / "mod02_characterization_goldens_v1.json"
MOD02_VERIFY = ROOT / "tools" / "architecture" / "verify_mod02_characterization.py"
MOD02_TEST = ROOT / "tests" / "test_v92_mod02_characterization.py"
MOD02_RUNNER = ROOT / "tools" / "architecture" / "run_mod02_stream_selftest.ps1"
MOD02_IDENTITY = ROOT / "srchybrid" / "Mod02BuildIdentity.h"
MOD04_BASELINE = ROOT / "docs" / "architecture" / "mod04_architecture_gate_baseline_v1.json"
SLICE_BASE = "3a1ccf5faec81ea8fa60cf9b084cb76be98f2074"
MOVED_SYMBOLS = (
    "PackSubHeader",
    "ParseSubHeader",
    "PackFragHeader",
    "ParseFragHeader",
    "SplitIntoCells",
    "ReassemblyIngest",
)

SPEC = importlib.util.spec_from_file_location("mod02_verifier_for_mod11", MOD02_VERIFY)
assert SPEC is not None and SPEC.loader is not None
MOD02 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD02)


class Mod11LiveTunnelFramingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.header = HEADER.read_text(encoding="utf-8")
        cls.source = SOURCE.read_text(encoding="utf-8")
        cls.queue_header = QUEUE_HEADER.read_text(encoding="utf-8")
        cls.queue_source = QUEUE_SOURCE.read_text(encoding="utf-8")
        cls.tunnel_source = TUNNEL_SOURCE.read_text(encoding="utf-8")
        cls.baseline = json.loads(MOD04_BASELINE.read_text(encoding="utf-8"))
        cls.goldens = json.loads(MOD02_GOLDENS.read_text(encoding="utf-8"))

    def test_module_is_pure_readable_and_within_the_planned_size(self) -> None:
        self.assertNotIn("stdafx.h", self.source)
        includes = re.findall(
            r'#\s*include\s*[<"]([^>"]+)[>"]',
            self.header + self.source,
        )
        self.assertEqual(
            set(includes),
            {
                "LiveTunnelFraming.h",
                "stddef.h",
                "stdint.h",
                "string.h",
                "utility",
                "vector",
            },
        )
        self.assertTrue({
            pathlib.PurePosixPath(include).name.casefold()
            for include in includes
        }.isdisjoint({
            "livetunnel.h",
            "webserver.h",
            "livestreammanager.h",
            "windows.h",
            "afx.h",
            "afxwin.h",
        }))
        module_loc = len(self.header.splitlines()) + len(self.source.splitlines())
        self.assertGreaterEqual(module_loc, 300)
        self.assertLessEqual(module_loc, 1200)
        self.assertGreater(self.source.count("\n"), 150)
        self.assertGreater(self.header.count("\n"), 120)

    def test_only_framing_moved_and_queue_crypto_boundary_remains(self) -> None:
        for symbol in MOVED_SYMBOLS:
            self.assertIn(symbol + "(", self.source)
            self.assertNotIn(symbol + "(", self.queue_source)
            self.assertNotIn(symbol + "(", self.queue_header)
        for symbol in ("CellPack", "CellUnpack", "CCellQueue::Push", "CCellQueue::Pop"):
            self.assertIn(symbol, self.queue_source)
            self.assertNotIn(symbol, self.source)
        self.assertIn('#include "LiveOnionCrypto.h"', self.queue_source)
        self.assertIn("SecureRandomBytes", self.queue_source)
        self.assertIn('#include "LiveTunnelFraming.h"', self.queue_header)
        self.assertIn("class CCellQueue", self.queue_header)

    def test_mod02_wire_fingerprints_are_unchanged_and_rebound(self) -> None:
        spec = self.goldens["goldens"]["live_tunnel_framing"]
        self.assertEqual(spec["production_file"], "srchybrid/LiveTunnelFraming.cpp")
        self.assertEqual(
            MOD02.fingerprint(spec["production_file"], spec["symbols"]),
            spec["token_sha256"],
        )
        self.assertEqual(set(spec["symbols"]), {
            "PackSubHeader",
            "ParseSubHeader",
            "PackFragHeader",
            "ParseFragHeader",
        })

    def test_characterization_wrapper_preserves_diagnostics_and_stateful_check(self) -> None:
        for result, diagnostic in (
            ("SplitFailed", "tunnel framing split failed"),
            ("ParseOrReassemblyFailed", "tunnel framing parse or reassembly failed"),
            ("PayloadMismatch", "tunnel framing payload mismatch"),
        ):
            self.assertIn("FramingSelfTestResult::" + result, self.tunnel_source)
            self.assertIn(diagnostic, self.tunnel_source)
        self.assertIn("RunFramingCharacterizationSelfTest()", self.tunnel_source)
        self.assertIn("SendThrough(NULL, 0)", self.tunnel_source)
        self.assertIn("tunnel empty dispatch was accepted", self.tunnel_source)

    def test_project_and_standalone_gate_compile_the_production_module(self) -> None:
        tree = ET.parse(PROJECT)
        namespace = {"m": "http://schemas.microsoft.com/developer/msbuild/2003"}
        items = tree.findall(".//m:ClCompile[@Include='LiveTunnelFraming.cpp']", namespace)
        self.assertEqual(len(items), 1)
        item = items[0]
        self.assertEqual(item.findtext("m:PrecompiledHeader", namespaces=namespace), "NotUsing")
        self.assertEqual(item.findtext("m:LanguageStandard", namespaces=namespace), "stdcpp17")
        self.assertEqual(item.findtext("m:WarningLevel", namespaces=namespace), "Level4")
        self.assertEqual(
            item.findtext("m:TreatWarningAsError", namespaces=namespace),
            "true",
        )
        project_headers = tree.findall(
            ".//m:ClInclude[@Include='LiveTunnelFraming.h']", namespace
        )
        self.assertEqual(len(project_headers), 1)

        make = MAKE.read_text(encoding="utf-8")
        compile_line = next(
            line for line in make.splitlines()
            if "test_live_tunnel_framing.exe" in line and line.lstrip().startswith("cl ")
        )
        self.assertIn("/W4 /WX /std:c++17", compile_line)
        self.assertIn("tests\\test_live_tunnel_framing.cpp", compile_line)
        self.assertIn("LiveTunnelFraming.cpp", compile_line)
        self.assertIn("tests\\build\\test_live_tunnel_framing.exe", make)

    def test_native_goldens_cover_wire_order_duplicates_and_hostile_bounds(self) -> None:
        native = NATIVE_TEST.read_text(encoding="utf-8")
        for required in (
            "sub-header byte golden",
            "fragment-header byte golden",
            "out-of-order reassembly completes",
            "duplicate fragment is idempotent",
            "zero-byte message reassembles safely",
            "reject declared sub-header overrun",
            "reject inconsistent fragment count",
            "reject inconsistent declared total",
            "reject completed message with wrong total size",
            "production characterization helper",
        ):
            self.assertIn(required, native)
        self.assertNotIn("assert(", native)
        self.assertNotRegex(native, r"cells\[[2-9]\].*zero")

    def test_architecture_catalog_slice_and_test_allowlist_are_exact(self) -> None:
        self.assertEqual(self.baseline["module_catalog"], {
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
            }, {
                "name": "WebTransferController",
                "owner": "CWebServer",
                "layer": "application",
                "implementation_files": ["srchybrid/WebTransferController.cpp"],
                "interface_files": ["srchybrid/WebTransferController.h"],
                "declared_direct_dependencies": [],
            }, {
                "name": "WebSearchController",
                "owner": "CWebServer",
                "layer": "application",
                "implementation_files": ["srchybrid/WebSearchController.cpp"],
                "interface_files": ["srchybrid/WebSearchController.h"],
                "declared_direct_dependencies": [],
            }, {
                "name": "WebSharedController",
                "owner": "CWebServer",
                "layer": "application",
                "implementation_files": ["srchybrid/WebSharedController.cpp"],
                "interface_files": ["srchybrid/WebSharedController.h"],
                "declared_direct_dependencies": [],
            }, {
                "name": "WebStaticAssets",
                "owner": "CWebServer",
                "layer": "application",
                "implementation_files": ["srchybrid/WebStaticAssets.cpp"],
                "interface_files": ["srchybrid/WebStaticAssets.h"],
                "declared_direct_dependencies": [],
            }, {
                "name": "WebSocketResponse",
                "owner": "CWebServer",
                "layer": "adapters",
                "implementation_files": ["srchybrid/WebSocketResponse.cpp"],
                "interface_files": ["srchybrid/WebSocketResponse.h"],
                "declared_direct_dependencies": [],
            }, {
                "name": "WebDiagnostics",
                "owner": "CWebServer",
                "layer": "application",
                "implementation_files": ["srchybrid/WebDiagnostics.cpp"],
                "interface_files": ["srchybrid/WebDiagnostics.h"],
                "declared_direct_dependencies": [],
            }, {
                "name": "LiveBroadcastSession",
                "owner": "CLiveStreamManager",
                "layer": "domain_state",
                "implementation_files": ["srchybrid/LiveBroadcastSession.cpp"],
                "interface_files": ["srchybrid/LiveBroadcastSession.h"],
                "declared_direct_dependencies": [],
            }, {
                "name": "LiveViewerSession",
                "owner": "CLiveStreamManager",
                "layer": "domain_state",
                "implementation_files": ["srchybrid/LiveViewerSession.cpp"],
                "interface_files": ["srchybrid/LiveViewerSession.h"],
                "declared_direct_dependencies": [],
            }, {
                "name": "LivePeerSet",
                "owner": "CLiveStreamManager",
                "layer": "domain_state",
                "implementation_files": ["srchybrid/LivePeerSet.cpp"],
                "interface_files": ["srchybrid/LivePeerSet.h"],
                "declared_direct_dependencies": [],
            }, {
                "name": "LiveChunkWindow",
                "owner": "CLiveStreamManager",
                "layer": "domain_state",
                "implementation_files": ["srchybrid/LiveChunkWindow.cpp"],
                "interface_files": ["srchybrid/LiveChunkWindow.h"],
                "declared_direct_dependencies": [],
            }, {
                "name": "LiveStreamSecurity",
                "owner": "CLiveStreamManager",
                "layer": "domain_state",
                "implementation_files": ["srchybrid/LiveStreamSecurity.cpp"],
                "interface_files": ["srchybrid/LiveStreamSecurity.h"],
                "declared_direct_dependencies": [],
            }, {
                "name": "LiveStreamFanout",
                "owner": "CLiveStreamManager",
                "layer": "application",
                "implementation_files": ["srchybrid/LiveStreamFanout.cpp"],
                "interface_files": ["srchybrid/LiveStreamFanout.h"],
                "declared_direct_dependencies": [],
            }, {
                "name": "LiveStreamRecovery",
                "owner": "CLiveStreamManager",
                "layer": "application",
                "implementation_files": ["srchybrid/LiveStreamRecovery.cpp"],
                "interface_files": ["srchybrid/LiveStreamRecovery.h"],
                "declared_direct_dependencies": [],
            }],
        })
        self.assertEqual(self.baseline["slice_evidence"], {
            "state": "EXTRACTION_ACTIVE",
            "entries": [{
                "module": "LiveTunnelFraming",
                "slice_base_commit": SLICE_BASE,
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
            }, {
                "module": "WebTransferController",
                "slice_base_commit": "cd64a412b0dfe0b3e65ebd3e4c3fc454240f3b95",
                "source_coordinator": "srchybrid/WebServer.cpp",
            }, {
                "module": "WebSearchController",
                "slice_base_commit": "cd64a412b0dfe0b3e65ebd3e4c3fc454240f3b95",
                "source_coordinator": "srchybrid/WebServer.cpp",
            }, {
                "module": "WebSharedController",
                "slice_base_commit": "cd64a412b0dfe0b3e65ebd3e4c3fc454240f3b95",
                "source_coordinator": "srchybrid/WebServer.cpp",
            }, {
                "module": "WebStaticAssets",
                "slice_base_commit": "6a83cb2797c48918f9e2adbd7dda6f4d5b405145",
                "source_coordinator": "srchybrid/WebServer.cpp",
            }, {
                "module": "WebSocketResponse",
                "slice_base_commit": "6a83cb2797c48918f9e2adbd7dda6f4d5b405145",
                "source_coordinator": "srchybrid/WebServer.cpp",
            }, {
                "module": "WebDiagnostics",
                "slice_base_commit": "96e1c64833dd0bd4da3715ed48b7d664684de329",
                "source_coordinator": "srchybrid/WebServer.cpp",
            }, {
                "module": "LiveBroadcastSession",
                "slice_base_commit": "a48445e560765fc68fc85b0e61a09e2e72b7f9de",
                "source_coordinator": "srchybrid/LiveStreamManager.cpp",
            }, {
                "module": "LiveViewerSession",
                "slice_base_commit": "a48445e560765fc68fc85b0e61a09e2e72b7f9de",
                "source_coordinator": "srchybrid/LiveStreamManager.cpp",
            }, {
                "module": "LivePeerSet",
                "slice_base_commit": "e56166bc11bbd41c6f27978519bad4b6099a3952",
                "source_coordinator": "srchybrid/LiveStreamManager.cpp",
            }, {
                "module": "LiveChunkWindow",
                "slice_base_commit": "d032418e65a2dc64c726c46a275e5841a9a34874",
                "source_coordinator": "srchybrid/LiveStreamManager.cpp",
            }, {
                "module": "LiveStreamSecurity",
                "slice_base_commit": "05c815444d106e305908ee076bd3c2bf62f24883",
                "source_coordinator": "srchybrid/LiveStreamManager.cpp",
            }, {
                "module": "LiveStreamFanout",
                "slice_base_commit": "c476950d1590fb7f337cc3010e1a86bdee10537d",
                "source_coordinator": "srchybrid/LiveStreamManager.cpp",
            }, {
                "module": "LiveStreamRecovery",
                "slice_base_commit": "03b8bb118d06b7d7407faaff0c7552b6ef51a2d1",
                "source_coordinator": "srchybrid/LiveStreamManager.cpp",
            }],
        })
        self.assertEqual(self.baseline["approved_non_module_code"], [
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
            {
                "path": "srchybrid/tests/test_web_controllers.cpp",
                "reason": (
                    "Standalone action, projection-policy and hostile-boundary "
                    "executable test for the three MOD-2.5 Web controller "
                    "extractions."
                ),
                "adr": "docs/architecture/ADR_MOD03_OWNERSHIP_AND_LAYERING_V1.md",
            },
            {
                "path": "srchybrid/tests/test_web_streaming.cpp",
                "reason": (
                    "Standalone range, MIME, cache, response-queue, "
                    "partial-write and bounded-source executable test for the "
                    "two MOD-2.6 Web streaming extractions."
                ),
                "adr": "docs/architecture/ADR_MOD03_OWNERSHIP_AND_LAYERING_V1.md",
            },
            {
                "path": "srchybrid/tests/test_web_diagnostics.cpp",
                "reason": (
                    "Standalone exact status, mesh, live-debug, privacy, "
                    "tick-wrap and hostile-bound executable test for the "
                    "MOD-2.7 diagnostics facade extraction."
                ),
                "adr": "docs/architecture/ADR_MOD03_OWNERSHIP_AND_LAYERING_V1.md",
            },
            {
                "path": "srchybrid/tests/test_live_stream_sessions.cpp",
                "reason": (
                    "Standalone lifecycle, dual-role, retry, tick-wrap and "
                    "secret-wipe executable test for the two MOD-3.1 session "
                    "extractions."
                ),
                "adr": "docs/architecture/ADR_MOD03_OWNERSHIP_AND_LAYERING_V1.md",
            },
            {
                "path": "srchybrid/tests/test_live_peer_set.cpp",
                "reason": (
                    "Standalone role, replacement, limit, ordering and IPv4 "
                    "diversity executable test for the MOD-3.2 peer-set "
                    "extraction."
                ),
                "adr": "docs/architecture/ADR_MOD03_OWNERSHIP_AND_LAYERING_V1.md",
            },
            {
                "path": "srchybrid/tests/test_live_chunk_window.cpp",
                "reason": (
                    "Standalone ingest, ordering, expiry, wraparound, "
                    "immutable-lifetime and reentrant-callback executable test "
                    "for the MOD-3.3 chunk-window extraction."
                ),
                "adr": "docs/architecture/ADR_MOD03_OWNERSHIP_AND_LAYERING_V1.md",
            },
            {
                "path": "srchybrid/tests/test_live_stream_security.cpp",
                "reason": (
                    "Standalone pinning, verified replay, serial-wrap, capacity, "
                    "concurrency and trust-policy executable test for the "
                    "MOD-3.4 security extraction."
                ),
                "adr": "docs/architecture/ADR_MOD03_OWNERSHIP_AND_LAYERING_V1.md",
            },
            {
                "path": "srchybrid/tests/test_live_stream_fanout.cpp",
                "reason": (
                    "Standalone selection, atomic batch reservation, "
                    "backpressure, replacement, closure and concurrency "
                    "executable test for the MOD-3.5 fanout extraction."
                ),
                "adr": "docs/architecture/ADR_MOD03_OWNERSHIP_AND_LAYERING_V1.md",
            },
            {
                "path": "srchybrid/LiveFanoutTransportAdapter.cpp",
                "reason": (
                    "Narrow MFC adapter projecting packet batches, socket queue "
                    "depth and transport completion into the portable MOD-3.5 "
                    "fanout owner."
                ),
                "adr": "docs/architecture/ADR_MOD03_OWNERSHIP_AND_LAYERING_V1.md",
            },
            {
                "path": "srchybrid/LiveFanoutTransportAdapter.h",
                "reason": (
                    "Move-only legacy packet-batch boundary for MOD-3.5 without "
                    "exposing Packet or CUpDownClient to the portable module."
                ),
                "adr": "docs/architecture/ADR_MOD03_OWNERSHIP_AND_LAYERING_V1.md",
            },
            {
                "path": "srchybrid/tests/test_live_stream_recovery.cpp",
                "reason": (
                    "Standalone retry, replenishment, emergency, FEC/NACK and "
                    "hostile-boundary executable test for the MOD-3.6 recovery extraction."
                ),
                "adr": "docs/architecture/ADR_MOD03_OWNERSHIP_AND_LAYERING_V1.md",
            },
            {
                "path": "srchybrid/LiveRecoveryTransportAdapter.cpp",
                "reason": (
                    "Narrow MFC adapter projecting typed peer endpoints into "
                    "the portable MOD-3.6 recovery owner."
                ),
                "adr": "docs/architecture/ADR_MOD03_OWNERSHIP_AND_LAYERING_V1.md",
            },
            {
                "path": "srchybrid/LiveRecoveryTransportAdapter.h",
                "reason": (
                    "Pointer-free recovery endpoint projection boundary for "
                    "MOD-3.6 without exposing CUpDownClient or CAddress to the "
                    "portable module."
                ),
                "adr": "docs/architecture/ADR_MOD03_OWNERSHIP_AND_LAYERING_V1.md",
            },
            {
                "path": "srchybrid/LiveStreamTrustAdapter.cpp",
                "reason": (
                    "Legacy MFC adapter projecting durable Live peer identities "
                    "and DTOs into the portable MOD-3.4 security owner without "
                    "creating a reverse domain dependency."
                ),
                "adr": "docs/architecture/ADR_MOD03_OWNERSHIP_AND_LAYERING_V1.md",
            },
            {
                "path": "srchybrid/LiveStreamTrustAdapter.h",
                "reason": (
                    "Narrow legacy projection interface binding LiveProtocol "
                    "DTOs to the portable MOD-3.4 security owner."
                ),
                "adr": "docs/architecture/ADR_MOD03_OWNERSHIP_AND_LAYERING_V1.md",
            },
        ])
        numstat = subprocess.check_output(
            ["git", "diff", "--numstat", SLICE_BASE, "--", "srchybrid/LiveTunnel.cpp"],
            cwd=ROOT,
            text=True,
        ).strip().split("\t")
        self.assertGreaterEqual(len(numstat), 2)
        self.assertTrue(numstat[0].isdigit() and numstat[1].isdigit())
        self.assertGreater(int(numstat[1]), int(numstat[0]))

    def test_mod01_overlay_and_mod02_identity_inputs_follow_the_extraction(self) -> None:
        overlays = json.loads(MOD01_OVERLAYS.read_text(encoding="utf-8"))
        tunnel = next(
            item for item in overlays["overlays"]
            if item["path"] == "srchybrid/LiveTunnel.cpp"
        )
        self.assertIn("MOD-0.2", tunnel["task"])
        self.assertIn("MOD-1.1", tunnel["task"])
        normalized = TUNNEL_SOURCE.read_bytes().replace(b"\r\n", b"\n")
        self.assertEqual(
            tunnel["overlay_sha256"],
            hashlib.sha256(normalized).hexdigest(),
        )

        expected_paths = {
            "srchybrid/LiveTunnelFraming.cpp",
            "srchybrid/LiveTunnelFraming.h",
            "srchybrid/LiveHandshakeWire.cpp",
            "srchybrid/LiveHandshakeWire.h",
            "srchybrid/LiveRelayDispatcher.cpp",
            "srchybrid/LiveRelayDispatcher.h",
            "srchybrid/LiveExitServices.cpp",
            "srchybrid/LiveExitServices.h",
            "srchybrid/LiveRelayTypes.h",
            "srchybrid/LiveTunnelScheduler.cpp",
            "srchybrid/LiveTunnelScheduler.h",
            "srchybrid/LiveTunnelPeerState.cpp",
            "srchybrid/LiveTunnelPeerState.h",
            "srchybrid/LiveTunnelKadBridge.cpp",
            "srchybrid/LiveTunnelKadBridge.h",
            "srchybrid/LiveTunnelMetrics.cpp",
            "srchybrid/LiveTunnelMetrics.h",
            "srchybrid/WebSocket.cpp",
            "srchybrid/WebSocket.h",
            "srchybrid/WebRequestParser.cpp",
            "srchybrid/WebRequestParser.h",
            "srchybrid/WebAuthPolicy.cpp",
            "srchybrid/WebAuthPolicy.h",
            "srchybrid/WebRouteTable.cpp",
            "srchybrid/WebRouteTable.h",
            "srchybrid/WebApiSerializer.cpp",
            "srchybrid/WebApiSerializer.h",
            "srchybrid/WebTransferController.cpp",
            "srchybrid/WebTransferController.h",
            "srchybrid/WebSearchController.cpp",
            "srchybrid/WebSearchController.h",
            "srchybrid/WebSharedController.cpp",
            "srchybrid/WebSharedController.h",
            "srchybrid/WebStaticAssets.cpp",
            "srchybrid/WebStaticAssets.h",
            "srchybrid/WebSocketResponse.cpp",
            "srchybrid/WebSocketResponse.h",
            "srchybrid/WebDiagnostics.cpp",
            "srchybrid/WebDiagnostics.h",
            "srchybrid/LiveBroadcastSession.cpp",
            "srchybrid/LiveBroadcastSession.h",
            "srchybrid/LiveViewerSession.cpp",
            "srchybrid/LiveViewerSession.h",
            "srchybrid/LivePeerSet.cpp",
            "srchybrid/LivePeerSet.h",
            "srchybrid/LiveChunkWindow.cpp",
            "srchybrid/LiveChunkWindow.h",
            "srchybrid/LiveStreamSecurity.cpp",
            "srchybrid/LiveStreamSecurity.h",
            "srchybrid/LiveStreamFanout.cpp",
            "srchybrid/LiveStreamFanout.h",
            "srchybrid/LiveStreamRecovery.cpp",
            "srchybrid/LiveStreamRecovery.h",
            "srchybrid/LiveRecoveryTransportAdapter.cpp",
            "srchybrid/LiveRecoveryTransportAdapter.h",
            "srchybrid/LiveFanoutTransportAdapter.cpp",
            "srchybrid/LiveFanoutTransportAdapter.h",
            "srchybrid/LiveStreamTrustAdapter.cpp",
            "srchybrid/LiveStreamTrustAdapter.h",
            "srchybrid/ClientList.cpp",
            "srchybrid/ClientList.h",
            "srchybrid/LiveMeshManager.cpp",
            "srchybrid/LiveMeshManager.h",
            "srchybrid/LiveBuddyRelay.cpp",
            "srchybrid/LiveBuddyRelay.h",
            "srchybrid/LiveStreamDlgUI.cpp",
            "srchybrid/LiveStreamDlg.h",
        }
        self.assertTrue(expected_paths.issubset(set(MOD02.CRITICAL_SOURCE_PATHS)))
        self.assertTrue(expected_paths.issubset(set(
            _critical_paths_from_test(MOD02_TEST.read_text(encoding="utf-8"))
        )))
        runner = MOD02_RUNNER.read_text(encoding="utf-8")
        for path in expected_paths:
            self.assertIn("'" + path + "'", runner)

        identity = MOD02.source_identity()
        header = MOD02_IDENTITY.read_text(encoding="utf-8")
        match = re.search(
            r'ESE_MOD02_CRITICAL_SOURCE_SHA256\s+"([0-9a-f]{64})"',
            header,
        )
        self.assertIsNotNone(match)
        assert match is not None
        self.assertEqual(match.group(1), identity)


def _critical_paths_from_test(text: str) -> list[str]:
    match = re.search(
        r"CRITICAL_SOURCE_PATHS\s*=\s*\[(.*?)\]\n",
        text,
        re.DOTALL,
    )
    if match is None:
        return []
    return re.findall(r'"([^"]+)"', match.group(1))


if __name__ == "__main__":
    unittest.main(verbosity=2)
