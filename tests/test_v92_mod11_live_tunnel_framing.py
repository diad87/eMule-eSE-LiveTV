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
