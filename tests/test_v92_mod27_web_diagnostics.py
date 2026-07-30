"""Production binding and fail-closed checks for MOD-2.7."""

from __future__ import annotations

import json
import pathlib
import subprocess
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
CONTRACT = (
    ROOT / "docs" / "architecture" / "mod27_web_diagnostics_contract_v1.json"
)


class Mod27WebDiagnosticsProductionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        cls.header = (
            ROOT / "srchybrid" / "WebDiagnostics.h"
        ).read_text(encoding="utf-8")
        cls.source = (
            ROOT / "srchybrid" / "WebDiagnostics.cpp"
        ).read_text(encoding="utf-8")
        cls.web_server = (
            ROOT / "srchybrid" / "WebServer.cpp"
        ).read_text(encoding="utf-8", errors="replace")
        cls.native_test = (
            ROOT / "srchybrid" / "tests" / "test_web_diagnostics.cpp"
        ).read_text(encoding="utf-8")

    def test_contract_is_exact_and_value_only(self) -> None:
        self.assertEqual(
            self.contract["schema"],
            "ese.mod27.web-diagnostics-contract/v1",
        )
        self.assertEqual(
            self.contract["module"]["routes"],
            ["/api/status", "/api/live/mesh", "/api/live/debug"],
        )
        self.assertEqual(
            self.contract["module"]["declared_direct_dependencies"],
            [],
        )
        self.assertEqual(self.contract["bounds"]["peer_detail_max"], 16)
        self.assertEqual(self.contract["privacy"]["remote_user_hash"], None)
        for concrete in (
            "CString",
            "CWebServer",
            "CWebSocket",
            "LiveDebugSnapshot",
            "HANDLE",
            "SOCKET",
            "windows.h",
        ):
            self.assertNotIn(concrete, self.header + self.source)

    def test_project_and_native_gate_compile_the_facade(self) -> None:
        project = (ROOT / "srchybrid" / "emule.vcxproj").read_text()
        make = (ROOT / "srchybrid" / "tests" / "make.bat").read_text()
        for name in ("WebDiagnostics.cpp", "WebDiagnostics.h"):
            self.assertIn(f'{name}"', project)
        self.assertIn("test_web_diagnostics.cpp", make)
        self.assertIn(
            "test_web_diagnostics.cpp WebDiagnostics.cpp",
            make,
        )

    def test_status_privacy_and_hostile_text_fail_closed(self) -> None:
        for token in (
            "if (local.exposed)",
            '"null"',
            "output += \"\\\\u00\"",
            '\\"user_hash\\"',
            '\\"connecting_client_duplicate_adds\\"',
            '\\"netlab_contribution_consent\\"',
        ):
            self.assertIn(token, self.source)
        self.assertIn(
            "Data.inadr.S_un.S_addr == htonl(INADDR_LOOPBACK)",
            self.web_server,
        )
        self.assertNotIn("localDiagnosticJson", self.web_server)

    def test_debug_projection_is_bounded_and_wrap_safe(self) -> None:
        self.assertIn(
            "return timestamp == 0u ? 0u : now - timestamp",
            self.source,
        )
        self.assertIn(
            "std::min(model.peer_detail.size(), MaxDebugPeers())",
            self.source,
        )
        self.assertIn("output += \"\\\\u00\"", self.source)
        self.assertIn(
            "LiveDebugSnapshot::MAX_PEER_DBG",
            self.web_server,
        )
        self.assertIn("BuildDebugSnapshot()", self.web_server)
        self.assertNotIn("lastChunkReceivedAt > 0", self.web_server)
        self.assertIn(
            "static_cast<std::uint32_t>(\n"
            "\t\t\t\t\ts.counters.lastChunkReceivedAt)",
            self.web_server,
        )

    def test_all_route_shapes_are_compared_byte_exactly(self) -> None:
        for message in (
            "local status response remains byte-exact",
            "remote status privacy and nullability remain byte-exact",
            "mesh response remains exact",
            "unavailable debug response remains byte-exact",
            "available debug response remains byte-exact",
        ):
            self.assertIn(message, self.native_test)
        self.assertGreaterEqual(self.native_test.count("=="), 5)

    def test_webserver_delegates_all_three_diagnostic_routes(self) -> None:
        self.assertGreaterEqual(
            self.web_server.count("WebDiagnostics::Serialize("),
            3,
        )
        for route in ("ApiStatus", "ApiLiveMesh", "ApiLiveDebug"):
            start = self.web_server.index(f"WebRouteId::{route}")
            next_route = self.web_server.find(
                "WebRouteId::",
                start + len(f"WebRouteId::{route}"),
            )
            block = self.web_server[
                start : next_route if next_route >= 0 else len(self.web_server)
            ]
            self.assertIn("WebDiagnostics::Serialize(", block)

    def test_coordinator_shrinks_from_reviewed_baseline(self) -> None:
        completed = subprocess.run(
            [
                "git",
                "diff",
                "--numstat",
                self.contract["baseline_commit"],
                "--",
                "srchybrid/WebServer.cpp",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        added, removed, _ = completed.stdout.strip().split("\t")
        self.assertGreater(int(removed), int(added))


if __name__ == "__main__":
    unittest.main()
