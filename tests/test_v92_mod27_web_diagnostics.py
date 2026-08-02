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
        cls.status_controller = (
            ROOT / "srchybrid" / "WebLiveApiStatusController.cpp"
        ).read_text(encoding="utf-8")
        cls.search_controller = (
            ROOT / "srchybrid" / "WebLiveApiSearchController.cpp"
        ).read_text(encoding="utf-8")
        cls.diagnostics_controller = (
            ROOT / "srchybrid" / "WebLiveApiDiagnosticsController.cpp"
        ).read_text(encoding="utf-8")
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
            ["/api/status", "/api/live/mesh"],
        )
        self.assertEqual(
            self.contract["module"]["declared_direct_dependencies"],
            [],
        )
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

    def test_debug_projection_has_moved_to_w10_diagnostics(self) -> None:
        self.assertIn(
            "W10DiagnosticsOperation::Debug",
            self.diagnostics_controller,
        )
        self.assertIn(
            "RunW10LiveDiagnosticsApi",
            self.diagnostics_controller,
        )
        self.assertNotIn("WebLiveDebugDiagnostics", self.header + self.source)

    def test_all_route_shapes_are_compared_byte_exactly(self) -> None:
        for message in (
            "local status response remains byte-exact",
            "remote status privacy and nullability remain byte-exact",
            "mesh response remains exact",
        ):
            self.assertIn(message, self.native_test)
        self.assertGreaterEqual(self.native_test.count("=="), 3)

    def test_diagnostic_routes_keep_serializer_ownership_after_w9_extraction(self) -> None:
        """W8/W9 delegate their families while MOD-2.7 keeps status/mesh."""
        dispatch_start = self.web_server.index("// W8 dispatch stays below")
        dispatch_end = self.web_server.index("W8LiveStreamRequest request", dispatch_start)
        dispatch = self.web_server[dispatch_start:dispatch_end]
        self.assertIn("RunW8LiveStatusApi(statusOperation", dispatch)
        self.assertIn("W8LiveStatusPort", dispatch)
        for route, operation in (
            ("ApiStatus", "W8LiveStatusOperation::Status"),
            ("ApiLiveChannels", "W8LiveStatusOperation::Channels"),
            ("ApiLiveMesh", "W8LiveStatusOperation::Mesh"),
        ):
            self.assertIn(
                f"WebRouteId::{route}: statusOperation=ese::web::{operation}",
                dispatch,
            )

        # Extracted routes keep explicit portable serializers.
        self.assertIn("r.body=Status(s,loopback)", self.status_controller)
        self.assertIn("r.body=Channels(c)", self.status_controller)
        self.assertIn("r.body=Mesh(m)", self.status_controller)
        w9_start = self.web_server.index("// W9 keeps authorization above")
        w9_end = self.web_server.index("// W10 owns settings", w9_start)
        w9_dispatch = self.web_server[w9_start:w9_end]
        self.assertIn("RunW9LiveSearchApi(search,port,response)", w9_dispatch)
        for route in (
            "ApiDebugSourceResolutions", "ApiLiveDiagnose", "ApiLiveKadStreams",
        ):
            self.assertEqual(w9_dispatch.count(f"WebRouteId::{route}"), 1)
        for serializer in ("Sources(n,e)", "Diagnose(!r.key.empty(),valid,s)", "Streams(p,kad,s)"):
            self.assertIn(serializer, self.search_controller)
        self.assertIn(
            "W10DiagnosticsOperation::Debug",
            self.diagnostics_controller,
        )

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
