"""MOD-2.3 method/route to handler dispatch contract."""

from __future__ import annotations

import json
import pathlib
import re
import unittest
import xml.etree.ElementTree as ET


ROOT = pathlib.Path(__file__).resolve().parents[1]
HEADER = ROOT / "srchybrid" / "WebRouteTable.h"
SOURCE = ROOT / "srchybrid" / "WebRouteTable.cpp"
SOCKET = ROOT / "srchybrid" / "WebSocket.cpp"
SERVER = ROOT / "srchybrid" / "WebServer.cpp"
NATIVE = ROOT / "srchybrid" / "tests" / "test_web_route_table.cpp"
MAKE = ROOT / "srchybrid" / "tests" / "make.bat"
PROJECT = ROOT / "srchybrid" / "emule.vcxproj"
CONTRACT = (
    ROOT / "docs" / "architecture" / "mod03_ownership_layering_contract_v1.json"
)
INVENTORY = (
    ROOT / "docs" / "architecture" / "mod23_web_route_inventory_v1.json"
)


class Mod23WebRouteTableTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.header = HEADER.read_text(encoding="utf-8")
        cls.source = SOURCE.read_text(encoding="utf-8")
        cls.socket = SOCKET.read_text(encoding="utf-8")
        cls.server = SERVER.read_text(encoding="utf-8")
        cls.native = NATIVE.read_text(encoding="utf-8")
        cls.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        cls.inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))

    def test_planned_owner_layer_and_responsibility_are_exact(self) -> None:
        web = next(
            item for item in self.contract["coordinators"]
            if item["name"] == "WebServer"
        )
        module = next(
            item for item in web["planned_modules"]
            if item["module"] == "WebRouteTable"
        )
        self.assertEqual(module["owner_before"], "CWebServer")
        self.assertEqual(module["owner_after"], "WebRouteTable")
        self.assertEqual(module["layer"], "application")
        self.assertEqual(
            module["responsibility"],
            "method and route to handler dispatch",
        )

    def test_module_is_portable_and_has_no_lateral_module_dependency(self) -> None:
        combined = self.header + self.source
        for forbidden in (
            "stdafx.h", "WebServer.h", "WebSocket.h", "WebRequestParser.h",
            "CString", "windows.h", "theApp", "thePrefs",
        ):
            self.assertNotIn(forbidden, combined)
        self.assertIn("enum class WebRouteMethod", self.header)
        self.assertNotRegex(combined, r"\bnew\b|\bdelete\b")

    def test_inventory_and_compiled_exact_table_are_identical(self) -> None:
        self.assertEqual(
            self.inventory["default_policy"],
            "deny_unknown_method_or_route",
        )
        compiled = re.findall(
            r'\{"([^"]+)",\s*WebRouteId::[A-Za-z0-9_]+\}',
            self.source,
        )
        self.assertEqual(compiled, self.inventory["exact_get_routes"])
        self.assertEqual(len(compiled), 43)
        self.assertIn("RegisteredExactWebRouteCount", self.source)

    def test_dynamic_routes_validate_shape_before_dispatch(self) -> None:
        for marker in (
            "IsHexSpan(path, 6, 32)",
            "IsHexSpan(path, 10, 32)",
            "IsSafeHlsResource(path.substr(43))",
            "IsSafeLeaf(resource, 64)",
            'resource.compare(resource.size() - 5, 5, ".m3u8") == 0',
            'resource.compare(resource.size() - 3, 3, ".ts") == 0',
            "ParseSessionPrefix(path, suffix)",
            "(static_cast<std::uint64_t>(INT_MAX) - digit) / 10u",
            'path.compare(0, 3, "/s/") == 0',
            "IsStaticAssetPath(path)",
        ):
            self.assertIn(marker, self.source)

    def test_method_matrix_is_explicit_and_fail_closed(self) -> None:
        for method in ("Get", "Post", "Options"):
            self.assertIn(f"WebRouteMethod::{method}", self.source)
        self.assertIn("WebRouteStatus::MethodNotAllowed", self.source)
        self.assertIn("WebRouteStatus::NotFound", self.header)
        self.assertIn("WebHandler::CorsPreflight", self.source)
        self.assertIn("getMatch.handler == WebHandler::ClassicPage", self.source)
        self.assertIn("getMatch.handler == WebHandler::LiveApi", self.source)

    def test_socket_delegates_before_any_handler(self) -> None:
        resolve = self.socket.index("ese::web::ResolveWebRoute(")
        live = self.socket.index("m_pParent->_ProcessLiveAPI", resolve)
        classic = self.socket.index("m_pParent->_ProcessURL", resolve)
        static = self.socket.index("m_pParent->_ProcessFileReq", resolve)
        self.assertLess(resolve, min(live, classic, static))
        self.assertIn("HTTP/1.1 404 Not Found", self.socket)
        self.assertIn("HTTP/1.1 405 Method Not Allowed", self.socket)
        for allow_value in (
            'allowed = "GET, OPTIONS"',
            'allowed = "GET, POST"',
            'allowed = "GET"',
            "Access-Control-Allow-Methods: GET, OPTIONS",
        ):
            self.assertIn(allow_value, self.socket)
        self.assertNotIn(
            "Access-Control-Allow-Methods: GET, POST, OPTIONS",
            self.socket,
        )
        self.assertIn(
            "route.handler == ese::web::WebHandler::CorsPreflight",
            self.socket,
        )
        for old_dispatch in (
            'sURL.Left(5) == "/api/"',
            'sURL.Left(3) == "/s/"',
            "if (!filereq &&",
        ):
            self.assertNotIn(old_dispatch, self.socket)

    def test_native_vectors_cover_exact_dynamic_method_and_hostile_cases(self) -> None:
        for diagnostic in (
            "registered exact route count must match the characterized inventory",
            "query text must not alter exact path dispatch",
            "strict positive session prefix must preserve canonical nested route",
            "POST API method must fail closed",
            "OPTIONS classic page must fail closed",
            "unknown or hostile route must fail closed",
            "production WebRouteTable self-test must pass",
        ):
            self.assertIn(diagnostic, self.native)
        for hostile in (
            "/api/statusXYZ",
            "/api/live/joined",
            "/api/relay/unknown",
            "/api/live/privacy/future",
            "/api/live/0123456789abcdef0123456789ABCDEF/stream_eng.M3U8",
            "/api/live/0123456789abcdef0123456789ABCDEF/seg_1.TS",
            "/s/2147483648/api/status",
            "/s/999999999999999999999999999999999999999/api/status",
            "/s/1/style.css",
            "/style.css:secret.css",
            "/%61pi/status",
        ):
            self.assertIn(hostile, self.native)

    def test_runtime_characterization_invokes_production_table(self) -> None:
        self.assertIn('#include "WebRouteTable.h"', self.server)
        self.assertIn("ese::web::RunWebRouteTableSelfTest(routeFailure)", self.server)
        for marker in (
            "web route table failed exact API dispatch",
            "web route table accepted unknown route",
            "web route table accepted unknown method",
            "web route table failed token-prefixed stream",
            "web route table accepted overflowing session token",
            "web route table accepted unsafe static path",
            "web route table widened dynamic HLS extension case",
        ):
            self.assertIn(marker, self.source)

    def test_project_and_standalone_gate_compile_production_module(self) -> None:
        namespace = {"m": "http://schemas.microsoft.com/developer/msbuild/2003"}
        project = ET.parse(PROJECT)
        compile_entry = project.find(
            ".//m:ClCompile[@Include='WebRouteTable.cpp']", namespace
        )
        self.assertIsNotNone(compile_entry)
        self.assertEqual(
            compile_entry.findtext("m:PrecompiledHeader", namespaces=namespace),
            "NotUsing",
        )
        self.assertEqual(
            compile_entry.findtext("m:WarningLevel", namespaces=namespace),
            "Level4",
        )
        self.assertEqual(
            compile_entry.findtext("m:TreatWarningAsError", namespaces=namespace),
            "true",
        )
        self.assertIsNotNone(
            project.find(".//m:ClInclude[@Include='WebRouteTable.h']", namespace)
        )
        gate = MAKE.read_text(encoding="utf-8")
        self.assertIn("test_web_route_table.cpp WebRouteTable.cpp", gate)
        self.assertIn("test_web_route_table.exe", gate)


if __name__ == "__main__":
    unittest.main(verbosity=2)
