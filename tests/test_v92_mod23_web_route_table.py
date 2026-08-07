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
        self.assertEqual(len(compiled), 45)
        self.assertIn("RegisteredExactWebRouteCount", self.source)

    def test_dynamic_routes_validate_shape_before_dispatch(self) -> None:
        for marker in (
            "IsHexSpan(path, 6, 32)",
            "IsHexSpan(path, 10, 32)",
            "IsSafeHlsResource(path.substr(43))",
            "IsSafeLeaf(resource, 64)",
            'resource.compare(8, 5, ".m3u8") == 0',
            'resource.compare(resource.size() - 3, 3, ".ts") != 0',
            "ParseSessionPrefix(path, suffix)",
            "(static_cast<std::uint64_t>(INT_MAX) - digit) / 10u",
            'path.compare(0, 3, "/s/") == 0',
            'path.compare(0, 3, "/h/") == 0',
            "IsStaticAssetPath(path)",
        ):
            self.assertIn(marker, self.source)

    def test_hls_capability_namespace_is_canonical_and_fail_closed(self) -> None:
        combined = self.header + self.source
        for required in (
            "struct WebHlsCapabilityPath",
            "ParseWebHlsCapabilityPath",
            "hls_capability_prefixed",
            'generationAt != 3 + 64',
            'resourceAt != streamAt + 33',
            'IsHexSpan(path, 3, 64)',
            'IsHexSpan(path, streamAt + 1, 32)',
            "ParseUnsigned64(generationText, capability.generation)",
            'capability.canonical_path = "/api/live/"',
            'target.find(\'?\') != std::string::npos',
        ):
            self.assertIn(required, combined)
        self.assertIn("value.size() > 1 && value.front() == '0'", self.source)
        self.assertIn("return parsed != 0", self.source)
        self.assertGreaterEqual(
            self.source.count("path[index] >= 'A' && path[index] <= 'F'"),
            2,
        )
        match = self.source.split("WebRouteMatch MatchGetPath", 1)[1].split(
            "} // namespace", 1
        )[0]
        strict_guard = match.index('if (path.compare(0, 3, "/h/") == 0)')
        static_fallback = match.index("if (IsStaticAssetPath(path))")
        self.assertLess(strict_guard, static_fallback)
        capability_dispatch = match.split(
            "if (ParseHlsCapabilityPathOnly(path, capability))", 1
        )[1].split("if (allowSessionPrefix)", 1)[0]
        self.assertIn("WebRouteId::ApiLiveStream", capability_dispatch)
        self.assertIn("WebHandler::LiveApi", capability_dispatch)
        self.assertNotIn("StaticAsset", capability_dispatch)

    def test_hls_resource_whitelist_matches_runtime_artifacts(self) -> None:
        resource_policy = self.source.split(
            "bool IsSafeHlsResource", 1
        )[1].split("bool ParseUnsigned64", 1)[0]
        for required in (
            'resource == "stream.m3u8"',
            "value.size() == 1",
            "value[0] >= '0' && value[0] <= '4'",
            "value.size() < 5 || value.size() > 10",
            "character < '0' || character > '9'",
            "parsed <= (std::numeric_limits<std::uint32_t>::max)()",
            "resource.size() == 13",
            'resource.compare(0, 7, "stream_") == 0',
            'resource.compare(8, 5, ".m3u8") == 0',
            'resource.compare(0, 4, "seg_") != 0',
            'resource.compare(resource.size() - 3, 3, ".ts") != 0',
            "identity.find('_')",
            "separator == 1",
            "identity.find('_', separator + 1) == std::string::npos",
        ):
            self.assertIn(required, resource_policy)
        self.assertNotIn("resource.size() > 12", resource_policy)
        self.assertIn("disabled multi-audio branch", resource_policy)
        self.assertIn("must extend this grammar explicitly", resource_policy)

        whitelist = re.compile(
            r"(?:stream\.m3u8|stream_[0-4]\.m3u8|"
            r"seg_[0-9]{5,10}\.ts|seg_[0-4]_[0-9]{5,10}\.ts)\Z"
        )
        positive = (
            "stream.m3u8",
            "stream_0.m3u8",
            "stream_4.m3u8",
            "seg_00000.ts",
            "seg_4294967295.ts",
            "seg_0_00001.ts",
            "seg_4_4294967295.ts",
        )
        negative = (
            "stream_.m3u8",
            "stream_5.m3u8",
            "stream_00.m3u8",
            "stream_eng.m3u8",
            "seg_.ts",
            "seg_secret.ts",
            "seg_0001.ts",
            "seg_00000000000.ts",
            "seg_4294967296.ts",
            "seg_5_00001.ts",
            "seg_0_.ts",
            "seg_0_0001.ts",
            "seg_0_4294967296.ts",
            "seg_0_00001_extra.ts",
        )
        def whitelisted(resource: str) -> bool:
            if whitelist.fullmatch(resource) is None:
                return False
            if not resource.startswith("seg_"):
                return True
            sequence = resource.removesuffix(".ts").rsplit("_", 1)[-1]
            return int(sequence) <= 0xFFFFFFFF

        self.assertTrue(all(whitelisted(item) for item in positive))
        self.assertTrue(all(not whitelisted(item) for item in negative))
        for resource in positive[1:]:
            self.assertIn(f'std::string("{resource}")', self.native)
        self.assertIn(
            "runtime ABR HLS capability output must dispatch", self.native
        )
        for resource in negative:
            self.assertIn(f'"/{resource}"', self.native)

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
            "numeric session locator must never authorize an HLS resource",
            "canonical HLS capability must preserve every scope component",
            "HLS capabilities must not expose a CORS preflight route",
            "POST API method must fail closed",
            "OPTIONS classic page must fail closed",
            "unknown or hostile route must fail closed",
            "hostile HLS capability must fail closed",
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
        for hostile_capability_marker in (
            "std::string(63, 'a')",
            "std::string(65, 'a')",
            'prefix + "0" + validTail',
            'prefix + "00" + validTail',
            'prefix + "01" + validTail',
            'prefix + "+1" + validTail',
            'prefix + "18446744073709551616" + validTail',
            '"/stream.M3U8"',
            '"/seg_1.TS"',
            '"/../stream.m3u8"',
            '"/stream.m3u8?range=1"',
            '"/stream%2em3u8"',
            '"/stream%252em3u8"',
            '"/stream.m3u8:secret.css"',
            '"//stream.m3u8"',
        ):
            self.assertIn(hostile_capability_marker, self.native)

    def test_runtime_characterization_invokes_production_table(self) -> None:
        self.assertIn('#include "WebRouteTable.h"', self.server)
        self.assertIn("ese::web::RunWebRouteTableSelfTest(routeFailure)", self.server)
        for marker in (
            "web route table failed exact API dispatch",
            "web route table accepted unknown route",
            "web route table accepted unknown method",
            "web route table failed HLS capability path",
            "web route table retained session credential in HLS path",
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
