"""MOD-2.1 request parsing, normalization and hostile-limit contract."""

from __future__ import annotations

import json
import pathlib
import re
import unittest
import xml.etree.ElementTree as ET


ROOT = pathlib.Path(__file__).resolve().parents[1]
HEADER = ROOT / "srchybrid" / "WebRequestParser.h"
SOURCE = ROOT / "srchybrid" / "WebRequestParser.cpp"
SOCKET = ROOT / "srchybrid" / "WebSocket.cpp"
SERVER = ROOT / "srchybrid" / "WebServer.cpp"
NATIVE_TEST = ROOT / "srchybrid" / "tests" / "test_web_request_parser.cpp"
MAKE = ROOT / "srchybrid" / "tests" / "make.bat"
PROJECT = ROOT / "srchybrid" / "emule.vcxproj"
CONTRACT = (
    ROOT / "docs" / "architecture" / "mod03_ownership_layering_contract_v1.json"
)


class Mod21WebRequestParserTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.header = HEADER.read_text(encoding="utf-8")
        cls.source = SOURCE.read_text(encoding="utf-8")
        cls.socket = SOCKET.read_text(encoding="utf-8")
        cls.server = SERVER.read_text(encoding="utf-8")
        cls.native = NATIVE_TEST.read_text(encoding="utf-8")
        cls.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))

    def test_planned_owner_layer_and_responsibility_are_exact(self) -> None:
        web = next(
            item for item in self.contract["coordinators"]
            if item["name"] == "WebServer"
        )
        module = next(
            item for item in web["planned_modules"]
            if item["module"] == "WebRequestParser"
        )
        self.assertEqual(module["owner_before"], "CWebServer")
        self.assertEqual(module["owner_after"], "WebRequestParser")
        self.assertEqual(module["layer"], "application")
        self.assertEqual(
            module["responsibility"],
            "request line, headers, limits and normalization",
        )

    def test_module_is_portable_and_coordinator_independent(self) -> None:
        self.assertNotIn("stdafx.h", self.source)
        includes = re.findall(
            r'#\s*include\s*[<"]([^>"]+)[>"]',
            self.header + self.source,
        )
        names = {
            pathlib.PurePosixPath(include).name.casefold()
            for include in includes
        }
        self.assertTrue(names.isdisjoint({
            "webserver.h", "websocket.h", "afx.h", "afxwin.h", "windows.h",
        }))
        self.assertNotIn("CString", self.header + self.source)
        self.assertIn("namespace ese", self.header)
        self.assertIn("namespace web", self.header)

    def test_limits_are_explicit_fixed_and_preallocation_safe(self) -> None:
        for declaration in (
            "kMaxHeaderBytes = 32u * 1024u",
            "kMaxTargetBytes = 8u * 1024u",
            "kMaxBodyBytes = 1024u * 1024u",
            "kMaxHeaderFields = 128u",
            "kMaxQueryFields = 128u",
            "kMaxQueryValueBytes = 64u * 1024u",
            "kMaxCookieHeaderBytes = 8u * 1024u",
            "kMaxCookieFields = 64u",
            "kMaxCookieValueBytes = 4u * 1024u",
        ):
            self.assertIn(declaration, self.header)
        self.assertIn("ParseStatus::HeaderTooLarge", self.source)
        self.assertIn("ParseStatus::TargetTooLarge", self.source)
        self.assertIn("ParseStatus::BodyTooLarge", self.source)
        self.assertIn("QueryStatus::TooManyFields", self.source)
        self.assertIn("QueryStatus::ValueTooLarge", self.source)
        self.assertIn("CookieStatus::TooManyFields", self.source)
        self.assertIn("CookieStatus::ValueTooLarge", self.source)
        self.assertIn("kMaxRequestBytes - m_dwRecv", self.socket)
        self.assertNotIn("dwSize + m_dwRecv + SIZE_PRESERVE", self.socket)

    def test_method_and_length_parsing_are_exact_and_fail_closed(self) -> None:
        self.assertIn('method_token == "GET"', self.source)
        self.assertIn('method_token == "POST"', self.source)
        self.assertIn('method_token == "OPTIONS"', self.source)
        self.assertNotIn("strncmp(sHeader, \"GET\", 3)", self.socket)
        self.assertNotIn("strncmp(sHeader, \"POST\", 4)", self.socket)
        self.assertNotIn("strncmp(sHeader, \"OPTIONS\", 7)", self.socket)
        self.assertNotIn("atol(", self.socket)
        for marker in (
            "ParseUnsignedDecimal",
            "duplicate_content_length",
            "transfer-encoding",
            "ParseStatus::BadRequest",
        ):
            self.assertIn(marker, self.source)

    def test_socket_adapter_delegates_before_dispatch(self) -> None:
        self.assertIn('#include "WebRequestParser.h"', self.socket)
        receive = self.socket.index("void CWebSocket::OnReceived(")
        inspect = self.socket.index("ese::web::InspectRequest(", receive)
        dispatch = self.socket.index("OnRequestReceived(", inspect)
        self.assertLess(inspect, dispatch)
        self.assertIn("ese::web::ParsedRequest parsed", self.socket)
        self.assertIn("request.method == ese::web::Method::Post", self.socket)
        self.assertIn("request.method == ese::web::Method::Options", self.socket)
        self.assertIn("request.target", self.socket)
        self.assertIn("RejectMalformedRequest(", self.socket)

    def test_web_query_helpers_delegate_and_preserve_unicode_adapter(self) -> None:
        self.assertIn('#include "WebRequestParser.h"', self.server)
        array_start = self.server.index("CString CWebServer::_ParseURLArray(")
        value_start = self.server.index("CString CWebServer::_ParseURL(")
        query_region = self.server[array_start:value_start + 1800]
        self.assertIn("ese::web::GetQueryValues(", query_region)
        self.assertIn("ese::web::GetQueryValue(", query_region)
        self.assertIn("OptUtf8ToStr(", query_region)
        self.assertNotIn("URL.Delete(pos, 10)", query_region)
        self.assertNotIn("URL.MakeLower()", query_region)

    def test_headless_characterization_exercises_integrated_parser(self) -> None:
        for marker in (
            "web parser failed exact deterministic query",
            "web parser failed repeated query",
            "web request parser failed runtime request",
            "web request parser failed runtime cookie",
            "web request parser accepted hostile length",
        ):
            self.assertIn(marker, self.source)
        self.assertIn(
            "ese::web::RunCharacterizationSelfTest(parserFailure)",
            self.server,
        )
        self.assertIn("production characterization helper passes", self.native)

    def test_native_vectors_cover_legacy_and_hostile_inputs(self) -> None:
        for diagnostic in (
            "complete CRLF GET is ready",
            "legacy LF request remains accepted",
            "partial POST waits for the declared body",
            "method prefix is rejected",
            "duplicate content length is rejected",
            "unsupported transfer encoding is rejected",
            "overflow-sized content length is rejected",
            "target above the byte cap is rejected",
            "header above the byte cap is rejected",
            "body exactly at the byte cap remains admissible",
            "headers are normalized without changing values",
            "header field count is bounded",
            "query names require exact boundaries",
            "query names remain case-sensitive",
            "form normalization preserves legacy decoding and control filtering",
            "repeated query values preserve order and case",
            "query field count is bounded",
            "individual query value size is bounded",
            "cookie value is parsed by exact name",
            "cookie name boundaries are exact",
            "duplicate security cookie is rejected",
            "malformed cookie is rejected",
            "cookie field count is bounded",
            "cookie value size is bounded",
        ):
            self.assertIn(diagnostic, self.native)
        self.assertNotIn("assert(", self.native)

    def test_project_and_standalone_gate_compile_production_module(self) -> None:
        tree = ET.parse(PROJECT)
        namespace = {"m": "http://schemas.microsoft.com/developer/msbuild/2003"}
        items = tree.findall(
            ".//m:ClCompile[@Include='WebRequestParser.cpp']", namespace
        )
        self.assertEqual(len(items), 1)
        item = items[0]
        self.assertEqual(
            item.findtext("m:PrecompiledHeader", namespaces=namespace),
            "NotUsing",
        )
        self.assertEqual(
            item.findtext("m:LanguageStandard", namespaces=namespace),
            "stdcpp17",
        )
        self.assertEqual(
            item.findtext("m:WarningLevel", namespaces=namespace),
            "Level4",
        )
        self.assertEqual(
            item.findtext("m:TreatWarningAsError", namespaces=namespace),
            "true",
        )
        headers = tree.findall(
            ".//m:ClInclude[@Include='WebRequestParser.h']", namespace
        )
        self.assertEqual(len(headers), 1)

        make = MAKE.read_text(encoding="utf-8")
        line = next(
            line for line in make.splitlines()
            if "test_web_request_parser.exe" in line
            and line.lstrip().startswith("cl ")
        )
        self.assertIn("/W4 /WX /std:c++17", line)
        self.assertIn("tests\\test_web_request_parser.cpp", line)
        self.assertIn("WebRequestParser.cpp", line)


if __name__ == "__main__":
    unittest.main(verbosity=2)
