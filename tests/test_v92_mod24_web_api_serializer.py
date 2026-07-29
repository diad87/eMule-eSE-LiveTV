"""MOD-2.4 WebApiSerializer extraction and escaping contract."""

from __future__ import annotations

import json
import pathlib
import unittest
import xml.etree.ElementTree as ET


ROOT = pathlib.Path(__file__).resolve().parents[1]
HEADER = ROOT / "srchybrid" / "WebApiSerializer.h"
SOURCE = ROOT / "srchybrid" / "WebApiSerializer.cpp"
SERVER = ROOT / "srchybrid" / "WebServer.cpp"
NATIVE = ROOT / "srchybrid" / "tests" / "test_web_api_serializer.cpp"
MAKE = ROOT / "srchybrid" / "tests" / "make.bat"
PROJECT = ROOT / "srchybrid" / "emule.vcxproj"
OWNERSHIP = (
    ROOT / "docs" / "architecture" / "mod03_ownership_layering_contract_v1.json"
)
CONTRACT = (
    ROOT / "docs" / "architecture" / "mod24_web_api_serializer_contract_v1.json"
)


class Mod24WebApiSerializerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.header = HEADER.read_text(encoding="utf-8")
        cls.source = SOURCE.read_text(encoding="utf-8")
        cls.server = SERVER.read_text(encoding="utf-8")
        cls.native = NATIVE.read_text(encoding="utf-8")
        cls.ownership = json.loads(OWNERSHIP.read_text(encoding="utf-8"))
        cls.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))

    def test_owner_layer_and_responsibility_match_the_approved_plan(self) -> None:
        web = next(
            item for item in self.ownership["coordinators"]
            if item["name"] == "WebServer"
        )
        planned = next(
            item for item in web["planned_modules"]
            if item["module"] == "WebApiSerializer"
        )
        self.assertEqual(planned["owner_before"], self.contract["owner_before"])
        self.assertEqual(planned["owner_after"], self.contract["owner_after"])
        self.assertEqual(planned["layer"], self.contract["layer"])
        self.assertEqual(
            planned["responsibility"],
            self.contract["responsibility"],
        )

    def test_module_is_portable_and_dependency_free(self) -> None:
        combined = self.header + self.source
        for forbidden in (
            "stdafx.h", "WebServer.h", "WebSocket.h", "CString",
            "windows.h", "theApp", "thePrefs", "new ", "delete ",
        ):
            self.assertNotIn(forbidden, combined)
        self.assertIn("#include <string>", self.header)

    def test_json_contract_is_explicit_and_byte_preserving(self) -> None:
        self.assertEqual(
            self.contract["text_encoding_policy"],
            "caller_owned_and_byte_or_code_unit_preserving",
        )
        for marker in (
            "std::string EscapeJson",
            'output += "\\\\\\\""',
            'output += "\\\\\\\\"',
            'output += "\\\\u00"',
            "value < 0x20",
            "static_cast<char>(value)",
        ):
            self.assertIn(marker, self.source + self.header)
        self.assertEqual(self.contract["json"]["slash"], "preserved")

    def test_markup_contract_preserves_both_legacy_modes(self) -> None:
        for entity in ("&amp;", "&lt;", "&gt;", "&quot;", "&#8217;"):
            self.assertIn(entity, self.source)
        self.assertIn("escapeApostropheAndNewline", self.source + self.header)
        self.assertIn("return EscapeHtml(input, false)", self.source)
        self.assertEqual(
            self.contract["xml"]["contract"],
            "same_as_html_text_mode",
        )

    def test_typed_response_models_own_representative_wire_contracts(
        self,
    ) -> None:
        for marker in (
            "struct SerializedWebResponse",
            "struct WebJoinResponseModel",
            "struct WebDirectJoinResponseModel",
            "struct WebTunnelPingResponseModel",
            "struct WebStringArrayResponseModel",
            "struct WebRemoteLinkXmlResponseModel",
        ):
            self.assertIn(marker, self.header)
        self.assertEqual(
            self.contract["response_models"]["owned_here"],
            [
                "WebJoinResponseModel",
                "WebDirectJoinResponseModel",
                "WebTunnelPingResponseModel",
                "WebStringArrayResponseModel",
                "WebRemoteLinkXmlResponseModel",
            ],
        )
        for marker in (
            "SerializedWebResponse Serialize(const WebJoinResponseModel&",
            "SerializedWebResponse Serialize(const WebDirectJoinResponseModel&",
            "SerializedWebResponse Serialize(const WebTunnelPingResponseModel&",
            "SerializedWebResponse Serialize(const WebStringArrayResponseModel&",
            "std::wstring Serialize(const WebRemoteLinkXmlResponseModel&",
        ):
            self.assertIn(marker, self.source + self.header)

    def test_webserver_adapts_mfc_state_into_serializer_owned_models(
        self,
    ) -> None:
        self.assertIn('#include "WebApiSerializer.h"', self.server)
        self.assertIn("ese::web::EscapeHtml(input, noquote)", self.server)
        self.assertIn("ese::web::EscapeJson(value)", self.server)
        self.assertLess(self.server.count("EseJsonEscapeA("), 34)
        self.assertIn(
            "ese::web::RunWebApiSerializerSelfTest(serializerFailure)",
            self.server,
        )
        self.assertNotIn('output.AppendFormat("\\\\u%04x", ch)', self.server)
        self.assertNotIn("Escape minimally for JSON", self.server)
        self.assertNotIn("Escape any quotes/backslashes", self.server)
        for model_marker in (
            "ese::web::WebJoinResponseModel{",
            "ese::web::WebDirectJoinResponseModel{",
            "ese::web::WebTunnelPingResponseModel{",
            "ese::web::WebStringArrayResponseModel model;",
            "ese::web::WebRemoteLinkXmlResponseModel{",
        ):
            self.assertIn(model_marker, self.server)
        for obsolete_fragment in (
            "const CStringA keyJson = EseJsonEscapeA(keyA)",
            "EseJsonEscapeA(CStringA(CT2A(keyT)))",
            "EseJsonEscapeA(CStringA(CT2A(ipT)))",
            "static CString EseXmlEscape",
        ):
            self.assertNotIn(obsolete_fragment, self.server)
        self.assertIn(
            "kwJson += EseJsonEscapeA(CStringA(kws[i]))",
            self.server,
        )
        self.assertNotIn(
            'kwJson += CStringA(kws[i])',
            self.server,
        )
        self.assertNotIn(
            '_T("<filename>") + HTTPTemp + _T("</filename>")',
            self.server,
        )
        self.assertNotIn('_T("<status result=\\"OK\\">")', self.server)
        self.assertIn(
            "static_cast<std::size_t>(HTTPTemp.GetLength())",
            self.server,
        )
        self.assertIn(
            "Anonymous link — searching Kad for the broadcaster (5-30 s)",
            self.server,
        )
        self.assertNotIn(
            "Anonymous link â€” searching Kad for the broadcaster (5-30 s)",
            self.server,
        )

    def test_native_vectors_cover_controls_entities_and_encoding_boundaries(
        self,
    ) -> None:
        for marker in (
            "every JSON control byte must be escaped",
            "JSON escaping must preserve caller-owned text encoding",
            "pre-escaped entities must not bypass escaping",
            "markup escaping must preserve embedded NUL",
            "join response must own exact status, headers, schema and escaping",
            "direct-join response must preserve the legacy UTF-8 em dash bytes",
            "failed tunnel-ping response must escape its reason",
            "string-array response must escape field names, values and NUL",
            "failed remote-link XML must omit filename",
            "production WebApiSerializer self-test must pass",
        ):
            self.assertIn(marker, self.native)

    def test_project_and_standalone_gate_compile_production_module(self) -> None:
        namespace = {"m": "http://schemas.microsoft.com/developer/msbuild/2003"}
        project = ET.parse(PROJECT)
        compile_entry = project.find(
            ".//m:ClCompile[@Include='WebApiSerializer.cpp']",
            namespace,
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
            compile_entry.findtext(
                "m:TreatWarningAsError",
                namespaces=namespace,
            ),
            "true",
        )
        self.assertIsNotNone(
            project.find(
                ".//m:ClInclude[@Include='WebApiSerializer.h']",
                namespace,
            )
        )
        gate = MAKE.read_text(encoding="utf-8")
        self.assertIn(
            "test_web_api_serializer.cpp WebApiSerializer.cpp",
            gate,
        )


if __name__ == "__main__":
    unittest.main()
