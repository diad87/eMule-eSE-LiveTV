"""M2A-W6 typed evidence for the portable search-result projection."""

from __future__ import annotations

import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
HEADER = ROOT / "srchybrid" / "WebSearchProjection.h"
SOURCE = ROOT / "srchybrid" / "WebSearchProjection.cpp"
FACADE = ROOT / "srchybrid" / "WebServer.cpp"
PROJECT = ROOT / "srchybrid" / "emule.vcxproj"


def declaration_tokens(text: str, name: str) -> list[str]:
    start = min(
        candidate for candidate in (
            text.find(prefix + name)
            for prefix in ("class ", "struct ")
        ) if candidate >= 0
    )
    opening = text.index("{", start)
    depth = 0
    for end in range(opening, len(text)):
        depth += (text[end] == "{") - (text[end] == "}")
        if depth == 0:
            return re.findall(
                r"[A-Za-z_]\w*|::|\d+(?:\.\d+)?|[^\s]",
                text[start:text.index(";", end) + 1],
            )
    raise AssertionError(f"unterminated {name}")


class W6SearchProjectionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.header = HEADER.read_text(encoding="utf-8")
        cls.source = SOURCE.read_text(encoding="utf-8")
        cls.facade = FACADE.read_text(encoding="utf-8")

    def test_module_is_portable_bounded_and_captures_owned_dtos(self):
        text = self.header + self.source
        self.assertLessEqual(len(text.splitlines()), 900)
        self.assertIn('#include "M2ABindingPort.h"', self.header)
        for forbidden in (
            "CString", "theApp", "thePrefs", "SendMessage", "windows.h",
            "WebServer.h", "WebSearchController", "callback",
        ):
            self.assertNotIn(forbidden, text)
        self.assertIn("std::vector<WebSearchProjectionRow> rows", self.header)
        self.assertIn("for (const WebSearchProjectionRow& row : input.rows)", self.source)

    def test_http_tokens_unicode_and_stale_snapshot_golden_are_owned(self):
        for token in (
            "[RESULTLIST]", "[SEARCHINFOMSG]", "[SORTASCVALUE",
            "ed2k://|file|", "EscapeApostrophe", "FormatRow",
            "input.rows[0].fileName = L\"changed\"",
        ):
            self.assertIn(token, self.source)
        self.assertIn("first.find(L\"changed\") == std::wstring::npos", self.source)

    def test_binding_selftest_and_project_are_real(self):
        for required in (
            "M2A_BIND_W6_64C04005E2", "new WebSearchProjection(parent)",
            "RunWebSearchProjectionCharacterizationSelfTest",
        ):
            self.assertIn(required, self.header + self.source)
        self.assertIn(
            "explicit WebSearchProjection(const M2AParentPort& parent)",
            self.header,
        )
        stop_server = self.facade.split("void CWebServer::StopServer", 1)[1].split(
            "void CWebServer::AddStatsLine", 1
        )[0]
        search = self.facade.split("CString CWebServer::_GetSearch", 1)[1].split(
            "INT_PTR CWebServer::UpdateSessionCount", 1
        )[0]
        self.assertIn(
            "M2A_BIND_W6_64C04005E2(M2AParentPort{Data.pThis})", search,
        )
        self.assertNotIn("M2A_BIND_W6_64C04005E2", stop_server)
        project = PROJECT.read_text(encoding="utf-8")
        self.assertIn('ClCompile Include="WebSearchProjection.cpp"', project)
        self.assertIn('ClInclude Include="WebSearchProjection.h"', project)

    def test_facade_has_one_snapshot_no_legacy_render_callback_and_is_small(self):
        body = self.facade.split("CString CWebServer::_GetSearch", 1)[1].split(
            "INT_PTR CWebServer::UpdateSessionCount", 1
        )[0]
        self.assertLessEqual(len(body.splitlines()), 80)
        self.assertEqual(body.count("GetWebList(&searchSnapshot"), 1)
        self.assertIn("RunWebSearchProjection", body)
        self.assertIn("M2A_BIND_W6_64C04005E2", body)
        self.assertNotIn("WebSearchProjection::Render", body)

    def test_value_contracts_are_odr_token_exact(self):
        for name in ("WebSearchProjectionRow", "WebSearchProjectionInput"):
            self.assertEqual(
                declaration_tokens(self.header, name),
                declaration_tokens(self.facade, name),
                name,
            )


class W6SearchProjectionTypedEvidence(unittest.TestCase):
    def test_m2a_fd0ffe9a39a379d2(self):
        self.assertIn("M2A_BIND_W6_64C04005E2", SOURCE.read_text(encoding="utf-8"))

    def test_m2a_8a7697af8117ed84(self):
        self.assertIn("class WebSearchProjection", HEADER.read_text(encoding="utf-8"))

    def test_m2a_427242c82094df1f(self):
        self.assertIn("RunWebSearchProjection", FACADE.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
