"""M2A-W6 typed evidence for the portable shared-files renderer."""

from __future__ import annotations

import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
HEADER = ROOT / "srchybrid" / "WebSharedFilesController.h"
SOURCE = ROOT / "srchybrid" / "WebSharedFilesController.cpp"
FACADE = ROOT / "srchybrid" / "WebServer.cpp"
WEB_HEADER = ROOT / "srchybrid" / "WebServer.h"
PROJECT = ROOT / "srchybrid" / "emule.vcxproj"


def declaration_tokens(text: str, name: str) -> list[str]:
    start = min(
        candidate for candidate in (
            text.find(prefix + name) for prefix in ("class ", "struct ")
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


class W6SharedFilesModuleTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.header = HEADER.read_text(encoding="utf-8")
        cls.source = SOURCE.read_text(encoding="utf-8")
        cls.text = cls.header + cls.source
        cls.facade = FACADE.read_text(encoding="utf-8")

    def test_module_is_portable_and_bounded(self):
        self.assertLessEqual(len(self.text.splitlines()), 900)
        self.assertIn('#include "M2ABindingPort.h"', self.header)
        for forbidden in (
            "CString", "theApp", "thePrefs", "SendMessage", "windows.h",
            "WebServer.h", "WebSharedController", "callback",
        ):
            self.assertNotIn(forbidden, self.text)

    def test_captured_wstring_dto_owns_sort_projection_and_rendering(self):
        for required in (
            "struct WebSharedFilesRow", "std::wstring fileName",
            "std::array<std::wstring, 3> textOrder", "std::uint64_t fileSizeBytes",
            "std::vector<WebSharedFilesRow> rows", "std::stable_sort",
            "std::wstring list", "ReplaceRow", "CompareRows",
            "CompleteSources", "PriorityToken", "ReplacePageProjection",
        ):
            self.assertIn(required, self.text)
        self.assertIn("std::vector<WebSharedFilesRow> rows(input.rows)", self.source)

    def test_http_template_tokens_and_unicode_escape_are_rendered(self):
        for token in (
            "[SharedFilesList]", "[LastChangedDataset]", "[IFDOWNLOADABLE]",
            "[/IFDOWNLOADABLE]", "[FileAllTimeTransferred]", "[FileHash]",
            "[Message]", "[Session]", "HtmlEscape", "&#8217;", "&amp;",
        ):
            self.assertIn(token, self.source)

    def test_binding_and_selftest_are_real(self):
        self.assertIn("M2A_BIND_W6_B161DA740E", self.text)
        self.assertIn("new WebSharedFilesController(parent)", self.source)
        self.assertIn("RunWebSharedFilesControllerCharacterizationSelfTest", self.source)
        self.assertIn("M2AModuleHandle binding", self.source)
        self.assertIn("雪&#8217;&amp;.mkv", self.source)

    def test_facade_captures_once_and_has_no_legacy_renderer(self):
        body = self.facade.split(
            "CString CWebServer::_GetSharedFilesList", 1
        )[1].split("CString CWebServer::_GetGraphs", 1)[0]
        self.assertLessEqual(len(body.splitlines()), 80)
        self.assertEqual(body.count("GetFileNext(pos)"), 1)
        self.assertIn("M2A_BIND_W6_B161DA740E(M2AParentPort{Data.pThis})", body)
        self.assertIn("RunWebSharedFilesController", body)
        self.assertNotIn("_SharedCmp", body)
        self.assertNotIn("GetFileByID", body.split("for (POSITION pos", 1)[1])
        web_header = WEB_HEADER.read_text(encoding="utf-8")
        self.assertNotIn("} SharedFiles;", web_header)
        self.assertNotIn("_SharedCmp", web_header + self.facade)

    def test_value_contracts_are_odr_token_exact(self):
        for name in ("WebSharedFilesRow", "WebSharedFilesInput"):
            self.assertEqual(
                declaration_tokens(self.header, name),
                declaration_tokens(self.facade, name),
                name,
            )

    def test_project_and_mod02_lists_compile_the_module(self):
        project = PROJECT.read_text(encoding="utf-8")
        self.assertIn('ClCompile Include="WebSharedFilesController.cpp"', project)
        self.assertIn('ClInclude Include="WebSharedFilesController.h"', project)
        for relative in (
            "tools/architecture/verify_mod02_characterization.py",
            "tools/architecture/run_mod02_stream_selftest.ps1",
        ):
            self.assertIn(
                "WebSharedFilesController.cpp",
                (ROOT / relative).read_text(encoding="utf-8"),
            )


class W6SharedFilesTypedEvidence(unittest.TestCase):
    def test_m2a_c96fd283cf5c4294(self):
        self.assertIn("M2A_BIND_W6_B161DA740E", SOURCE.read_text(encoding="utf-8"))

    def test_m2a_a8a849f02126e94c(self):
        self.assertIn("class WebSharedFilesController", HEADER.read_text(encoding="utf-8"))

    def test_m2a_7e3fd3afc75a92be(self):
        self.assertIn("std::stable_sort", SOURCE.read_text(encoding="utf-8"))

    def test_m2a_3a2eb322b3642e94(self):
        self.assertIn("RunWebSharedFilesControllerCharacterizationSelfTest", SOURCE.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
