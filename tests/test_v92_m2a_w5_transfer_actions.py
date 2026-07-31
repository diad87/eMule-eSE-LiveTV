"""M2A-W5 typed evidence for WebTransferActions."""

from __future__ import annotations

import pathlib
import re
import subprocess
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
MC = ROOT / "srchybrid" / "WebTransferActions.cpp"
MH = ROOT / "srchybrid" / "WebTransferActions.h"
WC = ROOT / "srchybrid" / "WebServer.cpp"
WH = ROOT / "srchybrid" / "WebServer.h"
PROJECT = ROOT / "srchybrid" / "emule.vcxproj"


class W5TransferActionsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.mc = MC.read_text(encoding="utf-8")
        cls.mh = MH.read_text(encoding="utf-8")
        cls.wc = WC.read_text(encoding="utf-8")
        cls.wh = WH.read_text(encoding="utf-8")

    def test_module_is_portable_and_bounded(self):
        self.assertLessEqual(
            len(self.mc.splitlines()) + len(self.mh.splitlines()), 1050
        )
        for forbidden in (
            "WebServer.h", "WebTransferController.h", "theApp",
            "thePrefs", "SendMessage", "CString", "windows.h",
        ):
            self.assertNotIn(forbidden, self.mc + self.mh)
        self.assertIn('#include "M2ABindingPort.h"', self.mh)

    def test_binding_and_runtime_selftest_are_real(self):
        self.assertIn("M2A_BIND_W5_095B87253F", self.mc)
        self.assertIn("new WebTransferActions(parent)", self.mc)
        self.assertIn("RunWebTransferActionsCharacterizationSelfTest", self.mc)
        self.assertIn("state.emitted != 0", self.mc)
        self.assertIn("state.emitted != 1", self.mc)
        self.assertIn("WebTransferActionKind::FileCancel", self.mc)

    def test_non_admin_is_fail_closed_before_any_effect(self):
        execute = self.mc.split(
            "WebTransferActionResult WebTransferActions::Execute", 1
        )[1].split("M2AModuleHandle M2A_BIND_W5", 1)[0]
        guard = execute.index("!input.admin")
        first_emit = execute.index("Emit(port")
        self.assertLess(guard, first_emit)

    def test_file_or_friend_branch_cannot_duplicate_one_operation(self):
        execute = self.mc.split(
            "WebTransferActionResult WebTransferActions::Execute", 1
        )[1].split("M2AModuleHandle M2A_BIND_W5", 1)[0]
        self.assertIn("if (!input.operation.empty() && input.fileHash.empty())", execute)
        self.assertIn("} else if (!input.operation.empty()", execute)
        self.assertNotIn("RunWebTransferActions", self.mc.split(
            "WebTransferActionResult WebTransferActions::Execute", 1
        )[0])

    def test_facade_routes_actions_without_rendering(self):
        body = self.wc.split("void CWebServer::_MakeTransferList", 1)[1].split(
            "CString CWebServer::_GetTransferList", 1
        )[0]
        self.assertLessEqual(len(body.splitlines()), 150)
        self.assertIn("RunWebTransferActions", body)
        self.assertNotIn("WebTransferController::", body)
        self.assertNotIn("Render", body)
        self.assertIn("(LPCTSTR)c.addDownload", body)
        self.assertIn("request->text = c.actionText", body)

    def test_production_selftest_and_project_are_wired(self):
        self.assertIn("RunWebTransferActionsCharacterizationSelfTest", self.wc)
        project = PROJECT.read_text(encoding="utf-8")
        self.assertIn('ClCompile Include="WebTransferActions.cpp"', project)
        self.assertIn('ClInclude Include="WebTransferActions.h"', project)

    def test_value_contracts_are_odr_token_exact(self):
        def tokens(text: str, name: str) -> list[str]:
            starts = [
                text.find(prefix + name)
                for prefix in ("enum class ", "struct ")
                if text.find(prefix + name) >= 0
            ]
            self.assertTrue(starts, name)
            start = min(starts)
            opening = text.index("{", start)
            depth = 0
            for end in range(opening, len(text)):
                depth += (text[end] == "{") - (text[end] == "}")
                if depth == 0:
                    declaration = text[start:text.index(";", end) + 1]
                    return re.findall(
                        r"[A-Za-z_]\w*|::|\d+(?:\.\d+)?|[^\s]",
                        declaration,
                    )
            self.fail(f"unterminated contract {name}")
        for name in (
            "WebTransferActionKind", "WebTransferActionSortDomain",
            "WebTransferActionCommand", "WebTransferActionInput",
            "WebTransferActionResult", "WebTransferActionsPort",
        ):
            self.assertEqual(tokens(self.mh, name), tokens(self.wc, name), name)

    def test_diff_is_free_of_whitespace_errors(self):
        result = subprocess.run(
            ["git", "diff", "--check"], cwd=ROOT,
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class W5TypedEvidence(unittest.TestCase):
    def test_m2a_5f4f5a17f00255c8(self):
        self.assertIn(
            "RunWebTransferActionsCharacterizationSelfTest",
            MC.read_text(encoding="utf-8"),
        )

    def test_m2a_451b06dc4b7d4488(self):
        self.assertIn(
            "class WebTransferActions",
            MH.read_text(encoding="utf-8"),
        )

    def test_m2a_bf7687ed0ca6c7bc(self):
        self.assertIn(
            "M2A_BIND_W5_095B87253F",
            MC.read_text(encoding="utf-8"),
        )

    def test_m2a_cc605fbcf72a771e(self):
        self.assertIn(
            "RunWebTransferActions",
            WC.read_text(encoding="utf-8"),
        )


if __name__ == "__main__":
    unittest.main()
