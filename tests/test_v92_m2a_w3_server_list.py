"""W3 server-list controller, GUI-port, permissions, and facade invariants."""
import pathlib
import re
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "srchybrid"
MH = SRC / "WebServerListController.h"
MC = SRC / "WebServerListController.cpp"
WH = SRC / "WebServer.h"
WC = SRC / "WebServer.cpp"
PROJECT = SRC / "emule.vcxproj"
BASE = "f348c536"
ACTIVATION = "c70efe30232dec73c749d9af48b192f319d2fdbe"


class W3ServerListTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mh, cls.mc, cls.wh, cls.wc, cls.project = (
            path.read_text(encoding="utf-8")
            for path in (MH, MC, WH, WC, PROJECT)
        )

    def test_module_is_physical_and_within_budget(self):
        self.assertLessEqual(
            len(self.mh.splitlines()) + len(self.mc.splitlines()), 700
        )
        self.assertIn('ClCompile Include="WebServerListController.cpp"', self.project)
        self.assertIn('ClInclude Include="WebServerListController.h"', self.project)

    def test_card_churn_budget_is_met(self):
        result = subprocess.run(
            [
                "git", "diff", "--numstat", BASE, ACTIVATION, "--",
                "srchybrid/WebServer.cpp", "srchybrid/WebServer.h",
                "srchybrid/WebServerListController.cpp",
                "srchybrid/WebServerListController.h",
                "srchybrid/emule.vcxproj",
            ],
            cwd=ROOT, check=True, capture_output=True, text=True,
        )
        added = deleted = 0
        for line in result.stdout.splitlines():
            left, right, _ = line.split("\t", 2)
            if left != "-":
                added += int(left)
            if right != "-":
                deleted += int(right)
        # Untracked module files are deliberately counted from their physical size.
        if not subprocess.run(
            ["git", "ls-files", "--error-unmatch", str(MH.relative_to(ROOT))],
            cwd=ROOT, capture_output=True,
        ).returncode == 0:
            added += len(self.mh.splitlines()) + len(self.mc.splitlines())
        self.assertLessEqual(added, 800)
        self.assertGreaterEqual(deleted, 600)
        self.assertLessEqual(added - deleted, 200)

    def test_parent_binding_is_explicit_and_lifetime_safe(self):
        for marker in ("M2A_BIND_W3_F05B56128F", "M2A_UNBIND_W3_F05B56128F"):
            self.assertIn(marker, self.mc)
            self.assertIn(marker, self.wc)
        self.assertIn("std::shared_ptr<WebServerListController> binding", self.mc)
        self.assertIn("new WebServerListController(parent)", self.mc)
        constructor = self.wc.split("CWebServer::CWebServer()", 1)[1].split(
            "CWebServer::~CWebServer()", 1
        )[0]
        self.assertIn(
            "M2A_BIND_W3_F05B56128F(M2AParentPort{this})",
            constructor,
        )

    def test_facade_routes_through_a_small_adapter(self):
        adapter = self.wc.split(
            "CString CWebServer::_GetServerList", 1
        )[1].split("CString CWebServer::_GetTransferList", 1)[0]
        self.assertLessEqual(len(adapter.splitlines()), 80)
        self.assertIn("RunWebServerPage", adapter)
        self.assertEqual(
            adapter.split("{", 1)[1].lstrip().splitlines()[0].strip().split(";", 1)[0],
            "M2AModuleHandle binding = M2A_BIND_W3_F05B56128F(M2AParentPort{Data.pThis})",
        )

    def test_coordinator_does_not_depend_on_module_type(self):
        self.assertNotIn('#include "WebServerListController.h"', self.wc + self.wh)
        self.assertNotIn("class WebServerListController", self.wc + self.wh)

    def test_gui_dependencies_are_only_callbacks(self):
        for callback in (
            "parse", "plain", "action", "addServer",
            "updateServerMet", "saveHidden", "snapshot",
        ):
            self.assertRegex(self.mh, rf"\(\*{callback}\)")
        lowered = self.mc.lower()
        for forbidden in (
            "emuledlg", "serverlistctrl", "serverconnect",
            "sendmessage", "web_gui_interaction",
        ):
            self.assertNotIn(forbidden, lowered)

    def test_non_admin_actions_are_rejected_by_characterization(self):
        self.assertIn("if (input.admin)", self.mc)
        self.assertIn("state.actions == 0", self.mc)
        self.assertIn('input.url = _T("ses=7&c=remove', self.mc)
        self.assertIn('input.url = _T("ses=7&c=disconnect")', self.mc)
        self.assertIn("state.actions == 3", self.mc)
        self.assertIn('state.events == _T("AC")', self.mc)

    def test_empty_list_order_and_menu_bounds_are_explicit(self):
        for marker in (
            "if (!rows.empty())",
            "Alpha|Bravo|",
            'empty.html == _T("LR")',
            "menu >= 0",
            "menu < static_cast<int>(result.hidden.size())",
            "state.saves == 0",
            "state.saves == 1",
            "port.snapshot(port.context, rows)",
        ):
            self.assertIn(marker, self.mc)

    def test_legacy_text_escaping_mode_is_preserved(self):
        adapter = self.wc.split(
            "CString CWebServer::_GetServerList", 1
        )[1].split("CString CWebServer::_GetTransferList", 1)[0]
        self.assertGreaterEqual(adapter.count("EscapeWebTemplateText("), 5)
        self.assertIn("bool noquote = true", self.wh)
        self.assertIn("EscapeWebTemplateText(server.GetListName(), true)", adapter)
        self.assertIn("EscapeWebTemplateText(server.GetDescription(), true)", adapter)
        self.assertGreaterEqual(
            adapter.count(
                "EscapeWebTemplateText(theApp.emuledlg->GetLastLogEntry(), true)"
            ),
            3,
        )
        self.assertIn(
            r'''_SpecialChars(_T("<&\"'\n"), true)''',
            self.wc,
        )
        self.assertIn(
            r'''_T("&lt;&amp;&quot;&#8217;\\n")''',
            self.wc,
        )

    def test_facade_value_contracts_are_odr_token_exact(self):
        def tokens(text, name):
            start = min(
                pos for prefix in ("enum class ", "struct ")
                if (pos := text.find(prefix + name)) >= 0
            )
            opening = text.index("{", start)
            depth = 0
            for end in range(opening, len(text)):
                depth += (text[end] == "{") - (text[end] == "}")
                if depth == 0:
                    declaration = text[start:text.index(";", end) + 1]
                    return re.findall(
                        r"[A-Za-z_]\w*|::|\d+(?:\.\d+)?|[^\s]", declaration
                    )
            self.fail(f"unterminated contract {name}")
        for name in (
            "WebServerAction", "WebServerRow", "WebServerPageInput",
            "WebServerPageResult", "WebServerGuiPort",
        ):
            self.assertEqual(tokens(self.mh, name), tokens(self.wc, name), name)

    def test_obsolete_server_list_implementation_is_gone(self):
        for marker in (
            "_GetAddServerBox", "_RemoveServer", "_AddToStatic",
            "_RemoveFromStatic", "_ConnectToServer", "_ServerCmp",
            "ServerEntry",
        ):
            self.assertNotIn(marker, self.wh + self.wc)


class W3TypedEvidence(unittest.TestCase):
    def test_m2a_24960e1bdd25bdc0(self):
        self.assertIn("M2A_BIND_W3_F05B56128F", MC.read_text(encoding="utf-8"))

    def test_m2a_ea1c678e71a8c0a7(self):
        self.assertIn("RunWebServerPage", WC.read_text(encoding="utf-8"))

    def test_m2a_e7165f9d60f4c24d(self):
        self.assertIn(
            "CString CWebServer::_GetServerList",
            WC.read_text(encoding="utf-8"),
        )

    def test_m2a_1a03992f0bc4c2ac(self):
        self.assertIn(
            "class WebServerListController",
            MH.read_text(encoding="utf-8"),
        )


if __name__ == "__main__":
    unittest.main()
