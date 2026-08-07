"""W4 immutable transfer-snapshot and projection invariants."""
import pathlib
import re
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "srchybrid"
MH = SRC / "WebTransferProjection.h"
MC = SRC / "WebTransferProjection.cpp"
WH = SRC / "WebServer.h"
WC = SRC / "WebServer.cpp"
PROJECT = SRC / "emule.vcxproj"
BASE = "64b3d3ec70f185a3694aa2a82768c60b997e6c5f"
ACTIVATION = "f4d6a6b0873e0b033a0ffc35efb3606bcd2eb01e"


class W4TransferProjectionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mh, cls.mc, cls.wh, cls.wc, cls.project = (
            path.read_text(encoding="utf-8")
            for path in (MH, MC, WH, WC, PROJECT)
        )

    def test_module_is_physical_and_within_budget(self):
        self.assertLessEqual(
            len(self.mh.splitlines()) + len(self.mc.splitlines()), 1050
        )
        self.assertIn('ClCompile Include="WebTransferProjection.cpp"', self.project)
        self.assertIn('ClInclude Include="WebTransferProjection.h"', self.project)

    def test_card_churn_budget_is_met(self):
        result = subprocess.run(
            [
                "git", "diff", "--numstat", BASE, ACTIVATION, "--",
                "srchybrid/WebServer.cpp", "srchybrid/WebServer.h",
                "srchybrid/WebTransferProjection.cpp",
                "srchybrid/WebTransferProjection.h",
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
        for path in (MH, MC, pathlib.Path(__file__)):
            if subprocess.run(
                ["git", "ls-files", "--error-unmatch", str(path.relative_to(ROOT))],
                cwd=ROOT, capture_output=True,
            ).returncode:
                added += len(path.read_text(encoding="utf-8").splitlines())
        self.assertLessEqual(added, 1250)
        self.assertGreaterEqual(deleted, 900)
        self.assertLessEqual(added - deleted, 350)

    def test_snapshot_is_single_and_precedes_render(self):
        self.assertIn("port.snapshot(port.context", self.mc)
        self.assertEqual(self.mc.count("port.snapshot(port.context"), 1)
        self.assertIn("state.events[0] == _T('S')", self.mc)
        self.assertIn("state.snapshots == 1", self.mc)
        render = self.mc.split("CString WebTransferProjection::Render", 1)[1]
        self.assertLess(render.index("port.snapshot("), render.index("RenderHeaders("))
        self.assertIn('html.Find(_T("A|CGB|")) >= 0', self.mc)
        self.assertIn("state.categoryCalls == 4", self.mc)
        self.assertIn("WEBGUIIA_TRANSFER_SNAPSHOT", self.wc)
        self.assertIn("WebTransferSnapshotRequest request", self.wc)

    def test_sorting_uses_only_snapshot_values(self):
        self.assertIn("qsort_s(snapshot.downloads.GetData()", self.mc)
        self.assertIn("qsort_s(snapshot.uploads.GetData()", self.mc)
        for forbidden in ("theApp", "CPartFile", "CUpDownClient", "SendMessage"):
            self.assertNotIn(forbidden, self.mc)
        self.assertNotIn("downloadGraph", self.mh + self.mc)
        self.assertIn("file.sDownloadGraph", self.mc)

    def test_facade_is_small_and_module_is_isolated(self):
        body = self.wc.split("CString CWebServer::_GetTransferList", 1)[1].split(
            "CString CWebServer::_GetSharedFilesList", 1
        )[0]
        self.assertLessEqual(len(body.splitlines()), 150)
        self.assertIn("RunWebTransferProjection", body)
        self.assertNotIn('#include "WebTransferProjection.h"', self.wc + self.wh)
        self.assertNotIn("class WebTransferProjection", self.wc + self.wh)
        actions = self.wc.split(
            "void CWebServer::_MakeTransferList", 1
        )[1].split("CString CWebServer::_GetTransferList", 1)[0]
        self.assertIn("PlanFileAction", actions)
        self.assertNotIn("PlanFileAction", body)

    def test_binding_and_selftest_are_wired(self):
        for marker in ("M2A_BIND_W4_AD763A5EE0", "M2A_UNBIND_W4_AD763A5EE0"):
            self.assertIn(marker, self.mc)
            self.assertIn(marker, self.wc)
        self.assertIn("new WebTransferProjection(parent)", self.mc)
        self.assertIn("RunWebTransferProjectionCharacterizationSelfTest", self.mc)
        self.assertIn("if (!parent) return M2AModuleHandle()", self.mc)

    def test_legacy_escape_and_queue_admin_rules_are_explicit(self):
        self.assertGreaterEqual(self.mc.count("Special(port,"), 2)
        self.assertGreaterEqual(self.mc.count(", true)"), 2)
        self.assertIn(
            "lineTemplate == WebTransferTemplate::QueueLine", self.mc
        )
        self.assertIn("input.admin = true", self.mc)

    def test_value_contracts_are_odr_token_exact(self):
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
            "WebTransferTemplate", "WebTransferProjectionInput",
            "WebTransferSnapshot", "WebTransferProjectionPort",
        ):
            self.assertEqual(tokens(self.mh, name), tokens(self.wc, name), name)


class W4TypedEvidence(unittest.TestCase):
    def test_m2a_4e2335a5b6f710c7(self):
        self.assertIn("RunWebTransferProjection", WC.read_text(encoding="utf-8"))

    def test_m2a_95eb726b82aed693(self):
        self.assertIn("class WebTransferProjection", MH.read_text(encoding="utf-8"))

    def test_m2a_82152fd976c17414(self):
        self.assertIn("M2A_BIND_W4_AD763A5EE0", MC.read_text(encoding="utf-8"))

    def test_m2a_4b37bd148be78c73(self):
        self.assertIn(
            "RunWebTransferProjection",
            WC.read_text(encoding="utf-8"),
        )
        body = WC.read_text(encoding="utf-8").split(
            "CString CWebServer::_GetTransferList", 1
        )[1].split("CString CWebServer::_GetSharedFilesList", 1)[0]
        self.assertLessEqual(len(body.splitlines()), 150)


if __name__ == "__main__":
    unittest.main()
