"""W1 WebRequestDispatch ownership, routing, and response invariants."""
import importlib.util
import pathlib
import re
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "srchybrid"
TOOLS = ROOT / "tools" / "architecture"
H, C = SRC / "WebRequestDispatch.h", SRC / "WebRequestDispatch.cpp"
WH, WC, PROJECT = SRC / "WebServer.h", SRC / "WebServer.cpp", SRC / "emule.vcxproj"
sys.path.insert(0, str(TOOLS))
SPEC = importlib.util.spec_from_file_location(
    "m2a00_w1", TOOLS / "verify_m2a00_migration_ratchet.py"
)
assert SPEC and SPEC.loader
GATE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = GATE
SPEC.loader.exec_module(GATE)


class W1RequestDispatchTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.h, cls.c, cls.wh, cls.wc, cls.project = (
            path.read_text(encoding="utf-8")
            for path in (H, C, WH, WC, PROJECT)
        )

    def test_module_project_and_parent_binding_are_physical(self):
        self.assertLessEqual(len(self.h.splitlines()) + len(self.c.splitlines()), 700)
        for marker in (
            'ClCompile Include="WebRequestDispatch.cpp"',
            'ClInclude Include="WebRequestDispatch.h"',
        ):
            self.assertIn(marker, self.project)
        self.assertIn("class WebRequestDispatch", self.h)
        start_server = self.wc.split("void CWebServer::StartServer()", 1)[1].split("void CWebServer::StopServer()", 1)[0]
        self.assertIn("requestDispatchBinding = M2A_BIND_W1_EC6846B80E(M2AParentPort{this})", start_server)
        self.assertIn("MakeM2AModuleHandle(new WebRequestDispatch(parent))", self.c)

    def test_process_url_is_a_small_port_adapter(self):
        lengths = GATE._coordinator_snapshot()["WebServer"]["functions"][
            "CWebServer::_ProcessURL"
        ]
        self.assertEqual(len(lengths), 1)
        self.assertLessEqual(lengths[0], 150)
        body = self.wc.split("void CWebServer::_ProcessURL", 1)[1].split(
            "CString CWebServer::_ParseURLArray", 1
        )[0]
        self.assertIn("WebClassicPort port", body)
        self.assertIn(
            "RunWebClassicRequest(M2AParentPort{owner}, input, port)", body
        )
        self.assertNotIn('sPage == _T("server")', body)

    def test_route_table_is_closed_case_sensitive_and_characterized(self):
        expected = {
            "server", "shared", "transfer", "search", "graphs", "log",
            "sinfo", "debuglog", "myinfo", "stats", "kad", "options",
        }
        actual = set(re.findall(
            r'\{_T\("([^"]+)"\), WebClassicView::\w+\}', self.c
        ))
        self.assertEqual(actual, expected)
        for marker in ("SERVER", "missing", "CString()"):
            self.assertIn(f"ResolveWebClassicView(_T(\"{marker}\"))" if marker != "CString()"
                          else "ResolveWebClassicView(CString())", self.c)
        self.assertIn("RunWebClassicRequestCharacterizationSelfTest()", self.wc)

    def test_security_and_single_response_guards_remain_explicit(self):
        code = self.h + self.c
        for marker in (
            "login_blocked", "validate_challenge", "validate_csrf",
            "ConstantTimeEqual", "input.loopback", "response_committed",
            "500 Internal Server Error", "X-CSRF-Token",
        ):
            self.assertIn(marker, code)
        self.assertIn("INADDR_LOOPBACK", self.wc)
        self.assertIn("if (state.response_committed)\n\t\treturn;", self.c)
        getfile = self.c.index('page == _T("getfile")')
        parse_hash = self.c.index('port.parse_url(input.url, _T("filehash"))', getfile); committed = self.c.index("state.response_committed = true;", getfile); send_file = self.c.index("port.send_requested_file(", getfile)
        restore = self.c.index("state.response_committed = sent;", send_file); self.assertLess(parse_hash, committed); self.assertLess(committed, send_file); self.assertLess(send_file, restore)
        self.assertIn("RunProbe(fileThrow", self.c)
        self.assertIn("fileThrow.replies != 0", self.c); self.assertIn("RunProbe(parseThrow", self.c); self.assertIn("dispatch = dispatchBinding; }", self.c)
        self.assertIn("CompressWebGzip(", self.wc)
        self.assertNotIn("CWebServer::_GzipCompress", self.wc)


class W1TypedEvidence(unittest.TestCase):
    def test_m2a_858a6990e5f070f9(self): self.assertIn("M2A_BIND_W1_EC6846B80E", C.read_text(encoding="utf-8"))
    def test_m2a_695fd6f3eaec3ffc(self): self.assertIn("W1 classic web request dispatcher", H.read_text(encoding="utf-8"))
    def test_m2a_cf6cacd8adea631d(self): self.assertIn("RunWebClassicRequest(M2AParentPort{owner}, input, port)", WC.read_text(encoding="utf-8"))
    def test_m2a_fe53365ab380de40(self): self.assertIn("class WebRequestDispatch", H.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
