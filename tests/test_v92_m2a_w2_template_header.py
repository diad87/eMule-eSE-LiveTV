"""W2 template ownership, escaping, metadata, and header/footer invariants."""
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "srchybrid"
TRH, TRC = SRC / "WebTemplateRenderer.h", SRC / "WebTemplateRenderer.cpp"
HFH, HFC = SRC / "WebHeaderFooter.h", SRC / "WebHeaderFooter.cpp"
WH, WC, PROJECT = SRC / "WebServer.h", SRC / "WebServer.cpp", SRC / "emule.vcxproj"

class W2TemplateHeaderTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.trh, cls.trc, cls.hfh, cls.hfc, cls.wh, cls.wc, cls.project = (
            p.read_text(encoding="utf-8") for p in (TRH, TRC, HFH, HFC, WH, WC, PROJECT)
        )

    def test_modules_and_budget_are_physical(self):
        self.assertLessEqual(sum(len(x.splitlines()) for x in (self.trh, self.trc, self.hfh, self.hfc)), 800)
        for name in ("WebTemplateRenderer", "WebHeaderFooter"):
            self.assertIn(f'ClCompile Include="{name}.cpp"', self.project); self.assertIn(f'ClInclude Include="{name}.h"', self.project)

    def test_parent_binding_is_persistent_and_complete(self):
        for marker in ("M2A_BIND_W2_071B3D442B", "M2A_BIND_W2_9330EBAD15"):
            self.assertIn(marker, self.wc)
        self.assertIn("std::shared_ptr<WebTemplateRenderer> binding", self.trc)
        self.assertIn("std::shared_ptr<WebHeaderFooter> binding", self.hfc)
        self.assertIn("M2A_BIND_W2_9330EBAD15(M2AParentPort{this})", self.wc.split("void CWebServer::RestartSockets()", 1)[1].split("void CWebServer::StartServer()", 1)[0])

    def test_template_state_has_one_owner(self):
        self.assertNotIn("WebTemplates", self.wh); self.assertNotIn("m_Templates", self.wh + self.wc)
        for marker in ("m_values", "m_lastModified", "m_etag"):
            self.assertIn(marker, self.trh)

    def test_adapters_are_small(self):
        header = self.wc.split("CString CWebServer::_GetHeader", 1)[1].split("const CString CWebServer::_GetFooter", 1)[0]
        self.assertLessEqual(len(header.splitlines()), 20); self.assertIn("RenderWebHeader", header)

    def test_missing_template_and_escaping_are_characterized(self):
        self.assertIn('ExtractTemplate(source, _T("MISSING"), false).IsEmpty()', self.trc)
        self.assertIn("&lt;&amp;&quot;&#8217;\\\\n", self.trc)

    def test_etag_and_exact_asset_headers_are_preserved(self):
        for marker in ("MD5Sum(lastModified).GetHashString()", "_tcsftime_l", '"C"', "options.lastModified.assign", "options.etag.assign"):
            self.assertIn(marker, self.trc + self.wc)

    def test_each_request_uses_one_coherent_template_snapshot(self):
        for marker in ("thread_local RequestSnapshot", "CaptureWebTemplateSnapshot", "renderer->Capture"):
            self.assertIn(marker, self.trc + self.wc)

    def test_header_footer_and_runtime_selftests_are_bound(self):
        for marker in ("[CharSet]", "[StyleSheet]", "[ConState]", "[KadConText]", "RunWebPageChromeCharacterizationSelfTest()"):
            self.assertIn(marker, self.hfc + self.wc)

    def test_log_graph_comment_and_login_rendering_remain_explicit(self):
        for marker in ("RenderWebLogView", "RenderWebCommentList", "RenderWebLogin"):
            self.assertIn(marker, self.hfh + self.hfc + self.wc)

    def test_facade_value_contracts_are_odr_token_exact(self):
        def tokens(text, name):
            start = min(pos for prefix in ("enum class ", "struct ")
                        if (pos := text.find(prefix + name)) >= 0)
            opening = text.index("{", start); depth = 0
            for end in range(opening, len(text)):
                depth += (text[end] == "{") - (text[end] == "}")
                if depth == 0:
                    return re.findall(r"[A-Za-z_]\w*|::|\d+(?:\.\d+)?|[^\s]",
                                      text[start:text.index(";", end) + 1])
            self.fail(f"unterminated contract {name}")
        for name, owner in (("WebTemplateId", self.trh),
                            ("WebTemplateLogView", self.hfh),
                            ("WebHeaderRuntime", self.hfh),
                            ("WebCommentRow", self.hfh),
                            ("WebCommentListInput", self.hfh)):
            self.assertEqual(tokens(owner, name), tokens(self.wc, name), name)

class W2TypedEvidence(unittest.TestCase):
    def test_m2a_479d18b816c62832(self): self.assertIn("M2A_BIND_W2_071B3D442B", TRC.read_text(encoding="utf-8"))
    def test_m2a_c91bb83974386e48(self): self.assertIn("M2A_BIND_W2_9330EBAD15", HFC.read_text(encoding="utf-8"))
    def test_m2a_2df16eaa9b59ed68(self): self.assertIn("WebTemplateRenderer.cpp", PROJECT.read_text(encoding="utf-8"))
    def test_m2a_907630c0bce11c84(self): self.assertIn("RenderWebHeader", WC.read_text(encoding="utf-8"))
    def test_m2a_7746cad6892c1338(self): self.assertIn("class WebTemplateRenderer", TRH.read_text(encoding="utf-8"))
    def test_m2a_b1b898ce26b0a675(self): self.assertIn("class WebHeaderFooter", HFH.read_text(encoding="utf-8"))

if __name__ == "__main__":
    unittest.main()
