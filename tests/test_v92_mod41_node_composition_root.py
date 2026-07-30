from __future__ import annotations

import hashlib
import json
import pathlib
import re
import subprocess
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "docs" / "architecture" / "mod41_node_composition_contract_v1.json"
SERVER = ROOT / "srchybrid" / "eSE" / "server.js"
DEBUG_PAGE = ROOT / "srchybrid" / "eSE" / "pages" / "debug_page.js"
PACKAGE = ROOT / "srchybrid" / "eSE" / "package.json"
SLICE_BASE = "76cee7b0482ef0c0916708ea159a56915d185b36"


def debug_html(source: str) -> str:
    marker = '<!doctype html><html><head><meta charset="utf-8">'
    end = "</body></html>"
    start = source.index(marker)
    return source[start:source.index(end, start) + len(end)]


class Mod41NodeCompositionRootTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        cls.server = SERVER.read_text(encoding="utf-8")
        cls.debug_page = DEBUG_PAGE.read_text(encoding="utf-8")

    def test_contract_freezes_scope_ownership_and_hard_stop(self) -> None:
        self.assertEqual(
            self.contract["schema"],
            "ese.mod41.node-composition-contract/v1",
        )
        self.assertEqual(self.contract["baseline_commit"], SLICE_BASE)
        root = self.contract["composition_root"]
        self.assertEqual(root["file"], "srchybrid/eSE/server.js")
        self.assertEqual(root["baseline_physical_loc"], 389)
        self.assertEqual(root["hard_stop_physical_loc"], 300)
        self.assertIn("HTTP server construction", root["owns"])
        self.assertIn("process lifecycle hooks", root["owns"])

    def test_server_is_the_only_bounded_composition_root(self) -> None:
        self.assertLessEqual(len(self.server.splitlines()), 300)
        for marker in (
            "http.createServer(",
            "server.listen(PORT, '127.0.0.1'",
            "tunnel.init(PORT)",
            "security.init({ tunnel })",
            "v1Routes.init({",
            "process.on('SIGINT'",
        ):
            self.assertIn(marker, self.server)
        for forbidden in (
            "http.createServer(",
            ".listen(",
            "process.on(",
            "tunnel.init(",
            "security.init(",
        ):
            self.assertNotIn(forbidden, self.debug_page)

    def test_security_and_route_order_are_unchanged(self) -> None:
        ordered = (
            "security.apply(url, req, res)",
            "debugLog.handle(url, req, res)",
            "debugPage.handle(url, req, res)",
            "liveApi.handleRoute(url, req, res",
            "v1Routes.handle(url, req, res)",
            "moviesRoutes.handle(url, req, res)",
            "miscPages.handle(url, req, res)",
        )
        positions = [self.server.index(marker) for marker in ordered]
        self.assertEqual(positions, sorted(positions))
        self.assertIn(
            "const debugPage    = require('./pages/debug_page');",
            self.server,
        )

    def test_extracted_page_is_stateless_and_byte_identical(self) -> None:
        for forbidden in (
            "require('./server')",
            'require("../server")',
            "node:fs",
            "child_process",
            "global.",
            "process.",
            "setTimeout(",
        ):
            self.assertNotIn(forbidden, self.debug_page)
        # The only setInterval text is inside the immutable browser response.
        executable_prefix = self.debug_page[:self.debug_page.index("<!doctype html>")]
        executable_suffix = self.debug_page[self.debug_page.index("</body></html>"):]
        self.assertNotIn("setInterval(", executable_prefix + executable_suffix)

        baseline = subprocess.run(
            ["git", "show", f"{SLICE_BASE}:srchybrid/eSE/server.js"],
            cwd=ROOT,
            check=True,
            capture_output=True,
        ).stdout.decode("utf-8")
        expected = debug_html(baseline)
        actual = debug_html(self.debug_page)
        self.assertEqual(actual, expected)
        self.assertEqual(
            hashlib.sha256(actual.encode("utf-8")).hexdigest(),
            self.contract["invariants"]["debug_template_source_sha256"],
        )

    def test_package_and_handler_contract_cover_the_extracted_module(self) -> None:
        package = json.loads(PACKAGE.read_text(encoding="utf-8"))
        self.assertIn("pages/*.js", package["pkg"]["scripts"])
        for marker in (
            "url.pathname !== '/debug'",
            "url.pathname !== '/debug/'",
            "res.writeHead(200, {'Content-Type': 'text/html; charset=utf-8'})",
            "return false;",
            "return true;",
            "module.exports = { handle };",
        ):
            self.assertIn(marker, self.debug_page)

    def test_negative_fixtures_detect_growth_order_and_response_drift(self) -> None:
        def validate(server: str, page: str) -> None:
            if len(server.splitlines()) > 300:
                raise ValueError("composition root LOC drift")
            if server.index("security.apply(") > server.index("debugPage.handle("):
                raise ValueError("security order drift")
            digest = hashlib.sha256(debug_html(page).encode("utf-8")).hexdigest()
            if digest != self.contract["invariants"]["debug_template_source_sha256"]:
                raise ValueError("debug response drift")

        validate(self.server, self.debug_page)
        mutations = (
            (self.server + "\n" * 2, self.debug_page),
            (
                re.sub(
                    r"  if \(!security\.apply\(url, req, res\)\) return;\n",
                    "",
                    self.server,
                ).replace(
                    "if (debugPage.handle(url, req, res)) return;",
                    "if (debugPage.handle(url, req, res)) return;\n"
                    "  if (!security.apply(url, req, res)) return;",
                ),
                self.debug_page,
            ),
            (self.server, self.debug_page.replace("<title>eSE/eMule", "<title>drift")),
        )
        for server, page in mutations:
            with self.assertRaises(ValueError):
                validate(server, page)


if __name__ == "__main__":
    unittest.main()
