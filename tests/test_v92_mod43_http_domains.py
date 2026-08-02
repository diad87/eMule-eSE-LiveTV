import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ESE = ROOT / "srchybrid" / "eSE"
CONTRACT_PATH = ROOT / "docs" / "architecture" / "mod43_http_domains_contract_v1.json"


class Mod43HttpDomainsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
        cls.server = (ESE / "server.js").read_text(encoding="utf-8")
        cls.router = (ESE / "routes" / "http_domain_router.js").read_text(encoding="utf-8")
        cls.static_routes = (ESE / "routes" / "static_routes.js").read_text(encoding="utf-8")
        cls.http_test = (ESE / "test" / "http_domain_router.test.js").read_text(encoding="utf-8")

    def test_contract_freezes_domain_and_route_order(self):
        self.assertEqual(self.contract["schema"], "ese.mod43.http-domains-contract/v1")
        self.assertEqual(
            self.contract["dispatcher"]["domain_order"],
            ["security", "debug", "live", "api", "pages", "static", "not_found"],
        )
        self.assertEqual(
            self.contract["api_route_order"],
            [
                "v1Routes",
                "moviesRoutes",
                "emuleRoutes",
                "streamCompleted",
                "streamPart",
                "systemRoutes",
            ],
        )
        self.assertEqual(
            self.contract["page_route_order"],
            [
                "miscPages",
                "connectPage",
                "searchPage",
                "appPage",
                "explorePage",
                "mylistPage",
                "mainPage",
            ],
        )

    def test_server_is_only_the_bounded_composition_root(self):
        self.assertLessEqual(len(self.server.splitlines()), 300)
        self.assertIn("createHttpDomainRouter", self.server)
        self.assertIn("createStaticRoutes", self.server)
        self.assertRegex(self.server, r"http\.createServer\(routeHttpRequest\)")
        self.assertNotRegex(
            self.server,
            r"if\s*\(\s*(?:v1Routes|moviesRoutes|emuleRoutes|streamCompleted|streamPart|systemRoutes)\.handle",
        )

    def test_dispatcher_owns_frozen_precedence_and_live_compatibility(self):
        positions = [
            self.router.index("security.apply"),
            self.router.index("debugLog.handle"),
            self.router.index("isLivePath"),
            self.router.index("runHandlers(apiHandlers"),
            self.router.index("runHandlers(pageHandlers"),
            self.router.index("staticRoutes.handle"),
            self.router.index('res.writeHead(404)'),
        ]
        self.assertEqual(positions, sorted(positions))
        for value in self.contract["live_paths"]["prefixes"]:
            self.assertIn(json.dumps(value), self.router)
        for value in self.contract["live_paths"]["exact"]:
            self.assertIn(json.dumps(value), self.router)

    def test_route_modules_stay_small_and_filesystem_is_async(self):
        self.assertLessEqual(len(self.router.splitlines()), 500)
        self.assertLessEqual(len(self.static_routes.splitlines()), 500)
        self.assertIn("fileSystem.promises.access", self.static_routes)
        self.assertNotRegex(
            self.static_routes,
            r"\b(?:accessSync|existsSync|readFileSync|readdirSync|statSync)\s*\(",
        )

    def test_real_http_gate_uses_ephemeral_loopback_and_cleanup(self):
        self.assertRegex(self.http_test, r'server\.listen\(0,\s*"127\.0\.0\.1"')
        self.assertIn('server.close(resolve)', self.http_test)
        for phrase in (
            "security denial short-circuits",
            "debug, live, API and page precedence",
            "static fallback and 404",
            "no fallthrough",
        ):
            self.assertIn(phrase, self.http_test)


if __name__ == "__main__":
    unittest.main()
