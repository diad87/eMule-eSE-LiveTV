from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ESE = ROOT / "srchybrid" / "eSE"
ROUTES = ESE / "routes"
CONTRACT_PATH = ROOT / "docs" / "architecture" / "mod44_route_context_contract_v1.json"


def context_reads(source: str) -> set[str]:
    return set(re.findall(r"\b_ctx\.([A-Za-z_][A-Za-z0-9_]*)", source))


def schema_dependencies(source: str, route_name: str) -> set[str]:
    match = re.search(
        rf"validateRouteContext\(ctx,\s*['\"]{re.escape(route_name)}['\"],\s*\{{(.*?)\}}\s*\)",
        source,
        flags=re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"missing validated context for {route_name}")
    return set(re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*:", match.group(1)))


class Mod44RouteContextTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
        cls.validator = (ROUTES / "route_context.js").read_text(encoding="utf-8")

    def test_contract_freezes_scope_and_safe_validation(self) -> None:
        self.assertEqual(
            self.contract["schema"],
            "ese.mod44.route-context-contract/v1",
        )
        self.assertIn("Object.prototype.hasOwnProperty.call(context, key)", self.validator)
        self.assertIn("validated[key] = context[key]", self.validator)
        self.assertIn(
            'throw new Error("invalid " + routeName + " route context")',
            self.validator,
        )
        for forbidden in ("JSON.stringify(context)", "String(context)", "context = validated"):
            self.assertNotIn(forbidden, self.validator)

    def test_every_context_read_is_declared_and_matches_contract(self) -> None:
        for file_name, route in self.contract["route_contexts"].items():
            source = (ROUTES / file_name).read_text(encoding="utf-8")
            declared = schema_dependencies(source, route["name"])
            expected = set(route["dependencies"])
            self.assertEqual(declared, expected, file_name)
            self.assertEqual(context_reads(source), expected, file_name)
            self.assertRegex(
                source,
                rf"function init\(ctx\)\s*\{{\s*_ctx = validateRouteContext\(",
                file_name,
            )

    def test_dispatcher_and_static_factories_validate_before_use(self) -> None:
        dispatcher = (ROUTES / self.contract["dispatcher_context"]["file"].split("/")[-1]).read_text(
            encoding="utf-8"
        )
        self.assertIn(
            'validateRouteContext(dependencies, "HTTP dispatcher"',
            dispatcher,
        )
        declared = set(
            re.findall(
                r"\b([A-Za-z_][A-Za-z0-9_]*)\s*:",
                re.search(
                    r'validateRouteContext\(dependencies,\s*"HTTP dispatcher",\s*\{(.*?)\}\s*\)',
                    dispatcher,
                    flags=re.DOTALL,
                ).group(1),
            )
        )
        self.assertEqual(
            declared,
            set(self.contract["dispatcher_context"]["dependencies"]),
        )

        static = (ROUTES / self.contract["static_context"]["file"].split("/")[-1]).read_text(
            encoding="utf-8"
        )
        self.assertIn('validateRouteContext(candidate, "static"', static)
        for key in self.contract["static_context"]["required"] + self.contract["static_context"]["defaulted"]:
            self.assertIn(f"{key}:", static)

    def test_route_and_composition_files_remain_bounded(self) -> None:
        limits = self.contract["limits"]
        server = (ESE / "server.js").read_text(encoding="utf-8")
        self.assertLessEqual(
            len(server.splitlines()),
            limits["composition_root_physical_lines"],
        )
        for route_file in ROUTES.glob("*.js"):
            with self.subTest(route=route_file.name):
                source = route_file.read_text(encoding="utf-8")
                self.assertLessEqual(
                    len(source.splitlines()),
                    limits["route_module_physical_lines"],
                )

    def test_negative_fixtures_detect_hidden_dependency_and_growth(self) -> None:
        route = (ROUTES / "movies_routes.js").read_text(encoding="utf-8")

        def validate(source: str) -> None:
            declared = schema_dependencies(source, "movies")
            if context_reads(source) != declared:
                raise ValueError("undeclared route dependency")
            if len(source.splitlines()) > self.contract["limits"]["route_module_physical_lines"]:
                raise ValueError("route module LOC drift")

        validate(route)
        with self.assertRaises(ValueError):
            validate(route.replace("_ctx.CACHE_DIR", "_ctx.hiddenDependency", 1))
        with self.assertRaises(ValueError):
            validate(route + "\n" * 501)


if __name__ == "__main__":
    unittest.main()
