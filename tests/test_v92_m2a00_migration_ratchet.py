"""M2A-00 freezes a green migration ratchet without weakening final M2."""
from __future__ import annotations
import copy
import hashlib
import importlib.util
import json
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools" / "architecture"
WORKFLOW = ROOT / ".github" / "workflows" / "build.yml"
sys.path.insert(0, str(TOOLS))
SPEC = importlib.util.spec_from_file_location("m2a00", TOOLS / "verify_m2a00_migration_ratchet.py")
assert SPEC and SPEC.loader
GATE = importlib.util.module_from_spec(SPEC); sys.modules[SPEC.name] = GATE; SPEC.loader.exec_module(GATE)


class M2A00RatchetTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract, cls.matrix, cls.baseline, cls.ledger = GATE.load(GATE.CONTRACT), GATE.load(GATE.MATRIX), GATE.load(GATE.BASELINE), GATE.load(GATE.ACTIVATION)

    def test_closed_matrix_is_exhaustive_and_green(self):
        GATE.validate_inputs(self.contract, self.matrix, self.baseline)
        self.assertEqual(GATE.report(), self.baseline)
        report = GATE.verify()
        self.assertEqual(report["status"], "PASS")

    def test_ci_runs_the_m2a00_ratchet_after_existing_architecture_gates(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        existing = 'python -m unittest discover -s tests -p "test_v92_mod*.py"'
        ratchet = 'python -m unittest discover -s tests -p "test_v92_m2a*.py"'
        self.assertIn(existing, workflow)
        self.assertIn(ratchet, workflow)
        self.assertLess(workflow.index(existing), workflow.index(ratchet))

    def test_incomplete_or_string_budget_rows_are_rejected(self):
        for mutate, message in (
            (lambda x: x["function_matrix"][0].pop("wire"), "function row schema incomplete"),
            (lambda x: x["function_matrix"][0].__setitem__("budget", "@{module_loc=1200}"), "function budget must be a typed closed object"),
            (lambda x: x["field_matrix"]["LiveTunnel"]["transfers"][0].pop("parent"), "field transfer schema incomplete"),
            (lambda x: x.__setitem__("dependency_policy", "implicit parent"), "parent/dependency policy drift"),
        ):
            candidate = copy.deepcopy(self.matrix); mutate(candidate)
            with self.assertRaisesRegex(GATE.GateError, message):
                GATE.validate_inputs(self.contract, candidate, self.baseline)

    def test_lt1_budget_limits_are_independent_and_scope_is_exact(self):
        transfer = next(
            item
            for item in self.matrix["field_matrix"]["LiveTunnel"]["transfers"]
            if item["card"] == "LT1"
        )
        module = next(
            item
            for item in self.matrix["additional_modules"]
            if item["card"] == "LT1"
        )
        expected = {
            "module_loc": 800,
            "add": 1000,
            "delete": 250,
            "net": 350,
        }
        self.assertEqual(transfer["budget"], expected)
        self.assertEqual(module["budget"], expected)
        self.assertEqual(
            self.matrix["card_budgets"]["LT1"],
            {
                "add": 1000,
                "delete": 250,
                "net": 350,
                "coordinator": "LiveTunnel",
                "facade_add_max": 80,
                "reduction_required": True,
            },
        )
        self.assertEqual(len(transfer["fields"]), 12)
        self.assertFalse(
            any("Economy" in field or "Hardening" in field
                for field in transfer["fields"])
        )
        candidate = copy.deepcopy(self.matrix)
        candidate["additional_modules"][0]["budget"]["net"] = 1001
        with self.assertRaisesRegex(
            GATE.GateError, "budget/dependency drift"
        ):
            GATE.validate_inputs(self.contract, candidate, self.baseline)

    def test_catalogue_rejects_collapsed_live_api_or_placeholder_dependencies(self):
        candidate = copy.deepcopy(self.matrix)
        candidate["additional_modules"] = [item for item in candidate["additional_modules"] if not item["name"].startswith("WebLiveApi")]
        requirements = GATE._card_test_requirements(self.matrix)
        with mock.patch.object(GATE, "_card_test_requirements", return_value=requirements):
            with self.assertRaisesRegex(GATE.GateError, "collapsed or placeholder"):
                GATE.validate_inputs(self.contract, candidate, self.baseline)

    def test_hash_pins_closed_schemas_and_activation_evidence_are_enforced(self):
        original = GATE.EXPECTED_DOC_HASHES["mod52_migration_matrix_v1.json"]
        try:
            GATE.EXPECTED_DOC_HASHES["mod52_migration_matrix_v1.json"] = "0" * 64
            with self.assertRaisesRegex(GATE.GateError, "hash-pinned M2A input drift"):
                GATE.validate_inputs(self.contract, self.matrix, self.baseline)
        finally:
            GATE.EXPECTED_DOC_HASHES["mod52_migration_matrix_v1.json"] = original
        candidate = copy.deepcopy(self.matrix); candidate["unreviewed"] = True
        with self.assertRaisesRegex(GATE.GateError, "closed schema drift"):
            GATE.validate_inputs(self.contract, candidate, self.baseline)
        ledger = copy.deepcopy(self.ledger)
        ledger["cards"]["LT1"] = {"state":"active","activation_commit":None,"evidence":[]}
        with self.assertRaisesRegex(GATE.GateError, "active M2A card lacks immutable commit/evidence"):
            GATE.validate_inputs(self.contract, self.matrix, self.baseline, ledger)

    def test_lexical_helper_detector_rejects_a_hidden_oversized_body(self):
        source = (ROOT / "srchybrid/LiveTunnel.cpp").read_bytes()
        injected = source + b"\nstatic void M2AHiddenOversizedHelper\n() {\n" + (b"  ;\n" * 151) + b"}\n"
        current = GATE.metrics({"srchybrid/LiveTunnel.cpp": injected})
        self.assertTrue(any("M2AHiddenOversizedHelper" in name for name, _ in current["coordinators"]["LiveTunnel"]["oversized_functions"]))
        # This is a LOC-neutral bypass attempt: only the hidden helper must
        # trigger the second ratchet, not the earlier coordinator-size guard.
        current["coordinators"]["LiveTunnel"]["files"] = copy.deepcopy(self.baseline["metrics"]["coordinators"]["LiveTunnel"]["files"])
        with self.assertRaisesRegex(GATE.GateError, "oversized function grew"):
            GATE.validate_ratchet(self.baseline, current, self.matrix)

    def test_lexical_helper_detector_catches_an_oversized_lambda(self):
        source = (ROOT / "srchybrid/LiveTunnel.cpp").read_bytes()
        injected = source + b"\nauto m2aHiddenLambda = []\n() {\n" + (b"  ;\n" * 151) + b"};\n"
        current = GATE.metrics({"srchybrid/LiveTunnel.cpp": injected})
        self.assertTrue(any("m2aHiddenLambda" in name for name, _ in current["coordinators"]["LiveTunnel"]["oversized_functions"]))

    def test_structural_safety_net_rejects_any_unclassified_long_body(self):
        source = (ROOT / "srchybrid/LiveTunnel.cpp").read_bytes()
        injected = (
            source
            + b"\nDEFINE_HELPER(M2AOpaqueBody) {\n"
            + (b"  ;\n" * 151)
            + b"}\n"
        )
        current = GATE.metrics({"srchybrid/LiveTunnel.cpp": injected})
        self.assertTrue(
            any(
                "unclassified-body" in name
                for name, _ in current["coordinators"]["LiveTunnel"]["oversized_functions"]
            )
        )

    def test_helper_parser_keeps_std_return_and_trailing_forms(self):
        body = ["  ;"] * 151
        helpers = GATE._free_helpers(["static std::vector<int> M2AStdHelper() -> std::vector<int> {"] + body + ["}"], "fixture.cpp")
        self.assertTrue(any("M2AStdHelper" in item["name"] for item in helpers))
        lambdas = GATE._free_helpers(["auto m2aNoParen = [] -> int {"] + body + ["};"], "fixture.cpp")
        self.assertTrue(any("m2aNoParen" in item["name"] for item in lambdas))
        noexcept = GATE._free_helpers(
            ["[[nodiscard]] static void M2ANoexcept() noexcept [[maybe_unused]] {"]
            + body + ["}"],
            "fixture.cpp",
        )
        self.assertTrue(any("M2ANoexcept" in item["name"] for item in noexcept))
        adversarial = (
            'extern "C" void M2AExtern() noexcept {',
            "__declspec(noinline) void M2ADeclspec() noexcept {",
            "static auto m2aStaticLambda = []() noexcept {",
            "auto const m2aConstLambda = []() noexcept {",
            "auto m2aGenericLambda = []<typename T>(T) noexcept {",
        )
        for declaration in adversarial:
            detected = GATE._free_helpers(
                [declaration] + body + ["}"], "fixture.cpp"
            )
            self.assertTrue(detected, declaration)

    def test_active_card_budget_provider_enforces_all_bounds(self):
        matrix = copy.deepcopy(self.matrix)
        matrix["additional_modules"] = [next(item for item in matrix["additional_modules"] if item["name"] == "WebServerFacade")]
        matrix["existing_modules"] = []
        matrix["card_budgets"] = {
            "W12": {
                "add": 800, "delete": 600, "net": 200,
                "coordinator": "WebServer", "facade_add_max": 80,
                "reduction_required": True,
            }
        }
        ledger = {"cards":{"W12":{"state":"active","activation_commit":"0" * 40,"evidence":[]}}}
        def run(aggregate=(800, 600), facade=(80, 100), loc=700):
            def stat(_base, _target, paths):
                return aggregate if not paths else facade
            GATE.validate_active_budgets(
                matrix, ledger, stat, lambda _paths: loc, lambda _commit: "f" * 40
            )
        run()
        for aggregate, facade, loc, message in (
            ((801, 600), (80, 100), 700, "card A/D/net"),
            ((800, 599), (80, 100), 700, "card A/D/net"),
            ((800, 600), (80, 100), 701, "module LOC"),
            ((800, 600), (81, 100), 700, "facade budget"),
            ((800, 600), (80, 80), 700, "coordinator reduction"),
        ):
            with self.assertRaisesRegex(GATE.GateError, message):
                run(aggregate, facade, loc)

    def test_existing_module_and_non_module_cards_use_the_same_budget_gate(self):
        matrix = copy.deepcopy(self.matrix)
        matrix["additional_modules"] = []
        matrix["existing_modules"] = copy.deepcopy(self.matrix["existing_modules"])
        matrix["card_budgets"] = {
            "LS4": copy.deepcopy(self.matrix["card_budgets"]["LS4"]),
            "W7": copy.deepcopy(self.matrix["card_budgets"]["W7"]),
        }
        ledger = {
            "cards": {
                "LS4": {"state": "active", "activation_commit": "1" * 40, "evidence": []},
                "W7": {"state": "active", "activation_commit": "2" * 40, "evidence": []},
            }
        }
        seen: list[list[str]] = []
        loc_seen: list[list[str]] = []
        def stat(_base, _target, paths):
            seen.append(paths)
            if not paths:
                if _target == "1" * 40:
                    budget = matrix["card_budgets"]["LS4"]
                    return budget["add"], budget["delete"]
                return 0, 0
            if any("LiveStreamRecovery" in path for path in paths):
                budget = matrix["card_budgets"]["LS4"]
                return budget["add"], budget["delete"]
            if any("LiveStreamManager" in path for path in paths):
                return 0, 1
            return 0, 0
        def loc(paths):
            loc_seen.append(paths)
            return 100
        GATE.validate_active_budgets(
            matrix, ledger, stat, loc, lambda commit: commit
        )
        self.assertTrue(any(any("LiveStreamRecovery.cpp" in path for path in paths) for paths in loc_seen))
        self.assertTrue(any(set(paths) == set(GATE.COORDINATOR_FILES["WebServer"]) for paths in seen))

    def test_binary_or_malformed_numstat_never_disappears_from_a_card_budget(self):
        with mock.patch.object(
            GATE.subprocess,
            "check_output",
            return_value="-\t-\tsrchybrid/payload.bin\n",
        ):
            with self.assertRaisesRegex(GATE.GateError, "binary or malformed"):
                GATE._numstat("a" * 40, "b" * 40, [])

    def test_typed_test_evidence_rejects_trivial_coverage_claims(self):
        coverage = "card:LT1"
        method = GATE._coverage_test_method(coverage)
        trivial = (
            "import unittest\n"
            "class Fixture(unittest.TestCase):\n"
            f"    def {method}(self): self.assertTrue(True)\n"
        ).encode()
        with self.assertRaisesRegex(GATE.GateError, "nontrivial assertion"):
            GATE._validate_test_source(trivial, [coverage])
        meaningful = (
            "import pathlib\nimport unittest\n"
            "class Fixture(unittest.TestCase):\n"
            f"    def {method}(self):\n"
            "        self.assertTrue(pathlib.Path(__file__).is_file())\n"
        ).encode()
        GATE._validate_test_source(meaningful, [coverage])

    def test_typed_test_evidence_rejects_skipped_or_unreachable_methods(self):
        coverage = "card:LT1"
        method = GATE._coverage_test_method(coverage)
        skipped = (
            "import unittest\n"
            "class Fixture(unittest.TestCase):\n"
            "    @unittest.skip('disabled')\n"
            f"    def {method}(self):\n"
            "        self.assertEqual(1, 2)\n"
        ).encode()
        with self.assertRaisesRegex(GATE.GateError, "may not be skipped"):
            GATE._validate_test_source(skipped, [coverage])
        after_return = (
            "import unittest\n"
            "class Fixture(unittest.TestCase):\n"
            f"    def {method}(self):\n"
            "        return\n"
            "        self.assertEqual(1, 2)\n"
        ).encode()
        with self.assertRaisesRegex(GATE.GateError, "reachable nontrivial"):
            GATE._validate_test_source(after_return, [coverage])
        false_branch = (
            "import unittest\n"
            "class Fixture(unittest.TestCase):\n"
            f"    def {method}(self):\n"
            "        if False:\n"
            "            self.assertEqual(1, 2)\n"
        ).encode()
        with self.assertRaisesRegex(GATE.GateError, "reachable nontrivial"):
            GATE._validate_test_source(false_branch, [coverage])

    def test_evidence_runner_requires_each_method_to_report_success(self):
        coverage = "card:LT1"
        method = GATE._coverage_test_method(coverage)
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            test_path = pathlib.Path(temporary) / "test_v92_m2a_runner.py"
            relative = test_path.relative_to(ROOT).as_posix()
            test_path.write_text(
                "import unittest\n"
                "class Fixture(unittest.TestCase):\n"
                f"    def {method}(self):\n"
                "        self.assertEqual(2 + 2, 4)\n",
                encoding="utf-8",
            )
            GATE._run_required_tests(relative, {coverage})
            test_path.write_text(
                "import unittest\n"
                "class Fixture(unittest.TestCase):\n"
                "    @unittest.skip('disabled')\n"
                f"    def {method}(self):\n"
                "        self.assertEqual(2 + 2, 4)\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                GATE.GateError, "failed|did not finish cleanly"
            ):
                GATE._run_required_tests(relative, {coverage})
            test_path.write_text(
                "import unittest\n"
                "class Fixture(unittest.TestCase):\n"
                f"    def {method}(self):\n"
                "        self.assertEqual(1, 2)\n"
                "        yield None\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                GATE.GateError, "defer execution|failed"
            ):
                GATE._validate_test_source(
                    test_path.read_bytes(), [coverage]
                )
                GATE._run_required_tests(relative, {coverage})
            test_path.write_text(
                "import unittest\n"
                "class Fixture(unittest.TestCase):\n"
                f"    def {method}(self):\n"
                "        self.assertEqual(1, 2)\n"
                f"Fixture.{method} = lambda self: None\n",
                encoding="utf-8",
            )
            GATE._validate_test_source(test_path.read_bytes(), [coverage])
            with self.assertRaisesRegex(
                GATE.GateError, "failed|did not finish cleanly"
            ):
                GATE._run_required_tests(relative, {coverage})
            test_path.write_text(
                "import unittest\n"
                "def neutralize(function):\n"
                "    return lambda self: None\n"
                "class Fixture(unittest.TestCase):\n"
                "    @neutralize\n"
                f"    def {method}(self):\n"
                "        self.assertEqual(1, 2)\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                GATE.GateError, "may not be decorated"
            ):
                GATE._validate_test_source(
                    test_path.read_bytes(), [coverage]
                )
            test_path.write_text(
                "import unittest\n"
                "class Fixture(unittest.TestCase):\n"
                "    def __init__(self, *args, **kwargs):\n"
                "        super().__init__(*args, **kwargs)\n"
                "        self.assertEqual = lambda *a, **k: None\n"
                f"    def {method}(self):\n"
                "        self.assertEqual(1, 2)\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                GATE.GateError, "failed|did not finish cleanly"
            ):
                GATE._run_required_tests(relative, {coverage})
            test_path.write_text(
                "import unittest\n"
                "class Fixture(unittest.TestCase):\n"
                "    def __init__(self, *args, **kwargs):\n"
                "        super().__init__('safe')\n"
                "    def safe(self):\n"
                "        self.assertEqual(1, 1)\n"
                "    def id(self):\n"
                f"        return 'Fixture.{method}'\n"
                f"    def {method}(self):\n"
                "        self.assertEqual(1, 2)\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                GATE.GateError, "failed|did not finish cleanly"
            ):
                GATE._run_required_tests(relative, {coverage})
            test_path.write_text(
                "import unittest\n"
                "class Fixture(unittest.TestCase):\n"
                "    def assertEqual(self, *args, **kwargs):\n"
                "        return None\n"
                f"    def {method}(self):\n"
                "        self.assertEqual(1, 2)\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                GATE.GateError, "failed|did not finish cleanly"
            ):
                GATE._run_required_tests(relative, {coverage})
            test_path.write_text(
                "import unittest\n"
                "Original = unittest.TestCase\n"
                "class Evil(Original):\n"
                "    def run(self, result=None):\n"
                "        result.addSuccess(self)\n"
                "unittest.TestCase = Evil\n"
                "unittest.case.TestCase = Evil\n"
                "class Fixture(unittest.TestCase):\n"
                f"    def {method}(self):\n"
                "        self.assertEqual(1, 2)\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                GATE.GateError, "failed|did not finish cleanly"
            ):
                GATE._run_required_tests(relative, {coverage})
            test_path.write_text(
                "import unittest\n"
                "_original_run = unittest.TestCase.run\n"
                "def _forge_success(self, result=None):\n"
                "    result.addSuccess(self)\n"
                "unittest.TestCase.run = _forge_success\n"
                "class Fixture(unittest.TestCase):\n"
                f"    def {method}(self):\n"
                "        self.assertEqual(1, 2)\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                GATE.GateError, "failed|did not finish cleanly"
            ):
                GATE._run_required_tests(relative, {coverage})

    def test_parent_binding_route_rejects_constant_false_branches(self):
        previous = (
            "bool Parent::Run() {\n"
            "  return true;\n"
            "}\n"
        )
        live = (
            "bool Parent::Run() {\n"
            "  m_handle = M2A_BIND_X(M2AParentPort{this});\n"
            "  return true;\n"
            "}\n"
        )
        dead = (
            "bool Parent::Run() {\n"
            "  if (false) {\n"
            "    m_handle = M2A_BIND_X(M2AParentPort{this});\n"
            "  }\n"
            "  return true;\n"
            "}\n"
        )
        unbraced = (
            "bool Parent::Run() {\n"
            "  if (0) m_handle = "
            "M2A_BIND_X(M2AParentPort{this});\n"
            "  return true;\n"
            "}\n"
        )
        false_variants = (
            "0u",
            "!true",
            "std::false_type::value",
        )
        self.assertTrue(GATE._preexisting_parent_route(
            live, previous, ("Parent",), live.index("m_handle")
        ))
        chained_previous = (
            "bool Parent::Run() {\n"
            "  m_m2a_binding_111 = "
            "M2A_BIND_OLD(M2AParentPort{this});\n"
            "  return true;\n"
            "}\n"
        )
        chained = (
            "bool Parent::Run() {\n"
            "  m_m2a_binding_111 = "
            "M2A_BIND_OLD(M2AParentPort{this});\n"
            "  m_m2a_binding_222 = "
            "M2A_BIND_NEW(M2AParentPort{this});\n"
            "  return true;\n"
            "}\n"
        )
        self.assertTrue(GATE._preexisting_parent_route(
            chained, chained_previous, ("Parent",),
            chained.index("m_m2a_binding_222")
        ))
        sources = [dead, unbraced]
        sources.extend(
            (
                "bool Parent::Run() {\n"
                f"  if ({condition}) "
                "m_handle = M2A_BIND_X(M2AParentPort{this});\n"
                "  return true;\n"
                "}\n"
            )
            for condition in false_variants
        )
        for source in sources:
            self.assertFalse(GATE._preexisting_parent_route(
                source,
                previous,
                ("Parent",),
                source.index("m_handle"),
            ))
        constructor = (
            "Parent::Parent():m_handle(M2AAssignmentPolicy::RetainExisting){"
            "m_handle=M2A_BIND_X(M2AParentPort{this});}\n"
        )
        self.assertTrue(GATE._new_default_parent_constructor_route(
            constructor, previous, "Parent", "M2A_BIND_X", "m_handle",
            constructor.index("m_handle=M2A_BIND_X"),
        ))
        self.assertFalse(GATE._new_default_parent_constructor_route(
            constructor.replace(";}", "; SideEffect();}"), previous,
            "Parent", "M2A_BIND_X", "m_handle",
            constructor.index("m_handle=M2A_BIND_X"),
        ))

    def test_local_handle_routes_require_consecutive_fail_closed_pairs(self):
        previous = "void Parent::Run() { return; }\n"
        first = (
            "M2AModuleHandle first = "
            "M2A_BIND_W8_1111111111(M2AParentPort{this}); "
            "if (!first) return;"
        )
        target = (
            "M2AModuleHandle target = "
            "M2A_BIND_W9_2222222222(M2AParentPort{this}); "
            "if (!target) return;"
        )
        current = f"void Parent::Run() {{ {first} {target} Work(); }}\n"
        start = current.index("M2AModuleHandle target")
        self.assertTrue(GATE._preexisting_local_handle_route(
            current, previous, ("Parent",),
            "M2A_BIND_W9_2222222222", start,
        ))
        first_start = current.index("M2AModuleHandle first")
        self.assertTrue(GATE._preexisting_local_handle_route(
            current, previous, ("Parent",),
            "M2A_BIND_W8_1111111111", first_start,
        ))
        first_without_guard = current.replace("if (!first) return;", "")
        self.assertFalse(GATE._preexisting_local_handle_route(
            first_without_guard, previous, ("Parent",),
            "M2A_BIND_W8_1111111111",
            first_without_guard.index("M2AModuleHandle first"),
        ))
        returning_value = current.replace(
            "if (!first) return;", "if (!first) return false;"
        )
        self.assertTrue(GATE._preexisting_local_handle_route(
            returning_value, previous, ("Parent",),
            "M2A_BIND_W8_1111111111",
            returning_value.index("M2AModuleHandle first"),
        ))
        for invalid in (
            current.replace(f"{first} {target}", f"{first} Prepare(); {target}"),
            current.replace("if (!first) return;", "if (!other) return;"),
            current.replace("if (!first) return;", ""),
            current.replace("M2A_BIND_W8_1111111111", "M2A_BIND_W8_BAD"),
            current.replace("M2AParentPort{this}", "M2AParentPort{other}", 1),
        ):
            invalid_start = invalid.index("M2AModuleHandle target")
            self.assertFalse(GATE._preexisting_local_handle_route(
                invalid, previous, ("Parent",),
                "M2A_BIND_W9_2222222222", invalid_start,
            ))

    def test_web_static_thread_route_is_exact_and_fail_closed(self):
        previous = (
            "CString CWebServer::_Get(const ThreadData &Data) { "
            "return CString(); }"
        )
        binding = (
            "M2AModuleHandle binding = "
            "M2A_BIND_X(M2AParentPort{Data.pThis});"
        )
        current = previous.replace("{ ", "{ " + binding + " ")
        header = (
            "class CWebServer { private: static CString "
            "_Get(const ThreadData &Data); };"
        )
        route = GATE._preexisting_web_static_thread_route
        self.assertTrue(route(
            current, previous, header, header, "M2A_BIND_X", "_Get"
        ))
        bad = (
            (current.replace("{ " + binding, "{ Prepare(); " + binding), previous, header, header),
            (current.replace(binding, "if (false) { " + binding + " }"), previous, header, header),
            (current, "", header, header),
            (current.replace("CWebServer", "Other"), previous, header, header),
            (current.replace("ThreadData", "OtherData"), previous, header, header),
            (current.replace("&Data", "&input"), previous, header, header),
            (current.replace("Data.pThis", "Data.pSocket"), previous, header, header),
            (current.replace("M2A_BIND_X", "M2A_BIND_Y"), previous, header, header),
            (current, previous, header.replace("static ", ""), header),
            (current, previous, header, header.replace("static ", "")),
        )
        for values in bad:
            self.assertFalse(route(
                *values, "M2A_BIND_X", "_Get"
            ))

    def test_real_git_activation_sequence_b_a_h_and_negative_cases(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = pathlib.Path(temporary)
            def git(*args):
                return subprocess.check_output(
                    ["git", *args], cwd=repo, text=True
                ).strip()
            git("init", "-q")
            git("config", "user.name", "M2A fixture")
            git("config", "user.email", "m2a@example.invalid")
            git("config", "core.autocrlf", "false")
            source_dir = repo / "srchybrid"
            source_dir.mkdir()
            coordinator = source_dir / "LiveTunnel.cpp"
            header = source_dir / "LiveTunnel.h"
            coordinator.write_text("one\ntwo\nthree\nfour\nfive\nsix\n", encoding="utf-8")
            header.write_text("header\n", encoding="utf-8")
            ledger_path = repo / "docs/architecture/mod52_migration_activation_ledger_v1.json"
            ledger_path.parent.mkdir(parents=True)
            planned_ledger = {
                "cards": {
                    "LT1": {
                        "state": "planned",
                        "activation_commit": None,
                        "evidence": [],
                    },
                    "LT2": {
                        "state": "planned",
                        "activation_commit": None,
                        "evidence": [],
                    },
                }
            }
            ledger_path.write_text(
                json.dumps(planned_ledger), encoding="utf-8"
            )
            git("add", "."); git("commit", "-q", "-m", "B baseline")
            baseline_commit = git("rev-parse", "HEAD")

            coordinator.write_text("one\ntwo\n", encoding="utf-8")
            module_cpp = source_dir / "ModuleX.cpp"
            module_h = source_dir / "ModuleX.h"
            module_cpp.write_text("implementation\n", encoding="utf-8")
            module_h.write_text("interface\n", encoding="utf-8")
            git("add", "."); git("commit", "-q", "-m", "A implementation")
            activation_commit = git("rev-parse", "HEAD")
            evidence_sha = hashlib.sha256(
                GATE._git_blob(
                    activation_commit, "srchybrid/ModuleX.cpp", repo
                )
            ).hexdigest()

            state = {
                "state": "active",
                "activation_commit": activation_commit,
                "evidence": [{
                    "path": "srchybrid/ModuleX.cpp",
                    "sha256": evidence_sha,
                    "commit": activation_commit,
                }],
            }
            ledger_path.write_text(
                json.dumps({
                    "cards": {
                        "LT1": state,
                        "LT2": planned_ledger["cards"]["LT2"],
                    }
                }),
                encoding="utf-8",
            )
            git("add", "."); git("commit", "-q", "-m", "H attestation")
            attestation_commit = git("rev-parse", "HEAD")
            paths = ["srchybrid/ModuleX.cpp", "srchybrid/ModuleX.h"]
            GATE.validate_source_activation(
                state, paths, repo, baseline_commit, "HEAD"
            )
            GATE.validate_activation_provenance(
                state,
                paths,
                repo,
                baseline_commit,
                "HEAD",
                "LT1",
                "docs/architecture/mod52_migration_activation_ledger_v1.json",
            )
            out_of_order = copy.deepcopy(state)
            with self.assertRaisesRegex(GATE.GateError, "prerequisite was not previously active"):
                GATE.validate_activation_provenance(
                    out_of_order,
                    [],
                    repo,
                    baseline_commit,
                    "HEAD",
                    "LT2",
                    "docs/architecture/mod52_migration_activation_ledger_v1.json",
                    ["LT1"],
                )
            GATE.validate_existing_module_activations(
                [{"name": "ModuleX", "card": "LT1"}],
                {"cards": {"LT1": state}},
                {
                    "ModuleX": {
                        "implementation_files": ["srchybrid/ModuleX.cpp"],
                        "interface_files": ["srchybrid/ModuleX.h"],
                    }
                },
                repo,
                baseline_commit,
                "HEAD",
            )
            matrix = {
                "additional_modules": [{
                    "name": "ModuleX", "card": "LT1",
                    "budget": {"module_loc": 10},
                }],
                "existing_modules": [],
                "card_budgets": {
                    "LT1": {
                        "add": 2, "delete": 4, "net": 0,
                        "coordinator": "LiveTunnel",
                        "facade_add_max": 0,
                        "reduction_required": True,
                    }
                },
            }
            ledger = {"cards": {"LT1": state}}
            GATE.validate_active_budgets(
                matrix,
                ledger,
                lambda base, target, governed: GATE._numstat(
                    base, target, governed, repo
                ),
                lambda governed: sum(
                    len((repo / path).read_text(encoding="utf-8").splitlines())
                    for path in governed
                ),
                lambda commit: GATE._activation_parent(commit, repo),
            )

            planned = {
                "state": "planned", "activation_commit": None, "evidence": []
            }
            GATE.validate_source_activation(
                planned, ["srchybrid/NotCreated.cpp"], repo, baseline_commit
            )
            (source_dir / "NotCreated.cpp").write_text("premature\n", encoding="utf-8")
            with self.assertRaisesRegex(GATE.GateError, "before card activation"):
                GATE.validate_source_activation(
                    planned, ["srchybrid/NotCreated.cpp"], repo, baseline_commit
                )
            module_cpp.write_text("modified after A\n", encoding="utf-8")
            with self.assertRaisesRegex(GATE.GateError, "differs from its activation commit"):
                GATE.validate_source_activation(
                    state, paths, repo, baseline_commit, "HEAD"
                )
            with self.assertRaisesRegex(GATE.GateError, "differs from its activation commit"):
                GATE.validate_existing_module_activations(
                    [{"name": "ModuleX", "card": "LT1"}],
                    {"cards": {"LT1": state}},
                    {
                        "ModuleX": {
                            "implementation_files": ["srchybrid/ModuleX.cpp"],
                            "interface_files": ["srchybrid/ModuleX.h"],
                        }
                    },
                    repo,
                    baseline_commit,
                    "HEAD",
                )
            module_cpp.write_text("implementation\n", encoding="utf-8")
            side = git("commit-tree", f"{baseline_commit}^{{tree}}", "-p", baseline_commit, "-m", "side")
            nonancestor = copy.deepcopy(state)
            nonancestor["activation_commit"] = side
            nonancestor["evidence"] = []
            with self.assertRaisesRegex(GATE.GateError, "not an ancestor of HEAD"):
                GATE.validate_activation_provenance(
                    nonancestor, [], repo, baseline_commit, "HEAD"
                )
            git("commit", "--allow-empty", "-q", "-m", "after attestation")
            active_at_a = copy.deepcopy(state)
            active_at_a["activation_commit"] = attestation_commit
            active_at_a["evidence"] = [{
                "path": "srchybrid/ModuleX.cpp",
                "sha256": hashlib.sha256(
                    GATE._git_blob(
                        attestation_commit, "srchybrid/ModuleX.cpp", repo
                    )
                ).hexdigest(),
                "commit": attestation_commit,
            }]
            with self.assertRaisesRegex(GATE.GateError, "not continuously planned|must not modify"):
                GATE.validate_activation_provenance(
                    active_at_a,
                    [],
                    repo,
                    baseline_commit,
                    "HEAD",
                    "LT1",
                    "docs/architecture/mod52_migration_activation_ledger_v1.json",
                )
            premature_cpp = source_dir / "Premature.cpp"
            premature_h = source_dir / "Premature.h"
            premature_cpp.write_text("implementation\n", encoding="utf-8")
            premature_h.write_text("interface\n", encoding="utf-8")
            git("add", "srchybrid/Premature.cpp", "srchybrid/Premature.h")
            git("commit", "-q", "-m", "P premature planned source")
            coordinator.write_text("one\n", encoding="utf-8")
            git("add", "srchybrid/LiveTunnel.cpp")
            git("commit", "-q", "-m", "A later coordinator reduction")
            late_activation = git("rev-parse", "HEAD")
            git("commit", "--allow-empty", "-q", "-m", "H later attestation")
            premature_state = {
                "state": "active",
                "activation_commit": late_activation,
                "evidence": [{
                    "path": "srchybrid/Premature.cpp",
                    "sha256": hashlib.sha256(
                        GATE._git_blob(
                            late_activation, "srchybrid/Premature.cpp", repo
                        )
                    ).hexdigest(),
                    "commit": late_activation,
                }],
            }
            with self.assertRaisesRegex(GATE.GateError, "existed before its activation commit"):
                GATE.validate_source_activation(
                    premature_state,
                    ["srchybrid/Premature.cpp", "srchybrid/Premature.h"],
                    repo,
                    baseline_commit,
                    "HEAD",
                )

    def test_first_activation_runs_end_to_end_through_mod04_and_m2a(self):
        fixture_relpaths = [
            "tools/architecture/verify_mod04_architecture_gate.py",
            "tools/architecture/verify_m2a00_migration_ratchet.py",
            "docs/architecture/mod03_ownership_layering_contract_v2.json",
            "docs/architecture/mod04_architecture_gate_catalog_v2.json",
            "docs/architecture/mod52_migration_activation_ledger_v1.json",
            "docs/architecture/mod52_migration_baseline_v1.json",
            "docs/architecture/mod52_migration_contract_v1.json",
            "docs/architecture/mod52_migration_matrix_v1.json",
            "srchybrid/M2ABindingPort.cpp",
            "srchybrid/M2ABindingPort.h",
            "srchybrid/LiveTunnelGatewayStorePort.h",
            "srchybrid/LiveTunnelSourcePublisherPort.h",
            "srchybrid/LiveTunnelStreamFlowPort.h", "srchybrid/LiveTunnelOriginPort.h", "srchybrid/LiveTunnelBulkStatePort.h", "srchybrid/LiveTunnelBulkFacade.inl", "srchybrid/LiveTunnelSearchPort.h", "srchybrid/LiveTunnelSearchFacade.inl", "srchybrid/LiveTunnelCoordinatorPort.h", "srchybrid/LiveTunnelCoordinatorMethods.inl",
            "srchybrid/LiveTunnelScheduler.cpp",
            "srchybrid/emule.vcxproj",
        ]
        with tempfile.TemporaryDirectory() as temporary:
            worktree = pathlib.Path(temporary) / "worktree"
            lt1_state = self.ledger["cards"]["LT1"]
            fixture_base = (
                GATE._activation_parent(lt1_state["activation_commit"])
                if lt1_state["state"] == "active" else "HEAD"
            )
            subprocess.check_call(
                ["git", "worktree", "add", "--detach", str(worktree), fixture_base],
                cwd=ROOT,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                def git(*args):
                    return subprocess.check_output(
                        ["git", *args], cwd=worktree, text=True
                    ).strip()
                def add_and_commit(message, paths):
                    subprocess.check_call(
                        ["git", "-c", "core.autocrlf=false", "add", "--", *paths],
                        cwd=worktree,
                    )
                    subprocess.check_call(
                        ["git", "commit", "-q", "-m", message], cwd=worktree
                    )
                    return git("rev-parse", "HEAD")
                for relative in fixture_relpaths:
                    target = worktree / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(ROOT / relative, target)
                fixture_ledger_path = worktree / (
                    "docs/architecture/mod52_migration_activation_ledger_v1.json"
                )
                fixture_ledger = json.loads(
                    fixture_ledger_path.read_text(encoding="utf-8"))
                for card in fixture_ledger["cards"].values():
                    card.update({
                        "state": "planned",
                        "activation_commit": None,
                        "evidence": [],
                    })
                fixture_ledger_path.write_text(
                    json.dumps(fixture_ledger, indent=2) + "\n", encoding="utf-8")
                gate_baseline_commit = add_and_commit(
                    "B M2A gate fixture", fixture_relpaths
                )

                coordinator_path = "srchybrid/LiveTunnel.cpp"
                coordinator_header_path = "srchybrid/LiveTunnel.h"
                baseline_source = subprocess.check_output(
                    ["git", "show", f"HEAD:{coordinator_path}"], cwd=worktree
                )
                baseline_header = subprocess.check_output(
                    ["git", "show", f"HEAD:{coordinator_header_path}"],
                    cwd=worktree,
                )
                fixture_matrix = json.loads(
                    (
                        worktree
                        / "docs/architecture/mod52_migration_matrix_v1.json"
                    ).read_text(encoding="utf-8")
                )
                lt1_module = next(
                    item
                    for item in fixture_matrix["additional_modules"]
                    if item["name"] == "LiveTunnelReleaseGate"
                )
                binding_marker = GATE._binding_marker(lt1_module)
                lt1_covers = sorted(
                    GATE._card_test_requirements(fixture_matrix)["LT1"]
                )
                lt1_fields = next(
                    item["fields"]
                    for item in fixture_matrix["field_matrix"]["LiveTunnel"]["transfers"]
                    if item["card"] == "LT1"
                )
                reduced_header = b"".join(
                    line
                    for line in baseline_header.splitlines(keepends=True)
                    if not any(
                        re.search(
                            rb"\b" + field.encode() + rb"\b", line
                        )
                        for field in lt1_fields
                    )
                )
                reduced = b"".join(
                    line
                    for line in baseline_source.splitlines(keepends=True)[751:]
                    if not any(
                        re.search(
                            rb"\b" + field.encode() + rb"\b", line
                        )
                        for field in lt1_fields
                    )
                )
                (worktree / coordinator_path).write_bytes(reduced)
                (worktree / coordinator_header_path).write_bytes(
                    reduced_header
                )
                module_cpp_path = "srchybrid/LiveTunnelReleaseGate.cpp"
                module_h_path = "srchybrid/LiveTunnelReleaseGate.h"
                parent_path = "srchybrid/LiveTunnelScheduler.cpp"
                parent_header_path = "srchybrid/LiveTunnelScheduler.h"
                baseline_parent = subprocess.check_output(
                    ["git", "show", f"HEAD:{parent_path}"], cwd=worktree
                )
                baseline_parent_header = subprocess.check_output(
                    ["git", "show", f"HEAD:{parent_header_path}"],
                    cwd=worktree,
                )
                test_source_path = "tests/test_v92_m2a_lt1_fixture.py"
                binding_member = GATE._binding_member(lt1_module)
                (worktree / module_cpp_path).write_bytes(
                    (
                        '#include "LiveTunnelReleaseGate.h"\n'
                        "namespace eSELive {\n"
                        f"M2AModuleHandle {binding_marker}("
                        "const M2AParentPort& parent) {\n"
                        "  return MakeM2AModuleHandle(new "
                        "LiveTunnelReleaseGate(parent));\n"
                        "}\n"
                        "} // namespace eSELive\n"
                    ).encode()
                )
                (worktree / module_h_path).write_bytes(
                    (
                        '#pragma once\n#include "M2ABindingPort.h"\n'
                        "namespace eSELive {\n"
                        "class LiveTunnelReleaseGate {\n"
                        "public:\n"
                        "  explicit LiveTunnelReleaseGate("
                        "const M2AParentPort&) {}\n"
                        "private:\n"
                        + "".join(
                            f"  int {field};\n" for field in lt1_fields
                        )
                        + "};\n"
                        f"M2AModuleHandle {binding_marker}("
                        "const M2AParentPort&);\n"
                        "} // namespace eSELive\n"
                    ).encode()
                )
                (worktree / parent_path).write_bytes(
                    baseline_parent.replace(
                        b"namespace eSELive {\n",
                        (
                            "namespace eSELive {\n"
                            f"extern M2AModuleHandle {binding_marker}("
                            "const M2AParentPort&);\n"
                        ).encode(),
                        1,
                    ).replace(
                        b"bool LiveTunnelScheduler::Enqueue("
                        b"LiveDeferredWork work)\n{\n",
                        (
                            "bool LiveTunnelScheduler::Enqueue("
                            "LiveDeferredWork work)\n{\n"
                            f"    {binding_member} = {binding_marker}("
                            "M2AParentPort{this});\n"
                        ).encode(),
                        1,
                    )
                )
                (worktree / parent_header_path).write_bytes(
                    baseline_parent_header.replace(
                        b'#include "LiveBulk.h"\n',
                        b'#include "LiveBulk.h"\n'
                        b'#include "M2ABindingPort.h"\n',
                        1,
                    ).replace(
                        b"private:\n",
                        (
                            "private:\n"
                            f"    M2AModuleHandle {binding_member};\n"
                        ).encode(),
                        1,
                    )
                )
                test_lines = [
                    "import pathlib",
                    "import unittest",
                    "",
                    "ROOT = pathlib.Path(__file__).resolve().parents[1]",
                    "",
                    "class LT1Fixture(unittest.TestCase):",
                ]
                for coverage in lt1_covers:
                    method = GATE._coverage_test_method(coverage)
                    test_lines.append(f"    def {method}(self):")
                    if coverage.startswith("binding:"):
                        test_lines.append(
                            f"        self.assertIn('{binding_marker}', "
                            "(ROOT / 'srchybrid/LiveTunnelScheduler.cpp').read_text(encoding='utf-8'))"
                        )
                    elif coverage.startswith("fields:"):
                        test_lines.append(
                            f"        self.assertNotIn('{lt1_fields[0]}', "
                            "(ROOT / 'srchybrid/LiveTunnel.cpp').read_text(encoding='utf-8'))"
                        )
                        test_lines.append(
                            f"        self.assertIn('{lt1_fields[0]}', "
                            "(ROOT / 'srchybrid/LiveTunnelReleaseGate.h').read_text(encoding='utf-8'))"
                        )
                    elif coverage.startswith("module:"):
                        test_lines.append(
                            "        self.assertIn('class LiveTunnelReleaseGate', "
                            "(ROOT / 'srchybrid/LiveTunnelReleaseGate.h').read_text(encoding='utf-8'))"
                        )
                    else:
                        test_lines.append(
                            "        self.assertTrue((ROOT / "
                            "'srchybrid/LiveTunnelReleaseGate.cpp').is_file())"
                        )
                (worktree / test_source_path).write_bytes(
                    ("\n".join(test_lines) + "\n").encode()
                )
                activation_commit = add_and_commit(
                    "A LT1 implementation",
                    [
                        coordinator_path,
                        coordinator_header_path,
                        module_cpp_path,
                        module_h_path,
                        parent_path,
                        parent_header_path,
                        test_source_path,
                    ],
                )

                ledger_path = worktree / "docs/architecture/mod52_migration_activation_ledger_v1.json"
                ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
                evidence_blob = subprocess.check_output(
                    ["git", "show", f"{activation_commit}:{test_source_path}"],
                    cwd=worktree,
                )
                ledger["cards"]["LT1"] = {
                    "state": "active",
                    "activation_commit": activation_commit,
                    "evidence": [{
                        "kind": "test_source",
                        "path": test_source_path,
                        "sha256": hashlib.sha256(evidence_blob).hexdigest(),
                        "commit": activation_commit,
                        "covers": lt1_covers,
                    }],
                }
                ledger_path.write_text(
                    json.dumps(ledger, indent=2) + "\n", encoding="utf-8"
                )
                add_and_commit(
                    "H attest LT1",
                    ["docs/architecture/mod52_migration_activation_ledger_v1.json"],
                )
                for verifier in (
                    "tools/architecture/verify_mod04_architecture_gate.py",
                    "tools/architecture/verify_m2a00_migration_ratchet.py",
                ):
                    completed = subprocess.run(
                        [sys.executable, verifier, "--verify"],
                        cwd=worktree,
                        text=True,
                        capture_output=True,
                        check=False,
                    )
                    self.assertEqual(
                        completed.returncode, 0,
                        completed.stdout + completed.stderr,
                    )
                (worktree / coordinator_path).write_bytes(baseline_source)
                add_and_commit(
                    "J forbidden coordinator restoration", [coordinator_path]
                )
                restored = subprocess.run(
                    [
                        sys.executable,
                        "tools/architecture/verify_m2a00_migration_ratchet.py",
                        "--verify",
                    ],
                    cwd=worktree,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertNotEqual(restored.returncode, 0)
                self.assertTrue(
                    any(
                        marker in restored.stdout + restored.stderr
                        for marker in (
                            "active M2A evidence test failed",
                            "active M2A evidence test did not finish cleanly",
                            "active card retains transferred field token",
                            "active coordinator LOC regressed after A",
                        )
                    ),
                    restored.stdout + restored.stderr,
                )

                subprocess.check_call(
                    ["git", "switch", "--detach", gate_baseline_commit],
                    cwd=worktree,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                bad_baseline_source = subprocess.check_output(
                    ["git", "show", f"HEAD:{coordinator_path}"], cwd=worktree
                )
                (worktree / coordinator_path).write_bytes(
                    b"".join(
                        line
                        for line in bad_baseline_source.splitlines(
                            keepends=True
                        )[751:]
                        if not any(
                            re.search(
                                rb"\b" + field.encode() + rb"\b", line
                            )
                            for field in lt1_fields
                        )
                    )
                )
                (worktree / coordinator_header_path).write_bytes(
                    reduced_header
                )
                (worktree / module_cpp_path).write_bytes(
                    (
                        '#include "LiveTunnelReleaseGate.h"\n'
                        '#include "LiveTunnel.h"\n'
                        "namespace eSELive {\n"
                        f"M2AModuleHandle {binding_marker}("
                        "const M2AParentPort& parent) {\n"
                        "  return MakeM2AModuleHandle(new "
                        "LiveTunnelReleaseGate(parent));\n"
                        "}\n"
                        "} // namespace eSELive\n"
                    ).encode()
                )
                (worktree / module_h_path).write_bytes(
                    (
                        '#pragma once\n#include "M2ABindingPort.h"\n'
                        "namespace eSELive {\n"
                        "class LiveTunnelReleaseGate {\n"
                        "public:\n"
                        "  explicit LiveTunnelReleaseGate("
                        "const M2AParentPort&) {}\n"
                        "private:\n"
                        + "".join(
                            f"  int {field};\n" for field in lt1_fields
                        )
                        + "};\n"
                        f"M2AModuleHandle {binding_marker}("
                        "const M2AParentPort&);\n"
                        "} // namespace eSELive\n"
                    ).encode()
                )
                (worktree / parent_path).write_bytes(
                    baseline_parent.replace(
                        b"namespace eSELive {\n",
                        (
                            "namespace eSELive {\n"
                            f"extern M2AModuleHandle {binding_marker}("
                            "const M2AParentPort&);\n"
                        ).encode(),
                        1,
                    ).replace(
                        b"bool LiveTunnelScheduler::Enqueue("
                        b"LiveDeferredWork work)\n{\n",
                        (
                            "bool LiveTunnelScheduler::Enqueue("
                            "LiveDeferredWork work)\n{\n"
                            f"    {binding_member} = {binding_marker}("
                            "M2AParentPort{this});\n"
                        ).encode(),
                        1,
                    )
                )
                (worktree / parent_header_path).write_bytes(
                    baseline_parent_header.replace(
                        b'#include "LiveBulk.h"\n',
                        b'#include "LiveBulk.h"\n'
                        b'#include "M2ABindingPort.h"\n',
                        1,
                    ).replace(
                        b"private:\n",
                        (
                            "private:\n"
                            f"    M2AModuleHandle {binding_member};\n"
                        ).encode(),
                        1,
                    )
                )
                (worktree / test_source_path).write_bytes(
                    ("\n".join(test_lines) + "\n").encode()
                )
                bad_activation = add_and_commit(
                    "A2 forbidden reverse include",
                    [
                        coordinator_path,
                        coordinator_header_path,
                        module_cpp_path,
                        module_h_path,
                        parent_path,
                        parent_header_path,
                        test_source_path,
                    ],
                )
                ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
                bad_blob = subprocess.check_output(
                    ["git", "show", f"{bad_activation}:{test_source_path}"],
                    cwd=worktree,
                )
                ledger["cards"]["LT1"] = {
                    "state": "active",
                    "activation_commit": bad_activation,
                    "evidence": [{
                        "kind": "test_source",
                        "path": test_source_path,
                        "sha256": hashlib.sha256(bad_blob).hexdigest(),
                        "commit": bad_activation,
                        "covers": lt1_covers,
                    }],
                }
                ledger_path.write_text(
                    json.dumps(ledger, indent=2) + "\n", encoding="utf-8"
                )
                add_and_commit(
                    "H2 attest forbidden fixture",
                    ["docs/architecture/mod52_migration_activation_ledger_v1.json"],
                )
                rejected = subprocess.run(
                    [
                        sys.executable,
                        "tools/architecture/verify_m2a00_migration_ratchet.py",
                        "--verify",
                    ],
                    cwd=worktree,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertNotEqual(rejected.returncode, 0)
                self.assertIn(
                    "reverse coordinator include",
                    rejected.stdout + rejected.stderr,
                )
            finally:
                subprocess.run(
                    ["git", "worktree", "remove", "--force", str(worktree)],
                    cwd=ROOT,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )

    def test_prerequisite_must_precede_a_and_belong_to_its_history(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = pathlib.Path(temporary)
            def git(*args):
                return subprocess.check_output(
                    ["git", *args], cwd=repo, text=True
                ).strip()
            git("init", "-q")
            git("config", "user.name", "M2A prerequisite fixture")
            git("config", "user.email", "m2a@example.invalid")
            git("config", "core.autocrlf", "false")
            ledger_rel = "docs/architecture/mod52_migration_activation_ledger_v1.json"
            ledger_path = repo / ledger_rel
            ledger_path.parent.mkdir(parents=True)
            planned = {
                "state": "planned", "activation_commit": None, "evidence": []
            }
            ledger_path.write_text(
                json.dumps({"cards": {"LT1": planned, "LT2": planned}}),
                encoding="utf-8",
            )
            git("add", "."); git("commit", "-q", "-m", "B")
            baseline = git("rev-parse", "HEAD")
            git("commit", "--allow-empty", "-q", "-m", "P prerequisite implementation")
            prerequisite_activation = git("rev-parse", "HEAD")
            prerequisite_state = {
                "state": "active",
                "activation_commit": prerequisite_activation,
                "evidence": [{
                    "path": ledger_rel,
                    "sha256": hashlib.sha256(
                        GATE._git_blob(
                            prerequisite_activation, ledger_rel, repo
                        )
                    ).hexdigest(),
                    "commit": prerequisite_activation,
                }],
            }
            ledger_path.write_text(
                json.dumps({
                    "cards": {"LT1": prerequisite_state, "LT2": planned}
                }),
                encoding="utf-8",
            )
            git("add", "."); git("commit", "-q", "-m", "S simultaneous prerequisite")
            simultaneous_a = git("rev-parse", "HEAD")
            simultaneous_state = {
                "state": "active",
                "activation_commit": simultaneous_a,
                "evidence": [{
                    "path": ledger_rel,
                    "sha256": hashlib.sha256(
                        GATE._git_blob(simultaneous_a, ledger_rel, repo)
                    ).hexdigest(),
                    "commit": simultaneous_a,
                }],
            }
            ledger_path.write_text(
                json.dumps({
                    "cards": {
                        "LT1": prerequisite_state,
                        "LT2": simultaneous_state,
                    }
                }),
                encoding="utf-8",
            )
            git("add", "."); git("commit", "-q", "-m", "H2")
            with self.assertRaisesRegex(GATE.GateError, "must not modify|not previously active"):
                GATE.validate_activation_provenance(
                    simultaneous_state,
                    [],
                    repo,
                    baseline,
                    "HEAD",
                    "LT2",
                    ledger_rel,
                    ["LT1"],
                )

            side = git(
                "commit-tree",
                f"{baseline}^{{tree}}",
                "-p",
                baseline,
                "-m",
                "unrelated prerequisite",
            )
            forged_prerequisite = copy.deepcopy(prerequisite_state)
            forged_prerequisite["activation_commit"] = side
            forged_prerequisite["evidence"][0]["commit"] = side
            ledger_path.write_text(
                json.dumps({
                    "cards": {"LT1": forged_prerequisite, "LT2": planned}
                }),
                encoding="utf-8",
            )
            git("add", "."); git("commit", "-q", "-m", "F forged prerequisite")
            git("commit", "--allow-empty", "-q", "-m", "A3 dependent implementation")
            dependent_a = git("rev-parse", "HEAD")
            dependent_state = {
                "state": "active",
                "activation_commit": dependent_a,
                "evidence": [{
                    "path": ledger_rel,
                    "sha256": hashlib.sha256(
                        GATE._git_blob(dependent_a, ledger_rel, repo)
                    ).hexdigest(),
                    "commit": dependent_a,
                }],
            }
            ledger_path.write_text(
                json.dumps({
                    "cards": {
                        "LT1": forged_prerequisite,
                        "LT2": dependent_state,
                    }
                }),
                encoding="utf-8",
            )
            git("add", "."); git("commit", "-q", "-m", "H3")
            with self.assertRaisesRegex(GATE.GateError, "not previously active"):
                GATE.validate_activation_provenance(
                    dependent_state,
                    [],
                    repo,
                    baseline,
                    "HEAD",
                    "LT2",
                    ledger_rel,
                    ["LT1"],
                )

    def test_active_source_include_cycle_and_undeclared_edge_are_rejected(self):
        ledger = copy.deepcopy(self.ledger)
        ledger["cards"]["LT4"] = {"state":"active","activation_commit":"0" * 40,"evidence":["reviewed-test"]}
        sources = {
            "srchybrid/LiveTunnelSourcePublisher.cpp": b'#include "LiveTunnelTicketPolicy.h"\n',
            "srchybrid/LiveTunnelSourcePublisher.h": b"",
            "srchybrid/LiveTunnelTicketPolicy.cpp": b"",
            "srchybrid/LiveTunnelTicketPolicy.h": b'#include "LiveTunnelSourcePublisher.h"\n',
        }
        cyclic_matrix = copy.deepcopy(self.matrix)
        next(
            item for item in cyclic_matrix["additional_modules"]
            if item["name"] == "LiveTunnelTicketPolicy"
        )["dependencies"] = ["LiveTunnelSourcePublisher"]
        include_errors = (GATE.GateError, GATE.mod04.GateError)
        with self.assertRaisesRegex(include_errors, "dependency SCC cycle|combined include SCC"):
            GATE.validate_active_include_contract(cyclic_matrix, ledger, sources)
        sources["srchybrid/LiveTunnelTicketPolicy.h"] = b""
        sources["srchybrid/LiveTunnelSourcePublisher.cpp"] = b""
        sources["srchybrid/LiveTunnelTicketPolicy.cpp"] = b'#include "LiveTunnelSourcePublisher.h"\n'
        with self.assertRaisesRegex(include_errors, "declared direct dependency drift|differ from declared catalogue"):
            GATE.validate_active_include_contract(self.matrix, ledger, sources)
        sources["srchybrid/LiveTunnelTicketPolicy.cpp"] = b'#include "LiveTunnel.h"\n'
        sources["srchybrid/LiveTunnelSourcePublisher.cpp"] = b'#include "LiveTunnelTicketPolicy.h"\n'
        with self.assertRaisesRegex(include_errors, "reverse coordinator include"):
            GATE.validate_active_include_contract(self.matrix, ledger, sources)
        for robust_form in (
            b'%:include "LiveTunnel.h"\n',
            b'#inc\\\nlude "LiveTunnel.h"\n',
        ):
            sources["srchybrid/LiveTunnelTicketPolicy.cpp"] = robust_form
            with self.assertRaisesRegex(include_errors, "reverse coordinator include"):
                GATE.validate_active_include_contract(
                    self.matrix, ledger, sources
                )
        ls4_ledger = copy.deepcopy(self.ledger)
        ls4_ledger["cards"]["LS4"] = {
            "state": "active", "activation_commit": "0" * 40,
            "evidence": ["fixture"],
        }
        for robust_form in (
            b'%:include "LiveStreamManager.h"\n',
            b'#inc\\\nlude "LiveStreamManager.h"\n',
        ):
            with self.assertRaisesRegex(include_errors, "reverse coordinator include"):
                GATE.validate_active_include_contract(
                    self.matrix,
                    ls4_ledger,
                    {"srchybrid/LiveStreamRecovery.cpp": robust_form},
                )
        lt1_ledger = copy.deepcopy(self.ledger)
        lt1_ledger["cards"]["LT1"] = {
            "state": "active", "activation_commit": "0" * 40,
            "evidence": ["fixture"],
        }
        with self.assertRaisesRegex(include_errors, "reverse coordinator include"):
            GATE.validate_active_include_contract(
                self.matrix,
                lt1_ledger,
                {
                    "srchybrid/LiveTunnelReleaseGate.cpp": b"",
                    "srchybrid/LiveTunnelReleaseGate.h": b"",
                    "srchybrid/LiveTunnelScheduler.cpp": (
                        b'%:include "LiveTunnel.h"\n'
                    ),
                },
            )

    def test_active_module_type_cannot_leak_back_into_a_coordinator(self):
        ledger = copy.deepcopy(self.ledger)
        ledger["cards"]["LT1"] = {
            "state": "active", "activation_commit": "0" * 40,
            "evidence": ["fixture"],
        }
        source = (ROOT / "srchybrid/LiveTunnel.cpp").read_bytes()
        comments_only = source + b"\n// LiveTunnelReleaseGate is intentionally absent\n"
        GATE.validate_coordinator_module_isolation(
            self.matrix, ledger, {"srchybrid/LiveTunnel.cpp": comments_only}
        )
        direct_reference = source + b"\nLiveTunnelReleaseGate* leaked_gate;\n"
        with self.assertRaisesRegex(GATE.GateError, "references"):
            GATE.validate_coordinator_module_isolation(
                self.matrix,
                ledger,
                {"srchybrid/LiveTunnel.cpp": direct_reference},
            )
        with self.assertRaisesRegex(GATE.GateError, "transitively reaches|include closure references"):
            GATE.validate_coordinator_module_isolation(
                self.matrix,
                ledger,
                {
                    "srchybrid/LiveTunnel.cpp": b'#include "M2AIntermediate.h"\n',
                    "srchybrid/M2AIntermediate.h": (
                        b'%:include "LiveTunnelReleaseGate.h"\n'
                        b"using ReleaseGateService = LiveTunnelReleaseGate;\n"
                    ),
                    "srchybrid/LiveTunnelReleaseGate.cpp": b"",
                    "srchybrid/LiveTunnelReleaseGate.h": b"",
                },
            )
        with self.assertRaisesRegex(GATE.GateError, "include closure references"):
            GATE.validate_coordinator_module_isolation(
                self.matrix,
                ledger,
                {
                    "srchybrid/LiveTunnel.cpp": b'#include "M2AForwardAlias.h"\n',
                    "srchybrid/M2AForwardAlias.h": (
                        b"class LiveTunnelReleaseGate;\n"
                        b"using ReleaseGateService = LiveTunnelReleaseGate;\n"
                    ),
                    "srchybrid/LiveTunnelReleaseGate.cpp": b"",
                    "srchybrid/LiveTunnelReleaseGate.h": b"",
                },
            )
        with self.assertRaisesRegex(GATE.GateError, "token-paste"):
            GATE.validate_coordinator_module_isolation(
                self.matrix,
                ledger,
                {
                    "srchybrid/LiveTunnel.cpp": b'#include "M2ATokenPaste.h"\n',
                    "srchybrid/M2ATokenPaste.h": (
                        b"#define CAT(a,b) a##b\n"
                        b"class CAT(LiveTunnelRe,leaseGate);\n"
                        b"using Alias = CAT(LiveTunnelRe,leaseGate);\n"
                    ),
                    "srchybrid/LiveTunnelReleaseGate.cpp": b"",
                    "srchybrid/LiveTunnelReleaseGate.h": b"",
                },
            )

    def test_coordinator_declarations_are_frozen_independent_of_member_naming(self):
        header = (ROOT / "srchybrid/WebServer.h").read_bytes()
        field_instead_of_method = header.replace(
            b"bool ReloadTemplates();", b"bool ReloadTemplates;"
        )
        with self.assertRaisesRegex(GATE.GateError, "gained or changed a declaration"):
            GATE.validate_coordinator_header_monotonicity(
                {"srchybrid/WebServer.h": field_instead_of_method}
            )
        alias_field = header.replace(
            b"bool ReloadTemplates();",
            b"using ReleaseGateService = int;\n\tReleaseGateService* gate_;",
        )
        with self.assertRaisesRegex(GATE.GateError, "gained or changed a declaration"):
            GATE.validate_coordinator_header_monotonicity(
                {"srchybrid/WebServer.h": alias_field}
            )
        public_state = header.replace(b"private:", b"public:")
        with self.assertRaisesRegex(GATE.GateError, "gained or changed a declaration"):
            GATE.validate_coordinator_header_monotonicity(
                {"srchybrid/WebServer.h": public_state}
            )
        fake_owner = """
        class LiveTunnelReleaseGate {
        public:
          void Dummy() { int m_k6ReleaseLock = 0; }
        };
        """
        self.assertNotIn(
            "m_k6ReleaseLock",
            GATE._class_data_identifiers(
                fake_owner, "LiveTunnelReleaseGate"
            ),
        )
        real_owner = """
        class LiveTunnelReleaseGate {
        private:
          int m_k6ReleaseLock;
        };
        """
        self.assertIn(
            "m_k6ReleaseLock",
            GATE._class_data_identifiers(
                real_owner, "LiveTunnelReleaseGate"
            ),
        )
        fake_public_constant = """
        class LiveTunnelReleaseGate {
        public:
          static constexpr int m_k6ReleaseLock = 0;
        };
        """
        self.assertNotIn(
            "m_k6ReleaseLock",
            GATE._class_data_identifiers(
                fake_public_constant, "LiveTunnelReleaseGate"
            ),
        )

    def test_matrix_rejects_replaced_or_overlapping_frozen_fields(self):
        candidate = copy.deepcopy(self.matrix)
        candidate["field_matrix"]["LiveTunnel"]["transfers"][0]["fields"][0] = "m_invented"
        with self.assertRaisesRegex(GATE.GateError, "does not exactly match baseline"):
            GATE.validate_inputs(self.contract, candidate, self.baseline)
        candidate = copy.deepcopy(self.matrix)
        candidate["field_matrix"]["LiveStreamManager"]["transfers"][0]["fields"][0] = candidate["field_matrix"]["LiveStreamManager"]["retained_parent_fields"][0]
        with self.assertRaisesRegex(GATE.GateError, "does not exactly match baseline"):
            GATE.validate_inputs(self.contract, candidate, self.baseline)
        candidate = copy.deepcopy(self.matrix)
        for item in candidate["additional_modules"]: item["dependencies"] = []
        with self.assertRaisesRegex(GATE.GateError, "collapsed or placeholder"):
            GATE.validate_inputs(self.contract, candidate, self.baseline)

    def test_ratchet_rejects_loc_field_function_and_scc_growth(self):
        current = GATE.metrics()
        for mutate, message in (
            (lambda x: x["coordinators"]["LiveTunnel"]["files"].__setitem__("srchybrid/LiveTunnel.cpp", 10362), "coordinator LOC grew"),
            (lambda x: x["coordinators"]["LiveStreamManager"]["fields"].append("m_new"), "mutable fields grew"),
            (lambda x: x["coordinators"]["WebServer"]["oversized_functions"].append(["CWebServer::NewLarge", 151]), "oversized function grew"),
            (lambda x: x.__setitem__("sccs", [["A", "B"]]), "new include SCC"),
        ):
            candidate = copy.deepcopy(current); mutate(candidate)
            with self.assertRaisesRegex(GATE.GateError, message):
                GATE.validate_ratchet(self.baseline, candidate, self.matrix)


if __name__ == "__main__": unittest.main(verbosity=2)
