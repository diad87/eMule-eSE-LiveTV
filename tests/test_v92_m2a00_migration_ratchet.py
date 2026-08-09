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

    def planned_ledger(self):
        ledger = copy.deepcopy(self.ledger)
        ledger["cards"] = {
            card: {"state": "planned", "activation_commit": None, "evidence": []}
            for card in ledger["cards"]
        }
        return ledger

    def test_closed_matrix_is_exhaustive_and_green(self):
        # The v1 matrix remains immutable historical evidence while W12 is a
        # separately governed v2 source overlay rooted at the qualified
        # v9.1+W1-W11 integration commit.  Validate the hash-pinned historical
        # inputs here; the v2 verify() call below owns all current-source,
        # evidence and budget checks from that immutable base.
        GATE._validate_w12_historical_inputs()
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

    def test_upnp_lifecycle_headers_are_closed_non_modules(self):
        catalogue = GATE.load(GATE.MOD04V2)
        GATE.validate_upnp_lifecycle_helpers(catalogue)
        entries = {item["path"]: item for item in catalogue["approved_non_module_code"]}
        self.assertEqual(
            {path for path in entries if path in GATE.UPNP_LIFECYCLE_HELPERS},
            set(GATE.UPNP_LIFECYCLE_HELPERS),
        )
        for path, policy in GATE.UPNP_LIFECYCLE_HELPERS.items():
            text = (ROOT / path).read_text(encoding="utf-8")
            self.assertLessEqual(len(text.splitlines()), policy["max_loc"])
            self.assertFalse((ROOT / (path[:-2] + ".cpp")).exists())
        test_path = ROOT / "srchybrid/tests/test_upnp_worker_lifecycle.cpp"
        self.assertLessEqual(len(test_path.read_text(encoding="utf-8").splitlines()), 300)
        self.assertNotIn(
            "test_upnp_worker_lifecycle.cpp",
            (ROOT / "srchybrid/emule.vcxproj").read_text(encoding="utf-8"),
        )

    def test_upnp_lifecycle_ratchet_rejects_removal_include_and_overflow(self):
        catalogue = GATE.load(GATE.MOD04V2)
        removed = copy.deepcopy(catalogue)
        removed["approved_non_module_code"] = [
            item for item in removed["approved_non_module_code"]
            if item["path"] != "srchybrid/UPnPWorkerLifecycle.h"
        ]
        with self.assertRaisesRegex(GATE.GateError, "missing from closed catalogue"):
            GATE.validate_upnp_lifecycle_helpers(removed)

        worker = (ROOT / "srchybrid/UPnPWorkerLifecycle.h").read_bytes()
        with self.assertRaisesRegex(GATE.GateError, "include drift"):
            GATE.validate_upnp_lifecycle_helpers(catalogue, {
                "srchybrid/UPnPWorkerLifecycle.h": worker.replace(
                    b"#include <atomic>", b"#include <atomic>\n#include \"EmuleDlg.h\""
                )
            })
        with self.assertRaisesRegex(GATE.GateError, "LOC overflow"):
            GATE.validate_upnp_lifecycle_helpers(catalogue, {
                "srchybrid/UPnPWorkerLifecycle.h": worker + (b"\n" * 7)
            })

        reaper = (ROOT / "srchybrid/UPnPDeferredReaperCore.h").read_bytes()
        with self.assertRaisesRegex(GATE.GateError, "concrete/global dependency"):
            GATE.validate_upnp_lifecycle_helpers(catalogue, {
                "srchybrid/UPnPDeferredReaperCore.h": reaper.replace(
                    b"#pragma once", b"#pragma once\n// CString"
                )
            })

        test_path = "srchybrid/tests/test_upnp_worker_lifecycle.cpp"
        test_blob = (ROOT / test_path).read_bytes()
        with self.assertRaisesRegex(GATE.GateError, "test LOC overflow"):
            GATE.validate_upnp_lifecycle_helpers(catalogue, {
                test_path: test_blob + (b"\n" * 36)
            })
        with self.assertRaisesRegex(GATE.GateError, "test include drift"):
            GATE.validate_upnp_lifecycle_helpers(catalogue, {
                test_path: test_blob.replace(
                    b"#include <cstdio>", b"#include <cstdio>\n#include \"../EmuleDlg.h\""
                )
            })
        removed_test = copy.deepcopy(catalogue)
        removed_test["approved_non_module_code"] = [
            item for item in removed_test["approved_non_module_code"]
            if item["path"] != test_path
        ]
        with self.assertRaisesRegex(GATE.GateError, "test missing from closed catalogue"):
            GATE.validate_upnp_lifecycle_helpers(removed_test)

    def test_upnp_lifecycle_reaper_overflow_is_fail_closed(self):
        catalogue = GATE.load(GATE.MOD04V2)
        reaper_path = "srchybrid/UPnPDeferredReaperCore.h"
        reaper = (ROOT / reaper_path).read_bytes()
        with self.assertRaisesRegex(GATE.GateError, "overflow must fail closed"):
            GATE.validate_upnp_lifecycle_helpers(catalogue, {
                reaper_path: reaper.replace(b"return false;", b"return true;")
            })

    def test_upnp_lifecycle_test_isolation_and_adr_are_pinned(self):
        catalogue = GATE.load(GATE.MOD04V2)
        test_name = b"test_upnp_worker_lifecycle.cpp"
        hostile = (
            ({"srchybrid/RootLeak.h": b'#include "tests/TEST_UPNP_WORKER_LIFECYCLE.CPP"\n'},
             "productive source includes"),
            ({"srchybrid/subdir/Leak.cpp": b'# include "test_upnp_worker_lifecycle.cpp"\n'},
             "productive source includes"),
            ({"other/product.vcxproj": b'<ClCompile Include="test_upnp_worker_lifecycle.cpp" />'},
             "linked into product manifest"),
        )
        for overrides, message in hostile:
            with self.subTest(message=message), self.assertRaisesRegex(GATE.GateError, message):
                GATE.validate_upnp_lifecycle_helpers(catalogue, overrides)
        adr = (ROOT / GATE.UPNP_LIFECYCLE_ADR).read_bytes()
        with self.assertRaisesRegex(GATE.GateError, "ADR hash drift"):
            GATE.validate_upnp_lifecycle_helpers(catalogue, {
                GATE.UPNP_LIFECYCLE_ADR: adr + b"\n"
            })

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
            GATE.validate_inputs(
                self.contract, candidate, self.baseline, self.planned_ledger()
            )

    def test_w11_corrected_delete_budget_is_consistent_and_narrow(self):
        function = next(
            item
            for item in self.matrix["function_matrix"]
            if item["name"] == "CWebServer::_ProcessLiveAPI"
        )
        module = next(
            item
            for item in self.matrix["additional_modules"]
            if item["name"] == "WebLiveApiLegacyController"
        )
        expected = {
            "module_loc": 1100,
            "add": 1300,
            "delete": 850,
            "net": 250,
        }
        self.assertEqual(function["budget"], expected)
        self.assertEqual(module["budget"], expected)
        self.assertEqual(
            self.matrix["card_budgets"]["W11"],
            {
                "add": 1300,
                "delete": 850,
                "net": 250,
                "coordinator": "WebServer",
                "facade_add_max": 80,
                "reduction_required": True,
            },
        )

    def test_catalogue_rejects_collapsed_live_api_or_placeholder_dependencies(self):
        candidate = copy.deepcopy(self.matrix)
        candidate["additional_modules"] = [item for item in candidate["additional_modules"] if not item["name"].startswith("WebLiveApi")]
        requirements = GATE._card_test_requirements(self.matrix)
        ledger = self.planned_ledger()
        # W12 is a governed overlay over the already activated W1..W11
        # sources.  Keep this unit test focused on the deliberately collapsed
        # catalogue instead of letting the checkout's W12 source overlay
        # pre-empt that assertion with an activation-blob mismatch.
        with mock.patch.object(GATE, "_card_test_requirements", return_value=requirements), \
             mock.patch.object(GATE, "validate_source_activation", return_value=None):
            with self.assertRaisesRegex(GATE.GateError, "collapsed or placeholder"):
                GATE.validate_inputs(self.contract, candidate, self.baseline, ledger)

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
                for card_name, card in fixture_ledger["cards"].items():
                    planned = {
                        "state": "planned",
                        "activation_commit": None,
                        "evidence": [],
                    }
                    if card_name == "W12":
                        fixture_ledger["cards"][card_name] = planned
                    else:
                        card.update(planned)
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
        for state in ledger["cards"].values():
            state.update(state="planned", activation_commit=None, evidence=[])
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
        for state in ls4_ledger["cards"].values():
            state.update(state="planned", activation_commit=None, evidence=[])
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
        for state in lt1_ledger["cards"].values():
            state.update(state="planned", activation_commit=None, evidence=[])
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
        ledger = self.planned_ledger()
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
        requirements = GATE._card_test_requirements(self.matrix)
        with mock.patch.object(GATE, "_card_test_requirements", return_value=requirements), \
             mock.patch.object(GATE, "validate_source_activation", return_value=None):
            with self.assertRaisesRegex(GATE.GateError, "collapsed or placeholder"):
                GATE.validate_inputs(
                    self.contract, candidate, self.baseline, self.planned_ledger()
                )

    def test_ratchet_rejects_loc_field_function_and_scc_growth(self):
        current = copy.deepcopy(self.baseline["metrics"])
        for mutate, message in (
            (lambda x: x["coordinators"]["LiveTunnel"]["files"].__setitem__("srchybrid/LiveTunnel.cpp", 10362), "coordinator LOC grew"),
            (lambda x: x["coordinators"]["LiveStreamManager"]["fields"].append("m_new"), "mutable fields grew"),
            (lambda x: x["coordinators"]["WebServer"]["oversized_functions"].append(["CWebServer::NewLarge", 151]), "oversized function grew"),
            (lambda x: x.__setitem__("sccs", [["A", "B"]]), "new include SCC"),
        ):
            candidate = copy.deepcopy(current); mutate(candidate)
            with self.assertRaisesRegex(GATE.GateError, message):
                GATE.validate_ratchet(self.baseline, candidate, self.matrix)


class W12OverlayRatchetTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.matrix = GATE.load(GATE.W12_MATRIX)
        cls.contract = GATE.load(GATE.W12_CONTRACT)
        cls.ownership = GATE.load(GATE.W12_MOD03)
        cls.catalogue = GATE.load(GATE.W12_MOD04)

    def card(self):
        return copy.deepcopy(self.matrix["cards"][0])

    def r_evidence(self, activation_commit="a" * 40, blobs=None):
        paths = GATE._w12_r_artifact_paths(activation_commit)
        blobs = (
            {key: f"persisted-{key}".encode("ascii") for key in paths}
            if blobs is None else blobs
        )
        verifier_sha = hashlib.sha256(b"immutable-verifier").hexdigest()
        return {
            **{
                key: {
                    "path": path,
                    "sha256": hashlib.sha256(blobs[key]).hexdigest(),
                }
                for key, path in paths.items()
            },
            "candidate_commit": activation_commit,
            "emule_sha256": "e" * 64,
            "verifier_sha256": verifier_sha,
        }

    def r_v2_artifacts(self, activation_commit="a" * 40):
        tool_blobs = {
            path: f"tool:{key}".encode("ascii")
            for key, path in GATE.W12_R_TOOL_PATHS.items()
        }
        tools = {
            key: hashlib.sha256(tool_blobs[path]).hexdigest()
            for key, path in GATE.W12_R_TOOL_PATHS.items()
        }
        tree = "1" * 64
        binding = {
            "activation_commit": activation_commit,
            "production_tree_sha256": tree,
            "toolset_sha256": GATE._w12_toolset_sha256(tools),
            "run_id_sha256": "2" * 64,
            "challenge_nonce_sha256": "3" * 64,
            "canary_sha256": "4" * 64,
        }
        candidate = {
            "build_commit": activation_commit, "emule_sha256": "e" * 64,
            "build_info_sha256": "5" * 64, "release": "v9.2-test",
        }
        values = {
            "activation": {
                "schema": "ese.v92.w12.activation/v2",
                "activation_commit": activation_commit,
                "production_tree_sha256": tree, "production_path_count": 99,
                "tool_sha256": tools,
            },
            "runtime": {
                "schema": "ese.v92.w12.security-runtime/v2", "candidate": candidate,
                "execution": {}, "cases": [], "canary": {}, "privacy": {},
                "binding": binding, "verdict": "PASS",
            },
            "browser_challenge": {
                "schema": "ese.v92.w12.browser-challenge/v2",
                "candidate": candidate, "binding": binding,
            },
            "browser_cdp_trace": {
                "schema": "ese.v92.w12.browser-cdp/v3",
                "activation_commit": activation_commit, "candidate": candidate,
                "binding": binding, "collector_sha256": tools["collector"],
                "browser_binding_sha256": "6" * 64, "product_sha256": "7" * 64,
                "version_sha256": "8" * 64, "user_agent_sha256": "9" * 64, "events": [],
            },
            "verdict": {
                "schema": "ese.v92.w12.security-verdict/v2",
                "activation_commit": activation_commit, "emule_sha256": "e" * 64,
                "cases": [], "verdict": "PASS",
            },
        }
        blobs = {key: json.dumps(value, sort_keys=True).encode("utf-8") for key, value in values.items()}
        evidence = self.r_evidence(activation_commit, blobs)
        evidence["verifier_sha256"] = tools["verifier"]
        return values, blobs, evidence, tool_blobs

    def validate_documents(self, matrix=None, contract=None, ownership=None, catalogue=None):
        return GATE.validate_w12_overlay_documents(
            copy.deepcopy(self.matrix if matrix is None else matrix),
            copy.deepcopy(self.contract if contract is None else contract),
            copy.deepcopy(self.ownership if ownership is None else ownership),
            copy.deepcopy(self.catalogue if catalogue is None else catalogue),
        )

    def test_w12_v2_closed_documents_and_cross_links_are_valid(self):
        card = self.validate_documents()
        self.assertEqual(card["card"], "M2A-W12")
        self.assertTrue(card["card_paths"])
        self.assertEqual(len(card["card_paths"]), len(set(card["card_paths"])))
        self.assertEqual(len(card["card_paths"]), 61)
        self.assertTrue(GATE.W12_SCOPE_EXPANSION_PATHS.issubset(card["card_paths"]))
        self.assertEqual(card["coverage_ids"], list(GATE.W12_COVERAGE_IDS))
        self.assertNotIn(
            "tests/test_v92_m2a_w11_live_api_legacy.py", card["card_paths"]
        )

    def test_w12_schema_and_historical_hash_are_fail_closed(self):
        matrix = copy.deepcopy(self.matrix)
        matrix["self_authorised"] = True
        with self.assertRaisesRegex(GATE.GateError, "closed schema drift"):
            self.validate_documents(matrix=matrix)
        matrix = copy.deepcopy(self.matrix)
        matrix["v1_evidence"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(GATE.GateError, "declared historical hash drift"):
            self.validate_documents(matrix=matrix)
        historical_path = "docs/architecture/mod52_migration_matrix_v1.json"
        with mock.patch.dict(
            GATE.W12_HISTORICAL_HASHES,
            {historical_path: "0" * 64},
        ):
            with self.assertRaisesRegex(GATE.GateError, "hash-pinned historical input drift"):
                self.validate_documents()

    def test_w12_card_paths_reject_duplicates_escape_and_unlisted_staging(self):
        matrix = copy.deepcopy(self.matrix)
        matrix["cards"][0]["card_paths"].append(
            matrix["cards"][0]["card_paths"][0]
        )
        with self.assertRaisesRegex(GATE.GateError, "duplicates"):
            self.validate_documents(matrix=matrix)
        matrix = copy.deepcopy(self.matrix)
        matrix["cards"][0]["card_paths"][0] = "../escape.cpp"
        with self.assertRaisesRegex(GATE.GateError, "unsafe path"):
            self.validate_documents(matrix=matrix)
        paths = self.card()["card_paths"]
        with self.assertRaisesRegex(GATE.GateError, "staged path is outside"):
            GATE.validate_w12_card_path_scope(
                paths, set(paths) | {"srchybrid/Unreviewed.cpp"},
                {"srchybrid/Unreviewed.cpp"},
            )

    def test_w12_budget_fields_are_typed_and_independently_enforced(self):
        matrix = copy.deepcopy(self.matrix)
        matrix["cards"][0]["coordinator_budget"]["add_max"] = "500"
        with self.assertRaisesRegex(GATE.GateError, "not typed"):
            self.validate_documents(matrix=matrix)
        card = self.card()
        numstat = GATE._w12_numstat(
            GATE.W12_BASE_COMMIT, None, card["card_paths"]
        )
        card["card_total_budget"]["add_max"] = 0
        with self.assertRaisesRegex(GATE.GateError, "total CARD_PATHS additions"):
            GATE.validate_w12_source_ratchets(card, numstat)

    def test_w12_joint_document_budget_mutation_cannot_self_authorise(self):
        matrix = copy.deepcopy(self.matrix)
        contract = copy.deepcopy(self.contract)
        forged = {"add_max": 999999, "delete_min": 1, "net_max": 999998}
        for document_budget in (
            matrix["cards"][0]["card_total_budget"],
            contract["card_total_budget"],
        ):
            document_budget.update(forged)
        with self.assertRaisesRegex(GATE.GateError, "literal-pinned"):
            self.validate_documents(matrix=matrix, contract=contract)

    def test_w12_new_mutable_field_is_rejected(self):
        path = "srchybrid/WebServer.h"
        baseline = GATE._w12_blob_or_none(GATE.W12_BASE_COMMIT, path)
        current = GATE._w12_current_or_none(path)
        self.assertIsNotNone(baseline)
        self.assertIsNotNone(current)
        mutated = current.replace(b"m_uCurIP", b"m_w12Leak")
        with self.assertRaisesRegex(GATE.GateError, "mutable fields grew"):
            GATE.validate_w12_field_monotonicity(
                baseline, mutated, "CWebServer", path
            )

    def test_w12_dependency_drift_and_scc_are_rejected(self):
        ownership = copy.deepcopy(self.ownership)
        ownership["layer_rules"]["WebHlsCapabilityController"] = []
        with self.assertRaisesRegex(GATE.GateError, "declared direct dependency drift"):
            GATE.validate_w12_dependencies_and_scc(self.card(), ownership)
        self.assertEqual(
            GATE._w12_tarjan({"A": {"B"}, "B": {"A"}}), [("A", "B")]
        )
        self.assertEqual(GATE._w12_tarjan({"A": {"B"}, "B": set()}), [])

    def test_w12_oversized_function_inventory_detects_new_body(self):
        raw = (
            b"static void W12HiddenOversized()\n{\n"
            + (b"    ;\n" * 151)
            + b"}\n"
        )
        inventory = GATE._w12_function_inventory(raw, "srchybrid/W12Fixture.cpp")
        self.assertTrue(
            any("W12HiddenOversized" in name for name in inventory), inventory
        )

    def test_w12_coverage_map_and_stage_assignment_are_complete(self):
        catalogue = copy.deepcopy(self.catalogue)
        catalogue["coverage_map"]["port:LiveHlsReadLease"] = []
        with self.assertRaisesRegex(GATE.GateError, "coverage map row invalid"):
            self.validate_documents(catalogue=catalogue)
        catalogue = copy.deepcopy(self.catalogue)
        catalogue["gates"][5]["stage"] = "PRE-A"
        with self.assertRaisesRegex(GATE.GateError, "stage assignment drift"):
            self.validate_documents(catalogue=catalogue)

    def test_w12_a_parent_and_active_evidence_sha_are_immutable(self):
        ledger = GATE.load(GATE.ACTIVATION); ledger["cards"]["W12"] = GATE._w12_planned_state()
        with mock.patch.object(GATE, "_git_text", return_value="a" * 40), \
             mock.patch.object(GATE, "_w12_exact_parent", return_value="b" * 40):
            with self.assertRaisesRegex(GATE.GateError, r"exact A\^\.\.A"):
                GATE.validate_w12_activation_state(self.card(), ledger)
        path = "tests/test_v92_m2a_w12_security_evidence.py"
        state = {
            "state": "active",
            "activation_commit": "a" * 40,
            "evidence": [{
                "kind": "test_source", "path": path, "sha256": "0" * 64,
                "commit": "a" * 40, "covers": list(GATE.W12_TYPED_COVERAGE),
            }],
        }
        with mock.patch.object(GATE, "_w12_blob_or_none", return_value=b"evidence"):
            with self.assertRaisesRegex(GATE.GateError, "evidence SHA drift"):
                GATE._validate_w12_activation_evidence(
                    state, self.card(), "a" * 40
                )

    def test_w12_exact_parent_rejects_merge_commit(self):
        with mock.patch.object(GATE, "_git_text", return_value=("a" * 40 + " " + "b" * 40)):
            self.assertEqual(GATE._w12_exact_parent("a" * 40), "b" * 40)
        with mock.patch.object(GATE, "_git_text", return_value=("a" * 40 + " " + "b" * 40 + " " + "c" * 40)):
            with self.assertRaisesRegex(GATE.GateError, "exactly one parent"):
                GATE._w12_exact_parent("a" * 40)
    def test_w12_r_post_history_is_linear_unique_and_protected(self):
        a, h, r, d, e = (letter * 40 for letter in "abcde"); ledger = GATE.ACTIVATION.relative_to(GATE.ROOT).as_posix()
        artifacts, paths = GATE._w12_r_artifact_paths(a), self.card()["card_paths"]
        def resolve(ledger_history=h + "\n" + r, descendants=d + "\n" + e,
                    changed=frozenset(), parent_error=False):
            text = lambda *args: descendants if "--ancestry-path" in args else ledger_history
            parents = {h: a, r: h, d: r, e: d}
            def parent(commit):
                if parent_error and commit == d:
                    raise GATE.GateError("W12 commit must have exactly one parent")
                return parents[commit]
            with mock.patch.object(GATE, "_git_text", side_effect=text), \
                 mock.patch.object(GATE, "_w12_exact_parent", side_effect=parent), \
                 mock.patch.object(GATE, "_is_ancestor", return_value=True), \
                 mock.patch.object(GATE, "_git_z_paths", return_value=set(changed)):
                return GATE._w12_resolve_r_history(a, ledger, artifacts, paths)
        self.assertEqual(resolve(), (h, r))
        for protected in (paths[0], ledger, next(iter(artifacts.values()))):
            with self.subTest(protected=protected), self.assertRaisesRegex(
                    GATE.GateError, "protected path changed after R"):
                resolve(changed={protected})
        with self.assertRaisesRegex(GATE.GateError, "exactly one parent"):
            resolve(descendants=d, parent_error=True)
        with self.assertRaisesRegex(GATE.GateError, "exactly one H and one R"):
            resolve(ledger_history=h + "\n" + r + "\n" + d)
    test_w12_r_accepts_linear_non_w12_descendants = test_w12_r_post_history_is_linear_unique_and_protected
    test_w12_r_rejects_protected_change_or_revert = test_w12_r_post_history_is_linear_unique_and_protected
    test_w12_r_rejects_merge_or_second_r = test_w12_r_post_history_is_linear_unique_and_protected

    def test_w12_submodule_and_gitlink_changes_are_out_of_scope(self):
        card_paths = self.card()["card_paths"]
        with mock.patch.object(GATE, "_git_z_paths", side_effect=[{"libutp"}, set(), set()]):
            changed, staged = GATE._w12_worktree_path_sets()
        self.assertEqual(changed, {"libutp"})
        self.assertEqual(staged, set())
        with self.assertRaisesRegex(GATE.GateError, "outside CARD_PATHS"):
            GATE.validate_w12_card_path_scope(card_paths, changed, staged)
        with mock.patch.object(GATE, "_git_z_paths", side_effect=[set(), set()]), \
             mock.patch.object(GATE.subprocess, "check_output", return_value="+" + "a" * 40 + " libutp (heads/main)\n"):
            dirty = GATE._w12_dirty_paths()
        self.assertEqual(dirty, {"libutp"})
        with self.assertRaisesRegex(GATE.GateError, "outside CARD_PATHS"):
            GATE.validate_w12_card_path_scope(card_paths, dirty)
        source = GATE.ROOT.joinpath("tools/architecture/verify_m2a00_migration_ratchet.py").read_text(encoding="utf-8")
        self.assertNotIn("--ignore-submodules=all", source)
        self.assertGreaterEqual(source.count("--ignore-submodules=none"), 5)

    def test_w12_strict_file_json_rejects_duplicate_keys_and_extra_document_fields(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "matrix.json"
            path.write_text('{"schema":"one","schema":"two"}', encoding="utf-8")
            with self.assertRaisesRegex(GATE.GateError, "duplicate JSON member"):
                GATE._w12_strict_json_file(path)
        matrix = copy.deepcopy(self.matrix)
        matrix["unexpected"] = True
        with self.assertRaisesRegex(GATE.GateError, "closed schema drift"):
            self.validate_documents(matrix=matrix)

    def test_w12_r_evidence_schema_is_closed_and_has_fixed_paths(self):
        activation_commit = "a" * 40
        evidence = self.r_evidence(activation_commit)
        self.assertEqual(
            GATE.validate_w12_r_evidence_schema(evidence, activation_commit),
            GATE._w12_r_artifact_paths(activation_commit),
        )
        free_path = copy.deepcopy(evidence)
        free_path["runtime"]["path"] = "artifacts/attacker-selected.json"
        with self.assertRaisesRegex(GATE.GateError, "path is not fixed"):
            GATE.validate_w12_r_evidence_schema(free_path, activation_commit)
        extra = copy.deepcopy(evidence)
        extra["self_authorised"] = True
        with self.assertRaisesRegex(GATE.GateError, "closed schema drift"):
            GATE.validate_w12_r_evidence_schema(extra, activation_commit)

    def test_w12_h_state_cannot_smuggle_r_evidence(self):
        activation_commit = "a" * 40
        ledger = GATE.load(GATE.ACTIVATION)
        ledger["cards"]["W12"] = {
            "state": "active",
            "stage": "H",
            "activation_commit": activation_commit,
            "evidence": [],
            "r_evidence": self.r_evidence(activation_commit),
        }
        legacy = copy.deepcopy(ledger)
        legacy["cards"]["W12"].pop("stage")
        with mock.patch.object(GATE, "_git_text", return_value="b" * 40):
            with self.assertRaisesRegex(GATE.GateError, "closed schema drift"):
                GATE.validate_w12_activation_state(self.card(), legacy)
        planned = {"cards": {"W12": GATE._w12_planned_state()}}
        ledger_path = GATE.ACTIVATION.relative_to(GATE.ROOT).as_posix()

        def parent(commit):
            return GATE.W12_BASE_COMMIT if commit == activation_commit else activation_commit

        with mock.patch.object(GATE, "_git_text", return_value="b" * 40), \
             mock.patch.object(GATE, "_w12_exact_parent", side_effect=parent), \
             mock.patch.object(GATE, "_is_ancestor", return_value=True), \
             mock.patch.object(GATE, "_w12_dirty_paths", return_value=set()), \
             mock.patch.object(GATE, "_w12_commit_changed_paths", return_value={ledger_path}), \
             mock.patch.object(GATE, "validate_w12_card_path_scope"), \
             mock.patch.object(GATE, "_w12_strict_json_blob", return_value=planned), \
             mock.patch.object(GATE, "_w12_blob_or_none", return_value=b"same"), \
             mock.patch.object(GATE, "_w12_current_or_none", return_value=b"same"), \
             mock.patch.object(GATE, "_validate_w12_activation_evidence"):
            with self.assertRaisesRegex(GATE.GateError, "H must not contain R evidence"):
                GATE.validate_w12_activation_state(self.card(), ledger)

    def test_w12_r_artifacts_bind_activation_and_immutable_a_tools(self):
        activation_commit = "a" * 40
        paths = GATE._w12_r_artifact_paths(activation_commit)
        values, artifact_blobs, evidence, tool_blobs = self.r_v2_artifacts(activation_commit)
        state = {"r_evidence": evidence}

        def blob(commit, path):
            for key, artifact_path in paths.items():
                if commit == "HEAD" and path == artifact_path:
                    return artifact_blobs[key]
            return tool_blobs.get(path)

        def current(path):
            for key, artifact_path in paths.items():
                if path == artifact_path:
                    return artifact_blobs[key]
            return tool_blobs.get(path)

        with mock.patch.object(GATE, "_w12_blob_or_none", side_effect=blob), \
             mock.patch.object(GATE, "_w12_current_or_none", side_effect=current), \
             mock.patch.object(GATE, "_w12_production_tree", return_value=("1" * 64, 99)), \
             mock.patch.object(GATE, "_run_w12_r_verifier") as verifier:
            GATE._validate_w12_r_artifacts(state, activation_commit, paths)
            verifier.assert_called_once_with(paths, evidence, activation_commit)
        bad_hash_state = copy.deepcopy(state)
        bad_hash_state["r_evidence"]["runtime"]["sha256"] = "0" * 64
        with mock.patch.object(GATE, "_w12_blob_or_none", side_effect=blob), \
             mock.patch.object(GATE, "_w12_current_or_none", side_effect=current):
            with self.assertRaisesRegex(GATE.GateError, "absent or not immutable"):
                GATE._validate_w12_r_artifacts(
                    bad_hash_state, activation_commit, paths
                )
        values["activation"]["activation_commit"] = "b" * 40
        artifact_blobs["activation"] = json.dumps(
            values["activation"], sort_keys=True
        ).encode("utf-8")
        evidence["activation"]["sha256"] = hashlib.sha256(
            artifact_blobs["activation"]
        ).hexdigest()
        with mock.patch.object(GATE, "_w12_blob_or_none", side_effect=blob), \
             mock.patch.object(GATE, "_w12_current_or_none", side_effect=current), \
             mock.patch.object(GATE, "_w12_production_tree", return_value=("1" * 64, 99)):
            with self.assertRaisesRegex(GATE.GateError, "not bound to A"):
                GATE._validate_w12_r_artifacts(state, activation_commit, paths)

    def test_w12_r_invokes_verifier_and_requires_reproducible_verdict(self):
        activation_commit = "a" * 40
        paths = GATE._w12_r_artifact_paths(activation_commit)
        values, blobs, evidence, tool_blobs = self.r_v2_artifacts(activation_commit)
        persisted = blobs["verdict"]
        commands = []

        def blob(commit, path):
            for key, artifact_path in paths.items():
                if path == artifact_path:
                    return blobs[key]
            return tool_blobs.get(path)

        def reproduce(command, **kwargs):
            commands.append(command)
            output = pathlib.Path(command[command.index("--output") + 1])
            output.write_bytes(persisted)
            return mock.Mock(returncode=0)

        with mock.patch.object(GATE.subprocess, "run", side_effect=reproduce), \
             mock.patch.object(GATE, "_w12_blob_or_none", side_effect=blob), \
             mock.patch.object(GATE, "_w12_strict_json_blob", return_value=values["verdict"]), \
             mock.patch.object(GATE, "_git_text", return_value="f" * 40), \
             mock.patch.object(GATE, "_w12_current_or_none", side_effect=AssertionError("worktree read")):
            GATE._run_w12_r_verifier(paths, evidence, activation_commit)
        self.assertEqual(len(commands), 1)
        for option in (
            "--activation", "--runtime", "--challenge", "--browser-trace", "--output"
        ):
            self.assertIn(option, commands[0])
        self.assertNotIn(GATE.W12_EVIDENCE_VERIFIER, commands[0])
        for original in paths.values():
            self.assertNotIn(original, commands[0])

        def mismatch(command, **kwargs):
            output = pathlib.Path(command[command.index("--output") + 1])
            output.write_bytes(b"{}\n")
            return mock.Mock(returncode=0)

        with mock.patch.object(GATE.subprocess, "run", side_effect=mismatch), \
             mock.patch.object(GATE, "_w12_blob_or_none", side_effect=blob), \
             mock.patch.object(GATE, "_git_text", return_value="f" * 40):
            with self.assertRaisesRegex(GATE.GateError, "not verifier-reproducible"):
                GATE._run_w12_r_verifier(paths, evidence, activation_commit)

    def test_w12_production_tree_uses_git_blob_oid_tab_path_lf_formula(self):
        listing = (
            b"100644 blob 1111111111111111111111111111111111111111\tsrchybrid/Z.cpp\0"
            b"100644 blob 2222222222222222222222222222222222222222\tsrchybrid/A.cpp\0"
        )
        expected = hashlib.sha256(
            b"2222222222222222222222222222222222222222\tsrchybrid/A.cpp\n"
            b"1111111111111111111111111111111111111111\tsrchybrid/Z.cpp\n"
        ).hexdigest()
        with mock.patch.object(GATE.subprocess, "check_output", return_value=listing):
            self.assertEqual(GATE._w12_production_tree("a" * 40), (expected, 2))

    def test_w12_r_v2_rejects_tree_tool_candidate_and_schema_mutations(self):
        activation_commit = "a" * 40
        paths = GATE._w12_r_artifact_paths(activation_commit)

        def validate(values, blobs, evidence, tool_blobs):
            def blob(commit, path):
                for key, artifact_path in paths.items():
                    if path == artifact_path:
                        return blobs[key]
                return tool_blobs.get(path)

            def current(path):
                for key, artifact_path in paths.items():
                    if path == artifact_path:
                        return blobs[key]
                return tool_blobs.get(path)

            with mock.patch.object(GATE, "_w12_blob_or_none", side_effect=blob), \
                 mock.patch.object(GATE, "_w12_current_or_none", side_effect=current), \
                 mock.patch.object(GATE, "_w12_production_tree", return_value=("1" * 64, 99)), \
                 mock.patch.object(GATE, "_run_w12_r_verifier"):
                GATE._validate_w12_r_artifacts({"r_evidence": evidence}, activation_commit, paths)

        def fresh():
            values, blobs, evidence, tool_blobs = self.r_v2_artifacts(activation_commit)
            return values, blobs, evidence, tool_blobs

        for mutate, message in (
            (lambda x: x["activation"].__setitem__("production_tree_sha256", "f" * 64), "production identity differs from Git A"),
            (lambda x: x["activation"].__setitem__("production_path_count", 98), "production identity differs from Git A"),
            (lambda x: x["activation"]["tool_sha256"].__setitem__("runner", "f" * 64), "tool hashes are not the immutable A tools"),
            (lambda x: x["browser_cdp_trace"].__setitem__("collector_sha256", "f" * 64), "collector is not the immutable A collector"),
            (lambda x: x["runtime"]["binding"].__setitem__("toolset_sha256", "f" * 64), "runtime.binding toolset differs"),
            (lambda x: x["runtime"]["candidate"].__setitem__("emule_sha256", "f" * 64), "runtime.candidate binary SHA differs"),
            (lambda x: x["browser_cdp_trace"].__setitem__("unreviewed", True), "closed schema drift"),
        ):
            values, blobs, evidence, tool_blobs = fresh()
            mutate(values)
            blobs = {key: json.dumps(value, sort_keys=True).encode("utf-8") for key, value in values.items()}
            evidence = self.r_evidence(activation_commit, blobs)
            evidence["verifier_sha256"] = hashlib.sha256(tool_blobs[GATE.W12_EVIDENCE_VERIFIER]).hexdigest()
            with self.assertRaisesRegex(GATE.GateError, message):
                validate(values, blobs, evidence, tool_blobs)

        values, blobs, evidence, tool_blobs = fresh()
        evidence["activation"]["sha256"] = "f" * 64
        with self.assertRaisesRegex(GATE.GateError, "absent or not immutable"):
            validate(values, blobs, evidence, tool_blobs)
        values, blobs, evidence, tool_blobs = fresh()
        blobs["activation"] = b'{"schema":"ese.v92.w12.activation/v2","schema":"ese.v92.w12.activation/v2"}'
        evidence = self.r_evidence(activation_commit, blobs)
        evidence["verifier_sha256"] = hashlib.sha256(tool_blobs[GATE.W12_EVIDENCE_VERIFIER]).hexdigest()
        with self.assertRaisesRegex(GATE.GateError, "duplicate JSON member"):
            validate(values, blobs, evidence, tool_blobs)

    def test_w12_r_rejects_verifier_detected_trace_request_manipulation(self):
        activation_commit = "a" * 40
        paths = GATE._w12_r_artifact_paths(activation_commit)
        _, blobs, evidence, tool_blobs = self.r_v2_artifacts(activation_commit)

        def blob(commit, path):
            for key, artifact_path in paths.items():
                if path == artifact_path:
                    return blobs[key]
            return tool_blobs.get(path)

        with mock.patch.object(
            GATE.subprocess, "run", return_value=mock.Mock(returncode=1)
        ), mock.patch.object(GATE, "_w12_blob_or_none", side_effect=blob), \
           mock.patch.object(GATE, "_git_text", return_value="f" * 40):
            with self.assertRaisesRegex(GATE.GateError, "verifier did not PASS"):
                # A nonzero verifier outcome models a manipulated request/trace:
                # the ratchet never accepts trace semantics on its own authority.
                GATE._run_w12_r_verifier(paths, evidence, activation_commit)

    def test_w12_r_rejects_extra_commit_path_before_running_verifier(self):
        activation_commit = "a" * 40
        h_commit = "b" * 40
        ledger = GATE.load(GATE.ACTIVATION)
        evidence = self.r_evidence(activation_commit)
        state = {
            "state": "active",
            "stage": "R",
            "activation_commit": activation_commit,
            "evidence": [],
            "r_evidence": evidence,
        }
        ledger["cards"]["W12"] = state
        ledger_path = GATE.ACTIVATION.relative_to(GATE.ROOT).as_posix()
        paths = GATE._w12_r_artifact_paths(activation_commit)
        expected_h = {
            "cards": {"W12": {
                "state": "active",
                "stage": "H",
                "activation_commit": activation_commit,
                "evidence": [],
                "r_evidence": None,
            }}
        }

        def changed(base, target):
            if (base, target) == (activation_commit, h_commit):
                return {ledger_path}
            if (base, target) == (h_commit, "HEAD"):
                return {ledger_path, *paths.values(), "artifacts/unreviewed.txt"}
            return set(self.card()["card_paths"])

        def strict(commit, path):
            if commit == activation_commit:
                return {"cards": {"W12": GATE._w12_planned_state()}}
            return expected_h

        with mock.patch.object(GATE, "_w12_dirty_paths", return_value=set()), \
             mock.patch.object(GATE, "_w12_exact_parent", return_value=GATE.W12_BASE_COMMIT), \
             mock.patch.object(GATE, "_is_ancestor", return_value=True), \
             mock.patch.object(GATE, "_w12_commit_changed_paths", side_effect=changed), \
             mock.patch.object(GATE, "_w12_resolve_r_history", return_value=(h_commit, "HEAD")), \
             mock.patch.object(GATE, "validate_w12_card_path_scope"), \
             mock.patch.object(GATE, "_w12_strict_json_blob", side_effect=strict), \
             mock.patch.object(GATE, "_w12_blob_or_none", return_value=b"same"), \
             mock.patch.object(GATE, "_w12_current_or_none", return_value=b"same"), \
             mock.patch.object(GATE, "_validate_w12_activation_evidence"), \
             mock.patch.object(GATE, "_validate_w12_r_artifacts") as verifier:
            with self.assertRaisesRegex(GATE.GateError, "only ledger plus five"):
                GATE.validate_w12_activation_state(self.card(), ledger)
            verifier.assert_not_called()


if __name__ == "__main__": unittest.main(verbosity=2)
