"""MOD-0.3 gate: ownership, layers, threads and locks are executable."""

from __future__ import annotations

import copy
import importlib.util
import json
import pathlib
import re
import subprocess
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "docs" / "architecture" / "mod03_ownership_layering_contract_v1.json"
INVENTORY = ROOT / "docs" / "architecture" / "mod01_architecture_inventory_v1.json"
MATRIX = ROOT / "docs" / "architecture" / "mod02_characterization_matrix_v1.json"
ADR = ROOT / "docs" / "architecture" / "ADR_MOD03_OWNERSHIP_AND_LAYERING_V1.md"
SCRIPT = ROOT / "tools" / "architecture" / "verify_mod03_architecture_contract.py"

SPEC = importlib.util.spec_from_file_location("mod03_verifier", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


class Mod03ArchitectureContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        cls.inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))
        cls.matrix = json.loads(MATRIX.read_text(encoding="utf-8"))

    def validate(self, contract: dict) -> None:
        VERIFIER.validate(contract, self.inventory, self.matrix)

    def assert_invalid(self, contract: dict, message: str) -> None:
        with self.assertRaisesRegex(VERIFIER.ContractError, message):
            self.validate(contract)

    def test_contract_is_exactly_bound_and_changes_no_behavior(self) -> None:
        self.validate(self.contract)
        self.assertEqual(
            self.contract["schema"],
            "ese.mod03.ownership-layering-contract/v1",
        )
        self.assertEqual(self.contract["status"], "PASS")
        self.assertEqual(set(self.contract["non_goals"].values()), {False})
        self.assertEqual(
            {item["owner"] for item in self.contract["coordinators"]},
            {"CLiveTunnel", "CWebServer", "CLiveStreamManager"},
        )
        self.assertEqual(
            self.contract["global_rules"]["lock_order"],
            ["registry", "pending", "queue", "timer_or_leaf"],
        )
        self.assertEqual(
            self.contract["global_rules"]["external_callbacks"],
            "snapshot_unlock_invoke",
        )
        adr = re.sub(r"\s+", " ", ADR.read_text(encoding="utf-8"))
        for required in (
            "no crea owners", "no mueve campos ni funciones",
            "no inicia una extracción", "no cambia wire",
            "formatos persistidos", "Ninguna extracción",
            "snapshot -> unlock -> invoke",
        ):
            self.assertIn(required, adr)
        async_counts = {
            item["owner"]: item["inventory_projection"][
                "external_async_callback_edges"
            ]["count"]
            for item in self.contract["coordinators"]
        }
        self.assertEqual(
            async_counts,
            {"CLiveTunnel": 0, "CWebServer": 0, "CLiveStreamManager": 1},
        )
        module_counts = {
            item["owner"]: len(item["planned_modules"])
            for item in self.contract["coordinators"]
        }
        self.assertEqual(
            module_counts,
            {"CLiveTunnel": 10, "CWebServer": 10, "CLiveStreamManager": 9},
        )
        for coordinator in self.contract["coordinators"]:
            for module in coordinator["planned_modules"]:
                self.assertEqual(module["owner_before"], coordinator["owner"])
                self.assertEqual(module["owner_after"], module["module"])
                self.assertNotIn("fields", module)
                self.assertNotIn("records", module)

    def test_cycle_and_layer_violation_fixtures_fail_in_memory(self) -> None:
        cyclic = copy.deepcopy(self.contract)
        cyclic["layer_model"]["allowed_edges"].append(
            ["foundation", "composition"]
        )
        with self.assertRaisesRegex(VERIFIER.ContractError, "layer cycle"):
            self.validate(cyclic)

        forbidden = copy.deepcopy(self.contract)
        forbidden["layer_model"]["allowed_edges"].append(
            ["application", "adapters"]
        )
        with self.assertRaisesRegex(VERIFIER.ContractError, "layer violation"):
            self.validate(forbidden)

    def test_duplicate_owner_fixture_fails_in_memory(self) -> None:
        mutated = copy.deepcopy(self.contract)
        records = mutated["coordinators"][0]["record_ownership"]
        records.append(copy.deepcopy(records[0]))
        with self.assertRaisesRegex(
            VERIFIER.ContractError, "duplicate state record owner"
        ):
            self.validate(mutated)

    def test_lock_inversion_fixture_fails_in_memory(self) -> None:
        mutated = copy.deepcopy(self.contract)
        mutated["coordinators"][0]["lock_contract"][
            "permitted_nested_edges"
        ].append(["pending", "registry"])
        with self.assertRaisesRegex(VERIFIER.ContractError, "lock inversion"):
            self.validate(mutated)

    def test_callback_under_lock_fixture_fails_in_memory(self) -> None:
        mutated = copy.deepcopy(self.contract)
        mutated["coordinators"][0]["external_callback_contracts"][0][
            "under_internal_lock"
        ] = True
        with self.assertRaisesRegex(
            VERIFIER.ContractError, "external callback under lock"
        ):
            self.validate(mutated)

    def test_complete_planned_module_objects_are_frozen(self) -> None:
        layer = copy.deepcopy(self.contract)
        layer["coordinators"][0]["planned_modules"][0]["layer"] = "application"
        self.assert_invalid(layer, "planned module layer drift")

        responsibility = copy.deepcopy(self.contract)
        responsibility["coordinators"][0]["planned_modules"][0][
            "responsibility"
        ] = "different responsibility"
        self.assert_invalid(responsibility, "planned module responsibility drift")

    def test_complete_thread_callback_and_include_contracts_are_frozen(self) -> None:
        missing_thread = copy.deepcopy(self.contract)
        missing_thread["coordinators"][0]["thread_affinity"].pop()
        self.assert_invalid(missing_thread, "complete thread_affinity contract drift")

        empty_marshal = copy.deepcopy(self.contract)
        empty_marshal["coordinators"][0]["thread_affinity"][0]["marshal"] = ""
        self.assert_invalid(empty_marshal, "marshal contains an empty value")

        wrong_marshal = copy.deepcopy(self.contract)
        wrong_marshal["coordinators"][0]["thread_affinity"][0][
            "marshal"
        ] = "direct mutation"
        self.assert_invalid(wrong_marshal, "complete thread_affinity contract drift")

        callback_rule = copy.deepcopy(self.contract)
        callback_rule["coordinators"][0]["external_callback_contracts"][0][
            "rule"
        ] = "invoke_under_lock"
        self.assert_invalid(
            callback_rule, "complete external_callback_contracts contract drift"
        )

        include_rule = copy.deepcopy(self.contract)
        del include_rule["coordinators"][0]["include_rules"][
            "sibling_coordinator_header"
        ]
        self.assert_invalid(include_rule, "complete include_rules contract drift")

    def test_layer_universe_and_forbidden_complement_are_frozen(self) -> None:
        extra_layer = copy.deepcopy(self.contract)
        extra_layer["layer_model"]["layers"].append("utility")
        self.assert_invalid(extra_layer, "ordered layer list drift")

        empty = copy.deepcopy(self.contract)
        empty["layer_model"]["forbidden_edges"] = []
        self.assert_invalid(empty, "exhaustive ordered complement")

        duplicate = copy.deepcopy(self.contract)
        duplicate["layer_model"]["forbidden_edges"].append(
            copy.deepcopy(duplicate["layer_model"]["forbidden_edges"][0])
        )
        self.assert_invalid(duplicate, "duplicate forbidden layer edge")

    def test_scope_rules_locks_stops_and_approval_are_frozen(self) -> None:
        lock_edge = copy.deepcopy(self.contract)
        lock_edge["coordinators"][0]["lock_contract"][
            "permitted_nested_edges"
        ].pop()
        self.assert_invalid(lock_edge, "complete lock contract drift")

        stop_text = copy.deepcopy(self.contract)
        stop_text["global_stop_conditions"][0]["condition"] += " altered"
        self.assert_invalid(stop_text, "complete ordered global stop conditions drift")

        scope = copy.deepcopy(self.contract)
        scope["scope"] = "architecture contract"
        self.assert_invalid(scope, "scope drift")

        global_rule = copy.deepcopy(self.contract)
        global_rule["global_rules"]["ownership"] += " altered"
        self.assert_invalid(global_rule, "complete global rules drift")

        next_gate = copy.deepcopy(self.contract)
        next_gate["approval"]["next_gate"] = "MOD-1"
        self.assert_invalid(next_gate, "complete MOD-0.3 approval policy drift")

    def test_exact_schema_rejects_ids_paths_and_unknown_keys(self) -> None:
        contract_id = copy.deepcopy(self.contract)
        contract_id["contract_id"] += ":drift"
        self.assert_invalid(contract_id, "contract_id drift")

        matrix_path = copy.deepcopy(self.contract)
        matrix_path["baselines"]["characterization"][
            "matrix_path"
        ] = "wrong.json"
        self.assert_invalid(matrix_path, "characterization baseline object drift")

        record_extra = copy.deepcopy(self.contract)
        record_extra["coordinators"][0]["record_ownership"][0][
            "owner_after"
        ] = "invented"
        self.assert_invalid(record_extra, r"record_ownership\[0\] keys drift")

        top_extra = copy.deepcopy(self.contract)
        top_extra["unexpected"] = True
        self.assert_invalid(top_extra, "top-level contract keys drift")

        coordinator_extra = copy.deepcopy(self.contract)
        coordinator_extra["coordinators"][0]["unexpected"] = True
        self.assert_invalid(coordinator_extra, r"coordinators\[0\] keys drift")

    def test_adr_and_json_are_clean_utf8_without_mojibake(self) -> None:
        for path in (ADR, CONTRACT):
            text = path.read_text(encoding="utf-8")
            for forbidden in ("\u00c3", "\u00e2\u20ac", "\ufffd"):
                self.assertNotIn(forbidden, text, f"{path}: mojibake {forbidden!r}")
        contract_text = CONTRACT.read_text(encoding="utf-8")
        self.assertTrue(contract_text.isascii(), "contract JSON must remain ASCII-safe")
        json.loads(contract_text)

    def test_cli_positive_and_all_negative_fixtures(self) -> None:
        for mode in ("--verify", "--negative-fixtures"):
            completed = subprocess.run(
                [sys.executable, str(SCRIPT), mode],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(
                completed.returncode, 0, completed.stdout + completed.stderr
            )
            if mode == "--negative-fixtures":
                self.assertIn("(25 negative fixtures)", completed.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
