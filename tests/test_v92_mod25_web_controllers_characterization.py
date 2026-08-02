"""Freeze the exact pre-extraction Web controller behavior for MOD-2.5."""

from __future__ import annotations

import json
import pathlib
import subprocess
import unittest

from tools.architecture.verify_mod02_characterization import fingerprint


ROOT = pathlib.Path(__file__).resolve().parents[1]
CONTRACT = (
    ROOT / "docs" / "architecture" / "mod25_web_controllers_contract_v1.json"
)
OWNERSHIP = (
    ROOT / "docs" / "architecture" / "mod03_ownership_layering_contract_v1.json"
)


class Mod25WebControllersCharacterizationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        cls.ownership = json.loads(OWNERSHIP.read_text(encoding="utf-8"))
        cls.baseline_source = subprocess.check_output(
            [
                "git",
                "show",
                f"{cls.contract['baseline_commit']}:srchybrid/WebServer.cpp",
            ],
            cwd=ROOT,
            text=True,
            encoding="utf-8",
        )

    def test_baseline_is_immutable_and_ancestral(self) -> None:
        completed = subprocess.run(
            [
                "git",
                "merge-base",
                "--is-ancestor",
                self.contract["baseline_commit"],
                "HEAD",
            ],
            cwd=ROOT,
            check=False,
        )
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(
            self.contract["valid_input_compatibility"],
            "token_and_output_exact",
        )
        self.assertEqual(
            self.contract["invalid_input_policy"],
            "fail_closed_without_mutation",
        )

    def test_exact_controller_seams_are_token_frozen(self) -> None:
        override = {
            "srchybrid/WebServer.cpp": self.baseline_source,
        }
        for module in self.contract["modules"]:
            self.assertEqual(
                fingerprint(
                    self.contract["source_coordinator"],
                    list(module["symbols"]),
                    override,
                ),
                module["symbols"],
            )

    def test_owners_match_the_approved_mod03_plan(self) -> None:
        web = next(
            item
            for item in self.ownership["coordinators"]
            if item["name"] == "WebServer"
        )
        planned = {
            item["module"]: item for item in web["planned_modules"]
        }
        for module in self.contract["modules"]:
            approved = planned[module["name"]]
            for field in (
                "owner_before",
                "owner_after",
                "layer",
                "responsibility",
            ):
                self.assertEqual(module[field], approved[field])

    def test_transfer_action_and_sort_vocabulary_is_complete(self) -> None:
        transfer = self.contract["modules"][0]
        for token in (
            *transfer["file_operations"],
            *transfer["friend_operations"],
            *transfer["sort_tokens"],
        ):
            self.assertIn(f'_T("{token}")', self.baseline_source)
        self.assertEqual(len(transfer["file_operations"]), 12)
        self.assertEqual(len(transfer["sort_tokens"]), 21)

    def test_search_contract_freezes_methods_types_and_limits(self) -> None:
        search = self.contract["modules"][1]
        for token, enum_name in search["methods"].items():
            if token != "default":
                self.assertIn(f'_T("{token}")', self.baseline_source)
            self.assertIn(enum_name, self.baseline_source)
        for constant in (
            "ED2KFTSTR_ARCHIVE",
            "ED2KFTSTR_AUDIO",
            "ED2KFTSTR_CDIMAGE",
            "ED2KFTSTR_DOCUMENT",
            "ED2KFTSTR_IMAGE",
            "ED2KFTSTR_PROGRAM",
            "ED2KFTSTR_VIDEO",
            "ED2KFTSTR_EMULECOLLECTION",
        ):
            self.assertIn(constant, self.baseline_source)
        self.assertIn(
            f'> {search["availability_max"]}',
            self.baseline_source,
        )
        self.assertIn(
            f"resToken.GetLength() == {search['download_hash_hex_length']}",
            self.baseline_source,
        )

    def test_shared_sort_and_priority_vocabulary_is_complete(self) -> None:
        shared = self.contract["modules"][2]
        for token in (*shared["sort_tokens"], *shared["priority_tokens"]):
            self.assertIn(f'_T("{token}")', self.baseline_source)
        self.assertEqual(len(shared["sort_tokens"]), 12)
        self.assertEqual(len(shared["priority_tokens"]), 6)

    def test_hardening_closes_every_hostile_index_and_mutation(self) -> None:
        hardening = self.contract["hardening"]
        self.assertEqual(
            hardening["column_index_limits"],
            {
                "download": 8,
                "upload": 5,
                "queue": 4,
                "search": 4,
                "shared": 7,
            },
        )
        self.assertTrue(hardening["admin_required_for_mutation"])
        for field in (
            "unknown_operation",
            "unknown_priority",
            "invalid_hash",
        ):
            self.assertEqual(hardening[field], "ignored")
        self.assertEqual(hardening["numeric_overflow"], "rejected")


if __name__ == "__main__":
    unittest.main()
