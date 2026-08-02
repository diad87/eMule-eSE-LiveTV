"""Freeze MOD-2.6 HTTP/static and socket response boundaries before extraction."""

from __future__ import annotations

import json
import pathlib
import subprocess
import unittest

from tools.architecture.verify_mod02_characterization import fingerprint


ROOT = pathlib.Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "docs" / "architecture" / "mod26_web_streaming_contract_v1.json"
OWNERSHIP = (
    ROOT / "docs" / "architecture" / "mod03_ownership_layering_contract_v1.json"
)


class Mod26WebStreamingCharacterizationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        cls.ownership = json.loads(OWNERSHIP.read_text(encoding="utf-8"))

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
            self.contract["invalid_input_policy"],
            "fail_closed_without_unbounded_allocation_or_busy_spin",
        )

    def test_exact_pre_extraction_seams_are_token_frozen(self) -> None:
        for module in self.contract["modules"]:
            source = subprocess.check_output(
                [
                    "git",
                    "show",
                    f"{self.contract['baseline_commit']}:{module['source']}",
                ],
                cwd=ROOT,
                text=True,
                encoding="utf-8",
            )
            self.assertEqual(
                fingerprint(
                    module["source"],
                    list(module["symbols"]),
                    {module["source"]: source},
                ),
                module["symbols"],
            )

    def test_owners_match_the_approved_mod03_plan(self) -> None:
        web = next(
            item
            for item in self.ownership["coordinators"]
            if item["name"] == "WebServer"
        )
        planned = {item["module"]: item for item in web["planned_modules"]}
        for module in self.contract["modules"]:
            approved = planned[module["name"]]
            for field in (
                "owner_before",
                "owner_after",
                "layer",
                "responsibility",
            ):
                self.assertEqual(module[field], approved[field])

    def test_range_and_streaming_hardening_is_closed(self) -> None:
        hardening = self.contract["hardening"]
        self.assertEqual(
            hardening["supported_ranges"],
            ["start-end", "start-", "-suffix"],
        )
        self.assertEqual(hardening["multiple_ranges"], "rejected_with_416")
        self.assertEqual(
            hardening["unsatisfiable_range"],
            "416_with_content_range_wildcard",
        )
        self.assertEqual(hardening["arithmetic"], "unsigned_64_bit_overflow_safe")
        self.assertEqual(hardening["socket_queue_bytes_max"], 2 * 1024 * 1024)
        self.assertEqual(hardening["socket_queue_chunks_max"], 64)
        self.assertEqual(hardening["queue_exhaustion"], "fail_closed")
        self.assertEqual(hardening["allocation_failure"], "fail_closed")
        self.assertEqual(
            hardening["tls_want_read_or_write"],
            "yield_to_event_loop",
        )

    def test_characterized_sources_expose_every_known_legacy_hazard(self) -> None:
        web = subprocess.check_output(
            [
                "git",
                "show",
                f"{self.contract['baseline_commit']}:srchybrid/WebServer.cpp",
            ],
            cwd=ROOT,
            text=True,
            encoding="utf-8",
        )
        socket = subprocess.check_output(
            [
                "git",
                "show",
                f"{self.contract['baseline_commit']}:srchybrid/WebSocket.cpp",
            ],
            cwd=ROOT,
            text=True,
            encoding="utf-8",
        )
        socket_header = subprocess.check_output(
            [
                "git",
                "show",
                f"{self.contract['baseline_commit']}:srchybrid/WebSocket.h",
            ],
            cwd=ROOT,
            text=True,
            encoding="utf-8",
        )
        self.assertIn("new BYTE[fileSize]", web)
        self.assertIn("new char[filesize]", web)
        self.assertNotIn("Content-Range:", web)
        self.assertNotIn("Accept-Ranges:", web)
        self.assertIn("class CChunk", socket_header)
        self.assertNotIn("m_queuedBytes", socket)
        self.assertGreaterEqual(socket.count("MBEDTLS_ERR_SSL_WANT_READ"), 3)


if __name__ == "__main__":
    unittest.main()
