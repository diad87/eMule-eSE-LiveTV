"""Host contract for the frozen MOD-0.1 coordinator inventory."""

from __future__ import annotations

import hashlib
import json
import pathlib
import subprocess
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "docs" / "architecture" / "mod01_architecture_inventory_v1.json"
SCRIPT = ROOT / "tools" / "architecture" / "generate_mod01_architecture_inventory.py"
OVERLAYS = ROOT / "docs" / "architecture" / "mod01_approved_overlays_v1.json"
BASELINE = "b875d3dd61a2d675b2138d61161f0a8fec9d9888"
EXPECTED = {
    "LiveTunnel": ("CLiveTunnel", "srchybrid/LiveTunnel.cpp", "srchybrid/LiveTunnel.h"),
    "WebServer": ("CWebServer", "srchybrid/WebServer.cpp", "srchybrid/WebServer.h"),
    "LiveStreamManager": (
        "CLiveStreamManager", "srchybrid/LiveStreamManager.cpp", "srchybrid/LiveStreamManager.h",
    ),
}
EXPECTED_COUNTS = {
    "LiveTunnel": {
        "source_functions": 208, "inline_functions": 6, "fields": 106,
        "state_records": 34, "member_locks": 6, "local_locks": 0,
        "lock_operations": 263, "lock_acquisitions": 235, "entrypoints": 37, "seams": 4,
    },
    "WebServer": {
        "source_functions": 66, "inline_functions": 4, "fields": 8,
        "state_records": 2, "member_locks": 0, "local_locks": 0,
        "lock_operations": 0, "lock_acquisitions": 0, "entrypoints": 57, "seams": 4,
    },
    "LiveStreamManager": {
        "source_functions": 79, "inline_functions": 29, "fields": 65,
        "state_records": 8, "member_locks": 1, "local_locks": 1,
        "lock_operations": 41, "lock_acquisitions": 36, "entrypoints": 16, "seams": 1,
    },
}


class Mod01ArchitectureInventoryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))
        cls.by_name = {item["name"]: item for item in cls.inventory["monoliths"]}

    def test_inventory_is_reproducible_and_worktree_is_frozen(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(SCRIPT), "--verify"], cwd=ROOT,
            text=True, capture_output=True, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_mod02_overlay_is_exactly_hash_bound_and_rejects_byte_drift(self) -> None:
        overlays = json.loads(OVERLAYS.read_text(encoding="utf-8"))
        self.assertEqual(overlays["schema"], "ese.mod01.approved-overlays/v1")
        self.assertEqual(overlays["baseline_commit"], BASELINE)
        self.assertEqual({item["path"] for item in overlays["overlays"]}, {
            "srchybrid/LiveTunnel.cpp", "srchybrid/LiveTunnel.h",
            "srchybrid/WebServer.cpp", "srchybrid/WebServer.h",
            "srchybrid/LiveStreamManager.cpp", "srchybrid/LiveStreamManager.h",
        })
        for item in overlays["overlays"]:
            self.assertRegex(item["baseline_sha256"], r"^[0-9a-f]{64}$")
            self.assertRegex(item["overlay_sha256"], r"^[0-9a-f]{64}$")
            self.assertTrue(item["task"] and item["reason"])
        completed = subprocess.run(
            [sys.executable, str(SCRIPT), "--negative-overlay-fixture"], cwd=ROOT,
            text=True, capture_output=True, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_baseline_scope_and_machine_inventory_are_exact(self) -> None:
        self.assertEqual(self.inventory["baseline_commit"], BASELINE)
        self.assertEqual(set(self.by_name), set(EXPECTED))
        self.assertEqual(
            self.inventory["scope"],
            "inventory only: no extraction or production behavior change",
        )
        privacy = self.inventory["privacy_sanitization"]
        self.assertFalse(privacy["contains_raw_network_endpoints"])
        self.assertFalse(privacy["contains_credentials_or_session_values"])
        self.assertGreaterEqual(len(self.inventory["parser_limitations"]), 4)

    def test_files_hashes_lines_functions_and_owners_are_frozen(self) -> None:
        for name, (owner, source, header) in EXPECTED.items():
            record = self.by_name[name]
            self.assertEqual(record["owner"], owner)
            files = {item["path"]: item for item in record["files"]}
            self.assertEqual(set(files), {source, header})
            for path, item in files.items():
                blob = subprocess.check_output(["git", "show", f"{BASELINE}:{path}"], cwd=ROOT)
                self.assertEqual(item["sha256"], hashlib.sha256(blob).hexdigest())
                self.assertEqual(item["loc_physical"], len(blob.decode("utf-8", errors="replace").splitlines()))
                self.assertGreater(item["loc_logical_approx"], 0)
            self.assertEqual(
                len(record["qualified_source_definitions"]),
                EXPECTED_COUNTS[name]["source_functions"],
            )
            self.assertEqual(
                len(record["inline_header_definitions"]),
                EXPECTED_COUNTS[name]["inline_functions"],
            )
            for function in (
                record["qualified_source_definitions"] + record["inline_header_definitions"]
            ):
                self.assertTrue(function["name"].startswith(owner + "::"))
                self.assertIn(function["file"], files)
                self.assertGreaterEqual(function["line_start"], 1)
                self.assertGreaterEqual(function["line_end_approx"], function["line_start"])
                self.assertGreater(function["length_approx"], 0)
                self.assertTrue(function["role"])
                self.assertIn(
                    function["role_basis"],
                    {"name_heuristic", "explicit_callback_assignment"},
                )
            for field in record["mutable_fields"]:
                self.assertEqual(field["owner"], owner)
                self.assertTrue(field["name"].startswith("m_"))
                self.assertEqual(field["file"], header)
                self.assertEqual(field["scope"], "owner_class_body")
            self.assertEqual(len(record["mutable_fields"]), EXPECTED_COUNTS[name]["fields"])
            self.assertEqual(len(record["state_records"]), EXPECTED_COUNTS[name]["state_records"])
            for state_record in record["state_records"]:
                self.assertTrue(state_record["owner"])
                self.assertEqual(state_record["file"], header)
                self.assertTrue(state_record["declaration_scope"])
                self.assertTrue(state_record["contained_by_owner"])
                self.assertIsInstance(state_record["containment_relationships"], list)
                for field in state_record["fields"]:
                    self.assertEqual(field["owner"], state_record["owner"])
                    self.assertNotEqual(field["name"], "UNPARSED")

    def test_includes_locks_threads_seams_and_stop_conditions_are_present(self) -> None:
        for record in self.by_name.values():
            expected_counts = EXPECTED_COUNTS[record["name"]]
            direct_includes = record["direct_includes"]
            self.assertEqual(set(direct_includes), {item["path"] for item in record["files"]})
            self.assertTrue(any(direct_includes.values()))
            locks = record["locks"]
            self.assertEqual(len(locks["member_fields"]), expected_counts["member_locks"])
            self.assertEqual(len(locks["local_definitions"]), expected_counts["local_locks"])
            self.assertEqual(len(locks["operation_sites"]), expected_counts["lock_operations"])
            self.assertEqual(len(locks["acquisition_sites"]), expected_counts["lock_acquisitions"])
            self.assertIn("target_order", locks)
            self.assertIn("UNSPECIFIED", locks["target_order"])
            for site in locks["acquisition_sites"]:
                self.assertGreaterEqual(site["line"], 1)
                self.assertRegex(site["lock"], r"^[ms]_")
                self.assertTrue(site["function"])
                self.assertIn(
                    site["scope"], {"lexical_function_range", "lexical_source_helper"},
                )
            for edge in locks["lexical_acquisition_sequence_edges"]:
                self.assertTrue(edge["function"].startswith(record["owner"] + "::"))
                self.assertRegex(edge["before"], r"^[ms]_")
                self.assertRegex(edge["after"], r"^[ms]_")
                self.assertEqual(
                    edge["scope"], "same_function_source_sequence_not_held-set_proof",
                )
            self.assertIsInstance(record["thread_task_callback_entrypoints"], list)
            self.assertIsInstance(record["external_async_callback_edges"], list)
            self.assertIsInstance(record["existing_test_seams"], list)
            self.assertEqual(len(record["thread_task_callback_entrypoints"]), expected_counts["entrypoints"])
            self.assertEqual(len(record["existing_test_seams"]), expected_counts["seams"])
            for seam in record["existing_test_seams"]:
                self.assertEqual(seam["evidence_kind"], "lexical_reference_not_coverage_proof")
            self.assertTrue(record["candidate_responsibilities"])
            self.assertTrue(record["risks"])
            self.assertTrue(record["stop_conditions"])
        tunnel_sites = self.by_name["LiveTunnel"]["locks"]["acquisition_sites"]
        self.assertTrue(any(site["line"] == 6743 and site["lock"] == "m_pendingLock"
                            for site in tunnel_sites))
        stream_locks = self.by_name["LiveStreamManager"]["locks"]
        self.assertEqual(
            stream_locks["local_definitions"],
            [{
                "file": "srchybrid/LiveStreamManager.cpp",
                "line": 1884,
                "name": "s_liveRequestRateLock",
                "storage": "anonymous_namespace_static",
                "type": "CCriticalSection",
            }],
        )
        self.assertTrue(any(
            site["line"] == 1889 and site["lock"] == "s_liveRequestRateLock"
            for site in stream_locks["acquisition_sites"]
        ))
        self.assertTrue(any(
            site["line"] == 5064 and site["operation"] == "direct_lock"
            for site in stream_locks["acquisition_sites"]
        ))
        tunnel = self.by_name["LiveTunnel"]
        tunnel_fields = {field["name"] for field in tunnel["mutable_fields"]}
        self.assertTrue({
            "m_k6TicketSecret", "m_k6EconomyInputs",
            "m_k6ReleaseChallenge", "m_k6GuardNodePub",
        }.issubset(tunnel_fields))
        stream_fields = {
            field["name"] for field in self.by_name["LiveStreamManager"]["mutable_fields"]
        }
        self.assertTrue({"m_broadcasterPrivkey", "m_pendingGhostKey"}.issubset(stream_fields))
        web_records = {
            record["owner"]: record for record in self.by_name["WebServer"]["state_records"]
        }
        self.assertEqual(set(web_records), {"GlobalParams", "WebTemplates"})
        self.assertEqual(web_records["GlobalParams"]["contained_by_fields"], ["m_Params"])
        self.assertEqual(web_records["WebTemplates"]["contained_by_fields"], ["m_Templates"])
        callbacks = tunnel["thread_task_callback_entrypoints"]
        self.assertTrue(any(
            entry["line"] == 318
            and entry["evidence_kind"] == "dispatch_or_thread_token"
            and {"CALLBACK", "K6Class5TimerProc"}.issubset(entry["markers"])
            for entry in callbacks
        ))
        callback_markers = {
            marker
            for entry in callbacks
            if entry["evidence_kind"] == "explicit_callback_assignment"
            for marker in entry["markers"]
        }
        self.assertEqual(
            callback_markers,
            {"CLiveTunnel::K6AllowTicketTarget", "CLiveTunnel::K6ConsumeTicket"},
        )
        tunnel_roles = {
            function["name"]: (function["role"], function["role_basis"])
            for function in tunnel["qualified_source_definitions"]
        }
        self.assertEqual(
            tunnel_roles["CLiveTunnel::K6AllowTicketTarget"],
            ("event_or_callback_handler", "explicit_callback_assignment"),
        )
        self.assertIn("CLiveTunnel::CLiveTunnel", tunnel_roles)
        tunnel_records = {
            record["owner"]: record for record in tunnel["state_records"]
        }
        self.assertEqual(
            tunnel_records["K6ShapedQueuedRecord"]["containment_relationships"][0]["owner"],
            "K6ShapedLinkState",
        )
        self.assertEqual(
            tunnel_records["K6QueuedOriginFrame"]["containment_relationships"][0]["owner"],
            "K6OriginStreamRuntime",
        )
        self.assertEqual(
            tunnel_records["ExitLiveSub"]["containment_relationships"][0]["owner"],
            "ExitStreamProxy",
        )
        stream_records = {
            record["owner"]: record
            for record in self.by_name["LiveStreamManager"]["state_records"]
        }
        self.assertEqual(
            stream_records["PendingPing"]["containment_relationships"],
            [{
                "owner": "CLiveStreamManager",
                "fields": ["m_pendingPings"],
                "via_alias": "PendingPingMap",
            }],
        )
        web_roles = {
            function["name"]: function["role"]
            for function in (
                self.by_name["WebServer"]["qualified_source_definitions"]
                + self.by_name["WebServer"]["inline_header_definitions"]
            )
        }
        self.assertEqual(web_roles["CWebServer::_ProcessURL"], "event_or_callback_handler")
        self.assertEqual(web_roles["CWebServer::_GetIsTempDisabled"], "query_or_snapshot")
        self.assertEqual(
            web_roles["CWebServer::CWebServer"], "lifecycle_or_state_transition",
        )
        web_callbacks = self.by_name["WebServer"]["thread_task_callback_entrypoints"]
        self.assertEqual(
            {
                marker
                for entry in web_callbacks
                if entry["evidence_kind"] == "explicit_sync_callback_assignment"
                for marker in entry["markers"]
            },
            {
                "CWebServer::_ServerCmp", "CWebServer::_DownloadCmp",
                "CWebServer::_UploadCmp", "CWebServer::_SharedCmp",
            },
        )
        stream_roles = {
            function["name"]: function["role"]
            for function in self.by_name["LiveStreamManager"]["qualified_source_definitions"]
        }
        self.assertEqual(
            stream_roles["CLiveStreamManager::CLiveStreamManager"],
            "lifecycle_or_state_transition",
        )
        stream = self.by_name["LiveStreamManager"]
        self.assertEqual(len(stream["external_async_callback_edges"]), 1)
        async_edge = stream["external_async_callback_edges"][0]
        self.assertEqual(
            async_edge["edge"],
            "CRTMPIngest watcher thread -> chunkCb -> CLiveStreamManager::FeedSegment",
        )
        self.assertEqual(async_edge["registration_lines"], [305, 307, 315, 317])
        self.assertTrue(any(
            entry["line"] == 298
            and entry["evidence_kind"] == "explicit_async_worker_callback"
            and entry["registration_lines"] == [305, 307, 315, 317]
            for entry in stream["thread_task_callback_entrypoints"]
        ))


if __name__ == "__main__":
    unittest.main(verbosity=2)
