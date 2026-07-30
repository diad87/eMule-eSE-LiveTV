from __future__ import annotations

import json
import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
ESE = ROOT / "srchybrid" / "eSE"
CONTRACT = ROOT / "docs" / "architecture" / "mod42_async_boundaries_contract_v1.json"
BASELINE = "fa8ed3c525fad3b36a57086ed78ade34210a306e"
SYNC_FS = re.compile(
    r"\b(?:readFileSync|writeFileSync|appendFileSync|existsSync|mkdirSync|"
    r"readdirSync|statSync|unlinkSync|renameSync|copyFileSync|rmSync|"
    r"openSync|fstatSync|closeSync|readSync)\b"
)


def production_js() -> list[pathlib.Path]:
    ignored_parts = {"node_modules", "_deprecated", "test", "vendor"}
    return [
        path
        for path in ESE.rglob("*.js")
        if not ignored_parts.intersection(path.parts)
        and path.name != "_player_bundle.js"
    ]


class Mod42AsyncBoundariesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))

    def test_contract_freezes_bounded_scope(self) -> None:
        self.assertEqual(
            self.contract["schema"],
            "ese.mod42.async-boundaries-contract/v1",
        )
        self.assertEqual(self.contract["baseline_commit"], BASELINE)
        runner = self.contract["process_runner"]
        self.assertTrue(runner["sole_child_process_owner"])
        self.assertFalse(runner["shell"])
        self.assertEqual(runner["maximum_timeout_ms"], 30000)
        self.assertEqual(runner["default_max_output_bytes"], 1024 * 1024)
        self.assertEqual(runner["maximum_output_bytes"], 4 * 1024 * 1024)

    def test_runner_is_the_only_production_child_process_owner(self) -> None:
        owners = []
        for path in production_js():
            source = path.read_text(encoding="utf-8", errors="replace")
            if "child_process" in source:
                owners.append(path.relative_to(ROOT).as_posix())
            self.assertNotRegex(source, r"\b(?:execSync|spawnSync|execFileSync)\b")
        self.assertEqual(owners, ["srchybrid/eSE/bounded_process_runner.js"])

    def test_runner_enforces_no_shell_timeout_output_and_argument_bounds(self) -> None:
        source = (ESE / "bounded_process_runner.js").read_text(encoding="utf-8")
        for marker in (
            "MAX_TIMEOUT_MS = 30000",
            "DEFAULT_MAX_OUTPUT_BYTES = 1024 * 1024",
            "MAX_OUTPUT_BYTES = 4 * 1024 * 1024",
            "args.length > 256",
            "windowsHide: true",
            "shell: false",
            "outputExceeded = true",
            "timedOut = true",
            "terminateSpawned(child)",
            "process.kill(-pid, signal)",
            "signalTree('SIGKILL')",
        ):
            self.assertIn(marker, source)

    def test_route_handlers_have_no_synchronous_filesystem_calls(self) -> None:
        for path in sorted((ESE / "routes").glob("*.js")):
            source = path.read_text(encoding="utf-8", errors="replace")
            self.assertIsNone(SYNC_FS.search(source), path.name)

        channel = (ESE / "eSE-live" / "channel_api.js").read_text(encoding="utf-8")
        handler = channel[channel.index("function handleRoute("):]
        self.assertIsNone(SYNC_FS.search(handler))
        startup = channel[:channel.index("function handleRoute(")]
        self.assertEqual(len(SYNC_FS.findall(startup)), 3)

    def test_async_status_stream_and_path_safety_contracts_remain_explicit(self) -> None:
        v1 = (ESE / "routes" / "v1_routes.js").read_text(encoding="utf-8")
        stream_part = (ESE / "routes" / "stream_part.js").read_text(encoding="utf-8")
        completed = (ESE / "routes" / "stream_completed.js").read_text(encoding="utf-8")
        channel = (ESE / "eSE-live" / "channel_api.js").read_text(encoding="utf-8")
        self.assertIn("currentEmuleRunning().then", v1)
        self.assertIn("() => false", v1)
        self.assertIn("isWithinBase(", stream_part)
        self.assertIn("fs.promises.access", stream_part)
        self.assertIn("createDisconnectGuard(req, res", stream_part)
        self.assertIn("runProcess(\n      'powershell'", stream_part)
        self.assertIn("stderrLog = (stderrLog + d.toString()).slice(-2048)", stream_part)
        self.assertIn("runProcess(", completed)
        self.assertIn("fs.promises.open", completed)
        self.assertIn("createDisconnectGuard(req, res", completed)
        self.assertIn("if (disconnect.checkNow()) return", completed)
        self.assertIn("pipeFileResponse(", channel)
        self.assertIn("fs.promises.stat", channel)

    def test_composition_root_stays_within_mod41_hard_stop(self) -> None:
        server = (ESE / "server.js").read_text(encoding="utf-8")
        self.assertLessEqual(len(server.splitlines()), 300)
        self.assertIn("async function startServer()", server)
        self.assertIn("await hwEncoderMod.detect(", server)

    def test_async_lifecycle_work_is_serialized_and_awaited_before_exit(self) -> None:
        server = (ESE / "server.js").read_text(encoding="utf-8")
        cleanup = (ESE / "cleanup.js").read_text(encoding="utf-8")
        emule = (ESE / "emule_api.js").read_text(encoding="utf-8")
        pipeline = (ESE / "eSE-live" / "ffmpeg_pipeline.js").read_text(
            encoding="utf-8"
        )
        rtmp = (ESE / "eSE-live" / "rtmp_server.js").read_text(encoding="utf-8")

        self.assertNotIn("process.on('SIGINT'", server)
        self.assertNotIn("process.on('SIGTERM'", server)
        self.assertIn("await killOrphanedFFmpeg()", cleanup)
        self.assertIn("void gracefulShutdown(signal).finally(", cleanup)
        self.assertIn("process.once('SIGINT'", cleanup)
        self.assertIn("process.once('SIGTERM'", cleanup)
        self.assertIn("async function stop()", pipeline)
        self.assertIn("await killProcessTree(pid)", pipeline)
        self.assertIn("async function stop()", rtmp)
        self.assertIn("await killProcessTree(pid)", rtmp)

        self.assertIn("let _lifecycleWatchdogInFlight = false", emule)
        self.assertIn("if (_lifecycleWatchdogInFlight) return", emule)
        self.assertIn("_lifecycleWatchdogInFlight = true", emule)
        self.assertIn("_lifecycleWatchdogInFlight = false", emule)
        self.assertIn("return result.ok &&", emule)


if __name__ == "__main__":
    unittest.main()
