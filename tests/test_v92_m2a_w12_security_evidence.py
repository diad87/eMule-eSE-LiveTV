"""Fail-closed W12 activation/runtime/CDP evidence fixtures."""
from __future__ import annotations
import copy
import hashlib
import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
ROOT = pathlib.Path(__file__).resolve().parents[1]
RUNNER = ROOT / "tools" / "architecture" / "run_w12_security_runtime.ps1"
VERIFIER = ROOT / "tools" / "architecture" / "verify_w12_security_evidence.py"
def _load():
    spec = importlib.util.spec_from_file_location("w12_gate", VERIFIER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
GATE = _load()
A = "a" * 40
EMULE, BUILD, TREE = "b" * 64, "c" * 64, "d" * 64
TOOLS = {"runner": "1" * 64, "verifier": "2" * 64, "collector": "3" * 64, "test": "4" * 64, "ratchet": "5" * 64}
STREAM, VALID_TOKEN = "5" * 32, "9" * 64
CANARY, RUN_ID, NONCE = "6" * 64, "7" * 64, "8" * 64
BASE = "http://127.0.0.1:24711/"
def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()
def _candidate() -> dict:
    return {"build_commit": A, "emule_sha256": EMULE, "build_info_sha256": BUILD, "release": "v0.70b-eSE9.2.0-test"}
def _binding() -> dict:
    toolset = hashlib.sha256(json.dumps(TOOLS, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"activation_commit": A, "production_tree_sha256": TREE, "toolset_sha256": toolset,
            "run_id_sha256": _sha(RUN_ID), "challenge_nonce_sha256": _sha(NONCE), "canary_sha256": _sha(CANARY)}
def _activation() -> dict:
    return {"schema": GATE.ACTIVATION_SCHEMA, "activation_commit": A, "production_tree_sha256": TREE,
            "production_path_count": 42, "tool_sha256": copy.deepcopy(TOOLS)}
def _runtime() -> dict:
    return {"schema": GATE.RUNTIME_SCHEMA, "candidate": _candidate(),
            "execution": {"loopback_only": True, "portable": True, "headless": True,
                          "process_termination_confirmed": True, "scratch_removed": True},
            "cases": [{"id": case, "status": "PASS", "http_status": GATE.RUNTIME_HTTP_STATUS[case],
                       "checks": ["bounded real observation"]} for case in GATE.RUNTIME_CASES],
            "canary": {"sha256": _sha(CANARY), "log_hits": 0, "artifact_hits": 0, "forged_body_hits": 0},
            "privacy": {"no_store_all_sensitive_responses": True, "no_referrer_all_sensitive_responses": True,
                        "secrets_persisted": False, "sensitive_urls_persisted": False},
            "binding": _binding(), "verdict": "PASS"}
def _challenge() -> dict:
    return {"schema": GATE.CHALLENGE_SCHEMA, "candidate": _candidate(), "binding": _binding()}
def _handoff(root: pathlib.Path) -> dict:
    return {"schema": "ese.v92.w12.browser-handoff/v2", "candidate": _candidate(), "binding": _binding(), "base_url": BASE,
            "login_password": "w12-browser-password", "csrf_token": None, "stream_key": STREAM,
            "canary": CANARY, "run_id": RUN_ID, "challenge_nonce": NONCE,
            "raw_cdp_path": str((root / "browser-cdp-raw.json").resolve()),
            "normalized_trace_path": str((root / "browser-cdp-trace.json").resolve()),
            "done_signal_path": str((root / "browser-done.json").resolve())}
def _security_headers() -> dict:
    return {"Cache-Control": "private, no-store", "Referrer-Policy": "no-referrer"}
def _raw_trace() -> dict:
    events: list[dict] = []
    def request(request_id: str, url: str, headers: dict | None = None) -> None:
        events.append({"method": "Network.requestWillBeSent", "params": {"requestId": request_id,
            "request": {"url": url, "method": "GET", "headers": headers or {"Accept": "*/*", "Cookie": "eSEWebSession=raw-transient-only"}}}})
    def response(request_id: str, status: int) -> None:
        events.append({"method": "Network.responseReceived", "params": {"requestId": request_id,
            "response": {"status": status, "headers": _security_headers()}}})
    def body(request_id: str, text: str) -> None:
        events.append({"method": "Network.getResponseBody", "params": {"requestId": request_id, "body": text, "base64Encoded": False}})
    valid_base = f"{BASE}h/{VALID_TOKEN}/7/{STREAM}"
    request("player", f"{BASE}live/{STREAM}"); response("player", 200)
    request("playlist", valid_base + "/stream.m3u8"); response("playlist", 200)
    request("segment", valid_base + "/seg_00001.ts", {"Accept": "video/mp2t", "Range": "bytes=0-1023"}); response("segment", 206)
    request("forged", f"{BASE}h/{CANARY}/7/{STREAM}/stream.m3u8"); response("forged", 403); body("forged", "Forbidden")
    request("log", f"{BASE}api/live/log?n=500", {"X-CSRF-Token": "raw-transient-only"}); response("log", 200); body("log", r"C:\Users\fixture\AppData peer=100.69.24.30 v6=2606:4700:110:8485::1")
    request("logout", f"{BASE}?w=logout", {"X-CSRF-Token": "raw-transient-only"}); response("logout", 200)
    request("revoked", valid_base + "/stream.m3u8"); response("revoked", 403); body("revoked", "Forbidden after logout")
    return {"events": events}
def _collector_raw_events(include_variant: bool = True) -> list[dict]:
    events: list[dict] = []
    def request(request_id: str, path: str, headers: dict | None = None) -> None:
        events.append({"method": "Network.requestWillBeSent", "params": {"requestId": request_id, "request": {"url": BASE.rstrip("/") + path, "method": "GET", "headers": headers or {"Cookie": "eSEWebSession=transient"}}}})
    def response(request_id: str, status: int) -> None:
        events.append({"method": "Network.responseReceived", "params": {"requestId": request_id, "response": {"status": status, "headers": _security_headers()}}})
    def body(request_id: str, text: str) -> None:
        events.append({"method": "Network.getResponseBody", "params": {"requestId": request_id, "body": text, "base64Encoded": False}})
    base = f"/h/{VALID_TOKEN}/7/{STREAM}"
    request("login", "/?w=password&p=transient"); response("login", 200)
    request("player", f"/live/{STREAM}"); response("player", 200)
    request("master", base + "/stream.m3u8"); response("master", 200)
    if include_variant:
        request("variant", base + "/stream_0.m3u8"); response("variant", 200)
    request("segment", base + "/seg_00001.ts", {"Range": "bytes=0-15"}); response("segment", 206)
    request("forged", f"/h/{CANARY}/7/{STREAM}/stream.m3u8"); response("forged", 403); body("forged", "Forbidden")
    request("log", "/api/live/log?n=500", {"X-CSRF-Token": "transient"}); response("log", 200); body("log", r"C:\Users\fixture\AppData peer=100.74.178.81 v6=2606:4700:110:8485::1")
    request("logout", "/?w=logout", {"X-CSRF-Token": "transient"}); response("logout", 200)
    request("revoked", base + "/stream.m3u8"); response("revoked", 403); body("revoked", "Forbidden after logout")
    return events
def _write(path: pathlib.Path, value: dict) -> None:
    path.write_text(json.dumps(value, separators=(",", ":")) + "\n", encoding="utf-8")
def _normalized_fixture() -> dict:
    with tempfile.TemporaryDirectory() as folder:
        root = pathlib.Path(folder)
        raw, challenge, handoff = root / "raw.json", root / "challenge.json", root / "handoff.json"
        _write(raw, _raw_trace()); _write(challenge, _challenge()); _write(handoff, _handoff(root))
        return GATE.normalize_cdp(raw, challenge, handoff)
def _verify(activation: dict, runtime: dict, challenge: dict, trace: dict) -> dict:
    with tempfile.TemporaryDirectory() as folder:
        root = pathlib.Path(folder)
        paths = [root / name for name in ("activation.json", "runtime.json", "challenge.json", "trace.json")]
        for path, value in zip(paths, (activation, runtime, challenge, trace)):
            _write(path, value)
        return GATE.verify(*paths)
def _event(trace: dict, request_id: str, method: str) -> dict:
    return next(item for item in trace["events"] if item["request_id"] == request_id and item["method"] == method)
def _move_logout_response_after_revoked_request(trace: dict) -> None:
    response = _event(trace, "logout", "Network.responseReceived")
    events = trace["events"]
    events.remove(response)
    revoked_request = _event(trace, "revoked", "Network.requestWillBeSent")
    events.insert(events.index(revoked_request) + 1, response)
    for sequence, event in enumerate(events):
        event["seq"] = sequence
class W12SecurityEvidence(unittest.TestCase):
    def test_realistic_raw_cdp_normalizes_and_verifies(self) -> None:
        trace = _normalized_fixture()
        encoded = json.dumps(trace, sort_keys=True)
        for forbidden in ("raw-transient-only", CANARY, VALID_TOKEN, BASE, '"route"', "referer_present", "canary_present", r"C:\Users", "100.69.", "2606:4700"):
            self.assertNotIn(forbidden, encoded)
        result = _verify(_activation(), _runtime(), _challenge(), trace)
        self.assertEqual((_event(trace, "log", "Network.getResponseBody")["body"], result["verdict"]), ("transient log checked and discarded", "PASS"))
        self.assertEqual([case["id"] for case in result["cases"]], list(GATE.BROWSER_CASES))
    def test_runtime_checks_are_closed_typed_and_nonempty(self) -> None:
        runtime = _runtime(); runtime["cases"][0].pop("checks")
        with self.assertRaisesRegex(GATE.EvidenceError, "fields differ"):
            GATE.validate_runtime(runtime)
        runtime = _runtime(); runtime["cases"][0]["checks"] = []
        with self.assertRaisesRegex(GATE.EvidenceError, "non-empty"):
            GATE.validate_runtime(runtime)
        runtime = _runtime(); runtime["cases"][0]["checks"] = [7]
        with self.assertRaises(GATE.EvidenceError):
            GATE.validate_runtime(runtime)
    def test_forged_response_with_different_request_id_fails(self) -> None:
        trace = _normalized_fixture()
        _event(trace, "forged", "Network.responseReceived")["request_id"] = "forged-other"
        with self.assertRaisesRegex(GATE.EvidenceError, "same request_id"):
            _verify(_activation(), _runtime(), _challenge(), trace)
    def test_more_than_twenty_normalized_negative_fixtures(self) -> None:
        fixtures: list[tuple[str, dict, dict, dict, dict]] = []
        def add(name: str, mutate) -> None:
            activation, runtime, challenge, trace = _activation(), _runtime(), _challenge(), _normalized_fixture()
            mutate(activation, runtime, challenge, trace)
            fixtures.append((name, activation, runtime, challenge, trace))
        add("runtime verdict forged", lambda a, r, c, t: r.__setitem__("verdict", "PASS-BY-HUMAN"))
        add("BUILD_INFO not A", lambda a, r, c, t: r["candidate"].__setitem__("build_commit", "f" * 40))
        add("runtime binary differs", lambda a, r, c, t: r["candidate"].__setitem__("emule_sha256", "f" * 64))
        add("activation tree differs", lambda a, r, c, t: a.__setitem__("production_tree_sha256", "f" * 64))
        add("runner hash differs", lambda a, r, c, t: a["tool_sha256"].__setitem__("runner", "f" * 64))
        add("verifier hash differs", lambda a, r, c, t: a["tool_sha256"].__setitem__("verifier", "f" * 64))
        add("test hash differs", lambda a, r, c, t: a["tool_sha256"].__setitem__("test", "f" * 64))
        add("ratchet hash differs", lambda a, r, c, t: a["tool_sha256"].__setitem__("ratchet", "f" * 64))
        add("run binding differs", lambda a, r, c, t: r["binding"].__setitem__("run_id_sha256", "f" * 64))
        add("challenge binding differs", lambda a, r, c, t: c["binding"].__setitem__("challenge_nonce_sha256", "f" * 64))
        add("extra trace verdict", lambda a, r, c, t: t.__setitem__("verdict", "PASS"))
        add("extra route assertion", lambda a, r, c, t: t["events"][0].__setitem__("route", "player"))
        add("non-contiguous sequence", lambda a, r, c, t: t["events"][1].__setitem__("seq", 99))
        add("duplicate request id", lambda a, r, c, t: _event(t, "playlist", "Network.requestWillBeSent").__setitem__("request_id", "player"))
        add("response unknown request", lambda a, r, c, t: _event(t, "segment", "Network.responseReceived").__setitem__("request_id", "unknown"))
        add("response precedes request", lambda a, r, c, t: t["events"].__setitem__(slice(0, 2), list(reversed(t["events"][:2]))))
        add("missing forged body", lambda a, r, c, t: t["events"].remove(_event(t, "forged", "Network.getResponseBody")))
        add("body attached to player", lambda a, r, c, t: t["events"].insert(2, {"seq": 2, "request_id": "player", "method": "Network.getResponseBody", "body": "safe"}))
        add("Referer present", lambda a, r, c, t: _event(t, "player", "Network.requestWillBeSent")["header_names"].append("referer"))
        add("non-loopback authority", lambda a, r, c, t: _event(t, "player", "Network.requestWillBeSent").__setitem__("authority", "127.0.0.2:24711"))
        add("weak cache", lambda a, r, c, t: _event(t, "playlist", "Network.responseReceived")["response_headers"].__setitem__("cache-control", "private"))
        add("weak referrer", lambda a, r, c, t: _event(t, "playlist", "Network.responseReceived")["response_headers"].__setitem__("referrer-policy", "origin"))
        add("64hex in body", lambda a, r, c, t: _event(t, "log", "Network.getResponseBody").__setitem__("body", "a" * 64))
        add("URL in body", lambda a, r, c, t: _event(t, "log", "Network.getResponseBody").__setitem__("body", "http://127.0.0.1/private"))
        add("canary marker in body", lambda a, r, c, t: _event(t, "log", "Network.getResponseBody").__setitem__("body", "canary absent"))
        add("ambiguous pre-logout 403", lambda a, r, c, t: _event(t, "forged", "Network.requestWillBeSent").__setitem__("token_sha256", "f" * 64))
        add("logout action missing", lambda a, r, c, t: t["events"].__setitem__(slice(11, 13), []))
        add("logout action not 200", lambda a, r, c, t: _event(t, "logout", "Network.responseReceived").__setitem__("status", 403))
        add("revocation request races logout response", lambda a, r, c, t: _move_logout_response_after_revoked_request(t))
        add("revoked token not valid", lambda a, r, c, t: _event(t, "revoked", "Network.requestWillBeSent").__setitem__("token_sha256", "f" * 64))
        add("segment token differs", lambda a, r, c, t: _event(t, "segment", "Network.requestWillBeSent").__setitem__("token_sha256", "f" * 64))
        add("segment Range absent", lambda a, r, c, t: _event(t, "segment", "Network.requestWillBeSent").__setitem__("range", None))
        add("browser candidate differs", lambda a, r, c, t: t["candidate"].__setitem__("emule_sha256", "f" * 64))
        self.assertGreaterEqual(len(fixtures), 20)
        for name, activation, runtime, challenge, trace in fixtures:
            # Re-numbering is deliberately omitted: structural mutations must fail too.
            with self.subTest(name=name), self.assertRaises(GATE.EvidenceError):
                _verify(activation, runtime, challenge, trace)
    def test_raw_cdp_and_handoff_fail_closed(self) -> None:
        mutations = []
        mutations.append(("external authority", lambda raw, handoff: raw["events"][0]["params"]["request"].__setitem__("url", "http://127.0.0.2:24711/live/" + STREAM)))
        mutations.append(("Referer survives as observable", lambda raw, handoff: raw["events"][0]["params"]["request"]["headers"].__setitem__("Referer", BASE)))
        mutations.append(("secret body", lambda raw, handoff: next(e for e in raw["events"] if e["method"] == "Network.getResponseBody" and e["params"]["requestId"] == "log")["params"].__setitem__("body", CANARY)))
        mutations.append(("malformed handoff run", lambda raw, handoff: handoff.__setitem__("run_id", "not-hex")))
        mutations.append(("handoff hash mismatch", lambda raw, handoff: handoff.__setitem__("challenge_nonce", "f" * 64)))
        for name, mutate in mutations:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as folder:
                root = pathlib.Path(folder); raw_value, handoff_value = _raw_trace(), _handoff(root)
                mutate(raw_value, handoff_value)
                raw, challenge, handoff = root / "raw.json", root / "challenge.json", root / "handoff.json"
                _write(raw, raw_value); _write(challenge, _challenge()); _write(handoff, handoff_value)
                if name == "Referer survives as observable":
                    with self.assertRaisesRegex(GATE.EvidenceError, "Referer"):
                        GATE.normalize_cdp(raw, challenge, handoff)
                else:
                    with self.assertRaises(GATE.EvidenceError):
                        GATE.normalize_cdp(raw, challenge, handoff)
    def test_canonical_tree_formula_uses_real_tab_and_lf(self) -> None:
        entries = [("2" * 40, "srchybrid/z.cpp"), ("1" * 40, "srchybrid/a.cpp")]
        expected_bytes = (("1" * 40) + "\tsrchybrid/a.cpp\n" + ("2" * 40) + "\tsrchybrid/z.cpp\n").encode()
        digest, count = GATE.canonical_production_tree(entries)
        self.assertEqual((digest, count), (hashlib.sha256(expected_bytes).hexdigest(), 2))
    def test_duplicate_json_and_extra_fields_fail(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "duplicate.json"
            path.write_text('{"schema":"x","schema":"y"}', encoding="utf-8")
            with self.assertRaisesRegex(GATE.EvidenceError, "unambiguous"):
                GATE._read_json(path)
        trace = _normalized_fixture(); trace["events"][0]["operator_status"] = "PASS"
        with self.assertRaisesRegex(GATE.EvidenceError, "fields differ"):
            GATE.derive_browser(trace, _binding())
    def test_collector_v3_hash_chain_normalizes_both_real_r_playlist_shapes(self) -> None:
        for include_variant in (False, True):
            with self.subTest(include_variant=include_variant), tempfile.TemporaryDirectory() as folder:
                root = pathlib.Path(folder); raw, handoff, ready, done, challenge = (root / name for name in ("raw.json", "handoff.json", "ready.json", "done.json", "challenge.json"))
                compact = _binding()
                handoff_value = {"schema": GATE.HANDOFF_SCHEMA, "A": A, "candidate": _candidate(), "binding": compact, "base_url": BASE, "login_password": "w12-browser-password", "stream_key": STREAM, "canary": CANARY, "run_id": RUN_ID, "challenge_nonce": NONCE, "raw_path": str(raw.resolve()), "done_path": str(done.resolve())}
                _write(handoff, handoff_value); _write(challenge, _challenge())
                handoff_sha = hashlib.sha256(handoff.read_bytes()).hexdigest()
                ready_value = {"schema": GATE.READY_SCHEMA, "A": A, "run_id_sha256": compact["run_id_sha256"], "challenge_nonce_sha256": compact["challenge_nonce_sha256"], "handoff_sha256": handoff_sha, "collector_sha256": TOOLS["collector"]}
                _write(ready, ready_value); ready_sha = hashlib.sha256(ready.read_bytes()).hexdigest()
                raw_value = {"schema": GATE.RAW_SCHEMA, "A": A, "candidate": _candidate(), "binding": compact, "collector_sha256": TOOLS["collector"], "ready_sha256": ready_sha, "handoff_sha256": handoff_sha, "browser_binding_sha256": hashlib.sha256(b"browser-id").hexdigest(), "proxy_authority": "127.0.0.1:24711", "browser": {"browser_id": "browser-id", "product": "product", "version": "version", "user_agent": "agent"}, "events": _collector_raw_events(include_variant)}
                _write(raw, raw_value); raw_sha = hashlib.sha256(raw.read_bytes()).hexdigest()
                _write(done, {"schema": GATE.DONE_SCHEMA, "A": A, "run_id_sha256": compact["run_id_sha256"], "challenge_nonce_sha256": compact["challenge_nonce_sha256"], "collector_sha256": TOOLS["collector"], "ready_sha256": ready_sha, "handoff_sha256": handoff_sha, "raw_sha256": raw_sha, "browser_binding_sha256": raw_value["browser_binding_sha256"], "product_sha256": hashlib.sha256(b"product").hexdigest(), "version_sha256": hashlib.sha256(b"version").hexdigest(), "user_agent_sha256": hashlib.sha256(b"agent").hexdigest()})
                trace = GATE.normalize_collector_cdp(raw, challenge, handoff, ready, done, GATE.validate_activation(_activation()))
                self.assertEqual(trace["schema"], GATE.CDP_SCHEMA); self.assertEqual(trace["collector_sha256"], TOOLS["collector"])
                serialized = json.dumps(trace, sort_keys=True).lower()
                for forbidden in ("w12-browser-password", STREAM, VALID_TOKEN, CANARY, BASE.lower(), "cookie", "x-csrf-token"):
                    self.assertNotIn(forbidden.lower(), serialized)
                legacy = {key: trace[key] for key in ("activation_commit", "candidate", "binding", "events")}; legacy["schema"] = GATE.LEGACY_CDP_SCHEMA
                self.assertEqual(GATE.derive_browser(legacy, _binding())[1][2]["id"], "W12-BROWSER-SEGMENT-RANGE")
                self.assertEqual(_verify(_activation(), _runtime(), _challenge(), trace)["verdict"], "PASS")
                raw_value["collector_sha256"] = "f" * 64; _write(raw.with_name("bad.json"), raw_value)
                with self.assertRaises(GATE.EvidenceError):
                    GATE.normalize_collector_cdp(raw.with_name("bad.json"), challenge, handoff, ready, done, GATE.validate_activation(_activation()))
                duplicate = raw.with_name("duplicate.json"); duplicate.write_text('{"schema":"x","schema":"y"}', encoding="utf-8")
                with self.assertRaisesRegex(GATE.EvidenceError, "unambiguous"):
                    GATE.normalize_collector_cdp(duplicate, challenge, handoff, ready, done, GATE.validate_activation(_activation()))
    def test_done_signal_is_bound_to_challenge_and_exact_trace_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            trace_path = pathlib.Path(folder) / "trace.json"
            _write(trace_path, _normalized_fixture())
            done = GATE._done_value(trace_path, _binding())
            GATE.validate_done_signal(done, trace_path, _binding())
            broken = copy.deepcopy(done); broken["trace_sha256"] = "f" * 64
            with self.assertRaisesRegex(GATE.EvidenceError, "trace hash differs"):
                GATE.validate_done_signal(broken, trace_path, _binding())
            broken = copy.deepcopy(done); broken["run_id_sha256"] = "f" * 64
            with self.assertRaisesRegex(GATE.EvidenceError, "binding differs"):
                GATE.validate_done_signal(broken, trace_path, _binding())
    def test_legacy_normalizer_is_isolated_from_collector_r_protocol(self) -> None:
        trace = _normalized_fixture()
        self.assertEqual(trace["schema"], GATE.LEGACY_CDP_SCHEMA)
        self.assertNotEqual(trace["schema"], GATE.CDP_SCHEMA)
        self.assertNotIn("--normalize-cdp", RUNNER.read_text(encoding="utf-8")); self.assertIn("transient log checked and discarded", VERIFIER.read_text(encoding="utf-8"))
    def test_runner_has_bounded_autonomous_handshake_and_global_cleanup(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        for marker in ("browser-handoff.json", "browser-ready.json", "browser-cdp-raw.json", "browser-cdp-trace.json",
                       "browser-done.json", "Wait-W12BrowserEvidence", "handoff_sha256", "collector_sha256",
                       "([Math]::Min($TimeoutSeconds, 180))", "Global cleanup",
                       "collector timed out", "W12-BROWSER-HANDSHAKE", "--normalize-collector",
                       "Export-W12GitBlob", "W12_BROWSER_READY=", "'APPDATA'", "'LOCALAPPDATA'", "'USERPROFILE'"):
            self.assertIn(marker, source)
        self.assertEqual(source.count("W12_BROWSER_READY="), 1)
        self.assertIn("Join-Path $exchange 'browser-ready.json'", source)
        self.assertIn("inspect sanitized runtime.json", source)
        self.assertNotIn("inspect sanitized w12-security-runtime.json", source)
        self.assertIn('$canonical.Add(("{0}`t{1}`n"', source)
        self.assertNotIn("'{0}`t{1}`n'", source)
        self.assertIn("Remove-Item -LiteralPath $scratchFull -Recurse -Force", source)
        self.assertIn("$buildInfo.commit -ceq $activation.activation_commit", source)
        self.assertIn("'srchybrid/eMule.tmpl'", source)
        self.assertIn("@('eMule', 'AppVersion', 'eSE v9.2 W12 isolated runtime')", source)
        self.assertIn("@('eMule', 'BindAddr', '')", source)
        self.assertIn("@('eMule.tmpl', 'config\\eMule.tmpl')", source)
        self.assertIn("(Get-Sha256File -Path $sourceTemplate) -ceq $expectedTemplateHash", source)
        self.assertIn("Get-Sha256File -Path (Join-Path $node $relativeTemplate)", source)
        self.assertGreaterEqual(source.count("$process.ExitCode -eq 0"), 2)
        self.assertGreaterEqual(source.count("$process.WaitForExit()"), 2)
        self.assertIn("for ($loginAttempt = 0; $loginAttempt -lt 20; $loginAttempt++)", source)
        self.assertIn("Start-Sleep -Milliseconds 250", source)
        self.assertIn("} catch { $loginReady = $false }", source)
        self.assertIn("Assert-W12 $loginReady", source)
        self.assertIn("[Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-fA-F]{40}$')][string]$ExpectedCommit", source)
        for marker in ("New-W12PrivateScratch", "Assert-W12PrivateScratch",
                       "New-W12ExchangeScratch", "Assert-W12ExchangeScratch",
                       "SetAccessRuleProtection($true, $false)", "S-1-5-18",
                       "CodexSandboxOffline", "$allowedSids", "'Modify'",
                       "$restrictedSids.Count -eq 2", "$script:w12CollectorSids", "$ScratchRoot",
                       "Assert-W12ScratchWrite", "-PrivateScratch $scratch"):
            self.assertIn(marker, source)
        private_scratch = source.split("function New-W12PrivateScratch", 1)[1].split(
            "function Assert-W12ExchangeScratch", 1
        )[0]
        self.assertNotIn("$w12Collector", private_scratch)
        exchange_scratch = source.split("function New-W12ExchangeScratch", 1)[1].split(
            "function Assert-W12ScratchWrite", 1
        )[0]
        self.assertIn("@($w12CollectorUserSid) + $w12CollectorSids", exchange_scratch)
        self.assertNotIn("$collectorGroup", exchange_scratch)
        self.assertIn("Remove-Item -LiteralPath $exchangeFull -Recurse -Force", source)
        self.assertNotIn("Authenticated Users", source)
        self.assertNotIn("BUILTIN\\Users", source)
        self.assertNotIn("$scratch = Join-Path $output 'scratch'", source)
if __name__ == "__main__":
    unittest.main()
