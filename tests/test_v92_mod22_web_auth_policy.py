"""MOD-2.2 WebAuthPolicy ownership, security and integration contract."""

from __future__ import annotations

import json
import pathlib
import re
import unittest
import xml.etree.ElementTree as ET


ROOT = pathlib.Path(__file__).resolve().parents[1]
HEADER = ROOT / "srchybrid" / "WebAuthPolicy.h"
SOURCE = ROOT / "srchybrid" / "WebAuthPolicy.cpp"
NATIVE_TEST = ROOT / "srchybrid" / "tests" / "test_web_auth_policy.cpp"
SERVER_H = ROOT / "srchybrid" / "WebServer.h"
SERVER_CPP = ROOT / "srchybrid" / "WebServer.cpp"
SOCKET_CPP = ROOT / "srchybrid" / "WebSocket.cpp"
PROJECT = ROOT / "srchybrid" / "emule.vcxproj"
NATIVE_GATE = ROOT / "srchybrid" / "tests" / "make.bat"
CONTRACT = ROOT / "docs" / "architecture" / "mod03_ownership_layering_contract_v1.json"


class Mod22WebAuthPolicyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.header = HEADER.read_text(encoding="utf-8")
        cls.source = SOURCE.read_text(encoding="utf-8")
        cls.native = NATIVE_TEST.read_text(encoding="utf-8")
        cls.server_h = SERVER_H.read_text(encoding="utf-8")
        cls.server = SERVER_CPP.read_text(encoding="utf-8")
        cls.socket = SOCKET_CPP.read_text(encoding="utf-8")
        cls.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))

    def test_planned_owner_layer_and_responsibility_are_exact(self) -> None:
        web = next(
            coordinator for coordinator in self.contract["coordinators"]
            if coordinator["name"] == "WebServer"
        )
        module = next(
            item for item in web["planned_modules"]
            if item["module"] == "WebAuthPolicy"
        )
        self.assertEqual(module["layer"], "application")
        self.assertEqual(
            module["responsibility"],
            "session, CSRF, permissions and rate limiting",
        )
        self.assertEqual(module["owner_before"], "CWebServer")
        self.assertEqual(module["owner_after"], "WebAuthPolicy")

    def test_module_is_portable_and_coordinator_independent(self) -> None:
        for forbidden in (
            "WebServer.h", "WebSocket.h", "CString", "CArray", "CTime",
            "GetTickCount", "thePrefs", "theApp", "windows.h",
        ):
            self.assertNotIn(forbidden, self.header)
            self.assertNotIn(forbidden, self.source)
        self.assertIn("std::mutex", self.header)
        self.assertIn("std::lock_guard<std::mutex>", self.source)
        self.assertNotRegex(self.source, r"\bnew\b|\bdelete\b")

    def test_session_owner_is_unique_and_fail_closed(self) -> None:
        self.assertIn("WebAuthPolicy m_authPolicy;", self.server_h)
        for old_owner in (
            "CArray<Session>", "CArray<BadLogin>",
            "CArray<PendingChallenge>", "m_Params.Sessions",
            "m_Params.badlogins", "m_Params.pendingChallenges",
        ):
            self.assertNotIn(old_owner, self.server_h)
            self.assertNotIn(old_owner, self.server)
        for required in (
            "id == 0", "role == WebRole::None",
            "duplicate != m_sessions.end()", "TouchSession",
            "PurgeExpiredSessions", "SetLastCategory", "GetLastCategory",
        ):
            self.assertIn(required, self.source)

    def test_challenge_replay_expiry_ip_binding_and_bounds_are_owned(self) -> None:
        for required in (
            "kChallengeLifetimeMs = 300000",
            "kMaxPendingChallenges = 64",
            "record.nonce == nonce && record.client_ip == clientIp",
            "m_challenges.erase(found)",
            "while (m_challenges.size() > kMaxPendingChallenges)",
        ):
            self.assertIn(required, self.header + self.source)
        self.assertIn("m_authPolicy.AddChallenge", self.server)
        self.assertIn("m_authPolicy.ConsumeChallenge", self.server)

    def test_login_rate_limit_is_bounded_isolated_and_cleared_on_success(self) -> None:
        for required in (
            "kLoginFailureWindowMs = 900000",
            "kMaxLoginFailuresPerIp = 5",
            "kMaxTrackedLoginFailures = 1024",
            "IsLoginBlocked", "RecordLoginFailure", "RecordLoginSuccess",
        ):
            self.assertIn(required, self.header + self.source)
        self.assertNotIn("MIN2MS(15)", self.server)
        self.assertNotIn("myfaults", self.server)

    def test_csrf_is_issued_forwarded_and_enforced(self) -> None:
        for required in (
            "ValidateCsrfRequest", "ConstantTimeEqual",
            'fetchSite == "same-origin"', 'fetchSite == "same-site"',
            'fetchSite == "none"',
        ):
            self.assertIn(required, self.source)
        self.assertIn('header.name == "x-csrf-token"', self.socket)
        self.assertIn('header.name == "sec-fetch-site"', self.socket)
        self.assertIn("X-CSRF-Token: %s", self.server)
        self.assertIn("Access-Control-Expose-Headers: X-CSRF-Token", self.server)
        self.assertIn("ValidateCsrfRequest(", self.server)
        self.assertIn("ConstantTimeEqual(", self.server)
        self.assertNotIn("computeExpected(thePrefs.GetWSPass()) == aResponse", self.server)
        self.assertIn("HTTP/1.1 403 Forbidden", self.server)

    def test_permissions_and_four_action_limits_delegate_to_policy(self) -> None:
        self.assertIn("HasPermission(", self.server)
        self.assertIn("RequiredRoleForLivePath(", self.server)
        for privileged in (
            "/api/debug/", "/api/ese/", "/api/holepunch/",
            "/api/keepalive/", "/api/krp/", "/api/network/",
            "/api/relay/", "/api/live/broadcast/",
            "/api/live/privacy/",
        ):
            self.assertIn(privileged, self.source)
        for action in (
            "NetworkConnect", "ManualRendezvous",
            "KeepaliveToggle", "ManualHolePunch",
        ):
            self.assertIn(f"WebAction::{action}", self.server)
            self.assertIn(action, self.header)
        for removed_clock in (
            "s_lastNetworkConnect", "s_lastManualRdv",
            "s_lastKeepaliveToggle", "s_lastManualHolePunch",
        ):
            self.assertNotIn(removed_clock, self.server)
        self.assertGreaterEqual(self.server.count("retry_after_ms"), 4)

    def test_native_vectors_cover_hostile_and_concurrent_cases(self) -> None:
        for required in (
            "zero session ID must fail closed",
            "duplicate session ID must fail closed",
            "challenge replay must fail",
            "fifth failure must block",
            "cross-site credentialed request without CSRF token must fail",
            "first action must be allowed even at tick zero",
            "concurrent session store must retain every unique session",
            "production WebAuthPolicy self-test must pass",
        ):
            self.assertIn(required, self.native)
        self.assertIn("threadCount = 8", self.native)
        self.assertIn("sessionsPerThread = 100", self.native)
        self.assertIn("RunWebAuthPolicySelfTest(authFailure)", self.server)

    def test_project_and_standalone_gate_compile_production_module(self) -> None:
        namespace = {"m": "http://schemas.microsoft.com/developer/msbuild/2003"}
        project = ET.parse(PROJECT)
        compile_entry = project.find(
            ".//m:ClCompile[@Include='WebAuthPolicy.cpp']", namespace
        )
        self.assertIsNotNone(compile_entry)
        self.assertEqual(
            compile_entry.findtext("m:PrecompiledHeader", namespaces=namespace),
            "NotUsing",
        )
        self.assertEqual(
            compile_entry.findtext("m:WarningLevel", namespaces=namespace),
            "Level4",
        )
        self.assertEqual(
            compile_entry.findtext("m:TreatWarningAsError", namespaces=namespace),
            "true",
        )
        self.assertIsNotNone(
            project.find(".//m:ClInclude[@Include='WebAuthPolicy.h']", namespace)
        )
        gate = NATIVE_GATE.read_text(encoding="utf-8")
        self.assertIn("test_web_auth_policy.cpp WebAuthPolicy.cpp", gate)
        self.assertIn("test_web_auth_policy.exe", gate)

    def test_coordinator_slice_has_real_reduction(self) -> None:
        baseline = (
            subprocess_output(
                "git", "show", "630ef1cc:srchybrid/WebServer.cpp"
            )
        )
        current = self.server
        removed_owner_tokens = (
            baseline.count("m_Params.Sessions")
            + baseline.count("m_Params.badlogins")
            + baseline.count("m_Params.pendingChallenges")
        )
        self.assertGreaterEqual(removed_owner_tokens, 12)
        self.assertLess(current.count("m_Params.Sessions"), 1)


def subprocess_output(*command: str) -> str:
    import subprocess

    return subprocess.run(
        command,
        cwd=ROOT,
        check=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
    ).stdout


if __name__ == "__main__":
    unittest.main()
