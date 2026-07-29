"""MOD-2.2 baseline for WebServer authentication and authorization extraction."""

from __future__ import annotations

import json
import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVER_H = ROOT / "srchybrid" / "WebServer.h"
SERVER_CPP = ROOT / "srchybrid" / "WebServer.cpp"
SOCKET_CPP = ROOT / "srchybrid" / "WebSocket.cpp"
CONTRACT = ROOT / "docs" / "architecture" / "mod03_ownership_layering_contract_v1.json"


class Mod22WebAuthPolicyBaselineTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.header = SERVER_H.read_text(encoding="utf-8")
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

    def test_session_state_is_nonzero_touched_and_expiring(self) -> None:
        self.assertRegex(
            self.header,
            r"struct\s*\{[^}]*startTime;[^}]*lSession;[^}]*lastcat;[^}]*admin;",
        )
        self.assertIn("if (lSession != 0)", self.server)
        self.assertIn(
            "pThis->m_Params.Sessions[i].startTime = CTime::GetCurrentTime();",
            self.server,
        )
        self.assertIn("thePrefs.GetWebTimeoutMins() * 60", self.server)
        self.assertIn("pThis->m_Params.Sessions.RemoveAt(i)", self.server)

    def test_challenges_are_ip_bound_single_use_expiring_and_bounded(self) -> None:
        self.assertIn("dwClientIP = inet_addr(ipstrA(Data.inadr))", self.server)
        self.assertIn("ch.sNonce == aNonce && ch.dwClientIP == clientIP", self.server)
        consume = re.search(
            r"bool CWebServer::_ValidateChallengeResponse.*?"
            r"pendingChallenges\.RemoveAt\(i\).*?"
            r"if \(!nonceFound\)",
            self.server,
            re.DOTALL,
        )
        self.assertIsNotNone(consume)
        self.assertIn("dwTimestamp + 300000u", self.server)
        self.assertIn("pendingChallenges.GetCount() > 64", self.server)

    def test_login_failures_block_fifth_attempt_for_fifteen_minutes(self) -> None:
        self.assertIn("MIN2MS(15)", self.server)
        self.assertGreaterEqual(self.server.count("myfaults > 4"), 2)
        self.assertIn("pThis->m_Params.badlogins.Add(newban)", self.server)
        self.assertIn("if (login)", self.server)
        self.assertIn("pThis->m_Params.badlogins.RemoveAt(i)", self.server)

    def test_live_api_has_remote_and_guest_permission_boundaries(self) -> None:
        self.assertIn("clientIP != loopback && !bTokenAuth", self.server)
        self.assertIn("bTokenAuth && !bTokenAdmin", self.server)
        for privileged_prefix in (
            "/api/live/broadcast/",
            "/api/holepunch/",
            "/api/network/",
            "/api/live/privacy/",
        ):
            self.assertIn(privileged_prefix, self.server)
        self.assertIn("admin session required", self.server)

    def test_csrf_header_is_declared_at_the_socket_boundary(self) -> None:
        self.assertIn("X-CSRF-Token", self.socket)
        self.assertIn("Access-Control-Allow-Origin: http://localhost:3000", self.socket)

    def test_mutating_api_rate_limits_are_explicit(self) -> None:
        for marker in (
            "s_lastNetworkConnect",
            "s_lastManualRdv",
            "s_lastKeepaliveToggle",
            "s_lastManualHolePunch",
        ):
            self.assertIn(marker, self.server)
        self.assertGreaterEqual(self.server.count("rate_limited"), 4)
        self.assertGreaterEqual(self.server.count("2000"), 2)
        self.assertGreaterEqual(self.server.count("5000"), 2)


if __name__ == "__main__":
    unittest.main()
