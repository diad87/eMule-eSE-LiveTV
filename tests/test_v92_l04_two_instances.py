#!/usr/bin/env python3
"""Unattended host-integration gate for V9.2 L04."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class L04TwoInstanceHostContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.firewall = (ROOT / "srchybrid/FirewallOpener.cpp").read_text(
            encoding="utf-8", errors="strict"
        )
        cls.firewall_h = (ROOT / "srchybrid/FirewallOpener.h").read_text(
            encoding="utf-8", errors="strict"
        )
        cls.windows_firewall = (
            ROOT / "srchybrid/WindowsFirewallHelper.cpp"
        ).read_text(encoding="utf-8", errors="strict")
        cls.windows_firewall_h = (
            ROOT / "srchybrid/WindowsFirewallHelper.h"
        ).read_text(encoding="utf-8", errors="strict")
        cls.preferences = (ROOT / "srchybrid/Preferences.cpp").read_text(
            encoding="utf-8", errors="strict"
        )
        cls.project = (ROOT / "srchybrid/emule.vcxproj").read_text(
            encoding="utf-8", errors="strict"
        )
        cls.t8 = (
            ROOT / "libnatmap/tests/test_two_instance_isolation.cpp"
        ).read_text(encoding="utf-8", errors="strict")

    def test_firewall_uses_product_isolation_policy(self) -> None:
        self.assertIn(
            '#include "natmap/instance_isolation.h"', self.firewall
        )
        self.assertIn("LoadOrCreateFirewallOwnerToken(", self.firewall)
        self.assertIn("BuildOwnedFirewallRuleName(", self.firewall)
        self.assertIn("EvaluateFirewallCleanup(", self.firewall)
        self.assertIn("EvaluateFirewallCleanup(", self.windows_firewall)

    def test_owner_token_is_persistent_random_and_never_logged(self) -> None:
        loader = self.firewall[
            self.firewall.index("bool ReadFirewallOwnerToken(") :
            self.firewall.index("#define RETURN_ON_FAIL")
        ]
        self.assertIn("BCRYPT_USE_SYSTEM_PREFERRED_RNG", loader)
        self.assertIn("CREATE_NEW", loader)
        self.assertIn("FlushFileBuffers(file)", loader)
        self.assertIn("ReadFirewallOwnerToken(path, token)", loader)
        self.assertIn(
            "ReadFirewallOwnerToken(temporaryPath, verifiedCandidate)",
            loader,
        )
        self.assertIn(
            "MoveFileEx(temporaryPath, path, MOVEFILE_WRITE_THROUGH)",
            loader,
        )
        self.assertLess(
            loader.index(
                "ReadFirewallOwnerToken(temporaryPath, verifiedCandidate)"
            ),
            loader.index(
                "MoveFileEx(temporaryPath, path, MOVEFILE_WRITE_THROUGH)"
            ),
        )
        self.assertNotIn("FingerprintInstanceProfile", self.firewall)
        self.assertNotRegex(loader, r"DebugLog.*(?:path|token|candidate)")
        legacy_add = self.firewall[
            self.firewall.index("bool CFirewallOpener::AddRule(") :
            self.firewall.index("bool CFirewallOpener::FindRule(")
        ]
        self.assertNotRegex(
            legacy_add, r"(?:DebugLog|QueueDebugLogLine).*m_strRuleName"
        )
        self.assertIn("m_profileOwnerToken", self.firewall_h)

    def test_protocol_and_logical_name_mismatch_fails_closed(self) -> None:
        owned = self.firewall[
            self.firewall.index("bool CFirewallOpener::BuildOwnedRuleInfo(") :
            self.firewall.index("bool CFirewallOpener::AddRule(")
        ]
        self.assertIn("tcpProtocol && udpLogicalName", owned)
        self.assertIn("udpProtocol && tcpLogicalName", owned)
        mismatch = owned.index("tcpProtocol && udpLogicalName")
        selection = owned.index("if (tcpProtocol || tcpLogicalName)")
        self.assertLess(mismatch, selection)

    def test_scoping_precedes_both_firewall_backends(self) -> None:
        action = self.firewall[
            self.firewall.index("bool CFirewallOpener::DoAction(") :
            self.firewall.index("bool CFirewallOpener::BuildOwnedRuleInfo(")
        ]
        self.assertLess(
            action.index("BuildOwnedRuleInfo("),
            action.index("s_modernFirewall.IsInited()"),
        )
        self.assertIn("FindRule(eAction, rule", action)
        self.assertNotIn(
            "s_modernFirewall.RemoveRule(riPortRule.m_strRuleName)", action
        )

    def test_unknown_or_empty_rule_identity_fails_closed(self) -> None:
        owned = self.firewall[
            self.firewall.index("bool CFirewallOpener::BuildOwnedRuleInfo(") :
            self.firewall.index("bool CFirewallOpener::AddRule(")
        ]
        self.assertIn("return false;", owned)
        self.assertIn("IsOwnedFirewallRuleName(", owned)
        self.assertIn("EvaluateFirewallCleanup(", owned)

    def test_legacy_backend_never_borrows_foreign_port_rule(self) -> None:
        action = self.firewall[
            self.firewall.index("bool CFirewallOpener::DoAction(") :
            self.firewall.index("bool CFirewallOpener::BuildOwnedRuleInfo(")
        ]
        exact = action.index(
            "FindRule(FOC_FINDRULEBYNAME, rule, pNSC, NULL)"
        )
        by_port = action.index(
            "FindRule(FOC_FINDRULEBYPORT, rule, pNSC, NULL)", exact
        )
        add = action.index("AddRule(rule, pNSC, pNCP)", by_port)
        self.assertLess(exact, by_port)
        self.assertLess(by_port, add)
        self.assertIn("bResult = false;", action[by_port:add])

    def test_random_tcp_and_udp_ports_use_os_entropy(self) -> None:
        random_ports = self.preferences[
            self.preferences.index("uint16 CPreferences::GetRandomTCPPort()") :
            self.preferences.index(
                "CString CPreferences::GetDefaultDirectory"
            )
        ]
        self.assertIn("BCRYPT_USE_SYSTEM_PREFERRED_RNG", self.preferences)
        self.assertEqual(
            random_ports.count("GetUniformSystemRandomPort(nPort)"), 2
        )
        self.assertNotIn("GetRandomUInt16()", random_ports)
        self.assertNotIn("% uValidPortRange", random_ports)

    def test_rng_failure_is_explicit_zero_not_weak_fallback(self) -> None:
        random_ports = self.preferences[
            self.preferences.index("uint16 CPreferences::GetRandomTCPPort()") :
            self.preferences.index(
                "CString CPreferences::GetDefaultDirectory"
            )
        ]
        helper = self.preferences[
            self.preferences.index("bool GetUniformSystemRandomPort(") :
            self.preferences.index("CString CPreferences::m_astrDefaultDirs")
        ]
        self.assertIn("if (entropy < kPortCount)", helper)
        self.assertIn("for (unsigned attempt = 0; attempt < 32;", helper)
        self.assertNotIn("rand(", helper)
        self.assertNotIn("GetTickCount", helper)
        self.assertIn("Secure TCP port selection failed", random_ports)
        self.assertIn("Secure UDP port selection failed", random_ports)
        self.assertIn("Secure TCP port selection exhausted", random_ports)
        self.assertIn("Secure UDP port selection exhausted", random_ports)
        self.assertEqual(random_ports.count("if (!bPortIsFree)"), 2)
        self.assertEqual(random_ports.count("nPort = 0;"), 6)

    def test_modern_cleanup_observes_application_protocol_and_port(self) -> None:
        cleanup = self.windows_firewall[
            self.windows_firewall.index(
                "bool CWindowsFirewallHelper::RemoveOwnedPortRule("
            ) :
            self.windows_firewall.index(
                "bool CWindowsFirewallHelper::DoesRuleExist("
            )
        ]
        for marker in (
            "get_Protocol",
            "get_LocalPorts",
            "get_ApplicationName",
            "get_Name",
            "get_Direction",
            "get_Action",
            "get_Enabled",
            "EvaluateFirewallCleanup(",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, cleanup)
        self.assertIn("observedName", cleanup)
        self.assertIn("CString(szRuleName) != CString(ownedName.data())", cleanup)
        self.assertIn("observedPort, observedName", cleanup)
        self.assertNotIn("observedPort, ownedName", cleanup)
        self.assertLess(
            cleanup.index("EvaluateFirewallCleanup("),
            cleanup.index("pRules->Remove("),
        )

    def test_global_cleanup_apis_are_removed(self) -> None:
        for marker in ("EnsureEmulePorts", "RemoveEmuleRules"):
            with self.subTest(marker=marker):
                self.assertNotIn(marker, self.windows_firewall)
                self.assertNotIn(marker, self.windows_firewall_h)

    def test_product_source_is_in_release_project(self) -> None:
        self.assertIn(
            r'..\libnatmap\src\instance_isolation.cpp', self.project
        )
        self.assertIn(
            r'..\libnatmap\include\natmap\instance_isolation.h',
            self.project,
        )

    def test_t8_matrix_contains_all_required_lifecycle_rows(self) -> None:
        for marker in (
            "TestSamePortAndDistinctPorts",
            "TestMapperEqualAndDifferentFailClosed",
            "TestCloseCrashRestartRefreshAndGatewayRestart",
            "TestInheritedMappingCannotBeClaimed",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, self.t8)

    def test_t8_never_invokes_real_firewall_or_router_tools(self) -> None:
        forbidden = (
            "netsh",
            "New-NetFirewallRule",
            "Remove-NetFirewallRule",
            "UPNP_AddPortMapping",
            "CreateProcess",
            "ShellExecute",
        )
        for marker in forbidden:
            with self.subTest(marker=marker):
                self.assertNotIn(marker, self.t8)


if __name__ == "__main__":
    unittest.main(verbosity=2)
