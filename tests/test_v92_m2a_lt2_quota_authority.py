import pathlib
import re
import unittest
ROOT = pathlib.Path(__file__).resolve().parents[1]
FIELDS = """
m_k6Hardening m_k6EconomyTelemetry m_k6EconomyInputs m_k6EconomyReady
m_k6EconomyUsefulBytes m_k6EconomyPublishAttempts m_k6EconomyLastUsefulBytes
m_k6EconomyLastPublishAttempts m_k6EconomyLastSampleAt m_k6EconomyLastProcessCpu
m_k6EconomyLastSystemCpu m_k6QuotaCrypto m_k6QuotaCertificate
m_k6QuotaCertificateWire m_k6QuotaCertificateEpoch m_k6QuotaInitAttempted
m_k6QuotaIssuerLimiter m_k6QuotaHierarchy m_k6QuotaSpent m_k6QuotaGrants
""".split()
SOURCE = ROOT / "srchybrid"
HEADER = (SOURCE / "LiveTunnelQuotaAuthority.h").read_text()
MODULE = (SOURCE / "LiveTunnelQuotaAuthority.cpp").read_text()
CRYPTO_ADAPTER = (SOURCE / "Kad6QuotaCrypto.cpp").read_text()
SCHEDULER_H = (SOURCE / "LiveTunnelScheduler.h").read_text()
SCHEDULER_C = (SOURCE / "LiveTunnelScheduler.cpp").read_text()
FACADE = (
    (SOURCE / "LiveTunnel.h").read_text()
    + (SOURCE / "LiveTunnel.cpp").read_text()
)
PROJECT = (SOURCE / "emule.vcxproj").read_text()
class LT2QuotaAuthority(unittest.TestCase):
    def test_m2a_9864c0595b80afa7(self):
        self.assertIn("M2A_BIND_LT2_8892179A6E", MODULE)
        self.assertIn(
            "m_m2a_binding_8892179a6e = M2A_BIND_LT2_8892179A6E",
            SCHEDULER_C,
        )
        self.assertIn(
            "M2AAssignmentPolicy::RetainExisting", SCHEDULER_C
        )
    def test_m2a_618a097ce5d99ee6(self):
        self.assertIn("class LiveTunnelQuotaAuthority", HEADER)
        self.assertIn("~LiveTunnelQuotaAuthority()", HEADER)
        self.assertIn("LiveTunnelQuotaBridge", HEADER)
        self.assertIn("m_k6EconomyMutex", HEADER)
        self.assertIn("m_k6QuotaMutex", HEADER)
    def test_m2a_d6fc6e3e231f03a4(self):
        self.assertTrue(
            FIELDS and all(field in HEADER for field in FIELDS)
        )
        for field in FIELDS:
            self.assertEqual(
                len(re.findall(rf"\b{re.escape(field)}\b", HEADER)),
                1,
                f"{field} must have exactly one physical owner",
            )
            self.assertNotIn(
                field,
                FACADE,
                f"{field} leaked back into CLiveTunnel",
            )
        self.assertNotIn("kad6/", HEADER)
        self.assertNotIn("LiveTunnel.h", HEADER)
    def test_m2a_329646b1fd1d79a5(self):
        self.assertLessEqual(
            len(HEADER.splitlines()) + len(MODULE.splitlines()),
            1100,
        )
        self.assertIn("RetainExisting", SCHEDULER_C)
        self.assertIn("LiveTunnelQuotaAuthority.cpp", PROJECT)
        self.assertIn("LiveTunnelQuotaAuthority.h", PROJECT)
    def test_quota_operations_are_routed_through_the_owner(self):
        operations = """EnsureQuotaAuthority IssueQuota PresentQuota
            ConsumeQuotaGrant PruneQuotaGrants ResetQuotaState""".split()
        for operation in operations:
            self.assertIn(operation, MODULE)
            self.assertIn(f"LT2{operation}", SCHEDULER_H)
            self.assertIn(f"LT2{operation}", SCHEDULER_C)
    def test_replay_and_grants_share_the_quota_lock(self):
        self.assertIn("VerifyK6QuotaPresentation", MODULE)
        self.assertIn("CommitQuotaGrant", MODULE)
        self.assertIn("ConsumeQuotaGrant", MODULE)
        self.assertGreaterEqual(
            MODULE.count("m_k6QuotaMutex"), 8
        )
    def test_fair_callbacks_run_between_owner_lock_scopes(self):
        start = MODULE.index("void M2A_LT2_PresentQuotaBridge")
        end = MODULE.index(
            "bool M2A_LT2_ConsumeQuotaGrantBridge", start
        )
        bridge = MODULE[start:end]
        prepare = bridge.index("PrepareQuotaPresentation")
        callback = bridge.index("if (!registerFair")
        commit = bridge.index("CommitQuotaGrant")
        self.assertLess(prepare, callback)
        self.assertLess(callback, commit)
    def test_crypto_adapter_contains_no_lt2_domain_rules(self):
        self.assertNotIn("LiveTunnelQuotaBridge", CRYPTO_ADAPTER)
        self.assertNotIn("M2A_LT2_", CRYPTO_ADAPTER)
if __name__ == "__main__":
    unittest.main()
