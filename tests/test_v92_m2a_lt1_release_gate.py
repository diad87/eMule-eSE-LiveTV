import pathlib
import re
import unittest
ROOT = pathlib.Path(__file__).resolve().parents[1]
HEADER = ROOT / "srchybrid" / "LiveTunnelReleaseGate.h"
SOURCE = ROOT / "srchybrid" / "LiveTunnelReleaseGate.cpp"
KAD6_BUILD = ROOT / "libkad6" / "make_crypto_vectors.bat"
class LT1ReleaseGateEvidence(unittest.TestCase):
    def test_m2a_f96f8c1e053f4f7f(self):
        self.assertIn("MakeM2AModuleHandle(new LiveTunnelReleaseGate(parent))",
            SOURCE.read_text(encoding="utf-8"))
    def test_m2a_af253fe578d81a9a(self):
        self.assertTrue(all(token in SOURCE.read_text(encoding="utf-8")
            for token in ("RunLiveTunnelReleaseGateCharacterizationSelfTest",
            "gate.ConsumeChallenge(challenge, 101)", "std::thread reader")))
    def test_m2a_63e348bda48632cf(self):
        self.assertTrue(HEADER.is_file() and SOURCE.is_file())
        header = HEADER.read_text(encoding="utf-8")
        fields = ("m_k6PublicStableEnabled", "m_k6PublicBetaEnabled",
            "m_k6ReleaseEvidenceLoaded", "m_k6ReleaseEvidencePresent",
            "m_k6ReleaseRuntimeHealthy", "m_k6ReleaseStatus",
            "m_k6ReleaseEvidence", "m_k6ReleaseLock", "m_k6ReleaseChallenge",
            "m_k6ReleaseChallengeExpires", "m_k6ReleaseChallengeReady",
            "m_k6ExitNoticeServer")
        self.assertTrue(all(len(re.findall(
            rf"\b{re.escape(field)}\b", header)) == 1 for field in fields))
    def test_m2a_1374f4a4efbb254c(self):
        self.assertLessEqual(sum(len(path.read_text(
            encoding="utf-8").splitlines()) for path in (HEADER, SOURCE)), 800)

    def test_exit_notice_target_links_the_lt1_and_kad6_owners(self):
        recipe = KAD6_BUILD.read_text(encoding="utf-8")
        start = recipe.index("/Febuild\\test_kad6_exit_notice_server.exe")
        end = recipe.index("if errorlevel 1 (echo EXIT NOTICE SERVER BUILD FAILED", start)
        target = recipe[start:end]
        for source in (
            "..\\srchybrid\\Kad6ExitNoticeServer.cpp",
            "..\\srchybrid\\LiveTunnelReleaseGate.cpp",
            "src\\kad6_release.cpp",
            "src\\kad6_exit_notice.cpp",
            "src\\kad6_tags.cpp",
            "src\\kad6_address.cpp",
        ):
            self.assertIn(source, target)
