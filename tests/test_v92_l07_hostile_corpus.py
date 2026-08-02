#!/usr/bin/env python3
"""Unattended product-integration gate for V9.2 L07."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class L07HostileCorpusHostContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        def read(relative: str) -> str:
            return (ROOT / relative).read_text(encoding="utf-8")

        cls.focused = read("libnatmap/tests/test_hostile_mapper_corpus.cpp")
        cls.codec_header = read("libnatmap/include/natmap/pcp_codec.h")
        cls.codec = read("libnatmap/src/pcp_codec.cpp")
        cls.projection_header = read(
            "libnatmap/include/natmap/legacy_mapper_projection.h"
        )
        cls.projection = read(
            "libnatmap/src/legacy_mapper_projection.cpp"
        )
        cls.pcp_projection_header = read(
            "libnatmap/include/natmap/pcp_map_projection.h"
        )
        cls.pcp_projection = read(
            "libnatmap/src/pcp_map_projection.cpp"
        )
        cls.pcp_product = read("srchybrid/UPnPImplPCP.cpp")
        cls.manager = read("srchybrid/DirectReachabilityManager.cpp")
        cls.make = read("libnatmap/make.bat")

    def test_all_required_hostile_families_are_executable(self) -> None:
        main = self.focused[self.focused.index("int main()") :]
        markers = (
            "TestEverySizeFromZeroThroughMaximumPlusOneFailsClosed",
            "TestReservedFieldsAreIgnoredWithoutSemanticChange",
            "TestZeroExternalPortIsRejectedAtSemanticBoundary",
            "TestExtremeLifetimeIsBoundedWithoutOverflow",
            "TestEpochWrapInvalidatesPriorSnapshotWithoutMutatingInput",
            "TestWrongNonceIsRejectedWithoutOutputMutation",
            "TestUnroutableAddressIsRejectedWithoutSnapshotMutation",
            "TestWrongGatewayIsRejectedWithoutSnapshotMutation",
            "TestDuplicateResponseCannotMutateDeliveryOutput",
            "TestReplayAfterNewGenerationIsRejectedWithoutMutation",
            "TestAdmissionReasonsAreDistinctAndNonMutating",
        )
        for marker in markers:
            with self.subTest(marker=marker):
                self.assertIn(marker, self.focused)
                self.assertIn(f"{marker}();", main)

    def test_size_corpus_is_exhaustive_and_not_boundary_sampling(self) -> None:
        body = self.focused[
            self.focused.index(
                "void TestEverySizeFromZeroThroughMaximumPlusOneFailsClosed()"
            ) :
            self.focused.index(
                "void TestReservedFieldsAreIgnoredWithoutSemanticChange()"
            )
        ]
        self.assertIn("size = 0", body)
        self.assertIn("size <= kPcpMaximumMessageSize + 1", body)
        self.assertIn("++size", body)
        self.assertIn("status != PcpDecodeStatus::Ok", body)
        self.assertIn("SamePcpResponse(output, before)", body)

    def test_rfc_reserved_and_lifetime_rules_are_preserved(self) -> None:
        self.assertNotIn("BadReserved", self.codec_header)
        self.assertNotIn("InvalidLifetime", self.codec_header)
        reserved = self.focused[
            self.focused.index(
                "void TestReservedFieldsAreIgnoredWithoutSemanticChange()"
            ) :
            self.focused.index(
                "void TestZeroExternalPortIsRejectedAtSemanticBoundary()"
            )
        ]
        self.assertGreaterEqual(
            reserved.count("PcpDecodeStatus::Ok"), 3
        )
        self.assertGreaterEqual(
            reserved.count("SamePcpResponse(output, expected)"), 2
        )
        self.assertIn("PcpEffectiveLifetime", self.focused)
        self.assertIn("== 86400", self.focused)
        self.assertIn(
            "std::uint32_t PcpEffectiveLifetime(",
            self.pcp_projection_header,
        )
        self.assertIn(
            "maximum_lifetime_seconds", self.pcp_projection
        )
        self.assertGreaterEqual(
            self.pcp_product.count("natmap::PcpEffectiveLifetime("), 2
        )

    def test_typed_admission_commits_output_only_after_all_guards(self) -> None:
        for marker in (
            "InvalidResult",
            "StaleGeneration",
            "UnsupportedResult",
            "UnroutableEndpoint",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, self.projection_header)
                self.assertIn(
                    f"LegacyMapperAdmissionStatus::{marker}",
                    self.projection,
                )
        admission = self.projection[
            self.projection.index(
                "LegacyMapperAdmissionStatus AdmitLegacyMapperObservation("
            ) :
            self.projection.index(
                "bool LegacyObservationAllowsSilentRenewal("
            )
        ]
        self.assertLess(
            admission.index("IsUnroutableExternalV4"),
            admission.index("observation = candidate"),
        )
        self.assertIn(
            "return LegacyMapperAdmissionStatus::Accepted", admission
        )

    def test_product_manager_uses_generation_correlated_admission(self) -> None:
        observer = self.manager[
            self.manager.index(
                "bool CDirectReachabilityManager::ObserveMapperResult("
            ) :
            self.manager.index(
                "bool CDirectReachabilityManager::ObserveMapperEpochReset()"
            )
        ]
        self.assertIn("AdmitLegacyMapperObservation(", observer)
        self.assertIn("m_snapshot.topology_generation", observer)
        self.assertIn("LegacyMapperAdmissionStatus::Accepted", observer)
        self.assertNotIn("ProjectLegacyMapperObservation(", observer)

    def test_focused_gate_is_built_and_has_an_exact_signature(self) -> None:
        self.assertIn("test_hostile_mapper_corpus.exe", self.make)
        self.assertIn(
            "build\\test_hostile_mapper_corpus.exe", self.make
        )
        self.assertIn(
            '"hostile corpus L07: %d checks, %d failures\\n"',
            self.focused,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
