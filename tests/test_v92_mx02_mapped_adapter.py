#!/usr/bin/env python3
"""Host integration checks for MX02 / TH92-2."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def function_body(
    source: str, signature: str, next_signature: str
) -> str:
    start = source.index(signature)
    return source[start : source.index(next_signature, start)]


class Mx02MappedAdapterHostContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.header = read(
            "libnatmap/include/natmap/mapped_candidate_adapter.h"
        )
        cls.adapter = read(
            "libnatmap/src/mapped_candidate_adapter.cpp"
        )
        cls.native = read(
            "libnatmap/tests/test_mapped_candidate_adapter.cpp"
        )
        cls.manager_h = read("srchybrid/DirectReachabilityManager.h")
        cls.manager = read("srchybrid/DirectReachabilityManager.cpp")
        cls.dialog = read("srchybrid/EmuleDlg.cpp")
        cls.consumer = read(
            "tests/fixtures/direct_candidate_snapshot_v1_consumer.py"
        )
        cls.make = read("libnatmap/make.bat")
        cls.project = read("srchybrid/emule.vcxproj")

    def test_actionable_view_is_typed_local_and_immutable(self) -> None:
        for marker in (
            "Process-local actionable view",
            "const Endpoint& local_endpoint()",
            "const Endpoint& published_endpoint()",
            "friend class MappedCandidatePublisher",
            "no JSON or serialization surface",
        ):
            self.assertIn(marker, self.header)
        self.assertNotIn("nlohmann", self.header)
        self.assertNotIn("rapidjson", self.header)

    def test_mapper_verification_never_promotes_candidate(self) -> None:
        apply_body = function_body(
            self.adapter,
            "MappedCandidatePublisher::ApplyMapping(",
            "MappedCandidatePromotion MappedCandidatePublisher::Promote(",
        )
        self.assertNotIn("data.verification", apply_body)
        self.assertIn(
            "MappedCandidateVerification::Candidate", apply_body
        )
        promote_body = function_body(
            self.adapter,
            "MappedCandidatePublisher::Promote(",
            "MappedCandidatePublisher::WithdrawExpired(",
        )
        for marker in (
            "EvidenceKind::ServerHighId",
            "EvidenceKind::InboundTcpAccept",
            "IsFreshFor",
            "proof.attempt.topology_generation",
            "candidate.published_endpoint()",
        ):
            self.assertIn(marker, self.adapter)
        self.assertIn("IsFreshTcpProof", promote_body)

    def test_tdd_matrix_covers_mx02_boundaries(self) -> None:
        for marker in (
            "TestMapReadbackNeverPromotesWithoutInboundProof",
            "TestStaleProofCannotPromote",
            "TestMixedTcpUdpPairDoesNotOverpromote",
            "TestIdenticalRenewalKeepsIdsAndGeneration",
            "TestEndpointGatewayAndRouteChangesInvalidate",
            "TestMonotonicEpochRenewalKeepsIdentityAndUpdatesEpoch",
            "TestEpochResetRequiresReplacement",
            "TestOwnershipNonceChangeReplacesIdAndWithdrawsProof",
            "TestOwnershipDigestChangeReplacesIdAndWithdrawsProof",
            "TestGatewayPortPreflightForcesCommittedReplacement",
            "TestTcpOnlyCommonResultRemainsFailClosed",
            "TestExpiryAndShutdownWithdrawAndFenceCallbacks",
            "TestAtomicPairExpiryAtExactBoundaryBothOrders",
            "TestRenewalAfterExpiredPairReplacesIdentityAndProof",
            "TestExpiredRenewalRejectedCommittedOldWithdrawsPair",
            "TestExpiredStaleAndInvalidResultsWithdrawPair",
            "TestRejectedResultJustBeforeExpiryKeepsPair",
            "TestOverflowOnExpiryAndIdentityChangeClosesEmpty",
            "TestCandidateIdExhaustionClosesEmpty",
            "TestPublicationSequenceOverflowClosesEmptyEveryPath",
            "TestOnlyOwnerThreadCanPublishSnapshot",
            "TestCommittedMainThreadGenerationPublishesWholePair",
        ):
            self.assertIn(marker, self.native)

    def test_ownership_identity_is_frozen_but_never_exported(self) -> None:
        for marker in (
            "std::array<std::uint8_t, 12> ownership_nonce_",
            "std::array<std::uint8_t, 32> ownership_identity_digest_",
            "ownership_nonce_ == data.ownership_nonce",
            "ownership_identity_digest_ ==",
        ):
            self.assertIn(
                marker,
                self.header if marker.startswith("std::array") else
                self.adapter,
            )
        self.assertNotIn("ownership_nonce() const", self.header)
        self.assertNotIn(
            "ownership_identity_digest() const", self.header
        )
        self.assertNotIn("ownership_nonce", self.consumer)

    def test_manager_owns_and_routes_from_typed_snapshot(self) -> None:
        for marker in (
            "natmap::MappedCandidatePublisher m_mappedCandidates",
            "GetMappedCandidateSnapshot() const",
            "ShutdownMappedCandidates()",
        ):
            self.assertIn(marker, self.manager_h)
        select = function_body(
            self.manager,
            "CDirectReachabilityManager::SelectPreferredRoute(",
            "bool CDirectReachabilityManager::HasVerifiedEd2kReachability()",
        )
        self.assertIn("m_mappedCandidates.snapshot().Find(", select)
        self.assertIn(
            "MappedCandidateVerification::Verified", select
        )
        observe = function_body(
            self.manager,
            "bool CDirectReachabilityManager::ObserveMapperResult(",
            "bool CDirectReachabilityManager::ObserveMapperEpochReset()",
        )
        self.assertIn("m_mappedCandidates.ApplyMapping(", observe)
        self.assertIn("DisableMappedPlanes", observe)
        preflight = observe.index(
            "m_mappedCandidates.RequiresReplacement("
        )
        legacy = observe.index("ObserveMappedPorts(")
        publish = observe.index("m_mappedCandidates.ApplyMapping(")
        self.assertLess(preflight, legacy)
        self.assertLess(legacy, publish)
        self.assertIn(
            "forceMappedGenerationAdvance, routeBinding", observe
        )
        mapped_ports = self.manager[
            self.manager.index(
                "bool CDirectReachabilityManager::ObserveMappedPorts("
            ):
        ]
        self.assertIn("bool bForceGenerationAdvance", mapped_ports)
        self.assertIn("&& !bForceGenerationAdvance", mapped_ports)

    def test_atomic_pair_and_overflow_are_fail_closed(self) -> None:
        for marker in (
            "AnyCandidateExpired(snapshot_, now_monotonic_ms)",
            "RetireExpiredPair()",
            "CloseFailClosed(",
            "IsCompleteSnapshot(next)",
            "snapshot_ = empty",
        ):
            self.assertIn(marker, self.adapter)
        withdraw = function_body(
            self.adapter,
            "MappedCandidatePublisher::WithdrawExpired(",
            "MappedCandidateRetirement MappedCandidatePublisher::Invalidate(",
        )
        self.assertNotIn("next.candidates_", withdraw)
        self.assertIn("RetireExpiredPair()", withdraw)
        apply_body = function_body(
            self.adapter,
            "MappedCandidatePublisher::ApplyMapping(",
            "MappedCandidatePromotion MappedCandidatePublisher::Promote(",
        )
        self.assertIn("prior_pair_expired", apply_body)
        self.assertIn("RejectAfterExpiryCheck", apply_body)
        self.assertIn("RetireExpiredPair()", apply_body)

    def test_epoch_value_is_not_mapping_identity(self) -> None:
        same_owned = function_body(
            self.adapter,
            "bool MappedCandidate::SameOwnedMapping(",
            "const MappedCandidate* MappedCandidateSnapshot::Find(",
        )
        self.assertNotIn("mapper_epoch_ ==", same_owned)
        apply_body = function_body(
            self.adapter,
            "MappedCandidatePublisher::ApplyMapping(",
            "MappedCandidatePromotion MappedCandidatePublisher::Promote(",
        )
        self.assertIn(
            "candidate.mapper_epoch_ = data.mapper_epoch", apply_body
        )

    def test_main_thread_publication_and_shutdown_fence_are_wired(self) -> None:
        self.assertIn("std::this_thread::get_id()", self.adapter)
        self.assertIn("snapshot_ = next", self.adapter)
        self.assertIn("AssertMainThread()", self.manager)
        close = function_body(
            self.dialog,
            "void CemuleDlg::OnClose()",
            "void CemuleDlg::DestroyMiniMule()",
        )
        shutdown = close.index("ShutdownMappedCandidates()")
        mailbox = close.index("m_mappingResultMailbox->Close()")
        self.assertLess(shutdown, mailbox)
        shutdown_body = function_body(
            self.manager,
            "bool CDirectReachabilityManager::ShutdownMappedCandidates()",
            "natmap::DirectRouteSelection",
        )
        self.assertNotIn("DisableMappedPlanes(", shutdown_body)
        self.assertNotIn("Invalidate(", shutdown_body)
        self.assertIn("m_bEnabled.store(false", shutdown_body)

    def test_fake_consumer_remains_contract_only(self) -> None:
        self.assertNotIn("libnatmap", self.consumer)
        self.assertNotIn("DirectReachabilityManager", self.consumer)
        self.assertNotIn("mapped_candidate_adapter", self.consumer)

    def test_build_manifests_include_the_adapter(self) -> None:
        for text in (self.make, self.project):
            self.assertIn("mapped_candidate_adapter.cpp", text)
        self.assertIn("test_mapped_candidate_adapter.cpp", self.make)


if __name__ == "__main__":
    unittest.main()
