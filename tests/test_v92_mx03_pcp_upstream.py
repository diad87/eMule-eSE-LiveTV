#!/usr/bin/env python3
"""Host contracts for MX03 / TH92-3 PCP local-to-upstream policy."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


class Mx03PcpUpstreamHostContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.header = read("libnatmap/include/natmap/pcp_upstream_policy.h")
        cls.source = read("libnatmap/src/pcp_upstream_policy.cpp")
        cls.native = read("libnatmap/tests/test_pcp_upstream_policy.cpp")
        cls.manager_h = read("srchybrid/DirectReachabilityManager.h")
        cls.manager = read("srchybrid/DirectReachabilityManager.cpp")
        cls.dialog = read("srchybrid/EmuleDlg.cpp")
        cls.mailbox = read("libnatmap/src/mapping_result_mailbox.cpp")
        cls.pcp = read("srchybrid/UPnPImplPCP.cpp")
        cls.pcp_h = read("srchybrid/UPnPImplPCP.h")
        cls.upnp_base = read("srchybrid/UPnPImpl.cpp")
        cls.make = read("libnatmap/make.bat")
        cls.project = read("srchybrid/emule.vcxproj")

    def test_runbook_matrix_and_reason_mapping_are_frozen(self) -> None:
        for marker in (
            "PcpUpstreamOutcome", "PcpUpstreamDisposition",
            "NoGlobalCandidate", "UpstreamDenied", "ChainIncomplete",
            "EndpointRejected", "Candidate", "Verified", "StaleProof",
            "NoGateway", "OperatorDenied", "CgnatWithoutLease",
            "ServerCallbackFailed",
        ):
            self.assertIn(marker, self.header)
        for marker in (
            "TestRunbookTableAndReasons",
            "TestCandidateThenExactCurrentProofPromotes",
            "TestStaleWrongAndIncompleteNeverPromote",
            "TestGatewayAndTransportContinuityRejectsDisconnectedInputs",
            "TestGenerationRouteOwnershipAndRequestBounds",
        ):
            self.assertIn(marker, self.native)

    def test_upstream_is_authorized_and_continues_both_transport_chains(self) -> None:
        for marker in (
            "upstream_gateways.count > upstream_gateways.addresses.size()",
            "IsAuthorizedGateway(upstream_gateways, data.gateway)",
            "cpe_tcp_chain.FinalEndpoint()",
            "cpe_udp_chain.FinalEndpoint()",
            "SameAddress(tcp->granted_external_endpoint.address",
        ):
            self.assertIn(marker, self.source)
        self.assertIn("wrong_gateway", self.native)
        self.assertIn("wrong_tcp", self.native)
        self.assertIn("wrong_udp", self.native)
        self.assertIn("split_public", self.native)

    def test_cpe_map_never_becomes_global_proof(self) -> None:
        self.assertIn("cpe_tcp_chain.Evaluate() != NatChainStatus::NeedsAuthorizedUpstream", self.source)
        self.assertIn("PcpUpstreamOutcome::Mapped", self.source)
        self.assertIn("data.source != MapperSource::PcpUpstream", self.source)
        self.assertNotIn("sendto(", self.source)

    def test_candidate_is_separate_from_exact_proof(self) -> None:
        self.assertIn("publisher.ApplyMapping(", self.source)
        self.assertIn("publisher.Promote(*proof", self.source)
        self.assertIn("ApplyMapping already published an unverified candidate", self.source)
        self.assertIn("decision.update", self.source)
        self.assertIn("!candidate_only.snapshot().HasVerifiedGlobalCandidate()", self.native)
        self.assertIn("TestNegativeObservationsWithdrawAnAlreadyVerifiedPair", self.native)
        self.assertIn("old proof is still", self.native)
        self.assertIn("WithdrawRejectedObservation", self.source)

    def test_product_bridge_consumes_one_atomic_bundle(self) -> None:
        self.assertIn("ObservePcpUpstreamBundle(", self.manager_h)
        self.assertIn(
            "const natmap::PcpUpstreamResultBundle& bundle",
            self.manager_h,
        )
        body = self.manager[
            self.manager.index(
                "CDirectReachabilityManager::ObservePcpUpstreamBundle("
            ):self.manager.index(
                "bool CDirectReachabilityManager::ObserveMapperEpochReset()"
            )
        ]
        for marker in (
            "bundle.IsValid()",
            "BuildUpstreamGatewayCandidates(",
            "cpeTcpChain.AppendLease(cpeTcp",
            "cpeUdpChain.AppendLease(cpeUdp",
            "tcpChain.AppendLease(upstreamTcp",
            "udpChain.AppendLease(upstreamUdp",
            "ProjectPcpFinalMapperResult(",
            "m_pcpCpeResult = cpeData",
            "WithdrawRejectedObservation()",
        ):
            self.assertIn(marker, body)
        publisher = body.index("m_mappedCandidates.ApplyMapping(")
        for prepared in (
            "tcpLease.Activate(",
            "udpLease.Activate(",
            "BuildMapperTopologyIdentity(",
        ):
            self.assertLess(body.index(prepared), publisher)
        self.assertGreater(body.index("m_snapshot.topology_generation ="), publisher)

    def test_ui_takes_bundle_first_and_rejection_is_not_success(self) -> None:
        take_bundle = self.dialog.index("TakePcpUpstreamBundle(")
        take_ordinary = self.dialog.index("m_mappingResultMailbox->Take(")
        self.assertLess(take_bundle, take_ordinary)
        observe = self.dialog.index("ObservePcpUpstreamBundle(")
        reject = self.dialog.index(
            "if (!decision.allows_global_candidate())", observe
        )
        force_failed = self.dialog.index(
            "resultCode = CUPnPImpl::UPNP_FAILED", reject
        )
        stop_worker = self.dialog.index(
            "impl->StopAsyncFind()", force_failed
        )
        exact_cleanup = self.dialog.index(
            "impl->DeletePortsForGeneration(", force_failed
        )
        switch_impl = self.dialog.index(
            "SwitchImplentation()", exact_cleanup
        )
        record_success = self.dialog.index("impl->RecordLeaseSuccess()")
        self.assertLess(observe, force_failed)
        self.assertLess(force_failed, stop_worker)
        self.assertLess(stop_worker, exact_cleanup)
        self.assertLess(exact_cleanup, switch_impl)
        self.assertLess(force_failed, record_success)
        self.assertIn("&& !bPcpUpstreamBundle", self.dialog)

    def test_negative_refresh_bundle_arms_one_generation_bound_recovery(self) -> None:
        bundle_block = self.dialog[
            self.dialog.index(
                "if (bPcpUpstreamBundle\n"
                "\t\t&& theApp.directreachability != NULL)"
            ):
            self.dialog.index("if (bPcpTcpOnlyCgnatFailure")
        ]
        self.assertEqual(1, bundle_block.count("ResetForNetworkChange("))
        self.assertEqual(1, bundle_block.count("ShouldRestartAdvertisementLogin("))
        recovery = bundle_block[
            bundle_block.index("// A negative refresh has just retired"):
            bundle_block.index("const natmap::AdvertisementObservation advertisement{")
        ]
        # The three guards keep initial failure on normal fallback, accept only
        # a withdrawn global candidate, and reject stale duplicate delivery.
        self.assertIn("bWasRefresh", recovery)
        self.assertIn("!decision.allows_global_candidate()", recovery)
        self.assertIn("currentGeneration > previousGeneration", recovery)
        self.assertIn("m_bUPnPRouteRecoveryPending = true", recovery)
        self.assertIn("UPnPMonotonicMilliseconds()", recovery)
        self.assertIn("RecordSuccess(", bundle_block)
        self.assertIn("&& !bPcpUpstreamBundle", self.dialog)

    def test_bundle_validation_fences_negative_and_hostile_inputs(self) -> None:
        for marker in (
            "outcome == Outcome::Absent",
            "IsCanonicalEmptyEvidence(authorized_evidence)",
            "authorized_evidence.evidence_count != 1",
            "GatewayCandidateSource::ExplicitConfiguration",
            "upstream.gateway.port != 5351",
            "IsCanonicalRfc1918(evidence.address)",
            "upstream.ownership != OwnershipState::OwnedByUs",
        ):
            self.assertIn(marker, self.mailbox)
        mailbox_native = read(
            "libnatmap/tests/test_mapping_result_mailbox.cpp"
        )
        for marker in (
            "CHECK(absent.IsValid())",
            "absent.authorized_evidence.evidence_count = 1",
            "CHECK(denied.IsValid())",
            "hostile.upstream.gateway.address.bytes[3] = 2",
            "hostile.upstream.request_interface_index = 13",
            "hostile.upstream.request_id = 42",
        ):
            self.assertIn(marker, mailbox_native)

    def test_worker_is_default_off_but_rfc1918_always_reports_bundle(self) -> None:
        for marker in (
            '_T("PcpUpstreamEnabled"), 0',
            "if (cpeNeedsUpstream)",
            "if (!upstreamEnabled ||",
            "Absent;",
            "SendPcpUpstreamBundleMessage(",
            "data.gateway = natmap::Endpoint{",
            "CUPnPImplPCP::PCP_PORT",
        ):
            self.assertIn(marker, self.pcp)
        self.assertIn("PublishPcpUpstreamBundle(bundle)", self.upnp_base)

    def test_worker_separates_bind_address_and_pcp_client_identity(self) -> None:
        self.assertIn(
            "const std::array<uint8, 16>& bindAddress",
            self.pcp_h,
        )
        exchange = self.pcp[
            self.pcp.index("bool CUPnPImplPCP::ExchangeMap("):
            self.pcp.index("bool CUPnPImplPCP::MapPort(")
        ]
        self.assertIn("ExtractIPv4(bindAddress, clientIP)", exchange)
        self.assertNotIn("ExtractIPv4(m_clientAddress", exchange)
        self.assertIn("request.client_ip = clientAddress", self.pcp)
        self.assertIn("m_pOwner->m_clientAddress,\n\t\t\t\t\t\tupstreamClientAddress", self.pcp)

    def test_worker_keeps_two_layer_identities_and_reverse_cleanup(self) -> None:
        for marker in (
            "m_upstreamTcpIdentity",
            "m_upstreamUdpIdentity",
            "m_oldUpstreamTcpIdentity",
            "m_oldUpstreamUdpIdentity",
            "m_dwOldUpstreamGatewayIP",
            "m_oldUpstreamClientAddress",
        ):
            self.assertIn(marker, self.pcp_h)
        cleanup = self.pcp[
            self.pcp.index("bool CUPnPImplPCP::DeletePorts(bool bSkipLock)"):
            self.pcp.index("bool CUPnPImplPCP::GenerateNonce(")
        ]
        order = [
            cleanup.index("m_oldUpstreamUdpIdentity))"),
            cleanup.index("m_oldUpstreamTcpIdentity))"),
            cleanup.index("m_oldUDPIdentity))"),
            cleanup.index("m_oldTCPIdentity))"),
        ]
        self.assertEqual(order, sorted(order))
        self.assertIn(
            "m_pOwner->m_udpIdentity.IsEmpty()", self.pcp
        )
        self.assertIn(
            "m_pOwner->m_tcpIdentity.nonce", self.pcp
        )
        self.assertIn(
            "ownership_identity_digest.begin() +",
            self.pcp,
        )
        self.assertIn("rollbackUpstreamGateway", self.pcp)
        self.assertIn("rollbackUpstreamClient", self.pcp)
        self.assertIn(
            "if (!m_pOwner->m_upstreamTcpIdentity.IsValid()",
            self.pcp,
        )

    def test_gateway_change_cleanup_keeps_the_previous_owner_on_delete_failure(self) -> None:
        start = self.pcp.index("if (!succeeded) {", self.pcp.index("routeStable"))
        end = self.pcp.index("if (succeeded) {", start)
        cleanup = self.pcp[start:end]
        self.assertIn("const bool existingUpstreamIdentity", cleanup)
        self.assertIn("m_pOwner->m_dwUpstreamGatewayIP", cleanup)
        self.assertIn("m_pOwner->m_upstreamClientAddress", cleanup)
        self.assertLess(
            cleanup.index("existingUpstreamIdentity"),
            cleanup.index("rollbackUpstreamGateway"),
        )
        self.assertIn("while either DELETE failed", cleanup)

    def test_only_explicit_pcp_policy_results_are_operator_denial(self) -> None:
        self.assertIn("bool IsOperatorPolicyDenial", self.pcp)
        self.assertIn("PcpResultCode::NotAuthorized", self.pcp)
        self.assertIn("PcpResultCode::UserExceededQuota", self.pcp)
        self.assertNotIn(
            "upstreamResult !=\n\t\t\t\t\t\t\tnatmap::PcpResultCode::Success",
            self.pcp,
        )

    def test_tcp_only_private_cpe_is_correlated_and_withdrawn_by_reason(self) -> None:
        self.assertIn("tcpOnlyPrivateCpeFailure", self.pcp)
        self.assertIn("CgnatWithoutLease", self.pcp)
        self.assertIn("SendMapperResultMessage(", self.pcp)
        self.assertLess(
            self.pcp.index("tcpOnlyPrivateCpeFailure = true"),
            self.pcp.index("PcpPairTransaction upstreamTransaction"),
        )
        self.assertIn("ObservePcpCpeAtomicityFailure(", self.manager_h)
        self.assertIn("ReasonCode::CgnatWithoutLease", self.manager)
        self.assertIn("ObservePcpCpeAtomicityFailure(", self.dialog)
        tcp_only_block = self.dialog[
            self.dialog.index("if (bPcpTcpOnlyCgnatFailure"):
            self.dialog.index("// A failed refresh", self.dialog.index(
                "if (bPcpTcpOnlyCgnatFailure"))
        ]
        self.assertNotIn(
            "ObserveMappingLoss();",
            tcp_only_block,
        )

    def test_negative_results_require_failed_verification_and_true_pcp_code(self) -> None:
        for marker in (
            "upstream.verification == VerificationState::Failed",
            "IsOperatorDenialPcpResultCode",
            "IsTransportFailurePcpResultCode",
        ):
            self.assertIn(marker, self.mailbox)
        self.assertIn("BuildFailedUpstream(", self.pcp)
        self.assertIn("protocolResult", self.pcp)
        self.assertIn("response.result ==", self.pcp)
        self.assertIn("PcpResultCode::NetworkFailure", self.pcp)
        self.assertIn(
            "natmap::PcpResultCode upstreamResult =\n"
            "\t\t\t\t\tnatmap::PcpResultCode::NetworkFailure;",
            self.pcp,
        )

    def test_staged_udp_epoch_failure_rolls_back_both_layers_in_reverse(self) -> None:
        cpe_stage = self.pcp[
            self.pcp.index("const bool udpStaged ="):
            self.pcp.index("const bool operationStale")
        ]
        self.assertIn("cpeAtomicPairFailure = udpMapped && !udpStaged", cpe_stage)
        self.assertIn("cpeEpochReset", cpe_stage)
        atomic_cleanup = cpe_stage[
            cpe_stage.index("if (cpeAtomicPairFailure)"):
            cpe_stage.index("} else {", cpe_stage.index(
                "if (cpeAtomicPairFailure)"))
        ]
        self.assertLess(
            atomic_cleanup.index("m_pOwner->m_udpIdentity"),
            atomic_cleanup.index("m_pOwner->m_tcpIdentity"),
        )
        ordinary_failure = cpe_stage[cpe_stage.index("} else {", cpe_stage.index(
            "if (cpeAtomicPairFailure)")):]
        self.assertIn("GetTcpRollbackIdentity", ordinary_failure)
        self.assertNotIn("m_pOwner->m_udpIdentity", ordinary_failure)
        upstream_stage = self.pcp[
            self.pcp.index("const bool upstreamUdpStaged ="):
            self.pcp.index("natmap::PcpPairCommit upstreamCommit")
        ]
        self.assertIn("upstreamUdpMapped", upstream_stage)
        self.assertIn("m_pOwner->m_upstreamUdpIdentity", upstream_stage)
        self.assertIn("upstreamResult = udpResult ==", upstream_stage)
        self.assertIn("PcpResultCode::NetworkFailure", upstream_stage)
        cleanup = self.pcp[
            self.pcp.index("if (!succeeded) {", self.pcp.index("routeStable")):
            self.pcp.index("if (succeeded) {", self.pcp.index("routeStable"))
        ]
        self.assertLess(
            cleanup.index("m_pOwner->m_upstreamUdpIdentity"),
            cleanup.index("m_pOwner->m_upstreamTcpIdentity"),
        )
        self.assertLess(
            cleanup.index("m_pOwner->m_udpIdentity"),
            cleanup.index("m_pOwner->m_tcpIdentity"),
        )
        self.assertIn("failure.mapper_epoch_reset = cpeEpochReset", self.pcp)

    def test_pcp_atomic_epoch_reset_has_one_retirement_and_keeps_natpmp_path(self) -> None:
        atomic_block = self.dialog[
            self.dialog.index("if (bPcpTcpOnlyCgnatFailure"):
            self.dialog.index("// A failed refresh", self.dialog.index(
                "if (bPcpTcpOnlyCgnatFailure"))
        ]
        self.assertEqual(
            1, atomic_block.count("ObservePcpCpeAtomicityFailure("),
        )
        self.assertEqual(
            1, atomic_block.count("ShouldRestartAdvertisementLogin("),
        )
        self.assertEqual(
            1, atomic_block.count("ResetForNetworkChange("),
        )
        reset_call = self.dialog.index("ObserveMapperEpochReset();")
        generic_reset = self.dialog[
            self.dialog.rfind("if (resultCode != CUPnPImpl::UPNP_OK", 0, reset_call):
            self.dialog.index("if (!bWasRefresh)", reset_call)
        ]
        self.assertIn("&& !bPcpTcpOnlyCgnatFailure", generic_reset)
        self.assertIn("ObserveMapperEpochReset();", generic_reset)
        self.assertIn("NAT-PMP mapper reset", generic_reset)

    def test_final_identity_binds_cpe_and_upstream_layers(self) -> None:
        self.assertIn("FinalPcpLayerIdentity", self.source)
        self.assertIn("projected.ownership_identity_digest", self.source)
        self.assertIn("TestCpeIdentityRotationReplacesFinalCandidateAtomically", self.native)
        self.assertIn("MappedCandidateUpdate::Replaced", self.native)
        self.assertIn("MappedCandidateUpdate::Rejected", self.native)

    def test_failed_outcome_is_noroute_while_absent_and_denied_keep_their_reasons(self) -> None:
        policy_test = read("libnatmap/tests/test_pcp_upstream_policy.cpp")
        self.assertIn("PcpUpstreamOutcome::Failed", policy_test)
        self.assertIn("failed.reason == ReasonCode::NoRoute", policy_test)
        self.assertIn("absent.reason == ReasonCode::NoGateway", policy_test)
        self.assertIn("denied.reason == ReasonCode::OperatorDenied", policy_test)

    def test_wrong_mailbox_take_type_preserves_the_exact_delivery(self) -> None:
        self.assertIn("if (found->is_bundle)\n        return false;", self.mailbox)
        mailbox_native = read("libnatmap/tests/test_mapping_result_mailbox.cpp")
        self.assertIn("TestWrongPayloadTypeDoesNotConsumeDelivery", mailbox_native)
        self.assertIn("!mailbox.Take(bundled.delivery_id, ordinaryTaken)", mailbox_native)

    def test_request_limits_do_not_create_filter_ranges_or_port_spray(self) -> None:
        for marker in (
            "PreferFailureRequiresDocumentedExactPort",
            "FilterRequiresConcretePeer", "PortSetRequiresNetLabOrOne",
            "request.port_set_size != 1",
        ):
            self.assertIn(marker, self.source)
        self.assertNotIn("KadRange", self.header)
        self.assertIn("FILTER wire encoder", self.header)
        self.assertIn("EncodePcpMapRequestForProduction", self.header)

    def test_production_encoders_cannot_bypass_request_policy(self) -> None:
        upnp = read("srchybrid/UPnPImplPCP.cpp")
        firewall = read("srchybrid/FirewallProberV6.cpp")
        for source in (upnp, firewall):
            self.assertIn("PcpMapRequestPolicyInput requestPolicy", source)
            self.assertIn("EncodePcpMapRequestForProduction", source)
        raw_callers = [
            str(path.relative_to(ROOT))
            for path in (ROOT / "srchybrid").rglob("*.cpp")
            if "EncodePcpMapRequest(" in path.read_text(
                encoding="utf-8", errors="ignore"
            )
        ]
        self.assertEqual(
            [],
            raw_callers,
            "production PCP callers must use the policy-enforcing encoder",
        )

    def test_builds_include_the_policy(self) -> None:
        self.assertIn("test_pcp_upstream_policy.exe", self.make)
        self.assertIn("pcp_upstream_policy.cpp", self.make)
        self.assertIn("pcp_upstream_policy.cpp", self.project)
        self.assertIn("pcp_upstream_policy.h", self.project)


if __name__ == "__main__":
    unittest.main(verbosity=2)
