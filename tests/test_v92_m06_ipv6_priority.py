#!/usr/bin/env python3
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def function_body(source: str, signature: str, next_signature: str) -> str:
    start = source.index(signature)
    return source[start : source.index(next_signature, start)]


class M06Ipv6PriorityHostContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.header = read(
            "libnatmap/include/natmap/direct_route_selection.h")
        cls.policy = read("libnatmap/src/direct_route_selection.cpp")
        cls.native = read(
            "libnatmap/tests/test_direct_route_selection.cpp")
        cls.manager_h = read("srchybrid/DirectReachabilityManager.h")
        cls.manager = read("srchybrid/DirectReachabilityManager.cpp")
        cls.prober_h = read("srchybrid/FirewallProberV6.h")
        cls.prober = read("srchybrid/FirewallProberV6.cpp")
        cls.base_client = read("srchybrid/BaseClient.cpp")
        cls.updown_h = read("srchybrid/UpDownClient.h")
        cls.listen = read("srchybrid/ListenSocket.cpp")
        cls.server_connect = read("srchybrid/ServerConnect.cpp")
        cls.server_socket = read("srchybrid/ServerSocket.cpp")
        cls.search = read("srchybrid/Kademlia/Kademlia/Search.cpp")
        cls.kad = read(
            "srchybrid/Kademlia/net/KademliaUDPListener.cpp")
        cls.make = read("libnatmap/make.bat")
        cls.project = read("srchybrid/emule.vcxproj")
        cls.wp0 = read("tools/lab/test_t8_wp0.ps1")

    def test_normative_order_is_closed_and_explicit(self) -> None:
        for marker in (
            "enum class CandidateReadiness",
            "enum class PreferredDirectRoute",
            "DirectV6 = 3",
            "DirectV4 = 2",
            "MappedV4 = 1",
            "Classic = 0",
            "SelectPreferredDirectRoute",
        ):
            self.assertIn(marker, self.header)
        order = [
            "PreferredDirectRoute::DirectV6",
            "PreferredDirectRoute::DirectV4",
            "PreferredDirectRoute::MappedV4",
        ]
        offsets = [self.policy.index(marker) for marker in order]
        self.assertEqual(offsets, sorted(offsets))

    def test_only_current_verified_evidence_can_win(self) -> None:
        for marker in (
            "IsStructurallyValid",
            "generation <= current_generation",
            "IsVerifiedFor",
            "generation == current_generation",
            "CandidateUnverified",
            "StaleGeneration",
            "InvalidInput",
        ):
            self.assertIn(marker, self.policy)
        self.assertIn("TestCandidatesNeverWin", self.native)
        self.assertIn("TestGenerationFencing", self.native)
        self.assertIn("TestDirectV4EvidenceProducer", self.native)

    def test_preferences_and_old_peer_have_classic_fallbacks(self) -> None:
        for marker in (
            "TestIPv6AndMappingPreferences",
            "TestOldPeerFallback",
            "Ipv6Disabled",
            "MappingsDisabled",
            "PeerIncompatible",
        ):
            self.assertIn(marker, self.native)

    def test_manager_derives_mapped_readiness_from_owned_state(self) -> None:
        self.assertIn("SelectPreferredRoute(", self.manager_h)
        body = function_body(
            self.manager,
            "CDirectReachabilityManager::SelectPreferredRoute(",
            "bool CDirectReachabilityManager::HasVerifiedEd2kReachability()",
        )
        for marker in (
            "m_snapshot.topology_generation",
            "m_snapshot.ed2k_tcp_v4",
            "mapped.lease.IsStructurallyValid()",
            "mapped.HasClassicHighIdEvidence()",
            "CandidateReadiness::Verified",
            "CandidateReadiness::Candidate",
            "SelectPreferredDirectRoute(input)",
        ):
            self.assertIn(marker, body)

    def test_ipv6_observations_are_bound_to_the_exact_generation(self) -> None:
        for marker in (
            "m_nDetectedV6Generation",
            "m_nInboundV6Generation",
            "GetDirectRouteObservation(",
            "uint64 topologyGeneration",
        ):
            self.assertIn(marker, self.prober_h)
        observed = function_body(
            self.prober,
            "CFirewallProberV6::GetDirectRouteObservation(",
            "void CFirewallProberV6::SetDetectedV6IP(",
        )
        for marker in (
            "m_nDetectedV6Generation != currentGeneration",
            "m_nDetectedV6InterfaceIndex == 0",
            "m_nInboundV6Generation",
            "m_nInboundV6InterfaceIndex",
            "EvaluateIpv6ScopeAdmission(input)",
            "GlobalRouteObservation(",
        ):
            self.assertIn(marker, observed)

    def test_kad_never_prioritizes_stale_or_candidate_ipv6(self) -> None:
        body = function_body(
            self.kad,
            "bool CKademliaUDPListener::BuildKad6Header(",
            "bool CKademliaUDPListener::SendKad6Payload(",
        )
        for marker in (
            "GetTopologyGeneration()",
            "GetDirectRouteObservation(",
            "SelectPreferredRoute(",
            "directV6.IsVerifiedFor(topologyGeneration)",
            "PreferredDirectRoute::DirectV6",
            "candidate.priority < selectedEndpoint->priority",
        ):
            self.assertIn(marker, body)
        self.assertNotIn(
            "directV6.readiness != natmap::CandidateReadiness::Absent",
            body,
        )
        self.assertLess(
            body.index("GetDirectRouteObservation("),
            body.index("endpoints.push_back(endpoint)"),
        )

    def test_ipv6_request_and_accept_capture_generation_at_origin(self) -> None:
        self.assertIn(
            "uint64\tm_nPublicIPV6RequestGeneration",
            self.updown_h,
        )
        send = function_body(
            self.base_client,
            "void CUpDownClient::SendPublicIPRequestV6()",
            "void CUpDownClient::ProcessPublicIPAnswerV6(",
        )
        answer = function_body(
            self.base_client,
            "void CUpDownClient::ProcessPublicIPAnswerV6(",
            "void CUpDownClient::CheckFailedFileIdReqs(",
        )
        self.assertIn(
            "m_nPublicIPV6RequestGeneration = requestGeneration", send)
        self.assertIn(
            "requestGeneration != currentGeneration", answer)
        self.assertIn("addr, requestGeneration", answer)
        accept = function_body(
            self.listen,
            "void CListenSocket::OnAccept(",
            "void CListenSocket::Process()",
        )
        self.assertIn("acceptedTopologyGeneration", accept)
        self.assertIn(
            "localV6, acceptedTopologyGeneration", accept)

    def test_prober_rejects_a_generation_not_current_at_consumption(self) -> None:
        detected = function_body(
            self.prober,
            "void CFirewallProberV6::SetDetectedV6IP(",
            "bool CFirewallProberV6::CanAdvertiseModernKadSource()",
        )
        inbound = function_body(
            self.prober,
            "void CFirewallProberV6::ReportInboundV6Reachable(",
            "bool CFirewallProberV6::TryHighID()",
        )
        self.assertIn("GetPublishedTopologyGeneration()", detected)
        self.assertNotIn("GetTopologyGeneration()", detected)
        # Inbound publication deliberately checks the published generation
        # under m_lock with the CAP promotion, rather than taking an unlocked
        # snapshot first.
        self.assertIn("m_nPublishedTopologyGeneration != topologyGeneration", inbound)
        self.assertIn("CSingleLock l(&m_lock, TRUE)", inbound)
        self.assertNotIn("GetTopologyGeneration()", inbound)
        self.assertIn("m_detectedIP != localAddress", inbound)
        self.assertNotIn("m_detectedIP = localAddress", inbound)

    def test_direct_ipv4_has_a_generation_bound_product_producer(self) -> None:
        self.assertIn("ObserveDirectV4ServerState(", self.manager_h)
        producer = function_body(
            self.manager,
            "bool CDirectReachabilityManager::ObserveDirectV4ServerState(",
            "bool CDirectReachabilityManager::ObserveMappedPorts(",
        )
        for marker in (
            "IsCurrentDirectV4Attempt(attempt)",
            "EvidenceKind::ServerHighId",
            "PromoteDirectV4IfEvidenceComplete()",
        ):
            self.assertIn(marker, producer)
        direct_begin = function_body(
            self.manager,
            "bool CDirectReachabilityManager::BeginDirectV4Verification(",
            "bool CDirectReachabilityManager::BeginEd2kVerification(",
        )
        self.assertIn("address.globally_routable", direct_begin)
        self.assertIn("GetSockName(", self.server_connect)
        self.assertIn("m_nDirectSocketLocalIP", self.server_connect)
        self.assertIn("BeginDirectV4Verification(", self.server_connect)
        self.assertIn("m_directV4ServerEvidence.IsFreshFor", self.manager)
        self.assertIn("m_directV4InboundEvidence.IsFreshFor", self.manager)
        self.assertIn("CandidateReadiness::Verified", self.native)
        self.assertLess(
            self.server_connect.index("m_nDirectTopologyGeneration ="),
            self.server_connect.index("BeginEd2kVerification(attempt)"),
        )
        self.assertIn(
            "ObserveDirectV4ServerState(", self.server_socket)
        self.assertIn(
            "input.direct_v4 = m_directV4Observation", self.manager)
        self.assertNotIn(
            "const natmap::CandidateObservation directV4{}", self.kad)

    def test_direct_ipv4_selection_is_bound_to_the_published_endpoint(self) -> None:
        selected = function_body(
            self.manager,
            "CDirectReachabilityManager::SelectPreferredRoute(",
            "bool CDirectReachabilityManager::HasVerifiedEd2kReachability()",
        )
        for marker in (
            "nPublishedV4",
            "nPublishedTcpPort",
            "m_directV4Attempt.endpoint",
            "SameSocketEndpoint(",
            "input.direct_v4_endpoint_current",
        ):
            self.assertIn(marker, selected)
        kad = function_body(
            self.kad,
            "bool CKademliaUDPListener::BuildKad6Header(",
            "bool CKademliaUDPListener::SendKad6Payload(",
        )
        self.assertIn("publicV4,", kad)
        self.assertIn("theApp.GetLocalTcpPort()", kad)
        self.assertIn("TestDirectV4EndpointBinding", self.native)
        self.assertIn("DirectV4EndpointMismatch", self.native)

    def test_listener_rebinds_before_accepting_a_stale_topology_backlog(self) -> None:
        start = function_body(
            self.listen,
            "bool CListenSocket::StartListening()",
            "void CListenSocket::ReStartListening()",
        )
        self.assertIn(
            "m_nListenerTopologyGeneration =", start)
        self.assertGreaterEqual(
            start.count("bListening = false;"), 2)
        restart = function_body(
            self.listen,
            "void CListenSocket::ReStartListening()",
            "void CListenSocket::StopListening()",
        )
        self.assertIn(
            "m_SocketData.hSocket == INVALID_SOCKET", restart)
        self.assertIn("!StartListening()", restart)
        accept = function_body(
            self.listen,
            "void CListenSocket::OnAccept(",
            "void CListenSocket::Process()",
        )
        fence = accept[: accept.index("if (!nErrorCode)")]
        for marker in (
            "GetTopologyGeneration()",
            "m_nListenerTopologyGeneration",
            "Close();",
            "CloseK6PreAuth();",
            "m_nPendingConnections = 0;",
            "!StartListening()",
            "m_nListenerTopologyGeneration = 0;",
            "return;",
        ):
            self.assertIn(marker, fence)
        self.assertIn(
            "const uint64 acceptedTopologyGeneration =\n"
            "\t\t\t\tm_nListenerTopologyGeneration;",
            accept,
        )
        self.assertNotIn(
            "acceptedTopologyGeneration =\n"
            "\t\t\t\t\ttheApp.directreachability",
            accept,
        )

    def test_all_publication_consumers_use_current_generation(self) -> None:
        modern = function_body(
            self.prober,
            "bool CFirewallProberV6::CanAdvertiseModernKadSource()",
            "void CFirewallProberV6::DetectLocalPublicV6(",
        )
        self.assertIn(
            "GetDirectRouteObservation(\n"
            "\t\t\tcurrentGeneration, natmap::Transport::Udp)",
            modern,
        )
        self.assertIn("observation.IsVerifiedFor(currentGeneration)", modern)
        self.assertNotIn("HasInboundV6Observation()", modern)
        self.assertIn(
            "GetDirectRouteObservation(\n"
            "\t\t\t\t\t\ttopologyGeneration, natmap::Transport::Udp)",
            self.search,
        )
        self.assertIn("directV6.IsVerifiedFor(topologyGeneration)", self.search)
        self.assertNotIn("HasInboundV6Observation()", self.search)

    def test_mapped_ports_require_mapped_route_selection(self) -> None:
        body = function_body(
            self.kad,
            "bool CKademliaUDPListener::BuildKad6Header(",
            "bool CKademliaUDPListener::SendKad6Payload(",
        )
        self.assertGreaterEqual(
            body.count("PreferredDirectRoute::MappedV4"), 2)
        self.assertIn("? theApp.GetAdvertisedUdpPort()", body)
        self.assertIn(": theApp.GetLocalUdpPort()", body)
        self.assertIn("? theApp.GetAdvertisedTcpPort()", body)
        self.assertIn(": theApp.GetLocalTcpPort()", body)

    def test_complete_gates_compile_product_and_require_exact_counts(self) -> None:
        self.assertIn("test_direct_route_selection.exe", self.make)
        self.assertIn(
            r"..\libnatmap\src\direct_route_selection.cpp",
            self.project,
        )
        self.assertIn(
            r"..\libnatmap\include\natmap\direct_route_selection.h",
            self.project,
        )
        self.assertIn(
            "'test_direct_route_selection: (153) checks, 0 failures'",
            self.wp0,
        )
        self.assertIn("$m06NativeChecks -eq 153", self.wp0)
        self.assertIn("$m06HostText -match 'Ran 14 tests'", self.wp0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
