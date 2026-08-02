#include "natmap/ipv6_scope_policy.h"

#include <cstdio>

using namespace natmap;

namespace {
int failures = 0;
int checks = 0;
#define CHECK(expr) do { ++checks; if (!(expr)) { ++failures; \
    std::printf("FAIL line %d: %s\n", __LINE__, #expr); } } while (0)

IpAddress V6(std::uint8_t tail) {
    IpAddress result{};
    result.family = AddressFamily::IPv6;
    result.bytes = {0x20, 0x01, 0x48, 0x60, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, tail};
    return result;
}

RouteBindingIdentity Binding(const IpAddress& address,
                             std::uint32_t interface_index = 7) {
    RouteBindingIdentity result{};
    result.local_address = address;
    result.interface_index = interface_index;
    result.family = address.family;
    result.origin = NetworkOrigin::Native;
    result.interface_present = true;
    return result;
}

Ipv6ScopeInput GlobalInput() {
    Ipv6ScopeInput input{};
    input.current_endpoint.address = V6(1);
    input.current_endpoint.port = 4662;
    input.current_endpoint.source = EndpointSource::LocalInterface;
    input.transport = Transport::Tcp;
    input.current_route_binding = Binding(input.current_endpoint.address);
    input.current_generation = 9;
    input.now_monotonic_ms = 100;
    return input;
}

PinholeEvidence ExactPinhole(const Ipv6ScopeInput& input) {
    PinholeEvidence result{};
    result.present = true;
    result.owned_by_us = true;
    result.authorized = true;
    result.endpoint = input.current_endpoint;
    result.public_endpoint = input.current_endpoint;
    result.transport = input.transport;
    result.route_binding = input.current_route_binding;
    result.generation = input.current_generation;
    result.expires_monotonic_ms = 101;
    return result;
}

void TestGlobalV6ClosedFirewallDoesNotWin() {
    const Ipv6ScopeDecision result = EvaluateIpv6ScopeAdmission(GlobalInput());
    CHECK(result.disposition == Ipv6ScopeDisposition::Candidate);
    CHECK(result.observation.readiness == CandidateReadiness::Candidate);
    CHECK(result.reason == ReasonCode::InboundFiltered);
    CHECK(!result.may_select_direct_v6 && !result.may_advertise_kad);
}

void TestGlobalV6ExactLivePinholeVerifies() {
    Ipv6ScopeInput input = GlobalInput();
    input.pinhole = ExactPinhole(input);
    const Ipv6ScopeDecision result = EvaluateIpv6ScopeAdmission(input);
    CHECK(result.disposition == Ipv6ScopeDisposition::VerifiedGlobal);
    CHECK(result.observation.IsVerifiedFor(input.current_generation));
    CHECK(result.reason == ReasonCode::None);
    CHECK(result.may_select_direct_v6 && result.may_advertise_remote_hello);
    CHECK(!result.may_advertise_kad);
    CHECK(!result.may_emit_unsanitized_report);
}

void TestExpiredPinholeWithdrawsCandidate() {
    Ipv6ScopeInput input = GlobalInput();
    input.pinhole = ExactPinhole(input);
    input.pinhole.expires_monotonic_ms = input.now_monotonic_ms;
    const Ipv6ScopeDecision result = EvaluateIpv6ScopeAdmission(input);
    CHECK(result.disposition == Ipv6ScopeDisposition::Withdraw);
    CHECK(result.observation.readiness == CandidateReadiness::Absent);
    CHECK(result.reason == ReasonCode::LeaseExpired);
}

void TestInterfaceAndGenerationChangeInvalidate() {
    Ipv6ScopeInput input = GlobalInput();
    input.pinhole = ExactPinhole(input);
    input.pinhole.route_binding.interface_index = 8;
    Ipv6ScopeDecision result = EvaluateIpv6ScopeAdmission(input);
    CHECK(result.disposition == Ipv6ScopeDisposition::Withdraw);
    CHECK(result.reason == ReasonCode::InterfaceChanged);
    input.pinhole = ExactPinhole(input);
    input.pinhole.generation = 8;
    result = EvaluateIpv6ScopeAdmission(input);
    CHECK(result.disposition == Ipv6ScopeDisposition::Withdraw);
    CHECK(result.reason == ReasonCode::StaleGeneration);
    input.pinhole = ExactPinhole(input);
    input.pinhole.transport = Transport::Udp;
    result = EvaluateIpv6ScopeAdmission(input);
    CHECK(result.reason == ReasonCode::InterfaceChanged);
}

PrivateSameLanEvidence ExactLan(const Ipv6ScopeInput& input) {
    PrivateSameLanEvidence result{};
    result.present = true;
    result.positive_same_lan_domain = true;
    result.endpoint = input.current_endpoint;
    result.peer_endpoint = input.current_endpoint;
    result.peer_endpoint.address.bytes[15] = 2;
    result.transport = input.transport;
    result.route_binding = input.current_route_binding;
    result.generation = input.current_generation;
    result.expires_monotonic_ms = 101;
    result.scope.enabled = true;
    result.scope.interface_index = input.current_route_binding.interface_index;
    result.scope.family = input.current_endpoint.address.family;
    result.scope.network = input.current_endpoint.address;
    result.scope.network.bytes[15] = 0;
    result.scope.prefix_length = 64;
    return result;
}

void TestPrivateAddressesNeverAdmitAsGlobal() {
    Ipv6ScopeInput input = GlobalInput();
    input.current_endpoint.address.bytes[0] = 0xfd;
    input.current_route_binding = Binding(input.current_endpoint.address);
    Ipv6ScopeDecision result = EvaluateIpv6ScopeAdmission(input);
    CHECK(result.disposition == Ipv6ScopeDisposition::RejectGlobal);
    CHECK(result.reason == ReasonCode::NoRoute);
    CHECK(result.address_reason == AddressReason::Ipv6UniqueLocal);
    input.current_endpoint.address = IpAddress::V4(192, 168, 1, 5);
    input.current_route_binding = Binding(input.current_endpoint.address);
    result = EvaluateIpv6ScopeAdmission(input);
    CHECK(result.disposition == Ipv6ScopeDisposition::RejectGlobal);
    CHECK(result.address_reason == AddressReason::Ipv4Rfc1918);
    input.current_endpoint.address = IpAddress::V4(169, 254, 1, 5);
    input.current_route_binding = Binding(input.current_endpoint.address);
    result = EvaluateIpv6ScopeAdmission(input);
    CHECK(result.disposition == Ipv6ScopeDisposition::RejectGlobal);
    CHECK(result.address_reason == AddressReason::Ipv4LinkLocal);
}

void TestSameLanRequiresRemotePeerInExactScope() {
    Ipv6ScopeInput input = GlobalInput();
    input.current_endpoint.address.bytes[0] = 0xfd;
    input.current_route_binding = Binding(input.current_endpoint.address);
    input.requested_scope = Ipv6ScopeRequest::SameLan;
    input.same_lan = ExactLan(input);
    const Ipv6ScopeDecision result = EvaluateIpv6ScopeAdmission(input);
    CHECK(result.disposition == Ipv6ScopeDisposition::SameLanOnly);
    CHECK(result.observation.IsVerifiedFor(input.current_generation));
    CHECK(!result.may_select_direct_v6 && !result.may_advertise_kad);
    CHECK(!result.may_advertise_remote_hello && !result.may_publish_global);
    CHECK(!result.may_emit_unsanitized_report);
    CHECK(GlobalRouteObservation(result).readiness ==
          CandidateReadiness::Absent);
    CHECK(CanUseSameLanEndpoint(result));
    input.same_lan.peer_endpoint.address.bytes[7] = 1;
    const Ipv6ScopeDecision otherPeer = EvaluateIpv6ScopeAdmission(input);
    CHECK(otherPeer.disposition == Ipv6ScopeDisposition::RejectSameLan);
    CHECK(otherPeer.reason == ReasonCode::InterfaceChanged);
    input.same_lan = ExactLan(input);
    input.same_lan.peer_endpoint.port = 0;
    const Ipv6ScopeDecision emptyPeer = EvaluateIpv6ScopeAdmission(input);
    CHECK(emptyPeer.disposition == Ipv6ScopeDisposition::RejectSameLan);
    CHECK(emptyPeer.reason == ReasonCode::NoRoute);
    input.same_lan = ExactLan(input);
    input.same_lan.peer_endpoint.source = EndpointSource::None;
    const Ipv6ScopeDecision sourceLessPeer = EvaluateIpv6ScopeAdmission(input);
    CHECK(sourceLessPeer.disposition == Ipv6ScopeDisposition::RejectSameLan);
    CHECK(sourceLessPeer.reason == ReasonCode::NoRoute);
}

void TestSameLanDoesNotCrossInterfaceOrGeneration() {
    Ipv6ScopeInput input = GlobalInput();
    input.current_endpoint.address.bytes[0] = 0xfd;
    input.current_route_binding = Binding(input.current_endpoint.address);
    input.requested_scope = Ipv6ScopeRequest::SameLan;
    input.same_lan = ExactLan(input);
    input.same_lan.route_binding.interface_index = 8;
    Ipv6ScopeDecision result = EvaluateIpv6ScopeAdmission(input);
    CHECK(result.disposition == Ipv6ScopeDisposition::RejectSameLan);
    CHECK(result.reason == ReasonCode::InterfaceChanged);
    input.same_lan = ExactLan(input);
    input.same_lan.generation = 8;
    result = EvaluateIpv6ScopeAdmission(input);
    CHECK(result.disposition == Ipv6ScopeDisposition::RejectSameLan);
    CHECK(result.reason == ReasonCode::StaleGeneration);
}

void TestIsolatedPhysicalLanAllowsUnknownButNotOverlayOrigin() {
    Ipv6ScopeInput input = GlobalInput();
    input.current_endpoint.address.bytes[0] = 0xfd;
    input.current_route_binding = Binding(input.current_endpoint.address);
    input.current_route_binding.origin = NetworkOrigin::Unknown;
    input.requested_scope = Ipv6ScopeRequest::SameLan;
    input.same_lan = ExactLan(input);
    input.same_lan.route_binding.origin = NetworkOrigin::Unknown;
    const Ipv6ScopeDecision isolated = EvaluateIpv6ScopeAdmission(input);
    CHECK(isolated.disposition == Ipv6ScopeDisposition::SameLanOnly);
    input.current_route_binding.origin = NetworkOrigin::Overlay;
    input.same_lan.route_binding.origin = NetworkOrigin::Overlay;
    const Ipv6ScopeDecision overlay = EvaluateIpv6ScopeAdmission(input);
    CHECK(overlay.disposition == Ipv6ScopeDisposition::RejectSameLan);
    CHECK(overlay.reason == ReasonCode::NoRoute);
}

void TestLinkLocalSameLanRequiresExactInterface() {
    Ipv6ScopeInput input = GlobalInput();
    input.current_endpoint.address.bytes[0] = 0xfe;
    input.current_endpoint.address.bytes[1] = 0x80;
    input.current_route_binding = Binding(input.current_endpoint.address);
    input.requested_scope = Ipv6ScopeRequest::SameLan;
    input.same_lan = ExactLan(input);
    const Ipv6ScopeDecision accepted = EvaluateIpv6ScopeAdmission(input);
    CHECK(accepted.disposition == Ipv6ScopeDisposition::SameLanOnly);
    input.same_lan.scope.interface_index = 8;
    const Ipv6ScopeDecision changed = EvaluateIpv6ScopeAdmission(input);
    CHECK(changed.disposition == Ipv6ScopeDisposition::RejectSameLan);
    CHECK(changed.reason == ReasonCode::InterfaceChanged);
}

void TestSameLanCannotReachGlobalConsumers() {
    Ipv6ScopeInput input = GlobalInput();
    input.current_endpoint.address.bytes[0] = 0xfd;
    input.current_route_binding = Binding(input.current_endpoint.address);
    input.requested_scope = Ipv6ScopeRequest::SameLan;
    input.same_lan = ExactLan(input);
    const Ipv6ScopeDecision lan = EvaluateIpv6ScopeAdmission(input);
    CHECK(CanUseSameLanEndpoint(lan));
    CHECK(GlobalRouteObservation(lan).readiness ==
          CandidateReadiness::Absent);
    CHECK(!lan.may_advertise_kad && !lan.may_advertise_remote_hello);
    CHECK(!lan.may_publish_global && !lan.may_emit_unsanitized_report);
}

void TestTransportProofDoesNotCross() {
    Ipv6ScopeInput input = GlobalInput();
    input.pinhole = ExactPinhole(input);
    Ipv6ScopeDecision tcp = EvaluateIpv6ScopeAdmission(input);
    CHECK(tcp.disposition == Ipv6ScopeDisposition::VerifiedGlobal);
    CHECK(!tcp.may_advertise_kad && tcp.may_advertise_remote_hello);

    input.transport = Transport::Udp;
    input.current_endpoint.port = 4672;
    const Ipv6ScopeDecision udpFromTcp =
        EvaluateIpv6ScopeAdmission(input);
    CHECK(udpFromTcp.disposition == Ipv6ScopeDisposition::Withdraw);
    CHECK(!udpFromTcp.may_advertise_kad);

    input.pinhole = ExactPinhole(input);
    input.pinhole.transport = Transport::Udp;
    input.pinhole.endpoint.port = input.current_endpoint.port;
    const Ipv6ScopeDecision udp = EvaluateIpv6ScopeAdmission(input);
    CHECK(udp.disposition == Ipv6ScopeDisposition::VerifiedGlobal);
    CHECK(udp.may_advertise_kad && !udp.may_advertise_remote_hello);
}

void TestPinholeReassignedEndpointDoesNotVerify() {
    Ipv6ScopeInput input = GlobalInput();
    input.pinhole = ExactPinhole(input);
    input.pinhole.public_endpoint.port = 4663;
    const Ipv6ScopeDecision result = EvaluateIpv6ScopeAdmission(input);
    CHECK(result.disposition == Ipv6ScopeDisposition::Withdraw);
    CHECK(result.reason == ReasonCode::MappingConflict);
    CHECK(!result.may_select_direct_v6 && !result.may_publish_global);
}

void TestIndependentInboundSurvivesExpiredPinhole() {
    Ipv6ScopeInput input = GlobalInput();
    input.pinhole = ExactPinhole(input);
    input.pinhole.expires_monotonic_ms = input.now_monotonic_ms;
    input.inbound.present = true;
    input.inbound.endpoint = input.current_endpoint;
    input.inbound.transport = input.transport;
    input.inbound.route_binding = input.current_route_binding;
    input.inbound.generation = input.current_generation;
    input.inbound.expires_monotonic_ms = 101;
    const Ipv6ScopeDecision result = EvaluateIpv6ScopeAdmission(input);
    CHECK(result.disposition == Ipv6ScopeDisposition::VerifiedGlobal);
    CHECK(result.observation.IsVerifiedFor(input.current_generation));
    CHECK(result.may_select_direct_v6 && result.may_advertise_remote_hello);
}

void TestOverlayOriginNeverAdmitsGlobalRoute() {
    const NetworkOriginEvidence overlay = {
        "wintun", "Tailscale Tunnel", false, false, true};
    CHECK(ClassifyNetworkOrigin(overlay).origin == NetworkOrigin::Overlay);
    Ipv6ScopeInput input = GlobalInput();
    input.current_route_binding.origin = NetworkOrigin::Overlay;
    const Ipv6ScopeDecision result = EvaluateIpv6ScopeAdmission(input);
    CHECK(result.disposition == Ipv6ScopeDisposition::RejectGlobal);
    CHECK(result.reason == ReasonCode::NoRoute);
}

void TestProbeAndPcpLifecycleFences() {
    ProbeIncarnation current{7, 11, false};
    CHECK(CanPublishProbeVerdict(current, current));
    ProbeIncarnation staleToken{7, 10, false};
    CHECK(!CanPublishProbeVerdict(staleToken, current));
    ProbeIncarnation staleGeneration{6, 11, false};
    CHECK(!CanPublishProbeVerdict(staleGeneration, current));
    current.shutdown = true;
    CHECK(!CanPublishProbeVerdict({7, 11, false}, current));

    CHECK(!MustCleanupPcpNonce(PcpExchangeDisposition::RequestNotSent));
    CHECK(MustCleanupPcpNonce(PcpExchangeDisposition::RequestSentNoResponse));
    CHECK(MustCleanupPcpNonce(PcpExchangeDisposition::ResponseRejected));
    CHECK(MustCleanupPcpNonce(PcpExchangeDisposition::Mapped));
    CHECK(MustCleanupPcpNonce(PcpExchangeDisposition::ZeroLifetime));
    CHECK(!MustCleanupPcpNonce(PcpExchangeDisposition::Deleted));

    PcpLeaseOwnerIdentity owner{};
    owner.generation = 7; owner.token = 11; owner.nonce[0] = 3;
    CHECK(IsCurrentPcpLeaseOwner(owner, owner));
    PcpLeaseOwnerIdentity wrongNonce = owner; wrongNonce.nonce[0] = 4;
    CHECK(!IsCurrentPcpLeaseOwner(owner, wrongNonce));
    PcpLeaseOwnerIdentity wrongToken = owner; wrongToken.token = 12;
    CHECK(!IsCurrentPcpLeaseOwner(owner, wrongToken));
    CHECK(EvaluateTopologyGenerationApply(0, 7) ==
          TopologyApplyDecision::Initialize);
    CHECK(EvaluateTopologyGenerationApply(7, 7) ==
          TopologyApplyDecision::Ignore);
    CHECK(EvaluateTopologyGenerationApply(7, 8) ==
          TopologyApplyDecision::Invalidate);
    CHECK(EvaluateScopedSocketBind(true, 7, 0) ==
          ScopedSocketBindDecision::Connect);
    CHECK(EvaluateScopedSocketBind(true, 7, -1) ==
          ScopedSocketBindDecision::Reject);
    CHECK(EvaluateScopedSocketBind(true, 0, 0) ==
          ScopedSocketBindDecision::Reject);
    CHECK(EvaluateScopedSocketBind(false, 0, -1) ==
          ScopedSocketBindDecision::Connect);
    CHECK(!MayPublishCascadeVerdict(PcpCascadeOutcome::Deferred));
    CHECK(MayPublishCascadeVerdict(PcpCascadeOutcome::Failed));
    CHECK(SelectPcpBusyRetryOwner(true) ==
          PcpBusyRetryOwner::ExistingOwner);
    CHECK(SelectPcpBusyRetryOwner(false) ==
          PcpBusyRetryOwner::WaitingWorker);
    CHECK(!UiPcpCleanupMayScheduleRetry());
}
} // namespace

int main() {
    TestGlobalV6ClosedFirewallDoesNotWin();
    TestGlobalV6ExactLivePinholeVerifies();
    TestExpiredPinholeWithdrawsCandidate();
    TestInterfaceAndGenerationChangeInvalidate();
    TestPrivateAddressesNeverAdmitAsGlobal();
    TestSameLanRequiresRemotePeerInExactScope();
    TestSameLanDoesNotCrossInterfaceOrGeneration();
    TestIsolatedPhysicalLanAllowsUnknownButNotOverlayOrigin();
    TestLinkLocalSameLanRequiresExactInterface();
    TestSameLanCannotReachGlobalConsumers();
    TestTransportProofDoesNotCross();
    TestPinholeReassignedEndpointDoesNotVerify();
    TestIndependentInboundSurvivesExpiredPinhole();
    TestOverlayOriginNeverAdmitsGlobalRoute();
    TestProbeAndPcpLifecycleFences();
    std::printf("test_ipv6_scope_policy: %d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
