#include "natmap/natmap_chain.h"
#include "fake_network.h"

#include <cstdio>

using namespace natmap;
using namespace natmap::test;

namespace {

int checks = 0;
int failures = 0;
#define CHECK(expr) do { ++checks; if (!(expr)) { ++failures; \
    std::printf("FAIL line %d: %s\n", __LINE__, #expr); } } while (0)

Endpoint Ep(std::uint8_t a, std::uint8_t b, std::uint8_t c,
            std::uint8_t d, std::uint16_t port,
            EndpointSource source = EndpointSource::LocalInterface) {
    return Endpoint{IpAddress::V4(a, b, c, d), port, source};
}

MapResult Map(FakeGateway& gateway, const Endpoint& local,
              std::uint64_t generation, std::uint16_t requested) {
    PortIntent intent = BuildAutomaticPortIntent(
        Transport::Tcp, local, gateway.lifetime_seconds, requested);
    intent.external_candidates[0] = requested;
    return gateway.Map(intent, generation);
}

UpstreamGatewayEvidence GatewayEvidence(
    const IpAddress& address, std::uint32_t interface_index,
    GatewayCandidateSource source =
        GatewayCandidateSource::InterfaceRoute) {
    UpstreamGatewayEvidence evidence{};
    evidence.address = address;
    evidence.interface_index = interface_index;
    evidence.source = source;
    evidence.interface_present = true;
    return evidence;
}

void TestDiscoveryRequiresAuthorizedEvidence() {
    UpstreamDiscoveryInput input{};
    input.mapper_wan_address = IpAddress::V4(192, 168, 1, 77);
    input.mapper_origin = NetworkOrigin::Native;
    input.interface_index = 17;
    const auto noEvidence = BuildUpstreamGatewayCandidates(input);
    CHECK(noEvidence.status ==
          UpstreamDiscoveryStatus::NoAuthorizedCandidate);
    CHECK(noEvidence.reason == ReasonCode::NoRoute);
    CHECK(noEvidence.count == 0);

    input.evidence[0] = GatewayEvidence(
        IpAddress::V4(192, 168, 1, 1), 17);
    input.evidence[1] = GatewayEvidence(
        IpAddress::V4(172, 20, 0, 1), 17,
        GatewayCandidateSource::DhcpOption);
    input.evidence_count = 2;
    const auto privateWan = BuildUpstreamGatewayCandidates(input);
    CHECK(privateWan.status == UpstreamDiscoveryStatus::CandidateGateways);
    CHECK(privateWan.count == 2);
    CHECK(privateWan.addresses[0].bytes[3] == 1);
    CHECK(privateWan.sources[0] ==
          GatewayCandidateSource::InterfaceRoute);
    CHECK(privateWan.addresses[1].bytes[0] == 172);
    CHECK(privateWan.sources[1] ==
          GatewayCandidateSource::DhcpOption);
    CHECK(privateWan.reason == ReasonCode::None);

    input.mapper_wan_address = IpAddress::V4(100, 69, 24, 30);
    const auto cgnat = BuildUpstreamGatewayCandidates(input);
    CHECK(cgnat.status == UpstreamDiscoveryStatus::OperatorCgnat);
    CHECK(cgnat.reason == ReasonCode::CgnatWithoutLease);
    CHECK(cgnat.count == 0);
    input.mapper_origin = NetworkOrigin::Overlay;
    const auto overlayCgnat = BuildUpstreamGatewayCandidates(input);
    CHECK(overlayCgnat.status ==
          UpstreamDiscoveryStatus::NoAuthorizedCandidate);
    CHECK(overlayCgnat.reason == ReasonCode::NoRoute);
    input.mapper_origin = NetworkOrigin::Native;
    input.mapper_wan_address = IpAddress::V4(88, 11, 22, 4);
    CHECK(BuildUpstreamGatewayCandidates(input).status ==
          UpstreamDiscoveryStatus::NotNeeded);
}

void TestDiscoveryRejectsUnauthorizedAndHostileCandidates() {
    UpstreamDiscoveryInput input{};
    input.mapper_wan_address = IpAddress::V4(10, 20, 30, 40);
    input.mapper_origin = NetworkOrigin::Native;
    input.interface_index = 7;
    input.evidence[0] = GatewayEvidence(
        IpAddress::V4(10, 20, 30, 1), 8);
    input.evidence[1] = GatewayEvidence(
        IpAddress::V4(10, 20, 30, 2), 7,
        GatewayCandidateSource::None);
    input.evidence[2] = GatewayEvidence(
        IpAddress::V4(88, 11, 22, 4), 7);
    input.evidence[3] = GatewayEvidence(
        input.mapper_wan_address, 7,
        GatewayCandidateSource::ExplicitConfiguration);
    input.evidence_count = 4;
    const auto rejected = BuildUpstreamGatewayCandidates(input);
    CHECK(rejected.status ==
          UpstreamDiscoveryStatus::NoAuthorizedCandidate);
    CHECK(rejected.count == 0);

    input.evidence[0] = GatewayEvidence(
        IpAddress::V4(10, 20, 30, 1), 7,
        GatewayCandidateSource::OperatorPolicy);
    input.evidence[1] = input.evidence[0];
    input.evidence[2] = GatewayEvidence(
        IpAddress::V4(172, 20, 0, 1), 7,
        GatewayCandidateSource::ExplicitConfiguration);
    input.evidence_count = 3;
    const auto deduplicated = BuildUpstreamGatewayCandidates(input);
    CHECK(deduplicated.status ==
          UpstreamDiscoveryStatus::CandidateGateways);
    CHECK(deduplicated.count == 2);

    input.evidence_count = static_cast<std::uint8_t>(
        input.evidence.size() + 1);
    CHECK(BuildUpstreamGatewayCandidates(input).status ==
          UpstreamDiscoveryStatus::InvalidInput);

    input = UpstreamDiscoveryInput{};
    input.mapper_wan_address = IpAddress::V4(192, 168, 1, 77);
    input.mapper_origin = NetworkOrigin::Native;
    input.interface_index = 17;
    input.evidence[0] = GatewayEvidence(
        IpAddress::V4(192, 168, 1, 1), 17);
    input.evidence[0].interface_present = false;
    input.evidence_count = 1;
    CHECK(BuildUpstreamGatewayCandidates(input).status ==
          UpstreamDiscoveryStatus::NoAuthorizedCandidate);
}

void TestTwoLayerCreateRenewAndRollback() {
    FakeGateway inner{};
    inner.mapper = MapperKind::UpnpIgd;
    inner.gateway = Ep(192, 168, 68, 1, 1900);
    inner.external_address = IpAddress::V4(192, 168, 1, 77);
    inner.forced_external_port = 52000;
    inner.lifetime_seconds = 100;
    MapResult first = Map(inner, Ep(192, 168, 68, 54, 4662), 41, 4662);

    FakeGateway outer{};
    outer.mapper = MapperKind::Pcp;
    outer.gateway = Ep(192, 168, 1, 1, 5351);
    outer.external_address = IpAddress::V4(88, 11, 22, 4);
    outer.forced_external_port = 443;
    outer.lifetime_seconds = 120;
    MapResult second = Map(outer, first.lease.public_endpoint, 41, 52000);

    NatChainTransaction chain;
    CHECK(chain.Begin(41, NetworkOrigin::Native));
    CHECK(chain.AppendLease(first.lease, 1000));
    CHECK(chain.NeedsUpstream());
    CHECK(chain.Evaluate() ==
          NatChainStatus::NeedsAuthorizedUpstream);
    CHECK(chain.AppendLease(second.lease, 1000));
    CHECK(chain.IsComplete());
    CHECK(chain.Evaluate() == NatChainStatus::CompletePublic);
    CHECK(chain.FinalEndpoint().port == 443);
    CHECK(chain.ShouldRenew(0, 46000));
    first.lease.mapper_epoch = 10;
    CHECK(chain.AcceptRenewal(0, first.lease, 46000));
    CHECK(!chain.ShouldRenew(0, 90000));

    std::array<PortLease, NatChainTransaction::kMaximumLayers> rollback{};
    CHECK(chain.Rollback(rollback) == 2);
    CHECK(rollback[0].gateway.address.bytes[2] == 1);
    CHECK(rollback[1].gateway.address.bytes[2] == 68);
    CHECK(chain.layer_count() == 0);
}

void TestIntermediateFailureAndDiscontinuity() {
    FakeGateway inner{};
    inner.mapper = MapperKind::NatPmp;
    inner.gateway = Ep(10, 0, 0, 1, 5351);
    inner.external_address = IpAddress::V4(172, 20, 0, 5);
    inner.forced_external_port = 50000;
    MapResult first = Map(inner, Ep(10, 0, 0, 20, 4662), 50, 4662);

    NatChainTransaction chain;
    CHECK(chain.Begin(50, NetworkOrigin::Native));
    CHECK(chain.AppendLease(first.lease, 0));
    PortLease disconnected = first.lease;
    disconnected.mapper = MapperKind::Pcp;
    disconnected.local = Ep(172, 20, 0, 99, 50000);
    disconnected.public_endpoint = Ep(192, 168, 1, 2, 50001,
        EndpointSource::PcpMap);
    disconnected.granted_external_port = 50001;
    CHECK(!chain.AppendLease(disconnected, 0));
    std::array<PortLease, NatChainTransaction::kMaximumLayers> rollback{};
    CHECK(chain.Rollback(rollback) == 1);
    CHECK(rollback[0].granted_external_port == 50000);
}

void TestCgnatStopsAutomaticChain() {
    FakeGateway operatorNat{};
    operatorNat.mapper = MapperKind::UpnpIgd;
    operatorNat.gateway = Ep(192, 168, 68, 1, 1900);
    operatorNat.external_address = IpAddress::V4(100, 69, 24, 30);
    operatorNat.forced_external_port = 4662;
    MapResult mapped = Map(operatorNat, Ep(192, 168, 68, 54, 4662), 60, 4662);
    NatChainTransaction chain;
    CHECK(chain.Begin(60, NetworkOrigin::Native));
    CHECK(chain.AppendLease(mapped.lease, 0));
    CHECK(chain.IsBlockedByCgnat());
    CHECK(chain.Evaluate() == NatChainStatus::OperatorCgnat);
    CHECK(!chain.NeedsUpstream());
    CHECK(!chain.IsComplete());

    NatChainTransaction overlay;
    CHECK(overlay.Begin(61, NetworkOrigin::Overlay));
    mapped.lease.generation = 61;
    CHECK(overlay.AppendLease(mapped.lease, 0));
    CHECK(overlay.Evaluate() ==
          NatChainStatus::NonPublishableEndpoint);
    CHECK(!overlay.IsBlockedByCgnat());

    NatChainTransaction unknown;
    CHECK(unknown.Begin(62, NetworkOrigin::Unknown));
    mapped.lease.generation = 62;
    CHECK(unknown.AppendLease(mapped.lease, 0));
    CHECK(unknown.Evaluate() ==
          NatChainStatus::NonPublishableEndpoint);
    CHECK(!unknown.IsBlockedByCgnat());
}

void TestDepthAndNonRoutablePromotionFailClosed() {
    FakeGateway firstGateway{};
    firstGateway.mapper = MapperKind::UpnpIgd;
    firstGateway.gateway = Ep(10, 0, 0, 1, 1900);
    firstGateway.external_address = IpAddress::V4(172, 20, 0, 5);
    firstGateway.forced_external_port = 50000;
    MapResult first = Map(
        firstGateway, Ep(10, 0, 0, 20, 4662), 70, 4662);

    FakeGateway secondGateway{};
    secondGateway.mapper = MapperKind::Pcp;
    secondGateway.gateway = Ep(172, 20, 0, 1, 5351);
    secondGateway.external_address = IpAddress::V4(192, 168, 1, 2);
    secondGateway.forced_external_port = 51000;
    MapResult second = Map(
        secondGateway, first.lease.public_endpoint, 70, 50000);

    NatChainTransaction chain;
    CHECK(chain.Begin(70, NetworkOrigin::Native));
    CHECK(chain.AppendLease(first.lease, 0));
    CHECK(chain.AppendLease(second.lease, 0));
    CHECK(chain.Evaluate() == NatChainStatus::DepthLimitReached);
    CHECK(!chain.NeedsUpstream());
    CHECK(!chain.IsComplete());

    PortLease third = second.lease;
    third.local = second.lease.public_endpoint;
    third.public_endpoint =
        Ep(88, 11, 22, 4, 52000, EndpointSource::PcpMap);
    third.granted_external_port = 52000;
    CHECK(!chain.AppendLease(third, 0));

    NatChainTransaction unroutable;
    CHECK(unroutable.Begin(71, NetworkOrigin::Native));
    PortLease documentation = first.lease;
    documentation.generation = 71;
    documentation.public_endpoint =
        Ep(192, 0, 2, 1, 50000, EndpointSource::UpnpExternalAddress);
    CHECK(unroutable.AppendLease(documentation, 0));
    CHECK(unroutable.Evaluate() ==
          NatChainStatus::NonPublishableEndpoint);
    CHECK(!unroutable.IsComplete());
}

} // namespace

int main() {
    TestDiscoveryRequiresAuthorizedEvidence();
    TestDiscoveryRejectsUnauthorizedAndHostileCandidates();
    TestTwoLayerCreateRenewAndRollback();
    TestIntermediateFailureAndDiscontinuity();
    TestCgnatStopsAutomaticChain();
    TestDepthAndNonRoutablePromotionFailClosed();
    std::printf("test_nat_chain: %d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
