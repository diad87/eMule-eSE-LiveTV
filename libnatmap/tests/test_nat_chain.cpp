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

void TestDiscoveryIsBounded() {
    const auto privateWan = BuildUpstreamGatewayCandidates(
        IpAddress::V4(192, 168, 1, 77));
    CHECK(privateWan.status == UpstreamDiscoveryStatus::CandidateGateways);
    CHECK(privateWan.count == 2);
    CHECK(privateWan.addresses[0].bytes[3] == 1);
    CHECK(privateWan.addresses[1].bytes[3] == 254);
    const auto cgnat = BuildUpstreamGatewayCandidates(
        IpAddress::V4(100, 69, 24, 30));
    CHECK(cgnat.status == UpstreamDiscoveryStatus::OperatorCgnat);
    CHECK(cgnat.count == 0);
    CHECK(BuildUpstreamGatewayCandidates(IpAddress::V4(88, 11, 22, 4)).status
          == UpstreamDiscoveryStatus::NotNeeded);
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
    CHECK(chain.Begin(41));
    CHECK(chain.AppendLease(first.lease, 1000));
    CHECK(chain.NeedsUpstream());
    CHECK(chain.AppendLease(second.lease, 1000));
    CHECK(chain.IsComplete());
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
    CHECK(chain.Begin(50));
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
    CHECK(chain.Begin(60));
    CHECK(chain.AppendLease(mapped.lease, 0));
    CHECK(chain.IsBlockedByCgnat());
    CHECK(!chain.NeedsUpstream());
    CHECK(!chain.IsComplete());
}

} // namespace

int main() {
    TestDiscoveryIsBounded();
    TestTwoLayerCreateRenewAndRollback();
    TestIntermediateFailureAndDiscontinuity();
    TestCgnatStopsAutomaticChain();
    std::printf("test_nat_chain: %d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
