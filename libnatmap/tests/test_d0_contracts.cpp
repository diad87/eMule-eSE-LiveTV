#include "natmap/natmap_types.h"
#include "fake_network.h"

#include <cstdio>

using namespace natmap;
using namespace natmap::test;

namespace {

int failures = 0;
int checks = 0;

#define CHECK(expr) do { ++checks; if (!(expr)) { ++failures; \
    std::printf("FAIL line %d: %s\n", __LINE__, #expr); } } while (0)

Endpoint Ep(std::uint8_t a, std::uint8_t b, std::uint8_t c,
            std::uint8_t d, std::uint16_t port,
            EndpointSource source = EndpointSource::LocalInterface) {
    return Endpoint{IpAddress::V4(a, b, c, d), port, source};
}

PortIntent TcpIntent(const Endpoint& local, std::uint16_t requested) {
    PortIntent intent{};
    intent.transport = Transport::Tcp;
    intent.local = local;
    intent.external_candidates[0] = requested;
    intent.candidate_count = 1;
    intent.requested_lifetime_seconds = 3600;
    return intent;
}

void TestAddressClassification() {
    CHECK(IpAddress::V4(192, 168, 68, 54).IsPrivateOrSharedV4());
    CHECK(IpAddress::V4(100, 69, 24, 30).IsPrivateOrSharedV4());
    CHECK(!IpAddress::V4(88, 11, 22, 4).IsPrivateOrSharedV4());
}

void TestSingleNatExactMapping() {
    FakeGateway igd{};
    igd.mapper = MapperKind::UpnpIgd;
    igd.gateway = Ep(192, 168, 68, 1, 1900);
    igd.external_address = IpAddress::V4(88, 11, 22, 4);

    const MapResult result = igd.Map(TcpIntent(Ep(192, 168, 68, 54, 4662), 4662), 1);
    CHECK(result.success);
    CHECK(result.lease.IsStructurallyValid());
    CHECK(result.lease.local.port == 4662);
    CHECK(result.lease.public_endpoint.port == 4662);
}

void TestPcpMayGrantDifferentPort() {
    FakeGateway pcp{};
    pcp.mapper = MapperKind::Pcp;
    pcp.gateway = Ep(100, 69, 0, 1, 5351);
    pcp.external_address = IpAddress::V4(88, 11, 22, 4);
    pcp.forced_external_port = 52144;

    const MapResult result = pcp.Map(TcpIntent(Ep(192, 168, 68, 54, 4662), 4662), 7);
    CHECK(result.success);
    CHECK(result.lease.requested_external_port == 4662);
    CHECK(result.lease.granted_external_port == 52144);
    CHECK(result.lease.public_endpoint.port == 52144);
    CHECK(result.lease.generation == 7);
}

void TestDoubleNatCanBeChained() {
    FakeGateway inner{};
    inner.mapper = MapperKind::UpnpIgd;
    inner.gateway = Ep(192, 168, 68, 1, 1900);
    inner.external_address = IpAddress::V4(192, 168, 1, 77);
    const MapResult first = inner.Map(TcpIntent(Ep(192, 168, 68, 54, 4662), 4662), 9);
    CHECK(first.success);
    CHECK(first.lease.public_endpoint.address.IsPrivateOrSharedV4());

    FakeGateway outer{};
    outer.mapper = MapperKind::Pcp;
    outer.gateway = Ep(192, 168, 1, 1, 5351);
    outer.external_address = IpAddress::V4(88, 11, 22, 4);
    outer.forced_external_port = 443;
    const MapResult second = outer.Map(TcpIntent(first.lease.public_endpoint, 443), 9);
    CHECK(second.success);
    CHECK(second.lease.local.port == 4662);
    CHECK(second.lease.public_endpoint.port == 443);
}

void TestNoMapperAndConflictAreExplicit() {
    FakeGateway absent{};
    const MapResult none = absent.Map(TcpIntent(Ep(192, 168, 1, 2, 4662), 4662), 2);
    CHECK(!none.success);
    CHECK(none.reason == ReasonCode::NoMappingProtocol);

    FakeGateway strict{};
    strict.mapper = MapperKind::NatPmp;
    strict.gateway = Ep(192, 168, 1, 1, 5351);
    strict.external_address = IpAddress::V4(88, 11, 22, 4);
    strict.forced_external_port = 50000;
    PortIntent intent = TcpIntent(Ep(192, 168, 1, 2, 4662), 4662);
    intent.allow_any_external_port = false;
    const MapResult conflict = strict.Map(intent, 3);
    CHECK(!conflict.success);
    CHECK(conflict.reason == ReasonCode::MappingConflict);
}

void TestHighIdNeedsBothPiecesOfEvidence() {
    FakeEd2kServer server{};
    const Endpoint advertised = Ep(88, 11, 22, 4, 52144, EndpointSource::PcpMap);
    const LoginResult low = server.Login(advertised, false, 11);
    CHECK(!low.high_id);

    const LoginResult high = server.Login(advertised, true, 11);
    CHECK(high.high_id);
    PlaneSnapshot snapshot{};
    snapshot.state = ReachabilityState::Reachable;
    snapshot.generation = 11;
    snapshot.advertised = advertised;
    snapshot.primary_evidence = high.server_evidence;
    snapshot.inbound_evidence = high.inbound_evidence;
    CHECK(snapshot.HasClassicHighIdEvidence());
    snapshot.generation = 12;
    CHECK(!snapshot.HasClassicHighIdEvidence());
}

} // namespace

int main() {
    TestAddressClassification();
    TestSingleNatExactMapping();
    TestPcpMayGrantDifferentPort();
    TestDoubleNatCanBeChained();
    TestNoMapperAndConflictAreExplicit();
    TestHighIdNeedsBothPiecesOfEvidence();
    std::printf("test_d0_contracts: %d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
