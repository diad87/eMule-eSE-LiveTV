#include "natmap/pcp_map_projection.h"

#include <cstdio>

using namespace natmap;

namespace {

int failures = 0;
int checks = 0;

#define CHECK(expr) do { ++checks; if (!(expr)) { ++failures; \
    std::printf("FAIL line %d: %s\n", __LINE__, #expr); } } while (0)

PcpMappingIdentity Identity(
    Transport transport = Transport::Tcp,
    std::uint16_t internal_port = 4662) {
    PcpMappingIdentity identity{};
    std::array<std::uint8_t, 12> nonce{};
    for (std::size_t i = 0; i < nonce.size(); ++i)
        nonce[i] = static_cast<std::uint8_t>(i + 1);
    InitializePcpMappingIdentity(
        identity, transport, internal_port, nonce);
    return identity;
}

PcpMapResponse Response(const PcpMappingIdentity& identity) {
    PcpMapResponse response{};
    response.result = PcpResultCode::Success;
    response.lifetime_seconds = 7200;
    response.epoch = 1234;
    response.nonce = identity.nonce;
    response.protocol =
        identity.transport == Transport::Tcp ? 6 : 17;
    response.internal_port = identity.internal_port;
    response.external_port = 52144;
    response.external_ip = PcpIpv4Mapped(88, 11, 22, 4);
    return response;
}

void TestTcpProjectionPreservesEveryField() {
    const PcpMappingIdentity identity = Identity();
    const PcpMapProjectionResult projected =
        ProjectPcpMapResponse(identity, 4662, Response(identity));
    CHECK(projected.IsProjected());
    CHECK(projected.value.transport == Transport::Tcp);
    CHECK(projected.value.internal_port == 4662);
    CHECK(projected.value.requested_external_port == 4662);
    CHECK(projected.value.granted_external_port == 52144);
    CHECK(projected.value.external_address.family
        == AddressFamily::IPv4);
    CHECK(projected.value.external_address.bytes[0] == 88);
    CHECK(projected.value.external_address.bytes[3] == 4);
    CHECK(projected.value.lifetime_seconds == 7200);
    CHECK(projected.value.epoch == 1234);
    CHECK(projected.value.nonce == identity.nonce);

    PcpMapProjection corrupted = projected.value;
    corrupted.external_address = IpAddress::V4(224, 0, 0, 1);
    CHECK(!corrupted.IsValid());
    corrupted = projected.value;
    corrupted.external_address.bytes[4] = 1;
    CHECK(!corrupted.IsValid());
}

void TestUdpAndWildcardProjection() {
    const PcpMappingIdentity identity =
        Identity(Transport::Udp, 4672);
    PcpMapResponse response = Response(identity);
    response.external_port = 53000;
    const PcpMapProjectionResult projected =
        ProjectPcpMapResponse(identity, 0, response);
    CHECK(projected.IsProjected());
    CHECK(projected.value.transport == Transport::Udp);
    CHECK(projected.value.internal_port == 4672);
    CHECK(projected.value.requested_external_port == 0);
    CHECK(projected.value.granted_external_port == 53000);
    CHECK(projected.value.nonce == identity.nonce);
}

void TestMismatchedIdentityFailsClosed() {
    const PcpMappingIdentity identity = Identity();
    PcpMapResponse response = Response(identity);
    response.nonce[0] ^= 1;
    CHECK(ProjectPcpMapResponse(identity, 4662, response).status
        == PcpMapProjectionStatus::WrongNonce);
    response = Response(identity);
    response.protocol = 17;
    CHECK(ProjectPcpMapResponse(identity, 4662, response).status
        == PcpMapProjectionStatus::WrongProtocol);
    response = Response(identity);
    response.internal_port = 4672;
    CHECK(ProjectPcpMapResponse(identity, 4662, response).status
        == PcpMapProjectionStatus::WrongInternalPort);
}

void TestInvalidGrantFailsClosed() {
    const PcpMappingIdentity identity = Identity();
    PcpMapResponse response = Response(identity);
    response.result = PcpResultCode::NotAuthorized;
    CHECK(ProjectPcpMapResponse(identity, 4662, response).status
        == PcpMapProjectionStatus::Rejected);
    response = Response(identity);
    response.external_port = 0;
    CHECK(ProjectPcpMapResponse(identity, 4662, response).status
        == PcpMapProjectionStatus::InvalidGrantedPort);
    response = Response(identity);
    response.lifetime_seconds = 0;
    CHECK(ProjectPcpMapResponse(identity, 4662, response).status
        == PcpMapProjectionStatus::InvalidLifetime);
    response = Response(identity);
    response.external_ip = {};
    CHECK(ProjectPcpMapResponse(identity, 4662, response).status
        == PcpMapProjectionStatus::InvalidExternalAddress);
    response = Response(identity);
    response.external_ip = PcpIpv4Mapped(224, 0, 0, 1);
    CHECK(ProjectPcpMapResponse(identity, 4662, response).status
        == PcpMapProjectionStatus::InvalidExternalAddress);
    CHECK(!ProjectPcpMapResponse(
        PcpMappingIdentity{}, 4662, Response(identity)).IsProjected());
}

void TestAbsurdLifetimeIsBoundedForProductUse() {
    CHECK(PcpEffectiveLifetime(0) == 0);
    CHECK(PcpEffectiveLifetime(7200) == 7200);
    CHECK(PcpEffectiveLifetime(86400) == 86400);
    CHECK(PcpEffectiveLifetime(86401) == 86400);
    CHECK(PcpEffectiveLifetime(0xffffffffu) == 86400);
}

} // namespace

int main() {
    TestTcpProjectionPreservesEveryField();
    TestUdpAndWildcardProjection();
    TestMismatchedIdentityFailsClosed();
    TestInvalidGrantFailsClosed();
    TestAbsurdLifetimeIsBoundedForProductUse();
    std::printf("test_pcp_map_projection: %d checks, %d failures\n",
                checks, failures);
    return failures == 0 ? 0 : 1;
}
