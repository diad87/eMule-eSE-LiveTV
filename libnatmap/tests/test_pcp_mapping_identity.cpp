#include "natmap/pcp_mapping_identity.h"

#include <cstdio>

using namespace natmap;

namespace {

int failures = 0;
int checks = 0;

#define CHECK(expr) do { ++checks; if (!(expr)) { ++failures; \
    std::printf("FAIL line %d: %s\n", __LINE__, #expr); } } while (0)

std::array<std::uint8_t, 12> Nonce(std::uint8_t seed) {
    std::array<std::uint8_t, 12> nonce{};
    for (std::size_t i = 0; i < nonce.size(); ++i)
        nonce[i] = static_cast<std::uint8_t>(seed + i);
    return nonce;
}

void TestIdentityInitializesExactlyOnce() {
    PcpMappingIdentity identity{};
    const auto nonce = Nonce(1);
    CHECK(identity.IsEmpty());
    CHECK(InitializePcpMappingIdentity(
        identity, Transport::Tcp, 4662, nonce)
        == PcpIdentityStatus::Valid);
    CHECK(identity.IsValid());
    CHECK(identity.Matches(Transport::Tcp, 4662));
    CHECK(identity.nonce == nonce);

    const PcpMappingIdentity frozen = identity;
    CHECK(InitializePcpMappingIdentity(
        identity, Transport::Tcp, 4662, Nonce(2))
        == PcpIdentityStatus::CorruptIdentity);
    CHECK(identity.nonce == frozen.nonce);
}

void TestRenewalRequiresTheSameTypedIdentity() {
    PcpMappingIdentity tcp{};
    CHECK(InitializePcpMappingIdentity(
        tcp, Transport::Tcp, 4662, Nonce(3))
        == PcpIdentityStatus::Valid);
    CHECK(ValidatePcpMappingIdentity(
        tcp, Transport::Tcp, 4662)
        == PcpIdentityStatus::Valid);
    CHECK(ValidatePcpMappingIdentity(
        tcp, Transport::Udp, 4662)
        == PcpIdentityStatus::IdentityMismatch);
    CHECK(ValidatePcpMappingIdentity(
        tcp, Transport::Tcp, 4672)
        == PcpIdentityStatus::IdentityMismatch);
    CHECK(ValidatePcpMappingIdentity(
        tcp, static_cast<Transport>(0), 4662)
        == PcpIdentityStatus::InvalidTransport);
    CHECK(ValidatePcpMappingIdentity(
        tcp, Transport::Tcp, 0)
        == PcpIdentityStatus::InvalidPort);
}

void TestInvalidOrZeroMaterialFailsClosed() {
    PcpMappingIdentity identity{};
    CHECK(InitializePcpMappingIdentity(
        identity, Transport::Tcp, 4662, {})
        == PcpIdentityStatus::ZeroNonce);
    CHECK(identity.IsEmpty());
    CHECK(InitializePcpMappingIdentity(
        identity, static_cast<Transport>(0), 4662, Nonce(4))
        == PcpIdentityStatus::InvalidTransport);
    CHECK(InitializePcpMappingIdentity(
        identity, Transport::Udp, 0, Nonce(4))
        == PcpIdentityStatus::InvalidPort);

    identity.transport = Transport::Udp;
    CHECK(ValidatePcpMappingIdentity(
        identity, Transport::Udp, 4672)
        == PcpIdentityStatus::CorruptIdentity);
    identity.Clear();
    CHECK(identity.IsEmpty());
}

} // namespace

int main() {
    TestIdentityInitializesExactlyOnce();
    TestRenewalRequiresTheSameTypedIdentity();
    TestInvalidOrZeroMaterialFailsClosed();
    std::printf("test_pcp_mapping_identity: %d checks, %d failures\n",
                checks, failures);
    return failures == 0 ? 0 : 1;
}
