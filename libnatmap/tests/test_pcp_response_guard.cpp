#include "natmap/pcp_response_guard.h"
#include "natmap/pcp_codec.h"
#include "natmap/pcp_mapping_identity.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>

using namespace natmap;

namespace {

int failures = 0;
int checks = 0;

#define CHECK(expr) do { ++checks; if (!(expr)) { ++failures; \
    std::printf("FAIL line %d: %s\n", __LINE__, #expr); } } while (0)

PcpResponseExpectation Expectation() {
    PcpResponseExpectation value{};
    value.source_address = {192, 168, 1, 1};
    value.source_port = 5351;
    value.request_id = 71;
    for (std::size_t i = 0; i < value.nonce.size(); ++i)
        value.nonce[i] = static_cast<std::uint8_t>(i + 1);
    return value;
}

PcpResponseObservation Observation() {
    const PcpResponseExpectation expected = Expectation();
    PcpResponseObservation value{};
    value.source_address = expected.source_address;
    value.source_port = expected.source_port;
    value.active_request_id = expected.request_id;
    value.nonce = expected.nonce;
    return value;
}

std::array<std::uint8_t, 12> Nonce(std::uint8_t seed) {
    std::array<std::uint8_t, 12> nonce{};
    for (std::size_t i = 0; i < nonce.size(); ++i)
        nonce[i] = static_cast<std::uint8_t>(seed + i);
    return nonce;
}

PcpMappingIdentity Identity(
    Transport transport, std::uint16_t port,
    std::uint8_t nonce_seed) {
    PcpMappingIdentity identity{};
    CHECK(InitializePcpMappingIdentity(
              identity, transport, port, Nonce(nonce_seed)) ==
          PcpIdentityStatus::Valid);
    return identity;
}

void Put16(std::uint8_t* out, std::uint16_t value) {
    out[0] = static_cast<std::uint8_t>(value >> 8);
    out[1] = static_cast<std::uint8_t>(value);
}

void Put32(std::uint8_t* out, std::uint32_t value) {
    for (unsigned i = 0; i < 4; ++i)
        out[i] = static_cast<std::uint8_t>(
            value >> ((3u - i) * 8u));
}

std::array<std::uint8_t, kPcpBaseMessageSize> CleanupResponse(
    const PcpMappingIdentity& identity,
    const std::array<std::uint8_t, 12>& response_nonce,
    std::uint32_t lifetime_seconds,
    bool mapper_succeeded = true) {
    std::array<std::uint8_t, kPcpBaseMessageSize> raw{};
    raw[0] = 2;
    raw[1] = 0x81;
    raw[3] = mapper_succeeded
        ? 0
        : static_cast<std::uint8_t>(PcpResultCode::NotAuthorized);
    Put32(raw.data() + 4, lifetime_seconds);
    Put32(raw.data() + 8, 1234);
    std::copy(response_nonce.begin(), response_nonce.end(),
              raw.begin() + 24);
    raw[36] = identity.transport == Transport::Tcp ? 6 : 17;
    Put16(raw.data() + 40, identity.internal_port);
    return raw;
}

PcpCleanupCommitStatus AttemptCleanup(
    PcpMappingIdentity& active_identity,
    const std::array<std::uint8_t, 12>& response_nonce,
    const std::array<std::uint8_t, 4>& expected_gateway,
    const std::array<std::uint8_t, 4>& response_gateway,
    std::uint32_t response_lifetime = 0,
    bool mapper_succeeded = true) {
    CHECK(active_identity.IsValid());
    PcpMapRequest request{};
    request.client_ip = PcpIpv4Mapped(192, 168, 1, 20);
    request.nonce = active_identity.nonce;
    request.protocol =
        active_identity.transport == Transport::Tcp ? 6 : 17;
    request.internal_port = active_identity.internal_port;

    std::array<std::uint8_t, kPcpBaseMessageSize> request_bytes{};
    const std::size_t request_size = EncodePcpMapRequest(
        request, request_bytes.data(), request_bytes.size());
    CHECK(request_size == kPcpBaseMessageSize);
    CHECK(std::all_of(
        request_bytes.begin() + 4, request_bytes.begin() + 8,
        [](std::uint8_t byte) { return byte == 0; }));
    CHECK(std::all_of(
        request_bytes.begin() + 42, request_bytes.end(),
        [](std::uint8_t byte) { return byte == 0; }));

    const auto raw = CleanupResponse(
        active_identity, response_nonce,
        response_lifetime, mapper_succeeded);
    PcpMapResponse decoded{};
    const PcpDecodeStatus decode_status = DecodePcpMapResponse(
        raw.data(), raw.size(), request, decoded);

    PcpResponseExpectation expectation{};
    expectation.source_address = expected_gateway;
    expectation.source_port = 5351;
    expectation.request_id = 71;
    expectation.nonce = request.nonce;
    PcpResponseObservation observation{};
    observation.source_address = response_gateway;
    observation.source_port = 5351;
    observation.active_request_id = 71;
    observation.nonce = response_nonce;
    const PcpResponseGuardStatus guard_status =
        decode_status == PcpDecodeStatus::Ok
            ? ValidatePcpResponseObservation(
                expectation, observation)
            : PcpResponseGuardStatus::Valid;
    const PcpCleanupCommitStatus commit =
        EvaluatePcpCleanupCommit(
            decode_status == PcpDecodeStatus::Ok,
            guard_status,
            decode_status == PcpDecodeStatus::Ok
                && decoded.result == PcpResultCode::Success,
            decode_status == PcpDecodeStatus::Ok
                ? decoded.lifetime_seconds : 0);
    if (commit == PcpCleanupCommitStatus::Commit)
        active_identity.Clear();
    return commit;
}

void TestExactObservationIsAccepted() {
    CHECK(Expectation().IsValid());
    CHECK(ValidatePcpResponseObservation(
        Expectation(), Observation())
        == PcpResponseGuardStatus::Valid);
}

void TestEveryBoundaryFailsClosed() {
    PcpResponseObservation value = Observation();
    value.source_address[3] = 2;
    CHECK(ValidatePcpResponseObservation(Expectation(), value)
        == PcpResponseGuardStatus::WrongSource);
    value = Observation();
    value.source_port = 5350;
    CHECK(ValidatePcpResponseObservation(Expectation(), value)
        == PcpResponseGuardStatus::WrongPort);
    value = Observation();
    value.nonce[0] ^= 1;
    CHECK(ValidatePcpResponseObservation(Expectation(), value)
        == PcpResponseGuardStatus::WrongNonce);
    value = Observation();
    value.active_request_id = 70;
    CHECK(ValidatePcpResponseObservation(Expectation(), value)
        == PcpResponseGuardStatus::StaleRequest);
    value = Observation();
    value.shutdown = true;
    CHECK(ValidatePcpResponseObservation(Expectation(), value)
        == PcpResponseGuardStatus::Shutdown);
    PcpResponseExpectation invalid{};
    CHECK(ValidatePcpResponseObservation(invalid, Observation())
        == PcpResponseGuardStatus::InvalidExpectation);
}

void TestShutdownPrecedesOtherwiseMatchingInput() {
    PcpResponseObservation value = Observation();
    value.shutdown = true;
    value.active_request_id = 70;
    value.source_port = 1;
    CHECK(ValidatePcpResponseObservation(Expectation(), value)
        == PcpResponseGuardStatus::Shutdown);
}

void TestTimeoutBudgetIsBounded() {
    CHECK(PcpExchangeTimeoutMilliseconds(0) == 1000);
    CHECK(PcpExchangeTimeoutMilliseconds(1) == 2000);
    CHECK(PcpExchangeTimeoutMilliseconds(2) == 4000);
    CHECK(PcpExchangeTimeoutMilliseconds(3) == 0);
    CHECK(PcpExchangeMaximumWaitMilliseconds() == 7700);
}

void TestRequestIdOwnsANonReusableLocalPort() {
    CHECK(PcpExchangeLocalPort(0) == 0);
    CHECK(PcpExchangeLocalPort(1) == 16384);
    CHECK(PcpExchangeLocalPort(2) == 16385);
    CHECK(PcpExchangeLocalPort(49152) == 65535);
    CHECK(PcpExchangeLocalPort(49153) == 0);
    CHECK(PcpExchangeLocalPort(71)
        != PcpExchangeLocalPort(70));

    std::array<bool, 65536> seen{};
    bool every_port_is_unique = true;
    for (std::uint64_t request_id = 1;
         request_id <= 49152; ++request_id) {
        const std::uint16_t port =
            PcpExchangeLocalPort(request_id);
        if (port < 16384 || seen[port]) {
            every_port_is_unique = false;
            break;
        }
        seen[port] = true;
    }
    CHECK(every_port_is_unique);
}

void TestOnlyPartialInitialMappingsAreCleanedAutomatically() {
    CHECK(PcpInitialMappingNeedsCleanup(true, true));
    CHECK(!PcpInitialMappingNeedsCleanup(true, false));
    CHECK(!PcpInitialMappingNeedsCleanup(false, true));
    CHECK(!PcpInitialMappingNeedsCleanup(false, false));
}

void TestCleanupOwnershipMatrix() {
    const std::array<std::uint8_t, 4> gateway{
        192, 168, 1, 1};
    const std::array<std::uint8_t, 4> changed_gateway{
        192, 168, 1, 2};

    PcpMappingIdentity tcp =
        Identity(Transport::Tcp, 4662, 1);
    CHECK(AttemptCleanup(
              tcp, tcp.nonce, gateway, gateway) ==
          PcpCleanupCommitStatus::Commit);
    CHECK(tcp.IsEmpty());

    PcpMappingIdentity udp =
        Identity(Transport::Udp, 4672, 20);
    CHECK(AttemptCleanup(
              udp, udp.nonce, gateway, gateway) ==
          PcpCleanupCommitStatus::Commit);
    CHECK(udp.IsEmpty());

    PcpMappingIdentity web =
        Identity(Transport::Tcp, 4711, 40);
    CHECK(AttemptCleanup(
              web, web.nonce, gateway, gateway) ==
          PcpCleanupCommitStatus::Commit);
    CHECK(web.IsEmpty());

    PcpMappingIdentity wrong_nonce =
        Identity(Transport::Tcp, 4662, 60);
    const auto owned_nonce = wrong_nonce.nonce;
    CHECK(AttemptCleanup(
              wrong_nonce, Nonce(80), gateway, gateway) ==
          PcpCleanupCommitStatus::InvalidResponse);
    CHECK(wrong_nonce.IsValid());
    CHECK(wrong_nonce.nonce == owned_nonce);

    const PcpMappingIdentity previous =
        Identity(Transport::Tcp, 4662, 100);
    PcpMappingIdentity remapped =
        Identity(Transport::Tcp, 4662, 120);
    const auto remapped_nonce = remapped.nonce;
    CHECK(previous.nonce != remapped.nonce);
    CHECK(AttemptCleanup(
              remapped, previous.nonce, gateway, gateway) ==
          PcpCleanupCommitStatus::InvalidResponse);
    CHECK(remapped.IsValid());
    CHECK(remapped.nonce == remapped_nonce);

    PcpMappingIdentity route_changed =
        Identity(Transport::Udp, 4672, 140);
    CHECK(AttemptCleanup(
              route_changed, route_changed.nonce,
              gateway, changed_gateway) ==
          PcpCleanupCommitStatus::GuardRejected);
    CHECK(route_changed.IsValid());

    PcpMappingIdentity nonzero_lifetime =
        Identity(Transport::Tcp, 4662, 160);
    CHECK(AttemptCleanup(
              nonzero_lifetime, nonzero_lifetime.nonce,
              gateway, gateway, 30) ==
          PcpCleanupCommitStatus::NonZeroLifetime);
    CHECK(nonzero_lifetime.IsValid());

    PcpMappingIdentity rejected =
        Identity(Transport::Tcp, 4662, 180);
    CHECK(AttemptCleanup(
              rejected, rejected.nonce,
              gateway, gateway, 0, false) ==
          PcpCleanupCommitStatus::MapperRejected);
    CHECK(rejected.IsValid());
}

} // namespace

int main() {
    TestExactObservationIsAccepted();
    TestEveryBoundaryFailsClosed();
    TestShutdownPrecedesOtherwiseMatchingInput();
    TestTimeoutBudgetIsBounded();
    TestRequestIdOwnsANonReusableLocalPort();
    TestOnlyPartialInitialMappingsAreCleanedAutomatically();
    TestCleanupOwnershipMatrix();
    std::printf("test_pcp_response_guard: %d checks, %d failures\n",
                checks, failures);
    return failures == 0 ? 0 : 1;
}
