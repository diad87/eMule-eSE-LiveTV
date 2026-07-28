#include "natmap/pcp_response_guard.h"

#include <cstdio>

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

} // namespace

int main() {
    TestExactObservationIsAccepted();
    TestEveryBoundaryFailsClosed();
    TestShutdownPrecedesOtherwiseMatchingInput();
    TestTimeoutBudgetIsBounded();
    TestRequestIdOwnsANonReusableLocalPort();
    TestOnlyPartialInitialMappingsAreCleanedAutomatically();
    std::printf("test_pcp_response_guard: %d checks, %d failures\n",
                checks, failures);
    return failures == 0 ? 0 : 1;
}
