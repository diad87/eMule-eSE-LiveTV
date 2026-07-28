#include "natmap/natpmp_gateway_policy.h"

#include <cstdio>
#include <cstring>

using namespace natmap;

namespace {

int checks = 0;
int failures = 0;

#define CHECK(expr) do { ++checks; if (!(expr)) { ++failures; \
    std::printf("FAIL line %d: %s\n", __LINE__, #expr); } } while (0)

std::uint32_t NetworkV4(
    std::uint8_t a, std::uint8_t b,
    std::uint8_t c, std::uint8_t d) {
    const std::uint8_t bytes[4]{a, b, c, d};
    std::uint32_t value = 0;
    std::memcpy(&value, bytes, sizeof(value));
    return value;
}

NatPmpExternalAddressResponse Response(
    std::uint8_t a, std::uint8_t b,
    std::uint8_t c, std::uint8_t d,
    std::uint16_t result_code = 0) {
    NatPmpExternalAddressResponse response{};
    response.result_code = result_code;
    response.epoch = 42;
    response.external_ip_network_order = NetworkV4(a, b, c, d);
    return response;
}

void TestGatewayIsBoundToTheCapturedInterface() {
    const NatPmpGatewaySelection selected =
        SelectNatPmpGateway(IpAddress::V4(192, 168, 68, 1), 17);
    CHECK(selected.IsSelected());
    CHECK(selected.interface_index == 17);
    CHECK(selected.gateway_address[0] == 192);
    CHECK(selected.gateway_address[3] == 1);
    CHECK(SelectNatPmpGateway(
        IpAddress::V4(192, 168, 68, 1), 0).status
        == NatPmpGatewayStatus::MissingInterface);
    CHECK(SelectNatPmpGateway(
        IpAddress::V4(192, 168, 68, 1),
        kNatPmpMaximumInterfaceIndex).IsSelected());
    CHECK(SelectNatPmpGateway(
        IpAddress::V4(192, 168, 68, 1),
        kNatPmpMaximumInterfaceIndex + 1).status
        == NatPmpGatewayStatus::MissingInterface);
    CHECK(SelectNatPmpGateway(IpAddress{}, 17).status
        == NatPmpGatewayStatus::InvalidAddress);
    CHECK(SelectNatPmpGateway(
        IpAddress::V4(224, 0, 0, 1), 17).status
        == NatPmpGatewayStatus::InvalidAddress);
    IpAddress corrupted = IpAddress::V4(192, 168, 68, 1);
    corrupted.bytes[4] = 1;
    CHECK(SelectNatPmpGateway(corrupted, 17).status
        == NatPmpGatewayStatus::InvalidAddress);
}

void TestRequiredExternalAddressOutcomes() {
    const NatPmpExternalAddressDecision public_address =
        ClassifyNatPmpExternalAddress(
            true, Response(88, 11, 22, 4));
    CHECK(public_address.status
        == NatPmpExternalAddressStatus::Public);
    CHECK(public_address.HasAddress());
    CHECK(public_address.epoch == 42);
    CHECK(public_address.should_attempt_map);
    CHECK(public_address.can_publish_direct);

    const NatPmpExternalAddressDecision missing =
        ClassifyNatPmpExternalAddress(false, {});
    CHECK(missing.status == NatPmpExternalAddressStatus::Missing);
    CHECK(missing.should_attempt_map);
    CHECK(!missing.HasAddress());
    CHECK(!missing.can_publish_direct);

    const NatPmpExternalAddressDecision rejected =
        ClassifyNatPmpExternalAddress(
            true, Response(0, 0, 0, 0, 2));
    CHECK(rejected.status == NatPmpExternalAddressStatus::Rejected);
    CHECK(rejected.should_attempt_map);
    CHECK(!rejected.HasAddress());
    CHECK(!rejected.can_publish_direct);

    const NatPmpExternalAddressDecision unknown_rejection =
        ClassifyNatPmpExternalAddress(
            true, Response(0, 0, 0, 0, 6));
    CHECK(unknown_rejection.status
        == NatPmpExternalAddressStatus::Invalid);
    CHECK(unknown_rejection.should_attempt_map);
    CHECK(!unknown_rejection.HasAddress());
    CHECK(!unknown_rejection.can_publish_direct);

    const NatPmpExternalAddressDecision private_address =
        ClassifyNatPmpExternalAddress(
            true, Response(192, 168, 1, 77));
    CHECK(private_address.status == NatPmpExternalAddressStatus::Private);
    CHECK(private_address.HasAddress());
    CHECK(private_address.should_attempt_map);
    CHECK(!private_address.can_publish_direct);

    const NatPmpExternalAddressDecision cgnat =
        ClassifyNatPmpExternalAddress(
            true, Response(100, 69, 24, 30));
    CHECK(cgnat.status == NatPmpExternalAddressStatus::Cgnat);
    CHECK(cgnat.HasAddress());
    CHECK(cgnat.should_attempt_map);
    CHECK(!cgnat.can_publish_direct);
}

void TestInvalidSuccessfulAddressesFailClosedButStillPermitMap() {
    const std::uint8_t invalid[][4]{
        {0, 0, 0, 0},
        {127, 0, 0, 1},
        {169, 254, 1, 1},
        {224, 0, 0, 1},
        {255, 255, 255, 255},
    };
    for (const auto& address : invalid) {
        const NatPmpExternalAddressDecision decision =
            ClassifyNatPmpExternalAddress(true, Response(
                address[0], address[1], address[2], address[3]));
        CHECK(decision.status == NatPmpExternalAddressStatus::Invalid);
        CHECK(decision.should_attempt_map);
        CHECK(!decision.HasAddress());
        CHECK(!decision.can_publish_direct);
    }
}

void TestEpochResetCannotReuseAnOldPublicAddress() {
    const NatPmpExternalAddressDecision retained =
        ClassifyNatPmpExternalAddress(
            true, Response(88, 11, 22, 4));
    const NatPmpExternalAddressDecision missing =
        ClassifyNatPmpExternalAddress(false, {});
    const NatPmpExternalAddressDecision rejected =
        ClassifyNatPmpExternalAddress(
            true, Response(0, 0, 0, 0, 2));

    CHECK(ResolveNatPmpPublishAddress(
        missing, retained, false).can_publish_direct);
    CHECK(ResolveNatPmpPublishAddress(
        rejected, retained, false).can_publish_direct);
    const NatPmpExternalAddressDecision reset_after_missing =
        ResolveNatPmpPublishAddress(missing, retained, true);
    CHECK(reset_after_missing.status
        == NatPmpExternalAddressStatus::Invalid);
    CHECK(!reset_after_missing.HasAddress());
    CHECK(!reset_after_missing.can_publish_direct);
    const NatPmpExternalAddressDecision reset_after_rejection =
        ResolveNatPmpPublishAddress(rejected, retained, true);
    CHECK(reset_after_rejection.status
        == NatPmpExternalAddressStatus::Invalid);
    CHECK(!reset_after_rejection.HasAddress());
    CHECK(!reset_after_rejection.can_publish_direct);

    const NatPmpExternalAddressDecision fresh_private =
        ClassifyNatPmpExternalAddress(
            true, Response(192, 168, 1, 77));
    CHECK(ResolveNatPmpPublishAddress(
        fresh_private, retained, false).status
        == NatPmpExternalAddressStatus::Private);

    NatPmpMapResponse primary_mapping{};
    primary_mapping.epoch = 100;
    NatPmpMapResponse post_reset_web_mapping{};
    post_reset_web_mapping.epoch = 2;
    const bool web_mapping_reset = NatPmpEpochAppearsReset(
        primary_mapping.epoch, post_reset_web_mapping.epoch);
    CHECK(web_mapping_reset);
    CHECK(!ResolveNatPmpPublishAddress(
        retained, retained, web_mapping_reset).can_publish_direct);
}

} // namespace

int main() {
    TestGatewayIsBoundToTheCapturedInterface();
    TestRequiredExternalAddressOutcomes();
    TestInvalidSuccessfulAddressesFailClosedButStillPermitMap();
    TestEpochResetCannotReuseAnOldPublicAddress();
    std::printf(
        "test_natpmp_gateway_policy: %d checks, %d failures\n",
        checks, failures);
    return failures == 0 ? 0 : 1;
}
