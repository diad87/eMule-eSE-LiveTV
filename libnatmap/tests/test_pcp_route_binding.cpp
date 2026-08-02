#include "natmap/pcp_route_binding.h"

#include <cstdio>

using namespace natmap;

namespace {

int failures = 0;
int checks = 0;

#define CHECK(expr) do { ++checks; if (!(expr)) { ++failures; \
    std::printf("FAIL line %d: %s\n", __LINE__, #expr); } } while (0)

void TestExactRoutePairIsFrozen() {
    const PcpRouteBindingSelection selected =
        SelectPcpRouteBinding(
            IpAddress::V4(192, 168, 68, 54),
            IpAddress::V4(192, 168, 68, 1), 12);
    CHECK(selected.IsSelected());
    CHECK(selected.status == PcpRouteBindingStatus::Valid);
    CHECK(selected.binding.interface_index == 12);
    CHECK(selected.binding.gateway_address[0] == 192);
    CHECK(selected.binding.gateway_address[3] == 1);
    CHECK(selected.binding.client_address[10] == 0xff);
    CHECK(selected.binding.client_address[11] == 0xff);
    CHECK(selected.binding.client_address[12] == 192);
    CHECK(selected.binding.client_address[15] == 54);
}

void TestIncompleteOrWrongFamilyFailsClosed() {
    CHECK(SelectPcpRouteBinding(
        IpAddress{}, IpAddress::V4(192, 168, 68, 1), 12).status
        == PcpRouteBindingStatus::UnsupportedFamily);
    CHECK(SelectPcpRouteBinding(
        IpAddress::V4(192, 168, 68, 54), IpAddress{}, 12).status
        == PcpRouteBindingStatus::UnsupportedFamily);

    IpAddress ipv6{};
    ipv6.family = AddressFamily::IPv6;
    ipv6.bytes[15] = 1;
    CHECK(SelectPcpRouteBinding(
        ipv6, IpAddress::V4(192, 168, 68, 1), 12).status
        == PcpRouteBindingStatus::UnsupportedFamily);
    CHECK(SelectPcpRouteBinding(
        IpAddress::V4(192, 168, 68, 54),
        IpAddress::V4(192, 168, 68, 1), 0).status
        == PcpRouteBindingStatus::InvalidInterface);
    CHECK(SelectPcpRouteBinding(
        IpAddress::V4(192, 168, 68, 54),
        IpAddress::V4(192, 168, 68, 1), 0x01000000u).status
        == PcpRouteBindingStatus::InvalidInterface);
    CHECK(SelectPcpRouteBinding(
        IpAddress::V4(192, 168, 68, 54),
        IpAddress::V4(192, 168, 68, 1), 0x00ffffffu).IsSelected());
}

void TestMalformedAndAmbiguousPairsFailClosed() {
    CHECK(SelectPcpRouteBinding(
        IpAddress::V4(0, 0, 0, 0),
        IpAddress::V4(192, 168, 68, 1), 12).status
        == PcpRouteBindingStatus::InvalidClientAddress);
    CHECK(SelectPcpRouteBinding(
        IpAddress::V4(192, 168, 68, 54),
        IpAddress::V4(255, 255, 255, 255), 12).status
        == PcpRouteBindingStatus::InvalidGatewayAddress);
    CHECK(SelectPcpRouteBinding(
        IpAddress::V4(192, 168, 68, 54),
        IpAddress::V4(192, 168, 68, 54), 12).status
        == PcpRouteBindingStatus::AmbiguousPair);

    IpAddress noncanonical = IpAddress::V4(192, 168, 68, 54);
    noncanonical.bytes[4] = 1;
    CHECK(SelectPcpRouteBinding(
        noncanonical, IpAddress::V4(192, 168, 68, 1), 12).status
        == PcpRouteBindingStatus::InvalidClientAddress);

    PcpRouteBinding corrupted =
        SelectPcpRouteBinding(
            IpAddress::V4(192, 168, 68, 54),
            IpAddress::V4(192, 168, 68, 1), 12).binding;
    corrupted.client_address[0] = 1;
    CHECK(!corrupted.IsValid());
    corrupted = SelectPcpRouteBinding(
        IpAddress::V4(192, 168, 68, 54),
        IpAddress::V4(192, 168, 68, 1), 12).binding;
    corrupted.gateway_address = {224, 0, 0, 1};
    CHECK(!corrupted.IsValid());
    corrupted.gateway_address = {192, 168, 68, 54};
    CHECK(!corrupted.IsValid());
    corrupted = SelectPcpRouteBinding(
        IpAddress::V4(192, 168, 68, 54),
        IpAddress::V4(192, 168, 68, 1), 12).binding;
    corrupted.interface_index = 0;
    CHECK(!corrupted.IsValid());
    corrupted.interface_index = 0x01000000u;
    CHECK(!corrupted.IsValid());
}

} // namespace

int main() {
    TestExactRoutePairIsFrozen();
    TestIncompleteOrWrongFamilyFailsClosed();
    TestMalformedAndAmbiguousPairsFailClosed();
    std::printf("test_pcp_route_binding: %d checks, %d failures\n",
                checks, failures);
    return failures == 0 ? 0 : 1;
}
