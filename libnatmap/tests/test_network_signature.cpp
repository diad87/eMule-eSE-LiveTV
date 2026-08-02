#include "natmap/network_signature.h"

#include <cstdio>

using namespace natmap;

namespace {

int failures = 0;
int checks = 0;

#define CHECK(expr) do { ++checks; if (!(expr)) { ++failures; \
    std::printf("FAIL line %d: %s\n", __LINE__, #expr); } } while (0)

NetworkSignatureInput NativeDefaultRoute() {
    NetworkSignatureInput input{};
    input.adapter_luid = 0x6008000000001234ull;
    input.interface_index = 17;
    input.local_address = IpAddress::V4(192, 168, 71, 23);
    input.gateway_address = IpAddress::V4(192, 168, 71, 1);
    input.route_destination = IpAddress::V4(0, 0, 0, 0);
    input.route_prefix_length = 0;
    input.compartment_id = 1;
    input.compartment_present = true;
    return input;
}

void TestStableIdentityAndEveryTopologyField() {
    const NetworkSignatureInput baseline = NativeDefaultRoute();
    NetworkSignature established;
    CHECK(BuildNetworkSignature(baseline, established) ==
          NetworkSignatureStatus::Valid);
    CHECK(established.IsValid());

    NetworkSignature same;
    CHECK(BuildNetworkSignature(baseline, same) ==
          NetworkSignatureStatus::Valid);
    CHECK(SameNetworkSignature(established, same));

    auto MustChange = [&](NetworkSignatureInput changed) {
        NetworkSignature observed;
        CHECK(BuildNetworkSignature(changed, observed) ==
              NetworkSignatureStatus::Valid);
        CHECK(!SameNetworkSignature(established, observed));
    };

    NetworkSignatureInput changed = baseline;
    changed.adapter_luid += 1;
    MustChange(changed);
    changed = baseline;
    changed.interface_index += 1;
    MustChange(changed);
    changed = baseline;
    changed.local_address = IpAddress::V4(192, 168, 71, 24);
    MustChange(changed);
    changed = baseline;
    changed.gateway_address = IpAddress::V4(192, 168, 71, 254);
    MustChange(changed);
    changed = baseline;
    changed.route_prefix_length = 8;
    MustChange(changed);
    changed = baseline;
    changed.compartment_id = 2;
    MustChange(changed);
    changed = baseline;
    changed.compartment_present = false;
    changed.compartment_id = 0;
    MustChange(changed);

    NetworkSignatureInput route_a = baseline;
    route_a.route_destination = IpAddress::V4(10, 0, 0, 0);
    route_a.route_prefix_length = 8;
    NetworkSignature established_route;
    CHECK(BuildNetworkSignature(route_a, established_route) ==
          NetworkSignatureStatus::Valid);
    NetworkSignatureInput route_b = route_a;
    route_b.route_destination = IpAddress::V4(11, 0, 0, 0);
    NetworkSignature changed_destination;
    CHECK(BuildNetworkSignature(route_b, changed_destination) ==
          NetworkSignatureStatus::Valid);
    CHECK(!SameNetworkSignature(
        established_route, changed_destination));
    route_b = route_a;
    route_b.route_prefix_length = 9;
    NetworkSignature changed_prefix;
    CHECK(BuildNetworkSignature(route_b, changed_prefix) ==
          NetworkSignatureStatus::Valid);
    CHECK(!SameNetworkSignature(established_route, changed_prefix));
}

void TestInvalidInputNeverMutatesEstablishedSignature() {
    const NetworkSignatureInput baseline = NativeDefaultRoute();
    NetworkSignature established;
    CHECK(BuildNetworkSignature(baseline, established) ==
          NetworkSignatureStatus::Valid);

    auto MustRejectWithoutMutation = [&](NetworkSignatureInput invalid,
                                         NetworkSignatureStatus status) {
        NetworkSignature output = established;
        CHECK(BuildNetworkSignature(invalid, output) == status);
        CHECK(SameNetworkSignature(established, output));
    };

    NetworkSignatureInput invalid = baseline;
    invalid.adapter_luid = 0;
    MustRejectWithoutMutation(invalid, NetworkSignatureStatus::AdapterInvalid);
    invalid = baseline;
    invalid.interface_index = 0;
    MustRejectWithoutMutation(invalid, NetworkSignatureStatus::InterfaceInvalid);
    invalid = baseline;
    invalid.gateway_address = {};
    invalid.gateway_address.family = AddressFamily::IPv6;
    invalid.gateway_address.bytes[0] = 0xfe;
    invalid.gateway_address.bytes[1] = 0x80;
    invalid.gateway_address.bytes[15] = 1;
    MustRejectWithoutMutation(invalid, NetworkSignatureStatus::FamilyMismatch);
    invalid = baseline;
    invalid.local_address = IpAddress::V4(127, 0, 0, 1);
    MustRejectWithoutMutation(
        invalid, NetworkSignatureStatus::LocalAddressInvalid);
    invalid = baseline;
    invalid.gateway_address = IpAddress::V4(192, 0, 2, 1);
    MustRejectWithoutMutation(invalid, NetworkSignatureStatus::GatewayInvalid);
    invalid = baseline;
    invalid.route_destination = IpAddress::V4(10, 1, 0, 0);
    invalid.route_prefix_length = 8;
    MustRejectWithoutMutation(invalid, NetworkSignatureStatus::RouteInvalid);
    invalid = baseline;
    invalid.route_prefix_length = 33;
    MustRejectWithoutMutation(invalid, NetworkSignatureStatus::RouteInvalid);
    invalid = baseline;
    invalid.compartment_id = 0;
    MustRejectWithoutMutation(
        invalid, NetworkSignatureStatus::CompartmentInvalid);
    invalid = baseline;
    invalid.compartment_present = false;
    MustRejectWithoutMutation(
        invalid, NetworkSignatureStatus::CompartmentInvalid);
}

void TestNoSignatureEqualsAnInvalidSignature() {
    NetworkSignature left;
    NetworkSignature right;
    CHECK(!left.IsValid());
    CHECK(!right.IsValid());
    CHECK(!SameNetworkSignature(left, right));
}

void TestIpv6DefaultRouteIsSupported() {
    NetworkSignatureInput input{};
    input.adapter_luid = 0x6008000000005678ull;
    input.interface_index = 23;
    input.local_address.family = AddressFamily::IPv6;
    input.local_address.bytes[0] = 0x20;
    input.local_address.bytes[1] = 0x01;
    input.local_address.bytes[2] = 0x48;
    input.local_address.bytes[3] = 0x60;
    input.local_address.bytes[15] = 0x23;
    input.gateway_address.family = AddressFamily::IPv6;
    input.gateway_address.bytes[0] = 0xfe;
    input.gateway_address.bytes[1] = 0x80;
    input.gateway_address.bytes[15] = 1;
    input.route_destination.family = AddressFamily::IPv6;
    input.route_prefix_length = 0;
    input.compartment_id = 1;
    input.compartment_present = true;

    NetworkSignature signature;
    CHECK(BuildNetworkSignature(input, signature) ==
          NetworkSignatureStatus::Valid);
    CHECK(signature.IsValid());

    NetworkSignature same;
    CHECK(BuildNetworkSignature(input, same) ==
          NetworkSignatureStatus::Valid);
    CHECK(SameNetworkSignature(signature, same));

    NetworkSignatureInput routed = input;
    routed.route_destination.bytes[0] = 0x20;
    routed.route_destination.bytes[1] = 0x01;
    routed.route_destination.bytes[2] = 0x0d;
    routed.route_destination.bytes[3] = 0xb8;
    routed.route_prefix_length = 32;
    NetworkSignature routed_signature;
    CHECK(BuildNetworkSignature(routed, routed_signature) ==
          NetworkSignatureStatus::Valid);
    CHECK(!SameNetworkSignature(signature, routed_signature));

    NetworkSignatureInput prefix_changed = routed;
    prefix_changed.route_prefix_length = 48;
    NetworkSignature prefix_signature;
    CHECK(BuildNetworkSignature(prefix_changed, prefix_signature) ==
          NetworkSignatureStatus::Valid);
    CHECK(!SameNetworkSignature(routed_signature, prefix_signature));

    NetworkSignatureInput destination_changed = routed;
    destination_changed.route_destination.bytes[3] = 0xb9;
    NetworkSignature destination_signature;
    CHECK(BuildNetworkSignature(
              destination_changed, destination_signature) ==
          NetworkSignatureStatus::Valid);
    CHECK(!SameNetworkSignature(
        routed_signature, destination_signature));

    NetworkSignatureInput invalid = input;
    invalid.route_prefix_length = 129;
    NetworkSignature sentinel = signature;
    CHECK(BuildNetworkSignature(invalid, sentinel) ==
          NetworkSignatureStatus::RouteInvalid);
    CHECK(SameNetworkSignature(signature, sentinel));
    invalid = routed;
    invalid.route_destination.bytes[8] = 1;
    invalid.route_prefix_length = 64;
    sentinel = signature;
    CHECK(BuildNetworkSignature(invalid, sentinel) ==
          NetworkSignatureStatus::RouteInvalid);
    CHECK(SameNetworkSignature(signature, sentinel));
}

}  // namespace

int main() {
    TestStableIdentityAndEveryTopologyField();
    TestInvalidInputNeverMutatesEstablishedSignature();
    TestNoSignatureEqualsAnInvalidSignature();
    TestIpv6DefaultRouteIsSupported();
    std::printf("test_network_signature: %d checks, %d failures\n",
                checks, failures);
    return failures == 0 ? 0 : 1;
}
