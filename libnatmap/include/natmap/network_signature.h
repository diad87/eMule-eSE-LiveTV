#pragma once

#include "natmap/natmap_types.h"

#include <cstdint>

namespace natmap {

struct NetworkSignatureInput {
    std::uint64_t adapter_luid = 0;
    std::uint32_t interface_index = 0;
    IpAddress local_address{};
    IpAddress gateway_address{};
    IpAddress route_destination{};
    std::uint8_t route_prefix_length = 0;
    std::uint32_t compartment_id = 0;
    bool compartment_present = false;
};

enum class NetworkSignatureStatus : std::uint8_t {
    Valid = 0,
    AdapterInvalid = 1,
    InterfaceInvalid = 2,
    FamilyMismatch = 3,
    LocalAddressInvalid = 4,
    GatewayInvalid = 5,
    RouteInvalid = 6,
    CompartmentInvalid = 7,
};

// Exact, in-memory topology identity. It deliberately contains no clocks,
// metrics, DHCP lease data, adapter text, counters or connectivity scores.
// Equality therefore changes only when a routing-relevant identity changes.
class NetworkSignature {
public:
    bool IsValid() const noexcept { return valid_; }

private:
    friend NetworkSignatureStatus BuildNetworkSignature(
        const NetworkSignatureInput&, NetworkSignature&) noexcept;
    friend bool SameNetworkSignature(
        const NetworkSignature&, const NetworkSignature&) noexcept;

    NetworkSignatureInput identity_{};
    bool valid_ = false;
};

NetworkSignatureStatus BuildNetworkSignature(
    const NetworkSignatureInput& input,
    NetworkSignature& signature) noexcept;

bool SameNetworkSignature(const NetworkSignature& left,
                          const NetworkSignature& right) noexcept;

}  // namespace natmap
