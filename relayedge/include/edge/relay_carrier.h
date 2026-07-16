// SPDX-License-Identifier: MIT
#pragma once

#include "relay/krp_auth.h"

#include <cstddef>
#include <cstdint>

namespace relayedge {

enum class CarrierState : std::uint8_t {
    Closed = 0,
    Handshaking,
    Open,
    Failed,
};

class IRelayCarrier {
public:
    virtual ~IRelayCarrier() = default;
    virtual CarrierState state() const noexcept = 0;
    virtual relay::KrpCarrierProfile profile() const noexcept = 0;
    virtual relay::RelayStatus Send(const relay::Byte* data,
                                    std::size_t size) noexcept = 0;
    virtual relay::RelayStatus Receive(relay::Byte* data,
                                       std::size_t capacity,
                                       std::size_t& received) noexcept = 0;
    virtual relay::RelayStatus ExportBinding(
        relay::KrpCarrierBinding& binding) noexcept = 0;
    virtual void Close() noexcept = 0;
};

} // namespace relayedge
