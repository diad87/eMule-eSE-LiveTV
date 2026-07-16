// SPDX-License-Identifier: MIT
#pragma once

#include "edge/relay_carrier.h"
#include "edge/wss_h1.h"

#include <vector>

namespace relayedge {

// Binary-message carrier used after a successful, externally validated H1
// upgrade. It owns no socket; lifetime must remain shorter than the TLS carrier.
class WssH1Carrier final : public IRelayCarrier {
public:
    WssH1Carrier(IRelayCarrier& tls_carrier, bool client_side) noexcept;

    CarrierState state() const noexcept override;
    relay::KrpCarrierProfile profile() const noexcept override {
        return relay::KrpCarrierProfile::WssH1;
    }
    relay::RelayStatus Send(const relay::Byte* data,
                            std::size_t size) noexcept override;
    relay::RelayStatus Receive(relay::Byte* data,
                               std::size_t capacity,
                               std::size_t& received) noexcept override;
    relay::RelayStatus ExportBinding(
        relay::KrpCarrierBinding& binding) noexcept override;
    void Close() noexcept override;
    bool HasBufferedInput() const noexcept {
        return !pending_.empty() || parser_.buffered_bytes() != 0;
    }

private:
    relay::RelayStatus SendFrame(WssOpcode opcode,
                                 const relay::Byte* data,
                                 std::size_t size) noexcept;

    IRelayCarrier* tls_ = nullptr;
    bool client_side_ = false;
    bool closed_ = false;
    WssFrameParser parser_;
    std::vector<relay::Byte> pending_{};
};

} // namespace relayedge
