// SPDX-License-Identifier: MIT
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>

#include "edge/wss_carrier.h"

#include <algorithm>
#include <array>

namespace relayedge {

WssH1Carrier::WssH1Carrier(IRelayCarrier& tls_carrier,
                           bool client_side) noexcept
    : tls_(&tls_carrier), client_side_(client_side),
      parser_(!client_side) {}

CarrierState WssH1Carrier::state() const noexcept {
    if (closed_ || tls_ == nullptr)
        return CarrierState::Closed;
    return tls_->state();
}

relay::RelayStatus WssH1Carrier::SendFrame(WssOpcode opcode,
                                            const relay::Byte* data,
                                            std::size_t size) noexcept {
    if (closed_ || tls_ == nullptr || tls_->state() != CarrierState::Open)
        return relay::RelayStatus::InvalidState;
    std::array<relay::Byte, 4> mask{};
    if (client_side_ && !BCRYPT_SUCCESS(BCryptGenRandom(
            nullptr, mask.data(), static_cast<ULONG>(mask.size()),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
        return relay::RelayStatus::InvalidState;
    std::vector<relay::Byte> encoded;
    const relay::RelayStatus encoded_status =
        EncodeWssFrame(opcode, data, size, client_side_, mask, encoded);
    if (encoded_status != relay::RelayStatus::Ok)
        return encoded_status;
    return tls_->Send(encoded.data(), encoded.size());
}

relay::RelayStatus WssH1Carrier::Send(const relay::Byte* data,
                                       std::size_t size) noexcept {
    return SendFrame(WssOpcode::Binary, data, size);
}

relay::RelayStatus WssH1Carrier::Receive(relay::Byte* data,
                                          std::size_t capacity,
                                          std::size_t& received) noexcept {
    received = 0;
    if (closed_ || tls_ == nullptr || data == nullptr || capacity == 0)
        return relay::RelayStatus::InvalidArgument;
    if (!pending_.empty()) {
        if (pending_.size() > capacity)
            return relay::RelayStatus::TooLarge;
        std::copy(pending_.begin(), pending_.end(), data);
        received = pending_.size();
        pending_.clear();
        return relay::RelayStatus::Ok;
    }

    std::array<relay::Byte, 4096> chunk{};
    for (;;) {
        WssFrame frame;
        relay::RelayStatus status = parser_.Pop(frame);
        if (status == relay::RelayStatus::Truncated) {
            std::size_t wire_received = 0;
            status = tls_->Receive(chunk.data(), chunk.size(), wire_received);
            if (status != relay::RelayStatus::Ok)
                return status;
            status = parser_.AddBytes(chunk.data(), wire_received);
            if (status != relay::RelayStatus::Ok)
                return status;
            continue;
        }
        if (status != relay::RelayStatus::Ok)
            return status;
        if (frame.opcode == WssOpcode::Ping) {
            status = SendFrame(WssOpcode::Pong, frame.payload.data(), frame.payload.size());
            if (status != relay::RelayStatus::Ok)
                return status;
            continue;
        }
        if (frame.opcode == WssOpcode::Pong)
            continue;
        if (frame.opcode == WssOpcode::Close) {
            if (!closed_)
                (void)SendFrame(WssOpcode::Close, frame.payload.data(), frame.payload.size());
            closed_ = true;
            return relay::RelayStatus::Expired;
        }
        if (frame.payload.size() > capacity) {
            try {
                pending_ = std::move(frame.payload);
            } catch (...) {
                return relay::RelayStatus::TooLarge;
            }
            return relay::RelayStatus::TooLarge;
        }
        std::copy(frame.payload.begin(), frame.payload.end(), data);
        received = frame.payload.size();
        return relay::RelayStatus::Ok;
    }
}

relay::RelayStatus WssH1Carrier::ExportBinding(
    relay::KrpCarrierBinding& binding) noexcept {
    return tls_ == nullptr ? relay::RelayStatus::InvalidState
                           : tls_->ExportBinding(binding);
}

void WssH1Carrier::Close() noexcept {
    if (closed_)
        return;
    const std::array<relay::Byte, 2> normal_close = {0x03, 0xE8};
    (void)SendFrame(WssOpcode::Close, normal_close.data(), normal_close.size());
    closed_ = true;
    parser_.Reset();
    pending_.clear();
    if (tls_ != nullptr)
        tls_->Close();
}

} // namespace relayedge
