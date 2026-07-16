// SPDX-License-Identifier: MIT
#pragma once

#include "relay/relay_core.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace relayedge {

constexpr std::size_t kMaxWssHandshakeBytes = 8192;
constexpr std::size_t kMaxWssHeaderLineBytes = 1024;
constexpr std::size_t kMaxWssHeaders = 64;
constexpr std::uint64_t kMaxWssPayloadBytes = 64 * 1024;
constexpr std::size_t kMaxWssBufferedBytes =
    2 * (static_cast<std::size_t>(kMaxWssPayloadBytes) + 14);

struct WssUpgradeRequest {
    std::string websocket_key;
    std::size_t consumed = 0;
};

relay::RelayStatus ParseWssUpgradeRequest(const relay::Byte* data,
                                          std::size_t size,
                                          WssUpgradeRequest& request);
relay::RelayStatus BuildWssUpgradeResponse(const WssUpgradeRequest& request,
                                           std::vector<relay::Byte>& response);

relay::RelayStatus BuildWssClientUpgradeRequest(
    const char* host,
    const char* path,
    std::vector<relay::Byte>& request,
    std::string& websocket_key) noexcept;

relay::RelayStatus ParseWssUpgradeResponse(
    const relay::Byte* data,
    std::size_t size,
    const std::string& websocket_key,
    std::size_t& consumed);

enum class WssOpcode : std::uint8_t {
    Binary = 0x2,
    Close = 0x8,
    Ping = 0x9,
    Pong = 0xA,
};

struct WssFrame {
    WssOpcode opcode = WssOpcode::Binary;
    std::vector<relay::Byte> payload;
};

relay::RelayStatus EncodeWssFrame(WssOpcode opcode,
                                  const relay::Byte* payload,
                                  std::size_t payload_size,
                                  bool mask,
                                  const std::array<relay::Byte, 4>& mask_key,
                                  std::vector<relay::Byte>& encoded);

class WssFrameParser {
public:
    explicit WssFrameParser(bool require_mask) noexcept
        : require_mask_(require_mask) {}

    relay::RelayStatus AddBytes(const relay::Byte* data, std::size_t size);
    relay::RelayStatus Pop(WssFrame& frame);
    std::size_t buffered_bytes() const noexcept { return buffer_.size(); }
    void Reset() noexcept { buffer_.clear(); }

private:
    bool require_mask_ = true;
    std::vector<relay::Byte> buffer_{};
};

} // namespace relayedge
