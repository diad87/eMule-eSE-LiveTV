#pragma once

#include "EseServerWire.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

namespace ese::server {
inline constexpr std::size_t HeaderSize = 28;
inline constexpr std::size_t MaxFrameSize = 65536;
inline constexpr std::size_t MaxPayloadSize = MaxFrameSize - HeaderSize;

using RequestId = std::array<std::uint8_t,16>;
struct FrameHeader {
    std::uint16_t type = 0;
    std::uint16_t flags = 0;
    RequestId request{};
};
struct ByteView {
    const std::uint8_t* data = nullptr;
    std::size_t size = 0;
};
struct FrameView {
    FrameHeader header;
    ByteView payload;
};

bool AcceptsAlpn(std::string_view selected) noexcept;

// Encodes a structural frame; the caller still validates phase, direction,
// correlated response and the actual message payload.
bool EncodeFrame(const FrameView& frame,std::vector<std::uint8_t>& output);

enum class DecodeState { Reading, Ready, Malformed, ResourceLimit };
struct FeedResult {
    std::size_t consumed;
    DecodeState state;
};

// A decoder belongs to exactly one negotiated stream. A malformed header is
// terminal. Read at most one frame per Feed and Get/Consume before resuming.
class FrameDecoder {
public:
    FeedResult Feed(ByteView input);
    std::optional<FrameView> Get() const noexcept;
    bool Consume() noexcept;
    std::size_t ReservedPayloadSize() const noexcept { return payload_.size(); }
private:
    std::array<std::uint8_t,HeaderSize> headerBytes_{};
    std::size_t headerUsed_ = 0;
    std::size_t payloadUsed_ = 0;
    FrameHeader header_{};
    std::vector<std::uint8_t> payload_;
    DecodeState state_ = DecodeState::Reading;
};

enum class Direction { ClientToServer, ServerToClient };
enum class Phase { Authentication, Authenticated };
enum class Disposition { Message, UnsupportedRequest, Invalid };

// Header dispatch only. Authentication step order, request correlation and
// message semantics remain owned by the session layer.
Disposition ClassifyFrame(const FrameHeader& header,Direction direction,Phase phase) noexcept;
std::optional<std::uint32_t> SelectCapabilities(std::uint32_t client,std::uint32_t server) noexcept;
}
