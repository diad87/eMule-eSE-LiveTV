// SPDX-License-Identifier: MIT
#include "relay/krp_control.h"
#include "relay/relay_bytes.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <vector>

namespace {

int g_pass = 0;
int g_fail = 0;

#define CHECK(condition, message) \
    do { \
        if (condition) { \
            ++g_pass; \
        } else { \
            ++g_fail; \
            std::printf("  FAIL: %s (%s:%d)\n", message, __FILE__, __LINE__); \
        } \
    } while (0)

void CheckVarint(std::uint64_t value, const std::vector<relay::Byte>& expected) {
    std::vector<relay::Byte> wire;
    relay::RelayByteWriter writer(wire);
    writer.WriteVarint(value);
    CHECK(wire == expected, "varint golden encoding");

    relay::RelayByteReader reader(wire.data(), wire.size());
    std::uint64_t decoded = 0;
    CHECK(reader.ReadVarint(decoded) == relay::RelayStatus::Ok,
          "varint golden decoding");
    CHECK(decoded == value && reader.remaining() == 0,
          "varint round trip consumes exact input");
}

void TestVarints() {
    CheckVarint(0, {0x00});
    CheckVarint(1, {0x01});
    CheckVarint(127, {0x7F});
    CheckVarint(128, {0x80, 0x01});
    CheckVarint(300, {0xAC, 0x02});
    CheckVarint(16384, {0x80, 0x80, 0x01});
    CheckVarint((std::numeric_limits<std::uint64_t>::max)(),
                {0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                 0xFF, 0xFF, 0xFF, 0xFF, 0x01});

    const relay::Byte truncated[] = {0x80};
    relay::RelayByteReader truncated_reader(truncated, sizeof(truncated));
    std::uint64_t unchanged = 77;
    CHECK(truncated_reader.ReadVarint(unchanged) == relay::RelayStatus::Truncated,
          "unterminated varint is truncated");
    CHECK(unchanged == 77, "failed varint does not modify output");

    const relay::Byte overlong[] = {0x80, 0x00};
    relay::RelayByteReader overlong_reader(overlong, sizeof(overlong));
    CHECK(overlong_reader.ReadVarint(unchanged) == relay::RelayStatus::Malformed,
          "overlong varint is rejected");

    const relay::Byte overflow[] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0x02};
    relay::RelayByteReader overflow_reader(overflow, sizeof(overflow));
    CHECK(overflow_reader.ReadVarint(unchanged) == relay::RelayStatus::Malformed,
          "varint wider than uint64 is rejected");

    relay::RelayByteReader null_reader(nullptr, 1);
    CHECK(null_reader.status() == relay::RelayStatus::InvalidArgument,
          "null with non-zero size is rejected");
}

void TestControlFrames() {
    relay::KrpControlFrame ping;
    ping.type = static_cast<std::uint64_t>(relay::KrpMessageType::KRP_PING);
    ping.flags = relay::kKrpFlagIdempotent;
    ping.payload = {1, 2, 3};

    std::vector<relay::Byte> wire;
    CHECK(relay::EncodeKrpControlFrame(ping, wire) == relay::RelayStatus::Ok,
          "PING frame encodes");
    CHECK(wire == std::vector<relay::Byte>({0x50, 0x02, 0x03, 1, 2, 3}),
          "PING frame has canonical golden bytes");

    relay::KrpControlFrame decoded;
    std::size_t consumed = 0;
    CHECK(relay::DecodeKrpControlFrame(wire.data(), wire.size(), decoded, consumed) ==
              relay::RelayStatus::Ok,
          "PING frame decodes");
    CHECK(consumed == wire.size() && decoded.type == ping.type &&
              decoded.flags == ping.flags && decoded.payload == ping.payload,
          "PING frame exact round trip");

    std::vector<relay::Byte> two_frames = wire;
    two_frames.insert(two_frames.end(), wire.begin(), wire.end());
    CHECK(relay::DecodeKrpControlFrame(two_frames.data(), two_frames.size(), decoded, consumed) ==
              relay::RelayStatus::Ok && consumed == wire.size(),
          "stream decoder consumes one frame and leaves trailing bytes");

    relay::KrpControlFrame unknown = ping;
    unknown.type = 0x7E;
    std::vector<relay::Byte> sentinel = {9, 9};
    CHECK(relay::EncodeKrpControlFrame(unknown, sentinel) ==
              relay::RelayStatus::UnsupportedMessage,
          "unknown message is rejected by producer");
    CHECK(sentinel == std::vector<relay::Byte>({9, 9}),
          "failed producer leaves caller output unchanged");

    const relay::Byte unknown_wire[] = {0x7E, 0x00, 0x00};
    consumed = 9;
    decoded.payload = {7};
    CHECK(relay::DecodeKrpControlFrame(unknown_wire, sizeof(unknown_wire), decoded, consumed) ==
              relay::RelayStatus::UnsupportedMessage,
          "unknown message is rejected by consumer");
    CHECK(consumed == 0 && decoded.payload.empty(),
          "failed consumer resets output and consumed count");

    const relay::Byte unknown_flags[] = {0x50, 0x40, 0x00};
    CHECK(relay::DecodeKrpControlFrame(unknown_flags, sizeof(unknown_flags), decoded, consumed) ==
              relay::RelayStatus::UnsupportedOption,
          "unknown control flag is rejected");

    const relay::Byte short_payload[] = {0x50, 0x00, 0x03, 0x01};
    CHECK(relay::DecodeKrpControlFrame(short_payload, sizeof(short_payload), decoded, consumed) ==
              relay::RelayStatus::Truncated,
          "truncated payload is rejected");

    relay::KrpControlFrame maximum;
    maximum.type = static_cast<std::uint64_t>(relay::KrpMessageType::KRP_SETTINGS);
    maximum.payload.resize(relay::kKrpMaxControlPayload, 0xA5);
    CHECK(relay::EncodeKrpControlFrame(maximum, wire) == relay::RelayStatus::Ok,
          "maximum control payload is accepted");
    maximum.payload.push_back(0);
    CHECK(relay::EncodeKrpControlFrame(maximum, wire) == relay::RelayStatus::TooLarge,
          "oversized control payload is rejected before encoding");

    const relay::Byte declared_too_large[] = {0x50, 0x00, 0x81, 0x80, 0x04};
    CHECK(relay::DecodeKrpControlFrame(declared_too_large,
                                       sizeof(declared_too_large),
                                       decoded,
                                       consumed) == relay::RelayStatus::TooLarge,
          "oversized declared payload is rejected before allocation");
}

std::uint64_t NextRandom(std::uint64_t& state) {
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    return state;
}

void TestDeterministicFuzz() {
    std::uint64_t state = 0x4B52505F50315F31ull;
    std::vector<relay::Byte> input(1024);
    std::size_t successful = 0;
    for (std::size_t iteration = 0; iteration < 100000; ++iteration) {
        const std::size_t size = static_cast<std::size_t>(NextRandom(state) % input.size());
        for (std::size_t i = 0; i < size; ++i)
            input[i] = static_cast<relay::Byte>(NextRandom(state));

        relay::KrpControlFrame decoded;
        std::size_t consumed = 0;
        const relay::RelayStatus status =
            relay::DecodeKrpControlFrame(input.data(), size, decoded, consumed);
        if (status != relay::RelayStatus::Ok)
            continue;

        ++successful;
        CHECK(consumed <= size, "fuzz success consumes within input");
        CHECK(decoded.payload.size() <= relay::kKrpMaxControlPayload,
              "fuzz success respects payload cap");
        CHECK(relay::IsReservedKrpMessageType(decoded.type),
              "fuzz success has a reserved message type");
        CHECK((decoded.flags & ~relay::kKrpKnownControlFlags) == 0,
              "fuzz success has only known flags");

        std::vector<relay::Byte> encoded;
        CHECK(relay::EncodeKrpControlFrame(decoded, encoded) == relay::RelayStatus::Ok,
              "fuzz success re-encodes");
        CHECK(encoded.size() == consumed, "canonical re-encode matches consumed size");
        CHECK(std::equal(encoded.begin(), encoded.end(), input.begin()),
              "canonical success round-trips exact frame bytes");
    }
    std::printf("  deterministic fuzz: 100000 inputs, %zu valid frames\n", successful);
}

} // namespace

int main() {
    TestVarints();
    TestControlFrames();
    TestDeterministicFuzz();
    std::printf("test_krp_control: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
