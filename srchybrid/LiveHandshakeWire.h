// this file is part of eMule eSE — byte-exact circuit handshake framing
#pragma once

#include <cstddef>
#include <cstdint>

namespace eSELive {

// Narrow boundary between circuit orchestration and the byte-level tunnel
// protocol. No coordinator or concrete peer type crosses this interface.
//
// Fixed cell envelope:
//   0..3  circuit id, little-endian
//   4     command
//   5..6  payload length, little-endian
//   7..511 payload followed by cryptographically random padding
//
// Authenticated v2 transcript:
//   label | ephemeral origin | ephemeral relay | signed capabilities |
//   create nonce | target user hash | relay node public key
//
// Authenticated v3 extends that context with:
//   origin circuit id | hop index | established-prefix hash |
//   shaping bucket
//
// The implementation statically binds every size and command value to the
// canonical LiveTunnelFraming definitions. Any drift therefore fails the
// build instead of producing a circuit that silently derives different keys.
//
// Peer access is deliberately opaque. The composition root supplies a
// read-only value snapshot and performs sends; the handshake never owns or
// dereferences CUpDownClient.
using LiveHandshakePeerHandle = void*;

struct LiveHandshakePeerView {
    bool validHash = false;
    std::uint8_t userHash[16]{};
    bool hasNodePublicKey = false;
    std::uint8_t nodePublicKey[32]{};
    bool supportsDataplane = false;
    bool supportsBulk = false;
    bool supportsAuth = false;
    bool supportsStrict3 = false;
    bool supportsShaped = false;
    bool hasIpv6 = false;
    std::uint8_t ipv6[16]{};
    bool ipv6Only = false;
    std::uint32_t ipv4 = 0;
    std::uint16_t port = 0;
};

namespace LiveCircuitHandshakeWire {

constexpr std::size_t HANDSHAKE_CELL_TOTAL_BYTES = 512;
constexpr std::size_t HANDSHAKE_CELL_PAYLOAD_MAX = 505;

enum HandshakeCellCommand : std::uint8_t {
    HANDSHAKE_CELL_CREATE = 0x01,
    HANDSHAKE_CELL_CREATED = 0x02,
    HANDSHAKE_CELL_EXTEND = 0x03,
    HANDSHAKE_CELL_EXTENDED = 0x04,
};

constexpr std::size_t TUN_TRANSCRIPT_LEN = 150;
constexpr std::size_t TUN_HKDF_INFO_LEN = 120;
constexpr std::size_t TUN_TRANSCRIPT_V3_LEN = 190;
constexpr std::size_t TUN_HKDF_INFO_V3_LEN = 159;
constexpr std::size_t TUN_CREATE_V3_LEN = 140;
constexpr std::size_t TUN_EXTEND_V3_LEN = 158;
constexpr std::size_t K6_SHAPE_MAX_RESERVED_LINKS = 8;

void PutU32LE(std::uint8_t* p, std::uint32_t v);
void PutU16LE(std::uint8_t* p, std::uint16_t v);
bool ConstantTimeEqual(
    const std::uint8_t* a,
    const std::uint8_t* b,
    std::size_t length) noexcept;
bool PackHandshakeCell(
    std::uint32_t circuitId,
    HandshakeCellCommand command,
    const std::uint8_t* payload,
    std::size_t payloadLength,
    std::uint8_t out[HANDSHAKE_CELL_TOTAL_BYTES]);

void BuildCreatedTranscript(
    std::uint32_t circId,
    const std::uint8_t evPub[32],
    const std::uint8_t erPub[32],
    std::uint32_t signedCaps,
    const std::uint8_t createNonce[16],
    const std::uint8_t targetUserHash[16],
    const std::uint8_t nodePub[32],
    std::uint8_t* out);

std::size_t BuildHkdfInfoV2(
    const char* label20,
    std::uint32_t circId,
    const std::uint8_t evPub[32],
    const std::uint8_t erPub[32],
    std::uint32_t signedCaps,
    const std::uint8_t nodePub[32],
    std::uint8_t* out);

void BuildCreatedTranscriptV3(
    std::uint32_t originCircId,
    std::uint8_t hopIndex,
    const std::uint8_t prefixHash[32],
    const std::uint8_t evPub[32],
    const std::uint8_t erPub[32],
    std::uint32_t signedCaps,
    std::uint16_t shapeBucketKiB,
    const std::uint8_t createNonce[16],
    const std::uint8_t targetHash[16],
    const std::uint8_t nodePub[32],
    std::uint8_t out[TUN_TRANSCRIPT_V3_LEN]);

std::size_t BuildHkdfInfoV3(
    const char* label20,
    std::uint32_t originCircId,
    std::uint8_t hopIndex,
    const std::uint8_t prefixHash[32],
    const std::uint8_t evPub[32],
    const std::uint8_t erPub[32],
    std::uint32_t signedCaps,
    std::uint16_t shapeBucketKiB,
    const std::uint8_t nodePub[32],
    std::uint8_t out[TUN_HKDF_INFO_V3_LEN]);

} // namespace LiveCircuitHandshakeWire
} // namespace eSELive
