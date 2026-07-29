// this file is part of eMule eSE — byte-exact circuit handshake framing
#include "LiveHandshakeWire.h"
#include "LiveTunnelFraming.h"
#include "LiveOnionCrypto.h"

#include <cstring>

namespace eSELive {
namespace LiveCircuitHandshakeWire {

static_assert(HANDSHAKE_CELL_TOTAL_BYTES == CELL_TOTAL_BYTES, "cell size drift");
static_assert(HANDSHAKE_CELL_PAYLOAD_MAX == CELL_PAYLOAD_MAX, "payload size drift");
static_assert(HANDSHAKE_CELL_CREATE == CELL_CREATE, "CREATE opcode drift");
static_assert(HANDSHAKE_CELL_CREATED == CELL_CREATED, "CREATED opcode drift");
static_assert(HANDSHAKE_CELL_EXTEND == CELL_EXTEND, "EXTEND opcode drift");
static_assert(HANDSHAKE_CELL_EXTENDED == CELL_EXTENDED, "EXTENDED opcode drift");

bool PackHandshakeCell(
    std::uint32_t circuitId,
    HandshakeCellCommand command,
    const std::uint8_t* payload,
    std::size_t payloadLength,
    std::uint8_t out[HANDSHAKE_CELL_TOTAL_BYTES])
{
    if (!out || payloadLength > CELL_PAYLOAD_MAX
        || (payloadLength > 0 && !payload))
        return false;
    PutU32LE(out, circuitId);
    out[4] = static_cast<std::uint8_t>(command);
    PutU16LE(out + 5, static_cast<std::uint16_t>(payloadLength));
    if (payloadLength > 0)
        std::memcpy(out + CELL_HEADER_BYTES, payload, payloadLength);
    const std::size_t paddingLength = CELL_PAYLOAD_MAX - payloadLength;
    if (paddingLength > 0)
        SecureRandomBytes(
            out + CELL_HEADER_BYTES + payloadLength,
            paddingLength);
    return true;
}

void PutU32LE(std::uint8_t* p, std::uint32_t v)
{
    p[0] = static_cast<std::uint8_t>(v);
    p[1] = static_cast<std::uint8_t>(v >> 8);
    p[2] = static_cast<std::uint8_t>(v >> 16);
    p[3] = static_cast<std::uint8_t>(v >> 24);
}

void PutU16LE(std::uint8_t* p, std::uint16_t v)
{
    p[0] = static_cast<std::uint8_t>(v);
    p[1] = static_cast<std::uint8_t>(v >> 8);
}

bool ConstantTimeEqual(
    const std::uint8_t* a,
    const std::uint8_t* b,
    std::size_t length) noexcept
{
    if (!a || !b)
        return false;
    std::uint8_t difference = 0;
    for (std::size_t i = 0; i < length; ++i)
        difference |= static_cast<std::uint8_t>(a[i] ^ b[i]);
    return difference == 0;
}

static const char TUN_TRANSCRIPT_LABEL[] = "ese-tun-created-v2";
static_assert(sizeof(TUN_TRANSCRIPT_LABEL) - 1 == 18, "v2 transcript label drift");
static_assert(TUN_TRANSCRIPT_LEN == 150, "v2 transcript layout drift");

void BuildCreatedTranscript(
    std::uint32_t circId,
    const std::uint8_t evPub[32],
    const std::uint8_t erPub[32],
    std::uint32_t signedCaps,
    const std::uint8_t createNonce[16],
    const std::uint8_t targetUserHash[16],
    const std::uint8_t nodePub[32],
    std::uint8_t* out)
{
    (void)circId; // circuit ids differ on relay-local legs
    std::size_t o = 0;
    std::memcpy(out + o, TUN_TRANSCRIPT_LABEL, 18); o += 18;
    std::memcpy(out + o, evPub, 32); o += 32;
    std::memcpy(out + o, erPub, 32); o += 32;
    PutU32LE(out + o, signedCaps); o += 4;
    std::memcpy(out + o, createNonce, 16); o += 16;
    std::memcpy(out + o, targetUserHash, 16); o += 16;
    std::memcpy(out + o, nodePub, 32);
}

static_assert(TUN_HKDF_INFO_LEN == 120, "v2 HKDF layout drift");

std::size_t BuildHkdfInfoV2(
    const char* label20,
    std::uint32_t circId,
    const std::uint8_t evPub[32],
    const std::uint8_t erPub[32],
    std::uint32_t signedCaps,
    const std::uint8_t nodePub[32],
    std::uint8_t* out)
{
    (void)circId;
    std::size_t o = 0;
    std::memcpy(out + o, label20, 20); o += 20;
    std::memcpy(out + o, evPub, 32); o += 32;
    std::memcpy(out + o, erPub, 32); o += 32;
    PutU32LE(out + o, signedCaps); o += 4;
    std::memcpy(out + o, nodePub, 32); o += 32;
    return o;
}

static const char TUN_TRANSCRIPT_V3_LABEL[] = "kad6-tun-created-v3";
static_assert(sizeof(TUN_TRANSCRIPT_V3_LABEL) - 1 == 19, "v3 transcript label drift");
static_assert(TUN_TRANSCRIPT_V3_LEN == 190, "v3 transcript layout drift");
static_assert(TUN_HKDF_INFO_V3_LEN == 159, "v3 HKDF layout drift");

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
    std::uint8_t out[TUN_TRANSCRIPT_V3_LEN])
{
    std::size_t o = 0;
    std::memcpy(out + o, TUN_TRANSCRIPT_V3_LABEL, 19); o += 19;
    PutU32LE(out + o, originCircId); o += 4;
    out[o++] = hopIndex;
    std::memcpy(out + o, prefixHash, 32); o += 32;
    std::memcpy(out + o, evPub, 32); o += 32;
    std::memcpy(out + o, erPub, 32); o += 32;
    PutU32LE(out + o, signedCaps); o += 4;
    PutU16LE(out + o, shapeBucketKiB); o += 2;
    std::memcpy(out + o, createNonce, 16); o += 16;
    std::memcpy(out + o, targetHash, 16); o += 16;
    std::memcpy(out + o, nodePub, 32);
}

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
    std::uint8_t out[TUN_HKDF_INFO_V3_LEN])
{
    std::size_t o = 0;
    std::memcpy(out + o, label20, 20); o += 20;
    PutU32LE(out + o, originCircId); o += 4;
    out[o++] = hopIndex;
    std::memcpy(out + o, prefixHash, 32); o += 32;
    std::memcpy(out + o, evPub, 32); o += 32;
    std::memcpy(out + o, erPub, 32); o += 32;
    PutU32LE(out + o, signedCaps); o += 4;
    PutU16LE(out + o, shapeBucketKiB); o += 2;
    std::memcpy(out + o, nodePub, 32); o += 32;
    return o;
}

} // namespace LiveCircuitHandshakeWire
} // namespace eSELive
