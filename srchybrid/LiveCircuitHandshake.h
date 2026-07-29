#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>

#include "LiveCircuitRegistry.h"

class CUpDownClient;

namespace eSELive {

class LiveCircuitHandshakeHost {
public:
    virtual ~LiveCircuitHandshakeHost() = default;
    virtual LiveCircuitRegistry& HandshakeCircuitRegistry() = 0;
    virtual bool SendHandshakeCell(
        CUpDownClient* peer,
        const std::uint8_t* cell) = 0;
    virtual void DestroyHandshakeCircuit(
        const std::shared_ptr<CLiveCircuit>& circuit) = 0;
    virtual std::uint32_t NewHandshakeCircuitId() = 0;
    virtual void ResolveHandshakeExitKey(
        CUpDownClient* exit,
        CLiveCircuit& circuit) = 0;
    virtual void RegisterActiveHandshakeCircuit(
        const std::shared_ptr<CLiveCircuit>& circuit) = 0;
    virtual const std::uint8_t* LocalHandshakeUserHash() const = 0;
    virtual const std::uint8_t* LocalHandshakeNodePublicKey() const = 0;
    virtual bool SignHandshakeTranscript(
        const std::uint8_t* bytes,
        std::size_t length,
        std::uint8_t signature[64]) const = 0;
    virtual std::uint32_t HandshakeRuntimeCapabilities() const = 0;
    virtual CUpDownClient* FindConnectedHandshakePeerByHash(
        const std::uint8_t hash[16]) const = 0;
    virtual CUpDownClient* FindConnectedHandshakePeer(
        std::uint32_t ipv4,
        std::uint16_t port) const = 0;
    virtual std::uint32_t LocalHandshakePublicIp() const = 0;
};

class LiveCircuitHandshake {
public:
    explicit LiveCircuitHandshake(LiveCircuitHandshakeHost& host)
        : m_host(host) {}

    bool HandleCreatedOriginator(
        std::shared_ptr<CLiveCircuit>& circuit,
        const std::uint8_t* payload,
        std::uint16_t payloadLength);
    bool ContinueOriginatorBuild(std::shared_ptr<CLiveCircuit>& circuit);
    bool HandleCreateRelay(
        std::uint32_t circuitId,
        const std::uint8_t* payload,
        std::uint16_t payloadLength,
        CUpDownClient* fromPeer);
    bool BuildExtend(
        std::shared_ptr<CLiveCircuit>& circuit,
        CUpDownClient* target);
    bool HandleExtendRelay(
        std::shared_ptr<CLiveCircuit>& circuit,
        const std::uint8_t* payload,
        std::uint16_t payloadLength);
    bool ForwardCreatedAsExtendedRelay(
        std::uint32_t outboundCircuitId,
        const std::uint8_t* payload,
        std::uint16_t payloadLength);
    bool ForwardExtendCellForward(
        std::shared_ptr<CLiveCircuit>& circuit,
        const std::uint8_t* payload,
        std::uint16_t payloadLength);
    bool ForwardExtendedCellReverse(
        std::shared_ptr<CLiveCircuit>& circuit,
        const std::uint8_t* payload,
        std::uint16_t payloadLength);
    bool HandleExtendedOriginator(
        std::shared_ptr<CLiveCircuit>& circuit,
        const std::uint8_t* payload,
        std::uint16_t payloadLength);

private:
    LiveCircuitHandshakeHost& m_host;
};

// Byte-exact primitives shared by circuit construction and the physical
// handshake implementation. The CLiveTunnel methods themselves stay as the
// compatibility facade while MOD-1.4 moves their implementation out of the
// coordinator translation unit.
namespace LiveCircuitHandshakeWire {

constexpr std::size_t TUN_TRANSCRIPT_LEN = 150;
constexpr std::size_t TUN_HKDF_INFO_LEN = 120;
constexpr std::size_t TUN_TRANSCRIPT_V3_LEN = 190;
constexpr std::size_t TUN_HKDF_INFO_V3_LEN = 159;
constexpr std::size_t TUN_CREATE_V3_LEN = 140;
constexpr std::size_t TUN_EXTEND_V3_LEN = 158;

void PutU32LE(std::uint8_t* p, std::uint32_t v);
void PutU16LE(std::uint8_t* p, std::uint16_t v);

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

bool BuildCircuitPrefixHash(
    const CLiveCircuit& circuit,
    std::uint8_t out[32]);

} // namespace LiveCircuitHandshakeWire
} // namespace eSELive
