#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>

#include "LiveCircuitRegistry.h"
#include "LiveHandshakeWire.h"

namespace eSELive {

class LiveCircuitHandshakeHost {
public:
    virtual ~LiveCircuitHandshakeHost() = default;
    virtual LiveCircuitRegistry& HandshakeCircuitRegistry() = 0;
    virtual bool SendHandshakeCell(
        LiveHandshakePeerHandle peer,
        const std::uint8_t* cell) = 0;
    virtual bool ReadHandshakePeer(
        LiveHandshakePeerHandle peer,
        LiveHandshakePeerView& view) const = 0;
    virtual void DestroyHandshakeCircuit(
        const std::shared_ptr<CLiveCircuit>& circuit) = 0;
    virtual std::uint32_t NewHandshakeCircuitId() = 0;
    virtual void ResolveHandshakeExitKey(
        LiveHandshakePeerHandle exit,
        CLiveCircuit& circuit) = 0;
    virtual void RegisterActiveHandshakeCircuit(
        const std::shared_ptr<CLiveCircuit>& circuit) = 0;
    virtual const std::uint8_t* LocalHandshakeUserHash() const = 0;
    virtual const std::uint8_t* LocalHandshakeNodePublicKey() const = 0;
    virtual bool SignHandshakeTranscript(
        const std::uint8_t* bytes,
        std::size_t length,
        std::uint8_t signature[64]) const = 0;
    virtual bool HashHandshakeCircuitPrefix(
        const CLiveCircuit& circuit,
        std::uint8_t out[32]) const = 0;
    virtual std::uint32_t HandshakeRuntimeCapabilities() const = 0;
    virtual LiveHandshakePeerHandle FindConnectedHandshakePeerByHash(
        const std::uint8_t hash[16]) const = 0;
    virtual LiveHandshakePeerHandle FindConnectedHandshakePeer(
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
        LiveHandshakePeerHandle fromPeer);
    bool BuildExtend(
        std::shared_ptr<CLiveCircuit>& circuit,
        LiveHandshakePeerHandle target);
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

} // namespace eSELive
