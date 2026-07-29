// this file is part of eMule eSE - validated relay sub-protocol dispatch
#pragma once

#include "LiveRelayTypes.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

namespace eSELive {

enum class LiveRelayFragmentResult : std::uint8_t {
    Incomplete = 0,
    Complete = 1,
    Rejected = 2,
};

// Narrow port implemented by the composition root. It binds the dispatcher
// to the already-characterized framing primitives and existing pending-rank
// synchronization without allowing the application module to include either
// the coordinator or a lower-layer concrete implementation.
class ILiveRelayDispatcherPort {
public:
    virtual ~ILiveRelayDispatcherPort() = default;

    virtual bool IsRelayMultiCell(std::uint8_t subCommand) const = 0;
    virtual bool ParseRelaySubHeader(
        const std::uint8_t* plain,
        std::size_t plainLength,
        std::uint8_t& subCommand,
        std::uint32_t& requestId,
        std::uint16_t& bodyLength,
        const std::uint8_t*& body) const = 0;
    virtual bool ParseRelayFragmentHeader(
        const std::uint8_t* body,
        std::size_t bodyLength,
        std::uint16_t& fragmentIndex,
        std::uint16_t& fragmentCount,
        std::uint32_t& messageLength,
        const std::uint8_t*& fragmentData,
        std::size_t& fragmentDataLength) const = 0;
    virtual LiveRelayFragmentResult IngestRelayFragment(
        std::uint32_t circuitId,
        std::uint32_t requestId,
        std::uint16_t fragmentIndex,
        std::uint16_t fragmentCount,
        std::uint32_t messageLength,
        const std::uint8_t* fragmentData,
        std::size_t fragmentDataLength,
        std::vector<std::uint8_t>& completedMessage) = 0;
    virtual bool DispatchRelayExit(
        const LiveTunnelRequestCtx& context) = 0;
};

class LiveRelayDispatcher {
public:
    // Consumes already onion-decrypted bytes. Malformed subheaders and
    // fragment headers return false. Incomplete, duplicate/rejected fragment
    // sequences and unknown handlers are deliberately silent accepted drops,
    // preserving wire behavior while failing closed.
    bool DispatchExitPlain(
        const std::shared_ptr<CLiveCircuit>& circuit,
        const std::uint8_t* plain,
        std::size_t plainLength,
        ILiveRelayDispatcherPort& port) const;
};

// Deterministic application-boundary test for the unattended production
// selftest. It proves validation order and all fragment terminal states without
// network, UI, timers or coordinator state.
bool RunLiveRelayDispatcherCharacterizationSelfTest();

} // namespace eSELive
