// this file is part of eMule eSE - exit handler and deferred-reply ownership
#pragma once

#include "LiveRelayTypes.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>

namespace eSELive {

// Canonical correlation key for all exit-side state. Keeping the circuit id
// in the high half prevents request-id reuse on different circuits from
// colliding in handler, reassembly or search state.
constexpr std::uint64_t LiveRequestKey(
    std::uint32_t circuitId,
    std::uint32_t requestId) noexcept
{
    return (static_cast<std::uint64_t>(circuitId) << 32) | requestId;
}

// Owns the exit handler table and deferred-reply lifecycle. Synchronization is
// deliberately supplied by the composition root: handler registration and
// dispatch are main-thread-only, while operation methods are called under the
// existing pending-rank lock. No callback is invoked by a lifecycle method.
class LiveExitServices {
public:
    struct Completion {
        std::shared_ptr<CLiveCircuit> circuit;
        std::uint8_t reply_op = 0;
    };

    LiveExitServices() = default;
    LiveExitServices(const LiveExitServices&) = delete;
    LiveExitServices& operator=(const LiveExitServices&) = delete;

    // Last registration wins, matching the historic constructor-only table.
    // A null handler is retained as an explicitly unavailable service and
    // dispatches fail closed.
    void RegisterHandler(
        std::uint8_t subCommand,
        LiveTunnelOpHandler handler);

    // Returns true only when a non-null handler was synchronously invoked.
    // Unknown and explicitly unavailable services are indistinguishable to
    // the peer and produce no reply.
    bool Dispatch(
        std::uint8_t subCommand,
        const LiveTunnelRequestCtx& context) const;

    // Registers a deferred operation. Duplicate (circuit, request) pairs are
    // rejected instead of overwriting live state, making replay fail closed.
    bool Begin(
        const std::shared_ptr<CLiveCircuit>& circuit,
        std::uint32_t requestId,
        std::uint8_t replyOp,
        std::uint32_t startedTick);

    // Atomically consumes an operation before the caller performs the
    // external send. A second completion therefore cannot produce a reply.
    bool TakeCompletion(
        std::uint32_t circuitId,
        std::uint32_t requestId,
        Completion& completion);

    // Looks up a non-final response without consuming the operation.
    bool FindPart(
        std::uint32_t circuitId,
        std::uint32_t requestId,
        Completion& completion) const;

    // Idempotent cancellation. Returns whether live state was removed.
    bool Abort(
        std::uint32_t circuitId,
        std::uint32_t requestId);

    // Removes every deferred operation bound to a circuit being destroyed.
    // Other circuits may reuse the same request id without interference.
    std::size_t AbortCircuit(std::uint32_t circuitId);

    // Drops all deferred operations during subsystem shutdown. Handler
    // registrations remain immutable and ready for a later restart.
    std::size_t Clear();

    // Removes expired or circuit-less operations. Unsigned subtraction
    // intentionally preserves Win32 tick-wrap semantics.
    std::size_t Sweep(
        std::uint32_t now,
        std::uint32_t ttl);

    std::size_t PendingCount() const noexcept
    {
        return m_operations.size();
    }
    std::size_t HandlerCount() const noexcept;
    bool HasOperation(
        std::uint32_t circuitId,
        std::uint32_t requestId) const;

private:
    struct Operation {
        std::weak_ptr<CLiveCircuit> circuit;
        std::uint32_t circuit_id = 0;
        std::uint32_t request_id = 0;
        std::uint8_t reply_op = 0;
        std::uint32_t started_tick = 0;
    };

    std::map<std::uint8_t, LiveTunnelOpHandler> m_handlers;
    std::map<std::uint64_t, Operation> m_operations;
};

// Deterministic production-boundary test used by the unattended `--selftest`
// path. It performs no network, UI, registry or filesystem operation.
bool RunLiveExitServicesCharacterizationSelfTest();

} // namespace eSELive
