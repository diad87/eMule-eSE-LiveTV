// this file is part of eMule eSE - exit handler and deferred-reply ownership
#pragma once

#include "M2ABindingPort.h"
#include "LiveRelayTypes.h"
#include "LiveTunnelSourcePublisherPort.h"
#include "LiveTunnelStreamFlowPort.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

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

    LiveExitServices();
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

    bool LT4InitializeTicketSecret(
        const std::array<std::uint8_t, 32>& secret) noexcept;
    bool LT4TicketSecretReady() const noexcept;
    std::array<std::uint8_t, 32> LT4TicketSecret() const noexcept;
    void LT4AuthorizeTarget(
        const std::string& key,
        const LiveTunnelAuthorizedTarget& target);
    bool LT4FindAuthorizedTarget(
        const std::string& key,
        std::uint64_t now,
        LiveTunnelAuthorizedTarget& target) const;
    bool LT4ConsumeTicket(
        const kad6::K6TargetTicket& ticket,
        std::uint64_t now) noexcept;
    std::map<std::uint64_t, LiveTunnelPublishRuntime>
        LT4PublishSnapshot() const;
    std::size_t LT4PublishCount() const noexcept;
    bool LT4FindPublish(
        std::uint64_t publishLeaseId,
        LiveTunnelPublishRuntime& runtime) const;
    std::map<std::string, std::uint64_t> LT4ShadowSnapshot() const;
    LiveTunnelPublishMutation LT4OpenPublish(LiveTunnelPublishRuntime&,const std::string&,LiveTunnelPublishRuntime&,bool&);
    LiveTunnelPublishMutation LT4RemovePublish(std::uint64_t,std::vector<LiveTunnelPublishAction>&);
    bool LT4DisablePublish(std::uint64_t); std::vector<std::uint64_t> LT4DisableSource(std::uint64_t); std::vector<std::uint64_t> LT4DisableAll(bool);
    bool LT4EnsureShadow(const std::string&,std::uint64_t,std::uint64_t&,bool&); bool LT4ForgetShadow(const std::string&); bool LT4SetQueueState(std::uint64_t,bool,std::uint64_t,std::uint64_t);
    bool LT4MarkNativeSent(std::uint64_t,std::uint64_t,std::uint64_t,std::uint64_t&); std::vector<std::uint64_t> LT4MarkShadowSent(std::uint64_t);
    bool LT4MarkShadowAck(std::uint64_t,std::uint8_t,std::uint64_t); bool LT4MarkShadowVerified(std::uint64_t); bool LT4MarkNativeResult(std::uint64_t,kad6::K6StoreStatus,std::uint8_t,std::uint64_t,std::uint64_t,bool&);
    std::vector<LiveTunnelPublishRuntime> LT4TakeNativeRefreshes(std::uint64_t); bool LT4CompleteNativeRefresh(std::uint64_t,bool,std::uint64_t);
    bool LT4TakeShadow(std::uint64_t,LiveTunnelPublishRuntime&); bool LT4CompleteShadow(std::uint64_t,bool,std::uint64_t);
    std::vector<LiveTunnelPublishRuntime> LT4TakeVisibilityProbes(std::uint64_t,bool&); bool LT4CompleteVisibilityProbe(std::uint64_t,bool,std::uint64_t);
    std::vector<LiveTunnelPublishAction> LT4Sweep(std::uint64_t); void LT4ResetPublishes();
    void LT4PruneTicketState(std::uint64_t now);
    void LT5ClearCredits() noexcept;
    std::size_t LT5ExitCount() const noexcept; std::size_t LT5OriginCount() const noexcept;
    LiveTunnelExitStreams LT5ExitSnapshot() const; LiveTunnelOriginStreams LT5OriginSnapshot() const;
    bool LT5FindExit(std::uint64_t,LiveTunnelExitStreamRuntime&) const; bool LT5FindOrigin(std::uint64_t,LiveTunnelOriginStreamRuntime&) const;
    bool LT5FindExit(std::uint64_t,CKad6ExitSocket*,LiveTunnelExitStreamRuntime&) const; bool LT5FindOrigin(std::uint64_t,CKad6OriginSocket*,LiveTunnelOriginStreamRuntime&) const;
    bool LT5CreateExit(std::uint64_t,LiveTunnelExitStreamRuntime&); bool LT5CreateOrigin(std::uint64_t,LiveTunnelOriginStreamRuntime&);
    bool LT5UpdateExit(std::uint64_t,CKad6ExitSocket*,std::uint64_t,const LiveTunnelExitStreamRuntime&); bool LT5UpdateOrigin(std::uint64_t,CKad6OriginSocket*,std::uint64_t,const LiveTunnelOriginStreamRuntime&);
    bool LT5TakeExit(std::uint64_t,CKad6ExitSocket*,std::uint64_t,LiveTunnelExitStreamRuntime&); bool LT5TakeOrigin(std::uint64_t,CKad6OriginSocket*,std::uint64_t,LiveTunnelOriginStreamRuntime&);
    bool LT5HalfCloseExit(std::uint32_t,const kad6::K6StreamHalfClose&); bool LT5HalfCloseOrigin(std::uint32_t,const kad6::K6StreamHalfClose&);
    bool LT5CloseExit(std::uint32_t,const kad6::K6StreamClose&,LiveTunnelExitStreamRuntime&); bool LT5CloseOrigin(std::uint32_t,const kad6::K6StreamClose&,LiveTunnelOriginStreamRuntime&);
    bool LT5Grant(std::uint32_t,const kad6::K6MaxStreamData&); bool LT5Grant(std::uint32_t,const kad6::K6MaxData&);
    std::uint64_t LT5Available(std::uint32_t,std::uint64_t,std::uint8_t,std::uint64_t,std::uint64_t,std::uint64_t) const; std::uint64_t LT5Sent(std::uint32_t,std::uint64_t,std::uint8_t) const;
    bool LT5CommitExitSend(CKad6ExitSocket*,std::uint64_t,std::uint64_t,std::uint8_t,std::uint64_t,std::uint64_t,std::uint64_t,std::uint64_t);
    bool LT5CommitOriginSend(CKad6OriginSocket*,std::uint64_t,std::uint64_t,std::uint8_t,std::uint64_t,std::uint64_t,std::uint64_t,std::uint64_t);
    bool LT5InitialCredit(std::uint32_t,std::uint64_t,std::uint8_t,kad6::K6MaxStreamData&,kad6::K6MaxData&) const; bool LT5CanAccept(std::uint32_t,std::uint64_t,std::uint8_t,std::uint64_t) const;
    bool LT5Accept(std::uint32_t,std::uint64_t,std::uint8_t,std::uint64_t,std::uint64_t); bool LT5Consume(std::uint32_t,std::uint64_t,std::uint8_t,std::uint64_t,std::uint64_t,kad6::K6MaxStreamData&,kad6::K6MaxData&); bool LT5ReadsPaused(std::uint32_t) const;

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
    M2AModuleHandle m_m2a_binding_6e698bd4a3;
    M2AModuleHandle m_m2a_binding_ae4815b275;
};

// Deterministic production-boundary test used by the unattended `--selftest`
// path. It performs no network, UI, registry or filesystem operation.
bool RunLiveExitServicesCharacterizationSelfTest();

} // namespace eSELive
