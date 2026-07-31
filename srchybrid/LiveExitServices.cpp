// this file is part of eMule eSE - exit handler and deferred-reply ownership
#include "stdafx.h"
#include "LiveExitServices.h"

#include "LiveCircuit.h"

#include <utility>

namespace eSELive {

M2AModuleHandle M2A_BIND_LT4_6E698BD4A3(const M2AParentPort&); bool RunLiveTunnelSourcePublisherCharacterizationSelfTest();
bool M2A_LT4_InitializeSecretBridge(M2AModuleHandle&,const std::array<std::uint8_t,32>&) noexcept; bool M2A_LT4_TicketSecretReadyBridge(const M2AModuleHandle&) noexcept; std::array<std::uint8_t,32> M2A_LT4_TicketSecretBridge(const M2AModuleHandle&) noexcept;
void M2A_LT4_AuthorizeTargetBridge(M2AModuleHandle&,const std::string&,const LiveTunnelAuthorizedTarget&); bool M2A_LT4_FindAuthorizedTargetBridge(const M2AModuleHandle&,const std::string&,std::uint64_t,LiveTunnelAuthorizedTarget&); bool M2A_LT4_ConsumeTicketBridge(M2AModuleHandle&,const kad6::K6TargetTicket&,std::uint64_t) noexcept;
std::map<std::uint64_t,LiveTunnelPublishRuntime> M2A_LT4_PublishSnapshotBridge(const M2AModuleHandle&); std::size_t M2A_LT4_PublishCountBridge(const M2AModuleHandle&) noexcept; bool M2A_LT4_FindPublishBridge(const M2AModuleHandle&,std::uint64_t,LiveTunnelPublishRuntime&); std::map<std::string,std::uint64_t> M2A_LT4_ShadowSnapshotBridge(const M2AModuleHandle&);
LiveTunnelPublishMutation M2A_LT4_OpenPublishBridge(M2AModuleHandle&,LiveTunnelPublishRuntime&,const std::string&,LiveTunnelPublishRuntime&,bool&); LiveTunnelPublishMutation M2A_LT4_RemovePublishBridge(M2AModuleHandle&,std::uint64_t,std::vector<LiveTunnelPublishAction>&); bool M2A_LT4_DisablePublishBridge(M2AModuleHandle&,std::uint64_t); std::vector<std::uint64_t> M2A_LT4_DisableSourceBridge(M2AModuleHandle&,std::uint64_t); std::vector<std::uint64_t> M2A_LT4_DisableAllBridge(M2AModuleHandle&,bool);
bool M2A_LT4_EnsureShadowBridge(M2AModuleHandle&,const std::string&,std::uint64_t,std::uint64_t&,bool&); bool M2A_LT4_ForgetShadowBridge(M2AModuleHandle&,const std::string&); bool M2A_LT4_SetQueueStateBridge(M2AModuleHandle&,std::uint64_t,bool,std::uint64_t,std::uint64_t); bool M2A_LT4_MarkNativeSentBridge(M2AModuleHandle&,std::uint64_t,std::uint64_t,std::uint64_t,std::uint64_t&); std::vector<std::uint64_t> M2A_LT4_MarkShadowSentBridge(M2AModuleHandle&,std::uint64_t); bool M2A_LT4_MarkShadowAckBridge(M2AModuleHandle&,std::uint64_t,std::uint8_t,std::uint64_t); bool M2A_LT4_MarkShadowVerifiedBridge(M2AModuleHandle&,std::uint64_t); bool M2A_LT4_MarkNativeResultBridge(M2AModuleHandle&,std::uint64_t,kad6::K6StoreStatus,std::uint8_t,std::uint64_t,std::uint64_t,bool&);
std::vector<LiveTunnelPublishRuntime> M2A_LT4_TakeNativeRefreshesBridge(M2AModuleHandle&,std::uint64_t); bool M2A_LT4_CompleteNativeRefreshBridge(M2AModuleHandle&,std::uint64_t,bool,std::uint64_t); bool M2A_LT4_TakeShadowBridge(M2AModuleHandle&,std::uint64_t,LiveTunnelPublishRuntime&); bool M2A_LT4_CompleteShadowBridge(M2AModuleHandle&,std::uint64_t,bool,std::uint64_t); std::vector<LiveTunnelPublishRuntime> M2A_LT4_TakeVisibilityProbesBridge(M2AModuleHandle&,std::uint64_t,bool&); bool M2A_LT4_CompleteVisibilityProbeBridge(M2AModuleHandle&,std::uint64_t,bool,std::uint64_t); std::vector<LiveTunnelPublishAction> M2A_LT4_SweepBridge(M2AModuleHandle&,std::uint64_t); void M2A_LT4_ResetPublishesBridge(M2AModuleHandle&); void M2A_LT4_PruneTicketStateBridge(M2AModuleHandle&,std::uint64_t);

LiveExitServices::LiveExitServices():m_m2a_binding_6e698bd4a3(M2AAssignmentPolicy::RetainExisting){}
bool LiveExitServices::LT4InitializeTicketSecret(const std::array<std::uint8_t,32>& v) noexcept{return M2A_LT4_InitializeSecretBridge(m_m2a_binding_6e698bd4a3,v);}
bool LiveExitServices::LT4TicketSecretReady() const noexcept{return M2A_LT4_TicketSecretReadyBridge(m_m2a_binding_6e698bd4a3);}
std::array<std::uint8_t,32> LiveExitServices::LT4TicketSecret() const noexcept{return M2A_LT4_TicketSecretBridge(m_m2a_binding_6e698bd4a3);}
void LiveExitServices::LT4AuthorizeTarget(const std::string& k,const LiveTunnelAuthorizedTarget& v){M2A_LT4_AuthorizeTargetBridge(m_m2a_binding_6e698bd4a3,k,v);}
bool LiveExitServices::LT4FindAuthorizedTarget(const std::string& k,std::uint64_t n,LiveTunnelAuthorizedTarget& v) const{return M2A_LT4_FindAuthorizedTargetBridge(m_m2a_binding_6e698bd4a3,k,n,v);}
bool LiveExitServices::LT4ConsumeTicket(const kad6::K6TargetTicket& t,std::uint64_t n) noexcept{return M2A_LT4_ConsumeTicketBridge(m_m2a_binding_6e698bd4a3,t,n);}
std::map<std::uint64_t,LiveTunnelPublishRuntime> LiveExitServices::LT4PublishSnapshot() const{return M2A_LT4_PublishSnapshotBridge(m_m2a_binding_6e698bd4a3);}
std::size_t LiveExitServices::LT4PublishCount() const noexcept{return M2A_LT4_PublishCountBridge(m_m2a_binding_6e698bd4a3);}
bool LiveExitServices::LT4FindPublish(std::uint64_t id,LiveTunnelPublishRuntime& v) const{return M2A_LT4_FindPublishBridge(m_m2a_binding_6e698bd4a3,id,v);}
std::map<std::string,std::uint64_t> LiveExitServices::LT4ShadowSnapshot() const{return M2A_LT4_ShadowSnapshotBridge(m_m2a_binding_6e698bd4a3);}
LiveTunnelPublishMutation LiveExitServices::LT4OpenPublish(LiveTunnelPublishRuntime& r,const std::string& k,LiveTunnelPublishRuntime& d,bool& e){return M2A_LT4_OpenPublishBridge(m_m2a_binding_6e698bd4a3,r,k,d,e);} LiveTunnelPublishMutation LiveExitServices::LT4RemovePublish(std::uint64_t id,std::vector<LiveTunnelPublishAction>& a){return M2A_LT4_RemovePublishBridge(m_m2a_binding_6e698bd4a3,id,a);}
bool LiveExitServices::LT4DisablePublish(std::uint64_t id){return M2A_LT4_DisablePublishBridge(m_m2a_binding_6e698bd4a3,id);} std::vector<std::uint64_t> LiveExitServices::LT4DisableSource(std::uint64_t id){return M2A_LT4_DisableSourceBridge(m_m2a_binding_6e698bd4a3,id);} std::vector<std::uint64_t> LiveExitServices::LT4DisableAll(bool c){return M2A_LT4_DisableAllBridge(m_m2a_binding_6e698bd4a3,c);}
bool LiveExitServices::LT4EnsureShadow(const std::string& k,std::uint64_t id,std::uint64_t& p,bool& c){return M2A_LT4_EnsureShadowBridge(m_m2a_binding_6e698bd4a3,k,id,p,c);} bool LiveExitServices::LT4ForgetShadow(const std::string& k){return M2A_LT4_ForgetShadowBridge(m_m2a_binding_6e698bd4a3,k);} bool LiveExitServices::LT4SetQueueState(std::uint64_t id,bool q,std::uint64_t p,std::uint64_t n){return M2A_LT4_SetQueueStateBridge(m_m2a_binding_6e698bd4a3,id,q,p,n);}
bool LiveExitServices::LT4MarkNativeSent(std::uint64_t id,std::uint64_t n,std::uint64_t t,std::uint64_t& s){return M2A_LT4_MarkNativeSentBridge(m_m2a_binding_6e698bd4a3,id,n,t,s);} std::vector<std::uint64_t> LiveExitServices::LT4MarkShadowSent(std::uint64_t id){return M2A_LT4_MarkShadowSentBridge(m_m2a_binding_6e698bd4a3,id);} bool LiveExitServices::LT4MarkShadowAck(std::uint64_t id,std::uint8_t l,std::uint64_t n){return M2A_LT4_MarkShadowAckBridge(m_m2a_binding_6e698bd4a3,id,l,n);} bool LiveExitServices::LT4MarkShadowVerified(std::uint64_t id){return M2A_LT4_MarkShadowVerifiedBridge(m_m2a_binding_6e698bd4a3,id);} bool LiveExitServices::LT4MarkNativeResult(std::uint64_t id,kad6::K6StoreStatus s,std::uint8_t l,std::uint64_t e,std::uint64_t n,bool& o){return M2A_LT4_MarkNativeResultBridge(m_m2a_binding_6e698bd4a3,id,s,l,e,n,o);}
std::vector<LiveTunnelPublishRuntime> LiveExitServices::LT4TakeNativeRefreshes(std::uint64_t n){return M2A_LT4_TakeNativeRefreshesBridge(m_m2a_binding_6e698bd4a3,n);} bool LiveExitServices::LT4CompleteNativeRefresh(std::uint64_t id,bool s,std::uint64_t n){return M2A_LT4_CompleteNativeRefreshBridge(m_m2a_binding_6e698bd4a3,id,s,n);} bool LiveExitServices::LT4TakeShadow(std::uint64_t id,LiveTunnelPublishRuntime& r){return M2A_LT4_TakeShadowBridge(m_m2a_binding_6e698bd4a3,id,r);} bool LiveExitServices::LT4CompleteShadow(std::uint64_t id,bool s,std::uint64_t n){return M2A_LT4_CompleteShadowBridge(m_m2a_binding_6e698bd4a3,id,s,n);}
std::vector<LiveTunnelPublishRuntime> LiveExitServices::LT4TakeVisibilityProbes(std::uint64_t n,bool& o){return M2A_LT4_TakeVisibilityProbesBridge(m_m2a_binding_6e698bd4a3,n,o);} bool LiveExitServices::LT4CompleteVisibilityProbe(std::uint64_t id,bool s,std::uint64_t n){return M2A_LT4_CompleteVisibilityProbeBridge(m_m2a_binding_6e698bd4a3,id,s,n);} std::vector<LiveTunnelPublishAction> LiveExitServices::LT4Sweep(std::uint64_t n){return M2A_LT4_SweepBridge(m_m2a_binding_6e698bd4a3,n);} void LiveExitServices::LT4ResetPublishes(){M2A_LT4_ResetPublishesBridge(m_m2a_binding_6e698bd4a3);}
void LiveExitServices::LT4PruneTicketState(std::uint64_t n){M2A_LT4_PruneTicketStateBridge(m_m2a_binding_6e698bd4a3,n);}

void LiveExitServices::RegisterHandler(
    std::uint8_t subCommand,
    LiveTunnelOpHandler handler)
{
    m_m2a_binding_6e698bd4a3=M2A_BIND_LT4_6E698BD4A3(M2AParentPort{this});
    m_handlers[subCommand] = std::move(handler);
}

bool LiveExitServices::Dispatch(
    std::uint8_t subCommand,
    const LiveTunnelRequestCtx& context) const
{
    const auto handler = m_handlers.find(subCommand);
    if (handler == m_handlers.end() || !handler->second)
        return false;
    handler->second(context);
    return true;
}

bool LiveExitServices::Begin(
    const std::shared_ptr<CLiveCircuit>& circuit,
    std::uint32_t requestId,
    std::uint8_t replyOp,
    std::uint32_t startedTick)
{
    if (!circuit || circuit->Id() == 0 || requestId == 0)
        return false;

    Operation operation;
    operation.circuit = circuit;
    operation.circuit_id = circuit->Id();
    operation.request_id = requestId;
    operation.reply_op = replyOp;
    operation.started_tick = startedTick;

    return m_operations.emplace(
        LiveRequestKey(operation.circuit_id, requestId),
        std::move(operation)).second;
}

bool LiveExitServices::TakeCompletion(
    std::uint32_t circuitId,
    std::uint32_t requestId,
    Completion& completion)
{
    completion = Completion{};
    const auto operation =
        m_operations.find(LiveRequestKey(circuitId, requestId));
    if (operation == m_operations.end())
        return false;

    completion.circuit = operation->second.circuit.lock();
    completion.reply_op = operation->second.reply_op;
    m_operations.erase(operation);
    if (!completion.circuit) {
        completion = Completion{};
        return false;
    }
    return true;
}

bool LiveExitServices::FindPart(
    std::uint32_t circuitId,
    std::uint32_t requestId,
    Completion& completion) const
{
    completion = Completion{};
    const auto operation =
        m_operations.find(LiveRequestKey(circuitId, requestId));
    if (operation == m_operations.end())
        return false;

    completion.circuit = operation->second.circuit.lock();
    completion.reply_op = operation->second.reply_op;
    if (!completion.circuit) {
        completion = Completion{};
        return false;
    }
    return true;
}

bool LiveExitServices::Abort(
    std::uint32_t circuitId,
    std::uint32_t requestId)
{
    return m_operations.erase(LiveRequestKey(circuitId, requestId)) != 0;
}

std::size_t LiveExitServices::AbortCircuit(std::uint32_t circuitId)
{
    std::size_t removed = 0;
    for (auto operation = m_operations.begin();
         operation != m_operations.end();) {
        if (operation->second.circuit_id == circuitId) {
            operation = m_operations.erase(operation);
            ++removed;
        } else {
            ++operation;
        }
    }
    return removed;
}

std::size_t LiveExitServices::Clear()
{
    const std::size_t removed = m_operations.size();
    m_operations.clear();
    return removed;
}

std::size_t LiveExitServices::HandlerCount() const noexcept
{
    return m_handlers.size();
}

bool LiveExitServices::HasOperation(
    std::uint32_t circuitId,
    std::uint32_t requestId) const
{
    return m_operations.find(
        LiveRequestKey(circuitId, requestId)) != m_operations.end();
}

std::size_t LiveExitServices::Sweep(
    std::uint32_t now,
    std::uint32_t ttl)
{
    std::size_t removed = 0;
    for (auto operation = m_operations.begin();
         operation != m_operations.end();) {
        const bool expired =
            static_cast<std::uint32_t>(
                now - operation->second.started_tick) > ttl;
        if (expired || operation->second.circuit.expired()) {
            operation = m_operations.erase(operation);
            ++removed;
        } else {
            ++operation;
        }
    }
    return removed;
}

namespace {

bool Check(bool condition)
{
    return condition;
}

} // namespace

bool RunLiveExitServicesCharacterizationSelfTest()
{
    // Handler lookup is fail closed. Unknown and null handlers do not run;
    // replacement is deterministic and last-registration-wins.
    LiveExitServices services;
    LiveTunnelRequestCtx context;
    int calls = 0;
    if (!Check(!services.Dispatch(0x01, context)))
        return false;
    services.RegisterHandler(0x01, LiveTunnelOpHandler{});
    if (!Check(!services.Dispatch(0x01, context)))
        return false;
    if (!Check(services.HandlerCount() == 1))
        return false;
    services.RegisterHandler(
        0x01,
        [&calls](const LiveTunnelRequestCtx&) { calls += 1; });
    if (!Check(services.Dispatch(0x01, context) && calls == 1))
        return false;
    services.RegisterHandler(
        0x01,
        [&calls](const LiveTunnelRequestCtx&) { calls += 10; });
    if (!Check(services.Dispatch(0x01, context) && calls == 11))
        return false;

    // Invalid identities are never admitted. This prevents a null circuit or
    // zero request from becoming an unaddressable deferred operation.
    if (!Check(!services.Begin(
            std::shared_ptr<CLiveCircuit>(), 7, 0x42, 100)))
        return false;
    const auto circuit = std::make_shared<CLiveCircuit>(17);
    if (!Check(!services.Begin(circuit, 0, 0x42, 100)))
        return false;

    // Replaying a live pair is rejected and cannot change its reply opcode.
    if (!Check(services.Begin(circuit, 7, 0x42, 100)))
        return false;
    if (!Check(!services.Begin(circuit, 7, 0x43, 101)))
        return false;
    if (!Check(services.PendingCount() == 1))
        return false;
    if (!Check(services.HasOperation(17, 7)))
        return false;
    if (!Check(!services.HasOperation(18, 7)))
        return false;

    // A partial response observes without consuming. Completion consumes
    // before any caller-owned send and is therefore exactly-once.
    LiveExitServices::Completion completion;
    if (!Check(services.FindPart(17, 7, completion)))
        return false;
    if (!Check(completion.circuit == circuit &&
               completion.reply_op == 0x42 &&
               services.PendingCount() == 1))
        return false;
    if (!Check(services.TakeCompletion(17, 7, completion)))
        return false;
    if (!Check(completion.circuit == circuit &&
               completion.reply_op == 0x42 &&
               services.PendingCount() == 0))
        return false;
    if (!Check(!services.TakeCompletion(17, 7, completion)))
        return false;
    if (!Check(!services.HasOperation(17, 7)))
        return false;

    // Abort is idempotent and scoped by the complete 64-bit key.
    if (!Check(services.Begin(circuit, 8, 0x44, 200)))
        return false;
    if (!Check(!services.Abort(18, 8)))
        return false;
    if (!Check(services.Abort(17, 8)))
        return false;
    if (!Check(!services.Abort(17, 8)))
        return false;

    // The complete correlation key isolates equal request ids on different
    // circuits. Circuit teardown removes only the matching ownership domain.
    const auto secondCircuit = std::make_shared<CLiveCircuit>(18);
    if (!Check(services.Begin(circuit, 11, 0x47, 250)))
        return false;
    if (!Check(services.Begin(secondCircuit, 11, 0x48, 250)))
        return false;
    if (!Check(services.AbortCircuit(17) == 1))
        return false;
    if (!Check(!services.FindPart(17, 11, completion)))
        return false;
    if (!Check(services.FindPart(18, 11, completion)))
        return false;
    if (!Check(completion.circuit == secondCircuit &&
               completion.reply_op == 0x48))
        return false;
    if (!Check(services.AbortCircuit(17) == 0))
        return false;
    if (!Check(services.AbortCircuit(18) == 1))
        return false;

    // A rejected replay cannot refresh the original deadline. This closes the
    // simplest resource-retention attack: repeatedly resending one live key.
    if (!Check(services.Begin(circuit, 14, 0x4b, 100)))
        return false;
    if (!Check(!services.Begin(circuit, 14, 0x4c, 1000)))
        return false;
    if (!Check(services.Sweep(200, 100) == 0))
        return false;
    if (!Check(services.Sweep(201, 100) == 1))
        return false;

    // Sweep keeps live entries inside the TTL, removes strictly older ones,
    // and handles unsigned wraparound exactly like GetTickCount arithmetic.
    if (!Check(services.Begin(circuit, 9, 0x45, 0xfffffff0u)))
        return false;
    if (!Check(services.Sweep(0x00000010u, 0x40u) == 0))
        return false;
    if (!Check(services.Sweep(0x00000040u, 0x40u) == 1))
        return false;

    // Expired weak ownership is removed even before its time deadline.
    {
        const auto temporary = std::make_shared<CLiveCircuit>(19);
        if (!Check(services.Begin(temporary, 10, 0x46, 500)))
            return false;
    }
    if (!Check(services.Sweep(501, 1000) == 1))
        return false;

    // Shutdown clears operations without mutating the constructor-owned
    // handler registry. A restarted subsystem can dispatch immediately.
    if (!Check(services.Begin(circuit, 12, 0x49, 600)))
        return false;
    if (!Check(services.Begin(secondCircuit, 13, 0x4a, 600)))
        return false;
    if (!Check(services.Clear() == 2 && services.PendingCount() == 0))
        return false;
    if (!Check(services.Clear() == 0))
        return false;
    if (!Check(services.Dispatch(0x01, context) && calls == 21))
        return false;
    if (!Check(services.HandlerCount() == 1))
        return false;

    return Check(services.PendingCount() == 0) &&
        RunLiveTunnelSourcePublisherCharacterizationSelfTest();
}

} // namespace eSELive
