// this file is part of eMule eSE - exit handler and deferred-reply ownership
#include "stdafx.h"
#include "LiveExitServices.h"

#include "LiveCircuit.h"

#include <utility>

namespace eSELive {

void LiveExitServices::RegisterHandler(
    std::uint8_t subCommand,
    LiveTunnelOpHandler handler)
{
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

    return Check(services.PendingCount() == 0);
}

} // namespace eSELive
