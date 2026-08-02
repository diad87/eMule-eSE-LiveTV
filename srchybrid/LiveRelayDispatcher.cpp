// this file is part of eMule eSE - validated relay sub-protocol dispatch
#include "stdafx.h"
#include "LiveRelayDispatcher.h"

#include "LiveCircuit.h"

namespace eSELive {
M2AModuleHandle M2A_BIND_LT8_17641C1557(const M2AParentPort&);
bool M2A_LT8_AddJobBridge(M2AModuleHandle&,std::uint64_t,const LiveTunnelSearchJob&);
bool M2A_LT8_UpdateJobBridge(M2AModuleHandle&,std::uint64_t,const LiveTunnelSearchJob&);
bool M2A_LT8_FindJobBridge(const M2AModuleHandle&,std::uint64_t,LiveTunnelSearchJob&);
bool M2A_LT8_TakeJobBridge(M2AModuleHandle&,std::uint64_t,LiveTunnelSearchJob&);
std::vector<LiveTunnelSearchJob> M2A_LT8_TakeDueBridge(M2AModuleHandle&,DWORD);
bool M2A_LT8_AppendReplyBridge(M2AModuleHandle&,std::uint64_t,const std::vector<std::uint8_t>&,std::uint16_t,std::size_t,DWORD);
bool M2A_LT8_TakeReplyBridge(M2AModuleHandle&,std::uint64_t,std::vector<std::uint8_t>&,std::uint16_t&);
std::size_t M2A_LT8_SweepRepliesBridge(M2AModuleHandle&,DWORD,DWORD);
std::size_t M2A_LT8_JobCountBridge(const M2AModuleHandle&) noexcept;
LiveRelayDispatcher::LiveRelayDispatcher():m_m2a_binding_17641c1557(M2AAssignmentPolicy::RetainExisting){m_m2a_binding_17641c1557=M2A_BIND_LT8_17641C1557(M2AParentPort{this});}
bool LiveRelayDispatcher::LT8AddJob(std::uint64_t k,const LiveTunnelSearchJob& v){return M2A_LT8_AddJobBridge(m_m2a_binding_17641c1557,k,v);}
bool LiveRelayDispatcher::LT8UpdateJob(std::uint64_t k,const LiveTunnelSearchJob& v){return M2A_LT8_UpdateJobBridge(m_m2a_binding_17641c1557,k,v);}
bool LiveRelayDispatcher::LT8FindJob(std::uint64_t k,LiveTunnelSearchJob& v)const{return M2A_LT8_FindJobBridge(m_m2a_binding_17641c1557,k,v);}
bool LiveRelayDispatcher::LT8TakeJob(std::uint64_t k,LiveTunnelSearchJob& v){return M2A_LT8_TakeJobBridge(m_m2a_binding_17641c1557,k,v);}
std::vector<LiveTunnelSearchJob> LiveRelayDispatcher::LT8TakeDue(DWORD n){return M2A_LT8_TakeDueBridge(m_m2a_binding_17641c1557,n);}
bool LiveRelayDispatcher::LT8AppendReply(std::uint64_t k,const std::vector<std::uint8_t>& v,std::uint16_t r,std::size_t b,DWORD n){return M2A_LT8_AppendReplyBridge(m_m2a_binding_17641c1557,k,v,r,b,n);}
bool LiveRelayDispatcher::LT8TakeReply(std::uint64_t k,std::vector<std::uint8_t>& v,std::uint16_t& c){return M2A_LT8_TakeReplyBridge(m_m2a_binding_17641c1557,k,v,c);}
std::size_t LiveRelayDispatcher::LT8SweepReplies(DWORD n,DWORD t){return M2A_LT8_SweepRepliesBridge(m_m2a_binding_17641c1557,n,t);}
std::size_t LiveRelayDispatcher::LT8JobCount()const noexcept{return M2A_LT8_JobCountBridge(m_m2a_binding_17641c1557);}

bool LiveRelayDispatcher::DispatchExitPlain(
    const std::shared_ptr<CLiveCircuit>& circuit,
    const std::uint8_t* plain,
    std::size_t plainLength,
    ILiveRelayDispatcherPort& port)
{
    if (!circuit || !plain)
        return false;

    std::uint8_t subCommand = 0;
    std::uint32_t requestId = 0;
    std::uint16_t bodyLength = 0;
    const std::uint8_t* body = nullptr;
    if (!port.ParseRelaySubHeader(
            plain,
            plainLength,
            subCommand,
            requestId,
            bodyLength,
            body)) {
        return false;
    }

    LiveTunnelRequestCtx context;
    context.circ = circuit;
    context.sub_cmd = subCommand;
    context.req_id = requestId;

    if (!port.IsRelayMultiCell(subCommand)) {
        context.body = body;
        context.bodyLen = bodyLength;
        // Unknown and unavailable services intentionally produce no reply.
        // The validated cell was nevertheless consumed successfully.
        (void)port.DispatchRelayExit(context);
        return true;
    }

    std::uint16_t fragmentIndex = 0;
    std::uint16_t fragmentCount = 0;
    std::uint32_t messageLength = 0;
    const std::uint8_t* fragmentData = nullptr;
    std::size_t fragmentDataLength = 0;
    if (!port.ParseRelayFragmentHeader(
            body,
            bodyLength,
            fragmentIndex,
            fragmentCount,
            messageLength,
            fragmentData,
            fragmentDataLength)) {
        return false;
    }

    std::vector<std::uint8_t> message;
    const LiveRelayFragmentResult result = port.IngestRelayFragment(
        circuit->Id(),
        requestId,
        fragmentIndex,
        fragmentCount,
        messageLength,
        fragmentData,
        fragmentDataLength,
        message);
    if (result != LiveRelayFragmentResult::Complete)
        return true;

    context.body = message.data();
    context.bodyLen = message.size();
    (void)port.DispatchRelayExit(context);
    return true;
}

namespace {

class RelayDispatcherTestPort final : public ILiveRelayDispatcherPort {
public:
    bool allowSubHeader = true;
    bool allowFragmentHeader = true;
    LiveRelayFragmentResult fragmentResult =
        LiveRelayFragmentResult::Complete;
    bool handlerAvailable = true;
    std::size_t subHeaderCalls = 0;
    std::size_t fragmentHeaderCalls = 0;
    std::size_t ingestCalls = 0;
    std::size_t dispatchCalls = 0;
    std::uint8_t observedSubCommand = 0;
    std::uint32_t observedRequestId = 0;
    std::vector<std::uint8_t> observedBody;

    bool IsRelayMultiCell(std::uint8_t subCommand) const override
    {
        return subCommand >= 0x40;
    }

    bool ParseRelaySubHeader(
        const std::uint8_t* plain,
        std::size_t plainLength,
        std::uint8_t& subCommand,
        std::uint32_t& requestId,
        std::uint16_t& bodyLength,
        const std::uint8_t*& body) const override
    {
        RelayDispatcherTestPort* self =
            const_cast<RelayDispatcherTestPort*>(this);
        ++self->subHeaderCalls;
        if (!allowSubHeader || !plain || plainLength < 2)
            return false;
        subCommand = plain[0];
        requestId = plain[1];
        bodyLength = static_cast<std::uint16_t>(plainLength - 2);
        body = plain + 2;
        return true;
    }

    bool ParseRelayFragmentHeader(
        const std::uint8_t* body,
        std::size_t bodyLength,
        std::uint16_t& fragmentIndex,
        std::uint16_t& fragmentCount,
        std::uint32_t& messageLength,
        const std::uint8_t*& fragmentData,
        std::size_t& fragmentDataLength) const override
    {
        RelayDispatcherTestPort* self =
            const_cast<RelayDispatcherTestPort*>(this);
        ++self->fragmentHeaderCalls;
        if (!allowFragmentHeader || !body || bodyLength == 0)
            return false;
        fragmentIndex = 0;
        fragmentCount = 1;
        messageLength = static_cast<std::uint32_t>(bodyLength);
        fragmentData = body;
        fragmentDataLength = bodyLength;
        return true;
    }

    LiveRelayFragmentResult IngestRelayFragment(
        std::uint32_t circuitId,
        std::uint32_t requestId,
        std::uint16_t fragmentIndex,
        std::uint16_t fragmentCount,
        std::uint32_t messageLength,
        const std::uint8_t* fragmentData,
        std::size_t fragmentDataLength,
        std::vector<std::uint8_t>& completedMessage) override
    {
        ++ingestCalls;
        if (circuitId == 0 || requestId == 0 ||
            fragmentIndex != 0 || fragmentCount != 1 ||
            messageLength != fragmentDataLength ||
            (!fragmentData && fragmentDataLength != 0)) {
            return LiveRelayFragmentResult::Rejected;
        }
        if (fragmentResult == LiveRelayFragmentResult::Complete) {
            completedMessage.assign(
                fragmentData,
                fragmentData + fragmentDataLength);
        }
        return fragmentResult;
    }

    bool DispatchRelayExit(
        const LiveTunnelRequestCtx& context) override
    {
        ++dispatchCalls;
        observedSubCommand = context.sub_cmd;
        observedRequestId = context.req_id;
        observedBody.clear();
        if (context.bodyLen != 0) {
            observedBody.assign(
                context.body,
                context.body + context.bodyLen);
        }
        return handlerAvailable;
    }

    void ResetObservations()
    {
        subHeaderCalls = 0;
        fragmentHeaderCalls = 0;
        ingestCalls = 0;
        dispatchCalls = 0;
        observedSubCommand = 0;
        observedRequestId = 0;
        observedBody.clear();
    }
};

bool Check(bool condition)
{
    return condition;
}

} // namespace

bool RunLiveRelayDispatcherCharacterizationSelfTest()
{
    LiveRelayDispatcher dispatcher;
    RelayDispatcherTestPort port;
    const auto circuit = std::make_shared<CLiveCircuit>(23);

    // The dispatcher never asks a port to parse an absent circuit or buffer.
    const std::uint8_t legacy[] = {0x01, 0x07, 0xaa, 0xbb};
    if (!Check(!dispatcher.DispatchExitPlain(
            std::shared_ptr<CLiveCircuit>(),
            legacy,
            sizeof legacy,
            port))) {
        return false;
    }
    if (!Check(!dispatcher.DispatchExitPlain(
            circuit, nullptr, sizeof legacy, port))) {
        return false;
    }
    if (!Check(port.subHeaderCalls == 0))
        return false;

    // Subheader rejection is terminal: no fragment or handler boundary runs.
    port.allowSubHeader = false;
    if (!Check(!dispatcher.DispatchExitPlain(
            circuit, legacy, sizeof legacy, port))) {
        return false;
    }
    if (!Check(port.subHeaderCalls == 1 &&
               port.fragmentHeaderCalls == 0 &&
               port.ingestCalls == 0 &&
               port.dispatchCalls == 0)) {
        return false;
    }

    // A valid legacy cell is dispatched synchronously with an exact borrowed
    // body. A missing handler remains a silent accepted drop.
    port.allowSubHeader = true;
    port.ResetObservations();
    if (!Check(dispatcher.DispatchExitPlain(
            circuit, legacy, sizeof legacy, port))) {
        return false;
    }
    if (!Check(port.dispatchCalls == 1 &&
               port.observedSubCommand == 0x01 &&
               port.observedRequestId == 0x07 &&
               port.observedBody ==
                   std::vector<std::uint8_t>({0xaa, 0xbb}))) {
        return false;
    }
    port.handlerAvailable = false;
    if (!Check(dispatcher.DispatchExitPlain(
            circuit, legacy, sizeof legacy, port))) {
        return false;
    }

    const std::uint8_t fragmented[] = {0x40, 0x09, 0xcc, 0xdd};

    // Malformed fragment headers fail before state publication or dispatch.
    port.handlerAvailable = true;
    port.allowFragmentHeader = false;
    port.ResetObservations();
    if (!Check(!dispatcher.DispatchExitPlain(
            circuit, fragmented, sizeof fragmented, port))) {
        return false;
    }
    if (!Check(port.fragmentHeaderCalls == 1 &&
               port.ingestCalls == 0 &&
               port.dispatchCalls == 0)) {
        return false;
    }

    // Incomplete and rejected/duplicate sequences are consumed silently.
    // They cannot reach a handler with a partial or adversarial message.
    port.allowFragmentHeader = true;
    port.fragmentResult = LiveRelayFragmentResult::Incomplete;
    port.ResetObservations();
    if (!Check(dispatcher.DispatchExitPlain(
            circuit, fragmented, sizeof fragmented, port))) {
        return false;
    }
    if (!Check(port.ingestCalls == 1 && port.dispatchCalls == 0))
        return false;
    port.fragmentResult = LiveRelayFragmentResult::Rejected;
    port.ResetObservations();
    if (!Check(dispatcher.DispatchExitPlain(
            circuit, fragmented, sizeof fragmented, port))) {
        return false;
    }
    if (!Check(port.ingestCalls == 1 && port.dispatchCalls == 0))
        return false;

    // Only a complete logical message crosses the handler boundary.
    port.fragmentResult = LiveRelayFragmentResult::Complete;
    port.ResetObservations();
    if (!Check(dispatcher.DispatchExitPlain(
            circuit, fragmented, sizeof fragmented, port))) {
        return false;
    }
    if (!Check(port.subHeaderCalls == 1 &&
               port.fragmentHeaderCalls == 1 &&
               port.ingestCalls == 1 &&
               port.dispatchCalls == 1 &&
               port.observedSubCommand == 0x40 &&
               port.observedRequestId == 0x09 &&
               port.observedBody ==
                   std::vector<std::uint8_t>({0xcc, 0xdd}))) {
        return false;
    }

    return RunLiveTunnelSearchServiceCharacterizationSelfTest();
}

} // namespace eSELive
