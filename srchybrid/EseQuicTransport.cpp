#include "EseQuicTransport.h"
#include <algorithm>
#include <cassert>
#include <limits>
namespace ese {
static reach::DirectReason DecodeCloseReason(std::uint16_t code) noexcept;
QuicTransport::QuicTransport(QuicPeerConfig config,std::unique_ptr<QuicRuntime> runtime,
    reach::DirectBufferPool& pool,reach::DirectEventQueue& events)
    : QuicTransport(config,std::move(runtime),pool,pool,events) {}
QuicTransport::QuicTransport(QuicPeerConfig config,std::unique_ptr<QuicRuntime> runtime,
    reach::DirectBufferPool& tx,reach::DirectBufferPool& rx,reach::DirectEventQueue& events)
    : config_(config),rxPool_(rx),txPool_(tx),runtime_(std::move(runtime)),buffers_(tx,rx),writer_(buffers_),events_(events) {}
QuicTransport::~QuicTransport() {
    Close(reach::DirectReason::PeerGone); FinishShutdown();
    assert(eventCount_==0 && "owner must drain terminal events before retiring adapter");
}
bool QuicTransport::Start(reach::DirectHandle handle,const reach::DirectSessionRoute& route) {
    if(started_ || closed_ || !runtime_ || handle.slot>=256 || !handle.generation || !route.id ||
        route.transport!=reach::DirectQuic || !(route.candidate.transport_mask&reach::DirectQuic) ||
        !config_.persistent || (!config_.hasPin && !HasExplicitFirstUsePolicy(config_)) ||
        (config_.hasPin && config_.allowFirstUse) || !config_.local.topologyGeneration ||
        route.candidate.topology_generation!=config_.local.topologyGeneration ||
        !route.candidate.port || (route.candidate.family!=4 && route.candidate.family!=6)) return false;
    std::array<std::uint8_t,binding::HelloSize> hello{};
    // First-use requires an explicit durable commit policy. Credit/DVL remain
    // unimplemented and cannot be advertised through this configuration.
    if(!binding::EncodeHello(config_.local,hello) || config_.local.caps!=1 ||
        (config_.hasPin && std::all_of(config_.pin.begin(),config_.pin.end(),[](std::uint8_t b){return b==0;})) ||
        std::all_of(config_.expectedNode.begin(),config_.expectedNode.end(),[](std::uint8_t b){return b==0;})) return false;
    startedMs_=runtime_->NowMs();
    if(route.candidate.expires_monotonic_ms<=startedMs_) return false;
    handle_=handle; route_=route; started_=true; inRuntime_=true;
    bool ok=false;
    try { ok=runtime_->Start(route_,*this); } catch(...) {}
    inRuntime_=false;
    if(!ok) Close(reach::DirectReason::DirectUnreachable);
    if(closed_) FinishShutdown();
    FlushEvents(); return ok && !closed_;
}
reach::DirectSendResult QuicTransport::Send(reach::DirectByteView bytes) {
    if(closed_ || closing_) return {reach::DirectIoStatus::Closed,0};
    if(bytes.size && !bytes.data) return {reach::DirectIoStatus::Invalid,0};
    if(!Ready()) return {reach::DirectIoStatus::WouldBlock,0};
    return buffers_.Send(bytes);
}
bool QuicTransport::AdoptWinner(reach::DirectHandle handle,std::uint32_t route,std::uint64_t epoch) {
    if(!started_ || adopted_ || inRuntime_ || !Ready() ||
        handle.slot!=handle_.slot || handle.generation!=handle_.generation || route!=route_.id ||
        config_.sessionEpoch==std::numeric_limits<std::uint64_t>::max() ||
        epoch!=config_.sessionEpoch+1) return false;
    config_.sessionEpoch=epoch; adopted_=true; return true;
}
bool QuicTransport::ReceiveDatagram(const udp::Endpoint& source,reach::DirectByteView bytes) {
    if(!started_ || closed_) return false;
    try { return runtime_->QueueDatagram(source,bytes); }
    catch(...) { Close(reach::DirectReason::ResourceLimit); return false; }
}
bool QuicTransport::ConsumeReceived(std::size_t bytes) {
    if(closed_ || bytes>(std::numeric_limits<std::uint64_t>::max)()-consumedData_ || !buffers_.ConsumeReceived(bytes)) return false;
    consumedData_+=bytes; return true;
}
bool QuicTransport::ReportUsefulBytes(std::uint64_t bytes) {
    return ReportUsefulBytes(bytes,bytes);
}
bool QuicTransport::ReportUsefulBytes(std::uint64_t bytes,std::uint64_t wireBytes) {
    if(!adopted_ || !Ready() || !bytes || !wireBytes || reportedUsefulWireBytes_>consumedData_ ||
        wireBytes>consumedData_-reportedUsefulWireBytes_ ||
        bytes>(std::numeric_limits<std::uint64_t>::max)()-reportedUsefulBytes_) return false;
    // At most one retained progress event: coalesce while the shared queue
    // applies backpressure, retaining space for the terminal event.
    for(std::size_t i=0;i<eventCount_;++i) {
        if(pendingEvents_[i].type==reach::DirectEventType::UsefulRange) {
            pendingEvents_[i].useful_bytes+=bytes; reportedUsefulBytes_+=bytes; reportedUsefulWireBytes_+=wireBytes;
            FlushEvents(); return true;
        }
    }
    if(eventCount_==pendingEvents_.size()) return false;
    Emit(reach::DirectEventType::UsefulRange,reach::DirectReason::None,bytes);
    reportedUsefulBytes_+=bytes; reportedUsefulWireBytes_+=wireBytes; return true;
}

bool QuicTransport::ReportVerifiedPart(reach::PartVerification proof) {
    if(proof!=reach::PartVerification::Verified || !adopted_ || !Ready() ||
        !reportedUsefulBytes_ || verifiedPartReported_ || eventCount_>=pendingEvents_.size()-1) return false;
    // Leave one retained slot for Closed, even when shared queue is full.
    Emit(reach::DirectEventType::VerifiedPart);
    verifiedPartReported_=true; return true;
}

void QuicTransport::SetReceiveBudget(std::size_t bytes) {
    if(closed_) return;
    const auto budget=(std::min)(bytes,reach::kDirectSessionBufferLimit);
    buffers_.SetReceiveBudget(budget);
    if(runtime_) {
        try { runtime_->SetReadBudget(budget); }
        catch(...) { Close(reach::DirectReason::ResourceLimit); }
    }
}
reach::DirectTransportSnapshot QuicTransport::Snapshot() const {
    auto out=buffers_.Snapshot(); out.started=started_; out.closed=closed_; return out;
}
void QuicTransport::Emit(reach::DirectEventType type,reach::DirectReason reason,std::uint64_t usefulBytes) {
    if(!started_) return;
    assert(eventCount_<pendingEvents_.size());
    if(eventCount_==pendingEvents_.size()) return;
    reach::DirectSessionEvent event; event.handle=handle_; event.route_id=route_.id;
    event.topology_generation=config_.local.topologyGeneration;
    event.session_epoch=config_.sessionEpoch; event.sequence=++sequence_; event.type=type; event.reason=reason;
    event.useful_bytes=usefulBytes;
    pendingEvents_[eventCount_++]=event; FlushEvents();
}
void QuicTransport::FlushEvents() {
    while(eventCount_) {
        if(events_.TryPush(pendingEvents_[0])!=reach::DirectEnqueueStatus::Accepted) break;
        for(std::size_t i=1;i<eventCount_;++i) pendingEvents_[i-1]=pendingEvents_[i];
        --eventCount_;
    }
}
void QuicTransport::Close(reach::DirectReason reason) {
    if(!closed_) { closed_=true; Emit(reach::DirectEventType::Closed,reason); }
    if(!inRuntime_) FinishShutdown();
}
bool QuicTransport::RequestClose(std::uint16_t code) {
    if(closed_ || !exchange_) return false;
    if(closing_) return DecodeCloseReason(code)==closeReason_ && exchange_->QueueClose(code);
    if(!Ready() || !exchange_->QueueClose(code)) return false;
    closeReason_=DecodeCloseReason(code);
    closeThrough_=controlSubmitted_+exchange_->Pending().size;
    closeStartedMs_=runtime_->NowMs(); closing_=true;
    SetReceiveBudget(0);
    return !closed_;
}
void QuicTransport::FinishShutdown() {
    if(!closed_ || shutdown_ || inRuntime_ || receivingControl_) return;
    if(runtime_) runtime_->Shutdown(); // library releases pointers before owned bytes
    shutdown_=true; exchange_.reset(); buffers_.Close();
}
void QuicTransport::CheckBinding() {
    if(!exchange_ || closed_) return;
    if(exchange_->Error()!=binding::Failure::None) {
        const auto reason=exchange_->Error()==binding::Failure::AuthTimeout ? reach::DirectReason::AuthTimeout :
            exchange_->Error()==binding::Failure::PinChanged ? reach::DirectReason::PinChanged : reach::DirectReason::IdentityMismatch;
        Emit(reach::DirectEventType::AuthenticationFailed,reason);
        Close(reason);
    } else if(exchange_->Ready() && !authenticated_) {
        if(config_.allowFirstUse) {
            const auto* session=exchange_->AuthenticatedSession();
            const auto committed=session && config_.trustCommitter ?
                config_.trustCommitter->Commit(*session,config_.expectedNode) : trust::CommitResult::PersistenceFailed;
            if(committed!=trust::CommitResult::Stored) {
                const auto reason=committed==trust::CommitResult::PinChanged ? reach::DirectReason::PinChanged : reach::DirectReason::ResourceLimit;
                Emit(reach::DirectEventType::AuthenticationFailed,reason);
                Close(reason); return;
            }
        }
        authenticated_=true; Emit(reach::DirectEventType::Authenticated);
    }
}
void QuicTransport::Poll(std::uint64_t now) {
    FlushEvents();
    if(!started_) return;
    if(!closed_) {
        if(closing_ && (now<closeStartedMs_ || now-closeStartedMs_>=1000)) Close(closeReason_);
        if(!exchange_ && now>=startedMs_ && now-startedMs_>=4000) Close(reach::DirectReason::Deadline);
        if(exchange_) { exchange_->Tick(now); CheckBinding(); }
    }
    if(!closed_) {
        inRuntime_=true;
        try { runtime_->Poll(now); } catch(...) { Close(reach::DirectReason::ResourceLimit); }
        inRuntime_=false;
    }
    if(closed_) FinishShutdown();
    FlushEvents();
}
bool QuicTransport::HandshakeComplete() {
    if(!started_ || closed_ || exchange_) return false;
    const auto now=runtime_->NowMs();
    if(now<startedMs_ || now-startedMs_>=4000) { Close(reach::DirectReason::Deadline); return false; }
    try {
        exchange_=std::make_unique<binding::ControlExchange>(config_.local,config_.expectedNode,
            config_.hasPin ? &config_.pin : nullptr,config_.persistent,true,now);
    } catch(...) { Close(reach::DirectReason::ResourceLimit); return false; }
    Emit(reach::DirectEventType::Connected); CheckBinding(); return !closed_;
}
reach::DirectByteView QuicTransport::Pending(std::int64_t stream) const {
    if(closed_) return {};
    if(stream==0 && exchange_) { const auto out=exchange_->Pending(); return {out.data,out.size}; }
    if(stream==4 && Ready()) return writer_.Pending();
    return {};
}
bool QuicTransport::Submitted(std::int64_t stream,std::size_t bytes) {
    if(closed_ || bytes>Pending(stream).size) return false;
    bool ok=false;
    if(stream==0 && exchange_) {
        ok=exchange_->SubmittedThrough(controlSubmitted_+bytes);
        if(ok) controlSubmitted_+=bytes;
        CheckBinding();
    } else if(stream==4 && Ready()) ok=writer_.Submitted(bytes);
    return ok;
}
bool QuicTransport::Acknowledged(std::int64_t stream,std::uint64_t offset,std::uint64_t bytes) {
    if(closed_) return false;
    if(stream==0) {
        if(offset>controlAcknowledged_ || offset>controlSubmitted_ || bytes>controlSubmitted_-offset) return false;
        controlAcknowledged_=(std::max)(controlAcknowledged_,offset+bytes);
        if(closing_ && controlAcknowledged_>=closeThrough_) Close(closeReason_);
        return true;
    }
    return stream==4 && (Ready() || closing_) && writer_.Acknowledged(offset,bytes);
}
reach::DirectSendResult QuicTransport::Received(std::int64_t stream,reach::DirectByteView bytes) {
    if(closed_) return {reach::DirectIoStatus::Closed,0};
    if(bytes.size && !bytes.data) return {reach::DirectIoStatus::Invalid,0};
    if(stream==4 && closing_) return {reach::DirectIoStatus::WouldBlock,0};
    if(stream==0 && exchange_) {
        bool ok=false;
        receivingControl_=true;
        try { ok=exchange_->Receive(runtime_->Crypto(),bytes.data,bytes.size,this); }
        catch(...) { Close(reach::DirectReason::ResourceLimit); }
        receivingControl_=false;
        CheckBinding();
        if(closed_) FinishShutdown();
        return {ok ? reach::DirectIoStatus::Accepted : reach::DirectIoStatus::Invalid,ok ? bytes.size : 0};
    }
    if(stream==4 && Ready()) return buffers_.Receive(bytes);
    Close(reach::DirectReason::IdentityMismatch); return {reach::DirectIoStatus::Invalid,0};
}
static reach::DirectReason DecodeCloseReason(std::uint16_t code) noexcept {
    auto reason=reach::DirectReason::UnsupportedRemote;
    switch(code) {
    case wire::kEseWireCloseNoCandidate: reason=reach::DirectReason::NoCandidate; break;
    case wire::kEseWireCloseNoRoute: reason=reach::DirectReason::NoRoute; break;
    case wire::kEseWireCloseDirectUnreachable: reason=reach::DirectReason::DirectUnreachable; break;
    case wire::kEseWireClosePeerIncompatible: reason=reach::DirectReason::PeerIncompatible; break;
    case wire::kEseWireCloseCapabilityMissing: reason=reach::DirectReason::CapabilityMissing; break;
    case wire::kEseWireCloseDeadline: reason=reach::DirectReason::Deadline; break;
    case wire::kEseWireCloseStaleTopology: reason=reach::DirectReason::StaleTopology; break;
    case wire::kEseWireCloseIdentityMismatch: reason=reach::DirectReason::IdentityMismatch; break;
    case wire::kEseWireClosePinChanged: reason=reach::DirectReason::PinChanged; break;
    case wire::kEseWireCloseAuthTimeout: reason=reach::DirectReason::AuthTimeout; break;
    case wire::kEseWireCloseUdpBlocked: reason=reach::DirectReason::UdpBlocked; break;
    case wire::kEseWireCloseQuicNoProgress: reason=reach::DirectReason::QuicNoProgress; break;
    case wire::kEseWireCloseMtuTooSmall: reason=reach::DirectReason::MtuTooSmall; break;
    case wire::kEseWireCloseResourceLimit: reason=reach::DirectReason::ResourceLimit; break;
    case wire::kEseWireCloseDisabled: reason=reach::DirectReason::Disabled; break;
    case wire::kEseWireClosePeerGone: reason=reach::DirectReason::PeerGone; break;
    case wire::kEseWireCloseBootstrapRequired: reason=reach::DirectReason::BootstrapRequired; break;
    case wire::kEseWireCloseDiscoveryUnavailable: reason=reach::DirectReason::DiscoveryUnavailable; break;
    case wire::kEseWireCloseStaleDescriptor: reason=reach::DirectReason::StaleDescriptor; break;
    case wire::kEseWireCloseRendezvousUnavailable: reason=reach::DirectReason::RendezvousUnavailable; break;
    case wire::kEseWireCloseLegacyCallbackUnavailable: reason=reach::DirectReason::LegacyCallbackUnavailable; break;
    default: break; // Unknown codes (including zero) are never success.
    }
    return reason;
}
bool QuicTransport::Frame(std::uint8_t type,const std::uint8_t* payload,std::size_t size) noexcept {
    if(type!=wire::kEseWireControlClose || size!=2 || !payload) return false;
    const auto code=static_cast<std::uint16_t>((static_cast<unsigned>(payload[0])<<8)|payload[1]);
    // Emit only; do not destroy the exchange while its Receive is on the stack.
    try { Close(DecodeCloseReason(code)); return true; }
    catch(...) { return false; }
}
}
