#pragma once
#include "EseChannelBinding.h"
#include "EsePeerTrust.h"
#include "reach/direct_transport.h"
#include "reach/direct_event_queue.h"
#include "reach/part_verification.h"
#include "EseUdpDemux.h"
#include <memory>
namespace ese {
class QuicIo {
public:
    virtual ~QuicIo() = default;
    virtual bool HandshakeComplete() = 0;
    virtual reach::DirectByteView Pending(std::int64_t stream) const = 0;
    virtual bool Submitted(std::int64_t stream,std::size_t bytes) = 0;
    virtual bool Acknowledged(std::int64_t stream,std::uint64_t offset,std::uint64_t bytes) = 0;
    virtual reach::DirectSendResult Received(std::int64_t stream,reach::DirectByteView bytes) = 0;
    virtual bool DataReady() const = 0;
    virtual std::uint64_t ConsumedData() const = 0;
    virtual std::uint8_t LocalRole() const = 0;
};
// Owned library adapter, operated on one thread. Callbacks only within Start or
// Poll. Shutdown must stop all callbacks/library references before returning.
// A WouldBlock receive must remain in owned, globally accounted runtime storage,
// never silently disappear. Socket/demux delivery belongs to the host adapter.
class QuicRuntime {
public:
    virtual ~QuicRuntime() = default;
    virtual std::uint64_t NowMs() const noexcept = 0;
    virtual binding::Crypto& Crypto() noexcept = 0;
    virtual bool Start(const reach::DirectSessionRoute&,QuicIo&) = 0;
    virtual void Poll(std::uint64_t nowMs) = 0;
    virtual void SetReadBudget(std::size_t bytes) = 0;
    virtual void Shutdown() noexcept = 0;
    virtual bool QueueDatagram(const udp::Endpoint&,reach::DirectByteView) { return false; }
};
struct QuicPeerConfig {
    binding::Hello local;
    std::array<std::uint8_t,32> expectedNode{},pin{};
    bool hasPin=false,persistent=false;
    // Explicit first-use mode only. No implicit descriptor-to-pin conversion.
    // Owned committer must publish trust before application readiness.
    bool allowFirstUse=false;
    std::shared_ptr<trust::Committer> trustCommitter;
    std::uint64_t sessionEpoch=0;
};
inline bool HasExplicitFirstUsePolicy(const QuicPeerConfig& peer) noexcept {
    return !peer.hasPin && peer.allowFirstUse && peer.trustCommitter &&
        std::all_of(peer.pin.begin(),peer.pin.end(),[](std::uint8_t b){return b==0;});
}
inline bool HasQuicPeerTrustPolicy(const QuicPeerConfig& peer) noexcept {
    return (peer.hasPin && !peer.allowFirstUse && peer.pin==peer.expectedNode &&
        std::any_of(peer.pin.begin(),peer.pin.end(),[](std::uint8_t b){return b!=0;})) ||
        HasExplicitFirstUsePolicy(peer);
}
// Implements the host-facing transport contract. The native runtime is owned,
// not a host socket pointer. No UI/MFC access; events carry DCO handles only.
class QuicTransport final : public reach::IDirectTransport, public QuicIo, public binding::ControlSink {
public:
    QuicTransport(QuicPeerConfig,std::unique_ptr<QuicRuntime>,reach::DirectBufferPool&,reach::DirectEventQueue&);
    QuicTransport(QuicPeerConfig,std::unique_ptr<QuicRuntime>,reach::DirectBufferPool& tx,
        reach::DirectBufferPool& rx,reach::DirectEventQueue&);
    reach::DirectBufferPool& RxPool() const { return rxPool_; }
    reach::DirectBufferPool& TxPool() const { return txPool_; }
    ~QuicTransport() override;
    bool Start(reach::DirectHandle,const reach::DirectSessionRoute&) override;
    reach::DirectSendResult Send(reach::DirectByteView) override;
    void SetReceiveBudget(std::size_t) override;
    void Close(reach::DirectReason) override;
    // Best-effort authenticated CLOSE. Owner must keep polling until Retirable.
    // Immediate Close remains available for faults, kill switches and shutdown.
    bool RequestClose(std::uint16_t wireReason);
    reach::DirectTransportSnapshot Snapshot() const override;
    void Poll(std::uint64_t nowMs);
    reach::DirectByteView ReceivedFront() const { return buffers_.ReceiveFront(); }
    bool ConsumeReceived(std::size_t bytes);
    // Application-accepted payload only; wire cost is bounded by consumed
    // stream bytes. Explicit logical/wire counts support compressed blocks.
    // Never implies a verified file part, hash success, or credit award.
    bool ReportUsefulBytes(std::uint64_t bytes);
    bool ReportUsefulBytes(std::uint64_t logicalBytes,std::uint64_t consumedWireBytes);
    // Only after the host correlates hash-job generation/file/part with this
    // session's accepted contribution. Corrupt/unknown results never emit.
    bool ReportVerifiedPart(reach::PartVerification);
    bool HasReportedVerifiedPart() const noexcept { return verifiedPartReported_; }
    bool Ready() const { return !closed_ && !closing_ && authenticated_ && exchange_ && exchange_->Ready(); }
    // Host calls only after consuming the DCO Attach action. Does not change
    // TLS/binding transcript; epoch is local callback/delivery correlation.
    bool AdoptWinner(reach::DirectHandle,std::uint32_t route,std::uint64_t epoch);
    bool AllowsDelivery(reach::DirectHandle handle,std::uint32_t route,std::uint64_t epoch) const {
        return adopted_ && Ready() && handle.slot==handle_.slot && handle.generation==handle_.generation &&
            route==route_.id && epoch==config_.sessionEpoch;
    }
    const binding::Hello* BoundPeer() const { return Ready() ? exchange_->BoundPeer() : nullptr; }
    // Owned route snapshot, not the HELLO-advertised address. Host must still
    // validate owner/handle/epoch before using it as the logical socket peer.
    const reach::DirectSessionRoute* BoundRoute() const { return adopted_ && Ready() ? &route_ : nullptr; }
    bool DataReady() const override { return Ready(); }
    std::uint64_t ConsumedData() const override { return consumedData_; }
    std::uint8_t LocalRole() const override { return config_.local.role; }
    bool ReceiveDatagram(const udp::Endpoint&,reach::DirectByteView);
    // The owner retains closed adapters and polls until queued events drain.
    bool Retirable() const { return closed_ && shutdown_ && eventCount_==0; }
    bool HandshakeComplete() override;
    reach::DirectByteView Pending(std::int64_t) const override;
    bool Submitted(std::int64_t,std::size_t) override;
    bool Acknowledged(std::int64_t,std::uint64_t,std::uint64_t) override;
    reach::DirectSendResult Received(std::int64_t,reach::DirectByteView) override;
    bool Frame(std::uint8_t,const std::uint8_t*,std::size_t) noexcept override;
private:
    void Emit(reach::DirectEventType,reach::DirectReason = reach::DirectReason::None,std::uint64_t usefulBytes=0);
    void FlushEvents();
    void FinishShutdown();
    void CheckBinding();
    QuicPeerConfig config_;
    reach::DirectBufferPool& rxPool_;
    reach::DirectBufferPool& txPool_;
    std::unique_ptr<QuicRuntime> runtime_;
    reach::DirectTransportBuffers buffers_;
    reach::DirectStreamWriter writer_;
    reach::DirectEventQueue& events_;
    std::unique_ptr<binding::ControlExchange> exchange_;
    reach::DirectHandle handle_{};
    reach::DirectSessionRoute route_{};
    std::array<reach::DirectSessionEvent,4> pendingEvents_{};
    std::size_t eventCount_=0,controlSubmitted_=0;
    std::uint64_t startedMs_=0,sequence_=0,consumedData_=0;
    std::uint64_t reportedUsefulBytes_=0;
    std::uint64_t reportedUsefulWireBytes_=0;
    std::uint64_t controlAcknowledged_=0,closeThrough_=0,closeStartedMs_=0;
    reach::DirectReason closeReason_=reach::DirectReason::None;
    bool closing_=false;
    bool verifiedPartReported_=false;
    bool started_=false,closed_=false,shutdown_=false,inRuntime_=false,receivingControl_=false,authenticated_=false,adopted_=false;
};
}
