#pragma once
#include "EseQuicUdpRouter.h"
#include "EseNativeQuicRuntime.h"
#include "EseQuicHostLifecycle.h"
namespace ese {
// Single socket thread; pool, queue, port and inspector must outlive this owner.
// Explicit detach, terminal-event drain/Poll, and Release precede destruction.
class QuicSocketOwner final : public QuicUdpIngress, public QuicHostLifecycle {
public:
    QuicSocketOwner(QuicSocketPort&,const udp::Inspector&,reach::DirectBufferPool&,reach::DirectEventQueue&);
    ~QuicSocketOwner();
    bool Attach();
    bool Attached() const noexcept { return attached_; }
    QuicUdpSendResult SendControl(const udp::Endpoint&,reach::DirectByteView);
    bool Detach();
    void Stop() override { if(attached_) Detach(); else SocketReset(); }
    std::uint64_t Begin(NativeQuicConfig,QuicPeerConfig,reach::DirectHandle,
        const reach::DirectSessionRoute&,QuicIdentitySigner* labSigner=nullptr);
    QuicTransport* Find(std::uint64_t id) const { return router_.Find(id); }
    bool Release(std::uint64_t id);
    // Never discards a transport with an undelivered terminal event.
    std::size_t RetireClosed() override;
    bool Empty() const noexcept override;
    udp::Decision Classify(const udp::Endpoint& peer,reach::DirectByteView bytes,std::uint64_t now) const { return router_.Classify(peer,bytes,now); }
    bool Current(const udp::Decision& decision) const { return router_.Current(decision); }
    bool Receive(const udp::Endpoint& peer,reach::DirectByteView bytes) noexcept override { return router_.Receive(peer,bytes); }
    bool PopControl(QuicUdpRouter::PendingControl& out) noexcept { return router_.PopControl(out); }
    void RemoveControl(std::uint64_t owner) noexcept { router_.RemoveControl(owner); }
    void Poll(std::uint64_t now) override;
    void SocketReset() noexcept override;
private:
    struct Sink final : QuicDatagramSink {
        QuicSocketOwner& parent; std::uint64_t id;
        reach::DirectBufferPool txPool,rxPool;
        reach::DirectReason failure=reach::DirectReason::None;
        Sink(QuicSocketOwner& owner,std::uint64_t value) : parent(owner),id(value),
            txPool(owner.pool_,reach::kDirectSessionBufferLimit),rxPool(owner.pool_,reach::kDirectSessionBufferLimit) {}
        bool Send(const udp::Endpoint&,reach::DirectByteView) noexcept override;
        bool RegisterCid(const udp::Cid&) noexcept override;
        bool RemoveCid(const udp::Cid&) noexcept override;
        void RemoveCids() noexcept override;
    };
    QuicSocketPort& port_;
    reach::DirectBufferPool& pool_;
    reach::DirectEventQueue& events_;
    // Sinks declared before router, so native references remain valid at teardown.
    std::array<std::unique_ptr<Sink>,256> sinks_{};
    QuicUdpRouter router_;
    std::uint64_t nextId_=0;
    bool attached_=false;
};
}
