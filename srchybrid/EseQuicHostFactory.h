#pragma once
#include "EseQuicHostLifecycle.h"
#include "EseNativeQuicRuntime.h"
#include "EseQuicUdpIngress.h"
#include "EseControlPendingRoutes.h"
#include "EseQuicUdpRouter.h"
#include "EseControlPacketBudget.h"
namespace ese {
class QuicSessionHost : public QuicHostLifecycle {
public:
    virtual bool ActivateControlService(const std::array<std::uint8_t,32>&,std::uint64_t,std::uint64_t) { return false; }
    virtual bool RegisterControlServiceSession(const std::array<std::uint8_t,32>&,const udp::Endpoint&,
        const control::Header&,std::uint64_t,std::uint64_t) { return false; }
    virtual bool ResolveControlServicePeer(const udp::Endpoint&,const control::Header&,std::uint64_t,
        std::array<std::uint8_t,32>& peer) const { peer={}; return false; }
    virtual void RetireControlService(std::uint64_t) {}
    virtual bool ExpectControlBootstrap(const std::array<std::uint8_t,32>&,
        const std::array<std::uint8_t,32>&,const udp::Endpoint&,std::uint64_t,std::uint64_t) { return false; }
    virtual bool ExpectControlReply(const control::Header&,std::uint8_t,const udp::Endpoint&,
        std::uint64_t,std::uint64_t) { return false; }
    virtual void RemoveControlReplies(std::uint64_t) {}
    virtual bool PopControlReply(QuicUdpRouter::PendingControl& out) { out={}; return false; }
    virtual QuicUdpSendResult SendControl(const udp::Endpoint&,reach::DirectByteView) { return {QuicUdpSendStatus::Invalid,0}; }
    virtual std::uint64_t Begin(NativeQuicConfig,QuicPeerConfig,reach::DirectHandle,
        const reach::DirectSessionRoute&) = 0;
    virtual QuicTransport* Find(std::uint64_t) const = 0;
    virtual bool Release(std::uint64_t) = 0;
};
// Default build returns null. Native build attaches but creates no sessions.
// Port/pool/queue/process budget must outlive result. A host restart must not
// renew the process budget. Stop/drain/poll/retire before destruction.
std::unique_ptr<QuicSessionHost> CreateQuicSessionHost(QuicSocketPort&,
    reach::DirectBufferPool&,reach::DirectEventQueue&,control::PacketBudget&);
}
