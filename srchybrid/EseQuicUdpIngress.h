#pragma once
#include "EseUdpDemux.h"
#include "reach/direct_transport.h"
namespace ese {
enum class QuicUdpSendStatus { Sent, WouldBlock, Invalid, Closed, Failed };
struct QuicUdpSendResult {
    QuicUdpSendStatus status=QuicUdpSendStatus::Invalid;
    std::uint32_t socketError=0;
};
// Non-owning socket-thread ingress. The session owner must detach before dying.
// Receive only classifies and copies into bounded owned queues; never polls TLS
// or mutates legacy/uTP parsers. true means claimed (including a known packet
// dropped for backpressure/auth failure), false leaves legacy processing intact.
class QuicUdpIngress {
public:
    virtual ~QuicUdpIngress() = default;
    virtual bool Receive(const udp::Endpoint&,reach::DirectByteView) noexcept = 0;
    // Called separately from receive, on the owning socket/main thread.
    virtual void Poll(std::uint64_t nowMs) = 0;
    // Called before socket teardown/rebind; cancel sessions/expectations and
    // release socket references. The registration is removed before this call.
    virtual void SocketReset() noexcept = 0;
};
class QuicSocketPort {
public:
    virtual ~QuicSocketPort() = default;
    virtual bool AttachQuicIngress(QuicUdpIngress*) = 0;
    virtual bool DetachQuicIngress(QuicUdpIngress*) = 0;
    virtual QuicUdpSendResult SendQuicDatagram(QuicUdpIngress*,const udp::Endpoint&,
        const std::uint8_t*,std::size_t) = 0;
};
}
