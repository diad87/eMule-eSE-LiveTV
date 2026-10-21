#pragma once
#include "EseQuicTransport.h"
namespace ese {
struct NativeQuicConfig { udp::Endpoint local; bool server=false; };
class QuicDatagramSink {
public:
    virtual ~QuicDatagramSink() = default;
    // false means WouldBlock; runtime retains exactly this packet for retry.
    virtual bool Send(const udp::Endpoint&,reach::DirectByteView) noexcept = 0;
    virtual bool RegisterCid(const udp::Cid&) noexcept = 0;
    virtual bool RemoveCid(const udp::Cid&) noexcept = 0;
    virtual void RemoveCids() noexcept = 0;
};
class QuicIdentitySigner {
public:
    virtual ~QuicIdentitySigner() = default;
    virtual bool Sign(const std::uint8_t*,std::size_t,std::uint8_t*) noexcept = 0;
};
// Null signer uses persistent NodeIdentitySign. An explicit signer is a seam
// for isolated identities in the lab; it must outlive the runtime.
// GnuTLS/ngtcp2 objects are owned here. The socket belongs only to the sink.
std::unique_ptr<QuicRuntime> CreateNativeQuicRuntime(const NativeQuicConfig&,
    QuicDatagramSink&,reach::DirectBufferPool&,QuicIdentitySigner* signer=nullptr);
}
