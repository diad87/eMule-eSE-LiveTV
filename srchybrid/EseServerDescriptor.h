#pragma once
#include "EseServerAuth.h"
#include <string>

namespace ese::server {
enum class DescriptorTrust { Pkix, Pin, Tofu };
struct ServerDescriptor {
    Bytes32 serverId{}, node{}, spkiSha256{};
    std::string host;
    std::uint16_t tlsPort=0,quicPort=0,rdvUdpPort=0;
    DescriptorTrust trust=DescriptorTrust::Pkix;
    bool allowPlaintextFallback=false;
};

// The input is a trusted local configuration/import, with one exact key=value
// per line. Parsing performs no network access, dial or trust-store mutation.
bool ParseServerDescriptor(std::string_view,AuthCrypto& hash,ServerDescriptor&);

enum class Transport { Quic, Tls, Classic };
enum class DialOutcome { NetworkUnavailable, Timeout, AppStalled, TrustFailed, ProtocolFailed, UserCancelled };
struct TransportOptions {
    bool quic=false,tls=false;
    std::uint16_t explicitlyConfiguredClassicPort=0;
};
struct TransportChoice { Transport transport; std::uint16_t port; };

// A failure in authentication or protocol processing terminates selection
// even when the descriptor explicitly allows a classic fallback.
class TransportPlan {
public:
    TransportPlan(const ServerDescriptor&,const TransportOptions&) noexcept;
    std::optional<TransportChoice> Current() const noexcept;
    void Advance(DialOutcome) noexcept;
private:
    std::array<TransportChoice,3> choices_{};
    std::size_t count_=0,current_=0;
};
}
