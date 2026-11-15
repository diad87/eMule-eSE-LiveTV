#pragma once
#include "reach/direct_session.h"
#include <algorithm>
#include <optional>
#include <limits>

namespace ese {
// Normalize an advertised descriptor endpoint for the quarantined handshake
// only. The host must independently enforce its public-address policy first.
// A descriptor's longer lease is not an authentication deadline or proof.
inline std::optional<reach::DirectSessionRoute> PrepareFreshTcpRecoveryRoute(
    const reach::DirectCandidate& candidate,std::uint32_t routeId,
    std::uint64_t topology,std::uint64_t now) noexcept {
    if(!routeId || !topology || now>(std::numeric_limits<std::uint64_t>::max)()-15000 ||
        !candidate.id || (candidate.kind!=reach::DirectKind::DirectV4 &&
            candidate.kind!=reach::DirectKind::VerifiedMapping) || candidate.family!=4 ||
        !candidate.port || !(candidate.transport_mask&reach::DirectTcp) ||
        candidate.evidence!=reach::DirectEvidence::Advertised || candidate.scope!=reach::DirectScope::Global ||
        candidate.interface_id || candidate.topology_generation!=topology || candidate.expires_monotonic_ms<=now ||
        std::any_of(candidate.address.begin()+4,candidate.address.end(),[](std::uint8_t byte) {return byte!=0;}))
        return std::nullopt;
    reach::DirectSessionRoute route{routeId,candidate,reach::DirectTcp,true};
    route.candidate.transport_mask=reach::DirectTcp;
    route.candidate.expires_monotonic_ms=(std::min)(candidate.expires_monotonic_ms,now+15000);
    return route;
}

// Local permission to negotiate with an already pinned identity. This is not
// return-path evidence or a cryptographic verifier. The host must check the
// signed QUIC identity, verified RSA pin, file identity and actual socket peer.
class TcpRecoveryAuthorization {
public:
    const std::optional<reach::DirectSessionRoute>& Route() const noexcept { return route_; }

    bool Issue(reach::DirectHandle handle,std::uint64_t lifetime,std::uint64_t epoch,
        const reach::DirectSessionRoute& route,std::uint64_t now) noexcept {
        const auto& c=route.candidate;
        if(route_ || !handle.generation || !lifetime || !epoch || epoch==(std::numeric_limits<std::uint64_t>::max)() ||
            !route.id || !route.recovery_authentication || route.transport!=reach::DirectTcp || !c.id || !c.port ||
            (c.kind!=reach::DirectKind::DirectV4 && c.kind!=reach::DirectKind::VerifiedMapping) ||
            c.family!=4 || c.transport_mask!=reach::DirectTcp ||
            c.evidence!=reach::DirectEvidence::Advertised || c.scope!=reach::DirectScope::Global || c.interface_id ||
            !c.topology_generation || c.expires_monotonic_ms<=now || c.expires_monotonic_ms-now>15000) return false;
        handle_=handle; lifetime_=lifetime; epoch_=epoch; route_=route; return true;
    }

    bool Claim(reach::DirectHandle handle,std::uint64_t lifetime,std::uint64_t topology,std::uint64_t epoch,
        const reach::DirectSessionRoute& route,std::uint64_t authenticationLifetime,std::uint64_t now) noexcept {
        if(authenticationLifetime_ || !authenticationLifetime || authenticationLifetime==lifetime ||
            !Matches(handle,lifetime,topology,now) || epoch!=epoch_ || !SameRoute(*route_,route)) return false;
        authenticationLifetime_=authenticationLifetime; return true;
    }

    bool Allows(reach::DirectHandle handle,std::uint64_t lifetime,std::uint64_t topology,std::uint64_t epoch,
        std::uint64_t authenticationLifetime,reach::DirectSessionState state,std::uint32_t winner,
        std::uint64_t now,bool adopting) const noexcept {
        if(!authenticationLifetime_ || authenticationLifetime!=authenticationLifetime_ ||
            !Matches(handle,lifetime,topology,now)) return false;
        if(adopting) return epoch==epoch_+1 && state==reach::DirectSessionState::Ready && winner==route_->id;
        return epoch==epoch_ && !winner && (state==reach::DirectSessionState::Connecting ||
            state==reach::DirectSessionState::Authenticating);
    }

private:
    bool Matches(reach::DirectHandle handle,std::uint64_t lifetime,std::uint64_t topology,std::uint64_t now) const noexcept {
        return route_ && handle.slot==handle_.slot && handle.generation==handle_.generation && lifetime==lifetime_ &&
            topology==route_->candidate.topology_generation && now<route_->candidate.expires_monotonic_ms;
    }
    static bool SameRoute(const reach::DirectSessionRoute& a,const reach::DirectSessionRoute& b) noexcept {
        const auto& x=a.candidate; const auto& y=b.candidate;
        return a.id==b.id && a.transport==b.transport && a.recovery_authentication==b.recovery_authentication &&
            x.id==y.id && x.kind==y.kind && x.family==y.family &&
            x.address==y.address && x.port==y.port && x.transport_mask==y.transport_mask && x.evidence==y.evidence &&
            x.scope==y.scope && x.interface_id==y.interface_id && x.topology_generation==y.topology_generation &&
            x.expires_monotonic_ms==y.expires_monotonic_ms && x.rtt_ms==y.rtt_ms;
    }
    reach::DirectHandle handle_;
    std::uint64_t lifetime_=0,epoch_=0,authenticationLifetime_=0;
    std::optional<reach::DirectSessionRoute> route_;
};

// PersistedSize is the key which has actually passed SecureIdent. A received
// public key alone is deliberately insufficient, even when its bytes match.
inline bool MatchesVerifiedTcpRecoveryKey(const std::uint8_t* expected,std::size_t expectedSize,
    const std::uint8_t* persisted,std::size_t persistedSize) noexcept {
    if(!expected || !persisted || !expectedSize || expectedSize>80 || expectedSize!=persistedSize) return false;
    for(std::size_t i=0;i<expectedSize;++i) if(expected[i]!=persisted[i]) return false;
    return true;
}
}
