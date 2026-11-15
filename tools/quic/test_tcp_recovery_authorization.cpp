#include "../../srchybrid/EseTcpRecoveryAuthorization.h"
#include <cstdio>
#include <cstdlib>

static unsigned checks=0;
static void Check(bool value) { ++checks; if(!value) { std::printf("FAIL %u\n",checks); std::exit(1); } }

int main() {
    using namespace reach;
    const DirectHandle handle{3,7};
    DirectSessionRoute route;
    route.id=5; route.transport=DirectTcp; route.recovery_authentication=true;
    route.candidate.id=2; route.candidate.kind=DirectKind::DirectV4; route.candidate.family=4;
    route.candidate.address[0]=8; route.candidate.address[1]=8; route.candidate.address[2]=8; route.candidate.address[3]=8;
    route.candidate.port=4662; route.candidate.transport_mask=DirectTcp;
    route.candidate.topology_generation=9; route.candidate.expires_monotonic_ms=15100;

    ese::TcpRecoveryAuthorization permission;
    Check(!permission.Claim(handle,40,9,1,route,41,101));
    Check(!permission.Allows(handle,40,9,2,41,DirectSessionState::Ready,5,102,true));
    Check(permission.Issue(handle,40,1,route,100));
    Check(permission.Route()->candidate.evidence==DirectEvidence::Advertised);
    Check(!permission.Issue(handle,40,1,route,100));
    Check(!permission.Claim({3,8},40,9,1,route,41,101));
    Check(!permission.Claim({4,7},40,9,1,route,41,101));
    Check(!permission.Claim(handle,42,9,1,route,41,101));
    Check(!permission.Claim(handle,40,10,1,route,41,101));
    Check(!permission.Claim(handle,40,9,2,route,41,101));
    Check(!permission.Claim(handle,40,9,1,route,0,101));
    Check(!permission.Claim(handle,40,9,1,route,40,101));
    auto changed=route; changed.candidate.port++;
    Check(!permission.Claim(handle,40,9,1,changed,41,101));
    changed=route; changed.candidate.address[0]++;
    Check(!permission.Claim(handle,40,9,1,changed,41,101));
    changed=route; changed.candidate.evidence=DirectEvidence::Observed;
    Check(!permission.Claim(handle,40,9,1,changed,41,101));
    changed=route; changed.candidate.expires_monotonic_ms++;
    Check(!permission.Claim(handle,40,9,1,changed,41,101));
    changed=route; changed.id++;
    Check(!permission.Claim(handle,40,9,1,changed,41,101));
    changed=route; changed.recovery_authentication=false;
    Check(!permission.Claim(handle,40,9,1,changed,41,101));
    Check(permission.Claim(handle,40,9,1,route,41,101));
    Check(!permission.Claim(handle,40,9,1,route,42,101)); // permission cannot migrate to another socket
    Check(permission.Allows(handle,40,9,1,41,DirectSessionState::Connecting,0,102,false));
    Check(permission.Allows(handle,40,9,1,41,DirectSessionState::Authenticating,0,103,false));
    Check(!permission.Allows(handle,40,9,1,41,DirectSessionState::Connecting,0,104,true));
    Check(!permission.Allows(handle,40,9,1,41,DirectSessionState::Ready,5,104,true));
    Check(!permission.Allows(handle,40,9,2,41,DirectSessionState::Authenticating,0,104,true));
    Check(permission.Allows(handle,40,9,2,41,DirectSessionState::Ready,5,105,true));
    Check(!permission.Allows(handle,40,9,2,41,DirectSessionState::Ready,6,105,true));
    Check(!permission.Allows(handle,40,9,2,42,DirectSessionState::Ready,5,105,true));
    Check(!permission.Allows({3,8},40,9,2,41,DirectSessionState::Ready,5,105,true));
    Check(!permission.Allows(handle,40,10,2,41,DirectSessionState::Ready,5,105,true));
    Check(!permission.Allows(handle,42,9,2,41,DirectSessionState::Ready,5,105,true));
    Check(!permission.Allows(handle,40,9,3,41,DirectSessionState::Ready,5,105,true));
    Check(!permission.Allows(handle,40,9,2,41,DirectSessionState::Cancelled,5,105,true));
    Check(!permission.Allows(handle,40,9,2,41,DirectSessionState::Transferring,5,105,true));
    Check(!permission.Allows(handle,40,9,2,41,DirectSessionState::Ready,5,15100,true));
    Check(!permission.Allows(handle,40,9,1,41,DirectSessionState::Authenticating,0,15100,false));

    // A signed descriptor calls its public endpoint a mapping, but still
    // carries only Advertised evidence. It may authenticate without acquiring
    // mapping proof or a transferable socket permission.
    auto mapped=route; mapped.candidate.kind=DirectKind::VerifiedMapping;
    auto advertised=mapped.candidate; advertised.transport_mask=DirectTcp|DirectQuic;
    advertised.expires_monotonic_ms=120100;
    const auto prepared=ese::PrepareFreshTcpRecoveryRoute(advertised,5,9,100);
    Check(prepared && prepared->candidate.expires_monotonic_ms==15100 &&
        prepared->candidate.transport_mask==DirectTcp && prepared->recovery_authentication);
    Check(advertised.expires_monotonic_ms==120100 && advertised.transport_mask==(DirectTcp|DirectQuic));
    advertised.expires_monotonic_ms=105;
    const auto shorterPrepared=ese::PrepareFreshTcpRecoveryRoute(advertised,5,9,100);
    Check(shorterPrepared && shorterPrepared->candidate.expires_monotonic_ms==105);
    Check(!ese::PrepareFreshTcpRecoveryRoute(advertised,5,9,105));
    Check(!ese::PrepareFreshTcpRecoveryRoute(advertised,5,9,(std::numeric_limits<std::uint64_t>::max)()-14999));
    ese::TcpRecoveryAuthorization mappedPermission;
    Check(mappedPermission.Issue(handle,40,1,mapped,100));
    Check(mappedPermission.Route()->candidate.kind==DirectKind::VerifiedMapping &&
        mappedPermission.Route()->candidate.evidence==DirectEvidence::Advertised);
    Check(!mappedPermission.Claim(handle,40,9,1,route,41,101));
    Check(mappedPermission.Claim(handle,40,9,1,mapped,41,101));
    Check(mappedPermission.Allows(handle,40,9,1,41,DirectSessionState::Authenticating,0,102,false));
    Check(!mappedPermission.Allows(handle,40,9,2,42,DirectSessionState::Ready,5,103,true));
    Check(mappedPermission.Allows(handle,40,9,2,41,DirectSessionState::Ready,5,104,true));
    Check(!mappedPermission.Allows(handle,40,9,2,41,DirectSessionState::Ready,5,15100,true));
    auto shorter=mapped; shorter.candidate.expires_monotonic_ms=105;
    ese::TcpRecoveryAuthorization shortPermission;
    Check(shortPermission.Issue(handle,40,1,shorter,100));
    Check(shortPermission.Claim(handle,40,9,1,shorter,41,101));
    Check(shortPermission.Allows(handle,40,9,2,41,DirectSessionState::Ready,5,104,true));
    Check(!shortPermission.Allows(handle,40,9,2,41,DirectSessionState::Ready,5,105,true));
    for(const auto kind:{DirectKind::DirectV6,DirectKind::Callback,DirectKind::Punch2,
        DirectKind::Punch3,DirectKind::Predicted,DirectKind::Birthday}) {
        auto invalid=mapped; invalid.candidate.kind=kind;
        ese::TcpRecoveryAuthorization rejected;
        Check(!rejected.Issue(handle,40,1,invalid,100) && !rejected.Route());
    }
    for(const auto proof:{DirectEvidence::Observed,DirectEvidence::Reserved,
        DirectEvidence::MappingVerified,DirectEvidence::InboundVerified}) {
        auto invalid=mapped; invalid.candidate.evidence=proof;
        ese::TcpRecoveryAuthorization rejected;
        Check(!rejected.Issue(handle,40,1,invalid,100) && !rejected.Route());
    }

    // Acquisition must not silently become a general route-policy exception.
    for(unsigned variant=0;variant<9;++variant) {
        auto invalid=mapped;
        if(variant==0) invalid.candidate.evidence=DirectEvidence::Observed;
        if(variant==1) invalid.transport=DirectUtp;
        if(variant==2) invalid.candidate.family=6;
        if(variant==3) invalid.candidate.scope=DirectScope::SameLan;
        if(variant==4) invalid.candidate.interface_id=19;
        if(variant==5) invalid.candidate.expires_monotonic_ms=15101;
        if(variant==6) invalid.candidate.expires_monotonic_ms=100;
        if(variant==7) invalid.candidate.transport_mask=DirectTcp|DirectQuic;
        if(variant==8) invalid.recovery_authentication=false;
        ese::TcpRecoveryAuthorization rejected;
        Check(!rejected.Issue(handle,40,1,invalid,100));
        Check(!rejected.Route());
    }
    ese::TcpRecoveryAuthorization overflow;
    Check(!overflow.Issue(handle,40,(std::numeric_limits<std::uint64_t>::max)(),route,100));

    std::uint8_t pin[80]{}; pin[0]=17;
    Check(!ese::MatchesVerifiedTcpRecoveryKey(pin,0,pin,0));
    Check(!ese::MatchesVerifiedTcpRecoveryKey(pin,80,pin,0)); // received key, no verified record
    Check(!ese::MatchesVerifiedTcpRecoveryKey(pin,81,pin,81));
    Check(!ese::MatchesVerifiedTcpRecoveryKey(nullptr,80,pin,80));
    Check(ese::MatchesVerifiedTcpRecoveryKey(pin,80,pin,80));
    std::uint8_t changedPin[80]{}; changedPin[0]=18;
    Check(!ese::MatchesVerifiedTcpRecoveryKey(pin,80,changedPin,80));
    std::printf("tcp recovery authorization: %u checks passed\n",checks);
}
