// Integrated, network-free regression for the normal signed publication shape.
// Addresses and receipt times are fixtures: no reachability, mapping ownership,
// Kad return proof, SecureIdent wire exchange, or file transfer is claimed here.
#include "../../srchybrid/LiveCrypto.h"
#include "../../srchybrid/EseKad6PublicationDescriptor.h"
#include "../../srchybrid/EseKad6Resolution.h"
#include "../../srchybrid/EseTcpRecoveryAuthorization.h"
#include "../../cryptopp/misc.h"
#include <cstdio>
#include <cstdlib>
#include <limits>

using namespace ese;
using namespace reach;
namespace {
unsigned checks=0;
#define CHECK(condition) do { ++checks; if(!(condition)) { \
    std::printf("FAIL line %d: %s\n",__LINE__,#condition); std::exit(1); } } while(false)

constexpr std::uint64_t kFileSize=1024ull*1024*1024;
constexpr std::uint64_t kTopology=7,kReceived=1000,kLifetime=19,kAuthenticationLifetime=23;
constexpr DirectHandle kHandle{3,5};
const std::array<std::uint8_t,16> kFile{{0x29,0x38}};

struct Identity final : control::Signer {
    std::array<std::uint8_t,32> pub{},secret{};
    Identity() { CHECK(eSELive::GenerateBroadcasterKeypair(pub.data(),secret.data())); }
    ~Identity() { CryptoPP::SecureWipeBuffer(secret.data(),secret.size()); }
    bool Sign(const std::uint8_t* bytes,std::size_t size,std::array<std::uint8_t,64>& out) noexcept override {
        return eSELive::SignMessage(secret.data(),pub.data(),bytes,size,out.data());
    }
};

discovery::ResolvedKad6Candidate Publication(Identity& owner,std::uint32_t candidateTtl=120) {
    std::array<discovery::OwnedPublicationCandidate,2> candidates{};
    for(auto& candidate:candidates) {
        candidate.endpoint.address={{8,8,8,8}}; // signed fixture bytes, never contacted
        candidate.ttl=candidateTtl;
    }
    candidates[0].endpoint.port=4662; candidates[0].transports=DirectTcp;
    candidates[1].endpoint.port=4672; candidates[1].transports=DirectQuic;
    std::array<std::uint8_t,16> userHash{{0x41}},kadId{{0x52}};
    std::array<std::uint8_t,173> signedSource{};
    discovery::ResolvedKad6Candidate result;
    CHECK(discovery::BuildOwnedPublication(kFile,kFileSize,11,17,owner.pub,userHash,kadId,
        candidates,2,120,owner,result.descriptor,result.length,signedSource,kFileSize));
    CHECK(control::VerifyDirectSource(owner.pub,signedSource.data(),signedSource.size(),kFileSize,result.source));
    result.receivedMs=kReceived; result.until=kReceived+120000; result.localGeneration=kTopology;
    // Signed discovery records and local receipt metadata only. No witness or
    // observed endpoint is invented to authorize a live network connection.
    return result;
}

NativeDirectCandidateSnapshotV1 Snapshot(const discovery::ResolvedKad6Candidate& publication,
    std::uint64_t now=kReceived) {
    NativeDirectCandidateSnapshotV1 snapshot;
    CHECK(discovery::Kad6Resolution::NativeSnapshot(publication,kFile,kFileSize,kTopology,now,snapshot));
    CHECK(snapshot.count==2 && snapshot.local_generation==kTopology && snapshot.remote_generation==11);
    CHECK(snapshot.peer.expected_node_pub && *snapshot.peer.expected_node_pub==publication.source.node);
    CHECK(snapshot.peer.expected_user_hash && (*snapshot.peer.expected_user_hash)[0]==0x41);
    CHECK(snapshot.peer.trust==DirectIdentityTrust::Unknown && snapshot.peer.pin_version==0);
    for(std::size_t i=0;i<snapshot.count;++i) {
        const auto& entry=snapshot.candidates[i];
        CHECK(entry.source==DirectCandidateSource::KadSource && !entry.mapping_id);
        CHECK(entry.route.kind==DirectKind::VerifiedMapping && entry.route.evidence==DirectEvidence::Advertised);
        CHECK(entry.route.scope==DirectScope::Global && entry.route.interface_id==0);
    }
    return snapshot;
}

DirectSessionEvent Event(std::uint32_t route,std::uint64_t sequence,DirectEventType type,
    std::uint64_t epoch,std::uint64_t bytes=0) {
    return {kHandle,kTopology,route,sequence,epoch,type,bytes};
}

std::size_t Count(const std::vector<DirectSessionAction>& actions,DirectActionType type) {
    return static_cast<std::size_t>(std::count_if(actions.begin(),actions.end(),
        [type](const DirectSessionAction& action) { return action.type==type; }));
}

DirectSession EstablishedThenClosed(const NativeDirectCandidateSnapshotV1& snapshot) {
    DirectSession session(kHandle,kTopology,kReceived);
    const DirectSessionRoute quic{1,snapshot.candidates[1].route,DirectQuic,false};
    CHECK(Count(session.SetRoutes({quic},kReceived),DirectActionType::Start)==1);
    session.Advance(kReceived+1,{Event(1,1,DirectEventType::Connected,0)});
    CHECK(session.State()==DirectSessionState::Authenticating && !session.Winner());
    // These fixtures exercise the portable adapter event boundary. They do not
    // perform QUIC or RSA authentication themselves.
    session.Advance(kReceived+2,{Event(1,2,DirectEventType::Authenticated,0)});
    CHECK(session.State()==DirectSessionState::Ready && session.Epoch()==1);
    session.Advance(kReceived+3,{Event(1,3,DirectEventType::UsefulRange,1,4096)});
    session.Advance(kReceived+4,{Event(1,4,DirectEventType::VerifiedPart,1)});
    auto closed=Event(1,5,DirectEventType::Closed,1); closed.reason=DirectReason::QuicNoProgress;
    session.Advance(kReceived+5,{closed});
    CHECK(session.State()==DirectSessionState::Recovering && !session.Winner() && session.Epoch()==1);
    CHECK(session.UsefulBytes()==4096 && session.TransferVerified());
    return session;
}

void RejectAlteredPublications(const discovery::ResolvedKad6Candidate& good) {
    for(unsigned variant=0;variant<9;++variant) {
        auto bad=good;
        switch(variant) {
        case 0:bad.descriptor[discovery::DescriptorHeader+4]^=1;break;
        case 1:bad.descriptor[bad.length-1]^=1;break;
        case 2:bad.source.file[0]^=1;break;
        case 3:bad.source.fileSize+=1;break;
        case 4:bad.source.serial+=1;break;
        case 5:bad.source.node[0]^=1;break;
        case 6:bad.localGeneration+=1;break;
        case 7:bad.until=kReceived;break;
        case 8:bad.receivedMs=kReceived+1;break;
        }
        NativeDirectCandidateSnapshotV1 rejected;
        CHECK(!discovery::Kad6Resolution::NativeSnapshot(bad,kFile,kFileSize,kTopology,kReceived,rejected));
        CHECK(rejected.count==0 && !rejected.peer.expected_node_pub);
    }
    NativeDirectCandidateSnapshotV1 rejected;
    CHECK(!discovery::Kad6Resolution::NativeSnapshot(good,kFile,kFileSize,kTopology+1,kReceived,rejected));
    CHECK(!discovery::Kad6Resolution::NativeSnapshot(good,kFile,kFileSize,kTopology,good.until,rejected));
}

void RejectWrongRecoveryRoutes(const DirectCandidate& candidate,std::uint64_t now) {
    for(unsigned variant=0;variant<11;++variant) {
        auto bad=candidate;
        switch(variant) {
        case 0:bad.kind=DirectKind::Predicted;break;
        case 1:bad.family=6;break;
        case 2:bad.transport_mask=DirectQuic;break;
        case 3:bad.evidence=DirectEvidence::Observed;break;
        case 4:bad.scope=DirectScope::SameLan;break;
        case 5:bad.interface_id=1;break;
        case 6:bad.topology_generation+=1;break;
        case 7:bad.expires_monotonic_ms=now;break;
        case 8:bad.port=0;break;
        case 9:bad.id=0;break;
        case 10:bad.address[4]=1;break;
        }
        CHECK(!PrepareFreshTcpRecoveryRoute(bad,2,kTopology,now));
    }
    CHECK(!PrepareFreshTcpRecoveryRoute(candidate,0,kTopology,now));
    CHECK(!PrepareFreshTcpRecoveryRoute(candidate,2,0,now));
    auto nearOverflow=candidate;
    nearOverflow.expires_monotonic_ms=(std::numeric_limits<std::uint64_t>::max)();
    CHECK(!PrepareFreshTcpRecoveryRoute(nearOverflow,2,kTopology,nearOverflow.expires_monotonic_ms-1));
}
}

int main() {
    Identity owner;
    const auto publication=Publication(owner);
    const auto snapshot=Snapshot(publication);
    const auto candidate=snapshot.candidates[0].route;
    constexpr std::uint64_t now=kReceived+10;
    const auto prepared=PrepareFreshTcpRecoveryRoute(candidate,2,kTopology,now);
    CHECK(prepared.has_value());
    const auto route=*prepared;
    CHECK(candidate.expires_monotonic_ms==kReceived+120000);
    CHECK(route.candidate.expires_monotonic_ms==now+15000);
    CHECK(route.candidate.kind==DirectKind::VerifiedMapping && route.candidate.evidence==DirectEvidence::Advertised);
    CHECK(route.recovery_authentication && route.transport==DirectTcp && route.candidate.transport_mask==DirectTcp);
    CHECK(route.candidate.address==candidate.address && route.candidate.port==candidate.port);
    // Defense in depth: the host descriptor path also caps deadlines. Neither
    // that cap nor this helper may renew a shorter publication/source lease.
    const auto shortPublication=Publication(owner,7);
    const auto shortSnapshot=Snapshot(shortPublication);
    const auto shortRoute=PrepareFreshTcpRecoveryRoute(shortSnapshot.candidates[0].route,2,kTopology,now);
    CHECK(shortRoute && shortRoute->candidate.expires_monotonic_ms==kReceived+7000);
    auto sourceLimited=shortPublication; sourceLimited.until=kReceived+4000;
    const auto limitedSnapshot=Snapshot(sourceLimited);
    const auto limitedRoute=PrepareFreshTcpRecoveryRoute(limitedSnapshot.candidates[0].route,2,kTopology,now);
    CHECK(limitedRoute && limitedRoute->candidate.expires_monotonic_ms==sourceLimited.until);
    CHECK(shortSnapshot.candidates[0].route.expires_monotonic_ms==kReceived+7000);
    auto combined=candidate; combined.transport_mask=DirectTcp|DirectQuic;
    const auto narrowed=PrepareFreshTcpRecoveryRoute(combined,2,kTopology,now);
    CHECK(narrowed && narrowed->candidate.transport_mask==DirectTcp && combined.transport_mask==(DirectTcp|DirectQuic));
    RejectAlteredPublications(publication);
    RejectWrongRecoveryRoutes(candidate,now);

    auto session=EstablishedThenClosed(snapshot);
    TcpRecoveryAuthorization permission;
    CHECK(permission.Issue(kHandle,kLifetime,session.Epoch(),route,now));
    CHECK(!permission.Issue(kHandle,kLifetime,session.Epoch(),route,now));
    CHECK(permission.Route() && permission.Route()->candidate.evidence==DirectEvidence::Advertised);
    CHECK(Count(session.SetRoutes({route},now),DirectActionType::Start)==1);
    CHECK(session.AuthorizesStart(route,1) && session.State()==DirectSessionState::Connecting);
    auto changed=route; changed.candidate.port+=1;
    CHECK(!permission.Claim(kHandle,kLifetime,kTopology,1,changed,kAuthenticationLifetime,now));
    CHECK(!permission.Claim({kHandle.slot,kHandle.generation+1},kLifetime,kTopology,1,route,kAuthenticationLifetime,now));
    CHECK(!permission.Claim(kHandle,kLifetime,kTopology,0,route,kAuthenticationLifetime,now));
    CHECK(permission.Claim(kHandle,kLifetime,kTopology,1,route,kAuthenticationLifetime,now));
    CHECK(!permission.Claim(kHandle,kLifetime,kTopology,1,route,kAuthenticationLifetime+1,now));
    CHECK(permission.Allows(kHandle,kLifetime,kTopology,1,kAuthenticationLifetime,session.State(),0,now,false));
    CHECK(!permission.Allows(kHandle,kLifetime,kTopology,1,kAuthenticationLifetime,session.State(),0,now,true));

    const auto connected=session.Advance(now+1,{Event(route.id,1,DirectEventType::Connected,1)});
    CHECK(!Count(connected,DirectActionType::Attach));
    CHECK(session.State()==DirectSessionState::Authenticating && !session.Winner() && session.Epoch()==1);
    CHECK(session.RecoveryOutcome()==DirectRecoveryOutcome::TcpConnected);
    CHECK(permission.Allows(kHandle,kLifetime,kTopology,1,kAuthenticationLifetime,session.State(),0,now+1,false));
    CHECK(!permission.Allows(kHandle,kLifetime,kTopology,1,kAuthenticationLifetime,session.State(),0,now+1,true));
    const auto premature=session.Advance(now+2,{Event(route.id,2,DirectEventType::UsefulRange,1,8192),
        Event(route.id,3,DirectEventType::VerifiedPart,1)});
    CHECK(!Count(premature,DirectActionType::Attach) && !session.Winner() && session.Epoch()==1);
    CHECK(session.UsefulBytes()==4096 && session.TransferVerified());
    // Only the adapter's authenticated event, after host SecureIdent/pin checks,
    // can make this core attach. A connect, descriptor or permission cannot.
    const auto attached=session.Advance(now+3,{Event(route.id,4,DirectEventType::Authenticated,1)});
    CHECK(Count(attached,DirectActionType::Attach)==1 && session.State()==DirectSessionState::Ready);
    CHECK(session.Winner()==route.id && session.Epoch()==2 && session.FallbackCount()==1);
    CHECK(permission.Allows(kHandle,kLifetime,kTopology,2,kAuthenticationLifetime,session.State(),session.Winner(),now+3,true));
    CHECK(!permission.Allows(kHandle,kLifetime,kTopology,2,kAuthenticationLifetime,session.State(),session.Winner(),now+3,false));
    CHECK(session.RecoveryOutcome()==DirectRecoveryOutcome::TcpAuthenticated);
    CHECK(session.UsefulBytes()==4096 && session.TransferVerified() && !session.EpochUsefulBytes() && !session.EpochTransferVerified());
    session.Advance(now+4,{Event(route.id,5,DirectEventType::UsefulRange,1,8192)});
    CHECK(session.UsefulBytes()==4096 && !session.EpochUsefulBytes());
    session.Advance(now+5,{Event(route.id,6,DirectEventType::UsefulRange,2,8192)});
    CHECK(session.UsefulBytes()==12288 && session.EpochUsefulBytes()==8192 && !session.EpochTransferVerified());
    CHECK(session.RecoveryOutcome()==DirectRecoveryOutcome::Receiving);
    session.Advance(now+6,{Event(route.id,7,DirectEventType::VerifiedPart,2)});
    CHECK(session.TransferVerified() && session.EpochTransferVerified() && session.RecoveryOutcome()==DirectRecoveryOutcome::VerifiedData);
    CHECK(session.RecoveryCause()==DirectReason::QuicNoProgress);
    CHECK(!permission.Allows(kHandle,kLifetime,kTopology,2,kAuthenticationLifetime,DirectSessionState::Ready,route.id,
        route.candidate.expires_monotonic_ms,true));

    // The core retains previous verified contributions on failure. It does not
    // own or delete the on-disk part files, which require separate host tests.
    for(unsigned failure=0;failure<3;++failure) {
        auto failed=EstablishedThenClosed(snapshot);
        CHECK(Count(failed.SetRoutes({route},now),DirectActionType::Start)==1);
        failed.Advance(now+1,{Event(route.id,1,DirectEventType::Connected,1)});
        if(failure==0) {
            auto rejected=Event(route.id,2,DirectEventType::AuthenticationFailed,1);
            rejected.reason=DirectReason::IdentityMismatch;
            failed.Advance(now+2,{rejected});
            CHECK(failed.RecoveryOutcome()==DirectRecoveryOutcome::IdentityRejected);
        } else if(failure==1) {
            failed.Advance(route.candidate.expires_monotonic_ms);
            CHECK(failed.State()==DirectSessionState::Failed);
        } else {
            failed.InvalidateTopology(kTopology+1);
            CHECK(failed.RecoveryOutcome()==DirectRecoveryOutcome::NetworkChanged);
        }
        CHECK(!failed.Winner() && failed.Epoch()==1 && failed.UsefulBytes()==4096 && failed.TransferVerified());
    }
    std::printf("TCP recovery publication: %u checks PASS (real Ed25519 publication -> NativeSnapshot -> scoped permission -> recovery core; no network, RSA-wire or 1-GiB transfer claim)\n",checks);
}
