#pragma once
#include "EseControlCookie.h"
#include "EseControlChallengeLimit.h"
#include "EseControlSessions.h"
#include "EseReachDescriptor.h"
#include "EseDescriptorSerials.h"
#include "EseK6DirectSource.h"
#include <limits>
namespace ese { namespace control {
bool DirectIndexKey(const std::array<std::uint8_t,16>& file,std::uint64_t fileSize,
    std::uint64_t maxFileSize,std::array<std::uint8_t,16>& out) noexcept;
// Cryptographic validity only. The expected key comes from caller policy,
// never implicitly from an arbitrary packet field. Does not validate payload,
// replay, cookie, endpoint return or authorize a transport route.
bool VerifyEnvelopeSignature(const std::array<std::uint8_t,32>& expectedSigner,
    const std::uint8_t* packet,std::size_t size) noexcept;
// Digest covers the entire descriptor, including its signature. Hashing alone
// is not authentication; expectedDigest must come from the requested locator.
bool DescriptorDigest(const std::uint8_t*,std::size_t,std::array<std::uint8_t,32>& out) noexcept;
bool VerifyDescriptor(const std::array<std::uint8_t,32>& expectedNode,
    const std::array<std::uint8_t,32>& expectedDigest,const std::uint8_t*,std::size_t,
    discovery::DescriptorView& out) noexcept;
// The only mutation occurs after locator/key/signature verification. Returned
// views borrow packet memory; admission is not a reachability or ticket grant.
template<std::size_t Capacity> discovery::SerialResult AdmitDescriptor(
    discovery::DescriptorSerials<Capacity>& serials,
    const std::array<std::uint8_t,32>& expectedNode,
    const std::array<std::uint8_t,32>& expectedDigest,const std::uint8_t* packet,std::size_t size,
    std::uint32_t sourceTtl,std::uint64_t now,discovery::DescriptorView& out,
    std::uint64_t& deadline) noexcept {
    out={}; deadline=0;
    discovery::DescriptorView verified;
    if(!VerifyDescriptor(expectedNode,expectedDigest,packet,size,verified))
        return discovery::SerialResult::Invalid;
    const auto result=serials.AcceptVerified(verified,expectedDigest,sourceTtl,now,deadline);
    if(result==discovery::SerialResult::Accepted || result==discovery::SerialResult::Duplicate)
        out=verified;
    return result;
}
class CookieAuthority;
// Stateless cryptographic/correlation gate. Caller additionally requires a
// live pending request, authenticated W session, endpoint and 2s deadline.
bool VerifyDescriptorResult(const std::array<std::uint8_t,32>& witness,
    const Header& request,const std::array<std::uint8_t,16>& file,
    const discovery::Locator&,const std::uint8_t*,std::size_t,
    discovery::ResultView& out) noexcept;
enum class DescriptorRequestState { Idle, Pending, Complete, Failed };
// Single-use main-thread request. Start only after control authentication;
// host must revalidate that session before Receive. No retry/route creation.
class DescriptorRequest {
public:
    DescriptorRequest() noexcept = default;
    DescriptorRequest(const DescriptorRequest&)=delete;
    DescriptorRequest& operator=(const DescriptorRequest&)=delete;
    bool Start(const std::array<std::uint8_t,32>& witness,const udp::Endpoint& endpoint,
        const Header& expectedResponse,const std::array<std::uint8_t,16>& file,
        const discovery::Locator& locator,std::uint64_t now,
        std::uint64_t resolutionDeadline=(std::numeric_limits<std::uint64_t>::max)(),std::uint64_t expectedGeneration=0) noexcept {
        if(state_!=DescriptorRequestState::Idle || !endpoint.port ||
            expectedResponse.type!=wire::kEseWireUdpDescriptorResult || !expectedResponse.generation ||
            !expectedResponse.sequence || !locator.ttl || locator.ttl>120 ||
            now>(std::numeric_limits<std::uint64_t>::max)()-2000 || resolutionDeadline<=now) return false;
        unsigned key=0,node=0,attempt=0;
        for(auto b:witness) key|=b; for(auto b:locator.node) node|=b;
        for(auto b:expectedResponse.attempt) attempt|=b;
        if(!key || !node || !attempt) return false;
        witness_=witness; endpoint_=endpoint; expected_=expectedResponse; file_=file; locator_=locator;
        expectedGeneration_=expectedGeneration;
        lastNow_=now; deadline_=(resolutionDeadline<now+2000)?resolutionDeadline:now+2000;
        state_=DescriptorRequestState::Pending; return true;
    }
    bool Receive(const udp::Endpoint& source,const std::uint8_t* packet,std::size_t size,
        std::uint64_t now,discovery::ResultView& out) noexcept {
        out={}; if(!Poll(now) || !(source==endpoint_) ||
            !VerifyDescriptorResult(witness_,expected_,file_,locator_,packet,size,out)) return false;
        if(out.status==0 && expectedGeneration_) {
            discovery::DescriptorView descriptor;
            if(!discovery::ParseUntrusted(out.descriptor,out.length,descriptor) || descriptor.generation!=expectedGeneration_) { out={}; return false; }
        }
        state_=DescriptorRequestState::Complete; return true;
    }
    bool Poll(std::uint64_t now) noexcept {
        if(state_!=DescriptorRequestState::Pending) return false;
        if(now<lastNow_ || now>=deadline_) { state_=DescriptorRequestState::Failed; return false; }
        lastNow_=now; return true;
    }
    void Cancel() noexcept { state_=DescriptorRequestState::Failed; }
    DescriptorRequestState State() const noexcept { return state_; }
private:
    std::array<std::uint8_t,32> witness_{};
    udp::Endpoint endpoint_;
    Header expected_;
    std::array<std::uint8_t,16> file_{};
    discovery::Locator locator_;
    std::uint64_t lastNow_=0,deadline_=0,expectedGeneration_=0;
    DescriptorRequestState state_=DescriptorRequestState::Idle;
};
template<std::size_t Capacity> discovery::SerialResult AdmitLocatedDescriptor(
    discovery::DescriptorSerials<Capacity>& serials,const discovery::Locator& locator,
    const std::uint8_t* packet,std::size_t size,std::uint64_t now,
    discovery::DescriptorView& out,std::uint64_t& deadline) noexcept {
    out={}; deadline=0; discovery::DescriptorView verified;
    if(!locator.ttl || locator.ttl>120 ||
        !VerifyDescriptor(locator.node,locator.digest,packet,size,verified) || verified.serial!=locator.serial)
        return discovery::SerialResult::Invalid;
    const auto result=serials.AcceptVerified(verified,locator.digest,locator.ttl,now,deadline);
    if(result==discovery::SerialResult::Accepted || result==discovery::SerialResult::Duplicate) out=verified;
    return result;
}
bool BuildChallenge(CookieAuthority&,ChallengeLimit&,const udp::Endpoint& observedSource,
    const std::array<std::uint8_t,32>& localNode,const std::array<std::uint8_t,32>& expectedPeer,
    const std::uint8_t* probe,std::size_t size,std::uint64_t now,Datagram& out) noexcept;
// Validates PROVE in one fail-closed gate, but does not consume replay state or
// create an ingress expectation/session. Repeated valid PROVE can pass this
// primitive; the receiver state machine must make adoption idempotent.
bool VerifyProve(const CookieAuthority&,const udp::Endpoint& observedSource,
    const std::array<std::uint8_t,32>& localNode,const std::array<std::uint8_t,32>& expectedPeer,
    const std::uint8_t* packet,std::size_t size,std::uint64_t now,Prove& out) noexcept;
Admission AdmitProve(const CookieAuthority&,Sessions&,const udp::Endpoint& observedSource,
    const std::array<std::uint8_t,32>& localNode,const std::array<std::uint8_t,32>& expectedPeer,
    const std::uint8_t* packet,std::size_t size,std::uint64_t now,Prove& out) noexcept;
class Signer {
public:
    virtual ~Signer() = default;
    virtual bool Sign(const std::uint8_t*,std::size_t,std::array<std::uint8_t,64>&) noexcept = 0;
};
bool BuildContactGet(const Header&,const std::array<std::uint8_t,32>& requester,Signer&,Datagram& out) noexcept;
bool VerifyContactGet(const std::array<std::uint8_t,32>& requester,const std::uint8_t*,std::size_t,Header& out) noexcept;
bool ContactGetDigest(const std::array<std::uint8_t,32>& requester,const std::uint8_t*,std::size_t,
    std::array<std::uint8_t,32>& out) noexcept;
template<std::size_t Capacity> bool AdmitContactGet(Sessions& sessions,DescriptorGetLimit<Capacity>& limit,
    const udp::Endpoint& endpoint,const std::array<std::uint8_t,32>& requester,
    const std::uint8_t* packet,std::size_t size,std::uint64_t now,Header& out) noexcept {
    out={}; Header header;
    if(!VerifyContactGet(requester,packet,size,header) || !sessions.ObserveVerified(requester,endpoint,header,now) ||
        !limit.Allow(requester,now)) return false;
    out=header; return true;
}
bool BuildDirectSource(const discovery::DirectSource&,std::uint64_t maxFileSize,Signer&,
    std::array<std::uint8_t,173>& out) noexcept;
bool BuildDirectFind(const Header&,const discovery::DirectFind&,std::uint64_t maxFileSize,Signer&,Datagram& out) noexcept;
bool VerifyDirectFind(const std::array<std::uint8_t,32>& requester,const std::uint8_t*,std::size_t,
    std::uint64_t maxFileSize,Header& outHeader,discovery::DirectFind& out) noexcept;
bool DirectFindDigest(const std::array<std::uint8_t,32>& requester,const std::uint8_t*,std::size_t,
    std::uint64_t maxFileSize,std::array<std::uint8_t,32>& out) noexcept;
// Authenticates W/correlation only. CLOSER contents still require libkad6
// verification, freshness, direct-index capability and distinct identities.
bool VerifyDirectFindResultSignature(const std::array<std::uint8_t,32>& witness,const Header& original,
    const discovery::DirectFind&,const std::array<std::uint8_t,32>& requestDigest,
    const std::uint8_t*,std::size_t,std::uint64_t maxFileSize,discovery::FindResultView& out) noexcept;
bool VerifyDirectFindSources(const discovery::FindResultView&,std::uint64_t maxFileSize) noexcept;
class FindContactsVerifier {
public:
    virtual ~FindContactsVerifier() = default;
    // Host implements libkad6 decoding/signatures/freshness/capability and
    // duplicate/not-W checks. No validator means no CLOSER acceptance.
    virtual bool Verify(const discovery::FindResultView&,const std::array<std::uint8_t,32>& witness) noexcept = 0;
};
class DirectFindRequest {
public:
    DirectFindRequest() noexcept = default;
    DirectFindRequest(const DirectFindRequest&)=delete;
    DirectFindRequest& operator=(const DirectFindRequest&)=delete;
    bool Start(const std::array<std::uint8_t,32>& witness,const udp::Endpoint& endpoint,
        const Header& original,const discovery::DirectFind& query,const std::array<std::uint8_t,32>& digest,
        std::uint64_t maxFileSize,std::uint64_t now,
        std::uint64_t resolutionDeadline=(std::numeric_limits<std::uint64_t>::max)()) noexcept {
        unsigned key=0,attempt=0; for(auto b:witness) key|=b; for(auto b:original.attempt) attempt|=b;
        std::array<std::uint8_t,121> checked{};
        if(state_!=DescriptorRequestState::Idle || !key || !attempt || !endpoint.port || !original.sequence ||
            !original.generation || original.type!=wire::kEseWireUdpK6DirectFind ||
            now>(std::numeric_limits<std::uint64_t>::max)()-2000 || resolutionDeadline<=now ||
            !discovery::EncodeFind(query,maxFileSize,checked)) return false;
        witness_=witness; endpoint_=endpoint; original_=original; query_=query; digest_=digest;
        maxFileSize_=maxFileSize; lastNow_=now; deadline_=(resolutionDeadline<now+2000)?resolutionDeadline:now+2000;
        state_=DescriptorRequestState::Pending; return true;
    }
    bool Receive(const udp::Endpoint& endpoint,const std::uint8_t* bytes,std::size_t size,std::uint64_t now,
        discovery::FindResultView& out,FindContactsVerifier* contacts=nullptr) noexcept {
        out={}; discovery::FindResultView verified;
        if(!Poll(now) || !(endpoint==endpoint_) ||
            !VerifyDirectFindResultSignature(witness_,original_,query_,digest_,bytes,size,maxFileSize_,verified) ||
            (verified.kind==0 && !VerifyDirectFindSources(verified,maxFileSize_)) ||
            (verified.kind==1 && (!contacts || !contacts->Verify(verified,witness_)))) return false;
        out=verified; state_=DescriptorRequestState::Complete; return true;
    }
    bool Poll(std::uint64_t now) noexcept {
        if(state_!=DescriptorRequestState::Pending) return false;
        if(now<lastNow_ || now>=deadline_) { state_=DescriptorRequestState::Failed; return false; }
        lastNow_=now; return true;
    }
    void Cancel() noexcept { state_=DescriptorRequestState::Failed; }
    DescriptorRequestState State() const noexcept { return state_; }
private:
    std::array<std::uint8_t,32> witness_{},digest_{};
    udp::Endpoint endpoint_;
    Header original_;
    discovery::DirectFind query_;
    std::uint64_t maxFileSize_=0,lastNow_=0,deadline_=0;
    DescriptorRequestState state_=DescriptorRequestState::Idle;
};
// count0 creates EMPTY; count1..4 SOURCES. CLOSER uses a separate Kad6 path.
bool BuildDirectFindSourcesResult(const Header& original,const discovery::DirectFind&,
    const std::array<std::uint8_t,32>& requestDigest,const std::array<discovery::FindEntryView,4>&,
    std::uint8_t count,std::uint64_t maxFileSize,const std::array<std::uint8_t,32>& witness,
    Signer&,Datagram& out) noexcept;
template<std::size_t Capacity> bool AdmitDirectFind(Sessions& sessions,DescriptorGetLimit<Capacity>& limit,
    const udp::Endpoint& endpoint,const std::array<std::uint8_t,32>& requester,const std::uint8_t* packet,
    std::size_t size,std::uint64_t maxFileSize,std::uint64_t now,Header& outHeader,discovery::DirectFind& out) noexcept {
    outHeader={}; out={}; Header header; discovery::DirectFind query;
    if(!VerifyDirectFind(requester,packet,size,maxFileSize,header,query) ||
        !sessions.ObserveVerified(requester,endpoint,header,now) || !limit.Allow(requester,now)) return false;
    outHeader=header; out=query; return true;
}
bool VerifyDirectSource(const std::array<std::uint8_t,32>& publisher,
    const std::uint8_t*,std::size_t,std::uint64_t maxFileSize,discovery::DirectSource& out) noexcept;
bool BuildDirectPut(const Header&,const std::uint8_t* record,std::size_t,
    std::uint64_t maxFileSize,const std::array<std::uint8_t,32>& publisher,Signer&,Datagram& out) noexcept;
bool VerifyDirectPut(const std::array<std::uint8_t,32>& publisher,const std::uint8_t*,std::size_t,
    std::uint64_t maxFileSize,Header& outHeader,discovery::DirectSource& out) noexcept;
bool AdmitDirectPut(Sessions&,const udp::Endpoint&,const std::array<std::uint8_t,32>& publisher,
    const std::uint8_t*,std::size_t,std::uint64_t maxFileSize,std::uint64_t now,
    Header& outHeader,discovery::DirectSource& out) noexcept;
template<std::size_t Capacity> bool AdmitDirectPut(Sessions& sessions,DescriptorGetLimit<Capacity>& limit,
    const udp::Endpoint& endpoint,const std::array<std::uint8_t,32>& publisher,const std::uint8_t* bytes,
    std::size_t size,std::uint64_t maxFileSize,std::uint64_t now,Header& outHeader,discovery::DirectSource& out) noexcept {
    outHeader={}; out={}; Header header; discovery::DirectSource verified;
    if(!AdmitDirectPut(sessions,endpoint,publisher,bytes,size,maxFileSize,now,header,verified) ||
        !limit.AllowPut(publisher,now)) return false;
    outHeader=header; out=verified; return true;
}
bool BuildDirectPutResult(const Header& original,std::uint8_t status,const discovery::DirectSource&,
    std::uint64_t maxFileSize,const std::array<std::uint8_t,32>& witness,Signer&,Datagram& out) noexcept;
// Stateless: pending request, endpoint/session/deadline enforced by host owner.
bool VerifyDirectPutResult(const std::array<std::uint8_t,32>& witness,const Header& original,
    const discovery::DirectSource&,std::uint64_t maxFileSize,const std::uint8_t*,std::size_t,
    std::uint8_t& status) noexcept;
// Main-thread single-use publication confirmation. Start/Receive require the
// host's authenticated W session to remain live; completion is not READY.
class DirectPutRequest {
public:
    DirectPutRequest() noexcept = default;
    DirectPutRequest(const DirectPutRequest&)=delete;
    DirectPutRequest& operator=(const DirectPutRequest&)=delete;
    bool Start(const std::array<std::uint8_t,32>& witness,const udp::Endpoint& endpoint,
        const Header& original,const discovery::DirectSource& source,std::uint64_t maxFileSize,
        std::uint64_t now) noexcept {
        unsigned key=0,attempt=0; for(auto b:witness) key|=b; for(auto b:original.attempt) attempt|=b;
        std::array<std::uint8_t,173> checked{};
        if(state_!=DescriptorRequestState::Idle || !key || !attempt || !endpoint.port ||
            original.type!=wire::kEseWireUdpK6DirectPut || !original.sequence || original.generation!=source.generation ||
            now>(std::numeric_limits<std::uint64_t>::max)()-2000 ||
            !discovery::EncodeSource(source,maxFileSize,checked)) return false;
        witness_=witness; endpoint_=endpoint; original_=original; source_=source; maxFileSize_=maxFileSize;
        lastNow_=now; deadline_=now+2000; state_=DescriptorRequestState::Pending; return true;
    }
    bool Receive(const udp::Endpoint& source,const std::uint8_t* packet,std::size_t size,
        std::uint64_t now,std::uint8_t& status) noexcept {
        status=255;
        if(!Poll(now) || !(source==endpoint_) ||
            !VerifyDirectPutResult(witness_,original_,source_,maxFileSize_,packet,size,status)) return false;
        state_=DescriptorRequestState::Complete; return true;
    }
    bool Poll(std::uint64_t now) noexcept {
        if(state_!=DescriptorRequestState::Pending) return false;
        if(now<lastNow_ || now>=deadline_) { state_=DescriptorRequestState::Failed; return false; }
        lastNow_=now; return true;
    }
    void Cancel() noexcept { state_=DescriptorRequestState::Failed; }
    DescriptorRequestState State() const noexcept { return state_; }
private:
    std::array<std::uint8_t,32> witness_{};
    udp::Endpoint endpoint_;
    Header original_;
    discovery::DirectSource source_;
    std::uint64_t maxFileSize_=0,lastNow_=0,deadline_=0;
    DescriptorRequestState state_=DescriptorRequestState::Idle;
};
bool BuildDescriptorGet(const Header&,const std::array<std::uint8_t,16>& file,
    const discovery::Locator&,const std::array<std::uint8_t,32>& requester,
    Signer&,Datagram& out) noexcept;
bool BuildDescriptorPut(const Header&,const std::array<std::uint8_t,16>& file,
    const std::uint8_t* descriptor,std::size_t,const std::array<std::uint8_t,32>& publisher,
    Signer&,Datagram& out) noexcept;
bool BuildDescriptorResult(const Header& expectedResponse,std::uint8_t status,
    const std::array<std::uint8_t,16>& file,const discovery::Locator&,
    const std::uint8_t* descriptor,std::size_t,const std::array<std::uint8_t,32>& witness,
    Signer&,Datagram& out) noexcept;
bool VerifyDescriptorPut(const std::array<std::uint8_t,32>& publisher,
    const std::uint8_t*,std::size_t,Header& outHeader,discovery::PutView& out,
    std::array<std::uint8_t,32>& digest) noexcept;
// Admission to authenticated control, NOT permission to publish/store: host
// must additionally match a live source or hold provisional <=5s/1 per B.
bool AdmitDescriptorPut(Sessions&,const udp::Endpoint& source,
    const std::array<std::uint8_t,32>& publisher,const std::uint8_t*,std::size_t,
    std::uint64_t now,Header& outHeader,discovery::PutView& out,
    std::array<std::uint8_t,32>& digest) noexcept;
// Caller must enforce authenticated control session, replay and GET rate limit.
bool VerifyDescriptorGet(const std::array<std::uint8_t,32>& requester,
    const std::uint8_t*,std::size_t,Header& outHeader,discovery::GetView& out) noexcept;
// Rate-rejected authenticated requests consume their sequence, not quota.
template<std::size_t Capacity> bool AdmitDescriptorGet(Sessions& sessions,
    DescriptorGetLimit<Capacity>& limit,const udp::Endpoint& source,
    const std::array<std::uint8_t,32>& requester,const std::uint8_t* packet,std::size_t size,
    std::uint64_t now,Header& outHeader,discovery::GetView& out) noexcept {
    outHeader={}; out={}; Header header; discovery::GetView verified;
    if(!VerifyDescriptorGet(requester,packet,size,header,verified) ||
        !sessions.ObserveVerified(requester,source,header,now) || !limit.Allow(requester,now)) return false;
    outHeader=header; out=verified; return true;
}
// Caller has already admitted PROVE. Key material never enters the codec.
bool BuildAck(const Prove&,const Header& original,std::uint8_t selected,
    const std::array<std::uint8_t,32>& localNode,Signer&,Datagram& out) noexcept;
bool VerifyAck(const std::array<std::uint8_t,32>& expectedPeer,const Header& original,
    const std::array<std::uint8_t,32>& nonce,std::uint8_t requestedMask,
    const std::uint8_t* packet,std::size_t size,Ack& out) noexcept;
// Internal primitive for deterministic vectors and the authority below. A
// caller-provided key is not automatically a fresh process secret.
bool ComputeCookie(const std::array<std::uint8_t,32>& secret,const udp::Endpoint&,
    const CookieProof&,const std::array<std::uint8_t,32>& signer,
    std::array<std::uint8_t,16>& out) noexcept;
class CookieAuthority {
public:
    CookieAuthority() noexcept = default;
    ~CookieAuthority();
    CookieAuthority(const CookieAuthority&)=delete;
    CookieAuthority& operator=(const CookieAuthority&)=delete;
    bool Initialize() noexcept;
    bool Issue(const udp::Endpoint&,CookieProof&,const std::array<std::uint8_t,32>& signer,
        std::uint64_t monotonicMs) noexcept;
    bool Verify(const udp::Endpoint&,const CookieProof&,const std::array<std::uint8_t,32>& signer,
        std::uint64_t monotonicMs) const noexcept;
private:
    std::array<std::uint8_t,32> secret_{};
    bool initialized_=false;
};
} }
