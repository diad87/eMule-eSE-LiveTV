#pragma once
#include "EseKad6Lookup.h"
#include "EseControlCookieCrypto.h"
#include "EseResolutionCooldown.h"
#include <optional>
#include "reach/native_direct_snapshot.h"
namespace ese { namespace discovery {
// Main-thread discovery owner, not a connection/credit authority. Retain source
// records and verified W session separately; no network send occurs here.
struct ResolvedKad6Candidate {
        DirectSource source; std::array<std::uint8_t,32> witness{}; udp::Endpoint witnessEndpoint;
        std::array<std::uint8_t,DescriptorMax> descriptor{}; std::size_t length=0;
        std::uint64_t until=0,receivedMs=0,localGeneration=0;
}; // Signed discovery evidence only: never READY, credit or verified route.
class Kad6Resolution {
public:
    using ResolvedCandidate=ResolvedKad6Candidate;
    struct LocatedSource {
        DirectSource source; Locator locator; std::array<std::uint8_t,32> witness{};
        udp::Endpoint witnessEndpoint; std::uint64_t until=0;
    };
    unsigned SnapshotLocatedSources(std::uint64_t now,std::array<LocatedSource,32>& out) noexcept {
        out={}; if(!Poll(now)) return 0;
        unsigned count=0;
        for(const auto& source:sources_) if(source.used && source.until>now) {
            const auto seconds=(source.until-now)/1000;
            if(!seconds) continue; // GET cannot encode a fractional-second lease.
            auto& entry=out[count++]; entry.source=source.record; entry.witness=source.witness;
            entry.witnessEndpoint=source.endpoint; entry.until=source.until;
            entry.locator.node=source.record.node; entry.locator.digest=source.record.digest;
            entry.locator.serial=source.record.serial;
            entry.locator.ttl=static_cast<std::uint32_t>((seconds<120)?seconds:120);
        }
        return count;
    }
    // Conversion preserves discovery provenance, not route/credit authority.
    // Caller still needs endpoint policy and independently established evidence.
    static bool NativeSnapshot(const ResolvedCandidate& candidate,
        const std::array<std::uint8_t,16>& file,std::uint64_t fileSize,
        std::uint64_t currentLocalGeneration,std::uint64_t now,
        reach::NativeDirectCandidateSnapshotV1& out) noexcept {
        out={}; DescriptorView descriptor; DirectSource verifiedSource;
        std::array<std::uint8_t,173> sourceBytes{};
        if(!currentLocalGeneration || candidate.localGeneration!=currentLocalGeneration ||
            now<candidate.receivedMs || now>=candidate.until || candidate.until<=candidate.receivedMs ||
            candidate.source.file!=file || !fileSize || candidate.source.fileSize!=fileSize ||
            !EncodeSource(candidate.source,fileSize,sourceBytes) ||
            !control::VerifyDirectSource(candidate.source.node,sourceBytes.data(),sourceBytes.size(),fileSize,verifiedSource) ||
            !control::VerifyDescriptor(candidate.source.node,candidate.source.digest,
                candidate.descriptor.data(),candidate.length,descriptor) ||
            !descriptor.generation || descriptor.generation!=candidate.source.generation ||
            !descriptor.serial || descriptor.serial!=candidate.source.serial) return false;
        reach::NativeDirectCandidateSnapshotV1 snapshot;
        snapshot.local_generation=candidate.localGeneration;
        snapshot.remote_generation=descriptor.generation;
        snapshot.peer.expected_node_pub=descriptor.node;
        if(reach::NonzeroIdentity(descriptor.userHash)) snapshot.peer.expected_user_hash=descriptor.userHash;
        if(reach::NonzeroIdentity(descriptor.kadId)) snapshot.peer.kad_id=descriptor.kadId;
        for(unsigned i=0;i<descriptor.candidates;++i) {
            const auto* wireCandidate=descriptor.candidateBytes+28*i;
            const auto lifetime=ReadBe(wireCandidate+24,4)*1000;
            if(candidate.receivedMs>(std::numeric_limits<std::uint64_t>::max)()-lifetime) return false;
            const auto routeUntil=candidate.receivedMs+lifetime;
            const auto until=(routeUntil<candidate.until)?routeUntil:candidate.until;
            if(until<=now) continue;
            // Descriptor capabilities and route transports are separate wire
            // namespaces. An advertised QUIC route needs the signed QUIC cap;
            // unknown descriptor bits cannot activate it (nor imply consent).
            const auto transports=static_cast<std::uint8_t>(wireCandidate[2] &
                ((descriptor.caps & 1u)?7u:3u));
            if(!transports) continue;
            auto& entry=snapshot.candidates[snapshot.count++];
            entry.source=reach::DirectCandidateSource::KadSource;
            auto& route=entry.route;
            route.id=i+1; route.family=wireCandidate[1];
            // Wire kinds are NOT the ordinal values of DirectKind.
            if(wireCandidate[0]==3) route.kind=reach::DirectKind::VerifiedMapping;
            else if(wireCandidate[0]==6) route.kind=reach::DirectKind::Predicted;
            else route.kind=(route.family==6)?reach::DirectKind::DirectV6:reach::DirectKind::DirectV4;
            route.scope=(wireCandidate[0]==5 || wireCandidate[22])?reach::DirectScope::SameLan:reach::DirectScope::Global;
            std::memcpy(route.address.data(),wireCandidate+4,16);
            route.port=static_cast<std::uint16_t>(ReadBe(wireCandidate+20,2));
            route.transport_mask=transports;
            route.evidence=reach::DirectEvidence::Advertised; // Never trust wire evidence.
            route.topology_generation=candidate.localGeneration;
            route.expires_monotonic_ms=until;
        }
        if(reach::ValidateNativeSnapshot(snapshot,currentLocalGeneration)!=reach::NativeSnapshotStatus::Ok) return false;
        out=snapshot; return true;
    }
    bool Start(const std::array<std::uint8_t,16>& file,std::uint64_t size,std::uint64_t maxSize,std::uint64_t now,
        std::uint64_t localGeneration=0) noexcept {
        std::array<std::uint8_t,16> key{};
        if(started_ || !control::DirectIndexKey(file,size,maxSize,key) || !lookup_.Start(key,now)) return false;
        file_=file; size_=size; maxSize_=maxSize; last_=now; localGeneration_=localGeneration; started_=true; return true;
    }
    bool StartForSource(const std::array<std::uint8_t,16>& file,std::uint64_t size,std::uint64_t maxSize,
        ResolutionCooldown<>& cooldown,const ResolutionCooldown<>::Key& source,std::uint64_t topology,
        std::uint64_t now,bool explicitUserAction=false) noexcept {
        if(!cooldown.Permit(source,topology,now,explicitUserAction) || !Start(file,size,maxSize,now,topology)) return false;
        cooldown_=&cooldown; source_=source; topology_=topology; return true;
    }
    bool Poll(std::uint64_t now) noexcept {
        if(!started_ || stopped_) return false;
        if(now<last_ || now>=lookup_.Deadline()) {
            if(now>=last_ && cooldown_) cooldown_->RecordExpired(source_,topology_,now);
            Cancel(); return false;
        }
        last_=now; lookup_.Poll(now);
        for(auto& request:find_) if(request) request->Poll(now);
        for(auto& request:get_) if(request) request->Poll(now);
        return true; // exhausted FIND budget does not forbid a pending DESC_GET
    }
    bool StartFind(unsigned slot,const std::array<std::uint8_t,32>& witness,const udp::Endpoint& endpoint,
        const control::Header& header,const DirectFind& query,const std::array<std::uint8_t,32>& digest,std::uint64_t now) noexcept {
        if(slot>=find_.size() || !Poll(now) || query.file!=file_ || query.fileSize!=size_ || !FreshContext(witness,header)) return false;
        if(find_[slot] && find_[slot]->State()==control::DescriptorRequestState::Pending) return false;
        const auto until=lookup_.FindAuthorization(witness,now); if(!until) return false;
        find_[slot].emplace();
        if(!find_[slot]->Start(witness,endpoint,header,query,digest,maxSize_,now,until)) return false;
        if(!lookup_.ConsumeFindAuthorization(witness,now)) { find_[slot].reset(); return false; }
        findWitness_[slot]=witness;
        findEndpoint_[slot]=endpoint;
        findPacket_[slot].size=0;
        Remember(witness,header); return true;
    }
    bool StartGet(unsigned slot,const std::array<std::uint8_t,32>& witness,const udp::Endpoint& endpoint,
        const control::Header& header,const Locator& locator,std::uint64_t now,std::uint64_t ownerDeadline=0) noexcept {
        if((ownerDeadline && ownerDeadline<=now) || slot>=get_.size() || !Poll(now) || !FreshContext(witness,header) || !HasLocatedSource(witness,endpoint,locator,now)) return false;
        if(get_[slot] && get_[slot]->State()==control::DescriptorRequestState::Pending) return false;
        get_[slot].emplace();
        std::uint64_t generation=0,sourceUntil=0;
        for(const auto& source:sources_) if(source.used && source.witness==witness && source.endpoint==endpoint &&
            source.record.node==locator.node && source.record.digest==locator.digest && source.record.serial==locator.serial) {
                generation=source.record.generation; sourceUntil=source.until;
                getSource_[slot]=source.record; getWitness_[slot]=witness; getEndpoint_[slot]=endpoint; getUntil_[slot]=source.until; break;
            }
        auto until=(sourceUntil<lookup_.Deadline())?sourceUntil:lookup_.Deadline();
        const auto requestUntil=now+((lookup_.Deadline()-now<2000)?lookup_.Deadline()-now:2000);
        if(requestUntil<until) until=requestUntil;
        if(ownerDeadline && ownerDeadline<until) until=ownerDeadline;
        if(!generation || !get_[slot]->Start(witness,endpoint,header,file_,locator,now,until,generation)) return false;
        Remember(witness,header); return true;
    }
    bool StartSignedFind(unsigned slot,const std::array<std::uint8_t,32>& witness,const udp::Endpoint& endpoint,
        const std::array<std::uint8_t,32>& requester,const control::Datagram& packet,std::uint64_t now) noexcept {
        control::Header header; DirectFind query; std::array<std::uint8_t,32> digest{};
        if(packet.size>packet.bytes.size() || !control::VerifyDirectFind(requester,packet.bytes.data(),packet.size,maxSize_,header,query) ||
            !control::DirectFindDigest(requester,packet.bytes.data(),packet.size,maxSize_,digest) ||
            !StartFind(slot,witness,endpoint,header,query,digest,now)) return false;
        findPacket_[slot]=packet; return true;
    }
    bool RetrySignedFind(unsigned slot,std::uint64_t now,control::Datagram& out) noexcept {
        out.size=0;
        if(slot>=findPacket_.size() || !findPacket_[slot].size || !AuthorizeFindRetry(slot,now)) return false;
        out=findPacket_[slot]; return true;
    }
    bool ReceiveFind(unsigned slot,const udp::Endpoint& endpoint,const std::uint8_t* packet,std::size_t size,
        std::uint64_t now,FindResultView& out,control::FindContactsVerifier* contacts=nullptr) noexcept {
        out={};
        if(slot>=find_.size() || !Poll(now) || !find_[slot] || !find_[slot]->Receive(endpoint,packet,size,now,out,contacts)) return false;
        if(out.kind==0 && !RememberSources(out,findWitness_[slot],findEndpoint_[slot],now)) { out={}; Cancel(); return false; }
        lookup_.Complete(findWitness_[slot],now); return true;
    }
    // One authorization costs one transmission, including a failed send.
    // Caller retransmits the exact original signed datagram, not a new request.
    bool AuthorizeFindRetry(unsigned slot,std::uint64_t now) noexcept {
        return slot<find_.size() && Poll(now) && find_[slot] &&
            find_[slot]->State()==control::DescriptorRequestState::Pending && lookup_.Retry(findWitness_[slot],now);
    }
    bool ReceiveGet(unsigned slot,const udp::Endpoint& endpoint,const std::uint8_t* packet,std::size_t size,
        std::uint64_t now,ResultView& out) noexcept {
        out={}; return slot<get_.size() && Poll(now) && get_[slot] && get_[slot]->Receive(endpoint,packet,size,now,out);
    }
    bool ReceiveResolved(unsigned slot,const udp::Endpoint& endpoint,const std::uint8_t* packet,std::size_t size,
        std::uint64_t now,ResolvedCandidate& out) noexcept {
        out={}; ResultView result;
        if(!ReceiveGet(slot,endpoint,packet,size,now,result) || result.status!=0 || result.length>out.descriptor.size()) return false;
        DescriptorView descriptor;
        if(!ParseUntrusted(result.descriptor,result.length,descriptor) ||
            now>(std::numeric_limits<std::uint64_t>::max)()-static_cast<std::uint64_t>(descriptor.ttl)*1000) return false;
        out.source=getSource_[slot]; out.witness=getWitness_[slot]; out.witnessEndpoint=getEndpoint_[slot];
        out.receivedMs=now; out.localGeneration=localGeneration_;
        std::memcpy(out.descriptor.data(),result.descriptor,result.length); out.length=result.length;
        const auto descriptorUntil=now+static_cast<std::uint64_t>(descriptor.ttl)*1000;
        out.until=(descriptorUntil<getUntil_[slot])?descriptorUntil:getUntil_[slot]; return true;
    }
    void Cancel() noexcept {
        stopped_=true; lookup_.Cancel();
        for(auto& request:find_) if(request) request->Cancel(); for(auto& request:get_) if(request) request->Cancel();
    }
    Kad6Lookup& Lookup() noexcept { return lookup_; }
    bool MatchesFile(const std::array<std::uint8_t,16>& file) const noexcept { return started_ && file==file_; }
    bool Query(DirectFind& out,std::uint64_t& maximumSize) const noexcept {
        out={}; maximumSize=0;
        if(!started_ || stopped_) return false;
        out.file=file_; out.fileSize=size_; out.maximum=4; maximumSize=maxSize_; return true;
    }
private:
    struct Source {
        DirectSource record; std::array<std::uint8_t,32> witness{}; udp::Endpoint endpoint;
        std::uint64_t until=0; bool used=false;
    };
    bool HasLocatedSource(const std::array<std::uint8_t,32>& witness,const udp::Endpoint& endpoint,const Locator& locator,std::uint64_t now) const noexcept {
        for(const auto& source:sources_) if(source.used && source.witness==witness && source.endpoint==endpoint &&
            source.record.node==locator.node && source.record.digest==locator.digest && source.record.serial==locator.serial &&
            source.until>now && locator.ttl && locator.ttl<=(source.until-now)/1000) return true;
        return false;
    }
    bool RememberSources(const FindResultView& result,const std::array<std::uint8_t,32>& witness,const udp::Endpoint& endpoint,std::uint64_t now) noexcept {
        // Stage the whole authenticated response: capacity/decoding failure
        // must not publish its first records while rejecting the rest.
        auto staged=sources_;
        for(unsigned i=0;i<result.count;++i) {
            DirectSource record;
            if(!DecodeSource(result.entries[i].bytes,result.entries[i].size,maxSize_,record) ||
                now>(std::numeric_limits<std::uint64_t>::max)()-static_cast<std::uint64_t>(result.entries[i].remainingTtl)*1000) return false;
            Source* chosen=nullptr;
            for(auto& source:staged) if(source.used && source.witness==witness && source.record.node==record.node &&
                source.record.generation==record.generation) { chosen=&source; break; }
            if(chosen && record.serial<=chosen->record.serial) continue; // duplicate/stale cannot renew TTL
            if(!chosen) {
                unsigned witnesses=0;
                bool alreadyKnown=false;
                std::array<std::array<std::uint8_t,32>,3> unique{};
                for(const auto& source:staged) if(source.used && source.until>now && source.record.node==record.node) {
                    if(source.witness==witness) alreadyKnown=true;
                    bool duplicate=false;
                    for(unsigned j=0;j<witnesses;++j) if(unique[j]==source.witness) duplicate=true;
                    if(!duplicate && witnesses<unique.size()) unique[witnesses++]=source.witness;
                }
                if(!alreadyKnown && witnesses>=3) continue; // A fourth W cannot crowd out other sources.
                for(auto& source:staged) if(!source.used || source.until<=now) { chosen=&source; break; }
            }
            if(!chosen) return false;
            *chosen={record,witness,endpoint,now+static_cast<std::uint64_t>(result.entries[i].remainingTtl)*1000,true};
        }
        sources_=staged;
        return true;
    }
    std::array<Source,32> sources_{};
    // Borrowed shared owner must outlive this resolution; cancellation does not
    // record expiry. No persistence or trust derives from cooldown metadata.
    ResolutionCooldown<>* cooldown_=nullptr;
    ResolutionCooldown<>::Key source_{}; std::uint64_t topology_=0;
    struct Context { std::array<std::uint8_t,32> witness{}; control::Header header; };
    bool FreshContext(const std::array<std::uint8_t,32>& witness,const control::Header& header) const noexcept {
        if(contextCount_==contexts_.size()) return false;
        for(unsigned i=0;i<contextCount_;++i) {
            const auto& old=contexts_[i];
            if(old.witness==witness && old.header.attempt==header.attempt && old.header.generation==header.generation &&
                old.header.sequence==header.sequence && old.header.type==header.type) return false;
        }
        return true;
    }
    void Remember(const std::array<std::uint8_t,32>& witness,const control::Header& header) noexcept {
        contexts_[contextCount_++]={witness,header};
    }
    std::array<Context,32> contexts_{}; unsigned contextCount_=0;
    Kad6Lookup lookup_;
    std::array<std::optional<control::DirectFindRequest>,2> find_{};
    std::array<std::array<std::uint8_t,32>,2> findWitness_{};
    std::array<udp::Endpoint,2> findEndpoint_{};
    std::array<control::Datagram,2> findPacket_{};
    std::array<std::optional<control::DescriptorRequest>,4> get_{};
    std::array<DirectSource,4> getSource_{};
    std::array<std::array<std::uint8_t,32>,4> getWitness_{};
    std::array<udp::Endpoint,4> getEndpoint_{};
    std::array<std::uint64_t,4> getUntil_{};
    std::array<std::uint8_t,16> file_{};
    std::uint64_t size_=0,maxSize_=0,last_=0,localGeneration_=0;
    bool started_=false,stopped_=false;
};
} }
