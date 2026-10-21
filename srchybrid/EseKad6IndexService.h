#pragma once
#include "EseKad6FindContacts.h"
#include "EseKad6ContactRefresh.h"
#include "EseWitnessDescriptors.h"
#include "EseKad6ServiceCapabilities.h"
#include <memory>
namespace ese { namespace discovery {
enum class IndexDispatch { Rejected, Silent, Reply };
struct IndexNeighbors {
    virtual ~IndexNeighbors()=default;
    virtual bool Find(const DirectFind&,std::array<FindEntryView,4>&,std::uint8_t&) noexcept=0;
};
// Shared-socket owner must resolve the expected peer from its authenticated
// exact-endpoint session, not from packet fields. This receiver does not grant
// a data route or advertise its service. Allocate it on the heap.
template<std::size_t Capacity=10000> class Kad6IndexService {
public:
    explicit Kad6IndexService(control::PacketBudget& budget)
        : requests_(budget),descriptorPuts_(budget),store_(std::make_unique<Store>()) {}
    IndexDispatch Receive(control::Sessions& sessions,const std::array<std::uint8_t,32>& peer,
        const udp::Endpoint& endpoint,const std::uint8_t* bytes,std::size_t size,
        std::uint64_t maxFileSize,std::uint64_t now,const std::array<std::uint8_t,32>& local,
        control::Signer& signer,control::Datagram& response,
        const std::uint8_t* selfContact=nullptr,std::size_t selfContactSize=0,
        const kad6::Kad6CryptoHooks* crypto=nullptr,std::uint64_t nowUnix=0,
        IndexNeighbors* neighbors=nullptr) noexcept {
        response={}; control::Envelope envelope;
        if((haveTime_ && now<last_) || now>(std::numeric_limits<std::uint64_t>::max)()-5000 ||
            !control::ParseUntrusted(bytes,size,envelope) || !sessions.Current(peer,endpoint,envelope.header,now))
            return IndexDispatch::Rejected;
        haveTime_=true; last_=now;
        Memo* available=nullptr;
        for(auto& memo:replies_) {
            if(memo.used && now>=memo.until && now>=memo.deferredUntil) memo={};
            if(memo.used && now<memo.until && memo.peer==peer && memo.endpoint==endpoint && memo.request.size==size &&
                !std::memcmp(memo.request.bytes.data(),bytes,size)) {
                response=memo.response;
                return response.size ? IndexDispatch::Reply : IndexDispatch::Silent;
            }
            if(!memo.used && !available) available=&memo;
        }
        // Saturation is rejected before replay admission or storage mutation.
        if(!available) return IndexDispatch::Rejected;
        control::Header header; bool accepted=false,waitingDescriptor=false,descriptorLimit=false;
        switch(envelope.header.type) {
        case wire::kEseWireUdpDescriptorPut: {
            PutView publication; std::array<std::uint8_t,32> digest{};
            if(!control::AdmitDescriptorPut(sessions,endpoint,peer,bytes,size,now,header,publication,digest) ||
                !descriptorPuts_.AllowPut(peer,now)) return IndexDispatch::Rejected;
            const auto result=store_->PutVerified(publication.file,publication.descriptor,publication.length,digest,endpoint,0,now);
            descriptorLimit=result==StoreResult::Limit;
            accepted=descriptorLimit || result==StoreResult::Stored || result==StoreResult::Provisional || result==StoreResult::Duplicate;
            DirectSource staged; DescriptorView descriptor;
            if(accepted && !descriptorLimit && ParseUntrusted(publication.descriptor,publication.length,descriptor)) {
                staged.file=publication.file; staged.node=descriptor.node; staged.digest=digest;
                staged.generation=descriptor.generation; staged.serial=descriptor.serial;
                if(store_->Get(staged.file,staged.node,staged.digest,now).bytes)
                    accepted=DescriptorAck(header,staged,now,local,signer,response);
                else waitingDescriptor=true;
            }
            // No premature DESC_RESULT: the publisher sends DIRECT_PUT without
            // waiting, and only its coherent STORED response confirms indexing.
            break;
        }
        case wire::kEseWireUdpK6DirectPut: {
            DirectSource source;
            if(!control::AdmitDirectPut(sessions,endpoint,peer,bytes,size,maxFileSize,now,header,source))
                return IndexDispatch::Rejected;
            std::uint8_t status=2; // LIMIT; rate failure consumes its sequence
            if(requests_.AllowPut(peer,now)) {
                bool limited=false;
                for(const auto& memo:replies_) if(memo.used && memo.descriptorLimit && now<memo.deferredUntil &&
                    MatchesDescriptor(memo,peer,endpoint,source)) limited=true;
                if(!limited) {
                const auto result=store_->DirectSourceVerified(envelope.payload,173,maxFileSize,now);
                switch(result) {
                case SourceStoreResult::Stored: case SourceStoreResult::Duplicate: status=0; break;
                case SourceStoreResult::NeedDescriptor: status=1; break;
                case SourceStoreResult::Stale: case SourceStoreResult::Conflict: status=3; break;
                default: return IndexDispatch::Rejected;
                }
                }
            }
            accepted=control::BuildDirectPutResult(header,status,source,maxFileSize,local,signer,response);
            if(accepted && status==0) for(auto& memo:replies_) if(memo.used && memo.waitingDescriptor &&
                now<memo.deferredUntil && MatchesDescriptor(memo,peer,endpoint,source)) {
                control::Envelope original;
                if(control::ParseUntrusted(memo.request.bytes.data(),memo.request.size,original) &&
                    sessions.Current(peer,endpoint,original.header,now) &&
                    DescriptorAck(original.header,source,now,local,signer,memo.response)) {
                    memo.waitingDescriptor=false; memo.secondary=true;
                }
            }
            break;
        }
        case wire::kEseWireUdpK6DirectFind: {
            DirectFind query; std::array<std::uint8_t,32> digest{}; FoundSources found;
            if(!control::AdmitDirectFind(sessions,requests_,endpoint,peer,bytes,size,maxFileSize,now,header,query) ||
                !control::DirectFindDigest(peer,bytes,size,maxFileSize,digest) ||
                !store_->Find(query.file,query.fileSize,query.maximum,now,found)) return IndexDispatch::Rejected;
            std::array<FindEntryView,4> entries{};
            for(unsigned i=0;i<found.count;++i) entries[i]={found.records[i].data(),173,found.remainingTtl[i]};
            std::array<FindEntryView,4> closer{}; std::uint8_t closerCount=0;
            // Resolve neighbors only after authentication, replay and quota admission.
            if(!found.count && neighbors && crypto && nowUnix && neighbors->Find(query,closer,closerCount) && closerCount) {
                control::Kad6FindContacts verifier(*crypto,K6_CAP_DIRECT_INDEX_V1,nowUnix);
                accepted=control::BuildDirectFindCloserResult(header,query,digest,closer,
                    (std::min)(closerCount,query.maximum),maxFileSize,local,signer,verifier,response);
            } else accepted=control::BuildDirectFindSourcesResult(header,query,digest,entries,
                static_cast<std::uint8_t>(found.count),maxFileSize,local,signer,response);
            break;
        }
        case wire::kEseWireUdpDescriptorGet: {
            GetView query;
            if(!control::AdmitDescriptorGet(sessions,requests_,endpoint,peer,bytes,size,now,header,query))
                return IndexDispatch::Rejected;
            const auto stored=store_->Get(query.file,query.node,query.digest,now);
            Locator locator; locator.node=query.node; locator.digest=query.digest; locator.ttl=1;
            if(stored.bytes) {
                DescriptorView descriptor;
                if(!ParseUntrusted(stored.bytes,stored.size,descriptor)) return IndexDispatch::Rejected;
                locator.serial=descriptor.serial;
            }
            header.type=wire::kEseWireUdpDescriptorResult;
            accepted=control::BuildDescriptorResult(header,stored.bytes ? 0 : 1,query.file,locator,
                stored.bytes,stored.size,local,signer,response);
            break;
        }
        case wire::kEseWireUdpK6ContactGet: {
            std::array<std::uint8_t,32> digest{};
            if(!crypto || !control::AdmitContactGet(sessions,requests_,endpoint,peer,bytes,size,now,header) ||
                !control::ContactGetDigest(peer,bytes,size,digest)) return IndexDispatch::Rejected;
            accepted=control::BuildContactResult(header,peer,digest,selfContact,selfContactSize,
                local,signer,*crypto,nowUnix,response);
            break;
        }
        default: return IndexDispatch::Rejected;
        }
        if(!accepted) { response={}; return IndexDispatch::Rejected; }
        available->peer=peer; available->endpoint=endpoint; available->request.size=size;
        std::memcpy(available->request.bytes.data(),bytes,size); available->response=response;
        available->until=now+2000; available->used=true;
        available->waitingDescriptor=waitingDescriptor; available->descriptorLimit=descriptorLimit;
        available->deferredUntil=(waitingDescriptor || descriptorLimit) ? now+5000 : 0;
        return response.size ? IndexDispatch::Reply : IndexDispatch::Silent;
    }
    std::size_t ChargedBytes() const noexcept { return sizeof(*this)+store_->ChargedBytes(); }
    bool PopSecondary(control::Sessions& sessions,std::uint64_t now,udp::Endpoint& endpoint,control::Datagram& response) noexcept {
        response={}; endpoint={};
        if(haveTime_ && now<last_) return false;
        for(auto& memo:replies_) if(memo.used && memo.secondary) {
            memo.secondary=false; control::Envelope original;
            const bool current=now<memo.deferredUntil &&
                control::ParseUntrusted(memo.request.bytes.data(),memo.request.size,original) &&
                sessions.Current(memo.peer,memo.endpoint,original.header,now);
            memo.deferredUntil=0;
            if(current) { endpoint=memo.endpoint; response=memo.response; return true; }
        }
        return false;
    }
private:
    // Reserve space for this receiver, service classifier and correlated
    // bootstrap state, not merely stored descriptor payloads.
    static constexpr std::size_t MetadataReserve=512*1024;
    using Store=WitnessDescriptors<Capacity,8*1024*1024-MetadataReserve>;
    struct Memo { std::array<std::uint8_t,32> peer{}; udp::Endpoint endpoint;
        control::Datagram request,response; std::uint64_t until=0,deferredUntil=0;
        bool used=false,waitingDescriptor=false,descriptorLimit=false,secondary=false; };
    static bool MatchesDescriptor(const Memo& memo,const std::array<std::uint8_t,32>& peer,
        const udp::Endpoint& endpoint,const DirectSource& source) noexcept {
        control::Envelope original; PutView publication; DescriptorView descriptor;
        std::array<std::uint8_t,32> digest{};
        return memo.peer==peer && memo.endpoint==endpoint &&
            control::ParseUntrusted(memo.request.bytes.data(),memo.request.size,original) &&
            original.header.type==wire::kEseWireUdpDescriptorPut &&
            DecodePut(original.payload,original.payloadSize,publication) && publication.file==source.file &&
            ParseUntrusted(publication.descriptor,publication.length,descriptor) && descriptor.node==source.node &&
            descriptor.generation==source.generation && descriptor.serial==source.serial &&
            control::DescriptorDigest(publication.descriptor,publication.length,digest) && digest==source.digest;
    }
    bool DescriptorAck(control::Header header,const DirectSource& source,std::uint64_t now,
        const std::array<std::uint8_t,32>& local,control::Signer& signer,control::Datagram& response) noexcept {
        const auto stored=store_->Get(source.file,source.node,source.digest,now);
        if(!stored.bytes || stored.deadline<=now || (stored.deadline-now)/1000==0) return false;
        Locator locator; locator.node=source.node; locator.digest=source.digest; locator.serial=source.serial;
        locator.ttl=static_cast<std::uint32_t>((stored.deadline-now)/1000);
        header.type=wire::kEseWireUdpDescriptorResult;
        return control::BuildDescriptorResult(header,0,source.file,locator,stored.bytes,stored.size,local,signer,response);
    }
    std::array<Memo,64> replies_{};
    control::DescriptorGetLimit<> requests_,descriptorPuts_;
    std::unique_ptr<Store> store_;
    std::uint64_t last_=0; bool haveTime_=false;
};
static_assert(sizeof(Kad6IndexService<>)<=256*1024,"index receiver metadata reservation");
} }
