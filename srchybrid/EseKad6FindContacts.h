#pragma once
#include "EseControlCookieCrypto.h"
#include "EseKad6Lookup.h"
#include "kad6/kad6_records.h"
namespace ese { namespace control {
// Construct per response with current Unix time and the registered signed
// router capability bit. No implicit assignment/advertisement of that bit.
class Kad6FindContacts final : public FindContactsVerifier {
public:
    Kad6FindContacts(const kad6::Kad6CryptoHooks& crypto,std::uint64_t directIndexBit,
        std::uint64_t nowUnix) noexcept : crypto_(crypto),bit_(directIndexBit),now_(nowUnix) {}
    bool Verify(const discovery::FindResultView& result,const std::array<std::uint8_t,32>& witness) noexcept override {
        if(result.kind!=1 || !result.count || result.count>2 || !bit_ || (bit_&(bit_-1)) || !now_) return false;
        try {
            std::array<kad6::K6RouterRecord,2> records;
            for(unsigned i=0;i<result.count;++i) {
                const auto& entry=result.entries[i]; std::size_t consumed=0;
                if(!entry.bytes || entry.size<kad6::kK6RouterRecordMinSize || entry.size>kad6::kK6RouterRecordMaxSize ||
                    kad6::DecodeK6RouterRecord(entry.bytes,entry.size,records[i],&consumed)!=kad6::Kad6Status::Ok || consumed!=entry.size ||
                    !(records[i].caps&bit_) || records[i].node_pub==witness ||
                    kad6::VerifyK6RouterRecord(crypto_,records[i])!=kad6::Kad6Status::Ok ||
                    kad6::K6RouterRecordCheckFresh(records[i],now_)!=kad6::Kad6Status::Ok) return false;
                for(const auto& endpoint:records[i].endpoints) if(endpoint.valid_until<=now_) return false;
                for(unsigned j=0;j<i;++j) if(records[i].node_pub==records[j].node_pub || records[i].kad_id==records[j].kad_id) return false;
            }
            return true;
        } catch(...) { return false; }
    }
private:
    kad6::Kad6CryptoHooks crypto_;
    std::uint64_t bit_,now_;
};
// Preserve the original signed Kad6 bytes; only the outer envelope is ours.
inline bool BuildDirectFindCloserResult(const Header& original,const discovery::DirectFind& query,
    const std::array<std::uint8_t,32>& digest,const std::array<discovery::FindEntryView,4>& entries,
    std::uint8_t count,std::uint64_t maxFileSize,const std::array<std::uint8_t,32>& witness,
    Signer& signer,Kad6FindContacts& contacts,Datagram& out) noexcept {
    out.size=0; std::array<std::uint8_t,121> checked{};
    if(original.type!=wire::kEseWireUdpK6DirectFind || !count || count>2 || count>query.maximum ||
        !discovery::EncodeFind(query,maxFileSize,checked)) return false;
    discovery::FindResultView candidates; candidates.kind=1; candidates.count=count; candidates.entries=entries;
    if(!contacts.Verify(candidates,witness)) return false;
    std::array<std::uint8_t,1160> body{}; body[0]=1;
    std::memcpy(body.data()+1,query.file.data(),16); std::memcpy(body.data()+25,query.requester.data(),32);
    std::memcpy(body.data()+57,digest.data(),32); body[89]=count;
    for(unsigned i=0;i<8;++i) body[17+i]=static_cast<std::uint8_t>(query.fileSize>>(56-8*i));
    std::size_t offset=90;
    for(unsigned i=0;i<count;++i) {
        if(entries[i].size>body.size()-offset-66) return false;
        body[offset]=static_cast<std::uint8_t>(entries[i].size>>8);
        body[offset+1]=static_cast<std::uint8_t>(entries[i].size);
        std::memcpy(body.data()+offset+2,entries[i].bytes,entries[i].size); offset+=2+entries[i].size;
    }
    auto header=original; header.type=wire::kEseWireUdpK6DirectFindResult;
    Datagram packet; SignatureInput input; std::array<std::uint8_t,64> signature{};
    if(!Encode(header,body.data(),offset+64,packet) || !BuildSignatureInput(packet.bytes.data(),packet.size,input) ||
        !signer.Sign(input.bytes.data(),input.size,signature)) return false;
    std::memcpy(packet.bytes.data()+packet.size-64,signature.data(),64);
    discovery::FindResultView verified;
    if(!VerifyDirectFindResultSignature(witness,original,query,digest,packet.bytes.data(),packet.size,maxFileSize,verified) ||
        !contacts.Verify(verified,witness)) return false;
    out=packet; return true;
}
// Authenticate/correlate the complete response before exposing any identity to
// the scheduler. The returned borrowed records remain owned by packet bytes;
// host must retain/revalidate them and prove return before scheduling FIND.
inline bool ReceiveCloserAndQueue(DirectFindRequest& pending,discovery::Kad6Lookup& lookup,
    const udp::Endpoint& endpoint,const std::uint8_t* bytes,std::size_t size,std::uint64_t now,
    Kad6FindContacts& verifier,discovery::FindResultView& out,unsigned& added) noexcept {
    out={}; added=0;
    if(!lookup.Poll(now)) return false;
    discovery::FindResultView result;
    if(!pending.Receive(endpoint,bytes,size,now,result,&verifier)) return false;
    if(result.kind!=1) { out=result; return true; }
    try {
        std::array<discovery::Kad6Lookup::Contact,2> contacts{};
        for(unsigned i=0;i<result.count;++i) {
            kad6::K6RouterRecord record; std::size_t consumed=0;
            if(kad6::DecodeK6RouterRecord(result.entries[i].bytes,result.entries[i].size,record,&consumed)!=kad6::Kad6Status::Ok ||
                consumed!=result.entries[i].size) return false;
            contacts[i].id=record.kad_id; contacts[i].node=record.node_pub;
        }
        for(unsigned i=0;i<result.count;++i) if(lookup.AddValidatedRecord(contacts[i],now)) ++added;
        out=result; return true;
    } catch(...) { return false; }
}
} }
