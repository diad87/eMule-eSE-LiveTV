#pragma once
#include "EseControlCookieCrypto.h"
#include "EseControlSessions.h"
#include "kad6/kad6_records.h"
namespace ese { namespace control {
inline bool VerifySelfContact(const std::array<std::uint8_t,32>& witness,const std::uint8_t* bytes,std::size_t size,
    const kad6::Kad6CryptoHooks& crypto,std::uint64_t nowUnix,kad6::K6RouterRecord& out) noexcept {
    out={};
    try {
        kad6::K6RouterRecord record; std::size_t consumed=0;
        if(!nowUnix || !bytes || size<kad6::kK6RouterRecordMinSize || size>kad6::kK6RouterRecordMaxSize ||
            kad6::DecodeK6RouterRecord(bytes,size,record,&consumed)!=kad6::Kad6Status::Ok || consumed!=size || record.node_pub!=witness ||
            kad6::VerifyK6RouterRecord(crypto,record)!=kad6::Kad6Status::Ok || kad6::K6RouterRecordCheckFresh(record,nowUnix)!=kad6::Kad6Status::Ok) return false;
        for(const auto& endpoint:record.endpoints) if(endpoint.valid_until<=nowUnix) return false;
        out=std::move(record); return true;
    } catch(...) { return false; }
}
inline bool VerifyContactResult(const std::array<std::uint8_t,32>& witness,const Header& original,
    const std::array<std::uint8_t,32>& requester,const std::array<std::uint8_t,32>& digest,
    const std::uint8_t* bytes,std::size_t size,const kad6::Kad6CryptoHooks& crypto,std::uint64_t nowUnix,
    kad6::K6RouterRecord& out) noexcept {
    out={}; Envelope envelope;
    if(original.type!=wire::kEseWireUdpK6ContactGet || !ParseUntrusted(bytes,size,envelope) ||
        envelope.header.type!=wire::kEseWireUdpK6ContactResult || envelope.header.attempt!=original.attempt ||
        envelope.header.generation!=original.generation || envelope.header.sequence!=original.sequence ||
        !original.generation || !original.sequence || envelope.payloadSize<130 ||
        std::memcmp(envelope.payload,requester.data(),32) || std::memcmp(envelope.payload+32,digest.data(),32) ||
        !VerifyEnvelopeSignature(witness,bytes,size)) return false;
    unsigned attempt=0; for(auto b:original.attempt) attempt|=b; if(!attempt) return false;
    const auto length=static_cast<std::size_t>(discovery::ReadBe(envelope.payload+64,2));
    return envelope.payloadSize==130+length && VerifySelfContact(witness,envelope.payload+66,length,crypto,nowUnix,out);
}
inline bool BuildContactResult(const Header& original,const std::array<std::uint8_t,32>& requester,
    const std::array<std::uint8_t,32>& digest,const std::uint8_t* record,std::size_t size,
    const std::array<std::uint8_t,32>& witness,Signer& signer,const kad6::Kad6CryptoHooks& crypto,
    std::uint64_t nowUnix,Datagram& out) noexcept {
    out.size=0; kad6::K6RouterRecord checked;
    if(!VerifySelfContact(witness,record,size,crypto,nowUnix,checked)) return false;
    std::array<std::uint8_t,130+kad6::kK6RouterRecordMaxSize> body{};
    std::memcpy(body.data(),requester.data(),32); std::memcpy(body.data()+32,digest.data(),32);
    body[64]=static_cast<std::uint8_t>(size>>8); body[65]=static_cast<std::uint8_t>(size);
    std::memcpy(body.data()+66,record,size);
    auto header=original; header.type=wire::kEseWireUdpK6ContactResult;
    Datagram packet; SignatureInput input; std::array<std::uint8_t,64> signature{};
    if(!Encode(header,body.data(),130+size,packet) || !BuildSignatureInput(packet.bytes.data(),packet.size,input) ||
        !signer.Sign(input.bytes.data(),input.size,signature)) return false;
    std::memcpy(packet.bytes.data()+packet.size-64,signature.data(),64);
    if(!VerifyContactResult(witness,original,requester,digest,packet.bytes.data(),packet.size,crypto,nowUnix,checked)) return false;
    out=packet; return true;
}
class ContactRefreshRequest {
public:
    bool Start(const std::array<std::uint8_t,32>& witness,const udp::Endpoint& endpoint,
        const std::array<std::uint8_t,32>& requester,const Datagram& get,std::uint64_t now,std::uint64_t resolutionDeadline) noexcept {
        unsigned key=0; for(auto b:witness) key|=b;
        Header header; std::array<std::uint8_t,32> digest{};
        if(state_!=DescriptorRequestState::Idle || !key || !endpoint.port || get.size>get.bytes.size() ||
            now>(std::numeric_limits<std::uint64_t>::max)()-2000 || resolutionDeadline<=now ||
            !VerifyContactGet(requester,get.bytes.data(),get.size,header) || !ContactGetDigest(requester,get.bytes.data(),get.size,digest)) return false;
        witness_=witness; endpoint_=endpoint; requester_=requester; digest_=digest; header_=header;
        last_=now; until_=(resolutionDeadline<now+2000)?resolutionDeadline:now+2000; state_=DescriptorRequestState::Pending; return true;
    }
    bool Receive(const udp::Endpoint& endpoint,const std::uint8_t* bytes,std::size_t size,std::uint64_t now,
        const kad6::Kad6CryptoHooks& crypto,std::uint64_t nowUnix,kad6::K6RouterRecord& out) noexcept {
        out={};
        if(!Poll(now) || !(endpoint==endpoint_) || !VerifyContactResult(witness_,header_,requester_,digest_,bytes,size,crypto,nowUnix,out)) return false;
        state_=DescriptorRequestState::Complete; return true;
    }
    bool ReceiveInSession(const Sessions& sessions,const udp::Endpoint& endpoint,
        const std::uint8_t* bytes,std::size_t size,std::uint64_t now,
        const kad6::Kad6CryptoHooks& crypto,std::uint64_t nowUnix,kad6::K6RouterRecord& out) noexcept {
        out={};
        if(!sessions.Current(witness_,endpoint,header_,now)) return false;
        return Receive(endpoint,bytes,size,now,crypto,nowUnix,out);
    }
    bool Poll(std::uint64_t now) noexcept {
        if(state_!=DescriptorRequestState::Pending) return false;
        if(now<last_ || now>=until_) { state_=DescriptorRequestState::Failed; return false; }
        last_=now; return true;
    }
    void Cancel() noexcept { state_=DescriptorRequestState::Failed; }
    DescriptorRequestState State() const noexcept { return state_; }
private:
    std::array<std::uint8_t,32> witness_{},requester_{},digest_{}; udp::Endpoint endpoint_; Header header_;
    std::uint64_t last_=0,until_=0; DescriptorRequestState state_=DescriptorRequestState::Idle;
};
} }
