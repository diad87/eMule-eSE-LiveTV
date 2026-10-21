#ifndef ESE_CONTROL_CRYPTO_STANDALONE
#include "stdafx.h"
#endif
#include "EseControlCookieCrypto.h"
#include "LiveCrypto.h"
#include "../cryptopp/hmac.h"
#include "../cryptopp/sha.h"
#include "../cryptopp/osrng.h"
#include "../cryptopp/misc.h"
namespace ese { namespace control {
bool VerifyContactGet(const std::array<std::uint8_t,32>& requester,const std::uint8_t* bytes,std::size_t size,Header& out) noexcept {
    out={}; Envelope envelope; unsigned attempt=0;
    if(!ParseUntrusted(bytes,size,envelope) || envelope.header.type!=wire::kEseWireUdpK6ContactGet || envelope.payloadSize!=96 ||
        std::memcmp(envelope.payload,requester.data(),32) || !envelope.header.generation || !envelope.header.sequence) return false;
    for(auto b:envelope.header.attempt) attempt|=b;
    if(!attempt || !VerifyEnvelopeSignature(requester,bytes,size)) return false;
    out=envelope.header; return true;
}
bool BuildContactGet(const Header& header,const std::array<std::uint8_t,32>& requester,Signer& signer,Datagram& out) noexcept {
    out.size=0; if(header.type!=wire::kEseWireUdpK6ContactGet) return false;
    std::array<std::uint8_t,96> body{}; std::memcpy(body.data(),requester.data(),32);
    Datagram packet; SignatureInput input; std::array<std::uint8_t,64> signature{}; Header checked;
    if(!Encode(header,body.data(),body.size(),packet) || !BuildSignatureInput(packet.bytes.data(),packet.size,input) ||
        !signer.Sign(input.bytes.data(),input.size,signature)) return false;
    std::memcpy(packet.bytes.data()+packet.size-64,signature.data(),64);
    if(!VerifyContactGet(requester,packet.bytes.data(),packet.size,checked)) return false;
    out=packet; return true;
}
bool ContactGetDigest(const std::array<std::uint8_t,32>& requester,const std::uint8_t* bytes,std::size_t size,
    std::array<std::uint8_t,32>& out) noexcept {
    out={}; Header header; if(!VerifyContactGet(requester,bytes,size,header)) return false;
    try { CryptoPP::SHA256 hash; hash.CalculateDigest(out.data(),bytes+40,96); return true; }
    catch(...) { out={}; return false; }
}
bool DirectIndexKey(const std::array<std::uint8_t,16>& file,std::uint64_t fileSize,
    std::uint64_t maxFileSize,std::array<std::uint8_t,16>& out) noexcept {
    out={}; if(!fileSize || fileSize>maxFileSize) return false;
    std::array<std::uint8_t,8> size{};
    for(unsigned i=0;i<8;++i) size[i]=static_cast<std::uint8_t>(fileSize>>(56-8*i));
    try {
        CryptoPP::SHA256 hash; std::array<std::uint8_t,32> digest{};
        hash.Update(reinterpret_cast<const std::uint8_t*>(wire::kEseWireKad6DirectIndexDomain),sizeof(wire::kEseWireKad6DirectIndexDomain));
        hash.Update(file.data(),file.size()); hash.Update(size.data(),size.size()); hash.Final(digest.data());
        std::memcpy(out.data(),digest.data(),out.size()); return true;
    } catch(...) { out={}; return false; }
}
bool VerifyEnvelopeSignature(const std::array<std::uint8_t,32>& expectedSigner,
    const std::uint8_t* packet,std::size_t size) noexcept {
    SignatureInput message;
    if(!BuildSignatureInput(packet,size,message)) return false;
    unsigned nonzero=0; for(auto byte:expectedSigner) nonzero|=byte;
    if(!nonzero) return false;
    try { return eSELive::VerifySignature(expectedSigner.data(),message.bytes.data(),message.size,packet+size-64); }
    catch(...) { return false; }
}
bool DescriptorDigest(const std::uint8_t* packet,std::size_t size,std::array<std::uint8_t,32>& out) noexcept {
    out={}; discovery::DescriptorView descriptor;
    if(!discovery::ParseUntrusted(packet,size,descriptor)) return false;
    try { CryptoPP::SHA256 hash; hash.CalculateDigest(out.data(),packet,size); return true; }
    catch(...) { out={}; return false; }
}
bool VerifyDescriptor(const std::array<std::uint8_t,32>& node,const std::array<std::uint8_t,32>& digest,
    const std::uint8_t* packet,std::size_t size,discovery::DescriptorView& out) noexcept {
    out={}; discovery::DescriptorView descriptor; discovery::DescriptorSignatureInput message;
    std::array<std::uint8_t,32> actual{};
    if(!discovery::ParseUntrusted(packet,size,descriptor) || descriptor.node!=node ||
        !DescriptorDigest(packet,size,actual) || !CryptoPP::VerifyBufsEqual(actual.data(),digest.data(),digest.size()) ||
        !discovery::BuildSignatureInput(packet,size,message)) return false;
    unsigned nonzero=0; for(auto byte:node) nonzero|=byte;
    if(!nonzero) return false;
    try {
        if(!eSELive::VerifySignature(node.data(),message.bytes.data(),message.size,descriptor.signature)) return false;
        out=descriptor; return true;
    } catch(...) { return false; }
}
bool VerifyDescriptorResult(const std::array<std::uint8_t,32>& witness,
    const Header& request,const std::array<std::uint8_t,16>& file,
    const discovery::Locator& locator,const std::uint8_t* packet,std::size_t size,
    discovery::ResultView& out) noexcept {
    out={}; Envelope envelope; discovery::ResultView result;
    if(!locator.ttl || locator.ttl>120 || !ParseUntrusted(packet,size,envelope) ||
        envelope.header.type!=wire::kEseWireUdpDescriptorResult ||
        envelope.header.attempt!=request.attempt || envelope.header.sequence!=request.sequence ||
        envelope.header.generation!=request.generation ||
        !discovery::DecodeResult(envelope.payload,envelope.payloadSize,result) ||
        result.file!=file || result.node!=locator.node || result.digest!=locator.digest ||
        !VerifyEnvelopeSignature(witness,packet,size)) return false;
    if(result.status==0) {
        discovery::DescriptorView descriptor;
        if(!VerifyDescriptor(locator.node,locator.digest,result.descriptor,result.length,descriptor) ||
            descriptor.serial!=locator.serial) return false;
    }
    out=result; return true;
}
bool ComputeCookie(const std::array<std::uint8_t,32>& secret,const udp::Endpoint& source,
    const CookieProof& proof,const std::array<std::uint8_t,32>& signer,
    std::array<std::uint8_t,16>& out) noexcept {
    out={}; CookieInput input;
    if(!BuildCookieInput(source,proof,signer,input)) return false;
    try {
        CryptoPP::HMAC<CryptoPP::SHA256> hmac(secret.data(),secret.size());
        hmac.Update(input.bytes.data(),input.bytes.size());
        hmac.TruncatedFinal(out.data(),out.size()); return true;
    } catch(...) { out={}; return false; }
}
CookieAuthority::~CookieAuthority() { CryptoPP::SecureWipeBuffer(secret_.data(),secret_.size()); }
bool CookieAuthority::Initialize() noexcept {
    if(initialized_) return true;
    try {
        CryptoPP::AutoSeededRandomPool random;
        random.GenerateBlock(secret_.data(),secret_.size()); initialized_=true; return true;
    } catch(...) { CryptoPP::SecureWipeBuffer(secret_.data(),secret_.size()); return false; }
}
bool CookieAuthority::Issue(const udp::Endpoint& source,CookieProof& proof,
    const std::array<std::uint8_t,32>& signer,std::uint64_t now) noexcept {
    proof.cookie={};
    if(!initialized_ || !CurrentEpoch(now,proof.epoch)) return false;
    return ComputeCookie(secret_,source,proof,signer,proof.cookie);
}
bool CookieAuthority::Verify(const udp::Endpoint& source,const CookieProof& proof,
    const std::array<std::uint8_t,32>& signer,std::uint64_t now) const noexcept {
    std::uint32_t epoch=0; std::array<std::uint8_t,16> expected{};
    if(!initialized_ || !CurrentEpoch(now,epoch) || !AcceptEpoch(proof.epoch,epoch) ||
        !ComputeCookie(secret_,source,proof,signer,expected)) return false;
    return CryptoPP::VerifyBufsEqual(expected.data(),proof.cookie.data(),expected.size());
}
bool VerifyProve(const CookieAuthority& authority,const udp::Endpoint& source,
    const std::array<std::uint8_t,32>& local,const std::array<std::uint8_t,32>& peer,
    const std::uint8_t* packet,std::size_t size,std::uint64_t now,Prove& out) noexcept {
    out={}; Envelope envelope; Prove proof;
    if(!ParseUntrusted(packet,size,envelope) || envelope.header.type!=wire::kEseWireUdpProve ||
        !Decode(envelope.payload,envelope.payloadSize,proof) || proof.probe.node!=peer ||
        proof.probe.peer!=local || !envelope.header.generation) return false;
    unsigned attempt=0,nonce=0,localNonzero=0;
    for(auto byte:envelope.header.attempt) attempt|=byte;
    for(auto byte:proof.probe.nonce) nonce|=byte;
    for(auto byte:local) localNonzero|=byte;
    if(!attempt || !nonce || !localNonzero) return false;
    CookieProof cookie; cookie.attempt=envelope.header.attempt;
    cookie.generation=envelope.header.generation; cookie.nonce=proof.probe.nonce;
    cookie.cookie=proof.cookie; cookie.epoch=proof.epoch;
    if(!authority.Verify(source,cookie,peer,now) || !VerifyEnvelopeSignature(peer,packet,size)) return false;
    out=proof; return true;
}
bool BuildChallenge(CookieAuthority& authority,ChallengeLimit& limit,const udp::Endpoint& source,
    const std::array<std::uint8_t,32>& local,const std::array<std::uint8_t,32>& peer,
    const std::uint8_t* packet,std::size_t size,std::uint64_t now,Datagram& out) noexcept {
    out.size=0; Envelope envelope; Probe probe;
    if(!ParseUntrusted(packet,size,envelope) || envelope.header.type!=wire::kEseWireUdpProbe ||
        !Decode(envelope.payload,envelope.payloadSize,probe) || probe.node!=peer ||
        probe.peer!=local || !envelope.header.generation) return false;
    unsigned attempt=0,nonce=0,localNonzero=0,peerNonzero=0;
    for(auto byte:envelope.header.attempt) attempt|=byte;
    for(auto byte:probe.nonce) nonce|=byte;
    for(auto byte:local) localNonzero|=byte;
    for(auto byte:peer) peerNonzero|=byte;
    if(!attempt || !nonce || !localNonzero || !peerNonzero || !limit.Allow(source,now)) return false;
    CookieProof proof; proof.attempt=envelope.header.attempt; proof.generation=envelope.header.generation;
    proof.nonce=probe.nonce;
    if(!authority.Issue(source,proof,peer,now)) return false;
    Challenge challenge; challenge.nonce=proof.nonce; challenge.cookie=proof.cookie; challenge.epoch=proof.epoch;
    std::array<std::uint8_t,52> body{}; Encode(challenge,body);
    auto header=envelope.header; header.type=wire::kEseWireUdpChallenge;
    return Encode(header,body.data(),body.size(),out);
}
Admission AdmitProve(const CookieAuthority& authority,Sessions& sessions,const udp::Endpoint& source,
    const std::array<std::uint8_t,32>& local,const std::array<std::uint8_t,32>& peer,
    const std::uint8_t* packet,std::size_t size,std::uint64_t now,Prove& out) noexcept {
    out={}; Prove proof;
    if(!VerifyProve(authority,source,local,peer,packet,size,now,proof)) return Admission::Rejected;
    try {
        std::array<std::uint8_t,32> digest{};
        CryptoPP::SHA256 hash; hash.CalculateDigest(digest.data(),packet,size);
        Envelope envelope;
        if(!ParseUntrusted(packet,size,envelope)) return Admission::Rejected;
        auto admitted=sessions.AdmitVerified(peer,source,envelope.header,digest,now);
        if(admitted==Admission::Rejected)
            admitted=sessions.ReadmitVerified(peer,source,envelope.header,digest,now);
        if(admitted==Admission::Accepted || admitted==Admission::Duplicate) out=proof;
        return admitted;
    } catch(...) { return Admission::Rejected; }
}
bool BuildDirectFind(const Header& header,const discovery::DirectFind& query,std::uint64_t maxFileSize,
    Signer& signer,Datagram& out) noexcept {
    out.size=0; std::array<std::uint8_t,121> body{};
    unsigned attempt=0; for(auto b:header.attempt) attempt|=b;
    if(header.type!=wire::kEseWireUdpK6DirectFind || !header.sequence || !header.generation || !attempt ||
        !discovery::EncodeFind(query,maxFileSize,body)) return false;
    Datagram packet; SignatureInput input; std::array<std::uint8_t,64> signature{};
    if(!Encode(header,body.data(),body.size(),packet) || !BuildSignatureInput(packet.bytes.data(),packet.size,input) ||
        !signer.Sign(input.bytes.data(),input.size,signature)) return false;
    std::memcpy(packet.bytes.data()+packet.size-64,signature.data(),64);
    if(!VerifyEnvelopeSignature(query.requester,packet.bytes.data(),packet.size)) return false;
    out=packet; return true;
}
bool VerifyDirectFind(const std::array<std::uint8_t,32>& requester,const std::uint8_t* packet,std::size_t size,
    std::uint64_t maxFileSize,Header& outHeader,discovery::DirectFind& out) noexcept {
    outHeader={}; out={}; Envelope envelope; discovery::DirectFind query;
    if(!ParseUntrusted(packet,size,envelope) || envelope.header.type!=wire::kEseWireUdpK6DirectFind ||
        !envelope.header.sequence || !envelope.header.generation ||
        !discovery::DecodeFind(envelope.payload,envelope.payloadSize,maxFileSize,query) || query.requester!=requester ||
        !VerifyEnvelopeSignature(requester,packet,size)) return false;
    unsigned attempt=0; for(auto b:envelope.header.attempt) attempt|=b;
    if(!attempt) return false;
    outHeader=envelope.header; out=query; return true;
}
bool DirectFindDigest(const std::array<std::uint8_t,32>& requester,const std::uint8_t* packet,std::size_t size,
    std::uint64_t maxFileSize,std::array<std::uint8_t,32>& out) noexcept {
    out={}; Header header; discovery::DirectFind query; Envelope envelope;
    if(!VerifyDirectFind(requester,packet,size,maxFileSize,header,query) || !ParseUntrusted(packet,size,envelope)) return false;
    try { CryptoPP::SHA256 hash; hash.CalculateDigest(out.data(),envelope.payload,envelope.payloadSize); return true; }
    catch(...) { out={}; return false; }
}
bool VerifyDirectFindResultSignature(const std::array<std::uint8_t,32>& witness,const Header& original,
    const discovery::DirectFind& query,const std::array<std::uint8_t,32>& requestDigest,
    const std::uint8_t* packet,std::size_t size,std::uint64_t maxFileSize,discovery::FindResultView& out) noexcept {
    out={}; Envelope envelope; discovery::FindResultView result; std::array<std::uint8_t,121> checked{};
    if(original.type!=wire::kEseWireUdpK6DirectFind || !original.generation || !original.sequence ||
        !discovery::EncodeFind(query,maxFileSize,checked) || !ParseUntrusted(packet,size,envelope) ||
        envelope.header.type!=wire::kEseWireUdpK6DirectFindResult || envelope.header.attempt!=original.attempt ||
        envelope.header.sequence!=original.sequence || envelope.header.generation!=original.generation ||
        !discovery::DecodeFindResult(envelope.payload,envelope.payloadSize,maxFileSize,result) ||
        result.file!=query.file || result.fileSize!=query.fileSize || result.requester!=query.requester ||
        result.requestDigest!=requestDigest || (result.kind==0 && result.count>query.maximum) ||
        !VerifyEnvelopeSignature(witness,packet,size)) return false;
    unsigned attempt=0; for(auto b:original.attempt) attempt|=b;
    if(!attempt) return false;
    out=result; return true;
}
bool VerifyDirectFindSources(const discovery::FindResultView& result,std::uint64_t maxFileSize) noexcept {
    if(result.kind!=0 || !result.count || result.count>4) return false;
    for(unsigned i=0;i<result.count;++i) {
        const auto& entry=result.entries[i]; discovery::DirectSource decoded,verified;
        if(!discovery::DecodeSource(entry.bytes,entry.size,maxFileSize,decoded) || decoded.file!=result.file ||
            decoded.fileSize!=result.fileSize || !entry.remainingTtl || entry.remainingTtl>decoded.ttl ||
            !VerifyDirectSource(decoded.node,entry.bytes,entry.size,maxFileSize,verified)) return false;
        for(unsigned j=0;j<i;++j) if(!std::memcmp(result.entries[j].bytes+25,decoded.node.data(),32)) return false;
    }
    return true;
}
bool BuildDirectFindSourcesResult(const Header& original,const discovery::DirectFind& query,
    const std::array<std::uint8_t,32>& requestDigest,const std::array<discovery::FindEntryView,4>& entries,
    std::uint8_t count,std::uint64_t maxFileSize,const std::array<std::uint8_t,32>& witness,
    Signer& signer,Datagram& out) noexcept {
    out.size=0; std::array<std::uint8_t,121> checked{};
    if(original.type!=wire::kEseWireUdpK6DirectFind || count>4 || count>query.maximum ||
        !discovery::EncodeFind(query,maxFileSize,checked)) return false;
    std::array<std::uint8_t,862> body{}; body[0]=count ? 0 : 2;
    std::memcpy(body.data()+1,query.file.data(),16); std::memcpy(body.data()+25,query.requester.data(),32);
    std::memcpy(body.data()+57,requestDigest.data(),32); body[89]=count;
    for(unsigned i=0;i<8;++i) body[17+i]=static_cast<std::uint8_t>(query.fileSize>>(56-8*i));
    std::size_t offset=90;
    for(unsigned i=0;i<count;++i) {
        if(!entries[i].bytes || entries[i].size!=173) return false;
        std::memcpy(body.data()+offset,entries[i].bytes,173);
        for(unsigned j=0;j<4;++j) body[offset+173+j]=static_cast<std::uint8_t>(entries[i].remainingTtl>>(24-8*j));
        offset+=177;
    }
    auto header=original; header.type=wire::kEseWireUdpK6DirectFindResult;
    Datagram packet; SignatureInput input; std::array<std::uint8_t,64> signature{};
    if(!Encode(header,body.data(),offset+64,packet) || !BuildSignatureInput(packet.bytes.data(),packet.size,input) ||
        !signer.Sign(input.bytes.data(),input.size,signature)) return false;
    std::memcpy(packet.bytes.data()+packet.size-64,signature.data(),64);
    discovery::FindResultView result;
    if(!VerifyDirectFindResultSignature(witness,original,query,requestDigest,packet.bytes.data(),packet.size,maxFileSize,result) ||
        (count && !VerifyDirectFindSources(result,maxFileSize))) return false;
    out=packet; return true;
}
bool VerifyDirectSource(const std::array<std::uint8_t,32>& publisher,
    const std::uint8_t* bytes,std::size_t size,std::uint64_t maxFileSize,discovery::DirectSource& out) noexcept {
    out={}; discovery::DirectSource record; discovery::SourceSignatureInput input;
    if(!discovery::DecodeSource(bytes,size,maxFileSize,record) || record.node!=publisher ||
        !discovery::BuildSourceSignatureInput(bytes,size,maxFileSize,input)) return false;
    try {
        if(!eSELive::VerifySignature(publisher.data(),input.bytes.data(),input.bytes.size(),record.signature.data())) return false;
        out=record; return true;
    } catch(...) { return false; }
}
bool BuildDirectSource(const discovery::DirectSource& record,std::uint64_t maxFileSize,Signer& signer,
    std::array<std::uint8_t,173>& out) noexcept {
    out={}; std::array<std::uint8_t,173> bytes{}; discovery::SourceSignatureInput input;
    std::array<std::uint8_t,64> signature{}; discovery::DirectSource checked;
    if(!discovery::EncodeSource(record,maxFileSize,bytes) ||
        !discovery::BuildSourceSignatureInput(bytes.data(),bytes.size(),maxFileSize,input) ||
        !signer.Sign(input.bytes.data(),input.bytes.size(),signature)) return false;
    std::memcpy(bytes.data()+109,signature.data(),64);
    if(!VerifyDirectSource(record.node,bytes.data(),bytes.size(),maxFileSize,checked)) return false;
    out=bytes; return true;
}
bool BuildDirectPut(const Header& header,const std::uint8_t* bytes,std::size_t size,
    std::uint64_t maxFileSize,const std::array<std::uint8_t,32>& publisher,Signer& signer,Datagram& out) noexcept {
    out.size=0; discovery::DirectSource record; unsigned attempt=0; for(auto b:header.attempt) attempt|=b;
    if(header.type!=wire::kEseWireUdpK6DirectPut || !header.sequence || !attempt ||
        !VerifyDirectSource(publisher,bytes,size,maxFileSize,record) || header.generation!=record.generation) return false;
    std::array<std::uint8_t,237> body{}; std::memcpy(body.data(),bytes,173);
    Datagram packet; SignatureInput input; std::array<std::uint8_t,64> signature{};
    if(!Encode(header,body.data(),body.size(),packet) || !BuildSignatureInput(packet.bytes.data(),packet.size,input) ||
        !signer.Sign(input.bytes.data(),input.size,signature)) return false;
    std::memcpy(packet.bytes.data()+packet.size-64,signature.data(),64);
    if(!VerifyEnvelopeSignature(publisher,packet.bytes.data(),packet.size)) return false;
    out=packet; return true;
}
bool VerifyDirectPut(const std::array<std::uint8_t,32>& publisher,const std::uint8_t* packet,std::size_t size,
    std::uint64_t maxFileSize,Header& outHeader,discovery::DirectSource& out) noexcept {
    outHeader={}; out={}; Envelope envelope; discovery::DirectSource record;
    if(!ParseUntrusted(packet,size,envelope) || envelope.header.type!=wire::kEseWireUdpK6DirectPut ||
        !envelope.header.sequence || envelope.payloadSize!=237 || !VerifyEnvelopeSignature(publisher,packet,size) ||
        !VerifyDirectSource(publisher,envelope.payload,173,maxFileSize,record) ||
        record.generation!=envelope.header.generation) return false;
    unsigned attempt=0; for(auto b:envelope.header.attempt) attempt|=b;
    if(!attempt) return false;
    outHeader=envelope.header; out=record; return true;
}
bool AdmitDirectPut(Sessions& sessions,const udp::Endpoint& source,const std::array<std::uint8_t,32>& publisher,
    const std::uint8_t* packet,std::size_t size,std::uint64_t maxFileSize,std::uint64_t now,
    Header& outHeader,discovery::DirectSource& out) noexcept {
    outHeader={}; out={}; Header header; discovery::DirectSource record;
    if(!VerifyDirectPut(publisher,packet,size,maxFileSize,header,record) ||
        !sessions.ObserveVerified(publisher,source,header,now)) return false;
    outHeader=header; out=record; return true;
}
bool BuildDirectPutResult(const Header& original,std::uint8_t status,const discovery::DirectSource& source,
    std::uint64_t maxFileSize,const std::array<std::uint8_t,32>& witness,Signer& signer,Datagram& out) noexcept {
    out.size=0; std::array<std::uint8_t,173> record{};
    unsigned attempt=0; for(auto b:original.attempt) attempt|=b;
    if(original.type!=wire::kEseWireUdpK6DirectPut || !original.sequence || !attempt || status>3 ||
        original.generation!=source.generation || !discovery::EncodeSource(source,maxFileSize,record)) return false;
    std::array<std::uint8_t,169> body{}; std::memcpy(body.data(),record.data(),105); body[0]=status;
    auto header=original; header.type=wire::kEseWireUdpK6DirectPutResult;
    Datagram packet; SignatureInput input; std::array<std::uint8_t,64> signature{};
    if(!Encode(header,body.data(),body.size(),packet) || !BuildSignatureInput(packet.bytes.data(),packet.size,input) ||
        !signer.Sign(input.bytes.data(),input.size,signature)) return false;
    std::memcpy(packet.bytes.data()+packet.size-64,signature.data(),64);
    if(!VerifyEnvelopeSignature(witness,packet.bytes.data(),packet.size)) return false;
    out=packet; return true;
}
bool VerifyDirectPutResult(const std::array<std::uint8_t,32>& witness,const Header& original,
    const discovery::DirectSource& source,std::uint64_t maxFileSize,const std::uint8_t* packet,std::size_t size,
    std::uint8_t& status) noexcept {
    status=255; Envelope envelope; std::array<std::uint8_t,173> record{};
    if(original.type!=wire::kEseWireUdpK6DirectPut || original.generation!=source.generation ||
        !discovery::EncodeSource(source,maxFileSize,record) || !ParseUntrusted(packet,size,envelope) ||
        envelope.header.type!=wire::kEseWireUdpK6DirectPutResult || envelope.payloadSize!=169 || envelope.payload[0]>3 ||
        envelope.header.attempt!=original.attempt || envelope.header.generation!=original.generation ||
        envelope.header.sequence!=original.sequence || std::memcmp(envelope.payload+1,record.data()+1,104) ||
        !VerifyEnvelopeSignature(witness,packet,size)) return false;
    unsigned attempt=0; for(auto b:original.attempt) attempt|=b;
    if(!attempt || !original.sequence) return false;
    status=envelope.payload[0]; return true;
}
bool BuildDescriptorResult(const Header& header,std::uint8_t status,
    const std::array<std::uint8_t,16>& file,const discovery::Locator& locator,
    const std::uint8_t* descriptor,std::size_t size,const std::array<std::uint8_t,32>& witness,
    Signer& signer,Datagram& out) noexcept {
    out.size=0; unsigned attempt=0,node=0;
    for(auto b:header.attempt) attempt|=b; for(auto b:locator.node) node|=b;
    if(header.type!=wire::kEseWireUdpDescriptorResult || status>2 || !header.generation ||
        !header.sequence || !attempt || !node || !locator.ttl || locator.ttl>120) return false;
    if(status==0) {
        discovery::DescriptorView verified;
        if(!VerifyDescriptor(locator.node,locator.digest,descriptor,size,verified) || verified.serial!=locator.serial) return false;
    } else if(size) return false;
    std::array<std::uint8_t,147+discovery::DescriptorMax> body{};
    body[0]=status; std::memcpy(body.data()+1,file.data(),16);
    std::memcpy(body.data()+17,locator.node.data(),32); std::memcpy(body.data()+49,locator.digest.data(),32);
    body[81]=static_cast<std::uint8_t>(size>>8); body[82]=static_cast<std::uint8_t>(size);
    if(size) std::memcpy(body.data()+83,descriptor,size);
    Datagram packet; SignatureInput input; std::array<std::uint8_t,64> signature{};
    if(!Encode(header,body.data(),147+size,packet) || !BuildSignatureInput(packet.bytes.data(),packet.size,input) ||
        !signer.Sign(input.bytes.data(),input.size,signature)) return false;
    std::memcpy(packet.bytes.data()+packet.size-64,signature.data(),64);
    if(!VerifyEnvelopeSignature(witness,packet.bytes.data(),packet.size)) return false;
    out=packet; return true;
}
bool BuildDescriptorPut(const Header& header,const std::array<std::uint8_t,16>& file,
    const std::uint8_t* descriptor,std::size_t size,const std::array<std::uint8_t,32>& publisher,
    Signer& signer,Datagram& out) noexcept {
    out.size=0; std::array<std::uint8_t,32> digest{}; discovery::DescriptorView view;
    unsigned attempt=0; for(auto b:header.attempt) attempt|=b;
    if(header.type!=wire::kEseWireUdpDescriptorPut || !header.generation || !header.sequence || !attempt ||
        !DescriptorDigest(descriptor,size,digest) || !VerifyDescriptor(publisher,digest,descriptor,size,view) ||
        view.generation!=header.generation) return false;
    std::array<std::uint8_t,82+discovery::DescriptorMax> body{};
    std::memcpy(body.data(),file.data(),16); body[16]=static_cast<std::uint8_t>(size>>8);
    body[17]=static_cast<std::uint8_t>(size); std::memcpy(body.data()+18,descriptor,size);
    Datagram packet; SignatureInput input; std::array<std::uint8_t,64> signature{};
    if(!Encode(header,body.data(),82+size,packet) || !BuildSignatureInput(packet.bytes.data(),packet.size,input) ||
        !signer.Sign(input.bytes.data(),input.size,signature)) return false;
    std::memcpy(packet.bytes.data()+packet.size-64,signature.data(),64);
    if(!VerifyEnvelopeSignature(publisher,packet.bytes.data(),packet.size)) return false;
    out=packet; return true;
}
bool VerifyDescriptorPut(const std::array<std::uint8_t,32>& publisher,
    const std::uint8_t* packet,std::size_t size,Header& outHeader,discovery::PutView& out,
    std::array<std::uint8_t,32>& digest) noexcept {
    outHeader={}; out={}; digest={}; Envelope envelope; discovery::PutView publication;
    discovery::DescriptorView descriptor; std::array<std::uint8_t,32> actual{};
    if(!ParseUntrusted(packet,size,envelope) || envelope.header.type!=wire::kEseWireUdpDescriptorPut ||
        !envelope.header.sequence || !envelope.header.generation ||
        !discovery::DecodePut(envelope.payload,envelope.payloadSize,publication) ||
        !VerifyEnvelopeSignature(publisher,packet,size) ||
        !DescriptorDigest(publication.descriptor,publication.length,actual) ||
        !VerifyDescriptor(publisher,actual,publication.descriptor,publication.length,descriptor) ||
        descriptor.generation!=envelope.header.generation) return false;
    unsigned attempt=0; for(auto b:envelope.header.attempt) attempt|=b;
    if(!attempt) return false;
    outHeader=envelope.header; out=publication; digest=actual; return true;
}
bool AdmitDescriptorPut(Sessions& sessions,const udp::Endpoint& source,
    const std::array<std::uint8_t,32>& publisher,const std::uint8_t* packet,std::size_t size,
    std::uint64_t now,Header& outHeader,discovery::PutView& out,std::array<std::uint8_t,32>& digest) noexcept {
    outHeader={}; out={}; digest={}; Header header; discovery::PutView publication;
    std::array<std::uint8_t,32> actual{};
    if(!VerifyDescriptorPut(publisher,packet,size,header,publication,actual) ||
        !sessions.ObserveVerified(publisher,source,header,now)) return false;
    outHeader=header; out=publication; digest=actual; return true;
}
bool BuildDescriptorGet(const Header& header,const std::array<std::uint8_t,16>& file,
    const discovery::Locator& locator,const std::array<std::uint8_t,32>& requester,
    Signer& signer,Datagram& out) noexcept {
    out.size=0;
    unsigned attempt=0,node=0;
    for(auto b:header.attempt) attempt|=b; for(auto b:locator.node) node|=b;
    if(header.type!=wire::kEseWireUdpDescriptorGet || !header.generation || !header.sequence ||
        !attempt || !node || !locator.ttl || locator.ttl>120) return false;
    std::array<std::uint8_t,144> body{};
    std::memcpy(body.data(),file.data(),16); std::memcpy(body.data()+16,locator.node.data(),32);
    std::memcpy(body.data()+48,locator.digest.data(),32);
    Datagram packet; SignatureInput input; std::array<std::uint8_t,64> signature{};
    if(!Encode(header,body.data(),body.size(),packet) || !BuildSignatureInput(packet.bytes.data(),packet.size,input) ||
        !signer.Sign(input.bytes.data(),input.size,signature)) return false;
    std::memcpy(packet.bytes.data()+packet.size-64,signature.data(),64);
    if(!VerifyEnvelopeSignature(requester,packet.bytes.data(),packet.size)) return false;
    out=packet; return true;
}
bool VerifyDescriptorGet(const std::array<std::uint8_t,32>& requester,
    const std::uint8_t* packet,std::size_t size,Header& outHeader,discovery::GetView& out) noexcept {
    outHeader={}; out={}; Envelope envelope; discovery::GetView query;
    if(!ParseUntrusted(packet,size,envelope) || envelope.header.type!=wire::kEseWireUdpDescriptorGet ||
        !envelope.header.generation || !envelope.header.sequence ||
        !discovery::DecodeGet(envelope.payload,envelope.payloadSize,query) ||
        !VerifyEnvelopeSignature(requester,packet,size)) return false;
    unsigned attempt=0,node=0;
    for(auto b:envelope.header.attempt) attempt|=b; for(auto b:query.node) node|=b;
    if(!attempt || !node) return false;
    outHeader=envelope.header; out=query; return true;
}
bool BuildAck(const Prove& proof,const Header& original,std::uint8_t selected,
    const std::array<std::uint8_t,32>& local,Signer& signer,Datagram& out) noexcept {
    out.size=0;
    if(original.type!=wire::kEseWireUdpProve || !ValidSelected(selected) ||
        (proof.probe.mask&0xf8) || (selected && !(proof.probe.mask&selected)) || proof.probe.peer!=local) return false;
    Ack ack; ack.nonce=proof.probe.nonce; ack.selected=selected;
    std::array<std::uint8_t,97> body{}; Encode(ack,body);
    auto header=original; header.type=wire::kEseWireUdpAck;
    Datagram packet; SignatureInput input;
    if(!Encode(header,body.data(),body.size(),packet) || !BuildSignatureInput(packet.bytes.data(),packet.size,input) ||
        !signer.Sign(input.bytes.data(),input.size,ack.signature)) return false;
    std::memcpy(packet.bytes.data()+packet.size-64,ack.signature.data(),64);
    if(!VerifyEnvelopeSignature(local,packet.bytes.data(),packet.size)) return false;
    out=packet; return true;
}
bool VerifyAck(const std::array<std::uint8_t,32>& peer,const Header& original,
    const std::array<std::uint8_t,32>& nonce,std::uint8_t mask,
    const std::uint8_t* packet,std::size_t size,Ack& out) noexcept {
    out={}; Envelope envelope; Ack ack;
    if(original.type!=wire::kEseWireUdpProve || (mask&0xf8) ||
        !ParseUntrusted(packet,size,envelope) || envelope.header.type!=wire::kEseWireUdpAck ||
        envelope.header.attempt!=original.attempt || envelope.header.generation!=original.generation ||
        envelope.header.sequence!=original.sequence || !Decode(envelope.payload,envelope.payloadSize,ack) ||
        ack.nonce!=nonce || (ack.selected && !(mask&ack.selected)) || !VerifyEnvelopeSignature(peer,packet,size)) return false;
    out=ack; return true;
}
} }
