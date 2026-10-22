#pragma once
#include "EseControlCookieCrypto.h"
namespace ese { namespace discovery {
struct OwnedPublicationCandidate {
    udp::Endpoint endpoint;
    std::uint8_t transports=0;
    std::uint32_t ttl=0;
};
// Caller supplies only current owned reachability proofs, never a peer's
// descriptor or a mapping grant alone. Wire evidence remains Advertised at A.
inline bool BuildOwnedPublication(const std::array<std::uint8_t,16>& file,std::uint64_t fileSize,
    std::uint64_t generation,std::uint64_t serial,const std::array<std::uint8_t,32>& node,
    const std::array<std::uint8_t,16>& userHash,const std::array<std::uint8_t,16>& kadId,
    const std::array<OwnedPublicationCandidate,2>& candidates,unsigned count,std::uint32_t ttl,
    control::Signer& signer,std::array<std::uint8_t,DescriptorMax>& descriptor,std::size_t& length,
    std::array<std::uint8_t,173>& source,std::uint64_t maximum) noexcept {
    descriptor={}; length=0; source={};
    if(count>candidates.size() || !generation || !serial || !ttl || ttl>120 || !fileSize || fileSize>maximum) return false;
    std::memcpy(descriptor.data(),wire::kEseWireDescriptorMagic,4); descriptor[4]=wire::kEseWireDescriptorVersion;
    bool quic=false;
    for(unsigned i=0;i<count;++i) {
        const auto& candidate=candidates[i]; const auto& ip=candidate.endpoint.address;
        if(candidate.endpoint.ipv6 || candidate.endpoint.scope || !candidate.endpoint.port ||
            !candidate.transports || (candidate.transports&~5u) || !candidate.ttl || candidate.ttl>ttl ||
            !ip[0] || ip[0]>=224 || ip[0]==10 || ip[0]==127 || (ip[0]==192 && ip[1]==168) ||
            (ip[0]==172 && ip[1]>=16 && ip[1]<=31) || (ip[0]==100 && ip[1]>=64 && ip[1]<=127) ||
            (ip[0]==169 && ip[1]==254) || (ip[0]==198 && (ip[1]==18 || ip[1]==19))) return false;
        auto* bytes=descriptor.data()+DescriptorHeader+28*i;
        bytes[0]=3; bytes[1]=4; bytes[2]=candidate.transports;
        std::memcpy(bytes+4,ip.data(),4); bytes[20]=static_cast<std::uint8_t>(candidate.endpoint.port>>8);
        bytes[21]=static_cast<std::uint8_t>(candidate.endpoint.port);
        for(unsigned j=0;j<4;++j) bytes[24+j]=static_cast<std::uint8_t>(candidate.ttl>>(24-8*j));
        quic=quic || (candidate.transports&4)!=0;
    }
    descriptor[8]=quic?1:0;
    for(unsigned i=0;i<8;++i) {
        descriptor[9+i]=static_cast<std::uint8_t>(generation>>(56-8*i));
        descriptor[17+i]=static_cast<std::uint8_t>(serial>>(56-8*i));
    }
    for(unsigned i=0;i<4;++i) descriptor[25+i]=static_cast<std::uint8_t>(ttl>>(24-8*i));
    std::memcpy(descriptor.data()+29,node.data(),32); std::memcpy(descriptor.data()+61,userHash.data(),16);
    std::memcpy(descriptor.data()+77,kadId.data(),16); descriptor[93]=static_cast<std::uint8_t>(count);
    const auto size=DescriptorHeader+28*count+DescriptorSignature;
    DescriptorSignatureInput input; std::array<std::uint8_t,64> signature{};
    if(!BuildSignatureInput(descriptor.data(),size,input) || !signer.Sign(input.bytes.data(),input.size,signature)) return false;
    std::memcpy(descriptor.data()+size-64,signature.data(),64);
    DirectSource record; record.file=file; record.fileSize=fileSize; record.node=node;
    record.generation=generation; record.serial=serial; record.ttl=ttl;
    DescriptorView verified;
    if(!control::DescriptorDigest(descriptor.data(),size,record.digest) ||
        !control::VerifyDescriptor(node,record.digest,descriptor.data(),size,verified) ||
        !control::BuildDirectSource(record,maximum,signer,source)) { descriptor={}; source={}; return false; }
    length=size; return true;
}
} }
