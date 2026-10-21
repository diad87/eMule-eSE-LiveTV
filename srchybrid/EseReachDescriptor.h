#pragma once
#include "EseControlEnvelope.h"
namespace ese { namespace discovery {
inline constexpr std::size_t DescriptorHeader=95,DescriptorSignature=64,DescriptorMax=968;
inline std::uint64_t ReadBe(const std::uint8_t* p,unsigned n) noexcept {
    std::uint64_t value=0; for(unsigned i=0;i<n;++i) value=(value<<8)|p[i]; return value;
}
// ese.reach3 BSOB payload; structurally valid locator is still untrusted.
struct Locator {
    std::array<std::uint8_t,32> node{},digest{};
    std::uint64_t serial=0;
    std::uint32_t ttl=0;
};
inline bool DecodeLocator(const std::uint8_t* p,std::size_t size,Locator& out) noexcept {
    out={};
    if(!p || size!=77 || p[0]!=1) return false;
    const auto ttl=static_cast<std::uint32_t>(ReadBe(p+73,4));
    if(!ttl || ttl>120) return false;
    std::memcpy(out.node.data(),p+1,32); std::memcpy(out.digest.data(),p+33,32);
    out.serial=ReadBe(p+65,8); out.ttl=ttl; return true;
}
inline bool EncodeLocator(const Locator& locator,std::array<std::uint8_t,77>& out) noexcept {
    out={}; if(!locator.ttl || locator.ttl>120) return false;
    out[0]=1; std::memcpy(out.data()+1,locator.node.data(),32);
    std::memcpy(out.data()+33,locator.digest.data(),32);
    for(unsigned i=0;i<8;++i) out[65+i]=static_cast<std::uint8_t>(locator.serial>>(56-8*i));
    for(unsigned i=0;i<4;++i) out[73+i]=static_cast<std::uint8_t>(locator.ttl>>(24-8*i));
    return true;
}
// Borrowed, untrusted announcement. Signature, locator digest, replay policy,
// global-address policy and each RDV ticket need independent verification.
// In particular the wire evidence byte must NEVER become local inbound proof.
struct DescriptorView {
    std::uint32_t caps=0,ttl=0;
    std::uint64_t generation=0,serial=0;
    std::array<std::uint8_t,32> node{};
    std::array<std::uint8_t,16> userHash{},kadId{};
    std::uint8_t candidates=0,reservations=0;
    const std::uint8_t* candidateBytes=nullptr;
    const std::uint8_t* reservationBytes=nullptr;
    const std::uint8_t* signature=nullptr;
};
inline bool ParseUntrusted(const std::uint8_t* p,std::size_t size,DescriptorView& out) noexcept {
    out={};
    if(!p || size<DescriptorHeader+DescriptorSignature || size>DescriptorMax ||
        std::memcmp(p,wire::kEseWireDescriptorMagic,4) || p[4]!=wire::kEseWireDescriptorVersion) return false;
    const auto count=p[93],reservations=p[94];
    if(count>8 || reservations>3 || size!=DescriptorHeader+28*static_cast<std::size_t>(count)+195*static_cast<std::size_t>(reservations)+DescriptorSignature) return false;
    const auto ttl=static_cast<std::uint32_t>(ReadBe(p+25,4));
    if(!ttl || ttl>120) return false;
    for(unsigned i=0;i<count;++i) {
        const auto* candidate=p+DescriptorHeader+28*i;
        if(candidate[0]<1 || candidate[0]>6 || (candidate[1]!=4 && candidate[1]!=6) ||
            !candidate[2] || (candidate[2]&0xf8) || candidate[3]>3 || !ReadBe(candidate+20,2) || candidate[23] ||
            candidate[22]>1 || !ReadBe(candidate+24,4) || ReadBe(candidate+24,4)>ttl ||
            (candidate[0]==1 && candidate[1]!=6) || (candidate[0]==2 && candidate[1]!=4)) return false;
        if(candidate[1]==4) for(unsigned j=8;j<20;++j) if(candidate[j]) return false;
    }
    const auto* reserved=p+DescriptorHeader+28*count;
    for(unsigned i=0;i<reservations;++i) {
        const auto* endpoint=reserved+195*i;
        if((endpoint[0]!=4 && endpoint[0]!=6) || !ReadBe(endpoint+17,2)) return false;
        if(endpoint[0]==4) for(unsigned j=5;j<17;++j) if(endpoint[j]) return false;
    }
    out.caps=static_cast<std::uint32_t>(ReadBe(p+5,4)); out.generation=ReadBe(p+9,8);
    out.serial=ReadBe(p+17,8); out.ttl=ttl;
    std::memcpy(out.node.data(),p+29,32); std::memcpy(out.userHash.data(),p+61,16);
    std::memcpy(out.kadId.data(),p+77,16); out.candidates=count; out.reservations=reservations;
    out.candidateBytes=p+DescriptorHeader; out.reservationBytes=reserved;
    out.signature=p+size-DescriptorSignature; return true;
}
struct DescriptorSignatureInput {
    std::array<std::uint8_t,DescriptorMax-DescriptorSignature+sizeof(wire::kEseWireReachAuthDomain)> bytes{};
    std::size_t size=0;
};
struct PutView {
    std::array<std::uint8_t,16> file{};
    const std::uint8_t* descriptor=nullptr;
    std::size_t length=0;
    const std::uint8_t* signature=nullptr;
};
struct GetView {
    std::array<std::uint8_t,16> file{};
    std::array<std::uint8_t,32> node{},digest{};
    const std::uint8_t* signature=nullptr;
};
struct ResultView : GetView {
    std::uint8_t status=0;
    const std::uint8_t* descriptor=nullptr;
    std::size_t length=0;
};
// Payload-only inspection. Outer control signature/session/correlation and
// inner descriptor signature/digest remain mandatory at admission.
inline bool DecodePut(const std::uint8_t* p,std::size_t size,PutView& out) noexcept {
    out={}; if(!p || size<82 || size>82+DescriptorMax) return false;
    const auto length=static_cast<std::size_t>(ReadBe(p+16,2));
    DescriptorView descriptor;
    if(size!=82+length || !ParseUntrusted(p+18,length,descriptor)) return false;
    std::memcpy(out.file.data(),p,16); out.descriptor=p+18;
    out.length=length; out.signature=p+18+length; return true;
}
inline bool DecodeGet(const std::uint8_t* p,std::size_t size,GetView& out) noexcept {
    out={}; if(!p || size!=144) return false;
    std::memcpy(out.file.data(),p,16); std::memcpy(out.node.data(),p+16,32);
    std::memcpy(out.digest.data(),p+48,32); out.signature=p+80; return true;
}
inline bool DecodeResult(const std::uint8_t* p,std::size_t size,ResultView& out) noexcept {
    out={}; if(!p || size<147 || size>147+DescriptorMax || p[0]>2) return false;
    const auto length=static_cast<std::size_t>(ReadBe(p+81,2));
    if(size!=147+length) return false;
    DescriptorView descriptor;
    if(p[0]==0 ? !ParseUntrusted(p+83,length,descriptor) : length!=0) return false;
    out.status=p[0]; std::memcpy(out.file.data(),p+1,16);
    std::memcpy(out.node.data(),p+17,32); std::memcpy(out.digest.data(),p+49,32);
    out.descriptor=length ? p+83 : nullptr; out.length=length;
    out.signature=p+83+length; return true;
}
inline bool BuildSignatureInput(const std::uint8_t* p,std::size_t size,DescriptorSignatureInput& out) noexcept {
    out.size=0; DescriptorView descriptor;
    if(!ParseUntrusted(p,size,descriptor)) return false;
    constexpr auto domain=sizeof(wire::kEseWireReachAuthDomain);
    std::memcpy(out.bytes.data(),wire::kEseWireReachAuthDomain,domain);
    std::memcpy(out.bytes.data()+domain,p,size-DescriptorSignature);
    out.size=domain+size-DescriptorSignature; return true;
}
} }
