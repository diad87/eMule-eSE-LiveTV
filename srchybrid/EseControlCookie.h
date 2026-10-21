#pragma once
#include "EseControlBootstrap.h"
#include "EseUdpDemux.h"
namespace ese { namespace control {
struct CookieProof {
    std::array<std::uint8_t,16> attempt{};
    std::uint64_t generation=0;
    std::array<std::uint8_t,32> nonce{};
    std::array<std::uint8_t,16> cookie{};
    std::uint32_t epoch=0;
};
inline bool Decode(const std::uint8_t* p,std::size_t n,CookieProof& out) noexcept {
    out={}; if(!p || n!=76) return false;
    std::memcpy(out.attempt.data(),p,16);
    for(unsigned i=16;i<24;++i) out.generation=(out.generation<<8)|p[i];
    std::memcpy(out.nonce.data(),p+24,32); std::memcpy(out.cookie.data(),p+56,16);
    out.epoch=ReadEpoch(p+72); return true;
}
inline void Encode(const CookieProof& in,std::array<std::uint8_t,76>& out) noexcept {
    std::memcpy(out.data(),in.attempt.data(),16);
    for(unsigned i=0;i<8;++i) out[16+i]=static_cast<std::uint8_t>(in.generation>>(56-8*i));
    std::memcpy(out.data()+24,in.nonce.data(),32); std::memcpy(out.data()+56,in.cookie.data(),16);
    WriteEpoch(out.data()+72,in.epoch);
}
// Epochs do not wrap: 16000 ms buckets, process-monotonic origin. Overflow
// requires replacing the secret/context, not accepting an epoch from the future.
inline bool CurrentEpoch(std::uint64_t now,std::uint32_t& out) noexcept {
    out=0; if(now/16000>UINT32_MAX) return false;
    out=static_cast<std::uint32_t>(now/16000); return true;
}
inline bool AcceptEpoch(std::uint32_t claimed,std::uint32_t current) noexcept {
    return claimed==current || (current && claimed==current-1);
}
// Constant-work comparison of the fixed cookie; the HMAC producer must fail
// closed separately. No secret or computed MAC is exposed by this comparison.
inline bool EqualCookie(const std::array<std::uint8_t,16>& a,const std::array<std::uint8_t,16>& b) noexcept {
    unsigned different=0;
    for(std::size_t i=0;i<a.size();++i) different|=static_cast<unsigned>(a[i]^b[i]);
    return different==0;
}
struct CookieInput {
    std::array<std::uint8_t,sizeof(wire::kEseWireCookieDomain)+19+16+8+32+32+4> bytes{};
};
inline bool BuildCookieInput(const udp::Endpoint& source,const CookieProof& proof,
    const std::array<std::uint8_t,32>& signer,CookieInput& out) noexcept {
    out={}; if(!source.port) return false;
    if(!source.ipv6) for(unsigned i=4;i<16;++i) if(source.address[i]) return false;
    std::size_t offset=sizeof(wire::kEseWireCookieDomain);
    std::memcpy(out.bytes.data(),wire::kEseWireCookieDomain,offset);
    out.bytes[offset++]=source.ipv6 ? 6 : 4;
    std::memcpy(out.bytes.data()+offset,source.address.data(),16); offset+=16;
    out.bytes[offset++]=static_cast<std::uint8_t>(source.port>>8);
    out.bytes[offset++]=static_cast<std::uint8_t>(source.port);
    std::memcpy(out.bytes.data()+offset,proof.attempt.data(),16); offset+=16;
    for(unsigned i=0;i<8;++i) out.bytes[offset++]=static_cast<std::uint8_t>(proof.generation>>(56-8*i));
    std::memcpy(out.bytes.data()+offset,signer.data(),32); offset+=32;
    std::memcpy(out.bytes.data()+offset,proof.nonce.data(),32); offset+=32;
    WriteEpoch(out.bytes.data()+offset,proof.epoch); return true;
}
} }
