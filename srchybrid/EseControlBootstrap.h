#pragma once
#include "EseControlEnvelope.h"
namespace ese { namespace control {
struct Probe {
    std::array<std::uint8_t,32> node{},peer{},nonce{};
    std::uint8_t mask=0;
    std::array<std::uint8_t,31> padding{};
};
struct Challenge {
    std::array<std::uint8_t,32> nonce{};
    std::array<std::uint8_t,16> cookie{};
    std::uint32_t epoch=0;
};
struct Prove {
    Probe probe;
    std::array<std::uint8_t,16> cookie{};
    std::uint32_t epoch=0;
    std::array<std::uint8_t,64> signature{};
};
struct Ack {
    std::array<std::uint8_t,32> nonce{};
    std::uint8_t selected=0;
    std::array<std::uint8_t,64> signature{};
};
// Bounded per-responder correlation for a challenge issued in the current
// bootstrap. Matching is NOT authentication: cookie and signature verification
// must still run before any session admission. In particular an old valid
// cookie from the previous epoch cannot stand in for the newly issued cookie.
class PendingBootstrapChallenge {
public:
    bool Remember(const Header& header,const Probe& probe,const Challenge& challenge,
        std::uint64_t issued,std::uint64_t deadline) noexcept {
        if(header.type!=wire::kEseWireUdpProbe || !header.sequence || !header.generation ||
            issued>=deadline || deadline-issued>2000 || probe.nonce!=challenge.nonce) return false;
        unsigned attempt=0,nonce=0,cookie=0;
        for(auto b:header.attempt) attempt|=b;
        for(auto b:probe.nonce) nonce|=b;
        for(auto b:challenge.cookie) cookie|=b;
        if(!attempt || !nonce || !cookie) return false;
        header_=header; probe_=probe; challenge_=challenge;
        issued_=issued; deadline_=deadline; pending_=true; return true;
    }
    bool Matches(const Header& header,const Prove& proof,std::uint64_t now) const noexcept {
        return pending_ && now>=issued_ && now<deadline_ && header.type==wire::kEseWireUdpProve &&
            header.attempt==header_.attempt && header.generation==header_.generation &&
            header.sequence==header_.sequence && proof.probe.node==probe_.node &&
            proof.probe.peer==probe_.peer && proof.probe.nonce==probe_.nonce &&
            proof.probe.mask==probe_.mask && proof.probe.padding==probe_.padding &&
            proof.cookie==challenge_.cookie && proof.epoch==challenge_.epoch;
    }
    std::uint64_t Issued() const noexcept { return issued_; }
    void Clear() noexcept { *this=PendingBootstrapChallenge{}; }
private:
    Header header_{};
    Probe probe_{};
    Challenge challenge_{};
    std::uint64_t issued_=0,deadline_=0;
    bool pending_=false;
};
inline std::uint32_t ReadEpoch(const std::uint8_t* p) noexcept {
    std::uint32_t value=0; for(unsigned i=0;i<4;++i) value=(value<<8)|p[i]; return value;
}
inline void WriteEpoch(std::uint8_t* p,std::uint32_t value) noexcept {
    for(unsigned i=0;i<4;++i) p[i]=static_cast<std::uint8_t>(value>>(24-8*i));
}
// Structural codecs only; callers must authenticate, correlate and check cookie
// before using any field. Padding is preserved, not treated as authority.
inline bool Decode(const std::uint8_t* p,std::size_t n,Probe& out) noexcept {
    out={}; if(!p || n!=128 || (p[96]&0xf8)) return false;
    std::memcpy(out.node.data(),p,32); std::memcpy(out.peer.data(),p+32,32);
    std::memcpy(out.nonce.data(),p+64,32); out.mask=p[96];
    std::memcpy(out.padding.data(),p+97,31); return true;
}
inline bool Encode(const Probe& in,std::array<std::uint8_t,128>& out) noexcept {
    out={}; if(in.mask&0xf8) return false;
    std::memcpy(out.data(),in.node.data(),32); std::memcpy(out.data()+32,in.peer.data(),32);
    std::memcpy(out.data()+64,in.nonce.data(),32); out[96]=in.mask;
    std::memcpy(out.data()+97,in.padding.data(),31); return true;
}
inline bool Decode(const std::uint8_t* p,std::size_t n,Challenge& out) noexcept {
    out={}; if(!p || n!=52) return false;
    std::memcpy(out.nonce.data(),p,32); std::memcpy(out.cookie.data(),p+32,16);
    out.epoch=ReadEpoch(p+48); return true;
}
inline bool Encode(const Challenge& in,std::array<std::uint8_t,52>& out) noexcept {
    std::memcpy(out.data(),in.nonce.data(),32); std::memcpy(out.data()+32,in.cookie.data(),16);
    WriteEpoch(out.data()+48,in.epoch); return true;
}
inline bool Decode(const std::uint8_t* p,std::size_t n,Prove& out) noexcept {
    out={}; if(!p || n!=212 || !Decode(p,128,out.probe)) return false;
    std::memcpy(out.cookie.data(),p+128,16); out.epoch=ReadEpoch(p+144);
    std::memcpy(out.signature.data(),p+148,64); return true;
}
inline bool Encode(const Prove& in,std::array<std::uint8_t,212>& out) noexcept {
    out={}; std::array<std::uint8_t,128> probe;
    if(!Encode(in.probe,probe)) return false;
    std::memcpy(out.data(),probe.data(),128); std::memcpy(out.data()+128,in.cookie.data(),16);
    WriteEpoch(out.data()+144,in.epoch); std::memcpy(out.data()+148,in.signature.data(),64); return true;
}
inline bool ValidSelected(std::uint8_t selected) noexcept { return selected==0 || selected==2 || selected==4; }
inline bool Decode(const std::uint8_t* p,std::size_t n,Ack& out) noexcept {
    out={}; if(!p || n!=97 || !ValidSelected(p[32])) return false;
    std::memcpy(out.nonce.data(),p,32); out.selected=p[32];
    std::memcpy(out.signature.data(),p+33,64); return true;
}
inline bool Encode(const Ack& in,std::array<std::uint8_t,97>& out) noexcept {
    out={}; if(!ValidSelected(in.selected)) return false;
    std::memcpy(out.data(),in.nonce.data(),32); out[32]=in.selected;
    std::memcpy(out.data()+33,in.signature.data(),64); return true;
}
} }
