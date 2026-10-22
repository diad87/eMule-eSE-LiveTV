#include "EseUdpDemux.h"
#include <algorithm>
#include <limits>
namespace ese { namespace udp {
namespace {
bool Valid(const Cid& c) noexcept { return c.size>0 && c.size<=c.bytes.size(); }
bool Equal(const Cid& a,const Cid& b) noexcept {
    return a.size==b.size && std::equal(a.bytes.begin(),a.bytes.begin()+a.size,b.bytes.begin());
}
}
bool Demux::RegisterCid(const Cid& cid,std::uint64_t owner) noexcept {
    if(!Valid(cid) || !owner || revision_==std::numeric_limits<std::uint64_t>::max()) return false;
    Registered* free=nullptr; std::size_t count=0;
    for(auto& entry:cids_) {
        if(entry.owner && Equal(entry.cid,cid)) return entry.owner==owner;
        if(entry.owner && std::equal(entry.cid.bytes.begin(),entry.cid.bytes.begin()+(std::min)(entry.cid.size,cid.size),
            cid.bytes.begin())) return false; // ambiguous short-header prefix
        if(entry.owner==owner) ++count;
        if(!entry.owner && !free) free=&entry;
    }
    if(!free || count>=8) return false;
    free->cid=cid; free->owner=owner; ++revision_; return true;
}
bool Demux::ExpectInitial(const Endpoint& endpoint,std::uint64_t owner,std::uint64_t expires) noexcept {
    if(!owner || !endpoint.port || !expires || revision_==std::numeric_limits<std::uint64_t>::max()) return false;
    Expected* free=nullptr;
    for(auto& entry:expected_) {
        if(entry.owner && entry.endpoint==endpoint) {
            if(entry.owner!=owner) return false;
            entry.expires=expires; ++revision_; return true;
        }
        if(!entry.owner && !free) free=&entry;
    }
    if(!free) return false;
    *free={endpoint,owner,expires}; ++revision_; return true;
}
bool Demux::RemoveCid(const Cid& cid,std::uint64_t owner) noexcept {
    if(!Valid(cid) || !owner || revision_==std::numeric_limits<std::uint64_t>::max()) return false;
    for(auto& entry:cids_) {
        if(entry.owner==owner && Equal(entry.cid,cid)) {
            entry={}; ++revision_; return true;
        }
    }
    return false;
}
void Demux::RemoveOwner(std::uint64_t owner) noexcept {
    if(!owner) return;
    bool changed=false;
    for(auto& entry:cids_) if(entry.owner==owner) { entry={}; changed=true; }
    for(auto& entry:expected_) if(entry.owner==owner) { entry={}; changed=true; }
    if(changed && revision_!=std::numeric_limits<std::uint64_t>::max()) ++revision_;
}
void Demux::Expire(std::uint64_t now) noexcept {
    bool changed=false;
    for(auto& entry:expected_) if(entry.owner && now>=entry.expires) { entry={}; changed=true; }
    if(changed && revision_!=std::numeric_limits<std::uint64_t>::max()) ++revision_;
}
Decision Demux::Inspect(const Inspector& inspector,const std::uint8_t* p,std::size_t n,
    const Endpoint& endpoint,std::uint64_t now) const noexcept {
    Decision out; out.revision=revision_;
    if(!p || !n || !endpoint.port) { out.channel=Channel::Drop; return out; }
    std::uint64_t owner=0;
    auto match=inspector.Control(p,n,endpoint,owner);
    if(match!=Match::None) { out.channel=match==Match::Valid && owner ? Channel::Control : Channel::Drop; out.owner=owner; return out; }
    // Try only locally registered short-header CID lengths. Unknown fixed-bit
    // packets do not create a context or get handed to a QUIC connection.
    std::array<bool,21> tried{};
    for(const auto& entry:cids_) {
        if(!entry.owner || tried[entry.cid.size]) continue;
        tried[entry.cid.size]=true; Header header{};
        if(!inspector.QuicHeader(p,n,entry.cid.size,header) || !Valid(header.destination)) continue;
        for(const auto& candidate:cids_) {
            if(candidate.owner && Equal(candidate.cid,header.destination)) {
                out.channel=Channel::Quic; out.owner=candidate.owner; return out;
            }
        }
    }
    // Long-header Initial discovery is gated by a known endpoint/attempt owner,
    // expiry and library acceptance, not a magic-byte heuristic.
    for(const auto& entry:expected_) {
        if(!entry.owner || now>=entry.expires || !(entry.endpoint==endpoint)) continue;
        Header header{};
        if(inspector.QuicHeader(p,n,0,header) && header.initial && Valid(header.destination) && inspector.AcceptInitial(p,n)) {
            out.channel=Channel::Quic; out.owner=entry.owner; out.newInitial=true; return out;
        }
    }
    owner=0; match=inspector.Utp(p,n,endpoint,owner);
    if(match!=Match::None) { out.channel=match==Match::Valid && owner ? Channel::Utp : Channel::Drop; out.owner=owner; }
    return out;
}
} }
