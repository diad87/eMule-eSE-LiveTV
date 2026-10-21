#pragma once
#include "EseControlEnvelope.h"
#include "EseControlBootstrap.h"
#include "EseUdpDemux.h"
namespace ese { namespace control {
// Socket-owner thread only. Classification never consumes a request: an
// unauthenticated matching packet cannot invalidate the legitimate response.
class PendingRoutes {
public:
    // Explicit trusted peer/endpoint window only. This is queue routing, NOT
    // signature, cookie or return-path authorization. No wildcard listener.
    bool AddBootstrap(const std::array<std::uint8_t,32>& local,
        const std::array<std::uint8_t,32>& expected,const udp::Endpoint& peer,
        std::uint64_t owner,std::uint64_t now,std::uint64_t until) noexcept {
        if(!Advance(now) || !owner || !peer.port || until<=now || until-now>2000) return false;
        unsigned a=0,b=0; for(auto v:local) a|=v; for(auto v:expected) b|=v;
        if(!a || !b || local==expected) return false;
        Bootstrap* free=nullptr;
        for(auto& entry:bootstrap_) {
            if(entry.owner && (entry.peer==peer || entry.owner==owner)) return false;
            if(!entry.owner && !free) free=&entry;
        }
        if(!free) return false;
        *free={local,expected,peer,owner,until}; return true;
    }
    bool Add(const Header& request,std::uint8_t reply,const udp::Endpoint& peer,
        std::uint64_t owner,std::uint64_t now,std::uint64_t until) noexcept {
        if(!Advance(now) || !owner || !peer.port || !KnownType(reply) || !request.generation ||
            !request.sequence || until<=now || until-now>2000) return false;
        unsigned attempt=0; for(auto b:request.attempt) attempt|=b; if(!attempt) return false;
        Entry* free=nullptr;
        for(auto& entry:entries_) {
            if(entry.owner && entry.peer==peer && Same(entry.request,request) && entry.reply==reply) return false;
            if(!entry.owner && !free) free=&entry;
        }
        if(!free) return false;
        *free={request,peer,owner,until,reply}; return true;
    }
    udp::Match Inspect(const std::uint8_t* bytes,std::size_t size,const udp::Endpoint& peer,
        std::uint64_t now,std::uint64_t& owner) const noexcept {
        owner=0; if(!Recognize(bytes,size)) return udp::Match::None;
        Envelope packet;
        if((haveTime_ && now<last_) || !ParseUntrusted(bytes,size,packet)) return udp::Match::Invalid;
        if(packet.header.type==wire::kEseWireUdpProbe || packet.header.type==wire::kEseWireUdpProve) {
            unsigned attempt=0; for(auto b:packet.header.attempt) attempt|=b;
            if(!attempt || !packet.header.generation || !packet.header.sequence) return udp::Match::Invalid;
            Probe probe;
            if(packet.header.type==wire::kEseWireUdpProbe) {
                if(!Decode(packet.payload,packet.payloadSize,probe)) return udp::Match::Invalid;
            } else {
                Prove prove; if(!Decode(packet.payload,packet.payloadSize,prove)) return udp::Match::Invalid;
                probe=prove.probe;
            }
            for(const auto& entry:bootstrap_) if(entry.owner && now<entry.until && entry.peer==peer &&
                entry.local==probe.peer && entry.expected==probe.node) {
                owner=entry.owner; return udp::Match::Valid;
            }
            return udp::Match::Invalid;
        }
        for(const auto& entry:entries_) if(entry.owner && now<entry.until && entry.peer==peer &&
            entry.reply==packet.header.type && Same(entry.request,packet.header)) {
            owner=entry.owner; return udp::Match::Valid;
        }
        return udp::Match::Invalid;
    }
    void Remove(std::uint64_t owner) noexcept {
        for(auto& entry:entries_) if(entry.owner==owner) entry={};
        for(auto& entry:bootstrap_) if(entry.owner==owner) entry={};
    }
    void Reset() noexcept { entries_={}; bootstrap_={}; last_=0; haveTime_=false; }
    bool Advance(std::uint64_t now) noexcept {
        if(haveTime_ && now<last_) return false;
        haveTime_=true; last_=now;
        for(auto& entry:entries_) if(entry.owner && now>=entry.until) entry={};
        for(auto& entry:bootstrap_) if(entry.owner && now>=entry.until) entry={};
        return true;
    }
private:
    static bool Same(const Header& a,const Header& b) noexcept {
        return a.attempt==b.attempt && a.generation==b.generation && a.sequence==b.sequence;
    }
    struct Entry { Header request{}; udp::Endpoint peer{}; std::uint64_t owner=0,until=0; std::uint8_t reply=0; };
    struct Bootstrap { std::array<std::uint8_t,32> local{},expected{}; udp::Endpoint peer{}; std::uint64_t owner=0,until=0; };
    std::array<Entry,64> entries_{};
    std::array<Bootstrap,16> bootstrap_{};
    std::uint64_t last_=0; bool haveTime_=false;
};
} }
