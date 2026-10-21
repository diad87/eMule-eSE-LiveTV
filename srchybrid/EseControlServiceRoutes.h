#pragma once
#include "EseControlBootstrap.h"
#include "EseUdpDemux.h"
#include <limits>
namespace ese { namespace control {
// Main socket-owner thread. Queue classification only: callers still perform
// cookie/signature/replay/rate admission. Explicit service activation is not a
// QUIC data authorization, trusted pin or extension negotiation with Kad2.
class ServiceRoutes {
public:
    bool Activate(const std::array<std::uint8_t,32>& local,std::uint64_t owner,
        std::uint64_t localGeneration) noexcept {
        unsigned key=0; for(auto byte:local) key|=byte;
        if(!key || !owner || !localGeneration) return false;
        if(owner_ && (owner_!=owner || local_!=local || generation_!=localGeneration)) return false;
        local_=local; owner_=owner; generation_=localGeneration; return true;
    }
    void Reset() noexcept { entries_={}; local_={}; owner_=0; generation_=0; last_=0; haveTime_=false; }
    // Only after a completely verified, ACCEPTED (not duplicate) PROVE.
    bool RegisterVerified(const std::array<std::uint8_t,32>& peer,const udp::Endpoint& endpoint,
        const Header& context,std::uint64_t now,std::uint64_t until) noexcept {
        unsigned key=0,attempt=0; for(auto byte:peer) key|=byte; for(auto byte:context.attempt) attempt|=byte;
        if(!owner_ || !key || peer==local_ || !attempt || !endpoint.port || !context.generation ||
            context.type!=wire::kEseWireUdpProve ||
            !context.sequence || !Clock(now) || until<=now || until-now>60000) return false;
        Entry* available=nullptr;
        for(auto& entry:entries_) {
            if(entry.used && now>=entry.until) entry={};
            if(entry.used && entry.endpoint==endpoint && Same(entry.context,context))
                return entry.peer==peer; // duplicate never renews route TTL
            if(!entry.used && !available) available=&entry;
        }
        if(!available) return false;
        *available={peer,endpoint,context,until,true}; return true;
    }
    bool Resolve(const udp::Endpoint& endpoint,const Header& context,std::uint64_t now,
        std::array<std::uint8_t,32>& peer) const noexcept {
        peer={}; if(!owner_ || (haveTime_ && now<last_)) return false;
        for(const auto& entry:entries_) if(entry.used && now<entry.until && entry.endpoint==endpoint &&
            Same(entry.context,context) && context.sequence>=entry.context.sequence) {
            peer=entry.peer; return true;
        }
        return false;
    }
    udp::Match Inspect(const std::uint8_t* bytes,std::size_t size,const udp::Endpoint& endpoint,
        std::uint64_t now,std::uint64_t& owner) const noexcept {
        owner=0; if(!Recognize(bytes,size)) return udp::Match::None;
        Envelope envelope;
        if(!owner_ || (haveTime_ && now<last_) || !endpoint.port || !ParseUntrusted(bytes,size,envelope))
            return udp::Match::Invalid;
        unsigned attempt=0; for(auto byte:envelope.header.attempt) attempt|=byte;
        if(!attempt || !envelope.header.generation || !envelope.header.sequence) return udp::Match::Invalid;
        if(envelope.header.type==wire::kEseWireUdpProbe || envelope.header.type==wire::kEseWireUdpProve) {
            Probe probe;
            if(envelope.header.type==wire::kEseWireUdpProbe) {
                if(!Decode(envelope.payload,envelope.payloadSize,probe)) return udp::Match::Invalid;
            } else {
                Prove prove; if(!Decode(envelope.payload,envelope.payloadSize,prove)) return udp::Match::Invalid;
                probe=prove.probe;
            }
            unsigned key=0; for(auto byte:probe.node) key|=byte;
            if(!key || probe.node==local_ || probe.peer!=local_) return udp::Match::Invalid;
        } else {
            switch(envelope.header.type) {
            case wire::kEseWireUdpDescriptorPut: case wire::kEseWireUdpDescriptorGet:
            case wire::kEseWireUdpK6DirectPut: case wire::kEseWireUdpK6DirectFind:
            case wire::kEseWireUdpK6ContactGet: break;
            default: return udp::Match::Invalid; // no replies, RDV or data route
            }
            std::array<std::uint8_t,32> peer{};
            if(!Resolve(endpoint,envelope.header,now,peer)) return udp::Match::Invalid;
        }
        owner=owner_; return udp::Match::Valid;
    }
private:
    static bool Same(const Header& a,const Header& b) noexcept {
        return a.attempt==b.attempt && a.generation==b.generation;
    }
    bool Clock(std::uint64_t now) noexcept {
        if(haveTime_ && now<last_) return false;
        last_=now; haveTime_=true; return true;
    }
    struct Entry { std::array<std::uint8_t,32> peer{}; udp::Endpoint endpoint; Header context;
        std::uint64_t until=0; bool used=false; };
    std::array<Entry,64> entries_{};
    std::array<std::uint8_t,32> local_{};
    std::uint64_t owner_=0,generation_=0,last_=0; bool haveTime_=false;
};
} }
