#pragma once
#include "EseKad6ContactCache.h"
namespace ese { namespace discovery {
// Owned requests, no borrowed datagrams or session lifetimes. Caller supplies
// the CURRENT session ledger/cache on each operation, never a saved snapshot.
class ContactRefreshReplies {
public:
    bool Start(std::uint64_t owner,const std::array<std::uint8_t,32>& witness,
        const udp::Endpoint& endpoint,const std::array<std::uint8_t,32>& requester,
        const control::Datagram& get,const control::Sessions& sessions,
        std::uint64_t now,std::uint64_t deadline) noexcept {
        if(!owner || owner<=lastOwner_) return false;
        control::Header header;
        if(!control::VerifyContactGet(requester,get.bytes.data(),get.size,header) ||
            !sessions.Current(witness,endpoint,header,now)) return false;
        for(auto& entry:entries_) if(!entry.owner) {
            control::ContactRefreshRequest pending;
            if(!pending.Start(witness,endpoint,requester,get,now,deadline)) return false;
            entry.owner=owner; entry.pending=pending; entry.endpoint=endpoint; entry.get=get;
            entry.witness=witness; entry.header=header; lastOwner_=owner; return true;
        }
        return false;
    }
    bool Receive(std::uint64_t owner,Kad6ContactCache& cache,const control::Sessions& sessions,
        const udp::Endpoint& endpoint,const std::uint8_t* bytes,std::size_t size,
        std::uint64_t now,const kad6::Kad6CryptoHooks& crypto,std::uint64_t utc) noexcept {
        for(auto& entry:entries_) if(entry.owner==owner && owner) {
            kad6::K6RouterRecord record;
            if(!ImportRefreshedContact(cache,entry.pending,sessions,endpoint,bytes,size,now,crypto,utc,record)) return false;
            entry={}; return true;
        }
        return false;
    }
    void Cancel(std::uint64_t owner) noexcept { for(auto& entry:entries_) if(entry.owner==owner) entry={}; }
    template<class Remove> void CancelAll(Remove remove) {
        for(auto& entry:entries_) if(entry.owner) {
            const auto owner=entry.owner; entry={}; remove(owner);
        }
    }
    bool Request(std::uint64_t owner,std::uint64_t now,udp::Endpoint& endpoint,control::Datagram& get) noexcept {
        endpoint={}; get={};
        for(auto& entry:entries_) if(entry.owner==owner && owner && entry.pending.Poll(now)) {
            endpoint=entry.endpoint; get=entry.get; return true;
        }
        return false;
    }
    // Each send rechecks the live ledger, not the session snapshot at Start.
    // This query grants no retransmission/rate authorization of its own.
    bool RequestInSession(std::uint64_t owner,const control::Sessions& sessions,
        std::uint64_t now,udp::Endpoint& endpoint,control::Datagram& get) noexcept {
        endpoint={}; get={};
        for(const auto& entry:entries_) if(entry.owner==owner && owner) {
            if(!sessions.Current(entry.witness,entry.endpoint,entry.header,now)) return false;
            return Request(owner,now,endpoint,get);
        }
        return false;
    }
    template<class Remove> void Poll(std::uint64_t now,Remove remove) {
        for(auto& entry:entries_) if(entry.owner && !entry.pending.Poll(now)) {
            const auto owner=entry.owner; entry={}; remove(owner);
        }
    }
    // Session revocation retires both owned requests and queued ingress before
    // processing replies. A later ledger restoration cannot resurrect them.
    template<class Remove> void PollInSession(const control::Sessions& sessions,
        std::uint64_t now,Remove remove) {
        for(auto& entry:entries_) if(entry.owner &&
            (!sessions.Current(entry.witness,entry.endpoint,entry.header,now) || !entry.pending.Poll(now))) {
            const auto owner=entry.owner; entry={}; remove(owner);
        }
    }
private:
    struct Entry { std::uint64_t owner=0; control::ContactRefreshRequest pending; udp::Endpoint endpoint{};
        control::Datagram get; std::array<std::uint8_t,32> witness{}; control::Header header{}; };
    std::array<Entry,16> entries_{}; std::uint64_t lastOwner_=0;
};
} }
