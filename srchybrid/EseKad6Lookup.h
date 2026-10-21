#pragma once
#include <array>
#include <cstdint>
#include <limits>

namespace ese { namespace discovery {
// Scheduling only: caller must validate the signed record and separately prove
// return reachability. This object never authenticates or adopts a contact.
class Kad6Lookup {
public:
    struct Contact { std::array<std::uint8_t,16> id{}; std::array<std::uint8_t,32> node{}; };
    enum class State { Idle,Active,Exhausted,Expired,Cancelled };
    bool Start(const std::array<std::uint8_t,16>& target,std::uint64_t now) noexcept {
        if(state_!=State::Idle || now>(std::numeric_limits<std::uint64_t>::max)()-5000) return false;
        target_=target; last_=now; deadline_=now+5000; state_=State::Active; return true;
    }
    bool AddValidatedRecord(const Contact& contact,std::uint64_t now) noexcept {
        if(!Poll(now)) return false;
        unsigned key=0,id=0; for(auto b:contact.node) key|=b; for(auto b:contact.id) id|=b;
        if(!key || !id) return false;
        for(unsigned i=0;i<count_;++i) if(entries_[i].contact.node==contact.node || entries_[i].contact.id==contact.id) return false;
        if(count_==16) return false;
        entries_[count_++].contact=contact; return true;
    }
    bool MarkReturnVerified(const std::array<std::uint8_t,32>& node,std::uint64_t now) noexcept {
        if(!Poll(now)) return false;
        for(unsigned i=0;i<count_;++i) if(entries_[i].contact.node==node) { entries_[i].returned=true; return true; }
        return false;
    }
    bool ContainsValidated(const Contact& contact) const noexcept {
        for(unsigned i=0;i<count_;++i)
            if(entries_[i].contact.node==contact.node && entries_[i].contact.id==contact.id) return true;
        return false;
    }
    // A batch is one round, at most two W. Do not start the next round until
    // both prior requests finish/expire; contacts learned meanwhile stay queued.
    unsigned BeginRound(std::uint64_t now,std::array<Contact,2>& out) noexcept {
        out={}; if(!Poll(now) || inflight_ || rounds_==4) return 0;
        unsigned selected=0;
        while(selected<2 && sends_<12) {
            unsigned best=16;
            for(unsigned i=0;i<count_;++i) if(!entries_[i].visited && entries_[i].returned &&
                (best==16 || Less(entries_[i].contact,entries_[best].contact))) best=i;
            if(best==16) break;
            auto& entry=entries_[best]; entry.visited=true; entry.active=true;
            entry.until=now+((deadline_-now<2000)?deadline_-now:2000);
            out[selected++]=entry.contact; ++sends_; ++inflight_;
        }
        if(selected) ++rounds_;
        return selected;
    }
    // Retry only a currently outstanding request; no extension of its original
    // timeout or global deadline, and every transmitted retry costs one FIND.
    bool Retry(const std::array<std::uint8_t,32>& node,std::uint64_t now) noexcept {
        if(!Poll(now) || sends_==12) return false;
        for(unsigned i=0;i<count_;++i) if(entries_[i].active && entries_[i].started && entries_[i].contact.node==node) { ++sends_; return true; }
        return false;
    }
    std::uint64_t FindAuthorization(const std::array<std::uint8_t,32>& node,std::uint64_t now) noexcept {
        if(!Poll(now)) return 0;
        for(unsigned i=0;i<count_;++i) if(entries_[i].active && !entries_[i].started && entries_[i].contact.node==node) return entries_[i].until;
        return 0;
    }
    bool ConsumeFindAuthorization(const std::array<std::uint8_t,32>& node,std::uint64_t now) noexcept {
        if(!FindAuthorization(node,now)) return false;
        for(unsigned i=0;i<count_;++i) if(entries_[i].contact.node==node) { entries_[i].started=true; return true; }
        return false;
    }
    bool Complete(const std::array<std::uint8_t,32>& node,std::uint64_t now) noexcept {
        if(!Poll(now)) return false;
        for(unsigned i=0;i<count_;++i) if(entries_[i].active && entries_[i].contact.node==node) {
            entries_[i].active=false; --inflight_; return true;
        }
        return false;
    }
    bool Poll(std::uint64_t now) noexcept {
        if(state_!=State::Active) return false;
        if(now<last_ || now>=deadline_) { state_=State::Expired; inflight_=0; return false; }
        last_=now;
        for(unsigned i=0;i<count_;++i) if(entries_[i].active && now>=entries_[i].until) { entries_[i].active=false; --inflight_; }
        if(!inflight_ && (rounds_==4 || sends_==12)) { state_=State::Exhausted; return false; }
        return true;
    }
    void Cancel() noexcept { state_=State::Cancelled; inflight_=0; }
    State Status() const noexcept { return state_; }
    unsigned Sends() const noexcept { return sends_; }
    unsigned Rounds() const noexcept { return rounds_; }
    std::uint64_t Deadline() const noexcept { return deadline_; }
private:
    bool Less(const Contact& a,const Contact& b) const noexcept {
        for(unsigned i=0;i<16;++i) { const auto x=a.id[i]^target_[i],y=b.id[i]^target_[i]; if(x!=y) return x<y; }
        return a.node<b.node;
    }
    struct Entry { Contact contact; std::uint64_t until=0; bool returned=false,visited=false,active=false,started=false; };
    std::array<Entry,16> entries_{};
    std::array<std::uint8_t,16> target_{};
    std::uint64_t last_=0,deadline_=0;
    unsigned count_=0,inflight_=0,sends_=0,rounds_=0;
    State state_=State::Idle;
};
} }
