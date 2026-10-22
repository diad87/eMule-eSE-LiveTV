#pragma once
#include "EseControlEnvelope.h"
#include "EseUdpDemux.h"
#include <limits>
namespace ese { namespace control {
enum class Admission { Accepted, Duplicate, Rejected, Full };
// Main-thread bounded replay/session ledger. Call ONLY after complete cookie,
// signature and expected-key verification. Does not itself authenticate bytes.
// Duplicate bootstrap never refreshes idle TTL; inactive entries are retained
// as tombstones beyond the maximum two cookie epochs to prevent resurrection.
class Sessions {
public:
    // Retain only the replay high-water for an explicitly owned live download.
    // Does not renew lastActivity or grant control permission. Repeating the
    // same owner is idempotent; ownership cannot be silently transferred.
    bool RetainDownload(const std::array<std::uint8_t,32>& peer,const udp::Endpoint& endpoint,
        const Header& context,std::uint64_t owner,std::uint64_t now) noexcept {
        if(!owner || !Clock(now)) return false;
        for(auto& entry:entries_) if(entry.used && entry.peer==peer && entry.endpoint==endpoint &&
            entry.header.attempt==context.attempt && entry.header.generation==context.generation) {
            if(now<entry.lastActivity || (entry.downloadOwner && entry.downloadOwner!=owner)) return false;
            entry.downloadOwner=owner; return true;
        }
        return false;
    }
    void ReleaseDownload(std::uint64_t owner) noexcept {
        if(owner) for(auto& entry:entries_) if(entry.downloadOwner==owner) entry.downloadOwner=0;
    }
    // Non-mutating guard for pending replies. No idle-TTL extension or replay
    // consumption before the reply's signature/context have been validated.
    bool Current(const std::array<std::uint8_t,32>& peer,const udp::Endpoint& endpoint,
        const Header& context,std::uint64_t now) const noexcept {
        if(clockSet_ && now<lastNow_) return false;
        for(const auto& entry:entries_) if(entry.used && entry.peer==peer &&
            entry.header.attempt==context.attempt && entry.header.generation==context.generation &&
            entry.endpoint==endpoint && context.sequence>=entry.header.sequence &&
            now>=entry.lastActivity && Active(entry,now)) return true;
        return false;
    }
    // Reserve a fresh outbound request sequence in an exact live session.
    // No idle renewal; a failed send still consumes this sequence. Retries
    // reuse the reserved signed packet and do not call this again.
    bool NextRequest(const std::array<std::uint8_t,32>& peer,const udp::Endpoint& endpoint,
        const Header& session,std::uint8_t type,std::uint64_t now,Header& out) noexcept {
        out={};
        if((type!=wire::kEseWireUdpK6DirectFind && type!=wire::kEseWireUdpDescriptorGet &&
            type!=wire::kEseWireUdpK6ContactGet && type!=wire::kEseWireUdpDescriptorPut &&
            type!=wire::kEseWireUdpK6DirectPut) ||
            !Clock(now)) return false;
        for(auto& entry:entries_) if(entry.used && entry.peer==peer && entry.endpoint==endpoint &&
            entry.header.attempt==session.attempt && entry.header.generation==session.generation &&
            now>=entry.lastActivity && Active(entry,now)) {
            const auto sequence=(entry.outgoingSequence>entry.lastSequence)?entry.outgoingSequence:entry.lastSequence;
            if(sequence==(std::numeric_limits<std::uint32_t>::max)()) return false;
            entry.outgoingSequence=sequence+1; out=entry.header;
            out.type=type; out.sequence=entry.outgoingSequence; return true;
        }
        return false;
    }
    // Track explicitly supplied signed requests before switching to automatic
    // sequence allocation. This grants no authentication or send permission.
    bool RememberOutgoing(const std::array<std::uint8_t,32>& peer,const udp::Endpoint& endpoint,
        const Header& request,std::uint64_t now) noexcept {
        if(!request.sequence || !Current(peer,endpoint,request,now)) return false;
        for(auto& entry:entries_) if(entry.used && entry.peer==peer && entry.endpoint==endpoint &&
            entry.header.attempt==request.attempt && entry.header.generation==request.generation) {
            if(request.sequence>entry.outgoingSequence) entry.outgoingSequence=request.sequence;
            return true;
        }
        return false;
    }
    Admission AdmitVerified(const std::array<std::uint8_t,32>& peer,const udp::Endpoint& endpoint,
        const Header& header,const std::array<std::uint8_t,32>& proofDigest,std::uint64_t now) noexcept {
        if(!Clock(now) || !header.sequence || !header.generation || !endpoint.port) return Admission::Rejected;
        unsigned key=0,attempt=0; for(auto b:peer) key|=b; for(auto b:header.attempt) attempt|=b;
        if(!key || !attempt) return Admission::Rejected;
        Entry* free=nullptr;
        for(auto& entry:entries_) {
            if(entry.used && !entry.downloadOwner && now-entry.lastActivity>=64000) entry.used=false;
            if(!entry.used) { if(!free) free=&entry; continue; }
            if(entry.peer!=peer || entry.header.attempt!=header.attempt) continue;
            if(!Active(entry,now) || !(entry.endpoint==endpoint) || entry.header.generation!=header.generation ||
                entry.header.sequence!=header.sequence || entry.digest!=proofDigest) return Admission::Rejected;
            return Admission::Duplicate;
        }
        if(!free) return Admission::Full;
        *free=Entry{}; free->used=true; free->peer=peer; free->endpoint=endpoint;
        free->header=header; free->digest=proofDigest; free->lastActivity=now;
        free->lastSequence=header.sequence; return Admission::Accepted;
    }
    // Fresh signed bootstrap for an already active exact session. Reserve a
    // strictly newer sequence before sending; no idle renewal or wrap on send.
    bool NextBootstrap(const std::array<std::uint8_t,32>& peer,const udp::Endpoint& endpoint,
        const Header& session,std::uint64_t now,Header& out) noexcept {
        const auto context=session; // input/output may alias in the owning host
        out={};
        if(!Clock(now)) return false;
        for(auto& entry:entries_) if(entry.used && entry.peer==peer && entry.endpoint==endpoint &&
            entry.header.attempt==context.attempt && entry.header.generation==context.generation) {
            if(now<entry.lastActivity || !Active(entry,now)) return false;
            const auto sequence=(std::max)(entry.lastSequence,entry.outgoingSequence);
            if(sequence==(std::numeric_limits<std::uint32_t>::max)()) return false;
            entry.outgoingSequence=sequence+1; out=entry.header;
            out.type=wire::kEseWireUdpProbe; out.sequence=entry.outgoingSequence; return true;
        }
        return false;
    }
    // Reserve a new proof exchange for an expired but retained exact session.
    // Allocation grants no control/data permission and never renews idle TTL.
    // Caller must own the still-live download and use a fresh CSPRNG nonce.
    bool NextExpiredBootstrap(const std::array<std::uint8_t,32>& peer,const udp::Endpoint& endpoint,
        const Header& session,std::uint64_t now,Header& out) noexcept {
        const auto context=session;
        out={};
        if(!Clock(now)) return false;
        for(auto& entry:entries_) if(entry.used && entry.peer==peer && entry.endpoint==endpoint &&
            entry.header.attempt==context.attempt && entry.header.generation==context.generation) {
            if(now<entry.lastActivity || Active(entry,now)) return false;
            const auto sequence=(std::max)(entry.lastSequence,entry.outgoingSequence);
            if(sequence==(std::numeric_limits<std::uint32_t>::max)()) return false;
            entry.outgoingSequence=sequence+1; out=entry.header;
            out.type=wire::kEseWireUdpProbe; out.sequence=entry.outgoingSequence; return true;
        }
        return false;
    }
    // Caller has verified the NEW nonce/cookie/signature and correlation.
    // Does not resurrect expired tombstones or move endpoint/generation.
    Admission ReadmitVerified(const std::array<std::uint8_t,32>& peer,const udp::Endpoint& endpoint,
        const Header& header,const std::array<std::uint8_t,32>& proofDigest,std::uint64_t now) noexcept {
        if(!Clock(now) || !header.sequence || !header.generation || !endpoint.port) return Admission::Rejected;
        for(auto& entry:entries_) if(entry.used && entry.peer==peer && entry.header.attempt==header.attempt) {
            if(now<entry.lastActivity || !Active(entry,now) || !(entry.endpoint==endpoint) ||
                entry.header.generation!=header.generation || header.sequence<=entry.lastSequence ||
                header.sequence<entry.outgoingSequence || entry.digest==proofDigest) return Admission::Rejected;
            entry.header=header; entry.digest=proofDigest; entry.lastSequence=header.sequence;
            entry.outgoingSequence=header.sequence; entry.lastActivity=now; return Admission::Accepted;
        }
        return Admission::Rejected;
    }
    // Explicit replacement of an expired exact control session, NOT replay
    // admission. Caller must authenticate a proof correlated to its newly
    // issued challenge (responder) or fresh nonce exchange (initiator).
    // issued is local monotonic time, never a field supplied by the peer.
    // The retained high-water fence remains authoritative; missing entries
    // cannot be reconstructed by this method. Current stays false until here.
    Admission ReadmitFreshVerified(const std::array<std::uint8_t,32>& peer,const udp::Endpoint& endpoint,
        const Header& header,const std::array<std::uint8_t,32>& proofDigest,
        std::uint64_t issued,std::uint64_t now) noexcept {
        if(!Clock(now) || issued>now || now-issued>=2000 || !header.sequence ||
            !header.generation || !endpoint.port) return Admission::Rejected;
        for(auto& entry:entries_) if(entry.used && entry.peer==peer && entry.header.attempt==header.attempt) {
            if(now<entry.lastActivity || Active(entry,now) || issued<=entry.lastActivity ||
                !(entry.endpoint==endpoint) || entry.header.generation!=header.generation ||
                header.sequence<=entry.lastSequence || header.sequence<entry.outgoingSequence ||
                entry.digest==proofDigest) return Admission::Rejected;
            entry.header=header; entry.digest=proofDigest; entry.lastSequence=header.sequence;
            entry.outgoingSequence=header.sequence; entry.lastActivity=now; return Admission::Accepted;
        }
        return Admission::Rejected;
    }
    bool ObserveVerified(const std::array<std::uint8_t,32>& peer,const udp::Endpoint& endpoint,
        const Header& header,std::uint64_t now) noexcept {
        if(!Clock(now)) return false;
        for(auto& entry:entries_) if(entry.used && entry.peer==peer && entry.header.attempt==header.attempt) {
            if(!Active(entry,now) || !(entry.endpoint==endpoint) || entry.header.generation!=header.generation ||
                header.sequence<=entry.lastSequence) return false;
            entry.lastSequence=header.sequence; entry.lastActivity=now; return true;
        }
        return false;
    }
private:
    struct Entry {
        std::array<std::uint8_t,32> peer{},digest{};
        udp::Endpoint endpoint;
        Header header;
        std::uint64_t lastActivity=0;
        std::uint64_t downloadOwner=0;
        std::uint32_t lastSequence=0;
        std::uint32_t outgoingSequence=0;
        bool used=false;
    };
    static bool Active(const Entry& entry,std::uint64_t now) noexcept { return now-entry.lastActivity<30000; }
    bool Clock(std::uint64_t now) noexcept {
        if(clockSet_ && now<lastNow_) return false;
        clockSet_=true; lastNow_=now; return true;
    }
    std::array<Entry,256> entries_{};
    std::uint64_t lastNow_=0;
    bool clockSet_=false;
};
} }
