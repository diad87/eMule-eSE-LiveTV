#pragma once
#include "EseControlCookieCrypto.h"
#include "EseControlPacketBudget.h"
namespace ese { namespace discovery {
enum class IndexBootstrapResult { Rejected, Challenge, Accepted, Duplicate };
// Main-thread bounded control-only admission. The socket owner installs a
// service session only on Accepted. Neither mask nor ACK grants a data route.
class Kad6IndexBootstrap {
public:
    explicit Kad6IndexBootstrap(control::PacketBudget& budget):budget_(budget) {}
    bool Initialize() noexcept { return authority_.Initialize(); }
    IndexBootstrapResult Receive(control::Sessions& sessions,const udp::Endpoint& endpoint,
        const std::array<std::uint8_t,32>& local,const std::uint8_t* bytes,std::size_t size,
        std::uint64_t now,control::Signer& signer,control::Datagram& response,
        std::array<std::uint8_t,32>& peer,control::Header& context) noexcept {
        response={}; peer={}; context={}; control::Envelope envelope;
        if((haveTime_ && now<last_) || now>(std::numeric_limits<std::uint64_t>::max)()-2000 ||
            !control::ParseUntrusted(bytes,size,envelope)) return IndexBootstrapResult::Rejected;
        haveTime_=true; last_=now;
        Pending* available=nullptr;
        for(auto& entry:pending_) {
            if(entry.used && now>=entry.until) entry={};
            if(!entry.used && !available) available=&entry;
        }
        if(envelope.header.type==wire::kEseWireUdpProbe) {
            control::Probe probe;
            if(!control::Decode(envelope.payload,envelope.payloadSize,probe) || probe.node==local || probe.peer!=local)
                return IndexBootstrapResult::Rejected;
            for(auto& entry:pending_) if(entry.used && entry.endpoint==endpoint &&
                entry.header.attempt==envelope.header.attempt && entry.header.generation==envelope.header.generation &&
                entry.header.sequence==envelope.header.sequence) {
                // An exact retry may repeat its challenge, never move its deadline.
                if(entry.probe.node!=probe.node || entry.probe.peer!=probe.peer || entry.probe.nonce!=probe.nonce ||
                    entry.probe.mask!=probe.mask || entry.probe.padding!=probe.padding || !budget_.Allow(now))
                    return IndexBootstrapResult::Rejected;
                response=entry.challengePacket; return IndexBootstrapResult::Challenge;
            }
            if(!available || !budget_.Allow(now) || !control::BuildChallenge(authority_,limit_,endpoint,local,
                probe.node,bytes,size,now,response)) return IndexBootstrapResult::Rejected;
            control::Envelope issued; control::Challenge challenge;
            if(!control::ParseUntrusted(response.bytes.data(),response.size,issued) ||
                !control::Decode(issued.payload,issued.payloadSize,challenge) ||
                !available->challenge.Remember(envelope.header,probe,challenge,now,now+2000)) {
                response={}; return IndexBootstrapResult::Rejected;
            }
            available->used=true; available->endpoint=endpoint; available->header=envelope.header;
            available->probe=probe; available->until=now+2000; available->challengePacket=response;
            return IndexBootstrapResult::Challenge;
        }
        if(envelope.header.type!=wire::kEseWireUdpProve) return IndexBootstrapResult::Rejected;
        control::Prove proof;
        if(!control::Decode(envelope.payload,envelope.payloadSize,proof)) return IndexBootstrapResult::Rejected;
        for(auto& entry:pending_) if(entry.used && entry.endpoint==endpoint && entry.challenge.Matches(envelope.header,proof,now)) {
            if(!budget_.Allow(now)) return IndexBootstrapResult::Rejected;
            const auto admission=control::AdmitProve(authority_,sessions,endpoint,local,entry.probe.node,bytes,size,now,proof);
            if(admission!=control::Admission::Accepted && admission!=control::Admission::Duplicate)
                return IndexBootstrapResult::Rejected;
            if(!control::BuildAck(proof,envelope.header,0,local,signer,response)) return IndexBootstrapResult::Rejected;
            peer=entry.probe.node; context=envelope.header;
            return admission==control::Admission::Accepted ? IndexBootstrapResult::Accepted : IndexBootstrapResult::Duplicate;
        }
        return IndexBootstrapResult::Rejected;
    }
private:
    struct Pending {
        udp::Endpoint endpoint; control::Header header; control::Probe probe;
        control::PendingBootstrapChallenge challenge; control::Datagram challengePacket;
        std::uint64_t until=0; bool used=false;
    };
    std::array<Pending,64> pending_{};
    control::CookieAuthority authority_; control::ChallengeLimit limit_;
    control::PacketBudget& budget_; std::uint64_t last_=0; bool haveTime_=false;
};
static_assert(sizeof(Kad6IndexBootstrap)<=128*1024,"index bootstrap metadata reservation");
} }
