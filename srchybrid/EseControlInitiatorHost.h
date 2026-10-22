#pragma once
#include "EseControlInitiator.h"
#include "EseQuicHostFactory.h"
namespace ese { namespace control {
// One main-thread attempt. Host and signer outlive this adapter. Caller owns
// owner allocation, endpoint/pin policy and CSPRNG context. No route or eD2K
// identity is granted by Ready; no session ledger is implicitly mutated.
class InitiatorHost {
public:
    explicit InitiatorHost(QuicSessionHost& host) noexcept : host_(host) {}
    ~InitiatorHost() { Cancel(); }
    InitiatorHost(const InitiatorHost&)=delete;
    InitiatorHost& operator=(const InitiatorHost&)=delete;
    bool Start(std::uint64_t owner,const Header& header,const Probe& probe,
        const udp::Endpoint& peer,std::uint64_t now,std::uint64_t deadline) {
        if(!owner || owner_ || deadline<=now || deadline-now>2000 ||
            !initiator_.Start(header,probe,peer,now,deadline)) return false;
        owner_=owner; header_=header; peer_=peer; deadline_=deadline;
        if(!host_.ExpectControlReply(header_,wire::kEseWireUdpChallenge,peer_,owner_,deadline_)) {
            Cancel(); return false;
        }
        return true;
    }
    void Poll(std::uint64_t now) {
        if(!owner_) return;
        const auto packet=initiator_.Pending(now);
        if(initiator_.State()==InitiatorState::Failed) { Cancel(); return; }
        if(!packet.size) return;
        const auto result=host_.SendControl(peer_,{packet.data,packet.size});
        if(result.status==QuicUdpSendStatus::Sent) {
            if(!initiator_.Submitted(now)) Cancel();
        } else if(result.status!=QuicUdpSendStatus::WouldBlock) Cancel();
    }
    bool Receive(std::uint64_t owner,const udp::Endpoint& source,
        const std::uint8_t* bytes,std::size_t size,std::uint64_t now,Signer& signer) {
        if(!owner_ || owner!=owner_) return false;
        if(initiator_.State()==InitiatorState::Probe) {
            if(!initiator_.ChallengeReceived(source,bytes,size,now,signer)) return false;
            host_.RemoveControlReplies(owner_);
            if(!host_.ExpectControlReply(header_,wire::kEseWireUdpAck,peer_,owner_,deadline_)) {
                Cancel(); return false;
            }
            return true;
        }
        if(!initiator_.AckReceived(source,bytes,size,now)) return false;
        host_.RemoveControlReplies(owner_); owner_=0; return true;
    }
    void Cancel() {
        if(owner_) { host_.RemoveControlReplies(owner_); owner_=0; }
        // Receive releases the reply registration on ACK, but cancellation
        // must also revoke a completed negotiation and its selected transport.
        initiator_.Cancel();
    }
    InitiatorState State() const noexcept { return initiator_.State(); }
    std::uint8_t Selected() const noexcept { return initiator_.Selected(); }
private:
    QuicSessionHost& host_; Initiator initiator_; Header header_;
    udp::Endpoint peer_; std::uint64_t owner_=0,deadline_=0;
};
} }
