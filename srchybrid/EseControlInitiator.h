#pragma once
#include "EseControlCookieCrypto.h"
namespace ese { namespace control {
enum class InitiatorState { Idle, Probe, Prove, Ready, Failed };
struct PendingDatagram { const std::uint8_t* data=nullptr; std::size_t size=0; };
// One attempt, main-thread. Owns retransmission bytes. Pending/Submitted are a
// two-phase send: WOULD_BLOCK does not consume a retransmission. READY here is
// a bound control exchange, not QUIC READY or verified eD2K identity/download.
class Initiator {
public:
    Initiator() noexcept = default;
    Initiator(const Initiator&)=delete;
    Initiator& operator=(const Initiator&)=delete;
    bool Start(const Header& header,const Probe& probe,const udp::Endpoint& peer,
        std::uint64_t now,std::uint64_t deadline) noexcept {
        if(state_!=InitiatorState::Idle || header.type!=wire::kEseWireUdpProbe ||
            !header.sequence || !header.generation || !peer.port || deadline<=now) return false;
        unsigned attempt=0,nonce=0,node=0,remote=0;
        for(auto b:header.attempt) attempt|=b; for(auto b:probe.nonce) nonce|=b;
        for(auto b:probe.node) node|=b; for(auto b:probe.peer) remote|=b;
        if(!attempt || !nonce || !node || !remote) return false;
        std::array<std::uint8_t,128> body{};
        if(!Encode(probe,body) || !Encode(header,body.data(),body.size(),probePacket_)) return false;
        header_=header; probe_=probe; peer_=peer; deadline_=deadline;
        stageStart_=lastNow_=now; state_=InitiatorState::Probe; return true;
    }
    PendingDatagram Pending(std::uint64_t now) noexcept {
        if(!Clock(now) || !Due(now)) return {};
        const auto& packet=state_==InitiatorState::Probe ? probePacket_ : provePacket_;
        return {packet.bytes.data(),packet.size};
    }
    bool Submitted(std::uint64_t now) noexcept {
        if(!Clock(now) || !Due(now)) return false;
        ++sent_; return true;
    }
    bool ChallengeReceived(const udp::Endpoint& source,const std::uint8_t* packet,
        std::size_t size,std::uint64_t now,Signer& signer) noexcept {
        if(!Clock(now) || state_!=InitiatorState::Probe || !sent_ || !(source==peer_)) return false;
        Envelope envelope; Challenge challenge;
        if(!ParseUntrusted(packet,size,envelope) || envelope.header.type!=wire::kEseWireUdpChallenge ||
            envelope.header.attempt!=header_.attempt || envelope.header.generation!=header_.generation ||
            envelope.header.sequence!=header_.sequence || !Decode(envelope.payload,envelope.payloadSize,challenge) ||
            challenge.nonce!=probe_.nonce) return false;
        Prove proof; proof.probe=probe_; proof.cookie=challenge.cookie; proof.epoch=challenge.epoch;
        std::array<std::uint8_t,212> body{}; Datagram next;
        auto header=header_; header.type=wire::kEseWireUdpProve;
        SignatureInput input;
        if(!Encode(proof,body) || !Encode(header,body.data(),body.size(),next) ||
            !BuildSignatureInput(next.bytes.data(),next.size,input) ||
            !signer.Sign(input.bytes.data(),input.size,proof.signature)) return false;
        std::memcpy(next.bytes.data()+next.size-64,proof.signature.data(),64);
        if(!VerifyEnvelopeSignature(probe_.node,next.bytes.data(),next.size)) return false;
        provePacket_=next; proveHeader_=header; sent_=0; stageStart_=now;
        state_=InitiatorState::Prove; return true;
    }
    bool AckReceived(const udp::Endpoint& source,const std::uint8_t* packet,
        std::size_t size,std::uint64_t now) noexcept {
        if(!Clock(now) || state_!=InitiatorState::Prove || !sent_ || !(source==peer_)) return false;
        Ack ack;
        if(!VerifyAck(probe_.peer,proveHeader_,probe_.nonce,probe_.mask,packet,size,ack)) return false;
        selected_=ack.selected; state_=InitiatorState::Ready; return true;
    }
    InitiatorState State() const noexcept { return state_; }
    std::uint8_t Selected() const noexcept { return state_==InitiatorState::Ready ? selected_ : 0; }
    void Cancel() noexcept { if(state_!=InitiatorState::Idle) state_=InitiatorState::Failed; }
private:
    bool Clock(std::uint64_t now) noexcept {
        if(state_==InitiatorState::Idle || state_==InitiatorState::Failed) return false;
        if(now<lastNow_ || (state_!=InitiatorState::Ready && now>=deadline_)) { state_=InitiatorState::Failed; return false; }
        lastNow_=now; return true;
    }
    bool Due(std::uint64_t now) const noexcept {
        static constexpr std::uint64_t schedule[]={0,400,1200};
        return (state_==InitiatorState::Probe || state_==InitiatorState::Prove) && sent_<3 && now-stageStart_>=schedule[sent_];
    }
    Header header_,proveHeader_;
    Probe probe_;
    udp::Endpoint peer_;
    Datagram probePacket_,provePacket_;
    std::uint64_t stageStart_=0,lastNow_=0,deadline_=0;
    unsigned sent_=0;
    std::uint8_t selected_=0;
    InitiatorState state_=InitiatorState::Idle;
};
} }
