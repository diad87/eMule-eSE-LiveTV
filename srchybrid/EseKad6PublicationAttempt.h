#pragma once
#include "EseControlCookieCrypto.h"
#include <memory>
namespace ese { namespace discovery {
enum class PublicationState { Idle, Pending, Restage, Stored, Failed };
// One explicitly owned W attempt. Immutable signed pair, exact session,
// maximum one NEED_DESCRIPTOR restage and one original 2s deadline.
class PublicationAttempt {
public:
    bool Start(control::Sessions& sessions,const std::array<std::uint8_t,32>& witness,const udp::Endpoint& endpoint,
        const control::Header& session,const std::uint8_t* descriptor,std::size_t length,
        const std::array<std::uint8_t,173>& source,std::uint64_t maximum,std::uint64_t now,control::Signer& signer) noexcept {
        if(state_!=PublicationState::Idle || now>(std::numeric_limits<std::uint64_t>::max)()-2000 ||
            !control::VerifyDirectSource(Publisher(source),source.data(),source.size(),maximum,source_) ||
            !sessions.Current(witness,endpoint,session,now) || session.generation!=source_.generation) return false;
        DescriptorView checked;
        if(!descriptor || length>descriptor_.size() || !control::VerifyDescriptor(source_.node,source_.digest,descriptor,length,checked) ||
            checked.generation!=source_.generation || checked.serial!=source_.serial || checked.ttl!=source_.ttl) return false;
        std::memcpy(descriptor_.data(),descriptor,length); length_=length; sourceBytes_=source;
        witness_=witness; endpoint_=endpoint; session_=session; maximum_=maximum;
        last_=now; until_=now+2000; firstSend_=now;
        return Prepare(sessions,now,signer);
    }
    bool Restage(control::Sessions& sessions,std::uint64_t now,control::Signer& signer) noexcept {
        if(!Poll(now) || state_!=PublicationState::Restage || now<firstSend_+1000 || retried_) return false;
        retried_=true; return Prepare(sessions,now,signer);
    }
    bool Receive(const control::Sessions& sessions,const udp::Endpoint& endpoint,const std::uint8_t* bytes,
        std::size_t size,std::uint64_t now,std::uint8_t& status) noexcept {
        status=255;
        if(!Poll(now) || state_!=PublicationState::Pending || !pending_ ||
            !sessions.Current(witness_,endpoint_,request_,now) || !pending_->Receive(endpoint,bytes,size,now,status)) return false;
        pending_.reset();
        state_=status==0 ? PublicationState::Stored : (status==1 && !retried_ ? PublicationState::Restage : PublicationState::Failed);
        if(state_==PublicationState::Restage) {
            // ACK receipt is after W consumed its first PUT quota. An anchor
            // at Start/Send can race W's 1-second limiter by network latency.
            if(until_-now<=1001) state_=PublicationState::Failed;
            else firstSend_=now+1; // Guard millisecond quantisation between peers.
        }
        return true;
    }
    bool Poll(std::uint64_t now) noexcept {
        if(state_!=PublicationState::Pending && state_!=PublicationState::Restage) return false;
        if(now<last_ || now>=until_) { Cancel(); return false; }
        last_=now; return true;
    }
    bool Current(const control::Sessions& sessions,std::uint64_t now) noexcept {
        if(!Poll(now) || !sessions.Current(witness_,endpoint_,request_,now)) { Cancel(); return false; }
        return true;
    }
    void Cancel() noexcept { state_=PublicationState::Failed; pending_.reset(); }
    PublicationState State() const noexcept { return state_; }
    std::uint64_t Deadline() const noexcept { return until_; }
    const control::Header& Request() const noexcept { return request_; }
    const control::Datagram& DescriptorPacket() const noexcept { return descriptorPacket_; }
    const control::Datagram& SourcePacket() const noexcept { return sourcePacket_; }
    const udp::Endpoint& Endpoint() const noexcept { return endpoint_; }
private:
    static std::array<std::uint8_t,32> Publisher(const std::array<std::uint8_t,173>& source) noexcept {
        std::array<std::uint8_t,32> node{}; std::memcpy(node.data(),source.data()+25,32); return node;
    }
    bool Prepare(control::Sessions& sessions,std::uint64_t now,control::Signer& signer) noexcept {
        control::Header descriptorRequest,sourceRequest;
        if(!sessions.NextRequest(witness_,endpoint_,session_,wire::kEseWireUdpDescriptorPut,now,descriptorRequest) ||
            !control::BuildDescriptorPut(descriptorRequest,source_.file,descriptor_.data(),length_,source_.node,signer,descriptorPacket_) ||
            !sessions.NextRequest(witness_,endpoint_,session_,wire::kEseWireUdpK6DirectPut,now,sourceRequest) ||
            !control::BuildDirectPut(sourceRequest,sourceBytes_.data(),sourceBytes_.size(),maximum_,source_.node,signer,sourcePacket_)) {
            Cancel(); return false;
        }
        try { pending_=std::make_unique<control::DirectPutRequest>(); } catch(...) { Cancel(); return false; }
        if(!pending_->Start(witness_,endpoint_,sourceRequest,source_,maximum_,now)) { Cancel(); return false; }
        request_=sourceRequest; state_=PublicationState::Pending; return true;
    }
    std::array<std::uint8_t,DescriptorMax> descriptor_{}; std::size_t length_=0;
    std::array<std::uint8_t,173> sourceBytes_{}; DirectSource source_;
    std::array<std::uint8_t,32> witness_{}; udp::Endpoint endpoint_; control::Header session_,request_;
    control::Datagram descriptorPacket_,sourcePacket_; std::unique_ptr<control::DirectPutRequest> pending_;
    std::uint64_t maximum_=0,firstSend_=0,last_=0,until_=0;
    PublicationState state_=PublicationState::Idle; bool retried_=false;
};
} }
