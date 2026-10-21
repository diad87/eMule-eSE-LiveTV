#pragma once
#include "../../srchybrid/EseQuicUdpIngress.h"
#include <array>
#include <algorithm>
#include <memory>

// TEST ONLY: a logical datagram namespace, not public IP ownership, physical
// UDP, NAT traversal or return-path evidence on the user's network. No socket
// API exists here: unknown destinations cannot escape onto the Internet.
namespace ese { namespace test {
class SimulatedQuicPort final : public QuicSocketPort {
public:
    static constexpr std::size_t Capacity=64,MaxPacket=1200;
    explicit SimulatedQuicPort(udp::Endpoint endpoint)
        : endpoint_(endpoint),packets_(std::make_unique<std::array<Packet,Capacity>>()) {}
    SimulatedQuicPort(const SimulatedQuicPort&)=delete;
    SimulatedQuicPort& operator=(const SimulatedQuicPort&)=delete;
    ~SimulatedQuicPort() override {
        if(remote_ && remote_->remote_==this) remote_->remote_=nullptr;
        if(ingress_) { auto* old=ingress_; ingress_=nullptr; old->SocketReset(); }
    }
    bool Link(SimulatedQuicPort& peer) noexcept {
        if(&peer==this || remote_ || peer.remote_ || endpoint_==peer.endpoint_ ||
            !endpoint_.port || !peer.endpoint_.port || size_ || peer.size_) return false;
        remote_=&peer; peer.remote_=this; return true;
    }
    bool AttachQuicIngress(QuicUdpIngress* ingress) override {
        if(!ingress || ingress_) return false;
        ingress_=ingress; return true;
    }
    bool DetachQuicIngress(QuicUdpIngress* ingress) override {
        if(!ingress || ingress_!=ingress) return false;
        ingress_=nullptr; head_=size_=dropNext_=0; ingress->SocketReset(); return true;
    }
    QuicUdpSendResult SendQuicDatagram(QuicUdpIngress* ingress,const udp::Endpoint& destination,
        const std::uint8_t* bytes,std::size_t length) override {
        if(!ingress || ingress!=ingress_ || !bytes || !length || length>MaxPacket) return {QuicUdpSendStatus::Invalid,0};
        if(!remote_ || !remote_->ingress_) return {QuicUdpSendStatus::Closed,0};
        if(!(destination==remote_->endpoint_)) return {QuicUdpSendStatus::Invalid,0};
        if(dropNext_) { --dropNext_; ++dropped_; return {QuicUdpSendStatus::Sent,0}; }
        if(remote_->size_==Capacity) return {QuicUdpSendStatus::WouldBlock,0};
        auto& packet=(*remote_->packets_)[(remote_->head_+remote_->size_)%Capacity];
        packet.source=endpoint_; packet.length=length;
        std::copy_n(bytes,length,packet.bytes.begin()); ++remote_->size_;
        return {QuicUdpSendStatus::Sent,0};
    }
    std::size_t Deliver(std::size_t budget=Capacity) noexcept {
        std::size_t delivered=0;
        while(ingress_ && size_ && delivered<budget) {
            const auto packet=(*packets_)[head_]; // Stable even if Receive reenters the fixture.
            head_=(head_+1)%Capacity; --size_; ++delivered;
            if(!ingress_->Receive(packet.source,{packet.bytes.data(),packet.length})) ++unclaimed_;
        }
        return delivered;
    }
    std::size_t Queued() const noexcept { return size_; }
    bool DropNext(std::size_t count) noexcept {
        if(!count || count>Capacity || dropNext_) return false;
        dropNext_=count; return true;
    }
    std::size_t Dropped() const noexcept { return dropped_; }
    // The memory adapter replaces the socket event loop as well as datagrams.
    // Caller supplies monotonic time; detached owners must never be polled.
    void Poll(std::uint64_t now) { if(ingress_) ingress_->Poll(now); }
    std::size_t Unclaimed() const noexcept { return unclaimed_; }
    const udp::Endpoint& Endpoint() const noexcept { return endpoint_; }
private:
    struct Packet { udp::Endpoint source; std::array<std::uint8_t,MaxPacket> bytes{}; std::size_t length=0; };
    udp::Endpoint endpoint_;
    std::unique_ptr<std::array<Packet,Capacity>> packets_;
    SimulatedQuicPort* remote_=nullptr;
    QuicUdpIngress* ingress_=nullptr;
    std::size_t head_=0,size_=0,unclaimed_=0,dropNext_=0,dropped_=0;
};
} }
