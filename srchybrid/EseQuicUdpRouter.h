#pragma once
#include "EseQuicUdpIngress.h"
#include "EseQuicTransport.h"
#include <cstring>
namespace ese {
// Single socket/session-owner thread. IDs are strictly increasing and never
// reused; socket detach precedes destruction. Reserved slots support CID
// registration while the native runtime is being constructed/started.
class QuicUdpRouter final : public QuicUdpIngress {
public:
    // Classification is not authentication. Consumer must recheck session,
    // request context, signature and deadline before acting on these bytes.
    struct PendingControl {
        udp::Endpoint peer{};
        std::array<std::uint8_t,1200> bytes{};
        std::size_t size=0;
        std::uint64_t owner=0,receivedMs=0;
    };
    bool PopControl(PendingControl& out) noexcept {
        out={}; if(!controlCount_) return false;
        out=control_[controlHead_]; control_[controlHead_]={};
        controlHead_=(controlHead_+1)%control_.size(); --controlCount_; return true;
    }
    void RemoveControl(std::uint64_t owner) noexcept {
        const auto count=controlCount_;
        for(std::size_t i=0;i<count;++i) {
            PendingControl packet;
            if(!PopControl(packet)) break;
            if(packet.owner!=owner) {
                control_[(controlHead_+controlCount_)%control_.size()]=packet;
                ++controlCount_;
            }
        }
    }
    explicit QuicUdpRouter(const udp::Inspector& probe) : probe_(probe) {}
    ~QuicUdpRouter();
    bool Reserve(std::uint64_t owner);
    bool Adopt(std::uint64_t owner,std::unique_ptr<QuicTransport>& transport);
    bool Release(std::uint64_t owner);
    QuicTransport* Find(std::uint64_t owner) const;
    bool RegisterCid(std::uint64_t owner,const udp::Cid& cid);
    bool RemoveCid(std::uint64_t owner,const udp::Cid& cid);
    void RemoveCids(std::uint64_t owner);
    udp::Decision Classify(const udp::Endpoint& peer,reach::DirectByteView packet,std::uint64_t now) const;
    bool Current(const udp::Decision& decision) const { return demux_.Current(decision); }
    bool ExpectInitial(std::uint64_t owner,const udp::Endpoint&,std::uint64_t expires);
    bool Receive(const udp::Endpoint&,reach::DirectByteView) noexcept override;
    void SocketReset() noexcept override;
    void Poll(std::uint64_t now) override;
private:
    struct Entry { std::uint64_t owner=0; std::unique_ptr<QuicTransport> transport; };
    Entry* Slot(std::uint64_t owner);
    const udp::Inspector& probe_;
    udp::Demux demux_;
    std::array<Entry,256> entries_{};
    std::array<PendingControl,32> control_{};
    std::size_t controlHead_=0,controlCount_=0;
    std::uint64_t lastOwner_=0,now_=0;
};
}
