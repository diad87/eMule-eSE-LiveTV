#pragma once
#include "EseRendezvousV2.h"
#include <memory>

namespace ese::server {
class ServerIndex;
class RendezvousListener {
public:
    RendezvousListener(ServerIndex&,std::uint16_t port);
    ~RendezvousListener();
    std::uint16_t Port() const noexcept;
    bool Attach(const rdv::SessionContext&,const Bytes32& key,const ClientHello&,std::uint64_t expiration,bool pairing);
    void Update(const rdv::SessionContext&,bool loggedIn,std::uint64_t expiration);
    void Remove(const rdv::SessionContext&) noexcept;
    std::optional<rdv::Registration> TakeStatus(const rdv::SessionContext&,std::uint64_t now);
    struct ControlReply {
        std::uint16_t type;
        bool terminal;
        std::vector<std::uint8_t> body;
    };
    bool Handles(std::uint16_t type) const noexcept;
    std::optional<ControlReply> Handle(const rdv::SessionContext&,const FrameView&,std::uint64_t now);
    std::optional<std::vector<std::uint8_t>> TakeControl(const rdv::SessionContext&,std::uint64_t now);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
}
