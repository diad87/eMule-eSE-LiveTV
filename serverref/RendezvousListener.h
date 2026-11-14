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
    bool Attach(const rdv::SessionContext&,const Bytes32& key,const ClientHello&,std::uint64_t expiration);
    void Update(const rdv::SessionContext&,bool loggedIn,std::uint64_t expiration);
    void Remove(const rdv::SessionContext&) noexcept;
    std::optional<rdv::Registration> TakeStatus(const rdv::SessionContext&,std::uint64_t now);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
}
