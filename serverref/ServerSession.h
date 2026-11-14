#pragma once
#include "EseServerAuth.h"
#include "ServerIndex.h"
#include <vector>

namespace ese::server {
using EncodedFrame = std::vector<std::uint8_t>;
using Responses = std::vector<EncodedFrame>;

struct ServerEndpoint {
    Bytes16 identity;
    std::array<std::uint8_t,4> ipv4;
    std::uint16_t port = 0;
    std::uint32_t lowId = 1;
};

// Initial reference operations. The session starts only after AUTH_OK was sent.
// Takes no pointers into caller-owned frames after Handle returns.
class ServerSession {
public:
    ServerSession(const ClientHello& authenticatedClient,ServerEndpoint endpoint,ServerIndex&,
        std::uint64_t generation,std::uint64_t now);
    ~ServerSession();
    ServerSession(const ServerSession&) = delete;
    ServerSession& operator=(const ServerSession&) = delete;
    bool Handle(const FrameView&,AuthCrypto&,std::uint64_t now,Responses& output);
    enum class RequestUse { New, OtherOperation, SameOperation, ResourceLimit };
    RequestUse ClaimDeferred(const RequestId&,std::uint16_t type,std::uint64_t now);
    bool LoggedIn() const noexcept { return loggedIn_; }
    bool Closed() const noexcept { return closed_; }
    std::uint64_t Deadline() const noexcept { return lease_; }
private:
    struct Completed {
        RequestId request;
        Bytes32 digest;
        std::uint64_t until;
        Responses responses;
    };
    bool Dispatch(const FrameView&,AuthCrypto&,std::uint64_t now,Responses&,bool& loggedIn,bool& closed,
        std::uint64_t& lease);

    ClientHello client_;
    ServerEndpoint endpoint_;
    std::uint64_t lease_ = 0;
    std::vector<Completed> completed_;
    struct Deferred {
        RequestId request;
        std::uint16_t type;
        std::uint64_t until;
    };
    std::vector<Deferred> deferred_;
    ServerIndex& index_;
    const std::uint64_t generation_;
    bool loggedIn_ = false;
    bool closed_ = false;
};
}
