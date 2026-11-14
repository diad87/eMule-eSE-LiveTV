#pragma once
#include "EseServerAuth.h"

namespace ese::server::rdv {
inline constexpr std::size_t DatagramSize=140;
using Datagram = std::array<std::uint8_t,DatagramSize>;

struct SessionContext {
    Bytes16 epoch{}, session{};
    std::uint64_t generation = 0;
};
struct Message {
    SessionContext context;
    std::uint8_t type = 0, family = 0;
    std::uint64_t sequence = 0;
    Bytes16 nonce{};
    Bytes32 cookie{};
};
struct Endpoint {
    std::array<std::uint8_t,16> address{};
    std::uint16_t port = 0;
    std::uint8_t family = 0;
};

class Crypto {
public:
    virtual ~Crypto()=default;
    virtual bool Hmac(const Bytes32& key,ByteView,Bytes32& output) noexcept=0;
    virtual bool Equal(const Bytes32&,const Bytes32&) noexcept=0;
};

// The listener may read the routing tuple to find a potential session. This
// does not authenticate the datagram and never authorizes a reply.
bool ReadContext(ByteView,SessionContext&) noexcept;
bool Encode(const Message&,const Bytes32& key,Crypto&,Datagram&) noexcept;
bool Decode(ByteView,Direction,const Bytes32& key,Crypto&,Message&) noexcept;
bool BuildCookie(const Message&,const Endpoint& observed,std::uint64_t timeBucket,
    const Bytes32& secret,Crypto&,Bytes32&) noexcept;
bool SameEndpoint(const Endpoint&,const Endpoint&) noexcept;

class CookieSecrets {
public:
    CookieSecrets() = default;
    CookieSecrets(const CookieSecrets&) = delete;
    CookieSecrets& operator=(const CookieSecrets&) = delete;
    ~CookieSecrets();
    bool Rotate(const Bytes32& newlyGenerated,std::uint64_t now) noexcept;
    const Bytes32* Current(std::uint64_t now) const noexcept;
    const Bytes32* Previous(std::uint64_t now) const noexcept;
private:
    Bytes32 current_{},previous_{};
    std::uint64_t issued_=0,previousUntil_=0;
};

struct Registration {
    Endpoint endpoint;
    std::uint64_t until = 0;
};
struct ReceiveResult {
    std::optional<Datagram> challenge;
    std::optional<Registration> status;
    bool supersededEndpoint = false;
};

// One authenticated application session, with independent sequence and UDP
// return proof per family. The caller owns the current and previous shared
// cookie secrets, session eligibility and endpoint allowlist.
class Session {
public:
    explicit Session(SessionContext context) noexcept : context_(context) {}
    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;
    ReceiveResult Receive(ByteView datagram,const Endpoint& observed,const Bytes32& udpKey,
        const CookieSecrets&,Crypto&,std::uint64_t now) noexcept;
    std::optional<Registration> Current(std::uint8_t family,std::uint64_t now) const noexcept;
private:
    struct Family {
        std::uint64_t highWater=0, challengeUntil=0, budgetBucket=0, issued=0;
        Datagram lastDatagram{};
        std::optional<Datagram> challenge;
        Endpoint endpoint;
        Message request;
        std::optional<Registration> registration;
    };
    SessionContext context_;
    std::array<Family,2> families_{};
};
}
