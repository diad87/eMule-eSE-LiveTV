#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
namespace ese { namespace udp {
struct Endpoint {
    std::array<std::uint8_t,16> address{};
    std::uint32_t scope=0;
    std::uint16_t port=0;
    bool ipv6=false;
    bool operator==(const Endpoint& other) const noexcept {
        return address==other.address && scope==other.scope && port==other.port && ipv6==other.ipv6;
    }
};
struct Cid { std::array<std::uint8_t,20> bytes{}; std::uint8_t size=0; };
enum class Match { None, Valid, Invalid };
enum class Channel { Legacy, Control, Quic, Utp, Drop };
struct Header { Cid destination; bool initial=false; };
// Inspection must not consume expectations or call a mutating network parser.
// QUIC header decoding is supplied by ngtcp2, not implemented here.
class Inspector {
public:
    virtual ~Inspector() = default;
    virtual Match Control(const std::uint8_t*,std::size_t,const Endpoint&,std::uint64_t&) const noexcept = 0;
    virtual bool QuicHeader(const std::uint8_t*,std::size_t,std::size_t shortCidSize,Header&) const noexcept = 0;
    virtual bool AcceptInitial(const std::uint8_t*,std::size_t) const noexcept = 0;
    virtual Match Utp(const std::uint8_t*,std::size_t,const Endpoint&,std::uint64_t&) const noexcept = 0;
};
struct Decision { Channel channel=Channel::Legacy; std::uint64_t owner=0,revision=0; bool newInitial=false; };
class Demux {
public:
    bool RegisterCid(const Cid&,std::uint64_t owner) noexcept;
    bool RemoveCid(const Cid&,std::uint64_t owner) noexcept;
    bool ExpectInitial(const Endpoint&,std::uint64_t owner,std::uint64_t expiresMs) noexcept;
    void RemoveOwner(std::uint64_t owner) noexcept;
    void Expire(std::uint64_t nowMs) noexcept;
    Decision Inspect(const Inspector&,const std::uint8_t*,std::size_t,const Endpoint&,std::uint64_t nowMs) const noexcept;
    // Recheck immediately before delivery. Registry mutation invalidates plans;
    // auth failure after classification is dropped, never retried as Legacy.
    bool Current(const Decision& d) const noexcept {
        return revision_!=(std::numeric_limits<std::uint64_t>::max)() && d.revision==revision_;
    }
private:
    struct Registered { Cid cid; std::uint64_t owner=0; };
    struct Expected { Endpoint endpoint; std::uint64_t owner=0,expires=0; };
    std::array<Registered,2048> cids_{}; // <=8 CIDs per owner
    std::array<Expected,128> expected_{};
    std::uint64_t revision_=1;
};
} }
