#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include "EseWireProtocol.h"

// Wire helpers and binding state machine. Cryptographic operations are supplied
// by the transport; decoding a HELLO alone does not authenticate a peer.
namespace ese { namespace binding {
constexpr std::size_t HelloSize = 110;
constexpr std::size_t AuthSize = 65;
constexpr std::size_t MaxControlLength = 4096;
constexpr std::uint32_t KnownCaps = wire::kEseWireCapQuicStream | wire::kEseWireCapDvlProfile | wire::kEseWireCapRemoteCredit;
struct Hello {
    std::uint8_t role = 0;
    std::array<std::uint8_t,32> node{};
    std::array<std::uint8_t,16> userHash{}, attempt{};
    std::uint64_t topologyGeneration = 0;
    std::array<std::uint8_t,32> nonce{};
    std::uint32_t caps = 0;
};
bool EncodeHello(const Hello&, std::array<std::uint8_t,HelloSize>&) noexcept;
bool DecodeHello(const std::uint8_t*, std::size_t, Hello&) noexcept;
// Exact signature domain, including its terminating NUL, then exporter,
// transcript SHA256 and role. Hashing/signing is deliberately not duplicated.
std::array<std::uint8_t,81> AuthMessage(
    const std::array<std::uint8_t,32>& exporter,
    const std::array<std::uint8_t,32>& context, std::uint8_t role) noexcept;
enum class ReadResult { NeedMore, Frame, Invalid };
class Crypto {
public:
    virtual ~Crypto() = default;
    virtual bool Hash(const std::uint8_t*,std::size_t,std::array<std::uint8_t,32>&) noexcept = 0;
    // Must use the normal post-handshake exporter with EXPORTER-eSE-peer-v1.
    virtual bool Export(const std::array<std::uint8_t,32>&,std::array<std::uint8_t,32>&) noexcept = 0;
    virtual bool Sign(const std::uint8_t*,std::size_t,std::array<std::uint8_t,64>&) noexcept = 0;
    virtual bool Verify(const std::array<std::uint8_t,32>&,const std::uint8_t*,std::size_t,
        const std::uint8_t*) noexcept = 0;
};
enum class Failure { None, InvalidConfig, WrongState, Malformed, IdentityMismatch,
    PinChanged, CryptoFailed, AuthTimeout };
class Session {
public:
    // expectedNode is the DCO mapping identity. A known pin, if present, is
    // independently checked. Local persistence and completed TLS are mandatory.
    Session(const Hello&, const std::array<std::uint8_t,32>& expectedNode,
        const std::array<std::uint8_t,32>* pin, bool persistent, bool tlsComplete,
        std::uint64_t startedMs) noexcept;
    bool LocalHello(std::array<std::uint8_t,HelloSize>&) noexcept;
    bool RemoteHello(const std::uint8_t*,std::size_t) noexcept;
    bool LocalAuth(Crypto&,std::array<std::uint8_t,AuthSize>&) noexcept;
    bool AuthSent() noexcept;
    bool RemoteAuth(Crypto&,const std::uint8_t*,std::size_t) noexcept;
    void Tick(std::uint64_t nowMs) noexcept;
    bool Ready() const noexcept { return failure_==Failure::None && sentAuth_ && verified_; }
    Failure Error() const noexcept { return failure_; }
    std::uint32_t SelectedCaps() const noexcept { return Ready() ? (local_.caps & remote_.caps & KnownCaps) : 0; }
    const Hello* BoundPeer() const noexcept { return Ready() ? &remote_ : nullptr; }
private:
    bool Fail(Failure) noexcept;
    bool Message(Crypto&,std::uint8_t,std::array<std::uint8_t,81>&) noexcept;
    Hello local_,remote_;
    std::array<std::uint8_t,32> expected_{},pin_{};
    std::array<std::uint8_t,HelloSize> localWire_{},remoteWire_{};
    std::uint64_t started_ = 0;
    Failure failure_ = Failure::None;
    bool hasPin_=false, sentHello_=false, gotHello_=false, madeAuth_=false,
        sentAuth_=false, verified_=false;
};
class ControlReader {
public:
    // Consumes at most one frame. Caller must dispatch it before feeding again.
    // Invalid is sticky. No allocation occurs for untrusted lengths.
    ReadResult Feed(const std::uint8_t*, std::size_t, std::size_t& consumed) noexcept;
    std::uint8_t Type() const noexcept { return ready_ ? bytes_[4] : 0; }
    const std::uint8_t* Payload() const noexcept { return ready_ ? bytes_.data()+5 : nullptr; }
    std::size_t PayloadSize() const noexcept { return ready_ ? length_-1 : 0; }
private:
    std::array<std::uint8_t,MaxControlLength+4> bytes_{};
    std::size_t used_ = 0, length_ = 0;
    bool invalid_ = false, ready_ = false;
};
struct ControlBytes { const std::uint8_t* data=nullptr; std::size_t size=0; };
class ControlSink {
public:
    virtual ~ControlSink() = default;
    // Borrowed payload only for this call; the sink must copy if retaining it.
    virtual bool Frame(std::uint8_t,const std::uint8_t*,std::size_t) noexcept = 0;
};
// Owns the initial HELLO/AUTH stream, retaining stable send storage until
// destruction (including after submission/ACK). No network allocations.
class ControlExchange {
public:
    ControlExchange(const Hello&,const std::array<std::uint8_t,32>& expectedNode,
        const std::array<std::uint8_t,32>* pin,bool persistent,bool tlsComplete,
        std::uint64_t startedMs) noexcept;
    ControlExchange(const ControlExchange&) = delete;
    ControlExchange& operator=(const ControlExchange&) = delete;
    bool Receive(Crypto&,const std::uint8_t*,std::size_t,ControlSink* = nullptr) noexcept;
    ControlBytes Pending() const noexcept;
    // Cumulative contiguous offset accepted by the QUIC stream writer.
    bool SubmittedThrough(std::size_t) noexcept;
    // One authenticated CLOSE, stored alongside HELLO/AUTH until destruction.
    // Retry with the same reason is idempotent; no heap or borrowed TX storage.
    bool QueueClose(std::uint16_t wireReason) noexcept;
    void Tick(std::uint64_t nowMs) noexcept { session_.Tick(nowMs); }
    bool Ready() const noexcept { return error_==Failure::None && session_.Ready(); }
    Failure Error() const noexcept { return error_==Failure::None ? session_.Error() : error_; }
    const Hello* BoundPeer() const noexcept { return Ready() ? session_.BoundPeer() : nullptr; }
    const Session* AuthenticatedSession() const noexcept { return Ready() ? &session_ : nullptr; }
    std::uint32_t SelectedCaps() const noexcept { return Ready() ? session_.SelectedCaps() : 0; }
private:
    bool Fail(Failure) noexcept;
    void Append(std::uint8_t,const std::uint8_t*,std::size_t) noexcept;
    Session session_;
    ControlReader reader_;
    std::array<std::uint8_t,HelloSize+AuthSize+10+7> output_{};
    std::size_t size_=0,submitted_=0;
    Failure error_=Failure::None;
    bool authQueued_=false,authSent_=false;
    std::uint16_t closeReason_=0;
};
} }
