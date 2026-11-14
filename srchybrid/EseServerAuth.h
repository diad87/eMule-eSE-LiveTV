#pragma once
#include "EseServerProtocol.h"

namespace ese::server {
using Bytes16 = std::array<std::uint8_t,16>;
using Bytes32 = std::array<std::uint8_t,32>;
using Signature = std::array<std::uint8_t,64>;
using ClientHelloBytes = std::array<std::uint8_t,105>;
using ServerHelloBytes = std::array<std::uint8_t,116>;
using AuthTranscript = std::array<std::uint8_t,sizeof(kEseWireServerAuthDomain)+32+32+1>;
inline constexpr std::uint32_t SessionLeaseSeconds = 600;

enum class SessionMode : std::uint8_t { Primary=0, Auxiliary=1 };
enum class AuthRole : std::uint8_t { Client=1, Server=2 };

struct ClientHello {
    Bytes32 nonce{}, node{};
    Bytes16 userHash{}, bootId{};
    std::uint32_t supported = 0;
    SessionMode mode = SessionMode::Primary;
};

struct ServerHello {
    Bytes32 nonce{}, node{};
    Bytes16 epoch{}, session{};
    std::uint64_t generation = 0;
    std::uint32_t selected = 0;
};

bool EncodeClientHello(const ClientHello&,ClientHelloBytes&) noexcept;
bool DecodeClientHello(ByteView,ClientHello&) noexcept;
bool EncodeServerHello(const ServerHello&,ServerHelloBytes&) noexcept;
bool DecodeServerHello(ByteView,ServerHello&) noexcept;
AuthTranscript BuildAuthTranscript(const Bytes32& exporter,const Bytes32& helloDigest,AuthRole) noexcept;

class AuthCrypto {
public:
    virtual ~AuthCrypto() = default;
    virtual bool Hash(ByteView,Bytes32&) noexcept = 0;
    virtual bool Export(const Bytes32& helloDigest,Bytes32& exporter) noexcept = 0;
    virtual bool Sign(const AuthTranscript&,Signature&) noexcept = 0;
    virtual bool Verify(const Bytes32& node,const AuthTranscript&,const Signature&) noexcept = 0;
};

enum class AuthState { SendHello, ReceiveHello, SendProof, ReceiveProof, SendAuthOk, ReceiveAuthOk, Authenticated, Failed };

// Role-ordered proof exchange. The transport must be authenticated before
// constructing this object. Server identity is separately bound to its
// explicit descriptor on the client side.
class AuthSession {
public:
    AuthSession(const ClientHello& local,const Bytes32& expectedServer,
        bool persistent,std::uint64_t now) noexcept;
    AuthSession(const ServerHello& local,std::uint32_t supported,
        bool persistent,std::uint64_t now) noexcept;
    AuthSession(const AuthSession&) = delete;
    AuthSession& operator=(const AuthSession&) = delete;

    AuthState State() const noexcept { return state_; }
    bool MakeNext(std::uint64_t now,AuthCrypto&,std::vector<std::uint8_t>& wire);
    bool Receive(std::uint64_t now,AuthCrypto&,const FrameView&);
    const ClientHello* RemoteClient() const noexcept;
    const ServerHello* RemoteServer() const noexcept;

private:
    bool InTime(std::uint64_t now) noexcept;
    bool Fail() noexcept { state_=AuthState::Failed; return false; }
    bool PrepareTranscript(AuthCrypto&,AuthRole,AuthTranscript&) const noexcept;

    AuthRole role_;
    AuthState state_;
    std::uint64_t started_;
    ClientHello client_{};
    ServerHello server_{};
    Bytes32 expectedServer_{};
    std::uint32_t supported_ = 0;
    ClientHelloBytes clientBytes_{};
    ServerHelloBytes serverBytes_{};
};
}
