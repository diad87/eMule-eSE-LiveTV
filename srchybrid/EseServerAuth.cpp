#include "EseServerAuth.h"
#include "EseChannelBinding.h"

#include <algorithm>

namespace ese::server {
namespace {
template<std::size_t Size>
bool Nonzero(const std::array<std::uint8_t,Size>& bytes) noexcept
{
    return std::any_of(bytes.begin(),bytes.end(),[](std::uint8_t byte) { return byte!=0; });
}

template<class Integer>
void Put(std::uint8_t* out,Integer value) noexcept
{
    for(std::size_t i=sizeof(value);i>0;--i) {
        out[i-1]=static_cast<std::uint8_t>(value);
        value>>=8;
    }
}

template<class Integer>
Integer Get(const std::uint8_t* input) noexcept
{
    Integer result=0;
    for(std::size_t i=0;i<sizeof(result);++i) result=(result<<8) | input[i];
    return result;
}

bool ValidClient(const ClientHello& hello) noexcept
{
    return Nonzero(hello.nonce) && Nonzero(hello.node) && Nonzero(hello.bootId) &&
        (hello.mode==SessionMode::Primary || hello.mode==SessionMode::Auxiliary);
}

bool ValidServer(const ServerHello& hello) noexcept
{
    return Nonzero(hello.nonce) && Nonzero(hello.node) && Nonzero(hello.epoch) &&
        Nonzero(hello.session) && hello.generation && SelectCapabilities(hello.selected,hello.selected)==hello.selected;
}
}

bool EncodeClientHello(const ClientHello& hello,ClientHelloBytes& output) noexcept
{
    if(!ValidClient(hello)) return false;
    std::copy(hello.nonce.begin(),hello.nonce.end(),output.begin());
    std::copy(hello.node.begin(),hello.node.end(),output.begin()+32);
    std::copy(hello.userHash.begin(),hello.userHash.end(),output.begin()+64);
    Put(output.data()+80,hello.supported);
    Put(output.data()+84,static_cast<std::uint32_t>(MaxFrameSize));
    std::copy(hello.bootId.begin(),hello.bootId.end(),output.begin()+88);
    output[104]=static_cast<std::uint8_t>(hello.mode);
    return true;
}

bool DecodeClientHello(ByteView input,ClientHello& output) noexcept
{
    if(!input.data || input.size!=ClientHelloBytes{}.size() || Get<std::uint32_t>(input.data+84)!=MaxFrameSize)
        return false;
    ClientHello hello;
    std::copy_n(input.data,hello.nonce.size(),hello.nonce.begin());
    std::copy_n(input.data+32,hello.node.size(),hello.node.begin());
    std::copy_n(input.data+64,hello.userHash.size(),hello.userHash.begin());
    hello.supported=Get<std::uint32_t>(input.data+80);
    std::copy_n(input.data+88,hello.bootId.size(),hello.bootId.begin());
    hello.mode=static_cast<SessionMode>(input.data[104]);
    if(!ValidClient(hello)) return false;
    output=hello;
    return true;
}

bool EncodeServerHello(const ServerHello& hello,ServerHelloBytes& output) noexcept
{
    if(!ValidServer(hello)) return false;
    std::copy(hello.nonce.begin(),hello.nonce.end(),output.begin());
    std::copy(hello.node.begin(),hello.node.end(),output.begin()+32);
    std::copy(hello.epoch.begin(),hello.epoch.end(),output.begin()+64);
    std::copy(hello.session.begin(),hello.session.end(),output.begin()+80);
    Put(output.data()+96,hello.generation);
    Put(output.data()+104,hello.selected);
    Put(output.data()+108,static_cast<std::uint32_t>(MaxFrameSize));
    Put(output.data()+112,SessionLeaseSeconds);
    return true;
}

bool DecodeServerHello(ByteView input,ServerHello& output) noexcept
{
    if(!input.data || input.size!=ServerHelloBytes{}.size() || Get<std::uint32_t>(input.data+108)!=MaxFrameSize ||
        Get<std::uint32_t>(input.data+112)!=SessionLeaseSeconds) return false;
    ServerHello hello;
    std::copy_n(input.data,hello.nonce.size(),hello.nonce.begin());
    std::copy_n(input.data+32,hello.node.size(),hello.node.begin());
    std::copy_n(input.data+64,hello.epoch.size(),hello.epoch.begin());
    std::copy_n(input.data+80,hello.session.size(),hello.session.begin());
    hello.generation=Get<std::uint64_t>(input.data+96);
    hello.selected=Get<std::uint32_t>(input.data+104);
    if(!ValidServer(hello)) return false;
    output=hello;
    return true;
}

AuthTranscript BuildAuthTranscript(const Bytes32& exporter,const Bytes32& helloDigest,AuthRole role) noexcept
{
    return binding::BuildTranscript(kEseWireServerAuthDomain,exporter,helloDigest,static_cast<std::uint8_t>(role));
}

AuthSession::AuthSession(const ClientHello& local,const Bytes32& expectedServer,
    bool persistent,std::uint64_t now) noexcept
    : role_(AuthRole::Client),state_(AuthState::Failed),started_(now),
      client_(local),expectedServer_(expectedServer)
{
    if(persistent && Nonzero(expectedServer_) && EncodeClientHello(client_,clientBytes_))
        state_=AuthState::SendHello;
}

AuthSession::AuthSession(const ServerHello& local,std::uint32_t supported,
    bool persistent,std::uint64_t now) noexcept
    : role_(AuthRole::Server),state_(AuthState::Failed),started_(now),
      server_(local),supported_(supported)
{
    if(persistent && Nonzero(local.nonce) && Nonzero(local.node) && Nonzero(local.epoch) &&
        Nonzero(local.session) && local.generation && SelectCapabilities(supported,supported))
        state_=AuthState::ReceiveHello;
}

bool AuthSession::InTime(std::uint64_t now) noexcept
{
    return state_!=AuthState::Failed && now>=started_ && now-started_<10000;
}

bool AuthSession::PrepareTranscript(AuthCrypto& crypto,AuthRole role,AuthTranscript& output) const noexcept
{
    std::array<std::uint8_t,ClientHelloBytes{}.size()+ServerHelloBytes{}.size()> hellos{};
    const auto cursor=std::copy(clientBytes_.begin(),clientBytes_.end(),hellos.begin());
    std::copy(serverBytes_.begin(),serverBytes_.end(),cursor);
    Bytes32 digest{}, exporter{};
    if(!crypto.Hash({hellos.data(),hellos.size()},digest) || !crypto.Export(digest,exporter))
        return false;
    output=BuildAuthTranscript(exporter,digest,role);
    return true;
}

bool AuthSession::MakeNext(std::uint64_t now,AuthCrypto& crypto,std::vector<std::uint8_t>& wire)
{
    if(state_==AuthState::Authenticated) return false;
    if(!InTime(now)) return Fail();
    const bool client=role_==AuthRole::Client;
    FrameView frame{};
    AuthState next=AuthState::Failed;
    Signature signature{};
    std::array<std::uint8_t,4> lease{};
    switch(state_) {
    case AuthState::SendHello:
        if(client) {
            frame.header.type=kEseWireServerClientHello;
            frame.payload={clientBytes_.data(),clientBytes_.size()};
            next=AuthState::ReceiveHello;
        } else {
            frame.header.type=kEseWireServerServerHello;
            frame.payload={serverBytes_.data(),serverBytes_.size()};
            next=AuthState::SendProof;
        }
        break;
    case AuthState::SendProof: {
        AuthTranscript transcript{};
        if(!PrepareTranscript(crypto,role_,transcript) || !crypto.Sign(transcript,signature)) return Fail();
        frame.header.type=client ? kEseWireServerClientProof : kEseWireServerServerProof;
        frame.payload={signature.data(),signature.size()};
        next=client ? AuthState::ReceiveAuthOk : AuthState::ReceiveProof;
        break;
    }
    case AuthState::SendAuthOk:
        Put(lease.data(),SessionLeaseSeconds);
        frame.header.type=kEseWireServerAuthOk;
        frame.payload={lease.data(),lease.size()};
        next=AuthState::Authenticated;
        break;
    default:
        return false;
    }
    if(!EncodeFrame(frame,wire)) return Fail();
    state_=next;
    return true;
}

bool AuthSession::Receive(std::uint64_t now,AuthCrypto& crypto,const FrameView& frame)
{
    if(state_==AuthState::Authenticated) return false;
    const bool client=role_==AuthRole::Client;
    if(!InTime(now) || ClassifyFrame(frame.header,client ? Direction::ServerToClient : Direction::ClientToServer,
          Phase::Authentication)!=Disposition::Message)
        return Fail();
    switch(state_) {
    case AuthState::ReceiveHello:
        if(client) {
            if(frame.header.type!=kEseWireServerServerHello || !DecodeServerHello(frame.payload,server_) ||
                server_.node!=expectedServer_ || (server_.selected & ~client_.supported)) return Fail();
            std::copy_n(frame.payload.data,serverBytes_.size(),serverBytes_.begin());
            state_=AuthState::ReceiveProof;
        } else {
            if(frame.header.type!=kEseWireServerClientHello || !DecodeClientHello(frame.payload,client_)) return Fail();
            const auto selected=SelectCapabilities(client_.supported,supported_);
            if(!selected) return Fail();
            std::copy_n(frame.payload.data,clientBytes_.size(),clientBytes_.begin());
            server_.selected=*selected;
            if(!EncodeServerHello(server_,serverBytes_)) return Fail();
            state_=AuthState::SendHello;
        }
        return true;
    case AuthState::ReceiveProof: {
        const auto expectedType=client ? kEseWireServerServerProof : kEseWireServerClientProof;
        const auto& node=client ? server_.node : client_.node;
        Signature signature{};
        if(frame.header.type!=expectedType || !frame.payload.data || frame.payload.size!=signature.size()) return Fail();
        std::copy_n(frame.payload.data,signature.size(),signature.begin());
        AuthTranscript transcript{};
        if(!PrepareTranscript(crypto,client ? AuthRole::Server : AuthRole::Client,transcript) ||
            !crypto.Verify(node,transcript,signature)) return Fail();
        state_=client ? AuthState::SendProof : AuthState::SendAuthOk;
        return true;
    }
    case AuthState::ReceiveAuthOk:
        if(frame.header.type!=kEseWireServerAuthOk || !frame.payload.data || frame.payload.size!=sizeof(std::uint32_t) ||
            Get<std::uint32_t>(frame.payload.data)!=SessionLeaseSeconds) return Fail();
        state_=AuthState::Authenticated;
        return true;
    default:
        return Fail();
    }
}

const ClientHello* AuthSession::RemoteClient() const noexcept
{
    return role_==AuthRole::Server && state_==AuthState::Authenticated ? &client_ : nullptr;
}

const ServerHello* AuthSession::RemoteServer() const noexcept
{
    return role_==AuthRole::Client && state_==AuthState::Authenticated ? &server_ : nullptr;
}
}
