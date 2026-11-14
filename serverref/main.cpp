#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include "ServerSession.h"
#include "ServerTls.h"
#include "RendezvousListener.h"
#include "LoopbackSockets.h"
#include <gnutls/crypto.h>
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <atomic>
#include <thread>
#include <utility>

namespace {
using namespace ese::server;

void Require(bool condition,const char* description)
{
    if(!condition) throw std::runtime_error(description);
}

std::uint64_t Now()
{
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}

struct Runtime {
    Runtime()
    {
        WSADATA data{};
        Require(WSAStartup(MAKEWORD(2,2),&data)==0,"initialize Winsock");
        if(gnutls_global_init()<0) {
            WSACleanup();
            throw std::runtime_error("initialize GnuTLS");
        }
    }
    ~Runtime() { gnutls_global_deinit(); WSACleanup(); }
};

struct Socket {
    explicit Socket(SOCKET raw) : value(raw) { Require(value!=INVALID_SOCKET,"open or accept a loopback socket"); }
    Socket(Socket&& other) noexcept : value(std::exchange(other.value,INVALID_SOCKET)) {}
    Socket(const Socket&) = delete;
    ~Socket() { if(value!=INVALID_SOCKET) closesocket(value); }
    SOCKET value;
};

class ServerIdentity {
public:
    ServerIdentity() = default;
    ~ServerIdentity()
    {
        if(credentials) gnutls_certificate_free_credentials(credentials);
        if(identity) gnutls_privkey_deinit(identity);
    }
    void Load(const char* certificate,const char* tlsKey,const char* nodeKey)
    {
        Require(gnutls_certificate_allocate_credentials(&credentials)==0 &&
            gnutls_certificate_set_x509_key_file(credentials,certificate,tlsKey,GNUTLS_X509_FMT_PEM)==0,
            "load configured TLS certificate and key");
        std::ifstream input(nodeKey,std::ios::binary);
        input.seekg(0,std::ios::end);
        const auto size=input.tellg();
        Require(input && size>0 && size<=16384,"load configured Ed25519 key");
        struct PrivateKeyBytes {
            std::array<std::uint8_t,16384> bytes{};
            ~PrivateKeyBytes() { SecureZeroMemory(bytes.data(),bytes.size()); }
        } data;
        input.seekg(0);
        Require(bool(input.read(reinterpret_cast<char*>(data.bytes.data()),size)),"read configured node key");
        const gnutls_datum_t key{data.bytes.data(),static_cast<unsigned int>(size)};
        Require(gnutls_privkey_init(&identity)==0 &&
            gnutls_privkey_import_x509_raw(identity,&key,GNUTLS_X509_FMT_PEM,nullptr,0)==0 &&
            ReadEd25519Identity(identity,node),
            "import configured persistent Ed25519 node key");
    }
    gnutls_certificate_credentials_t credentials=nullptr;
    gnutls_privkey_t identity=nullptr;
    Bytes32 node{};
};

class TlsChannel {
public:
    TlsChannel(const Socket& socket,gnutls_certificate_credentials_t credentials)
        : socket_(socket)
    {
        if(gnutls_init(&session_,GNUTLS_SERVER | GNUTLS_NO_TICKETS)<0)
            throw std::runtime_error("allocate TLS channel");
        if(!ConfigureTlsServer(session_,credentials)) {
            gnutls_deinit(session_);
            throw std::runtime_error("configure server TLS policy");
        }
        gnutls_transport_set_ptr(session_,this);
        gnutls_transport_set_push_function(session_,Push);
        gnutls_transport_set_pull_function(session_,Pull);
    }
    ~TlsChannel() { gnutls_deinit(session_); }
    gnutls_session_t Session() const noexcept { return session_; }
    void SetDeadline(std::uint64_t end) noexcept { deadline_=end; }
    bool InputError() const noexcept { return inputError_; }
    bool Handshake()
    {
        SetDeadline(Now()+10000);
        int status;
        do { status=gnutls_handshake(session_); }
        while((status==GNUTLS_E_INTERRUPTED || status==GNUTLS_E_AGAIN) && Now()<deadline_);
        return status==0 && IsServerTls(session_);
    }
    bool Send(const EncodedFrame& frame)
    {
        for(size_t offset=0;offset<frame.size();) {
            const auto sent=gnutls_record_send(session_,frame.data()+offset,frame.size()-offset);
            if(sent<=0) return false;
            offset+=static_cast<size_t>(sent);
        }
        return true;
    }
    std::optional<FrameView> Next(RendezvousListener* rendezvous=nullptr,const rdv::SessionContext* context=nullptr)
    {
        if(decoder_.Get() && !decoder_.Consume()) return std::nullopt;
        while(Now()<deadline_) {
            if(rendezvous && context) {
                for(unsigned family=0;family<2;++family) {
                    const auto status=rendezvous->TakeStatus(*context,Now());
                    if(!status) break;
                    if(!SendStatus(*status)) {
                        inputError_=true;
                        return std::nullopt;
                    }
                }
                for(unsigned count=0;count<16;++count) {
                    const auto control=rendezvous->TakeControl(*context,Now());
                    if(!control) break;
                    if(!Send(*control)) {
                        inputError_=true;
                        return std::nullopt;
                    }
                }
            }
            if(offset_==used_) {
                if(rendezvous && !gnutls_record_check_pending(session_)) {
                    fd_set input;
                    FD_ZERO(&input);
                    FD_SET(socket_.value,&input);
                    timeval interval{0,50000};
                    const auto ready=select(0,&input,nullptr,nullptr,&interval);
                    if(ready==0) continue;
                    if(ready<0) return std::nullopt;
                }
                const auto count=gnutls_record_recv(session_,input_.data(),input_.size());
                if(count<=0) return std::nullopt;
                offset_=0;
                used_=static_cast<size_t>(count);
            }
            const auto fed=decoder_.Feed({input_.data()+offset_,used_-offset_});
            offset_+=fed.consumed;
            if(fed.state==DecodeState::Ready) return decoder_.Get();
            if(fed.state!=DecodeState::Reading) {
                inputError_=true;
                return std::nullopt;
            }
        }
        return std::nullopt;
    }
private:
    bool SendStatus(const rdv::Registration& status)
    {
        const auto now=Now();
        if(now>=status.until) return true;
        const auto ttl=static_cast<std::uint32_t>((std::min)(status.until-now,std::uint64_t{60000}));
        // REG_STATUS contains the family and the complete canonical endpoint.
        const auto family=status.endpoint.family;
        const std::size_t size=family==6 ? 16 : 4;
        std::array<std::uint8_t,24> body{family,family};
        std::copy_n(status.endpoint.address.begin(),size,body.begin()+2);
        body[2+size]=static_cast<std::uint8_t>(status.endpoint.port>>8);
        body[3+size]=static_cast<std::uint8_t>(status.endpoint.port);
        for(unsigned i=0;i<4;++i) body[size+4+i]=static_cast<std::uint8_t>(ttl>>(24-i*8));
        EncodedFrame wire;
        return EncodeFrame({{kEseWireServerRegStatus,0,{}},{body.data(),size+8}},wire) && Send(wire);
    }
    bool IoTimeout(int option)
    {
        const auto now=Now();
        if(now>=deadline_) return false;
        const auto budget=static_cast<DWORD>((std::min)(deadline_-now,static_cast<std::uint64_t>(MAXDWORD)));
        return setsockopt(socket_.value,SOL_SOCKET,option,reinterpret_cast<const char*>(&budget),sizeof budget)==0;
    }
    static ssize_t Push(gnutls_transport_ptr_t pointer,const void* bytes,size_t count)
    {
        auto& self=*static_cast<TlsChannel*>(pointer);
        if(!self.IoTimeout(SO_SNDTIMEO)) { errno=EIO; return -1; }
        const auto result=send(self.socket_.value,static_cast<const char*>(bytes),static_cast<int>((std::min)(count,size_t{65536})),0);
        if(result==SOCKET_ERROR) errno=EIO;
        return result;
    }
    static ssize_t Pull(gnutls_transport_ptr_t pointer,void* bytes,size_t count)
    {
        auto& self=*static_cast<TlsChannel*>(pointer);
        if(!self.IoTimeout(SO_RCVTIMEO)) { errno=EIO; return -1; }
        const auto result=recv(self.socket_.value,static_cast<char*>(bytes),static_cast<int>((std::min)(count,size_t{65536})),0);
        if(result==SOCKET_ERROR) errno=EIO;
        return result;
    }
    const Socket& socket_;
    gnutls_session_t session_=nullptr;
    std::uint64_t deadline_=0;
    FrameDecoder decoder_;
    std::array<std::uint8_t,4096> input_{};
    size_t offset_=0,used_=0;
    bool inputError_=false;
};

bool AuthenticationFailure(TlsChannel& transport)
{
    const std::uint8_t payload[]={0,kEseWireServerAuthFailed,0,0,0,0};
    EncodedFrame frame;
    if(EncodeFrame({{kEseWireServerError,kEseWireServerFinal,{}},{payload,sizeof payload}},frame))
        transport.Send(frame);
    return false;
}

bool Serve(const Socket& peer,const ServerIdentity& identity,const Bytes16& epoch,std::uint64_t generation,
    const ServerEndpoint& endpoint,ServerIndex& index,RendezvousListener* rendezvous)
{
    TlsChannel transport(peer,identity.credentials);
    if(!transport.Handshake()) return false;
    const auto started=Now();
    transport.SetDeadline(started+10000);
    ServerHello local;
    local.node=identity.node;
    local.epoch=epoch;
    local.generation=generation;
    if(gnutls_rnd(GNUTLS_RND_NONCE,local.nonce.data(),local.nonce.size())<0 ||
        gnutls_rnd(GNUTLS_RND_NONCE,local.session.data(),local.session.size())<0) return false;
    ChannelCrypto crypto(transport.Session(),identity.identity);
    const auto capabilities=kEseWireServerCapEd2kEnvelope | kEseWireServerCapAtomicPublish |
        (rendezvous ? kEseWireServerCapRdv2 | kEseWireServerCapCrossCallback : 0u);
    AuthSession auth(local,capabilities,true,started);
    EncodedFrame wire;
    for(;;) {
        switch(auth.State()) {
        case AuthState::ReceiveHello:
        case AuthState::ReceiveProof: {
            const auto frame=transport.Next();
            if(!frame) return false;
            if(!auth.Receive(Now(),crypto,*frame)) return AuthenticationFailure(transport);
            continue;
        }
        case AuthState::SendHello:
        case AuthState::SendProof:
        case AuthState::SendAuthOk:
            if(!auth.MakeNext(Now(),crypto,wire) || !transport.Send(wire)) return false;
            continue;
        default:
            break;
        }
        break;
    }
    const auto* client=auth.RemoteClient();
    const auto* authenticated=auth.NegotiatedServer();
    if(!client || !authenticated) return false;
    ServerSession session(*client,endpoint,index,generation,Now());
    struct Registration {
        RendezvousListener* listener=nullptr;
        rdv::SessionContext context;
        ~Registration() { if(listener) listener->Remove(context); }
    } registration;
    if(rendezvous && (authenticated->selected & kEseWireServerCapRdv2)) {
        const rdv::SessionContext context{authenticated->epoch,authenticated->session,authenticated->generation};
        Bytes32 digest{}, key{};
        const bool attached=auth.HelloDigest(crypto,digest) && ExportRendezvousKey(transport.Session(),digest,key) &&
            rendezvous->Attach(context,key,*client,session.Deadline(),
                (authenticated->selected & kEseWireServerCapCrossCallback)!=0);
        SecureZeroMemory(key.data(),key.size());
        if(!attached) return false;
        registration.listener=rendezvous;
        registration.context=context;
    }
    while(!session.Closed()) {
        transport.SetDeadline((std::min)(session.Deadline(),Now()+30000));
        const auto frame=transport.Next(registration.listener,&registration.context);
        if(!frame) return session.LoggedIn() && !transport.InputError();
        Responses responses;
        if(registration.listener && registration.listener->Handles(frame->header.type) && session.LoggedIn() &&
            ClassifyFrame(frame->header,Direction::ClientToServer,Phase::Authenticated)==Disposition::Message) {
            using Use=ServerSession::RequestUse;
            const auto use=session.ClaimDeferred(frame->header.request,frame->header.type,Now());
            const auto code=use==Use::ResourceLimit ? kEseWireServerResourceLimit : kEseWireServerConflict;
            const auto reply=use==Use::New || use==Use::SameOperation ?
                registration.listener->Handle(registration.context,*frame,Now()) :
                std::optional<RendezvousListener::ControlReply>{{kEseWireServerError,true,
                    {0,static_cast<std::uint8_t>(code),0,0,0,0}}};
            if(!reply) return false;
            if(reply->type) {
                EncodedFrame response;
                const auto flags=static_cast<std::uint16_t>(kEseWireServerResponse |
                    (reply->terminal ? kEseWireServerFinal : 0));
                if(!EncodeFrame({{reply->type,flags,frame->header.request},
                    {reply->body.data(),reply->body.size()}},response)) return false;
                responses.push_back(std::move(response));
            }
        } else if(!session.Handle(*frame,crypto,Now(),responses)) return false;
        if(registration.listener)
            registration.listener->Update(registration.context,session.LoggedIn() && !session.Closed(),session.Deadline());
        transport.SetDeadline(Now()+3000);
        for(const auto& response:responses)
            if(!transport.Send(response)) return false;
    }
    gnutls_bye(transport.Session(),GNUTLS_SHUT_WR);
    return session.LoggedIn();
}

class Connections {
public:
    explicit Connections(ServerIndex& index) : index_(index), maintenance_([this] { Maintain(); }) {}
    ~Connections()
    {
        for(auto& slot:slots_) slot.Join();
        {
            const std::lock_guard<std::mutex> lock(maintenanceMutex_);
            stopping_=true;
        }
        maintenanceWake_.notify_one();
        maintenance_.join();
    }
    void Add(SOCKET listener,const ServerIdentity& identity,const Bytes16& epoch,
        std::uint64_t generation,const ServerEndpoint& endpoint,ServerIndex& index,RendezvousListener* rendezvous)
    {
        auto& slot=slots_[(generation-1)%slots_.size()];
        slot.Join();
        Socket accepted(accept(listener,nullptr,nullptr));
        slot.thread=std::thread([&,generation,rendezvous,peer=std::move(accepted)] {
            try {
                if(Serve(peer,identity,epoch,generation,endpoint,index,rendezvous)) ++completed_;
            } catch(const std::exception&) {
                // Malformed/failed individual sessions are disconnected. Do
                // not log remote data or private material on this path.
            }
        });
    }
    unsigned Complete()
    {
        for(auto& slot:slots_) slot.Join();
        return completed_.load();
    }
private:
    void Maintain()
    {
        std::unique_lock<std::mutex> lock(maintenanceMutex_);
        while(!maintenanceWake_.wait_for(lock,std::chrono::seconds(1),[this] { return stopping_; }))
            index_.Expire(Now());
    }

    struct Slot {
        std::thread thread;
        void Join() { if(thread.joinable()) thread.join(); }
    };
    std::array<Slot,16> slots_{};
    std::atomic<unsigned> completed_{0};
    ServerIndex& index_;
    std::mutex maintenanceMutex_;
    std::condition_variable maintenanceWake_;
    bool stopping_=false;
    std::thread maintenance_;
};

unsigned ParseNumber(const char* argument,unsigned maximum)
{
    const std::string text(argument);
    Require(!text.empty() && text.find_first_not_of("0123456789")==std::string::npos,"numeric option expected");
    const auto number=std::stoul(text);
    Require(number<=maximum,"numeric option exceeds maximum");
    return number;
}
}

int main(int argc,char** argv)
{
    try {
        if(argc!=6 && argc!=7) {
            std::cerr<<"Usage: ese-server-ref <loopback-port> <certificate-pem> <tls-key-pem> <node-key-pem> <connection-count> [rdv-udp-port]\n";
            return 2;
        }
        Runtime runtime;
        const auto port=static_cast<std::uint16_t>(ParseNumber(argv[1],65535));
        const auto connectionCount=ParseNumber(argv[5],256);
        Require(connectionCount>0,"connection count must be positive");
        ServerIdentity identity;
        identity.Load(argv[2],argv[3],argv[4]);
        Bytes16 epoch{};
        Require(gnutls_rnd(GNUTLS_RND_NONCE,epoch.data(),epoch.size())==0,"generate server epoch");
        LoopbackSockets listeners(SOCK_STREAM,IPPROTO_TCP,port);
        for(const auto listener:listeners.Handles())
            Require(listen(listener,1)==0,"listen on native loopback TLS socket");
        ServerEndpoint endpoint{};
        endpoint.ipv4={127,0,0,1};
        endpoint.port=listeners.Port();
        Bytes32 digest{};
        Require(gnutls_hash_fast(GNUTLS_DIG_SHA256,identity.node.data(),identity.node.size(),digest.data())==0,
            "derive public server identity");
        std::copy_n(digest.begin(),endpoint.identity.size(),endpoint.identity.begin());
        Bytes32 emptyDigest{};
        ChannelCrypto hash(nullptr,nullptr);
        Require(hash.Hash({},emptyDigest),"derive empty publication digest");
        ServerIndex index(emptyDigest);
        auto rendezvous=argc==7 ? std::make_unique<RendezvousListener>(index,
            static_cast<std::uint16_t>(ParseNumber(argv[6],65535))) : nullptr;
        Connections connections(index);
        std::cout<<"LISTENING "<<endpoint.port;
        if(rendezvous) std::cout<<" RDV "<<rendezvous->Port();
        std::cout<<std::endl;
        for(unsigned attempt=0;attempt<connectionCount;++attempt) {
            fd_set incoming;
            FD_ZERO(&incoming);
            for(const auto listener:listeners.Handles()) FD_SET(listener,&incoming);
            timeval wait{15,0};
            if(select(0,&incoming,nullptr,nullptr,&wait)<=0) break;
            for(const auto listener:listeners.Handles())
                if(FD_ISSET(listener,&incoming)) {
                    connections.Add(listener,identity,epoch,std::uint64_t{attempt}+1,endpoint,index,rendezvous.get());
                    break;
                }
        }
        const auto completed=connections.Complete();
        std::cout<<"LOGIN_SESSIONS "<<completed<<std::endl;
        return completed ? 0 : 1;
    } catch(const std::exception& error) {
        std::cerr<<"Server reference failed: "<<error.what()<<'\n';
        return 1;
    }
}
