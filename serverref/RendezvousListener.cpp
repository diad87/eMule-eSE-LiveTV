#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include "RendezvousListener.h"
#include "ServerIndex.h"
#include "ServerTls.h"
#include <gnutls/crypto.h>
#include <atomic>
#include <chrono>
#include <mutex>
#include <stdexcept>
#include <thread>

namespace ese::server {
namespace {
std::uint64_t Now()
{
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}

bool Matches(const rdv::SessionContext& left,const rdv::SessionContext& right) noexcept
{
    return left.epoch==right.epoch && left.session==right.session && left.generation==right.generation;
}

class Crypto final : public rdv::Crypto {
public:
    bool Hmac(const Bytes32& key,ByteView bytes,Bytes32& output) noexcept override
    {
        return gnutls_hmac_fast(GNUTLS_MAC_SHA256,key.data(),key.size(),bytes.data,bytes.size,output.data())==0;
    }
    bool Equal(const Bytes32& a,const Bytes32& b) noexcept override
    {
        return gnutls_memcmp(a.data(),b.data(),a.size())==0;
    }
};
}

struct RendezvousListener::Impl {
    struct Entry {
        Entry(const rdv::SessionContext& given,const Bytes32& secret,const ClientHello& client,std::uint64_t until)
            : context(given),key(secret),node(client.node),expiration(until),
              primary(client.mode==SessionMode::Primary),ledger(context) {}
        ~Entry() { SecureZeroMemory(key.data(),key.size()); }
        rdv::SessionContext context;
        Bytes32 key,node;
        std::uint64_t expiration;
        bool primary,loggedIn=false;
        rdv::Session ledger;
        std::optional<rdv::Registration> pending;
    };

    Impl(ServerIndex& owner,std::uint16_t port) : index(owner)
    {
        socketHandle=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
        if(socketHandle==INVALID_SOCKET) throw std::runtime_error("open reference RendezvousV2 socket");
        try {
            sockaddr_in bindAddress{};
            bindAddress.sin_family=AF_INET;
            bindAddress.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
            bindAddress.sin_port=htons(port);
            int size=sizeof bindAddress;
            constexpr BOOL exclusive=TRUE;
            if(setsockopt(socketHandle,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,reinterpret_cast<const char*>(&exclusive),sizeof exclusive)!=0 ||
                bind(socketHandle,reinterpret_cast<sockaddr*>(&bindAddress),sizeof bindAddress)!=0 ||
                getsockname(socketHandle,reinterpret_cast<sockaddr*>(&bindAddress),&size)!=0 ||
                bindAddress.sin_addr.s_addr!=htonl(INADDR_LOOPBACK) || !bindAddress.sin_port ||
                !RefreshSecret(Now())) throw std::runtime_error("bind reference loopback UDP listener");
            listenPort=ntohs(bindAddress.sin_port);
            worker=std::thread([this] { Run(); });
        } catch(...) {
            closesocket(socketHandle);
            throw;
        }
    }

    ~Impl()
    {
        stop=true;
        worker.join();
        closesocket(socketHandle);
    }

    Entry* Find(const rdv::SessionContext& context) noexcept
    {
        for(auto& entry:entries)
            if(entry && Matches(entry->context,context)) return &*entry;
        return nullptr;
    }

    bool Eligible(const Entry& entry,std::uint64_t now)
    {
        return entry.loggedIn && now<entry.expiration &&
            (!entry.primary || index.CurrentPrimary(entry.node,entry.context.generation,now));
    }

    bool RefreshSecret(std::uint64_t now)
    {
        if(secrets.Current(now)) return true;
        Bytes32 secret{};
        const bool success=gnutls_rnd(GNUTLS_RND_KEY,secret.data(),secret.size())==0 && secrets.Rotate(secret,now);
        SecureZeroMemory(secret.data(),secret.size());
        return success;
    }

    void Run()
    {
        while(!stop) {
            fd_set allowed;
            FD_ZERO(&allowed);
            FD_SET(socketHandle,&allowed);
            timeval timeout{0,50000};
            if(select(0,&allowed,nullptr,nullptr,&timeout)<=0) continue;
            std::array<std::uint8_t,rdv::DatagramSize+1> datagram{};
            sockaddr_in source{};
            int length=sizeof source;
            const auto count=recvfrom(socketHandle,reinterpret_cast<char*>(datagram.data()),
                static_cast<int>(datagram.size()),0,reinterpret_cast<sockaddr*>(&source),&length);
            if(stop || count!=rdv::DatagramSize || length!=sizeof source || source.sin_family!=AF_INET ||
                source.sin_addr.s_addr!=htonl(INADDR_LOOPBACK) || !source.sin_port) continue;
            const ByteView view{datagram.data(),rdv::DatagramSize};
            rdv::SessionContext context;
            if(!rdv::ReadContext(view,context)) continue;
            const auto now=Now();
            const std::lock_guard<std::mutex> lock(mutex);
            auto* entry=Find(context);
            if(!entry || !Eligible(*entry,now) || !RefreshSecret(now)) continue;
            const auto second=now/1000;
            if(second!=budgetSecond) { budgetSecond=second; sent=0; }
            // Datagram input only, responses never exceed received size.
            // Publish status only through the TLS owner after return proof.
            if(datagram[8]!=kEseWireRdv2Echo && sent>=32) continue;
            const rdv::Endpoint endpoint{{127,0,0,1},ntohs(source.sin_port),4};
            const auto result=entry->ledger.Receive(view,endpoint,entry->key,secrets,crypto,now);
            if(result.status && Eligible(*entry,now)) entry->pending=result.status;
            if(result.challenge) {
                if(!Eligible(*entry,now)) continue;
                ++sent;
                sendto(socketHandle,reinterpret_cast<const char*>(result.challenge->data()),
                    static_cast<int>(result.challenge->size()),0,reinterpret_cast<const sockaddr*>(&source),sizeof source);
            }
        }
    }

    ServerIndex& index;
    SOCKET socketHandle=INVALID_SOCKET;
    std::uint16_t listenPort=0;
    std::atomic<bool> stop{false};
    std::mutex mutex;
    std::array<std::optional<Entry>,16> entries{};
    rdv::CookieSecrets secrets;
    Crypto crypto;
    std::uint64_t budgetSecond=0;
    unsigned sent=0;
    std::thread worker;
};

RendezvousListener::RendezvousListener(ServerIndex& index,std::uint16_t port)
    : impl_(std::make_unique<Impl>(index,port)) {}
RendezvousListener::~RendezvousListener() = default;

std::uint16_t RendezvousListener::Port() const noexcept { return impl_->listenPort; }

bool RendezvousListener::Attach(const rdv::SessionContext& context,const Bytes32& key,const ClientHello& client,
    std::uint64_t expiration)
{
    const std::lock_guard<std::mutex> lock(impl_->mutex);
    if(impl_->Find(context)) return false;
    for(auto& entry:impl_->entries)
        if(!entry) {
            entry.emplace(context,key,client,expiration);
            return true;
        }
    return false;
}

void RendezvousListener::Update(const rdv::SessionContext& context,bool loggedIn,std::uint64_t expiration)
{
    const std::lock_guard<std::mutex> lock(impl_->mutex);
    if(auto* entry=impl_->Find(context)) {
        entry->loggedIn=loggedIn;
        entry->expiration=expiration;
    }
}

void RendezvousListener::Remove(const rdv::SessionContext& context) noexcept
{
    const std::lock_guard<std::mutex> lock(impl_->mutex);
    for(auto& entry:impl_->entries)
        if(entry && Matches(entry->context,context)) entry.reset();
}

std::optional<rdv::Registration> RendezvousListener::TakeStatus(const rdv::SessionContext& context,std::uint64_t now)
{
    const std::lock_guard<std::mutex> lock(impl_->mutex);
    auto* entry=impl_->Find(context);
    if(!entry || !impl_->Eligible(*entry,now)) return {};
    const auto status=entry->pending;
    entry->pending.reset();
    return status && now<status->until ? status : std::nullopt;
}
}
