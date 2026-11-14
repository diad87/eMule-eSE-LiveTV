#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include "RendezvousListener.h"
#include "LoopbackSockets.h"
#include "ServerIndex.h"
#include "ServerTls.h"
#include <gnutls/crypto.h>
#include <atomic>
#include <algorithm>
#include <chrono>
#include <limits>
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

template<class Bytes>
bool Nonzero(const Bytes& bytes) noexcept
{
    return std::any_of(bytes.begin(),bytes.end(),[](std::uint8_t value) { return value!=0; });
}

std::uint64_t Read64(const std::uint8_t* input) noexcept
{
    std::uint64_t value=0;
    for(unsigned i=0;i<8;++i) value=(value<<8)|input[i];
    return value;
}

std::uint64_t AddTime(std::uint64_t now,std::uint64_t interval) noexcept
{
    const auto maximum=(std::numeric_limits<std::uint64_t>::max)();
    return now>maximum-interval ? maximum : now+interval;
}

void Append(std::vector<std::uint8_t>& output,std::uint64_t number,unsigned count)
{
    for(unsigned i=count;i>0;--i) output.push_back(static_cast<std::uint8_t>(number>>(8*(i-1))));
}

using Reply=RendezvousListener::ControlReply;
Reply Error(std::uint16_t code)
{
    return {kEseWireServerError,true,{static_cast<std::uint8_t>(code>>8),static_cast<std::uint8_t>(code),0,0,0,0}};
}

Reply Ack()
{
    return {kEseWireServerAck,true,{0,0}};
}

bool Body(ByteView payload,std::size_t size) noexcept
{
    return payload.data && payload.size==size;
}

std::optional<rdv::Endpoint> ObservedEndpoint(const sockaddr_storage& source,int length) noexcept
{
    if(source.ss_family==AF_INET && length==sizeof(sockaddr_in)) {
        const auto& address=*reinterpret_cast<const sockaddr_in*>(&source);
        if(address.sin_addr.s_addr==htonl(INADDR_LOOPBACK) && address.sin_port)
            return rdv::Endpoint{{127,0,0,1},ntohs(address.sin_port),4};
    }
    if(source.ss_family==AF_INET6 && length==sizeof(sockaddr_in6)) {
        const auto& address=*reinterpret_cast<const sockaddr_in6*>(&source);
        if(IN6_IS_ADDR_LOOPBACK(&address.sin6_addr) && address.sin6_port && !address.sin6_scope_id) {
            rdv::Endpoint endpoint{};
            endpoint.family=6;
            endpoint.address.back()=1;
            endpoint.port=ntohs(address.sin6_port);
            return endpoint;
        }
    }
    return std::nullopt;
}

std::size_t FamilyIndex(std::uint8_t family) noexcept { return family==6 ? 1 : 0; }

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
    struct Outgoing {
        std::uint16_t type;
        RequestId request;
        bool response;
        std::vector<std::uint8_t> body;
        std::uint64_t until=0;
        std::size_t ttlOffset=0;
        std::optional<rdv::SessionContext> remote;
        rdv::Endpoint path{};
        rdv::Endpoint local{};
        std::array<std::uint8_t,24> file{};
        bool remotePublisher=false;
        std::uint64_t remoteVersion=0,localVersion=0;
    };
    struct Entry {
        Entry(const rdv::SessionContext& given,const Bytes32& secret,const ClientHello& client,std::uint64_t until,bool pairing)
            : context(given),key(secret),node(client.node),expiration(until),
              primary(client.mode==SessionMode::Primary),pairing(pairing),ledger(context) {}
        ~Entry() { SecureZeroMemory(key.data(),key.size()); }
        rdv::SessionContext context;
        Bytes32 key,node;
        std::uint64_t expiration;
        std::array<std::uint64_t,2> endpointVersion{};
        bool primary,pairing,loggedIn=false;
        rdv::Session ledger;
        std::array<std::optional<rdv::Registration>,2> pending;
        std::vector<Outgoing> outgoing;
        struct Receipt { RequestId request; Bytes32 digest; std::uint64_t until; };
        std::vector<Receipt> consentReceipts;
    };

    struct Voucher {
        Bytes32 token;
        rdv::SessionContext requester,target;
        std::array<std::uint8_t,24> file;
        std::uint64_t expires;
        std::uint64_t retainUntil=0;
        std::uint8_t purpose;
        RequestId issuance{};
        std::array<std::uint8_t,57> requestBody{};
        enum class State { Available, Pending, Finished } state=State::Available;
        RequestId request{};
        std::array<std::uint8_t,72> pairBody{};
        std::optional<Outgoing> response;
    };

    struct Pending {
        Bytes16 transaction,attempt;
        std::uint64_t generation,deadline,sourceVersion,targetVersion;
        rdv::Endpoint requesterEndpoint,targetEndpoint;
        std::size_t voucher;
    };

    Impl(ServerIndex& owner,std::uint16_t port) : index(owner),sockets(SOCK_DGRAM,IPPROTO_UDP,port)
    {
        if(!RefreshSecret(Now())) throw std::runtime_error("initialize RendezvousV2 cookie secret");
        worker=std::thread([this] { Run(); });
    }

    ~Impl()
    {
        stop=true;
        worker.join();
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

    bool Queue(Entry& entry,std::uint16_t type,const RequestId& request,bool response,
        std::vector<std::uint8_t> body,std::optional<Outgoing>* stored=nullptr,
        std::uint64_t until=0,std::size_t ttlOffset=0)
    {
        if(entry.outgoing.size()>=16) return false;
        Outgoing queued{type,request,response,std::move(body),until,ttlOffset,std::nullopt,{},{},{},false,0,0};
        if(stored) *stored=queued;
        entry.outgoing.push_back(std::move(queued));
        return true;
    }

    void FailPair(Pending& pair,std::uint16_t code)
    {
        auto& voucher=*vouchers[pair.voucher];
        voucher.state=Voucher::State::Finished;
        if(auto* requester=Find(voucher.requester))
            Queue(*requester,kEseWireServerError,voucher.request,true,Error(code).body,&voucher.response);
    }

    bool CurrentEndpoint(const Entry& entry,const rdv::Endpoint& endpoint,std::uint64_t now)
    {
        const auto current=entry.ledger.Current(endpoint.family,now);
        return current && rdv::SameEndpoint(current->endpoint,endpoint);
    }

    void Prune(std::uint64_t now)
    {
        for(auto& pair:pending) {
            if(!pair) continue;
            auto& voucher=*vouchers[pair->voucher];
            const auto* from=Find(voucher.requester);
            const auto* to=Find(voucher.target);
            if(now>=pair->deadline || now>=voucher.expires) {
                FailPair(*pair,kEseWireServerExpired);
            } else if(!from || !to || !Eligible(*from,now) || !Eligible(*to,now) ||
                from->endpointVersion[FamilyIndex(pair->requesterEndpoint.family)]!=pair->sourceVersion ||
                to->endpointVersion[FamilyIndex(pair->targetEndpoint.family)]!=pair->targetVersion ||
                !CurrentEndpoint(*from,pair->requesterEndpoint,now) || !CurrentEndpoint(*to,pair->targetEndpoint,now) ||
                !index.HasPublication(to->node,to->context.generation,voucher.file,now)) {
                FailPair(*pair,kEseWireServerTargetGone);
            } else continue;
            pair.reset();
        }
        for(auto& voucher:vouchers)
            if(voucher && voucher->state!=Voucher::State::Pending && now>=voucher->retainUntil)
                voucher.reset();
    }

    Reply RequestVoucher(Entry& requester,const FrameView& frame,std::uint64_t now)
    {
        const auto body=frame.payload;
        if(!Body(body,57) || (body.data[56]!=1 && body.data[56]!=2)) return Error(kEseWireServerMalformed);
        Bytes32 targetNode{};
        std::array<std::uint8_t,24> file{};
        std::copy_n(body.data,32,targetNode.begin());
        std::copy_n(body.data+32,24,file.begin());
        if(targetNode==requester.node || !Nonzero(targetNode) || !Read64(file.data()+16))
            return Error(kEseWireServerMalformed);
        Entry* target=nullptr;
        for(auto& found:entries)
            if(found && found->node==targetNode && found->primary && found->pairing && Eligible(*found,now)) {
                target=&*found;
                break;
            }
        if(!target || !index.HasPublication(targetNode,target->context.generation,file,now))
            return Error(kEseWireServerTargetGone);
        for(const auto& existing:vouchers) {
            if(!existing || !Matches(existing->requester,requester.context) || existing->issuance!=frame.header.request) continue;
            if(!std::equal(existing->requestBody.begin(),existing->requestBody.end(),body.data))
                return Error(kEseWireServerConflict);
            std::vector<std::uint8_t> payload(existing->token.begin(),existing->token.end());
            payload.insert(payload.end(),targetNode.begin(),targetNode.end());
            if(now>=existing->expires) return Error(kEseWireServerExpired);
            Append(payload,existing->expires-now,4);
            return {kEseWireServerVoucher,true,std::move(payload)};
        }
        auto available=std::find_if(vouchers.begin(),vouchers.end(),[](const auto& value){ return !value; });
        if(available==vouchers.end()) return Error(kEseWireServerResourceLimit);
        Voucher voucher{};
        voucher.requester=requester.context;
        voucher.target=target->context;
        voucher.file=file;
        voucher.purpose=body.data[56];
        voucher.issuance=frame.header.request;
        std::copy_n(body.data,voucher.requestBody.size(),voucher.requestBody.begin());
        voucher.expires=AddTime(now,30000);
        voucher.retainUntil=AddTime(now,120000);
        if(gnutls_rnd(GNUTLS_RND_KEY,voucher.token.data(),voucher.token.size())<0 || !Nonzero(voucher.token))
            return Error(kEseWireServerResourceLimit);
        if(std::any_of(vouchers.begin(),vouchers.end(),[&](const auto& prior) {
            return prior && gnutls_memcmp(prior->token.data(),voucher.token.data(),voucher.token.size())==0;
        })) return Error(kEseWireServerResourceLimit);
        std::vector<std::uint8_t> payload(voucher.token.begin(),voucher.token.end());
        payload.insert(payload.end(),targetNode.begin(),targetNode.end());
        Append(payload,30000,4);
        available->emplace(std::move(voucher));
        return {kEseWireServerVoucher,true,std::move(payload)};
    }

    Reply StartPair(Entry& requester,const FrameView& frame,std::uint64_t now)
    {
        if(!Body(frame.payload,72)) return Error(kEseWireServerMalformed);
        const auto* bytes=frame.payload.data;
        for(auto& voucher:vouchers) {
            if(voucher && Matches(voucher->requester,requester.context) && voucher->issuance==frame.header.request)
                return Error(kEseWireServerConflict);
            if(!voucher || voucher->state==Voucher::State::Available ||
                !Matches(voucher->requester,requester.context) || voucher->request!=frame.header.request) continue;
            if(!std::equal(voucher->pairBody.begin(),voucher->pairBody.end(),bytes))
                return Error(kEseWireServerConflict);
            if(voucher->state==Voucher::State::Finished) {
                if(!voucher->response || requester.outgoing.size()>=16)
                    return Error(kEseWireServerResourceLimit);
                requester.outgoing.push_back(*voucher->response);
            }
            return {0,false,{}};
        }
        auto item=std::find_if(vouchers.begin(),vouchers.end(),[&](const auto& voucher) {
            return voucher && Matches(voucher->requester,requester.context) &&
                gnutls_memcmp(voucher->token.data(),bytes,voucher->token.size())==0;
        });
        if(item==vouchers.end()) return Error(kEseWireServerTargetGone);
        auto& voucher=**item;
        if(now>=voucher.expires) return Error(kEseWireServerExpired);
        if(voucher.state!=Voucher::State::Available) return Error(kEseWireServerReplay);
        auto* target=Find(voucher.target);
        auto sourcePath=requester.ledger.Current(6,now);
        auto targetPath=target ? target->ledger.Current(6,now) : std::nullopt;
        if(!sourcePath || !targetPath) {
            sourcePath=requester.ledger.Current(4,now);
            targetPath=target ? target->ledger.Current(4,now) : std::nullopt;
        }
        if(!target || !sourcePath || !targetPath || !Eligible(*target,now) ||
            !index.HasPublication(target->node,target->context.generation,voucher.file,now))
            return Error(kEseWireServerTargetGone);
        auto available=std::find_if(pending.begin(),pending.end(),[](const auto& value) { return !value; });
        if(available==pending.end()) return Error(kEseWireServerResourceLimit);
        Pending pair{};
        pair.generation=Read64(bytes+48);
        Bytes16 nonce{};
        std::copy_n(bytes+32,16,pair.attempt.begin());
        std::copy_n(bytes+56,16,nonce.begin());
        if(!pair.generation || !Nonzero(pair.attempt) || !Nonzero(nonce)) return Error(kEseWireServerMalformed);
        if(gnutls_rnd(GNUTLS_RND_NONCE,pair.transaction.data(),pair.transaction.size())<0 || !Nonzero(pair.transaction))
            return Error(kEseWireServerResourceLimit);
        if(std::any_of(pending.begin(),pending.end(),[&](const auto& current) {
            return current && current->transaction==pair.transaction;
        })) return Error(kEseWireServerResourceLimit);
        pair.deadline=(std::min)(AddTime(now,10000),voucher.expires);
        pair.voucher=static_cast<std::size_t>(item-vouchers.begin());
        pair.requesterEndpoint=sourcePath->endpoint;
        pair.targetEndpoint=targetPath->endpoint;
        pair.sourceVersion=requester.endpointVersion[FamilyIndex(sourcePath->endpoint.family)];
        pair.targetVersion=target->endpointVersion[FamilyIndex(targetPath->endpoint.family)];
        std::vector<std::uint8_t> query(pair.transaction.begin(),pair.transaction.end());
        query.insert(query.end(),requester.node.begin(),requester.node.end());
        query.insert(query.end(),voucher.file.begin(),voucher.file.end());
        query.push_back(voucher.purpose);
        Append(query,pair.deadline-now,4);
        if(!Queue(*target,kEseWireServerConsentQuery,{},false,std::move(query),nullptr,pair.deadline,73))
            return Error(kEseWireServerResourceLimit);
        target->outgoing.back().remote=requester.context;
        target->outgoing.back().path=sourcePath->endpoint;
        target->outgoing.back().local=targetPath->endpoint;
        target->outgoing.back().file=voucher.file;
        target->outgoing.back().remoteVersion=pair.sourceVersion;
        target->outgoing.back().localVersion=pair.targetVersion;
        voucher.state=Voucher::State::Pending;
        voucher.request=frame.header.request;
        std::copy_n(bytes,voucher.pairBody.size(),voucher.pairBody.begin());
        available->emplace(pair);
        return {0,false,{}};
    }

    std::vector<std::uint8_t> PairResult(const Pending& pair,const Bytes16& attempt,std::uint64_t generation,
        const Bytes32& peer,const rdv::Endpoint& endpoint,std::uint64_t remaining)
    {
        std::vector<std::uint8_t> result(pair.transaction.begin(),pair.transaction.end());
        result.insert(result.end(),attempt.begin(),attempt.end());
        Append(result,generation,8);
        result.insert(result.end(),peer.begin(),peer.end());
        Append(result,remaining,4);
        result.push_back(1);
        result.push_back(endpoint.family);
        const auto length=endpoint.family==6 ? 16 : 4;
        result.insert(result.end(),endpoint.address.begin(),endpoint.address.begin()+length);
        Append(result,endpoint.port,2);
        return result;
    }

    Reply Consent(Entry& target,const FrameView& frame,std::uint64_t now)
    {
        if(!Body(frame.payload,41) || frame.payload.data[16]>1) return Error(kEseWireServerMalformed);
        Bytes16 transaction{}, attempt{};
        const auto* bytes=frame.payload.data;
        std::copy_n(bytes,16,transaction.begin());
        std::copy_n(bytes+17,16,attempt.begin());
        const auto generation=Read64(bytes+33);
        if(bytes[16] && (!generation || !Nonzero(attempt))) return Error(kEseWireServerMalformed);
        Bytes32 digest{};
        if(gnutls_hash_fast(GNUTLS_DIG_SHA256,bytes,frame.payload.size,digest.data())<0)
            return Error(kEseWireServerResourceLimit);
        target.consentReceipts.erase(std::remove_if(target.consentReceipts.begin(),target.consentReceipts.end(),
            [now](const Entry::Receipt& receipt) { return now>=receipt.until; }),target.consentReceipts.end());
        for(const auto& receipt:target.consentReceipts)
            if(receipt.request==frame.header.request)
                return receipt.digest==digest ? Ack() : Error(kEseWireServerConflict);
        if(target.consentReceipts.size()>=32) return Error(kEseWireServerResourceLimit);
        auto selected=std::find_if(pending.begin(),pending.end(),[&](const auto& pair) {
            return pair && pair->transaction==transaction && Matches(vouchers[pair->voucher]->target,target.context);
        });
        if(selected==pending.end()) return Error(kEseWireServerTargetGone);
        auto& pair=**selected;
        auto& voucher=*vouchers[pair.voucher];
        if(!bytes[16]) FailPair(pair,kEseWireServerNoConsent);
        else {
            auto* requester=Find(voucher.requester);
            const auto from=requester ? requester->ledger.Current(pair.requesterEndpoint.family,now) : std::nullopt;
            const auto to=target.ledger.Current(pair.targetEndpoint.family,now);
            if(!requester || !from || !to || !Eligible(*requester,now) || !Eligible(target,now) ||
                requester->endpointVersion[FamilyIndex(pair.requesterEndpoint.family)]!=pair.sourceVersion ||
                target.endpointVersion[FamilyIndex(pair.targetEndpoint.family)]!=pair.targetVersion ||
                !rdv::SameEndpoint(from->endpoint,pair.requesterEndpoint) || !rdv::SameEndpoint(to->endpoint,pair.targetEndpoint) ||
                !index.HasPublication(target.node,target.context.generation,voucher.file,now))
                FailPair(pair,kEseWireServerTargetGone);
            else if(requester->outgoing.size()>=16 || target.outgoing.size()>=16)
                return Error(kEseWireServerResourceLimit);
            else {
                const auto ttl=(std::min)({std::uint64_t{10000},from->until-now,to->until-now,
                    requester->expiration-now,target.expiration-now});
                const auto toRequester=PairResult(pair,pair.attempt,pair.generation,target.node,to->endpoint,ttl);
                const auto toTarget=PairResult(pair,attempt,generation,requester->node,from->endpoint,ttl);
                const auto until=AddTime(now,ttl);
                if(!Queue(*requester,kEseWireServerPairResult,voucher.request,true,toRequester,&voucher.response,until,72) ||
                    !Queue(target,kEseWireServerPairResult,{},false,toTarget,nullptr,until,72))
                    return Error(kEseWireServerResourceLimit);
                requester->outgoing.back().remote=target.context;
                requester->outgoing.back().path=to->endpoint;
                requester->outgoing.back().local=from->endpoint;
                requester->outgoing.back().file=voucher.file;
                requester->outgoing.back().remotePublisher=true;
                requester->outgoing.back().remoteVersion=pair.targetVersion;
                requester->outgoing.back().localVersion=pair.sourceVersion;
                *voucher.response=requester->outgoing.back();
                target.outgoing.back().remote=requester->context;
                target.outgoing.back().path=from->endpoint;
                target.outgoing.back().local=to->endpoint;
                target.outgoing.back().file=voucher.file;
                target.outgoing.back().remoteVersion=pair.sourceVersion;
                target.outgoing.back().localVersion=pair.targetVersion;
                voucher.state=Voucher::State::Finished;
            }
        }
        target.consentReceipts.push_back({frame.header.request,digest,AddTime(now,120000)});
        selected->reset();
        return Ack();
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
            for(const auto socketHandle:sockets.Handles()) FD_SET(socketHandle,&allowed);
            timeval timeout{0,50000};
            if(select(0,&allowed,nullptr,nullptr,&timeout)<=0) continue;
            for(const auto socketHandle:sockets.Handles())
                if(FD_ISSET(socketHandle,&allowed)) Receive(socketHandle);
        }
    }

    void Receive(SOCKET socketHandle)
    {
        std::array<std::uint8_t,rdv::DatagramSize+1> datagram{};
        sockaddr_storage source{};
        int length=sizeof source;
        const auto count=recvfrom(socketHandle,reinterpret_cast<char*>(datagram.data()),
            static_cast<int>(datagram.size()),0,reinterpret_cast<sockaddr*>(&source),&length);
        if(stop || count!=rdv::DatagramSize) return;
        const auto endpoint=ObservedEndpoint(source,length);
        rdv::SessionContext context;
        const ByteView view{datagram.data(),rdv::DatagramSize};
        if(!endpoint || !rdv::ReadContext(view,context) || datagram[9]!=endpoint->family) return;
        const auto now=Now();
        const std::lock_guard<std::mutex> lock(mutex);
        auto* entry=Find(context);
        if(!entry || !Eligible(*entry,now) || !RefreshSecret(now)) return;
        const auto second=now/1000;
        if(second!=budgetSecond) { budgetSecond=second; sent=0; }
        // Both native sockets share the same process budget. Responses are
        // never larger than the triggering datagrams.
        if(datagram[8]!=kEseWireRdv2Echo && sent>=32) return;
        const auto result=entry->ledger.Receive(view,*endpoint,entry->key,secrets,crypto,now);
        const auto family=FamilyIndex(endpoint->family);
        if(result.supersededEndpoint) {
            if(entry->endpointVersion[family]==(std::numeric_limits<std::uint64_t>::max)()) {
                entry->loggedIn=false;
                return;
            }
            ++entry->endpointVersion[family];
        }
        if(result.status && Eligible(*entry,now)) entry->pending[family]=result.status;
        if(result.challenge && Eligible(*entry,now)) {
            ++sent;
            sendto(socketHandle,reinterpret_cast<const char*>(result.challenge->data()),
                static_cast<int>(result.challenge->size()),0,reinterpret_cast<const sockaddr*>(&source),length);
        }
    }

    ServerIndex& index;
    LoopbackSockets sockets;
    std::atomic<bool> stop{false};
    std::mutex mutex;
    std::array<std::optional<Entry>,16> entries{};
    std::array<std::optional<Voucher>,64> vouchers{};
    std::array<std::optional<Pending>,16> pending{};
    rdv::CookieSecrets secrets;
    Crypto crypto;
    std::uint64_t budgetSecond=0;
    unsigned sent=0;
    std::thread worker;
};

RendezvousListener::RendezvousListener(ServerIndex& index,std::uint16_t port)
    : impl_(std::make_unique<Impl>(index,port)) {}
RendezvousListener::~RendezvousListener() = default;

std::uint16_t RendezvousListener::Port() const noexcept { return impl_->sockets.Port(); }

bool RendezvousListener::Attach(const rdv::SessionContext& context,const Bytes32& key,const ClientHello& client,
    std::uint64_t expiration,bool pairing)
{
    const std::lock_guard<std::mutex> lock(impl_->mutex);
    if(impl_->Find(context)) return false;
    for(auto& entry:impl_->entries)
        if(!entry) {
            entry.emplace(context,key,client,expiration,pairing);
            entry->outgoing.reserve(16);
            entry->consentReceipts.reserve(32);
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
    for(auto& pending:entry->pending) {
        const auto status=pending;
        pending.reset();
        if(status && now<status->until) return status;
    }
    return std::nullopt;
}

bool RendezvousListener::Handles(std::uint16_t type) const noexcept
{
    return type==kEseWireServerVoucherGet || type==kEseWireServerPairRequest || type==kEseWireServerConsentReply;
}

std::optional<Reply> RendezvousListener::Handle(const rdv::SessionContext& context,const FrameView& frame,std::uint64_t now)
{
    if(ClassifyFrame(frame.header,Direction::ClientToServer,Phase::Authenticated)!=Disposition::Message) return std::nullopt;
    const std::lock_guard<std::mutex> lock(impl_->mutex);
    impl_->Prune(now);
    auto* entry=impl_->Find(context);
    if(!entry || !impl_->Eligible(*entry,now)) return Error(kEseWireServerWrongState);
    if(!entry->pairing) return Error(kEseWireServerUnsupported);
    switch(frame.header.type) {
    case kEseWireServerVoucherGet: return impl_->RequestVoucher(*entry,frame,now);
    case kEseWireServerPairRequest: return impl_->StartPair(*entry,frame,now);
    case kEseWireServerConsentReply: return impl_->Consent(*entry,frame,now);
    default: return Error(kEseWireServerUnsupported);
    }
}

std::optional<std::vector<std::uint8_t>> RendezvousListener::TakeControl(const rdv::SessionContext& context,std::uint64_t now)
{
    const std::lock_guard<std::mutex> lock(impl_->mutex);
    impl_->Prune(now);
    auto* entry=impl_->Find(context);
    if(!entry || !impl_->Eligible(*entry,now)) return {};
    while(!entry->outgoing.empty()) {
        auto message=std::move(entry->outgoing.front());
        entry->outgoing.erase(entry->outgoing.begin());
        if(message.remote) {
            const auto* remote=impl_->Find(*message.remote);
            const auto* publisher=message.remotePublisher ? remote : entry;
            if(!remote || !publisher || !impl_->Eligible(*remote,now) ||
                remote->endpointVersion[FamilyIndex(message.path.family)]!=message.remoteVersion ||
                entry->endpointVersion[FamilyIndex(message.local.family)]!=message.localVersion ||
                !impl_->CurrentEndpoint(*remote,message.path,now) || !impl_->CurrentEndpoint(*entry,message.local,now) ||
                !impl_->index.HasPublication(publisher->node,publisher->context.generation,message.file,now)) {
                if(!message.response) continue;
                message.type=kEseWireServerError;
                message.body=Error(kEseWireServerTargetGone).body;
                message.until=0;
            }
        }
        if(message.until) {
            if(now>=message.until) {
                if(!message.response) continue;
                message.type=kEseWireServerError;
                message.body=Error(kEseWireServerExpired).body;
            } else {
                const auto ttl=message.until-now;
                for(unsigned i=0;i<4;++i)
                    message.body[message.ttlOffset+i]=static_cast<std::uint8_t>(ttl>>(24-i*8));
            }
        }
        std::vector<std::uint8_t> encoded;
        const auto flags=static_cast<std::uint16_t>(message.response ? kEseWireServerResponse | kEseWireServerFinal : 0);
        if(EncodeFrame({{message.type,flags,message.request},{message.body.data(),message.body.size()}},encoded))
            return encoded;
    }
    return {};
}
}
