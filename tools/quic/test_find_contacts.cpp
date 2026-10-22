#include <winsock2.h>
#include "../../srchybrid/EseKad6FindContacts.h"
#include "../../srchybrid/EseKad6Lookup.h"
#include "../../srchybrid/EseKad6Resolution.h"
#include "../../srchybrid/EseKad6ResolutionHost.h"
#include "../../srchybrid/EseResolutionCooldown.h"
#include "../../srchybrid/EseKad6ContactRefresh.h"
#include "../../srchybrid/EseKad6ContactCache.h"
#include "../../srchybrid/EseKad6LookupCooldown.h"
#include "../../srchybrid/EseKad6ContactRefreshReplies.h"
#include "../../srchybrid/EseKad6ContactCacheFile.h"
#include "../../srchybrid/LiveCrypto.h"
#include <cstdio>
#include <cstdlib>
static unsigned checks=0;
static void CheckAt(bool value,unsigned line) { ++checks; if(!value) { std::printf("FAIL %u line %u\n",checks,line); std::exit(1); } }
#define Check(...) CheckAt((__VA_ARGS__),__LINE__)
struct UdpPort {
    SOCKET socket=INVALID_SOCKET; sockaddr_in address{};
    UdpPort() {
        socket=::socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP); Check(socket!=INVALID_SOCKET);
        address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        Check(bind(socket,reinterpret_cast<sockaddr*>(&address),sizeof(address))==0);
        int n=sizeof(address); Check(getsockname(socket,reinterpret_cast<sockaddr*>(&address),&n)==0);
        DWORD timeout=1000; Check(setsockopt(socket,SOL_SOCKET,SO_RCVTIMEO,reinterpret_cast<const char*>(&timeout),sizeof(timeout))==0);
    }
    ~UdpPort() { if(socket!=INVALID_SOCKET) closesocket(socket); }
    UdpPort(const UdpPort&)=delete; UdpPort& operator=(const UdpPort&)=delete;
};
static void UdpRoundtrip(const ese::control::Datagram& packet,const ese::control::Header& header,
    const ese::discovery::DirectFind& query,const std::array<std::uint8_t,32>& digest,
    const std::array<std::uint8_t,32>& witness,ese::control::Kad6FindContacts& gate) {
    UdpPort sender,receiver; ese::udp::Endpoint expected; expected.address[0]=127; expected.address[3]=1;
    expected.port=ntohs(sender.address.sin_port);
    ese::control::DirectFindRequest pending; Check(pending.Start(witness,expected,header,query,digest,1000,100));
    Check(sendto(sender.socket,reinterpret_cast<const char*>(packet.bytes.data()),static_cast<int>(packet.size),0,
        reinterpret_cast<const sockaddr*>(&receiver.address),sizeof(receiver.address))==static_cast<int>(packet.size));
    ese::control::Datagram received; sockaddr_in source{}; int sourceSize=sizeof(source);
    const int n=recvfrom(receiver.socket,reinterpret_cast<char*>(received.bytes.data()),static_cast<int>(received.bytes.size()),0,
        reinterpret_cast<sockaddr*>(&source),&sourceSize);
    Check(n==static_cast<int>(packet.size)); Check(source.sin_port==sender.address.sin_port);
    Check(!std::memcmp(received.bytes.data(),packet.bytes.data(),packet.size));
    ese::udp::Endpoint actual; std::memcpy(actual.address.data(),&source.sin_addr,4); actual.port=ntohs(source.sin_port);
    ese::discovery::FindResultView result;
    Check(pending.Receive(actual,received.bytes.data(),static_cast<std::size_t>(n),101,result,&gate));
    Check(result.kind==1); Check(!pending.Receive(actual,received.bytes.data(),static_cast<std::size_t>(n),102,result,&gate));
}
static void FindOverUdp(const ese::control::Datagram& packet,const std::array<std::uint8_t,32>& requester,
    ese::control::Header& header,ese::discovery::DirectFind& query,std::array<std::uint8_t,32>& digest) {
    UdpPort sender,receiver;
    Check(sendto(sender.socket,reinterpret_cast<const char*>(packet.bytes.data()),static_cast<int>(packet.size),0,
        reinterpret_cast<const sockaddr*>(&receiver.address),sizeof(receiver.address))==static_cast<int>(packet.size));
    ese::control::Datagram received; sockaddr_in source{}; int sourceSize=sizeof(source);
    const int n=recvfrom(receiver.socket,reinterpret_cast<char*>(received.bytes.data()),static_cast<int>(received.bytes.size()),0,
        reinterpret_cast<sockaddr*>(&source),&sourceSize);
    Check(n==static_cast<int>(packet.size)); Check(source.sin_port==sender.address.sin_port);
    Check(ese::control::VerifyDirectFind(requester,received.bytes.data(),static_cast<std::size_t>(n),1000,header,query));
    Check(ese::control::DirectFindDigest(requester,received.bytes.data(),static_cast<std::size_t>(n),1000,digest));
}
static const std::uint8_t* activePub=nullptr;
static bool Sign(const kad6::Byte* secret,std::size_t n,const kad6::Byte* p,std::size_t size,kad6::Byte* signature) {
    return n==32 && eSELive::SignMessage(secret,activePub,p,size,signature);
}
static bool Verify(const kad6::Byte* pub,const kad6::Byte* p,std::size_t size,const kad6::Byte* signature) {
    return eSELive::VerifySignature(pub,p,size,signature);
}
struct FindHost final : ese::QuicSessionHost {
    UdpPort* port=nullptr;
    ese::control::Datagram sent; unsigned sends=0,removes=0; bool allow=true;
    bool ExpectControlReply(const ese::control::Header&,std::uint8_t type,const ese::udp::Endpoint&,std::uint64_t,std::uint64_t) override {
        Check(type==ese::wire::kEseWireUdpK6DirectFindResult || type==ese::wire::kEseWireUdpDescriptorResult); return allow;
    }
    void RemoveControlReplies(std::uint64_t) override { ++removes; }
    ese::QuicUdpSendResult SendControl(const ese::udp::Endpoint& peer,reach::DirectByteView bytes) override {
        ++sends; sent.size=bytes.size; std::memcpy(sent.bytes.data(),bytes.data,bytes.size);
        if(port) {
            sockaddr_in destination{}; destination.sin_family=AF_INET;
            std::memcpy(&destination.sin_addr,peer.address.data(),4); destination.sin_port=htons(peer.port);
            if(sendto(port->socket,reinterpret_cast<const char*>(bytes.data),static_cast<int>(bytes.size),0,
                reinterpret_cast<const sockaddr*>(&destination),sizeof(destination))!=static_cast<int>(bytes.size))
                return {ese::QuicUdpSendStatus::Failed,static_cast<std::uint32_t>(WSAGetLastError())};
        }
        return {ese::QuicUdpSendStatus::Sent,0};
    }
    void Stop() override {} void Poll(std::uint64_t) override {}
    std::size_t RetireClosed() override { return 0; } bool Empty() const noexcept override { return true; }
    std::uint64_t Begin(ese::NativeQuicConfig,ese::QuicPeerConfig,reach::DirectHandle,const reach::DirectSessionRoute&) override { return 0; }
    ese::QuicTransport* Find(std::uint64_t) const override { return nullptr; }
    bool Release(std::uint64_t) override { return false; }
};
class WitnessSigner final : public ese::control::Signer {
public:
    std::array<std::uint8_t,32> pub{},secret{};
    bool Sign(const std::uint8_t* p,std::size_t n,std::array<std::uint8_t,64>& s) noexcept override {
        return eSELive::SignMessage(secret.data(),pub.data(),p,n,s.data());
    }
};
static ese::control::Datagram ReceivePacket(UdpPort& port,const UdpPort& sender) {
    ese::control::Datagram packet; sockaddr_in source{}; int length=sizeof(source);
    const int n=recvfrom(port.socket,reinterpret_cast<char*>(packet.bytes.data()),static_cast<int>(packet.bytes.size()),0,
        reinterpret_cast<sockaddr*>(&source),&length);
    Check(n>0); Check(source.sin_port==sender.address.sin_port && source.sin_addr.s_addr==sender.address.sin_addr.s_addr);
    packet.size=static_cast<std::size_t>(n); return packet;
}
static void SendPacket(UdpPort& sender,const UdpPort& receiver,const ese::control::Datagram& packet) {
    Check(sendto(sender.socket,reinterpret_cast<const char*>(packet.bytes.data()),static_cast<int>(packet.size),0,
        reinterpret_cast<const sockaddr*>(&receiver.address),sizeof(receiver.address))==static_cast<int>(packet.size));
}
static void RetryOverUdp(const ese::control::Datagram& find,const ese::discovery::DirectFind& query,
    WitnessSigner& witness,const std::array<ese::discovery::FindEntryView,4>& entries,ese::control::Kad6FindContacts& gate) {
    UdpPort a,w; ese::udp::Endpoint remote; remote.address[0]=127; remote.address[3]=1; remote.port=ntohs(w.address.sin_port);
    ese::discovery::Kad6Resolution owner; Check(owner.Start(query.file,query.fileSize,1000,100));
    ese::discovery::Kad6Lookup::Contact contact; contact.node=witness.pub; contact.id[0]=1;
    Check(owner.Lookup().AddValidatedRecord(contact,100)); Check(owner.Lookup().MarkReturnVerified(contact.node,100));
    std::array<ese::discovery::Kad6Lookup::Contact,2> batch{}; Check(owner.Lookup().BeginRound(100,batch)==1);
    Check(owner.StartSignedFind(0,witness.pub,remote,query.requester,find,100));
    SendPacket(a,w,find); const auto dropped=ReceivePacket(w,a); // intentionally no response
    ese::control::Datagram retry; Check(owner.RetrySignedFind(0,500,retry));
    Check(retry.size==dropped.size && !std::memcmp(retry.bytes.data(),dropped.bytes.data(),retry.size));
    SendPacket(a,w,retry); const auto received=ReceivePacket(w,a);
    ese::control::Header header; ese::discovery::DirectFind decoded; std::array<std::uint8_t,32> digest{};
    Check(ese::control::VerifyDirectFind(query.requester,received.bytes.data(),received.size,1000,header,decoded));
    Check(ese::control::DirectFindDigest(query.requester,received.bytes.data(),received.size,1000,digest));
    ese::control::Datagram response;
    Check(ese::control::BuildDirectFindCloserResult(header,decoded,digest,entries,1,1000,witness.pub,witness,gate,response));
    SendPacket(w,a,response); const auto result=ReceivePacket(a,w); ese::discovery::FindResultView out;
    Check(owner.ReceiveFind(0,remote,result.bytes.data(),result.size,501,out,&gate));
    Check(owner.Lookup().Sends()==2); Check(!owner.RetrySignedFind(0,502,retry));
    Check(!owner.ReceiveFind(0,remote,result.bytes.data(),result.size,502,out,&gate));
}
static void RefreshOverUdp(const ese::control::Datagram& get,const std::array<std::uint8_t,32>& requester,
    WitnessSigner& witness,const std::vector<kad6::Byte>& record,const kad6::Kad6CryptoHooks& hooks) {
    UdpPort a,w; ese::udp::Endpoint remote; remote.address[0]=127; remote.address[3]=1; remote.port=ntohs(w.address.sin_port);
    ese::control::ContactRefreshRequest pending; Check(pending.Start(witness.pub,remote,requester,get,100,5000));
    SendPacket(a,w,get); const auto received=ReceivePacket(w,a);
    ese::control::Header header; std::array<std::uint8_t,32> digest{};
    Check(ese::control::VerifyContactGet(requester,received.bytes.data(),received.size,header));
    Check(ese::control::ContactGetDigest(requester,received.bytes.data(),received.size,digest));
    ese::control::Datagram response;
    Check(ese::control::BuildContactResult(header,requester,digest,record.data(),record.size(),witness.pub,witness,hooks,150,response));
    SendPacket(w,a,response); const auto reply=ReceivePacket(a,w); kad6::K6RouterRecord refreshed;
    Check(pending.Receive(remote,reply.bytes.data(),reply.size,101,hooks,150,refreshed));
    Check(refreshed.node_pub==witness.pub);
    Check(!pending.Receive(remote,reply.bytes.data(),reply.size,102,hooks,150,refreshed));
}
int main() {
    ese::discovery::ResolutionCooldown<1> cooldown;
    ese::discovery::ResolutionCooldown<1>::Key failed; failed.node[0]=1; failed.generation=7;
    Check(cooldown.RecordExpired(failed,1,100)); Check(!cooldown.Permit(failed,1,100));
    Check(cooldown.RecordExpired(failed,1,200));
    Check(cooldown.Permit(failed,1,200,true)); Check(cooldown.Permit(failed,2,200));
    Check(!cooldown.Permit(failed,1,200)); // bypass does not erase original cooldown
    auto otherFailed=failed; otherFailed.node[0]=2;
    Check(!cooldown.RecordExpired(otherFailed,1,200));
    Check(!cooldown.Permit(otherFailed,1,200));
    Check(cooldown.Permit(otherFailed,1,200,true));
    Check(cooldown.Permit(otherFailed,2,200));
    Check(!cooldown.Permit(failed,1,60099)); Check(cooldown.Permit(failed,1,60100));
    Check(!cooldown.Permit(failed,1,60099)); // time rollback fails closed
    Check(cooldown.RecordExpired(otherFailed,1,60100));
    std::array<std::uint8_t,16> file{},index{};
    for(unsigned i=0;i<16;++i) file[i]=static_cast<std::uint8_t>(i);
    const std::array<std::uint8_t,16> expectedIndex={0x2f,0x6f,0xdf,0x20,0x57,0xf2,0x84,0xe2,0x60,0x21,0x0d,0xcb,0x96,0x32,0xc0,0xbf};
    Check(ese::control::DirectIndexKey(file,123,1000,index)); Check(index==expectedIndex);
    Check(ese::control::DirectIndexKey(file,124,1000,index)); Check(index!=expectedIndex);
    Check(!ese::control::DirectIndexKey(file,0,1000,index)); Check(index==std::array<std::uint8_t,16>{});
    Check(!ese::control::DirectIndexKey(file,1001,1000,index));
    ese::discovery::ResolutionCooldown<> sharedCooldown;
    ese::discovery::ResolutionCooldown<>::Key knownSource; knownSource.node[0]=1; knownSource.generation=7;
    ese::discovery::Kad6Resolution expiringResolution;
    Check(expiringResolution.StartForSource(file,123,1000,sharedCooldown,knownSource,1,100));
    Check(!expiringResolution.Poll(5100));
    ese::discovery::Kad6Resolution blockedResolution;
    Check(!blockedResolution.StartForSource(file,123,1000,sharedCooldown,knownSource,1,5101));
    Check(blockedResolution.StartForSource(file,123,1000,sharedCooldown,knownSource,1,5101,true));
    blockedResolution.Cancel();
    Check(!sharedCooldown.Permit(knownSource,1,65099)); Check(sharedCooldown.Permit(knownSource,1,65100));
    ese::discovery::Kad6Lookup lookup; std::array<std::uint8_t,16> target{};
    Check(lookup.Start(target,100)); Check(lookup.Deadline()==5100);
    std::array<ese::discovery::Kad6Lookup::Contact,16> candidates{};
    for(unsigned i=0;i<16;++i) {
        candidates[i].id[15]=static_cast<std::uint8_t>(16-i); candidates[i].node[0]=static_cast<std::uint8_t>(i+1);
        Check(lookup.AddValidatedRecord(candidates[i],100));
    }
    Check(!lookup.AddValidatedRecord(candidates[0],100));
    std::array<ese::discovery::Kad6Lookup::Contact,2> batch{};
    Check(lookup.BeginRound(100,batch)==0); // signatures alone are probation
    for(const auto& candidate:candidates) Check(lookup.MarkReturnVerified(candidate.node,100));
    Check(lookup.BeginRound(100,batch)==2); Check(batch[0].id[15]==1 && batch[1].id[15]==2);
    const auto first=batch;
    Check(!lookup.Retry(first[0].node,100));
    Check(lookup.ConsumeFindAuthorization(first[0].node,100));
    Check(!lookup.ConsumeFindAuthorization(first[0].node,100));
    Check(lookup.BeginRound(101,batch)==0);
    for(unsigned i=0;i<4;++i) Check(lookup.Retry(first[0].node,101));
    Check(lookup.Complete(first[0].node,102)); Check(!lookup.Complete(first[0].node,102));
    Check(lookup.BeginRound(102,batch)==0); Check(lookup.Complete(first[1].node,102));
    for(unsigned round=0;round<3;++round) {
        Check(lookup.BeginRound(103+round,batch)==2);
        Check(lookup.Complete(batch[0].node,103+round)); Check(lookup.Complete(batch[1].node,103+round));
    }
    Check(lookup.Sends()==12 && lookup.Rounds()==4); Check(!lookup.Poll(106));
    Check(lookup.Status()==ese::discovery::Kad6Lookup::State::Exhausted);
    ese::discovery::Kad6Lookup deadline; Check(deadline.Start(target,100));
    Check(deadline.AddValidatedRecord(candidates[0],100)); Check(deadline.MarkReturnVerified(candidates[0].node,100));
    Check(deadline.BeginRound(4000,batch)==1); Check(!deadline.Poll(5100));
    Check(!deadline.Retry(candidates[0].node,4001));
    ese::discovery::Kad6Lookup cancelled; Check(cancelled.Start(target,100)); cancelled.Cancel(); Check(!cancelled.Poll(101));
    WSADATA winsock{}; Check(WSAStartup(MAKEWORD(2,2),&winsock)==0);
    std::array<std::uint8_t,32> pub{},secret{},witness{};
    Check(eSELive::GenerateBroadcasterKeypair(pub.data(),secret.data())); witness.fill(3); activePub=pub.data();
    kad6::Kad6CryptoHooks hooks; hooks.ed25519_sign=&Sign; hooks.ed25519_verify=&Verify;
    kad6::K6RouterRecord record; record.node_pub=pub; record.kad_id[0]=1; record.epoch=7;
    record.caps=1; record.valid_from=100; record.valid_until=200;
    kad6::K6Endpoint endpoint; endpoint.addr.family=kad6::Kad6Address::Family::IPv4;
    endpoint.addr.addr[0]=203; endpoint.addr.addr[2]=113; endpoint.addr.addr[3]=8;
    endpoint.udp_port=123; endpoint.transport_flags=kad6::kK6EpUdpKad6; endpoint.valid_until=200; record.endpoints.push_back(endpoint);
    std::vector<kad6::Byte> bytes;
    Check(kad6::SignK6RouterRecord(hooks,secret.data(),secret.size(),record,bytes)==kad6::Kad6Status::Ok);
    ese::discovery::FindResultView result; result.kind=1; result.count=1; result.entries[0]={bytes.data(),bytes.size(),0};
    ese::control::Kad6FindContacts gate(hooks,1,150); // lab-selected bit, NOT an assigned wire capability
    Check(gate.Verify(result,witness)); Check(!gate.Verify(result,pub));
    for(std::size_t i=0;i<bytes.size();++i) {
        auto changed=bytes; changed[i]^=1; result.entries[0]={changed.data(),changed.size(),0}; Check(!gate.Verify(result,witness));
    }
    result.entries[0]={bytes.data(),bytes.size(),0}; result.count=2; result.entries[1]=result.entries[0];
    Check(!gate.Verify(result,witness)); result.count=1;
    ese::control::Kad6FindContacts expired(hooks,1,200),future(hooks,1,99),missing(hooks,2,150),invalidMask(hooks,3,150);
    Check(!expired.Verify(result,witness)); Check(!future.Verify(result,witness));
    Check(!missing.Verify(result,witness)); Check(!invalidMask.Verify(result,witness));
    result.entries[0].size=1; Check(!gate.Verify(result,witness));
    WitnessSigner signer; Check(eSELive::GenerateBroadcasterKeypair(signer.pub.data(),signer.secret.data()));
    ese::control::Header header; header.type=ese::wire::kEseWireUdpK6DirectFind;
    header.attempt[0]=1; header.generation=9; header.sequence=2;
    ese::discovery::DirectFind query; query.requester=pub; query.file[0]=1; query.fileSize=123; query.maximum=4;
    WitnessSigner requester; Check(eSELive::GenerateBroadcasterKeypair(requester.pub.data(),requester.secret.data()));
    query.requester=requester.pub;
    auto contactHeader=header; contactHeader.type=ese::wire::kEseWireUdpK6ContactGet;
    ese::control::Datagram contactGet; ese::control::Header decodedContact;
    Check(ese::control::BuildContactGet(contactHeader,requester.pub,requester,contactGet) && contactGet.size==136);
    Check(ese::control::VerifyContactGet(requester.pub,contactGet.bytes.data(),contactGet.size,decodedContact));
    std::array<std::uint8_t,32> contactDigest{};
    Check(ese::control::ContactGetDigest(requester.pub,contactGet.bytes.data(),contactGet.size,contactDigest));
    for(std::size_t i=0;i<contactGet.size;++i) {
        auto bad=contactGet; bad.bytes[i]^=1;
        Check(!ese::control::VerifyContactGet(requester.pub,bad.bytes.data(),bad.size,decodedContact));
    }
    Check(!ese::control::VerifyContactGet(pub,contactGet.bytes.data(),contactGet.size,decodedContact));
    auto selfRecord=record; selfRecord.node_pub=signer.pub; selfRecord.kad_id[0]=3;
    activePub=signer.pub.data(); std::vector<kad6::Byte> selfBytes;
    Check(kad6::SignK6RouterRecord(hooks,signer.secret.data(),32,selfRecord,selfBytes)==kad6::Kad6Status::Ok);
    ese::discovery::Kad6ContactCache contactCache; kad6::K6RouterRecord cached;
    ese::discovery::Kad6LookupCooldown fileCooldown;
    std::array<std::uint8_t,16> scheduledFile{};
    Check(!fileCooldown.Claim(scheduledFile,100));
    scheduledFile[0]=1;
    Check(fileCooldown.Claim(scheduledFile,100));
    Check(!fileCooldown.Claim(scheduledFile,60099));
    Check(fileCooldown.Claim(scheduledFile,60100));
    Check(!fileCooldown.Claim(scheduledFile,60000));
    for(unsigned i=2;i<=64;++i) {
        scheduledFile[0]=static_cast<std::uint8_t>(i);
        Check(fileCooldown.Claim(scheduledFile,60100));
    }
    scheduledFile[0]=65;
    Check(!fileCooldown.Claim(scheduledFile,60100));
    Check(fileCooldown.Claim(scheduledFile,120100));
    Check(!fileCooldown.Claim(scheduledFile,(std::numeric_limits<std::uint64_t>::max)()));
    std::array<std::array<std::uint8_t,32>,64> contactHints{};
    contactHints[0]=signer.pub;
    Check(contactCache.SnapshotHints(contactHints)==0 && contactHints[0]==std::array<std::uint8_t,32>{});
    Check(contactCache.Import(signer.pub,selfBytes.data(),selfBytes.size(),hooks));
    Check(contactCache.SnapshotHints(contactHints)==1 && contactHints[0]==signer.pub &&
        contactHints[1]==std::array<std::uint8_t,32>{});
    Check(!contactCache.Import(pub,selfBytes.data(),selfBytes.size(),hooks));
    auto rollbackRecord=selfRecord; std::vector<kad6::Byte> rollbackBytes;
    rollbackRecord.epoch--;
    Check(kad6::SignK6RouterRecord(hooks,signer.secret.data(),32,rollbackRecord,rollbackBytes)==kad6::Kad6Status::Ok);
    Check(!contactCache.Import(signer.pub,rollbackBytes.data(),rollbackBytes.size(),hooks));
    rollbackRecord=selfRecord; rollbackRecord.valid_from--;
    Check(kad6::SignK6RouterRecord(hooks,signer.secret.data(),32,rollbackRecord,rollbackBytes)==kad6::Kad6Status::Ok);
    // A signed validity-window update is not an epoch rollback.
    Check(contactCache.Import(signer.pub,rollbackBytes.data(),rollbackBytes.size(),hooks));
    Check(contactCache.Import(signer.pub,selfBytes.data(),selfBytes.size(),hooks));
    Check(contactCache.Fresh(signer.pub,hooks,150,cached)); Check(!contactCache.Fresh(signer.pub,hooks,200,cached));
    std::array<std::uint8_t,kad6::kK6RouterRecordMaxSize> cachedBytes{}; std::size_t cachedSize=0;
    Check(contactCache.BeginRefresh(signer.pub,100,cachedBytes,cachedSize));
    Check(cachedSize==selfBytes.size() && !std::memcmp(cachedBytes.data(),selfBytes.data(),cachedSize));
    Check(!contactCache.BeginRefresh(signer.pub,60099,cachedBytes,cachedSize));
    Check(contactCache.Import(signer.pub,selfBytes.data(),selfBytes.size(),hooks));
    Check(!contactCache.BeginRefresh(signer.pub,60099,cachedBytes,cachedSize));
    Check(contactCache.BeginRefresh(signer.pub,60100,cachedBytes,cachedSize));
    std::array<std::uint8_t,32768> cacheWire{}; std::size_t cacheLength=0;
    Check(contactCache.Serialize(cacheWire,cacheLength) && cacheLength==12+2+selfBytes.size());
    ese::discovery::Kad6ContactCache loadedCache;
    Check(loadedCache.Load(cacheWire.data(),cacheLength,hooks));
    Check(!loadedCache.Load(cacheWire.data(),cacheLength,hooks));
    Check(loadedCache.Fresh(signer.pub,hooks,150,cached));
    Check(!loadedCache.Fresh(signer.pub,hooks,200,cached));
    // Cold-loaded/expired hints remain refresh candidates, not usable witnesses.
    Check(loadedCache.SnapshotHints(contactHints)==1 && contactHints[0]==signer.pub);
    Check(!loadedCache.Fresh(contactHints[0],hooks,200,cached));
    Check(loadedCache.ReadHint(signer.pub,cached) && cached.node_pub==signer.pub && cached.valid_until==selfRecord.valid_until);
    Check(!loadedCache.ReadHint(pub,cached) && cached.node_pub==std::array<std::uint8_t,32>{});
    Check(!loadedCache.Fresh(signer.pub,hooks,200,cached)); // reading is no renewal
    std::array<wchar_t,MAX_PATH> cacheFile{};
    Check(GetTempFileNameW(L"D:\\tmp",L"kc6",0,cacheFile.data())!=0);
    const std::wstring temporaryCache=std::wstring(cacheFile.data())+L".new";
    Check(ese::discovery::SaveContactCache(contactCache,cacheFile.data(),temporaryCache.c_str()));
    ese::discovery::Kad6ContactCache diskCache;
    Check(ese::discovery::LoadContactCache(diskCache,cacheFile.data(),hooks));
    Check(diskCache.Fresh(signer.pub,hooks,150,cached));
    rollbackRecord=selfRecord; rollbackRecord.epoch--;
    Check(kad6::SignK6RouterRecord(hooks,signer.secret.data(),32,rollbackRecord,rollbackBytes)==kad6::Kad6Status::Ok);
    Check(!diskCache.Import(signer.pub,rollbackBytes.data(),rollbackBytes.size(),hooks));
    std::array<std::uint8_t,32768> afterRollback{}; std::size_t afterRollbackLength=0;
    Check(diskCache.Serialize(afterRollback,afterRollbackLength));
    Check(afterRollbackLength==cacheLength && !std::memcmp(afterRollback.data(),cacheWire.data(),cacheLength));
    Check(diskCache.Fresh(signer.pub,hooks,150,cached) && cached.epoch==selfRecord.epoch);
    HANDLE heldCache=CreateFileW(cacheFile.data(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
    Check(heldCache!=INVALID_HANDLE_VALUE); ese::discovery::Kad6ContactCache emptyDiskCache;
    Check(!ese::discovery::SaveContactCache(emptyDiskCache,cacheFile.data(),temporaryCache.c_str()));
    Check(CloseHandle(heldCache)!=FALSE);
    ese::discovery::Kad6ContactCache preservedDiskCache;
    Check(ese::discovery::LoadContactCache(preservedDiskCache,cacheFile.data(),hooks));
    Check(preservedDiskCache.Fresh(signer.pub,hooks,150,cached));
    Check(GetFileAttributesW(temporaryCache.c_str())==INVALID_FILE_ATTRIBUTES);
    HANDLE collisionFile=CreateFileW(temporaryCache.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
    Check(collisionFile!=INVALID_HANDLE_VALUE);
    const std::array<std::uint8_t,3> sentinel={0x31,0x42,0x53}; DWORD sentinelWritten=0;
    Check(WriteFile(collisionFile,sentinel.data(),static_cast<DWORD>(sentinel.size()),&sentinelWritten,nullptr)!=FALSE && sentinelWritten==sentinel.size());
    Check(CloseHandle(collisionFile)!=FALSE);
    Check(!ese::discovery::SaveContactCache(emptyDiskCache,cacheFile.data(),temporaryCache.c_str()));
    collisionFile=CreateFileW(temporaryCache.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
    Check(collisionFile!=INVALID_HANDLE_VALUE);
    std::array<std::uint8_t,3> sentinelRead{}; DWORD sentinelLength=0;
    Check(ReadFile(collisionFile,sentinelRead.data(),static_cast<DWORD>(sentinelRead.size()),&sentinelLength,nullptr)!=FALSE && sentinelLength==sentinel.size() && sentinelRead==sentinel);
    Check(CloseHandle(collisionFile)!=FALSE); Check(DeleteFileW(temporaryCache.c_str())!=FALSE);
    Check(!ese::discovery::SaveContactCache(contactCache,cacheFile.data(),cacheFile.data()));
    Check(DeleteFileW(cacheFile.data())!=FALSE);
    for(std::size_t i=0;i<cacheLength;++i) {
        auto corruptedCache=cacheWire; corruptedCache[i]^=1; ese::discovery::Kad6ContactCache emptyCache;
        Check(!emptyCache.Load(corruptedCache.data(),cacheLength,hooks));
        Check(emptyCache.Load(cacheWire.data(),cacheLength,hooks)); // failed load committed nothing
    }
    RefreshOverUdp(contactGet,requester.pub,signer,selfBytes,hooks);
    ese::control::Datagram contactResult; kad6::K6RouterRecord refreshed;
    Check(ese::control::BuildContactResult(contactHeader,requester.pub,contactDigest,selfBytes.data(),selfBytes.size(),signer.pub,signer,hooks,150,contactResult));
    Check(ese::control::VerifyContactResult(signer.pub,contactHeader,requester.pub,contactDigest,contactResult.bytes.data(),contactResult.size,hooks,150,refreshed));
    Check(refreshed.node_pub==signer.pub && refreshed.kad_id==selfRecord.kad_id);
    ese::udp::Endpoint refreshEndpoint; refreshEndpoint.port=123;
    ese::control::ContactRefreshRequest refreshPending;
    Check(refreshPending.Start(signer.pub,refreshEndpoint,requester.pub,contactGet,100,150));
    auto wrongRefreshEndpoint=refreshEndpoint; wrongRefreshEndpoint.port=124;
    ese::control::Sessions liveSession; // trusted-admission fixture, not bootstrap evidence
    Check(!refreshPending.ReceiveInSession(liveSession,refreshEndpoint,contactResult.bytes.data(),contactResult.size,101,hooks,150,refreshed));
    Check(refreshPending.State()==ese::control::DescriptorRequestState::Pending);
    auto admitted=contactHeader; admitted.type=3; admitted.sequence=1;
    Check(liveSession.AdmitVerified(signer.pub,refreshEndpoint,admitted,contactDigest,100)==ese::control::Admission::Accepted);
    auto transactionalPending=refreshPending;
    ese::discovery::Kad6ContactCache refreshedCache;
    Check(ese::discovery::ImportRefreshedContact(refreshedCache,transactionalPending,liveSession,
        refreshEndpoint,contactResult.bytes.data(),contactResult.size,101,hooks,150,refreshed));
    Check(transactionalPending.State()==ese::control::DescriptorRequestState::Complete);
    Check(refreshedCache.Fresh(signer.pub,hooks,150,cached) && cached.epoch==selfRecord.epoch);
    Check(!ese::discovery::ImportRefreshedContact(refreshedCache,transactionalPending,liveSession,
        refreshEndpoint,contactResult.bytes.data(),contactResult.size,102,hooks,150,refreshed));
    auto higherRecord=selfRecord; ++higherRecord.epoch; std::vector<kad6::Byte> higherBytes;
    Check(kad6::SignK6RouterRecord(hooks,signer.secret.data(),32,higherRecord,higherBytes)==kad6::Kad6Status::Ok);
    Check(refreshedCache.Import(signer.pub,higherBytes.data(),higherBytes.size(),hooks));
    transactionalPending=refreshPending;
    Check(!ese::discovery::ImportRefreshedContact(refreshedCache,transactionalPending,liveSession,
        refreshEndpoint,contactResult.bytes.data(),contactResult.size,103,hooks,150,refreshed));
    Check(transactionalPending.State()==ese::control::DescriptorRequestState::Pending);
    Check(refreshedCache.Fresh(signer.pub,hooks,150,cached) && cached.epoch==higherRecord.epoch);
    ese::discovery::ContactRefreshReplies replies;
    Check(replies.Start(1,signer.pub,refreshEndpoint,requester.pub,contactGet,liveSession,100,150));
    ese::udp::Endpoint ownedRequestEndpoint;
    ese::control::Datagram ownedRequest;
    Check(replies.Request(1,100,ownedRequestEndpoint,ownedRequest));
    Check(ownedRequestEndpoint==refreshEndpoint);
    Check(replies.RequestInSession(1,liveSession,100,ownedRequestEndpoint,ownedRequest));
    ese::control::Sessions endedRefreshSession;
    Check(!replies.RequestInSession(1,endedRefreshSession,100,ownedRequestEndpoint,ownedRequest));
    Check(ownedRequest.size==0 && ownedRequestEndpoint==ese::udp::Endpoint{});
    Check(!replies.RequestInSession(1,liveSession,99,ownedRequestEndpoint,ownedRequest));
    Check(ownedRequest.size==0 && ownedRequestEndpoint==ese::udp::Endpoint{});
    Check(replies.RequestInSession(1,liveSession,100,ownedRequestEndpoint,ownedRequest));
    Check(ownedRequest.size==contactGet.size && !std::memcmp(ownedRequest.bytes.data(),contactGet.bytes.data(),contactGet.size));
    ownedRequest.bytes[0]^=1;
    Check(replies.Request(1,101,ownedRequestEndpoint,ownedRequest));
    Check(ownedRequest.size==contactGet.size && !std::memcmp(ownedRequest.bytes.data(),contactGet.bytes.data(),contactGet.size));
    Check(!replies.Request(999,101,ownedRequestEndpoint,ownedRequest));
    Check(ownedRequest.size==0 && ownedRequestEndpoint==ese::udp::Endpoint{});
    Check(!replies.Start(1,signer.pub,refreshEndpoint,requester.pub,contactGet,liveSession,100,150));
    ese::discovery::Kad6ContactCache ownedRefreshCache;
    Check(replies.Receive(1,ownedRefreshCache,liveSession,refreshEndpoint,contactResult.bytes.data(),contactResult.size,101,hooks,150));
    Check(!replies.Receive(1,ownedRefreshCache,liveSession,refreshEndpoint,contactResult.bytes.data(),contactResult.size,102,hooks,150));
    Check(!replies.Start(1,signer.pub,refreshEndpoint,requester.pub,contactGet,liveSession,102,150));
    Check(replies.Start(2,signer.pub,refreshEndpoint,requester.pub,contactGet,liveSession,102,150));
    unsigned expiredReplies=0; replies.Poll(150,[&](std::uint64_t owner) { Check(owner==2); ++expiredReplies; });
    Check(expiredReplies==1);
    Check(replies.Start(3,signer.pub,refreshEndpoint,requester.pub,contactGet,liveSession,151,200));
    Check(replies.Start(4,signer.pub,refreshEndpoint,requester.pub,contactGet,liveSession,151,200));
    unsigned removedReplies=0;
    replies.CancelAll([&](std::uint64_t owner) { Check(owner==3 || owner==4); ++removedReplies; });
    Check(removedReplies==2);
    Check(!replies.RequestInSession(3,liveSession,152,ownedRequestEndpoint,ownedRequest));
    Check(ownedRequest.size==0);
    Check(!replies.Receive(4,ownedRefreshCache,liveSession,refreshEndpoint,contactResult.bytes.data(),contactResult.size,152,hooks,150));
    Check(!replies.Start(4,signer.pub,refreshEndpoint,requester.pub,contactGet,liveSession,152,200));
    Check(!replies.Request(2,150,ownedRequestEndpoint,ownedRequest));
    Check(ownedRequest.size==0 && ownedRequestEndpoint==ese::udp::Endpoint{});
    Check(replies.Start(5,signer.pub,refreshEndpoint,requester.pub,contactGet,liveSession,152,200));
    unsigned revokedReplies=0;
    const auto retired=[&](std::uint64_t owner) { Check(owner==5); ++revokedReplies; };
    replies.PollInSession(liveSession,153,retired);
    Check(revokedReplies==0);
    replies.PollInSession(endedRefreshSession,154,retired);
    Check(revokedReplies==1);
    replies.PollInSession(endedRefreshSession,155,retired);
    replies.PollInSession(liveSession,156,retired);
    Check(revokedReplies==1);
    Check(!replies.RequestInSession(5,liveSession,156,ownedRequestEndpoint,ownedRequest));
    Check(ownedRequest.size==0 && ownedRequestEndpoint==ese::udp::Endpoint{});
    Check(!replies.Receive(5,ownedRefreshCache,liveSession,refreshEndpoint,contactResult.bytes.data(),contactResult.size,156,hooks,150));
    Check(!replies.Start(5,signer.pub,refreshEndpoint,requester.pub,contactGet,liveSession,156,200));
    Check(!refreshPending.Receive(wrongRefreshEndpoint,contactResult.bytes.data(),contactResult.size,101,hooks,150,refreshed));
    auto badRefresh=contactResult; badRefresh.bytes[badRefresh.size-1]^=1;
    Check(!refreshPending.Receive(refreshEndpoint,badRefresh.bytes.data(),badRefresh.size,102,hooks,150,refreshed));
    Check(refreshPending.State()==ese::control::DescriptorRequestState::Pending);
    Check(refreshPending.ReceiveInSession(liveSession,refreshEndpoint,contactResult.bytes.data(),contactResult.size,149,hooks,150,refreshed));
    Check(!refreshPending.Receive(refreshEndpoint,contactResult.bytes.data(),contactResult.size,149,hooks,150,refreshed));
    ese::control::ContactRefreshRequest refreshLate;
    Check(refreshLate.Start(signer.pub,refreshEndpoint,requester.pub,contactGet,100,150));
    Check(!refreshLate.Receive(refreshEndpoint,contactResult.bytes.data(),contactResult.size,150,hooks,150,refreshed));
    Check(refreshLate.State()==ese::control::DescriptorRequestState::Failed);
    for(std::size_t i=0;i<contactResult.size;++i) {
        auto bad=contactResult; bad.bytes[i]^=1;
        Check(!ese::control::VerifyContactResult(signer.pub,contactHeader,requester.pub,contactDigest,bad.bytes.data(),bad.size,hooks,150,refreshed));
    }
    Check(!ese::control::VerifyContactResult(signer.pub,contactHeader,requester.pub,contactDigest,contactResult.bytes.data(),contactResult.size,hooks,200,refreshed));
    Check(!ese::control::BuildContactResult(contactHeader,requester.pub,contactDigest,bytes.data(),bytes.size(),signer.pub,signer,hooks,150,contactResult));
    ese::control::Datagram findPacket;
    Check(ese::control::BuildDirectFind(header,query,1000,requester,findPacket));
    std::array<std::uint8_t,32> digest{};
    FindOverUdp(findPacket,requester.pub,header,query,digest);
    std::array<ese::discovery::FindEntryView,4> entries{}; entries[0]={bytes.data(),bytes.size(),0};
    ese::control::Datagram packet;
    Check(ese::control::BuildDirectFindCloserResult(header,query,digest,entries,1,1000,signer.pub,signer,gate,packet));
    RetryOverUdp(findPacket,query,signer,entries,gate);
    UdpRoundtrip(packet,header,query,digest,signer.pub,gate);
    ese::udp::Endpoint address; address.port=123;
    WitnessSigner publisher; publisher.pub=pub; publisher.secret=secret;
    ese::discovery::DirectSource sourceRecord; sourceRecord.file=query.file; sourceRecord.fileSize=query.fileSize;
    sourceRecord.node=pub; sourceRecord.generation=7; sourceRecord.serial=1; sourceRecord.ttl=120;
    std::array<std::uint8_t,327> reach{}; std::memcpy(reach.data(),"ESD3",4); reach[4]=3;
    reach[8]=1; reach[16]=7; reach[24]=1; reach[28]=120; std::memcpy(reach.data()+29,pub.data(),32);
    reach[93]=6;
    for(unsigned i=0;i<6;++i) {
        auto* route=reach.data()+95+28*i;
        route[0]=static_cast<std::uint8_t>(i+1); route[1]=(i==0)?6:4;
        route[2]=7; route[3]=3; // Claimed inbound proof must remain advertised.
        if(i==0) { route[4]=0x20; route[5]=1; route[6]=0x48; route[7]=0x60; route[19]=1; }
        else { route[4]=8; route[5]=8; route[6]=8; route[7]=static_cast<std::uint8_t>(i); }
        route[20]=0x12; route[21]=0x34; route[27]=static_cast<std::uint8_t>((i==0)?1:120);
    }
    ese::discovery::DescriptorSignatureInput reachInput;
    Check(ese::discovery::BuildSignatureInput(reach.data(),reach.size(),reachInput));
    Check(eSELive::SignMessage(secret.data(),pub.data(),reachInput.bytes.data(),reachInput.size,reach.data()+reach.size()-64));
    Check(ese::control::DescriptorDigest(reach.data(),reach.size(),sourceRecord.digest));
    std::array<std::uint8_t,173> signedSource{};
    Check(ese::control::BuildDirectSource(sourceRecord,1000,publisher,signedSource));
    std::array<ese::discovery::FindEntryView,4> sourceEntries{}; sourceEntries[0]={signedSource.data(),signedSource.size(),2};
    ese::control::Datagram sourceResult;
    Check(ese::control::BuildDirectFindSourcesResult(header,query,digest,sourceEntries,1,1000,signer.pub,signer,sourceResult));
    {
        auto boundedStorage=std::make_unique<ese::discovery::Kad6Resolution>();
        auto& bounded=*boundedStorage; Check(bounded.Start(query.file,query.fileSize,1000,100,9));
        std::array<WitnessSigner,4> witnesses;
        for(unsigned i=0;i<witnesses.size();++i) {
            Check(eSELive::GenerateBroadcasterKeypair(witnesses[i].pub.data(),witnesses[i].secret.data()));
            ese::discovery::Kad6Lookup::Contact contact; contact.node=witnesses[i].pub;
            contact.id[15]=static_cast<std::uint8_t>(i+1);
            Check(bounded.Lookup().AddValidatedRecord(contact,100));
            Check(bounded.Lookup().MarkReturnVerified(contact.node,100));
        }
        auto unrelated=sourceRecord; unrelated.node=requester.pub;
        std::array<std::uint8_t,173> unrelatedBytes{};
        Check(ese::control::BuildDirectSource(unrelated,1000,requester,unrelatedBytes));
        std::array<ese::discovery::Kad6Resolution::LocatedSource,32> boundedSources;
        unsigned received=0;
        for(unsigned round=0;round<2;++round) {
            const auto now=100+round*10;
            Check(bounded.Lookup().BeginRound(now,batch)==2);
            for(unsigned slot=0;slot<2;++slot) {
                const auto sendTime=now+slot*2;
                WitnessSigner* boundedWitness=nullptr;
                for(auto& candidate:witnesses) if(candidate.pub==batch[slot].node) boundedWitness=&candidate;
                Check(boundedWitness!=nullptr);
                Check(bounded.StartSignedFind(slot,boundedWitness->pub,address,requester.pub,findPacket,sendTime));
                auto records=sourceEntries; std::uint8_t count=1;
                if(received==3) { records[1]={unrelatedBytes.data(),unrelatedBytes.size(),2}; count=2; }
                ese::control::Datagram response;
                Check(ese::control::BuildDirectFindSourcesResult(header,query,digest,records,count,1000,boundedWitness->pub,*boundedWitness,response));
                Check(bounded.ReceiveFind(slot,address,response.bytes.data(),response.size,sendTime+1,result));
                ++received;
                Check(bounded.SnapshotLocatedSources(sendTime+1,boundedSources)==(received<4?received:4));
            }
        }
        unsigned primary=0,other=0;
        for(const auto& boundedRecord:boundedSources) {
            if(boundedRecord.source.node==pub) { ++primary; Check(boundedRecord.until<=2113); }
            if(boundedRecord.source.node==requester.pub) ++other;
        }
        Check(primary==3 && other==1); // fourth W ignored, unrelated source retained
    }
    auto sourceOwnerStorage=std::make_unique<ese::discovery::Kad6Resolution>();
    auto& sourceOwner=*sourceOwnerStorage; Check(sourceOwner.Start(query.file,query.fileSize,1000,100,9));
    ese::discovery::Kad6Lookup::Contact sourceW; sourceW.node=signer.pub; sourceW.id[0]=1;
    Check(sourceOwner.Lookup().AddValidatedRecord(sourceW,100)); Check(sourceOwner.Lookup().MarkReturnVerified(sourceW.node,100));
    Check(sourceOwner.Lookup().BeginRound(100,batch)==1);
    Check(sourceOwner.StartSignedFind(0,signer.pub,address,requester.pub,findPacket,100));
    Check(sourceOwner.ReceiveFind(0,address,sourceResult.bytes.data(),sourceResult.size,101,result));
    std::array<ese::discovery::Kad6Resolution::LocatedSource,32> located;
    Check(sourceOwner.SnapshotLocatedSources(101,located)==1);
    Check(located[0].source.node==pub && located[0].witness==signer.pub && located[0].witnessEndpoint==address &&
        located[0].until==2101 && located[0].locator.ttl==2 && located[0].locator.digest==sourceRecord.digest);
    Check(sourceOwner.SnapshotLocatedSources(102,located)==1 && located[0].until==2101 && located[0].locator.ttl==1);
    ese::discovery::Locator sourceLocator; sourceLocator.node=pub; sourceLocator.digest=sourceRecord.digest; sourceLocator.serial=1; sourceLocator.ttl=1;
    auto getHeader=header; getHeader.type=ese::wire::kEseWireUdpDescriptorResult; ++getHeader.sequence;
    auto wrongLocator=sourceLocator; wrongLocator.digest[0]^=1;
    Check(!sourceOwner.StartGet(0,signer.pub,address,getHeader,wrongLocator,102));
    Check(!sourceOwner.StartGet(0,witness,address,getHeader,sourceLocator,102));
    auto tooLong=sourceLocator; tooLong.ttl=2;
    Check(!sourceOwner.StartGet(0,signer.pub,address,getHeader,tooLong,102));
    Check(sourceOwner.StartGet(0,signer.pub,address,getHeader,sourceLocator,102));
    ese::control::Datagram descriptorResult;
    Check(ese::control::BuildDescriptorResult(getHeader,0,query.file,sourceLocator,reach.data(),reach.size(),signer.pub,signer,descriptorResult));
    {
        UdpPort requesterPort,witnessPort;
        ese::udp::Endpoint remote; remote.address[0]=127; remote.address[3]=1; remote.port=ntohs(witnessPort.address.sin_port);
        const auto savedAddress=address; address=remote;
        ese::discovery::Kad6Resolution hosted; Check(hosted.Start(query.file,query.fileSize,1000,100));
        Check(hosted.Lookup().AddValidatedRecord(sourceW,100)); Check(hosted.Lookup().MarkReturnVerified(sourceW.node,100));
        Check(hosted.Lookup().BeginRound(100,batch)==1);
        FindHost host; host.port=&requesterPort; ese::discovery::Kad6ResolutionHost bridge(host,hosted);
        ese::control::Sessions sessions; auto proof=header; proof.type=ese::wire::kEseWireUdpProve;
        Check(sessions.AdmitVerified(signer.pub,address,proof,digest,100)==ese::control::Admission::Accepted);
        Check(bridge.StartFind(0,1,signer.pub,address,requester.pub,findPacket,sessions,100,2100));
        Check(bridge.SendFind(0,sessions,100).status==ese::QuicUdpSendStatus::Sent);
        const auto wireFind=ReceivePacket(witnessPort,requesterPort);
        Check(wireFind.size==findPacket.size && !std::memcmp(wireFind.bytes.data(),findPacket.bytes.data(),findPacket.size));
        SendPacket(witnessPort,requesterPort,sourceResult);
        const auto wireSources=ReceivePacket(requesterPort,witnessPort);
        Check(bridge.ReceiveFind(1,sessions,address,wireSources.bytes.data(),wireSources.size,101,result));
        auto requestHeader=getHeader; requestHeader.type=ese::wire::kEseWireUdpDescriptorGet;
        ese::control::Datagram getPacket;
        Check(ese::control::BuildDescriptorGet(requestHeader,query.file,sourceLocator,requester.pub,requester,getPacket));
        auto badGet=getPacket; badGet.bytes[badGet.size-1]^=1;
        Check(!bridge.StartGet(0,2,signer.pub,address,requester.pub,sourceLocator,badGet,sessions,102,2100));
        Check(!bridge.StartGet(0,2,signer.pub,address,requester.pub,wrongLocator,getPacket,sessions,102,2100));
        Check(bridge.StartGet(0,2,signer.pub,address,requester.pub,sourceLocator,getPacket,sessions,102,2100));
        Check(bridge.SendGet(0,sessions,102).status==ese::QuicUdpSendStatus::Sent);
        const auto wireGet=ReceivePacket(witnessPort,requesterPort);
        Check(wireGet.size==getPacket.size && !std::memcmp(wireGet.bytes.data(),getPacket.bytes.data(),getPacket.size));
        Check(host.sent.size==getPacket.size && !std::memcmp(host.sent.bytes.data(),getPacket.bytes.data(),getPacket.size));
        Check(bridge.SendGet(0,sessions,103).status==ese::QuicUdpSendStatus::Invalid);
        bridge.PumpGetRetries(sessions,601); Check(host.sends==2);
        bridge.PumpGetRetries(sessions,602);
        auto wireRetry=ReceivePacket(witnessPort,requesterPort);
        Check(host.sends==3 && wireRetry.size==getPacket.size && !std::memcmp(wireRetry.bytes.data(),getPacket.bytes.data(),getPacket.size));
        bridge.PumpGetRetries(sessions,1601); Check(host.sends==3);
        bridge.PumpGetRetries(sessions,1602);
        wireRetry=ReceivePacket(witnessPort,requesterPort);
        Check(host.sends==4 && wireRetry.size==getPacket.size && !std::memcmp(wireRetry.bytes.data(),getPacket.bytes.data(),getPacket.size));
        bridge.PumpGetRetries(sessions,1602); Check(host.sends==4);
        ese::discovery::Kad6Resolution::ResolvedCandidate candidate;
        auto badReply=descriptorResult; badReply.bytes[badReply.size-1]^=1;
        SendPacket(witnessPort,requesterPort,badReply);
        const auto wireBad=ReceivePacket(requesterPort,witnessPort);
        Check(!bridge.ReceiveResolved(2,sessions,address,wireBad.bytes.data(),wireBad.size,1603,candidate));
        Check(!candidate.length && host.removes==1);
        SendPacket(witnessPort,requesterPort,descriptorResult);
        const auto wireResult=ReceivePacket(requesterPort,witnessPort);
        Check(bridge.ReceiveResolved(2,sessions,address,wireResult.bytes.data(),wireResult.size,1604,candidate));
        Check(candidate.length==reach.size() && !std::memcmp(candidate.descriptor.data(),reach.data(),reach.size()) && candidate.until==2101);
        Check(host.removes==2 && host.sends==4);
        bridge.PumpGetRetries(sessions,2099); Check(host.sends==4);
        Check(!bridge.ReceiveResolved(2,sessions,address,descriptorResult.bytes.data(),descriptorResult.size,2100,candidate));
        Check(!candidate.length);
        address=savedAddress;
    }
    ese::discovery::ResultView resolved;
    auto corruptDescriptorResult=descriptorResult; corruptDescriptorResult.bytes[corruptDescriptorResult.size-1]^=1;
    Check(!sourceOwner.ReceiveGet(0,address,corruptDescriptorResult.bytes.data(),corruptDescriptorResult.size,103,resolved));
    ese::discovery::Kad6Resolution::ResolvedCandidate ownedCandidate;
    Check(sourceOwner.ReceiveResolved(0,address,descriptorResult.bytes.data(),descriptorResult.size,104,ownedCandidate));
    Check(ownedCandidate.length==reach.size() && !std::memcmp(ownedCandidate.descriptor.data(),reach.data(),reach.size()));
    Check(ownedCandidate.source.file==query.file && ownedCandidate.source.fileSize==query.fileSize &&
        ownedCandidate.source.node==pub && ownedCandidate.witness==signer.pub && ownedCandidate.witnessEndpoint==address && ownedCandidate.until==2101);
    Check(ownedCandidate.receivedMs==104 && ownedCandidate.localGeneration==9);
    reach::NativeDirectCandidateSnapshotV1 nativeSnapshot;
    Check(ese::discovery::Kad6Resolution::NativeSnapshot(ownedCandidate,query.file,query.fileSize,9,104,nativeSnapshot));
    Check(nativeSnapshot.count==6 && nativeSnapshot.local_generation==9 && nativeSnapshot.remote_generation==7 &&
        nativeSnapshot.peer.expected_node_pub==pub && nativeSnapshot.peer.trust==reach::DirectIdentityTrust::Unknown &&
        !nativeSnapshot.peer.pin_version && !nativeSnapshot.peer.expected_user_hash);
    for(unsigned i=0;i<6;++i) {
        const auto& entry=nativeSnapshot.candidates[i];
        Check(entry.source==reach::DirectCandidateSource::KadSource && !entry.mapping_id &&
            entry.route.evidence==reach::DirectEvidence::Advertised && entry.route.topology_generation==9 &&
            entry.route.port==0x1234 && entry.route.transport_mask==7 && !entry.route.interface_id);
        Check(entry.route.expires_monotonic_ms==((i==0)?1104u:2101u));
    }
    Check(nativeSnapshot.candidates[0].route.kind==reach::DirectKind::DirectV6 &&
        nativeSnapshot.candidates[1].route.kind==reach::DirectKind::DirectV4 &&
        nativeSnapshot.candidates[2].route.kind==reach::DirectKind::VerifiedMapping &&
        nativeSnapshot.candidates[3].route.kind==reach::DirectKind::DirectV4 &&
        nativeSnapshot.candidates[4].route.scope==reach::DirectScope::SameLan &&
        nativeSnapshot.candidates[5].route.kind==reach::DirectKind::Predicted);
    Check(ese::discovery::Kad6Resolution::NativeSnapshot(ownedCandidate,query.file,query.fileSize,9,1104,nativeSnapshot));
    Check(nativeSnapshot.count==5 && nativeSnapshot.candidates[0].route.id==2 && nativeSnapshot.candidates[0].route.expires_monotonic_ms==2101);
    Check(!ese::discovery::Kad6Resolution::NativeSnapshot(ownedCandidate,query.file,query.fileSize,10,105,nativeSnapshot));
    Check(!nativeSnapshot.count && !nativeSnapshot.local_generation);
    Check(!ese::discovery::Kad6Resolution::NativeSnapshot(ownedCandidate,query.file,query.fileSize,9,103,nativeSnapshot));
    Check(!ese::discovery::Kad6Resolution::NativeSnapshot(ownedCandidate,query.file,query.fileSize+1,9,105,nativeSnapshot));
    auto wrongFile=query.file; wrongFile[0]^=1;
    Check(!ese::discovery::Kad6Resolution::NativeSnapshot(ownedCandidate,wrongFile,query.fileSize,9,105,nativeSnapshot));
    Check(!ese::discovery::Kad6Resolution::NativeSnapshot(ownedCandidate,query.file,query.fileSize,9,2101,nativeSnapshot));
    auto changedCandidate=ownedCandidate; ++changedCandidate.source.serial;
    Check(!ese::discovery::Kad6Resolution::NativeSnapshot(changedCandidate,query.file,query.fileSize,9,105,nativeSnapshot));
    changedCandidate=ownedCandidate; ++changedCandidate.source.generation;
    Check(!ese::discovery::Kad6Resolution::NativeSnapshot(changedCandidate,query.file,query.fileSize,9,105,nativeSnapshot));
    changedCandidate=ownedCandidate; changedCandidate.descriptor[changedCandidate.length-1]^=1;
    Check(!ese::discovery::Kad6Resolution::NativeSnapshot(changedCandidate,query.file,query.fileSize,9,105,nativeSnapshot));
    changedCandidate=ownedCandidate; changedCandidate.source.signature[0]^=1;
    Check(!ese::discovery::Kad6Resolution::NativeSnapshot(changedCandidate,query.file,query.fileSize,9,105,nativeSnapshot));
    changedCandidate=ownedCandidate; changedCandidate.source.file=wrongFile;
    Check(!ese::discovery::Kad6Resolution::NativeSnapshot(changedCandidate,wrongFile,query.fileSize,9,105,nativeSnapshot));
    changedCandidate=ownedCandidate; ++changedCandidate.source.fileSize;
    Check(!ese::discovery::Kad6Resolution::NativeSnapshot(changedCandidate,query.file,query.fileSize+1,9,105,nativeSnapshot));
    const auto consumedDescriptorResult=descriptorResult;
    descriptorResult.bytes.fill(0); Check(!std::memcmp(ownedCandidate.descriptor.data(),reach.data(),reach.size()));
    Check(!sourceOwner.ReceiveGet(0,address,consumedDescriptorResult.bytes.data(),consumedDescriptorResult.size,105,resolved));
    auto expiredGetHeader=getHeader; ++expiredGetHeader.sequence;
    Check(sourceOwner.StartGet(1,signer.pub,address,expiredGetHeader,sourceLocator,105));
    Check(ese::control::BuildDescriptorResult(expiredGetHeader,0,query.file,sourceLocator,reach.data(),reach.size(),signer.pub,signer,descriptorResult));
    Check(!sourceOwner.ReceiveGet(1,address,descriptorResult.bytes.data(),descriptorResult.size,2101,resolved));
    Check(!resolved.descriptor);
    auto resolutionStorage=std::make_unique<ese::discovery::Kad6Resolution>();
    auto& resolution=*resolutionStorage;
    {
        auto alternateStorage=std::make_unique<ese::discovery::Kad6Resolution>();
        auto& alternate=*alternateStorage;
        Check(alternate.Start(query.file,query.fileSize,1000,100));
        ese::discovery::Kad6Lookup::Contact firstWitness=sourceW,second=sourceW;
        second.node=publisher.pub; second.id[0]=2;
        Check(alternate.Lookup().AddValidatedRecord(firstWitness,100));
        Check(alternate.Lookup().AddValidatedRecord(second,100));
        Check(alternate.Lookup().MarkReturnVerified(firstWitness.node,100));
        Check(alternate.Lookup().MarkReturnVerified(second.node,100));
        Check(alternate.Lookup().BeginRound(100,batch)==2);
        UdpPort localPort,firstPort,secondPort;
        ese::udp::Endpoint firstAddress; firstAddress.address[0]=127; firstAddress.address[3]=1;
        firstAddress.port=ntohs(firstPort.address.sin_port);
        auto secondAddress=firstAddress; secondAddress.port=ntohs(secondPort.address.sin_port);
        Check(alternate.StartSignedFind(0,firstWitness.node,firstAddress,requester.pub,findPacket,100));
        Check(alternate.StartSignedFind(1,second.node,secondAddress,requester.pub,findPacket,100));
        auto longSources=sourceEntries; longSources[0].remainingTtl=120;
        ese::control::Datagram firstSources,secondSources;
        Check(ese::control::BuildDirectFindSourcesResult(header,query,digest,longSources,1,1000,signer.pub,signer,firstSources));
        Check(ese::control::BuildDirectFindSourcesResult(header,query,digest,longSources,1,1000,publisher.pub,publisher,secondSources));
        Check(alternate.ReceiveFind(0,firstAddress,firstSources.bytes.data(),firstSources.size,101,result));
        Check(alternate.ReceiveFind(1,secondAddress,secondSources.bytes.data(),secondSources.size,102,result));
        Check(alternate.SnapshotLocatedSources(103,located)==2);
        auto firstLocator=located[0].locator;
        Check(!alternate.StartGet(0,firstWitness.node,firstAddress,getHeader,firstLocator,103,103));
        FindHost alternateHost; alternateHost.port=&localPort;
        auto alternateBridgeStorage=std::make_unique<ese::discovery::Kad6ResolutionHost>(alternateHost,alternate);
        auto& alternateBridge=*alternateBridgeStorage;
        auto alternateSessionsStorage=std::make_unique<ese::control::Sessions>();
        auto& alternateSessions=*alternateSessionsStorage;
        auto proofHeader=header; proofHeader.type=ese::wire::kEseWireUdpProve;
        Check(alternateSessions.AdmitVerified(firstWitness.node,firstAddress,proofHeader,digest,103)==ese::control::Admission::Accepted);
        Check(alternateSessions.AdmitVerified(second.node,secondAddress,proofHeader,digest,103)==ese::control::Admission::Accepted);
        auto getRequestHeader=getHeader; getRequestHeader.type=ese::wire::kEseWireUdpDescriptorGet;
        ese::control::Datagram firstGet;
        Check(ese::control::BuildDescriptorGet(getRequestHeader,query.file,firstLocator,requester.pub,requester,firstGet));
        Check(alternateBridge.StartGet(0,1,firstWitness.node,firstAddress,requester.pub,firstLocator,firstGet,alternateSessions,103,2100));
        Check(alternateBridge.SendGet(0,alternateSessions,103).status==ese::QuicUdpSendStatus::Sent);
        const auto receivedFirstGet=ReceivePacket(firstPort,localPort);
        Check(receivedFirstGet.size==firstGet.size && !std::memcmp(receivedFirstGet.bytes.data(),firstGet.bytes.data(),firstGet.size));
        ese::control::Datagram lateFirst;
        Check(ese::control::BuildDescriptorResult(getHeader,0,query.file,firstLocator,reach.data(),reach.size(),signer.pub,signer,lateFirst));
        alternateBridge.Poll(alternateSessions,2100); Check(!alternateBridge.OwnsGet(1));
        Check(alternate.Lookup().Deadline()==5100);
        Check(alternate.SnapshotLocatedSources(2103,located)==2);
        auto secondLocator=located[1].locator;
        ese::control::Datagram secondGet;
        Check(ese::control::BuildDescriptorGet(getRequestHeader,query.file,secondLocator,requester.pub,requester,secondGet));
        Check(alternateBridge.StartGet(0,2,second.node,secondAddress,requester.pub,secondLocator,secondGet,alternateSessions,2103,4103));
        Check(alternateBridge.SendGet(0,alternateSessions,2103).status==ese::QuicUdpSendStatus::Sent);
        const auto receivedSecondGet=ReceivePacket(secondPort,localPort);
        Check(receivedSecondGet.size==secondGet.size && !std::memcmp(receivedSecondGet.bytes.data(),secondGet.bytes.data(),secondGet.size));
        ese::control::Datagram alternativeResult;
        Check(ese::control::BuildDescriptorResult(getHeader,0,query.file,secondLocator,reach.data(),reach.size(),publisher.pub,publisher,alternativeResult));
        ese::discovery::Kad6Resolution::ResolvedCandidate candidate;
        SendPacket(firstPort,localPort,lateFirst); const auto receivedLate=ReceivePacket(localPort,firstPort);
        Check(!alternateBridge.ReceiveResolved(1,alternateSessions,firstAddress,receivedLate.bytes.data(),receivedLate.size,2104,candidate));
        Check(!alternateBridge.ReceiveResolved(2,alternateSessions,firstAddress,receivedLate.bytes.data(),receivedLate.size,2104,candidate));
        SendPacket(secondPort,localPort,alternativeResult); const auto receivedAlternative=ReceivePacket(localPort,secondPort);
        Check(alternateBridge.ReceiveResolved(2,alternateSessions,secondAddress,receivedAlternative.bytes.data(),receivedAlternative.size,2104,candidate));
        Check(candidate.witness==second.node && candidate.witnessEndpoint==secondAddress && candidate.until==120102);
        Check(alternate.Lookup().Deadline()==5100);
        Check(!alternateBridge.ReceiveResolved(2,alternateSessions,secondAddress,alternativeResult.bytes.data(),alternativeResult.size,2105,candidate));
    }
    {
        ese::discovery::Kad6Resolution hosted;
        Check(hosted.Start(query.file,query.fileSize,1000,100));
        ese::discovery::Kad6Lookup::Contact contact; contact.node=signer.pub; contact.id[0]=1;
        Check(hosted.Lookup().AddValidatedRecord(contact,100));
        Check(hosted.Lookup().MarkReturnVerified(contact.node,100));
        Check(hosted.Lookup().BeginRound(100,batch)==1);
        FindHost host; ese::discovery::Kad6ResolutionHost bridge(host,hosted);
        ese::control::Sessions sessions;
        Check(!bridge.StartFind(0,1,signer.pub,address,requester.pub,findPacket,sessions,100,2100));
        auto proofHeader=header; proofHeader.type=ese::wire::kEseWireUdpProve;
        Check(sessions.AdmitVerified(signer.pub,address,proofHeader,digest,100)==ese::control::Admission::Accepted);
        host.allow=false;
        Check(!bridge.StartFind(0,1,signer.pub,address,requester.pub,findPacket,sessions,100,2100));
        host.allow=true;
        Check(bridge.StartFind(0,1,signer.pub,address,requester.pub,findPacket,sessions,100,2100));
        Check(bridge.SendFind(0,sessions,100).status==ese::QuicUdpSendStatus::Sent);
        Check(host.sent.size==findPacket.size && !std::memcmp(host.sent.bytes.data(),findPacket.bytes.data(),findPacket.size));
        bridge.PumpFindRetries(sessions,599); Check(host.sends==1 && hosted.Lookup().Sends()==1);
        bridge.PumpFindRetries(sessions,600); Check(host.sends==2 && hosted.Lookup().Sends()==2);
        Check(host.sent.size==findPacket.size && !std::memcmp(host.sent.bytes.data(),findPacket.bytes.data(),findPacket.size));
        bridge.PumpFindRetries(sessions,600); Check(host.sends==2);
        Check(hosted.Lookup().Sends()==2);
        Check(!bridge.ReceiveFind(2,sessions,address,packet.bytes.data(),packet.size,601,result,&gate));
        auto bad=packet; bad.bytes[bad.size-1]^=1;
        Check(!bridge.ReceiveFind(1,sessions,address,bad.bytes.data(),bad.size,601,result,&gate));
        Check(host.removes==0);
        sessions={}; bridge.PumpFindRetries(sessions,1600);
        Check(host.removes==1 && host.sends==2);
        Check(bridge.SendFind(0,sessions,1601).status==ese::QuicUdpSendStatus::Invalid);
        Check(sessions.AdmitVerified(signer.pub,address,proofHeader,digest,1601)==ese::control::Admission::Accepted);
        Check(!bridge.ReceiveFind(1,sessions,address,packet.bytes.data(),packet.size,1602,result,&gate));
        Check(!bridge.StartFind(1,1,signer.pub,address,requester.pub,findPacket,sessions,1602,2100));
    }
    {
        ese::discovery::Kad6Resolution scheduled; Check(scheduled.Start(query.file,query.fileSize,1000,100));
        ese::discovery::Kad6Lookup::Contact contact; contact.node=signer.pub; contact.id[0]=1;
        Check(scheduled.Lookup().AddValidatedRecord(contact,100));
        Check(scheduled.Lookup().MarkReturnVerified(contact.node,100));
        Check(scheduled.Lookup().BeginRound(100,batch)==1);
        FindHost host; ese::discovery::Kad6ResolutionHost bridge(host,scheduled);
        ese::control::Sessions sessions; auto proofHeader=header; proofHeader.type=ese::wire::kEseWireUdpProve;
        Check(sessions.AdmitVerified(signer.pub,address,proofHeader,digest,100)==ese::control::Admission::Accepted);
        Check(bridge.StartFind(0,1,signer.pub,address,requester.pub,findPacket,sessions,100,2100));
        Check(bridge.SendFind(0,sessions,100).status==ese::QuicUdpSendStatus::Sent);
        bridge.PumpFindRetries(sessions,600); Check(host.sends==2);
        bridge.PumpFindRetries(sessions,1599); Check(host.sends==2);
        bridge.PumpFindRetries(sessions,1600); Check(host.sends==3 && scheduled.Lookup().Sends()==3);
        Check(host.sent.size==findPacket.size && !std::memcmp(host.sent.bytes.data(),findPacket.bytes.data(),findPacket.size));
        bridge.PumpFindRetries(sessions,2099); Check(host.sends==3);
        bridge.PumpFindRetries(sessions,2100); Check(host.sends==3 && !bridge.OwnsFind(1) && host.removes==1);
        bridge.PumpFindRetries(sessions,5100); Check(host.sends==3);
    }
    Check(resolution.Start(query.file,query.fileSize,1000,100));
    Check(!resolution.StartFind(0,signer.pub,address,header,query,digest,5000));
    ese::discovery::Kad6Lookup::Contact selected; selected.node=signer.pub; selected.id[0]=1;
    Check(resolution.Lookup().AddValidatedRecord(selected,5000));
    Check(resolution.Lookup().MarkReturnVerified(selected.node,5000));
    Check(resolution.Lookup().BeginRound(5000,batch)==1);
    auto invalidFind=findPacket; invalidFind.bytes[invalidFind.size-1]^=1;
    Check(!resolution.StartSignedFind(0,signer.pub,address,requester.pub,invalidFind,5000));
    Check(resolution.StartSignedFind(0,signer.pub,address,requester.pub,findPacket,5000));
    Check(!resolution.StartFind(0,signer.pub,address,header,query,digest,5000));
    ese::control::Datagram retryPacket;
    for(unsigned i=0;i<11;++i) {
        Check(resolution.RetrySignedFind(0,5001,retryPacket));
        Check(retryPacket.size==findPacket.size && !std::memcmp(retryPacket.bytes.data(),findPacket.bytes.data(),findPacket.size));
    }
    Check(!resolution.RetrySignedFind(0,5001,retryPacket)); Check(retryPacket.size==0); Check(resolution.Lookup().Sends()==12);
    Check(resolution.ReceiveFind(0,address,packet.bytes.data(),packet.size,5099,result,&gate));
    Check(!resolution.AuthorizeFindRetry(0,5099));
    Check(!resolution.StartFind(0,signer.pub,address,header,query,digest,5099));
    auto freshHeader=header; ++freshHeader.sequence;
    Check(!resolution.StartFind(0,signer.pub,address,freshHeader,query,digest,5099));
    Check(!resolution.ReceiveFind(0,address,packet.bytes.data(),packet.size,5099,result,&gate));
    Check(!resolution.ReceiveFind(0,address,packet.bytes.data(),packet.size,5100,result,&gate));
    Check(!resolution.Poll(5000));
    ese::discovery::Kad6Resolution cancelledResolution;
    Check(cancelledResolution.Start(query.file,query.fileSize,1000,100)); cancelledResolution.Cancel();
    Check(!cancelledResolution.StartFind(0,signer.pub,address,header,query,digest,101));
    ese::control::DirectFindRequest capped;
    Check(capped.Start(signer.pub,address,header,query,digest,1000,5000,5100));
    Check(capped.Poll(5099)); Check(!capped.Poll(5100));
    ese::control::DirectFindRequest alreadyExpired;
    Check(!alreadyExpired.Start(signer.pub,address,header,query,digest,1000,5100,5100));
    ese::control::DescriptorRequest getCapped;
    auto responseHeader=header; responseHeader.type=ese::wire::kEseWireUdpDescriptorResult;
    ese::discovery::Locator locator; locator.node=pub; locator.ttl=120; locator.serial=1;
    Check(getCapped.Start(signer.pub,address,responseHeader,query.file,locator,5000,5100));
    Check(getCapped.Poll(5099)); Check(!getCapped.Poll(5100));
    ese::control::DescriptorRequest getExpired;
    Check(!getExpired.Start(signer.pub,address,responseHeader,query.file,locator,5100,5100));
    for(std::size_t i=0;i<packet.size;++i) {
        auto corrupted=packet; corrupted.bytes[i]^=1;
        ese::control::DirectFindRequest request;
        Check(request.Start(signer.pub,address,header,query,digest,1000,100));
        Check(!request.Receive(address,corrupted.bytes.data(),corrupted.size,101,result,&gate));
        Check(request.State()==ese::control::DescriptorRequestState::Pending);
        Check(request.Receive(address,packet.bytes.data(),packet.size,102,result,&gate));
    }
    ese::control::DirectFindRequest timed;
    Check(timed.Start(signer.pub,address,header,query,digest,1000,100));
    auto wrongAddress=address; wrongAddress.port=124;
    Check(!timed.Receive(wrongAddress,packet.bytes.data(),packet.size,101,result,&gate));
    Check(!timed.Receive(address,packet.bytes.data(),packet.size,2100,result,&gate));
    Check(timed.State()==ese::control::DescriptorRequestState::Failed);
    Check(!timed.Receive(address,packet.bytes.data(),packet.size,102,result,&gate));
    // A second independently signed identity exercises the two-contact path.
    WitnessSigner contact2; Check(eSELive::GenerateBroadcasterKeypair(contact2.pub.data(),contact2.secret.data()));
    auto record2=record; record2.node_pub=contact2.pub; record2.kad_id[0]=2;
    activePub=contact2.pub.data(); std::vector<kad6::Byte> bytes2;
    Check(kad6::SignK6RouterRecord(hooks,contact2.secret.data(),32,record2,bytes2)==kad6::Kad6Status::Ok);
    entries[1]={bytes2.data(),bytes2.size(),0}; ese::control::Datagram pair;
    Check(ese::control::BuildDirectFindCloserResult(header,query,digest,entries,2,1000,signer.pub,signer,gate,pair));
    UdpRoundtrip(pair,header,query,digest,signer.pub,gate);
    ese::control::DirectFindRequest pairRequest;
    Check(pairRequest.Start(signer.pub,address,header,query,digest,1000,100));
    Check(pairRequest.Receive(address,pair.bytes.data(),pair.size,101,result,&gate));
    Check(result.count==2 && result.entries[1].size==bytes2.size() &&
        !std::memcmp(result.entries[1].bytes,bytes2.data(),bytes2.size()));
    ese::discovery::Kad6Lookup learned; Check(learned.Start(target,100));
    ese::control::DirectFindRequest learnRequest; Check(learnRequest.Start(signer.pub,address,header,query,digest,1000,100));
    unsigned added=0; auto badPair=pair; badPair.bytes[badPair.size-1]^=1;
    Check(!ese::control::ReceiveCloserAndQueue(learnRequest,learned,address,badPair.bytes.data(),badPair.size,101,gate,result,added));
    Check(added==0 && learnRequest.State()==ese::control::DescriptorRequestState::Pending);
    Check(ese::control::ReceiveCloserAndQueue(learnRequest,learned,address,pair.bytes.data(),pair.size,102,gate,result,added));
    Check(added==2); Check(learned.BeginRound(102,batch)==0);
    Check(learned.MarkReturnVerified(pub,103)); Check(learned.BeginRound(103,batch)==1);
    Check(batch[0].node==pub);
    Check(!ese::control::ReceiveCloserAndQueue(learnRequest,learned,address,pair.bytes.data(),pair.size,104,gate,result,added));
    Check(added==0);
    entries[1]=entries[0];
    Check(!ese::control::BuildDirectFindCloserResult(header,query,digest,entries,2,1000,signer.pub,signer,gate,pair));
    Check(pair.size==0);
    ese::control::DirectFindRequest pending;
    Check(pending.Start(signer.pub,address,header,query,digest,1000,100));
    Check(!pending.Receive(address,packet.bytes.data(),packet.size,101,result));
    Check(pending.Receive(address,packet.bytes.data(),packet.size,102,result,&gate));
    Check(result.entries[0].size==bytes.size() && !std::memcmp(result.entries[0].bytes,bytes.data(),bytes.size()));
    Check(!pending.Receive(address,packet.bytes.data(),packet.size,103,result,&gate));
    Check(!ese::control::BuildDirectFindCloserResult(header,query,digest,entries,1,1000,witness,signer,gate,packet));
    Check(packet.size==0);
    Check(!ese::control::BuildDirectFindCloserResult(header,query,digest,entries,1,1000,signer.pub,signer,expired,packet));
    Check(WSACleanup()==0);
    std::printf("Kad6 CLOSER contacts: %u checks PASS (real UDP/libkad6/Crypto++; capability allocation/host adoption pending)\n",checks);
}
