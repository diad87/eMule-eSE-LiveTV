#include <winsock2.h>
#include <ws2tcpip.h>
#include "../../srchybrid/EseControlInitiator.h"
#include "../../srchybrid/EseWitnessDescriptors.h"
#include "../../srchybrid/LiveCrypto.h"
#include <chrono>
#include <cstdio>
#include <stdexcept>
#include <thread>
#include <memory>
using namespace ese::control;
static void Check(bool ok,const char* reason) { if(!ok) throw std::runtime_error(reason); }
static std::uint64_t Now() { return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count()); }
struct Identity final : Signer {
    std::array<std::uint8_t,32> pub{},secret{};
    Identity() { Check(eSELive::GenerateBroadcasterKeypair(pub.data(),secret.data()),"keypair"); }
    bool Sign(const std::uint8_t* p,std::size_t n,std::array<std::uint8_t,64>& out) noexcept override {
        return eSELive::SignMessage(secret.data(),pub.data(),p,n,out.data());
    }
};
struct Port {
    SOCKET socket=INVALID_SOCKET;
    ese::udp::Endpoint endpoint;
    Port() {
        socket=::socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
        Check(socket!=INVALID_SOCKET,"socket");
        sockaddr_in address{}; address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        if(bind(socket,reinterpret_cast<sockaddr*>(&address),sizeof(address))) { closesocket(socket); socket=INVALID_SOCKET; Check(false,"bind"); }
        int length=sizeof(address);
        if(getsockname(socket,reinterpret_cast<sockaddr*>(&address),&length)) { closesocket(socket); socket=INVALID_SOCKET; Check(false,"getsockname"); }
        endpoint.address[0]=127; endpoint.address[3]=1; endpoint.port=ntohs(address.sin_port);
        u_long nonblocking=1;
        if(ioctlsocket(socket,FIONBIO,&nonblocking)) { closesocket(socket); socket=INVALID_SOCKET; Check(false,"nonblocking"); }
    }
    ~Port() { if(socket!=INVALID_SOCKET) closesocket(socket); }
    Port(const Port&)=delete; Port& operator=(const Port&)=delete;
    bool Send(const ese::udp::Endpoint& target,const std::uint8_t* bytes,std::size_t size) {
        sockaddr_in address{}; address.sin_family=AF_INET; address.sin_port=htons(target.port);
        std::memcpy(&address.sin_addr,target.address.data(),4);
        const int sent=sendto(socket,reinterpret_cast<const char*>(bytes),static_cast<int>(size),0,reinterpret_cast<sockaddr*>(&address),sizeof(address));
        if(sent==SOCKET_ERROR) { Check(WSAGetLastError()==WSAEWOULDBLOCK,"sendto"); return false; }
        Check(sent==static_cast<int>(size),"partial datagram"); return true;
    }
    bool Receive(Datagram& packet,ese::udp::Endpoint& source) {
        sockaddr_in address{}; int length=sizeof(address);
        const int n=recvfrom(socket,reinterpret_cast<char*>(packet.bytes.data()),static_cast<int>(packet.bytes.size()),0,reinterpret_cast<sockaddr*>(&address),&length);
        if(n==SOCKET_ERROR) { Check(WSAGetLastError()==WSAEWOULDBLOCK,"recvfrom"); return false; }
        source={}; std::memcpy(source.address.data(),&address.sin_addr,4); source.port=ntohs(address.sin_port);
        packet.size=static_cast<std::size_t>(n); return true;
    }
};
static Datagram ReceiveFrom(Port& port,const ese::udp::Endpoint& expected) {
    Datagram packet; ese::udp::Endpoint source; const auto deadline=Now()+2000;
    while(Now()<deadline) {
        if(port.Receive(packet,source)) { Check(source==expected,"descriptor UDP source"); return packet; }
        std::this_thread::yield();
    }
    Check(false,"descriptor UDP receive timeout"); return {};
}
// Wire/store integration. Direct source PUT is real; Kad lookup is not wired.
static Header AuthenticateRequester(Identity& requester,Identity& witness,Port& pc,Port& pb,
    CookieAuthority& authority,ChallengeLimit& limit,Sessions& sessions) {
    Header header; header.type=1; header.generation=9; header.sequence=1; header.attempt.fill(0x53);
    Probe probe; probe.node=requester.pub; probe.peer=witness.pub; probe.nonce.fill(0x64);
    Initiator initiator; const auto now=Now(); Check(initiator.Start(header,probe,pb.endpoint,now,now+8000),"A control start");
    auto pending=initiator.Pending(now);
    Check(pc.Send(pb.endpoint,pending.data,pending.size) && initiator.Submitted(now),"A PROBE send");
    auto packet=ReceiveFrom(pb,pc.endpoint); Datagram response;
    Check(BuildChallenge(authority,limit,pc.endpoint,witness.pub,requester.pub,packet.bytes.data(),packet.size,Now(),response),"A challenge");
    Check(pb.Send(pc.endpoint,response.bytes.data(),response.size),"A challenge send");
    packet=ReceiveFrom(pc,pb.endpoint);
    Check(initiator.ChallengeReceived(pb.endpoint,packet.bytes.data(),packet.size,Now(),requester),"A challenge correlate");
    const auto proveNow=Now(); pending=initiator.Pending(proveNow);
    Check(pc.Send(pb.endpoint,pending.data,pending.size) && initiator.Submitted(proveNow),"A PROVE send");
    packet=ReceiveFrom(pb,pc.endpoint); Prove proof; Envelope envelope;
    Check(ParseUntrusted(packet.bytes.data(),packet.size,envelope) &&
        AdmitProve(authority,sessions,pc.endpoint,witness.pub,requester.pub,packet.bytes.data(),packet.size,Now(),proof)==Admission::Accepted,"A control admission");
    Check(BuildAck(proof,envelope.header,0,witness.pub,witness,response),"A ACK build");
    Check(pb.Send(pc.endpoint,response.bytes.data(),response.size),"A ACK send");
    packet=ReceiveFrom(pc,pb.endpoint);
    Check(initiator.AckReceived(pb.endpoint,packet.bytes.data(),packet.size,Now()) && initiator.State()==InitiatorState::Ready,"A control ready");
    return header;
}
static void DescriptorRoundtrip(Identity& publisher,Identity& witness,Port& pa,Port& pb,
    Sessions& sessions,const Header& bootstrap,CookieAuthority& authority,ChallengeLimit& challengeLimit,
    PacketBudget& processBudget) {
    Identity requester; Port pc;
    Check(requester.pub!=publisher.pub && requester.pub!=witness.pub && publisher.pub!=witness.pub,"three independent identities");
    const auto requesterHeader=AuthenticateRequester(requester,witness,pc,pb,authority,challengeLimit,sessions);
    std::array<std::uint8_t,968> descriptor{};
    std::memcpy(descriptor.data(),"ESD3",4); descriptor[4]=3;
    descriptor[8]=1; descriptor[16]=7; descriptor[24]=1; descriptor[28]=120;
    std::memcpy(descriptor.data()+29,publisher.pub.data(),32); descriptor[93]=8; descriptor[94]=3;
    for(unsigned i=0;i<8;++i) {
        auto* candidate=descriptor.data()+95+28*i;
        candidate[0]=2; candidate[1]=4; candidate[2]=4; candidate[21]=1; candidate[27]=60;
    }
    for(unsigned i=0;i<3;++i) {
        auto* reservation=descriptor.data()+95+8*28+195*i;
        reservation[0]=4; reservation[18]=1;
    }
    ese::discovery::DescriptorSignatureInput signedInput; std::array<std::uint8_t,64> signature{};
    Check(ese::discovery::BuildSignatureInput(descriptor.data(),descriptor.size(),signedInput) &&
        publisher.Sign(signedInput.bytes.data(),signedInput.size,signature),"sign maximum descriptor");
    std::memcpy(descriptor.data()+descriptor.size()-64,signature.data(),64);
    ese::discovery::Locator locator; locator.node=publisher.pub; locator.serial=1; locator.ttl=120;
    Check(DescriptorDigest(descriptor.data(),descriptor.size(),locator.digest),"maximum descriptor digest");
    std::array<std::uint8_t,16> file{}; file.fill(0x91);
    auto header=bootstrap; header.type=ese::wire::kEseWireUdpDescriptorPut; header.sequence=2;
    Datagram packet;
    Check(BuildDescriptorPut(header,file,descriptor.data(),descriptor.size(),publisher.pub,publisher,packet) && packet.size==1090,"maximum PUT build");
    auto confirmation=header; confirmation.type=ese::wire::kEseWireUdpDescriptorResult;
    DescriptorRequest publicationRequest;
    Check(publicationRequest.Start(witness.pub,pb.endpoint,confirmation,file,locator,Now()),"PUT pending confirmation");
    Check(pa.Send(pb.endpoint,packet.bytes.data(),packet.size),"PUT send");
    auto received=ReceiveFrom(pb,pa.endpoint); Header verified; ese::discovery::PutView publication;
    std::array<std::uint8_t,32> digest{};
    Check(AdmitDescriptorPut(sessions,pa.endpoint,publisher.pub,received.bytes.data(),received.size,Now(),verified,publication,digest),"PUT session admission");
    Check(publication.file==file && digest==locator.digest && publication.length==968,"PUT identity/content");
    auto store=std::make_unique<ese::discovery::WitnessDescriptors<>>();
    DescriptorGetLimit<> limit(processBudget);
    Check(store->PutVerified(file,publication.descriptor,publication.length,digest,pa.endpoint,0,Now())==ese::discovery::StoreResult::Provisional,"W provisional storage");
    Check(!store->Get(file,publisher.pub,digest,Now()).bytes,"provisional cannot answer GET");
    ese::discovery::DirectSource directSource; directSource.file=file; directSource.fileSize=123456;
    directSource.node=publisher.pub; directSource.digest=digest; directSource.generation=7;
    directSource.serial=1; directSource.ttl=120;
    constexpr std::uint64_t maxFileSize=0x4000000000ULL;
    std::array<std::uint8_t,173> sourceBytes{};
    Check(BuildDirectSource(directSource,maxFileSize,publisher,sourceBytes),"independent source signature");
    auto sourceHeader=bootstrap; sourceHeader.type=ese::wire::kEseWireUdpK6DirectPut; sourceHeader.sequence=3;
    Check(BuildDirectPut(sourceHeader,sourceBytes.data(),sourceBytes.size(),maxFileSize,publisher.pub,publisher,packet),"direct source PUT build");
    DirectPutRequest sourceRequest;
    Check(sourceRequest.Start(witness.pub,pb.endpoint,sourceHeader,directSource,maxFileSize,Now()),"source publication pending before send");
    Check(pa.Send(pb.endpoint,packet.bytes.data(),packet.size),"direct source PUT send without waiting DESC_RESULT");
    received=ReceiveFrom(pb,pa.endpoint); ese::discovery::DirectSource admittedSource; Envelope sourceEnvelope;
    Check(AdmitDirectPut(sessions,limit,pa.endpoint,publisher.pub,received.bytes.data(),received.size,maxFileSize,Now(),verified,admittedSource),"direct source session/rate admission");
    Check(ParseUntrusted(received.bytes.data(),received.size,sourceEnvelope),"direct source envelope");
    Check(store->DirectSourceVerified(sourceEnvelope.payload,173,maxFileSize,Now())==ese::discovery::SourceStoreResult::Stored,"coherent source promotes descriptor");
    Check(BuildDirectPutResult(sourceHeader,0,admittedSource,maxFileSize,witness.pub,witness,packet) && packet.size==209,"STORED result build");
    Check(pb.Send(pa.endpoint,packet.bytes.data(),packet.size),"STORED result send");
    received=ReceiveFrom(pa,pb.endpoint); std::uint8_t sourceStatus=255;
    Check(sourceRequest.Receive(pb.endpoint,received.bytes.data(),received.size,Now(),sourceStatus) && sourceStatus==0,"STORED pending signed correlation");
    Check(!sourceRequest.Receive(pb.endpoint,received.bytes.data(),received.size,Now(),sourceStatus) && sourceStatus==255,"STORED replay consumed");
    ese::discovery::FoundSources found;
    Check(store->Find(file,directSource.fileSize,4,Now(),found) && found.count==1 && found.records[0]==sourceBytes,"direct source index lookup");
    auto stored=store->Get(file,publisher.pub,digest,Now());
    Check(stored.size==968 && store->ChargedBytes()<=8*1024*1024,"W owned descriptor/budget");
    Check(BuildDescriptorResult(confirmation,0,file,locator,stored.bytes,stored.size,witness.pub,witness,packet),"PUT confirmation build");
    Check(pb.Send(pa.endpoint,packet.bytes.data(),packet.size),"PUT confirmation send");
    received=ReceiveFrom(pa,pb.endpoint); ese::discovery::ResultView confirmed;
    Check(publicationRequest.Receive(pb.endpoint,received.bytes.data(),received.size,Now(),confirmed) && confirmed.status==0,"PUT confirmed before locator");
    ese::discovery::DirectFind lookup; lookup.requester=requester.pub; lookup.file=file;
    lookup.fileSize=directSource.fileSize; lookup.maximum=4;
    auto findHeader=requesterHeader; findHeader.type=ese::wire::kEseWireUdpK6DirectFind; findHeader.sequence=2;
    Check(BuildDirectFind(findHeader,lookup,maxFileSize,requester,packet),"A FIND build without B session");
    std::array<std::uint8_t,32> findDigest{};
    Check(DirectFindDigest(requester.pub,packet.bytes.data(),packet.size,maxFileSize,findDigest),"A FIND digest");
    DirectFindRequest findRequest;
    Check(findRequest.Start(witness.pub,pb.endpoint,findHeader,lookup,findDigest,maxFileSize,Now()),"A FIND pending before send");
    Check(pc.Send(pb.endpoint,packet.bytes.data(),packet.size),"A FIND send");
    received=ReceiveFrom(pb,pc.endpoint); ese::discovery::DirectFind admittedFind;
    Check(AdmitDirectFind(sessions,limit,pc.endpoint,requester.pub,received.bytes.data(),received.size,maxFileSize,Now(),verified,admittedFind),"W FIND session admission");
    Check(store->Find(admittedFind.file,admittedFind.fileSize,admittedFind.maximum,Now(),found) && found.count==1,"W FIND source index");
    std::array<ese::discovery::FindEntryView,4> entries{};
    for(std::size_t i=0;i<found.count;++i) entries[i]={found.records[i].data(),173,found.remainingTtl[i]};
    Check(BuildDirectFindSourcesResult(verified,admittedFind,findDigest,entries,static_cast<std::uint8_t>(found.count),maxFileSize,witness.pub,witness,packet),"W FIND result build");
    Check(pb.Send(pc.endpoint,packet.bytes.data(),packet.size),"W FIND result send");
    received=ReceiveFrom(pc,pb.endpoint); ese::discovery::FindResultView foundResult;
    Check(findRequest.Receive(pb.endpoint,received.bytes.data(),received.size,Now(),foundResult) && foundResult.count==1,"A pending W/B signatures FIND result");
    ese::discovery::DirectSource discovered;
    Check(ese::discovery::DecodeSource(foundResult.entries[0].bytes,173,maxFileSize,discovered),"A discovered source");
    locator.node=discovered.node; locator.digest=discovered.digest; locator.serial=discovered.serial; locator.ttl=foundResult.entries[0].remainingTtl;
    std::array<std::uint8_t,77> locatorBytes{};
    Check(ese::discovery::EncodeLocator(locator,locatorBytes) && ese::discovery::DecodeLocator(locatorBytes.data(),locatorBytes.size(),locator),"locator handoff codec (not Kad)");
    header=requesterHeader; header.type=ese::wire::kEseWireUdpDescriptorGet; header.sequence=3;
    Check(BuildDescriptorGet(header,file,locator,requester.pub,requester,packet),"GET build");
    auto expected=header; expected.type=ese::wire::kEseWireUdpDescriptorResult;
    DescriptorRequest request; Check(request.Start(witness.pub,pb.endpoint,expected,file,locator,Now()),"GET pending");
    Check(pc.Send(pb.endpoint,packet.bytes.data(),packet.size),"GET send");
    received=ReceiveFrom(pb,pc.endpoint); ese::discovery::GetView query;
    Check(AdmitDescriptorGet(sessions,limit,pc.endpoint,requester.pub,received.bytes.data(),received.size,Now(),verified,query),"GET session admission");
    Check(query.file==file && query.node==locator.node && query.digest==locator.digest,"GET lookup identity");
    stored=store->Get(query.file,query.node,query.digest,Now());
    Check(stored.size==968,"W GET lookup");
    Check(BuildDescriptorResult(expected,0,file,locator,stored.bytes,stored.size,witness.pub,witness,packet) && packet.size==1155,"maximum RESULT build");
    Check(pb.Send(pc.endpoint,packet.bytes.data(),packet.size),"RESULT send");
    received=ReceiveFrom(pc,pb.endpoint); ese::discovery::ResultView result;
    Check(request.Receive(pb.endpoint,received.bytes.data(),received.size,Now(),result) && result.length==968 &&
        !std::memcmp(result.descriptor,descriptor.data(),descriptor.size()),"RESULT double signature/correlation/content");
    Check(!request.Receive(pb.endpoint,received.bytes.data(),received.size,Now(),result),"RESULT replay consumed");
    const auto oldDigest=locator.digest;
    descriptor[24]=2;
    Check(ese::discovery::BuildSignatureInput(descriptor.data(),descriptor.size(),signedInput) &&
        publisher.Sign(signedInput.bytes.data(),signedInput.size,signature),"replacement descriptor sign");
    std::memcpy(descriptor.data()+descriptor.size()-64,signature.data(),64);
    locator.serial=2; Check(DescriptorDigest(descriptor.data(),descriptor.size(),locator.digest),"replacement digest");
    auto replaceHeader=bootstrap; replaceHeader.type=ese::wire::kEseWireUdpDescriptorPut; replaceHeader.sequence=4;
    Check(BuildDescriptorPut(replaceHeader,file,descriptor.data(),descriptor.size(),publisher.pub,publisher,packet),"replacement PUT build");
    Check(pa.Send(pb.endpoint,packet.bytes.data(),packet.size),"replacement PUT send");
    received=ReceiveFrom(pb,pa.endpoint);
    Check(AdmitDescriptorPut(sessions,pa.endpoint,publisher.pub,received.bytes.data(),received.size,Now(),verified,publication,digest),"replacement PUT admit");
    Check(store->PutVerified(file,publication.descriptor,publication.length,digest,pa.endpoint,0,Now())==ese::discovery::StoreResult::Provisional,"replacement stage");
    Check(store->Get(file,publisher.pub,oldDigest,Now()).size==968 && !store->Get(file,publisher.pub,locator.digest,Now()).bytes,"old publication survives UDP staging");
    directSource.serial=2; directSource.digest=locator.digest;
    Check(BuildDirectSource(directSource,maxFileSize,publisher,sourceBytes),"replacement source sign");
    sourceHeader.sequence=5;
    Check(BuildDirectPut(sourceHeader,sourceBytes.data(),sourceBytes.size(),maxFileSize,publisher.pub,publisher,packet),"replacement source PUT build");
    // Respect the real publication 1/s limiter; stage wait remains <=5s.
    const auto publishAfter=Now()+1000; while(Now()<publishAfter) std::this_thread::yield();
    Check(pa.Send(pb.endpoint,packet.bytes.data(),packet.size),"replacement source PUT send");
    received=ReceiveFrom(pb,pa.endpoint);
    Check(AdmitDirectPut(sessions,limit,pa.endpoint,publisher.pub,received.bytes.data(),received.size,maxFileSize,Now(),verified,admittedSource),"replacement source admit/rate");
    Check(ParseUntrusted(received.bytes.data(),received.size,sourceEnvelope) &&
        store->DirectSourceVerified(sourceEnvelope.payload,173,maxFileSize,Now())==ese::discovery::SourceStoreResult::Stored,"replacement pair atomic commit");
    Check(!store->Get(file,publisher.pub,oldDigest,Now()).bytes && store->Get(file,publisher.pub,locator.digest,Now()).size==968,"new publication visible after UDP commit");
    Check(store->Find(file,directSource.fileSize,4,Now(),found) && found.count==1 && found.records[0]==sourceBytes,"FIND switches to new signed record");
    std::printf("Descriptor UDP A/B/W PUT/source STORED/FIND/GET PASS: A discovers B from signed W FIND_RESULT then retrieves exact968B; no Kad contact lookup/ticket validation\n");
}
int main(int argc,char** argv) {
    WSADATA data{}; if(WSAStartup(MAKEWORD(2,2),&data)) return 1;
    struct Cleanup { ~Cleanup() { WSACleanup(); } } cleanup;
    try {
        const bool loseChallenge=argc>1 && std::strcmp(argv[1],"loss-challenge")==0;
        const bool loseAck=argc>1 && std::strcmp(argv[1],"loss-ack")==0;
        const bool badAck=argc>1 && std::strcmp(argv[1],"bad-ack")==0;
        Identity a,b; Port pa,pb; CookieAuthority authority; PacketBudget processBudget;
        ChallengeLimit limit(processBudget); Sessions sessions;
        Check(authority.Initialize(),"cookie secret");
        Header header; header.type=1; header.generation=7; header.sequence=1; header.attempt.fill(0x28);
        Probe probe; probe.node=a.pub; probe.peer=b.pub; probe.nonce.fill(0x36); probe.mask=0;
        Initiator initiator; const auto start=Now(),deadline=start+(badAck ? 2000 : 8000);
        Check(initiator.Start(header,probe,pb.endpoint,start,deadline),"initiator start");
        unsigned challenges=0,acks=0,adoptions=0,duplicates=0,sends=0,dropped=0;
        unsigned rejectedAcks=0;
        while(Now()<deadline && initiator.State()!=InitiatorState::Ready && initiator.State()!=InitiatorState::Failed) {
            const auto now=Now(); const auto pending=initiator.Pending(now);
            if(pending.size && pa.Send(pb.endpoint,pending.data,pending.size)) { Check(initiator.Submitted(now),"submission"); ++sends; }
            Datagram packet,response; ese::udp::Endpoint source;
            for(unsigned i=0;i<16 && pb.Receive(packet,source);++i) {
                Check(source==pa.endpoint,"responder source"); Envelope envelope;
                Check(ParseUntrusted(packet.bytes.data(),packet.size,envelope),"envelope");
                if(envelope.header.type==1) {
                    Check(BuildChallenge(authority,limit,source,b.pub,a.pub,packet.bytes.data(),packet.size,now,response),"challenge");
                    ++challenges;
                    if(loseChallenge && challenges==1) { ++dropped; continue; }
                } else {
                    Check(envelope.header.type==3,"expected PROVE"); Prove proof;
                    const auto admission=AdmitProve(authority,sessions,source,b.pub,a.pub,packet.bytes.data(),packet.size,now,proof);
                    Check(admission==Admission::Accepted || admission==Admission::Duplicate,"admit PROVE");
                    if(admission==Admission::Accepted) ++adoptions; else ++duplicates;
                    Check(BuildAck(proof,envelope.header,0,b.pub,b,response),"signed ACK"); ++acks;
                    if(badAck) response.bytes[response.size-1]^=1;
                    if(loseAck && acks==1) { ++dropped; continue; }
                }
                Check(pb.Send(source,response.bytes.data(),response.size),"response send");
            }
            for(unsigned i=0;i<16 && pa.Receive(packet,source);++i) {
                Envelope envelope; Check(ParseUntrusted(packet.bytes.data(),packet.size,envelope),"response envelope");
                if(envelope.header.type==2) Check(initiator.ChallengeReceived(source,packet.bytes.data(),packet.size,now,a),"challenge correlation");
                else {
                    const bool accepted=initiator.AckReceived(source,packet.bytes.data(),packet.size,now);
                    if(badAck) { Check(!accepted,"forged ACK accepted"); ++rejectedAcks; }
                    else Check(accepted,"ACK correlation");
                }
            }
            std::this_thread::yield();
        }
        if(badAck) {
            initiator.Pending(deadline);
            Check(initiator.State()==InitiatorState::Failed && initiator.Selected()==0 && adoptions==1,"bad ACK must time out without ready");
            Check(rejectedAcks==3 && duplicates==2 && sends==4,"bad ACK bounded retries and no readoption");
        } else Check(initiator.State()==InitiatorState::Ready && initiator.Selected()==0 && adoptions==1,"control-only ready/adopt once");
        Check(!loseAck || duplicates>=1,"lost ACK replay idempotent");
        Check(!(loseAck || loseChallenge) || dropped==1,"loss injection");
        Check(sends<=6,"bounded transmissions");
        if(!badAck) DescriptorRoundtrip(a,b,pa,pb,sessions,header,authority,limit,processBudget);
        std::printf("Control/1 UDP [%s] PASS: real Ed25519/HMAC, control-only, sends=%u adopted=%u duplicates=%u rejectedACK=%u ready=%d; no QUIC expectation or eD2K identity credited\n",argc>1 ? argv[1] : "clean",sends,adoptions,duplicates,rejectedAcks,initiator.State()==InitiatorState::Ready);
        return 0;
    } catch(const std::exception& error) { std::printf("FAIL: %s\n",error.what()); return 1; }
}
