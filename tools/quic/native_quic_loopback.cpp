#include <winsock2.h>
#include <ws2tcpip.h>
#include "../../srchybrid/EseNativeQuicRuntime.h"
#include "../../srchybrid/LiveCrypto.h"
#include "../../srchybrid/NodeIdentity.h"
#include "../../srchybrid/EseQuicHeaderProbe.h"
#include "../../srchybrid/EseQuicUdpRouter.h"
#include "../../srchybrid/EseQuicSocketOwner.h"
#include "../../srchybrid/EseQuicHostFactory.h"
#include "../../srchybrid/EseQuicHostStart.h"
#include "../../srchybrid/EseQuicEd2kWriter.h"
#include "../../srchybrid/EsePeerTrustStore.h"
#include "SimulatedQuicPort.h"
#include "../../srchybrid/EseControlInitiatorHost.h"
#include <chrono>
#include <cstring>
#include <algorithm>
#include <cstdio>
#include <stdexcept>
#include <thread>
// This fixture uses explicit ephemeral identities, never production persistence.
namespace eSELive {
bool NodeIdentityIsPersistent() { return false; }
bool NodeIdentitySign(const std::uint8_t*,std::size_t,std::uint8_t sig[64]) { (void)sig; return false; }
}
using namespace ese;
using namespace reach;
static void Check(bool b,const char* message) { if(!b) throw std::runtime_error(message); }
static std::uint64_t Now() {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}
struct Identity final : QuicIdentitySigner {
    std::array<std::uint8_t,32> pub{},priv{};
    bool corrupt=false;
    Identity() { Check(eSELive::GenerateBroadcasterKeypair(pub.data(),priv.data()),"keypair"); }
    bool Sign(const std::uint8_t* p,std::size_t n,std::uint8_t* sig) noexcept override {
        const bool ok=eSELive::SignMessage(priv.data(),pub.data(),p,n,sig);
        if(ok && corrupt) sig[0]^=1;
        return ok;
    }
};
struct Probe final : udp::Inspector {
    udp::Match Control(const std::uint8_t*,std::size_t,const udp::Endpoint&,std::uint64_t&) const noexcept override { return udp::Match::None; }
    udp::Match Utp(const std::uint8_t*,std::size_t,const udp::Endpoint&,std::uint64_t&) const noexcept override { return udp::Match::None; }
    bool QuicHeader(const std::uint8_t* p,std::size_t n,std::size_t length,udp::Header& out) const noexcept override {
        return udp::DecodeQuicHeader(p,n,length,out);
    }
    bool AcceptInitial(const std::uint8_t* p,std::size_t n) const noexcept override { return udp::AcceptQuicInitial(p,n); }
};
struct Port final : QuicSocketPort {
    SOCKET socket=INVALID_SOCKET; udp::Endpoint endpoint;
    bool loss=false,block=false,failSend=false;
    unsigned sends=0,retries=0,drops=0;
    std::vector<std::uint8_t> blocked;
    Probe probe; QuicUdpIngress* ingress=nullptr;
    unsigned classified=0,initials=0;
    Port() {
        socket=::socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP); Check(socket!=INVALID_SOCKET,"socket");
        sockaddr_in address{}; address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        Check(bind(socket,reinterpret_cast<sockaddr*>(&address),sizeof(address))==0,"bind");
        int size=sizeof(address); Check(getsockname(socket,reinterpret_cast<sockaddr*>(&address),&size)==0,"name");
        endpoint.address[0]=127; endpoint.address[3]=1; endpoint.port=ntohs(address.sin_port);
        u_long nonblock=1; Check(ioctlsocket(socket,FIONBIO,&nonblock)==0,"nonblock");
        int buffer=4*1024*1024;
        Check(setsockopt(socket,SOL_SOCKET,SO_RCVBUF,reinterpret_cast<char*>(&buffer),sizeof(buffer))==0,"buffer");
    }
    ~Port() { if(ingress) { auto* old=ingress; ingress=nullptr; old->SocketReset(); } if(socket!=INVALID_SOCKET) closesocket(socket); }
    bool AttachQuicIngress(QuicUdpIngress* owner) override { if(!owner || ingress) return false; ingress=owner; return true; }
    bool DetachQuicIngress(QuicUdpIngress* owner) override {
        if(!owner || ingress!=owner) return false;
        ingress=nullptr; owner->SocketReset(); return true;
    }
    QuicUdpSendResult SendQuicDatagram(QuicUdpIngress* owner,const udp::Endpoint& peer,const std::uint8_t* bytes,std::size_t size) override {
        if(owner!=ingress || !size || size>1200) return {QuicUdpSendStatus::Invalid,0};
        if(failSend) return {QuicUdpSendStatus::Failed,WSAENETUNREACH};
        return Send(peer,{bytes,size}) ? QuicUdpSendResult{QuicUdpSendStatus::Sent,0} :
            QuicUdpSendResult{QuicUdpSendStatus::WouldBlock,WSAEWOULDBLOCK};
    }
    bool Send(const udp::Endpoint& peer,DirectByteView p) noexcept {
        if(!blocked.empty()) {
            if(blocked.size()!=p.size || std::memcmp(blocked.data(),p.data,p.size)) std::abort();
            blocked.clear(); ++retries;
        } else if(block && sends%7==0) {
            try { blocked.assign(p.data,p.data+p.size); } catch(...) { std::abort(); }
            ++sends; return false;
        }
        ++sends;
        if(loss && sends%10==0) { ++drops; return true; }
        sockaddr_in address{}; address.sin_family=AF_INET; address.sin_port=htons(peer.port);
        std::memcpy(&address.sin_addr,peer.address.data(),4);
        return sendto(socket,reinterpret_cast<const char*>(p.data),static_cast<int>(p.size),0,
            reinterpret_cast<sockaddr*>(&address),sizeof(address))==static_cast<int>(p.size);
    }
    void Deliver(QuicSocketOwner& owner) {
        std::array<std::uint8_t,65536> packet{};
        for(unsigned i=0;i<128;++i) {
            sockaddr_in source{}; int size=sizeof(source);
            int n=recvfrom(socket,reinterpret_cast<char*>(packet.data()),static_cast<int>(packet.size()),0,
                reinterpret_cast<sockaddr*>(&source),&size);
            if(n<0) { Check(WSAGetLastError()==WSAEWOULDBLOCK,"recvfrom"); break; }
            udp::Endpoint peer; std::memcpy(peer.address.data(),&source.sin_addr,4); peer.port=ntohs(source.sin_port);
            const auto decision=owner.Classify(peer,{packet.data(),static_cast<std::size_t>(n)},Now());
            Check(decision.channel==udp::Channel::Quic && decision.owner==1 && owner.Current(decision),"QUIC demux");
            ++classified;
            if(decision.newInitial) {
                ++initials;
                auto wrong=peer; ++wrong.port;
                Check(owner.Classify(wrong,{packet.data(),static_cast<std::size_t>(n)},Now()).channel==udp::Channel::Legacy,
                    "unexpected endpoint must not claim Initial");
            }
            Check(ingress && ingress->Receive(peer,{packet.data(),static_cast<std::size_t>(n)}),"registered ingress datagram claim");
        }
    }
};
static QuicPeerConfig Config(const Identity& local,const Identity& peer,bool server) {
    QuicPeerConfig c; c.local.role=server ? 1 : 0; c.local.node=local.pub;
    c.local.nonce.fill(server ? 5 : 4); c.local.attempt.fill(3); c.local.caps=1;
    c.local.topologyGeneration=7; c.expectedNode=peer.pub; c.pin=peer.pub;
    c.hasPin=true; c.persistent=true; c.sessionEpoch=0; return c;
}
static DirectSessionRoute Route(const Port& peer) {
    DirectSessionRoute r; r.id=3; r.transport=DirectQuic; r.candidate.family=4;
    r.candidate.address=peer.endpoint.address; r.candidate.port=peer.endpoint.port;
    r.candidate.transport_mask=DirectQuic; r.candidate.topology_generation=7;
    r.candidate.expires_monotonic_ms=Now()+30000; return r;
}
// Actual native TLS/exporter/Ed25519 over a memory-only datagram namespace.
// Logical globally shaped addresses are NOT physical return-path evidence.
static void RunSimulatedNative() {
    struct State { DirectBufferPool pool; DirectEventQueue events; };
    auto state=std::make_unique<State>();
    Identity a,b; Probe probe;
    udp::Endpoint ea,eb; ea.address[0]=8; ea.address[3]=1; ea.port=41001;
    eb.address[0]=9; eb.address[3]=1; eb.port=41002;
    test::SimulatedQuicPort pa(ea),pb(eb);
    Check(pa.Link(pb),"simulated native link");
    {
        control::PacketBudget ba,bb;
        auto ha=CreateQuicSessionHost(pa,state->pool,state->events,ba);
        auto hb=CreateQuicSessionHost(pb,state->pool,state->events,bb);
        Check(ha && hb,"simulated control factory hosts");
        struct Signer final : control::Signer {
            Identity& identity;
            explicit Signer(Identity& value):identity(value) {}
            bool Sign(const std::uint8_t* p,std::size_t n,std::array<std::uint8_t,64>& sig) noexcept override {
                return identity.Sign(p,n,sig.data());
            }
        } sa(a),sb(b);
        auto sessions=std::make_unique<control::Sessions>();
        control::CookieAuthority authority; control::ChallengeLimit limit;
        Check(authority.Initialize(),"simulated cookie authority");
        const auto start=Now(),until=start+1500;
        control::Header header; header.type=wire::kEseWireUdpProbe;
        header.attempt=Config(a,b,false).local.attempt; header.generation=7; header.sequence=1;
        control::Probe request; request.node=a.pub; request.peer=b.pub; request.nonce.fill(11); request.mask=4;
        Check(hb->ExpectControlBootstrap(b.pub,a.pub,ea,42,until),"simulated responder expectation");
        control::InitiatorHost initiator(*ha);
        Check(initiator.Start(41,header,request,eb,start,until),"simulated initiator start");
        unsigned probes=0,proofs=0;
        while(Now()<until && initiator.State()!=control::InitiatorState::Ready) {
            initiator.Poll(Now()); pb.Deliver();
            QuicUdpRouter::PendingControl packet;
            while(hb->PopControlReply(packet)) {
                control::Envelope envelope; control::Datagram response;
                Check(packet.owner==42 && packet.peer==ea &&
                    control::ParseUntrusted(packet.bytes.data(),packet.size,envelope),"simulated responder owned packet");
                if(envelope.header.type==wire::kEseWireUdpProbe) {
                    ++probes;
                    Check(control::BuildChallenge(authority,limit,packet.peer,b.pub,a.pub,
                        packet.bytes.data(),packet.size,Now(),response),"simulated cookie challenge");
                } else {
                    ++proofs; control::Prove verified;
                    Check(control::AdmitProve(authority,*sessions,packet.peer,b.pub,a.pub,
                        packet.bytes.data(),packet.size,Now(),verified)==control::Admission::Accepted,"simulated signed PROVE");
                    Check(control::BuildAck(verified,envelope.header,4,b.pub,sb,response),"simulated signed ACK4");
                }
                Check(hb->SendControl(ea,{response.bytes.data(),response.size}).status==QuicUdpSendStatus::Sent,"simulated control response send");
            }
            pa.Deliver();
            while(ha->PopControlReply(packet)) Check(initiator.Receive(packet.owner,packet.peer,
                packet.bytes.data(),packet.size,Now(),sa),"simulated initiator verifies reply");
        }
        Check(probes==1 && proofs==1 && initiator.State()==control::InitiatorState::Ready &&
            initiator.Selected()==4 && ha->Empty() && hb->Empty(),"simulated ACK4 before QUIC session creation");
        initiator.Cancel();
        Check(initiator.Selected()==0,"simulated cancel revokes ACK4");
        ha->Stop(); hb->Stop(); state->events.Drain(); ha->Poll(Now()); hb->Poll(Now());
        Check(ha->Empty() && hb->Empty(),"simulated control host shutdown");
        std::printf("native control simulated namespace: cookie + signed PROVE/ACK4 via factory hosts PASS (not manager route grant)\n");
    }
    QuicSocketOwner oa(pa,probe,state->pool,state->events),ob(pb,probe,state->pool,state->events);
    Check(oa.Attach() && ob.Attach(),"simulated native attach");
    auto route=[](const udp::Endpoint& ep) {
        DirectSessionRoute r; r.id=3; r.transport=DirectQuic; r.candidate.family=4;
        r.candidate.address=ep.address; r.candidate.port=ep.port;
        r.candidate.transport_mask=DirectQuic; r.candidate.topology_generation=7;
        r.candidate.expires_monotonic_ms=Now()+30000; return r;
    };
    try {
        Check(oa.Begin({ea,false},Config(a,b,false),{0,1},route(eb),&a)==1 &&
            ob.Begin({eb,true},Config(b,a,true),{1,1},route(ea),&b)==1,"simulated native begin");
        auto& client=*oa.Find(1); auto& server=*ob.Find(1);
        const std::uint8_t early=1;
        Check(client.Send({&early,1}).status==DirectIoStatus::WouldBlock &&
            server.Send({&early,1}).status==DirectIoStatus::WouldBlock,"simulated pre-auth guard");
        const auto deadline=Now()+20000;
        bool adopted=false;
        std::array<std::uint8_t,4097> bytes{};
        for(std::size_t i=0;i<bytes.size();++i) bytes[i]=static_cast<std::uint8_t>(i%251);
        std::size_t sent=0,received=0;
        while(Now()<deadline) {
            pa.Deliver(); pb.Deliver(); oa.Poll(Now()); ob.Poll(Now());
            Check(!client.Snapshot().closed && !server.Snapshot().closed,"simulated unexpected close");
            if(!adopted && client.Ready() && server.Ready()) {
                Check(client.AdoptWinner({0,1},3,1) && server.AdoptWinner({1,1},3,1),"simulated bound winner");
                adopted=true;
            }
            if(adopted && sent<bytes.size()) {
                const auto result=client.Send({bytes.data()+sent,bytes.size()-sent});
                Check(result.status==DirectIoStatus::Accepted || result.status==DirectIoStatus::WouldBlock,"simulated send");
                sent+=result.accepted;
            }
            const auto data=server.ReceivedFront();
            Check(data.size<=bytes.size()-received,"simulated receive bounds");
            for(std::size_t i=0;i<data.size;++i) Check(data.data[i]==bytes[received+i],"simulated exact payload");
            received+=data.size; Check(server.ConsumeReceived(data.size),"simulated consume");
            if(received==bytes.size() && client.Snapshot().acknowledged_offset==bytes.size()) break;
            std::this_thread::yield();
        }
        Check(adopted && sent==bytes.size() && received==bytes.size() &&
            client.Snapshot().acknowledged_offset==bytes.size(),"simulated native transfer deadline");
        Check(pa.Unclaimed()==0 && pb.Unclaimed()==0,"simulated native all packets claimed");
        client.Close(DirectReason::Disabled); server.Close(DirectReason::Disabled);
        state->events.Drain(); oa.Poll(Now()); ob.Poll(Now());
        Check(oa.RetireClosed()==1 && ob.RetireClosed()==1 && state->pool.Used()==0,"simulated native retirement");
        Check(oa.Detach() && ob.Detach() && pa.Queued()==0 && pb.Queued()==0,"simulated native detach");
        std::printf("native QUIC simulated namespace: real TLS/exporter/Ed25519, 4097 exact bytes + ACK, pool drained PASS (no physical UDP/NAT; no MFC scheduler)\n");
    } catch(...) {
        oa.Stop(); ob.Stop(); state->events.Drain(); oa.Poll(Now()); ob.Poll(Now());
        oa.RetireClosed(); ob.RetireClosed(); throw;
    }
}
int main(int argc,char** argv) {
    WSADATA winsock{}; if(WSAStartup(MAKEWORD(2,2),&winsock)) return 1;
    struct WinsockLifetime { ~WinsockLifetime() { WSACleanup(); } } winsockLifetime;
    int result=1;
    try {
        if(argc>1 && std::strcmp(argv[1],"simulated")==0) { RunSimulatedNative(); return 0; }
        // Keep bounded registry/mailbox storage off the caller's stack. The
        // simulated branch has its own owner frame; growing scalar snapshots
        // must not make their combined frames exceed the Windows stack reserve.
        struct ClientDcoState { DirectBufferPool pool; DirectEventQueue events; DirectCoordinator coordinator; };
        auto clientDco=std::make_unique<ClientDcoState>();
        auto& pool=clientDco->pool; auto& events=clientDco->events;
        Identity a,b; Port pa,pb;
        {
            const auto peer=Config(a,b,false); const auto route=Route(pb);
            DirectCoordinatorSnapshot attempt; attempt.peer.domain=DirectPeerDomain::NodePublicKey;
            attempt.peer.identity=b.pub; attempt.attempt_id=peer.local.attempt;
            attempt.epoch=0; attempt.state=DirectSessionState::Connecting;
            QuicHostStartContext host{a.pub,7,Now(),pa.endpoint.port,true};
            const NativeQuicConfig native{pa.endpoint,false};
            Check(ValidQuicHostStart(native,peer,route,attempt,host),"host Start guard valid");
            auto authenticating=attempt; authenticating.state=DirectSessionState::Authenticating;
            Check(ValidQuicHostStart(native,peer,route,authenticating,host),"parallel Start while another route authenticates");
            auto stale=host; ++stale.topology;
            Check(!ValidQuicHostStart(native,peer,route,attempt,stale),"host Start stale topology");
            stale=host; stale.persistent=false;
            Check(!ValidQuicHostStart(native,peer,route,attempt,stale),"host Start volatile identity");
            stale=host; ++stale.boundPort;
            Check(!ValidQuicHostStart(native,peer,route,attempt,stale),"host Start wrong port");
            auto bad=peer; bad.local.node[0]^=1;
            Check(!ValidQuicHostStart(native,bad,route,attempt,host),"host Start wrong local node");
            bad=peer; bad.local.attempt[0]^=1;
            Check(!ValidQuicHostStart(native,bad,route,attempt,host),"host Start wrong attempt");
            bad=peer; ++bad.sessionEpoch;
            Check(!ValidQuicHostStart(native,bad,route,attempt,host),"host Start wrong epoch");
            bad=peer; bad.pin[0]^=1;
            Check(!ValidQuicHostStart(native,bad,route,attempt,host),"host Start pin mismatch");
            auto closed=attempt; closed.state=DirectSessionState::Cancelled;
            Check(!ValidQuicHostStart(native,peer,route,closed,host),"host Start cancelled attempt");
        }
        {
            control::PacketBudget processBudget;
            auto host=CreateQuicSessionHost(pa,pool,events,processBudget);
            Check(host && host->Empty() && pa.ingress,"native host factory attaches");
            Check(!CreateQuicSessionHost(pa,pool,events,processBudget),"native host factory rejects occupied socket");
            control::Header request; request.type=24; request.attempt[0]=1;
            request.generation=2; request.sequence=3;
            auto reply=request; reply.type=25; control::Datagram packet;
            Check(control::Encode(reply,nullptr,0,packet),"control fixture envelope");
            QuicUdpRouter::PendingControl queued;
            Check(pa.ingress->Receive(pb.endpoint,{packet.bytes.data(),packet.size}) &&
                !host->PopControlReply(queued),"unsolicited control claimed without queue");
            Check(host->ExpectControlReply(request,25,pb.endpoint,99,Now()+2000),"register control expectation");
            auto wrong=pb.endpoint; ++wrong.port;
            Check(pa.ingress->Receive(wrong,{packet.bytes.data(),packet.size}) &&
                !host->PopControlReply(queued),"wrong control endpoint dropped");
            Check(pa.ingress->Receive(pb.endpoint,{packet.bytes.data(),packet.size}) &&
                host->PopControlReply(queued) && queued.owner==99 && queued.peer==pb.endpoint &&
                queued.size==packet.size,"matching control owned queue, not authenticated");
            Check(pa.ingress->Receive(pb.endpoint,{packet.bytes.data(),packet.size}),"enqueue before cancel");
            host->RemoveControlReplies(99);
            Check(!host->PopControlReply(queued),"cancel purges already queued response");
            Check(pa.ingress->Receive(pb.endpoint,{packet.bytes.data(),packet.size}) &&
                !host->PopControlReply(queued),"cancelled control expectation dropped");
            auto invalid=Route(pb); invalid.candidate.port=0;
            Check(host->Begin({pa.endpoint,false},Config(a,b,false),{0,1},invalid)==0 &&
                host->Empty(),"factory invalid Begin cleans owner");
            const auto budgetStart=Now();
            for(unsigned i=0;i<100;++i) Check(processBudget.Allow(budgetStart),"charge shared process budget");
            Check(host->SendControl(pb.endpoint,{packet.bytes.data(),packet.size}).status==QuicUdpSendStatus::WouldBlock,
                "factory cannot bypass process quota");
            host->Stop(); host->Stop(); host->Poll(Now());
            Check(!pa.ingress && host->Empty() && host->RetireClosed()==0 &&
                pool.Used()==0,"factory stop detach and cleanup");
            host.reset();
            host=CreateQuicSessionHost(pa,pool,events,processBudget);
            Check(host && host->SendControl(pb.endpoint,{packet.bytes.data(),packet.size}).status==QuicUdpSendStatus::WouldBlock,
                "factory restart preserves process quota");
            host->Stop();
        }
        const bool pause=argc>1 && std::strcmp(argv[1],"pause")==0;
        const bool serverOnly=argc>1 && std::strcmp(argv[1],"server-only")==0;
        const bool badAuth=argc>1 && std::strcmp(argv[1],"bad-auth")==0;
        const bool sendFail=argc>1 && std::strcmp(argv[1],"send-fail")==0;
        const bool tofu=argc>1 && std::strcmp(argv[1],"tofu")==0;
        const bool tofuFail=argc>1 && std::strcmp(argv[1],"tofu-fail")==0;
        struct TrustProfile {
            std::wstring directory,path,temporary;
            bool created=false;
            ~TrustProfile() {
                if(created) {
                    DeleteFileW(path.c_str()); DeleteFileW(temporary.c_str());
                    RemoveDirectoryW(directory.c_str());
                }
            }
        } trustProfile;
        auto clientConfig=Config(a,b,false);
        if(tofu || tofuFail) {
            wchar_t base[MAX_PATH]{};
            Check(GetTempPathW(MAX_PATH,base)>0,"trust temp root");
            trustProfile.directory=std::wstring(base)+L"ese-native-tofu-"+std::to_wstring(GetCurrentProcessId())+L"-"+std::to_wstring(GetTickCount64());
            Check(CreateDirectoryW(trustProfile.directory.c_str(),nullptr)!=FALSE,"private trust profile");
            trustProfile.created=true;
            trustProfile.path=trustProfile.directory+L"/peer.trust";
            trustProfile.temporary=trustProfile.directory+L"/peer.new";
            if(tofuFail) {
                HANDLE collision=CreateFileW(trustProfile.temporary.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
                Check(collision!=INVALID_HANDLE_VALUE && CloseHandle(collision),"owned fixture blocks temporary publication");
            }
            clientConfig.hasPin=false; clientConfig.pin={}; clientConfig.allowFirstUse=true;
            clientConfig.trustCommitter=std::make_shared<trust::FileCommitter>(trustProfile.path,trustProfile.temporary);
        }
        pa.failSend=sendFail;
        const bool reset=argc>1 && std::strcmp(argv[1],"reset")==0;
        if(argc>1 && std::strcmp(argv[1],"begin-fail")==0) {
            QuicSocketOwner owner(pa,pa.probe,pool,events);
            auto route=Route(pb);
            Check(owner.Begin({pa.endpoint,true},Config(a,b,true),{0,1},route,&a)==0,"unattached begin rejection");
            Check(owner.Attach() && !owner.Attach(),"single ingress attachment");
            auto invalid=route; invalid.candidate.port=0;
            Check(owner.Begin({pa.endpoint,false},Config(a,b,false),{0,1},invalid,&a)==0,"invalid route release");
            const auto retained=owner.Begin({pa.endpoint,true},Config(a,b,true),{0,1},route,&a);
            Check(retained!=0 && owner.Find(retained),"valid Initial expectation retained");
            for(unsigned i=0;i<256;++i)
                Check(owner.Begin({pa.endpoint,true},Config(a,b,true),{1,1},route,&a)==0,"duplicate Initial cleanup");
            auto another=route; ++another.candidate.port;
            auto noPort=pa.endpoint; noPort.port=0;
            Check(owner.Begin({noPort,true},Config(a,b,true),{1,1},another,&a)==0,"runtime Start failure cleanup");
            Check(owner.Find(retained) && pool.Used()==0,"original session unaffected by failures");
            Check(owner.Detach(),"failed begin detach");
            events.Drain(); owner.Poll(Now());
            auto& rx=owner.Find(retained)->RxPool();
            Check(rx.ReserveExact(1) && pool.Used()==1,"external frame reservation counted globally");
            Check(!owner.Release(retained) && owner.RetireClosed()==0 && owner.Find(retained),"retain session pool while frame borrows it");
            rx.Release(1);
            Check(owner.Release(retained) && !owner.Find(retained) && pool.Used()==0,"failure scenario release");
            std::printf("native QUIC socket owner begin failures: invalid route + 256 duplicate Initial + failed Start + release PASS\n");
            return 0;
        }
        b.corrupt=badAuth;
        pa.loss=pb.loss=argc>1 && std::strcmp(argv[1],"loss")==0;
        pa.block=pb.block=argc>1 && std::strcmp(argv[1],"block")==0;
        const bool dcoScenario=argc>1 && std::strcmp(argv[1],"dco")==0;
        struct ServerDcoState { DirectEventQueue events; DirectCoordinator coordinator; };
        auto serverDco=std::make_unique<ServerDcoState>();
        auto& serverEvents=serverDco->events;
        const DirectHandle serverHandle{dcoScenario ? 0u : 1u,1};
        QuicSocketOwner oa(pa,pa.probe,pool,events),ob(pb,pb.probe,pool,dcoScenario ? serverEvents : events);
        Check(oa.Attach() && ob.Attach(),"socket owner registration");
        auto& nativeCoordinator=clientDco->coordinator;
        auto& serverCoordinator=serverDco->coordinator;
        const auto clientRoute=Route(pb);
        const auto serverRoute=Route(pa);
        if(dcoScenario) {
            DirectPeerKey peer; peer.domain=DirectPeerDomain::NodePublicKey; peer.identity=b.pub;
            const auto request=nativeCoordinator.Request(peer,1,Config(a,b,false).local.attempt,7,Now());
            Check(request.status==DirectRequestStatus::Created && request.handle.slot==0 && request.handle.generation==1,"native DCO admission");
            const auto start=nativeCoordinator.SetRoutes(request.handle,{clientRoute},Now());
            Check(start.actions.size()==1 && start.actions[0].type==DirectActionType::Start &&
                nativeCoordinator.AuthorizesStart(request.handle,clientRoute,start.actions[0].session_epoch),"native DCO authorizes exact Start");
            peer.identity=a.pub;
            const auto serverRequest=serverCoordinator.Request(peer,1,Config(b,a,true).local.attempt,7,Now());
            Check(serverRequest.status==DirectRequestStatus::Created && serverRequest.handle.slot==serverHandle.slot
                && serverRequest.handle.generation==serverHandle.generation,"native server DCO admission");
            const auto serverStart=serverCoordinator.SetRoutes(serverRequest.handle,{serverRoute},Now());
            Check(serverStart.actions.size()==1 && serverStart.actions[0].type==DirectActionType::Start
                && serverCoordinator.AuthorizesStart(serverRequest.handle,serverRoute,serverStart.actions[0].session_epoch),"native server DCO authorizes exact Start");
        }
        try {
            Check(oa.Begin({pa.endpoint,false},clientConfig,{0,1},clientRoute,&a)==1 &&
                ob.Begin({pb.endpoint,true},Config(b,a,true),serverHandle,serverRoute,&b)==1,"native owner begin");
            auto& client=*oa.Find(1); auto& server=*ob.Find(1);
            auto forwardWriter=std::make_unique<QuicEd2kWriter>(client.TxPool());
            auto reverseWriter=std::make_unique<QuicEd2kWriter>(server.TxPool());
            client.SetReceiveBudget(4096); server.SetReceiveBudget(4096);
            const std::uint8_t early=1;
            Check(client.Send({&early,1}).status==DirectIoStatus::WouldBlock &&
                server.Send({&early,1}).status==DirectIoStatus::WouldBlock && pool.Used()==0,"pre-auth bulk forbidden");
            Check(!client.ReportUsefulBytes(1) && !server.ReportUsefulBytes(1),"pre-auth useful progress forbidden");
            const std::uint8_t unknown[]={0x40,1,2,3,4,5,6,7,8,9};
            Check(oa.Classify(pb.endpoint,{unknown,sizeof(unknown)},Now()).channel==udp::Channel::Legacy,
                "unknown fixed-bit packet must remain legacy");
            const auto deadline=Now()+20000;
            const std::size_t total=6*1024*1024;
            std::array<std::uint8_t,32768> data{};
            std::size_t sent=0,received=0,reverseSent=0,reverseReceived=0;
            const std::size_t forwardTotal=serverOnly ? 0 : total;
            std::uint64_t pausedAt=0; bool resumed=false,adopted=false;
            while(Now()<deadline) {
                pa.Deliver(oa); pb.Deliver(ob); oa.Poll(Now()); ob.Poll(Now());
                if((badAuth || sendFail || tofuFail) && client.Snapshot().closed) break;
                Check(!client.Snapshot().closed && !server.Snapshot().closed,"unexpected close");
                if(dcoScenario) {
                    const auto batch=nativeCoordinator.Advance({0,1},Now(),events.Drain());
                    for(const auto& action:batch.actions) if(action.type==DirectActionType::Attach) {
                        Check(action.route_id==3 && action.session_epoch==1 &&
                            client.AdoptWinner({0,1},action.route_id,action.session_epoch),"native DCO authenticated winner adoption");
                    }
                    const auto serverBatch=serverCoordinator.Advance(serverHandle,Now(),serverEvents.Drain());
                    for(const auto& action:serverBatch.actions) if(action.type==DirectActionType::Attach) {
                        Check(action.route_id==3 && action.session_epoch==1 &&
                            server.AdoptWinner(serverHandle,action.route_id,action.session_epoch),"native server DCO authenticated winner adoption");
                    }
                }
                if(!adopted && client.Ready() && server.Ready()) {
                    if(tofu) {
                        trust::Record persisted;
                        Check(trust::LoadRecord(trustProfile.path.c_str(),persisted)==trust::LoadResult::Loaded &&
                            persisted.node==b.pub && persisted.version==1 && persisted.kind==trust::Kind::Tofu,
                            "native TOFU durable record before winner/application bytes");
                        Check(sent==0 && reverseSent==0 && received==0 && reverseReceived==0,"native TOFU pre-commit zero bulk");
                    }
                    if(dcoScenario) {
                        const auto state=nativeCoordinator.Snapshot({0,1});
                        Check(state && state->winner==3 && state->epoch==1 && state->state==DirectSessionState::Ready,"native DCO READY before bulk");
                        const auto serverState=serverCoordinator.Snapshot(serverHandle);
                        Check(serverState && serverState->winner==3 && serverState->epoch==1
                            && serverState->state==DirectSessionState::Ready,"native server DCO READY before bulk");
                    } else Check(client.AdoptWinner({0,1},3,1),"native client winner epoch adoption");
                    if(!dcoScenario) Check(server.AdoptWinner(serverHandle,3,1),"native server winner epoch adoption");
                    adopted=true;
                }
                if(client.Ready() && server.Ready() && sent<forwardTotal) {
                    if(pause && !pausedAt) { pausedAt=Now(); server.SetReceiveBudget(0); }
                    if(!forwardWriter->Remaining()) {
                        const auto n=(std::min)(data.size(),forwardTotal-sent);
                        for(std::size_t i=0;i<n;++i) data[i]=static_cast<std::uint8_t>((sent+i)%251);
                        const auto queued=forwardWriter->Queue({data.data(),n});
                        Check(queued.status==DirectIoStatus::Accepted || queued.status==DirectIoStatus::WouldBlock,"forward writer queue");
                    }
                    sent+=forwardWriter->Flush(client,{0,1},3,1,data.size()).accepted;
                }
                if(client.Ready() && server.Ready() && reverseSent<total) {
                    if(!reverseWriter->Remaining()) {
                        const auto n=(std::min)(data.size(),total-reverseSent);
                        for(std::size_t i=0;i<n;++i) data[i]=static_cast<std::uint8_t>((reverseSent+i+17)%251);
                        const auto queued=reverseWriter->Queue({data.data(),n});
                        Check(queued.status==DirectIoStatus::Accepted || queued.status==DirectIoStatus::WouldBlock,"reverse writer queue");
                    }
                    reverseSent+=reverseWriter->Flush(server,serverHandle,3,1,data.size()).accepted;
                }
                const auto p=server.ReceivedFront();
                if(pause && pausedAt && !resumed) {
                    Check(p.size==0 && client.Snapshot().acknowledged_offset<=4096,"pause credit/receive");
                    if(Now()-pausedAt>=200) { server.SetReceiveBudget(4096); resumed=true; }
                }
                for(std::size_t i=0;i<p.size;++i) Check(p.data[i]==static_cast<std::uint8_t>((received+i)%251),"payload mismatch");
                received+=p.size; Check(server.ConsumeReceived(p.size),"consume");
                if(dcoScenario && p.size) Check(server.ReportUsefulBytes(p.size),"server application-checked payload progress");
                const auto reverse=client.ReceivedFront();
                for(std::size_t i=0;i<reverse.size;++i)
                    Check(reverse.data[i]==static_cast<std::uint8_t>((reverseReceived+i+17)%251),"reverse payload mismatch");
                reverseReceived+=reverse.size; Check(client.ConsumeReceived(reverse.size),"reverse consume");
                if(dcoScenario && reverse.size) Check(client.ReportUsefulBytes(reverse.size),"client application-checked payload progress");
                if(received==forwardTotal && reverseReceived==total && client.Snapshot().acknowledged_offset==forwardTotal &&
                    server.Snapshot().acknowledged_offset==total) break;
                // A 1 ms Windows sleep can round to a whole scheduler tick;
                // yield without throttling this deliberately tiny credit window.
                std::this_thread::yield();
            }
            if(badAuth || sendFail || tofuFail) {
                Check(client.Snapshot().closed && !client.Ready(),"bad AUTH closure");
                Check(sent==0 && reverseSent==0 && received==0 && reverseReceived==0,"bad AUTH zero application bytes");
                bool rejected=false;
                for(const auto& event:events.Drain()) {
                    if(tofuFail && event.handle.slot==0)
                        Check(event.type!=DirectEventType::Authenticated,"failed native TOFU emits no authentication grant");
                    if(event.handle.slot==0 && event.type==((badAuth || tofuFail) ? DirectEventType::AuthenticationFailed : DirectEventType::Closed) &&
                        event.reason==(tofuFail ? DirectReason::ResourceLimit : badAuth ? DirectReason::IdentityMismatch : DirectReason::DirectUnreachable)) rejected=true;
                }
                Check(rejected,"bad AUTH typed rejection");
                server.Close(DirectReason::Disabled); client.Poll(Now()); server.Poll(Now());
                Check(client.Retirable() && server.Retirable() && pool.Used()==0,"bad AUTH retirement");
                if(tofuFail) {
                    Check(GetFileAttributesW(trustProfile.path.c_str())==INVALID_FILE_ATTRIBUTES &&
                        GetFileAttributesW(trustProfile.temporary.c_str())!=INVALID_FILE_ATTRIBUTES,
                        "failed TOFU no record and foreign temporary preserved");
                }
                std::printf("native QUIC socket owner [%s]: zero application bytes, typed rejection, pool drained PASS\n",tofuFail ? "tofu-fail" : badAuth ? "bad-auth" : "send-fail");
            } else {
            if(sent!=forwardTotal || received!=forwardTotal || client.Snapshot().acknowledged_offset!=forwardTotal)
                std::printf("transfer state: sent=%zu received=%zu ACK=%llu ready=%d/%d pool=%zu\n",
                    sent,received,static_cast<unsigned long long>(client.Snapshot().acknowledged_offset),
                    client.Ready(),server.Ready(),pool.Used());
            Check(sent==forwardTotal && received==forwardTotal && client.Snapshot().acknowledged_offset==forwardTotal,"transfer deadline");
            Check(reverseSent==total && reverseReceived==total && server.Snapshot().acknowledged_offset==total,"reverse deadline");
            if(dcoScenario) {
                nativeCoordinator.Advance({0,1},Now(),events.Drain());
                serverCoordinator.Advance(serverHandle,Now(),serverEvents.Drain());
                const auto clientState=nativeCoordinator.Snapshot({0,1});
                const auto serverState=serverCoordinator.Snapshot(serverHandle);
                Check(clientState && serverState && clientState->state==DirectSessionState::Transferring
                    && serverState->state==DirectSessionState::Transferring && clientState->useful_bytes==total
                    && serverState->useful_bytes==forwardTotal && !clientState->transfer_verified
                    && !serverState->transfer_verified,"application progress is not verified-part integrity");
                Check(!client.ReportUsefulBytes(1) && !server.ReportUsefulBytes(1),"no double-counted consumed bytes");
            }
            Check(!pause || resumed,"pause resume");
            Check(!pa.loss || pa.drops+pb.drops>0,"loss injection");
            Check(!pa.block || pa.retries+pb.retries>0,"WouldBlock injection");
            Check(pa.classified>0 && pb.classified>0 && pb.initials>0,"demux exercised");
            if(argc>1 && std::strcmp(argv[1],"close")==0) {
                events.Drain();
                const auto closeStart=Now();
                Check(client.RequestClose(15) && !client.Ready(),"native authenticated CLOSE request");
                while(Now()-closeStart<3000 && (!client.Retirable() || !server.Retirable())) {
                    // Shutdown removes CIDs; this lab's strict Deliver helper
                    // only applies to live sessions, not late retired packets.
                    if(!client.Retirable()) pa.Deliver(oa);
                    if(!server.Retirable()) pb.Deliver(ob);
                    oa.Poll(Now()); ob.Poll(Now());
                    std::this_thread::yield();
                }
                const auto terminal=events.Drain();
                unsigned local=0,remote=0;
                for(const auto& event:terminal) {
                    Check(event.type==DirectEventType::Closed && event.reason==DirectReason::Disabled &&
                        event.session_epoch==1 && event.route_id==3,"native CLOSE typed terminal");
                    if(event.handle.slot==0) ++local;
                    if(event.handle.slot==1) ++remote;
                }
                Check(local==1 && remote==1 && client.Retirable() && server.Retirable(),"native CLOSE both terminal once");
                Check(pool.Used()==0,"native CLOSE pool drained");
                std::printf("native QUIC authenticated CLOSE PASS: remote reason15 Disabled, both terminal once; local ACK-or-timeout is best-effort\n");
            } else if(reset) {
                events.Drain();
                DirectSessionEvent filler; filler.type=DirectEventType::Closed;
                filler.handle={8,1}; filler.route_id=9; filler.topology_generation=7;
                for(std::size_t i=0;i<kDirectEventCapacity;++i) {
                    filler.sequence=i+1;
                    Check(events.TryPush(filler)==DirectEnqueueStatus::Accepted,"native reset event saturation");
                }
                Check(oa.Detach() && ob.Detach(),"native reset socket detach");
                oa.Stop(); ob.Stop(); // idempotent after socket-owned reset
                Check(!oa.Release(1) && !ob.Release(1),"native reset retains pending terminal");
                Check(oa.RetireClosed()==0 && ob.RetireClosed()==0 &&
                    !oa.Empty() && !ob.Empty(),"bulk retirement preserves pending terminal");
                events.Drain(); oa.Poll(Now()); ob.Poll(Now());
                const auto terminal=events.Drain();
                Check(terminal.size()==2 && terminal[0].type==DirectEventType::Closed &&
                    terminal[1].type==DirectEventType::Closed && terminal[0].session_epoch==1 &&
                    terminal[1].session_epoch==1,"native reset terminal delivery in adopted epoch");
            } else { client.Close(DirectReason::Disabled); server.Close(DirectReason::Disabled); }
            Check(client.Retirable() && server.Retirable() && pool.Used()==0,"retirement/pool");
            if(dcoScenario) {
                nativeCoordinator.Advance({0,1},Now(),events.Drain());
                const auto terminal=nativeCoordinator.Cancel({0,1},DirectReason::Disabled);
                (void)terminal;
                Check(nativeCoordinator.Release({0,1}) && nativeCoordinator.Size()==0,"native DCO terminal release after transport drain");
                serverCoordinator.Advance(serverHandle,Now(),serverEvents.Drain());
                serverCoordinator.Cancel(serverHandle,DirectReason::Disabled);
                Check(serverCoordinator.Release(serverHandle) && serverCoordinator.Size()==0,"native server DCO terminal release after transport drain");
                std::printf("native DCO event-driven admission/authentication/adoption/release PASS (both coordinators; not MFC transfer)\n");
            }
            std::printf("native QUIC facade UDP [%s]: %zu/%zu bytes exact + ACK + demux + pool drained PASS (ephemeral lab identities; no shared host socket)\n",argc>1 ? argv[1] : "clean",forwardTotal,total);
            }
            // Writers borrow child pools; destroy them before owner retirement, even empty.
            forwardWriter.reset(); reverseWriter.reset();
            Check(oa.RetireClosed()==1 && ob.RetireClosed()==1 &&
                oa.Empty() && ob.Empty(),"native socket owner bulk retirement");
            Check(oa.RetireClosed()==0 && ob.RetireClosed()==0,"bulk retirement idempotent");
        } catch(...) {
            // Release can succeed for only one owner; do not touch old refs.
            for(auto* transport : {oa.Find(1),ob.Find(1)})
                if(transport) transport->Close(DirectReason::Disabled);
            events.Drain(); serverEvents.Drain(); oa.Poll(Now()); ob.Poll(Now());
            oa.Release(1); ob.Release(1); throw;
        }
        result=0;
    } catch(const std::exception& e) { std::printf("FAIL: %s\n",e.what()); }
    return result;
}
