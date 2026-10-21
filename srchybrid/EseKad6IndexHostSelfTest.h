#pragma once
#include "kademlia/kademlia/Kademlia.h"
// Explicit isolated-profile fixture only. The mapper/UDP witness verdict is
// injected, not a public-router or physical NAT test. Control datagrams below
// traverse the application's real shared UDP socket and service dispatcher.
namespace ese { namespace shared_socket_selftest {
inline void RunIndexHost(CDirectReachabilityManager& manager,std::uint16_t portNumber) {
    Require(theApp.m_bReachBindingSelfTest && !Kademlia::CKademlia::IsRunning(),"index isolated stopped Kad prerequisite");
    struct Restore {
        CDirectReachabilityManager& manager;
        int consent=thePrefs.GetEseNetLabConsent(); bool enabled=thePrefs.GetEseNetLabEnabled();
        int advanced=thePrefs.GetEseNetLabAdvancedConsent();
        uint8 mask=thePrefs.GetKadNetworkMask(); uint16 port=thePrefs.GetUDPPort();
        bool openedTcp=false;
        ~Restore() {
            manager.ShutdownQuicHost(); Kademlia::CKademlia::Stop();
            thePrefs.SetKadNetworkMask(mask); thePrefs.SetEseNetLabConsent(consent);
            thePrefs.SetEseNetLabAdvancedConsent(advanced);
            thePrefs.SetEseNetLabEnabled(enabled); thePrefs.SetUDPPort(port); theApp.clientudp->Rebind();
            if(openedTcp) theApp.listensocket->Close();
            manager.SynchronizeLocalSocketBindings();
        }
    } restore{manager};
    thePrefs.SetEseNetLabConsent(CPreferences::EseNetLabAccepted); thePrefs.SetEseNetLabEnabled(true);
    thePrefs.SetEseNetLabAdvancedConsent(CPreferences::EseNetLabAccepted);
    thePrefs.SetUDPPort(portNumber); Require(theApp.clientudp->Rebind(),"index shared socket binding");
    if(!theApp.listensocket->GetConnectedPort()) {
        Require(theApp.listensocket->StartListening(),"index actual classic TCP listener activation");
        restore.openedTcp=true;
    }
    thePrefs.SetKadNetworkMask(KadNetworkPolicy::Both);
    Log(_T("INDEX_HOST_SELFTEST activation: UDP=%u mask=%u effective=%u"),unsigned(thePrefs.GetUDPPort()),
        unsigned(thePrefs.GetKadNetworkMask()),unsigned(thePrefs.GetEffectiveKadNetworkMask()));
    Kademlia::CKademlia::Start();
    Require(Kademlia::CKademlia::IsKad6Running(),"index Kad6 activation");
    manager.TickDirectConnections(); Require(manager.EnableNativeQuicLab(),"index real host activation");
    Require(!manager.GetKad6ServiceCapabilities(),"index no capability from mapping alone");
    Require(manager.ObserveMappedPorts(natmap::MapperKind::Pcp,htonl(0x34020304),thePrefs.GetPort(),
        55001,portNumber,55002,120,1,false),"index injected mapping transaction");
    const auto peerIp=htonl(0x35020304);
    Require(manager.BeginKad6PublicContactVerification(peerIp) &&
        manager.ObserveKad6PublicContactVerification(peerIp,55002,portNumber),"index injected UDP witness verdict");
    manager.TickDirectConnections();
    Require(manager.GetKad6ServiceCapabilities()==discovery::K6_CAP_DIRECT_INDEX_V1,"index receiver-first capability only");
    std::array<std::uint8_t,32> localPub{}; memcpy(localPub.data(),eSELive::NodeIdentityPub(),32);
    struct Signer final : control::Signer {
        Identity identity;
        bool Sign(const std::uint8_t* p,std::size_t n,std::array<std::uint8_t,64>& out) noexcept override { return identity.Sign(p,n,out.data()); }
    } publisher;
    Port peer; udp::Endpoint local; local.address[0]=127; local.address[3]=1; local.port=portNumber;
    sockaddr_in destination{}; destination.sin_family=AF_INET;
    destination.sin_addr.s_addr=htonl(INADDR_LOOPBACK); destination.sin_port=htons(portNumber);
    auto send=[&](const control::Datagram& packet) {
        Require(sendto(peer.socket,reinterpret_cast<const char*>(packet.bytes.data()),static_cast<int>(packet.size),0,
            reinterpret_cast<const sockaddr*>(&destination),sizeof(destination))==static_cast<int>(packet.size),"index real UDP send");
    };
    auto receive=[&](control::Datagram& packet,std::uint64_t until) {
        while(Now()<until) {
            MSG message; while(PeekMessage(&message,nullptr,0,0,PM_REMOVE)) { TranslateMessage(&message); DispatchMessage(&message); }
            manager.TickDirectConnections(); sockaddr_in origin{}; int size=sizeof(origin);
            const int length=recvfrom(peer.socket,reinterpret_cast<char*>(packet.bytes.data()),static_cast<int>(packet.bytes.size()),0,
                reinterpret_cast<sockaddr*>(&origin),&size);
            if(length!=SOCKET_ERROR) {
                Require(origin.sin_port==destination.sin_port && origin.sin_addr.s_addr==destination.sin_addr.s_addr,"index exact shared response source");
                packet.size=static_cast<std::size_t>(length); return true;
            }
            Require(WSAGetLastError()==WSAEWOULDBLOCK,"index UDP receive failure"); SwitchToThread();
        }
        return false;
    };
    control::Header header; header.type=wire::kEseWireUdpProbe; header.generation=7; header.sequence=1;
    control::Probe probe; probe.node=publisher.identity.pub; probe.peer=localPub;
    const auto crypto=MakeKad6HostCryptoHooks();
    Require(crypto.random_bytes(header.attempt.data(),header.attempt.size()) && crypto.random_bytes(probe.nonce.data(),probe.nonce.size()),"index CSPRNG context");
    const auto deadline=Now()+1800; control::Initiator initiator;
    Require(initiator.Start(header,probe,local,Now(),deadline),"index bootstrap start");
    while(Now()<deadline && initiator.State()!=control::InitiatorState::Ready) {
        const auto pending=initiator.Pending(Now());
        if(pending.size) { control::Datagram packet; packet.size=pending.size; memcpy(packet.bytes.data(),pending.data,pending.size);
            send(packet); Require(initiator.Submitted(Now()),"index bootstrap submitted"); }
        control::Datagram response;
        if(!receive(response,(std::min)(deadline,Now()+100))) continue;
        if(initiator.State()==control::InitiatorState::Probe)
            Require(initiator.ChallengeReceived(local,response.bytes.data(),response.size,Now(),publisher),"index shared challenge");
        else Require(initiator.AckReceived(local,response.bytes.data(),response.size,Now()),"index persistent signed control ACK");
    }
    Require(initiator.State()==control::InitiatorState::Ready,"index bootstrap completion");
    std::array<std::uint8_t,16> file{},user{},kad{}; file[0]=0x66;
    std::array<discovery::OwnedPublicationCandidate,2> routes{};
    std::array<std::uint8_t,discovery::DescriptorMax> descriptor{};
    std::array<std::uint8_t,173> source{}; std::size_t length=0;
    Require(discovery::BuildOwnedPublication(file,123,7,1,publisher.identity.pub,user,kad,routes,0,30,publisher,
        descriptor,length,source,MAX_EMULE_FILE_SIZE),"index own coherent signed metadata pair");
    control::Datagram packet,response; header.type=wire::kEseWireUdpDescriptorPut; header.sequence=2;
    Require(control::BuildDescriptorPut(header,file,descriptor.data(),length,publisher.identity.pub,publisher,packet),"index descriptor PUT");
    send(packet); header.type=wire::kEseWireUdpK6DirectPut; header.sequence=3;
    Require(control::BuildDirectPut(header,source.data(),source.size(),MAX_EMULE_FILE_SIZE,publisher.identity.pub,publisher,packet),"index source PUT");
    send(packet); Require(receive(response,Now()+1000),"index coherent source ACK");
    discovery::DirectSource parsed; std::uint8_t status=255;
    Require(control::VerifyDirectSource(publisher.identity.pub,source.data(),source.size(),MAX_EMULE_FILE_SIZE,parsed) &&
        control::VerifyDirectPutResult(localPub,header,parsed,MAX_EMULE_FILE_SIZE,response.bytes.data(),response.size,status) && status==0,"index normal receiver STORED");
    Require(receive(response,Now()+1000),"index deferred descriptor ACK after coherent source");
    control::Envelope deferred; discovery::ResultView descResult;
    Require(control::VerifyEnvelopeSignature(localPub,response.bytes.data(),response.size) &&
        control::ParseUntrusted(response.bytes.data(),response.size,deferred) &&
        deferred.header.type==wire::kEseWireUdpDescriptorResult && deferred.header.sequence==2 &&
        discovery::DecodeResult(deferred.payload,deferred.payloadSize,descResult) && descResult.status==0 &&
        descResult.length==length && !memcmp(descResult.descriptor,descriptor.data(),length),"index deferred descriptor original correlation and exact bytes");
    // A source-less W must return its nearest complete signed contact, not
    // stop a bounded lookup at EMPTY merely because its own replica is empty.
    Signer neighbor;
    auto neighborHooks=MakeKad6HostCryptoHooks();
    neighborHooks.ed25519_sign=[](const kad6::Byte* key,std::size_t n,const kad6::Byte* p,std::size_t size,kad6::Byte* sig)->bool {
        return n==64 && eSELive::SignMessage(key,key+32,p,size,sig);
    };
    struct NeighborSecret { std::array<std::uint8_t,64> bytes{}; ~NeighborSecret() { SecureZeroMemory(bytes.data(),bytes.size()); } } neighborSecret;
    memcpy(neighborSecret.bytes.data(),neighbor.identity.priv.data(),32);
    memcpy(neighborSecret.bytes.data()+32,neighbor.identity.pub.data(),32);
    const auto utc=static_cast<std::uint64_t>(std::time(nullptr));
    kad6::K6RouterRecord neighborRecord; neighborRecord.node_pub=neighbor.identity.pub;
    neighborRecord.kad_id[0]=0x7a; neighborRecord.epoch=Now();
    neighborRecord.caps=discovery::K6_CAP_DIRECT_INDEX_V1;
    neighborRecord.valid_from=utc-1; neighborRecord.valid_until=utc+120;
    kad6::K6Endpoint neighborEndpoint; neighborEndpoint.addr.family=kad6::Kad6Address::Family::IPv4;
    neighborEndpoint.addr.addr[0]=54; neighborEndpoint.addr.addr[1]=2; neighborEndpoint.addr.addr[2]=3; neighborEndpoint.addr.addr[3]=4;
    neighborEndpoint.udp_port=5678; neighborEndpoint.transport_flags=kad6::kK6EpUdpKad6;
    neighborEndpoint.valid_until=neighborRecord.valid_until; neighborRecord.endpoints.push_back(neighborEndpoint);
    std::vector<kad6::Byte> neighborBytes;
    Require(kad6::SignK6RouterRecord(neighborHooks,neighborSecret.bytes.data(),neighborSecret.bytes.size(),neighborRecord,neighborBytes)==kad6::Kad6Status::Ok &&
        manager.ImportDirectKad6Contact(neighborRecord.node_pub,neighborBytes.data(),neighborBytes.size()),"index signed neighboring contact import");
    discovery::DirectFind find; find.requester=publisher.identity.pub; find.file[0]=0x77; find.fileSize=123; find.maximum=2;
    header.type=wire::kEseWireUdpK6DirectFind; header.sequence=4;
    std::array<std::uint8_t,32> findDigest{}; discovery::FindResultView found;
    Require(control::BuildDirectFind(header,find,MAX_EMULE_FILE_SIZE,publisher,packet) &&
        control::DirectFindDigest(publisher.identity.pub,packet.bytes.data(),packet.size,MAX_EMULE_FILE_SIZE,findDigest),"index missing source FIND signing");
    send(packet);
    control::Kad6FindContacts neighborsGate(neighborHooks,discovery::K6_CAP_DIRECT_INDEX_V1,utc);
    Require(receive(response,Now()+1000) &&
        control::VerifyDirectFindResultSignature(localPub,header,find,findDigest,response.bytes.data(),response.size,MAX_EMULE_FILE_SIZE,found) &&
        found.kind==1 && found.count==1 && neighborsGate.Verify(found,localPub) &&
        found.entries[0].size==neighborBytes.size() && !memcmp(found.entries[0].bytes,neighborBytes.data(),neighborBytes.size()),
        "index real shared UDP CLOSER complete original signed contact");
    neighborRecord.caps=0; ++neighborRecord.epoch;
    Require(kad6::SignK6RouterRecord(neighborHooks,neighborSecret.bytes.data(),neighborSecret.bytes.size(),neighborRecord,neighborBytes)==kad6::Kad6Status::Ok &&
        manager.ImportDirectKad6Contact(neighborRecord.node_pub,neighborBytes.data(),neighborBytes.size()),"index signed neighbor capability withdrawal");
    header.sequence=5;
    Require(control::BuildDirectFind(header,find,MAX_EMULE_FILE_SIZE,publisher,packet) &&
        control::DirectFindDigest(publisher.identity.pub,packet.bytes.data(),packet.size,MAX_EMULE_FILE_SIZE,findDigest),"index post-withdrawal FIND signing");
    send(packet);
    Require(receive(response,Now()+1000) &&
        control::VerifyDirectFindResultSignature(localPub,header,find,findDigest,response.bytes.data(),response.size,MAX_EMULE_FILE_SIZE,found) &&
        found.kind==2 && found.count==0,"index withdrawn neighbor never returned");
    Log(_T("REACH_SELFTEST V169 PASS: normal index missing source returns complete signed CLOSER over real shared UDP; signed capability withdrawal yields EMPTY; no peer session or route granted"));
    header.type=wire::kEseWireUdpK6DirectPut; header.sequence=3;
    Require(control::BuildDirectPut(header,source.data(),source.size(),MAX_EMULE_FILE_SIZE,publisher.identity.pub,publisher,packet),"index retired duplicate PUT fixture");
    thePrefs.SetEseNetLabEnabled(false); manager.TickDirectConnections();
    Require(!manager.GetKad6ServiceCapabilities(),"index disabled service withdrawn");
    send(packet); Require(!receive(response,Now()+100),"index retired classifier returns no ACK");
    Log(_T("REACH_SELFTEST V166 PASS: receiver-first activation control bootstrap descriptor/source STORED over real shared loopback UDP; consent withdrawal no reply no RDV; mapping and public UDP verdict injected not physical NAT"));
    // A new real inbound TCP socket is required before the classic UDP ACK.
    // The external TCP mapping is injected and deliberately differs from bind.
    thePrefs.SetEseNetLabEnabled(true);
    manager.TickDirectConnections();
    const auto boundTcp=theApp.listensocket->GetConnectedPort();
    Require(boundTcp && manager.ObserveMappedPorts(natmap::MapperKind::Pcp,htonl(0x34020304),boundTcp,
        55001,portNumber,55002,120,2,false),"classic fresh injected mapping after consent reactivation");
    Log(_T("CLASSIC_HOST_SELFTEST mapping: enabled=%u localTCP=%u advertisedTCP=%u generation=%I64u"),
        unsigned(manager.IsEnabled()),unsigned(manager.GetLocalTcpPort()),unsigned(manager.GetAdvertisedTcpPort()),
        static_cast<ULONGLONG>(manager.GetTopologyGeneration()));
    const auto classicPeer=htonl(INADDR_LOOPBACK);
    Require(manager.BeginClassicCallbackVerification(classicPeer),"classic mapped callback request");
    theApp.clientlist->AddKadFirewallRequest(classicPeer);
    const std::array<char,2> classicAck{{static_cast<char>(OP_KADEMLIAHEADER),static_cast<char>(KADEMLIA_FIREWALLED_ACK_RES)}};
    auto ack=[&]() {
        Require(sendto(peer.socket,classicAck.data(),static_cast<int>(classicAck.size()),0,
            reinterpret_cast<const sockaddr*>(&destination),sizeof(destination))==static_cast<int>(classicAck.size()),"classic real UDP ACK");
    };
    ack(); receive(response,Now()+50);
    Require(!manager.HasVerifiedClassicCallbackReachability(),"classic ACK without inbound socket rejected");
    SOCKET inbound=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    Require(inbound!=INVALID_SOCKET,"classic inbound socket creation");
    struct CloseSocket { SOCKET value; ~CloseSocket() { closesocket(value); } } closeSocket{inbound};
    auto tcpDestination=destination; tcpDestination.sin_port=htons(boundTcp);
    Require(connect(inbound,reinterpret_cast<const sockaddr*>(&tcpDestination),sizeof(tcpDestination))==0,"classic new TCP connection to actual listener");
    receive(response,Now()+100); ack(); receive(response,Now()+100);
    Require(manager.HasVerifiedClassicCallbackReachability() && manager.GetAdvertisedTcpPort()==55001 &&
        manager.GetLocalTcpPort()==boundTcp,"classic inbound then ACK exact external/local mapping tuple");
    Log(_T("REACH_SELFTEST V167 PASS: classic UDP ACK before inbound rejected then real new loopback TCP accept and classic UDP ACK verify mapped external port distinct from bind; router injected not external client or HighID proof"));
    RunServerCallbackHost(manager);
    const auto oldGeneration=manager.GetTopologyGeneration();
    const auto failedReadback=manager.BeginMapperOperation(natmap::MapperKind::Pcp,boundTcp,portNumber,true,4000);
    natmap::MapperResult missing; natmap::OwnedMapperResult retired;
    Require(failedReadback && manager.MapperResults()->Publish(failedReadback,missing) &&
        manager.TakeMapperResult(failedReadback,retired) && !retired.result.success &&
        manager.GetTopologyGeneration()!=oldGeneration && !manager.IsEnabled() &&
        !manager.HasVerifiedClassicCallbackReachability() && !manager.GetKad6ServiceCapabilities() &&
        manager.MappingRediscoveryNeeded() && !manager.MapperResults()->Publish(failedReadback,missing),
        "owned current readback failure retires grant callback receiver generation and stale worker");
    Log(_T("REACH_SELFTEST V170 PASS: current owned mapping readback failure consumed once withdraws grant classic callback and receiver before rediscovery; injected worker result not physical router deletion"));
    Require(Kademlia::CKademlia::ApplyNetworkMask(KadNetworkPolicy::Kad6),"publication Kad6-only profile");
    manager.Initialize(boundTcp,portNumber);
    Require(!manager.GetKad6ServiceCapabilities() && !manager.HasVerifiedClassicCallbackReachability(),
        "publication outbound client has no public receiver or inbound proof");
    RunPublicationHost(manager);
}
} }
