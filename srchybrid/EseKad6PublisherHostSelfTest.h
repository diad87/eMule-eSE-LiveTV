#pragma once
#include "kademlia/kademlia/Kademlia.h"
#include "EseKad6IndexService.h"
#include "EseKad6IndexBootstrap.h"
namespace ese { namespace shared_socket_selftest {
// Persistent product publisher and real manager scheduler; the witness/network
// are logical test fixtures, not a second product or public NAT acceptance.
inline void RunPublicationHost(CDirectReachabilityManager& manager) {
    Require(theApp.m_bReachBindingSelfTest && Kademlia::CKademlia::IsKad6Running(),"publication isolated Kad scope");
    manager.ShutdownQuicHost();
    udp::Endpoint local; local.address={9,9,9,9}; local.port=thePrefs.GetUDPPort();
    test::SimulatedQuicPort localPort(local); control::PacketBudget budget;
    Port witness(true); Require(localPort.Link(*witness.memory),"publication logical namespace link");
    witness.pairedMemory=&localPort;
    auto host=CreateQuicSessionHost(localPort,manager.DirectBuffers(),manager.DirectEvents(),budget);
    Require(manager.AdoptQuicHost(host),"publication production host adoption");
    struct Inbox final : QuicUdpIngress {
        std::vector<QuicUdpRouter::PendingControl> packets;
        bool Receive(const udp::Endpoint& peer,reach::DirectByteView bytes) noexcept override {
            if(packets.size()>=16 || bytes.size>1200) return false;
            try { QuicUdpRouter::PendingControl packet; packet.peer=peer; packet.size=bytes.size;
                memcpy(packet.bytes.data(),bytes.data,bytes.size); packets.push_back(packet); return true; }
            catch(...) { return false; }
        }
        void Poll(std::uint64_t) override {}
        void SocketReset() noexcept override { packets.clear(); }
    } inbox;
    Require(witness.AttachQuicIngress(&inbox),"publication witness ingress");
    struct Signer final : control::Signer {
        Identity identity;
        bool Sign(const std::uint8_t* p,std::size_t n,std::array<std::uint8_t,64>& out) noexcept override { return identity.Sign(p,n,out.data()); }
    } signer;
    auto hooks=MakeKad6HostCryptoHooks();
    hooks.ed25519_sign=[](const kad6::Byte* key,std::size_t n,const kad6::Byte* p,std::size_t size,kad6::Byte* signature)->bool {
        return n==64 && eSELive::SignMessage(key,key+32,p,size,signature);
    };
    struct Secret { std::array<std::uint8_t,64> bytes{}; ~Secret() { SecureZeroMemory(bytes.data(),bytes.size()); } } secret;
    memcpy(secret.bytes.data(),signer.identity.priv.data(),32); memcpy(secret.bytes.data()+32,signer.identity.pub.data(),32);
    const auto utc=static_cast<std::uint64_t>(std::time(nullptr));
    kad6::K6RouterRecord record; record.node_pub=signer.identity.pub; record.kad_id[0]=4; record.epoch=Now();
    record.caps=discovery::K6_CAP_DIRECT_INDEX_V1; record.valid_from=utc-1; record.valid_until=utc+120;
    kad6::K6Endpoint endpoint; endpoint.addr.family=kad6::Kad6Address::Family::IPv4;
    endpoint.addr.addr=witness.endpoint.address; endpoint.udp_port=witness.endpoint.port;
    endpoint.transport_flags=kad6::kK6EpUdpKad6; endpoint.valid_until=record.valid_until; record.endpoints.push_back(endpoint);
    std::vector<kad6::Byte> bytes;
    Require(kad6::SignK6RouterRecord(hooks,secret.bytes.data(),secret.bytes.size(),record,bytes)==kad6::Kad6Status::Ok &&
        manager.ImportDirectKad6Contact(record.node_pub,bytes.data(),bytes.size()),"publication signed live W contact");
    const CString directory=thePrefs.GetTempDir(),name=_T("normal-kad6-publication.bin"),path=directory+_T("\\")+name;
    Require(directory.Left(7).CompareNoCase(_T("D:\\tmp\\"))==0 && GetFileAttributes(path)==INVALID_FILE_ATTRIBUTES,"publication isolated fresh file");
    std::array<BYTE,123> content{}; for(unsigned i=0;i<content.size();++i) content[i]=static_cast<BYTE>(i);
    { CFile disk(path,CFile::modeCreate|CFile::modeWrite|CFile::shareExclusive); disk.Write(content.data(),static_cast<UINT>(content.size())); disk.Flush(); }
    auto file=std::make_unique<CKnownFile>();
    Require(file->CreateFromFile(directory,name,nullptr),"publication actual shared file hash");
    struct Cleanup {
        CDirectReachabilityManager& manager; Port& witness; Inbox& inbox; std::unique_ptr<CKnownFile>& file; bool shared=false;
        ~Cleanup() { manager.ShutdownQuicHost(); witness.DetachQuicIngress(&inbox); if(shared) theApp.sharedfiles->RemoveFile(file.get()); }
    } cleanup{manager,witness,inbox,file};
    Require(theApp.sharedfiles->SafeAddKFile(file.get(),true),"publication shared ownership registration"); cleanup.shared=true;
    const auto storedBefore=CNativeDirectSelfTestAccess::StoredKad6Publications(manager);
    Require(manager.TryPublishQueuedKad6File(*file),"publication normal owned-file admission");
    control::PacketBudget receiverBudget; auto sessions=std::make_unique<control::Sessions>();
    auto bootstrap=std::make_unique<discovery::Kad6IndexBootstrap>(receiverBudget);
    auto receiver=std::make_unique<discovery::Kad6IndexService<4>>(receiverBudget);
    Require(bootstrap->Initialize(),"publication witness real cookie authority");
    unsigned descriptors=0,putResults=0,stored=0; bool lostAck=false;
    const auto deadline=Now()+4500;
    while(Now()<deadline && CNativeDirectSelfTestAccess::StoredKad6Publications(manager)==storedBefore) {
        manager.TickDirectConnections(); witness.memory->Deliver();
        auto packets=std::move(inbox.packets); inbox.packets.clear();
        for(const auto& packet:packets) {
            control::Envelope envelope; Require(control::ParseUntrusted(packet.bytes.data(),packet.size,envelope),"publication witness envelope");
            control::Datagram response; std::array<std::uint8_t,32> peer{}; control::Header context;
            if(envelope.header.type==wire::kEseWireUdpProbe || envelope.header.type==wire::kEseWireUdpProve) {
                Require(bootstrap->Receive(*sessions,packet.peer,signer.identity.pub,packet.bytes.data(),packet.size,Now(),signer,response,peer,context)
                    !=discovery::IndexBootstrapResult::Rejected,"publication signed control bootstrap");
            } else {
                memcpy(peer.data(),eSELive::NodeIdentityPub(),32);
                if(envelope.header.type==wire::kEseWireUdpDescriptorPut && ++descriptors==1) continue; // drop first descriptor
                const auto result=receiver->Receive(*sessions,peer,packet.peer,packet.bytes.data(),packet.size,MAX_EMULE_FILE_SIZE,
                    Now(),signer.identity.pub,signer,response);
                Require(result!=discovery::IndexDispatch::Rejected,"publication receiver admission");
                if(envelope.header.type==wire::kEseWireUdpK6DirectPut) {
                    ++putResults; discovery::DirectSource source; std::uint8_t status=255;
                    Require(control::VerifyDirectSource(peer,envelope.payload,173,MAX_EMULE_FILE_SIZE,source) &&
                        !memcmp(source.file.data(),file->GetFileHash(),16) && source.fileSize==file->GetFileSize() &&
                        control::VerifyDirectPutResult(signer.identity.pub,envelope.header,source,MAX_EMULE_FILE_SIZE,response.bytes.data(),response.size,status),"publication exact owned source ACK");
                    if(status==0) { ++stored; if(!lostAck) { lostAck=true; continue; } }
                    else Require(status==1,"publication only bounded NEED_DESCRIPTOR restage");
                }
            }
            if(response.size) Require(witness.SendQuicDatagram(&inbox,packet.peer,response.bytes.data(),response.size).status==QuicUdpSendStatus::Sent,"publication witness response");
        }
        localPort.Deliver(); manager.TickDirectConnections(); SwitchToThread();
    }
    Require(descriptors==2 && putResults>=3 && stored>=2 && lostAck &&
        CNativeDirectSelfTestAccess::StoredKad6Publications(manager)==storedBefore+1,"publication restage once lost ACK duplicate single completion");
    // Withdraw this ephemeral witness's service with its own higher signed
    // epoch. Later fixtures must not inherit an eligible, destroyed index.
    ++record.epoch; record.caps=0; bytes.clear();
    Require(kad6::SignK6RouterRecord(hooks,secret.bytes.data(),secret.bytes.size(),record,bytes)==kad6::Kad6Status::Ok &&
        manager.ImportDirectKad6Contact(record.node_pub,bytes.data(),bytes.size()),"publication signed fixture capability withdrawal");
    Log(_T("REACH_SELFTEST V168 PASS: normal manager publishes actual shared file persistent signed serial descriptor/source; lost descriptor one restage lost STORED ACK exact retry one completion; simulated W no physical NAT claim"));
    std::array<std::uint8_t,16> noBootstrapFile{}; noBootstrapFile[0]=0x79;
    Require(!manager.TryBeginQueuedKad6Resolution(noBootstrapFile,123) &&
        manager.GetKad6DiscoveryOutcome()==discovery::DiscoveryOutcome::BootstrapRequired,
        "normal discovery without an eligible signed W reports BOOTSTRAP_REQUIRED");
    manager.TickDirectConnections();
    auto diagnostic=manager.GetDirectStatusJson();
    Require(diagnostic.find("\"kad6_discovery\":\"BOOTSTRAP_REQUIRED\"")!=std::string::npos &&
        diagnostic.find("\"classic_callback\":\"NO_ROUTE\"")!=std::string::npos,
        "immutable normal API exposes bootstrap and classic no-route outcomes");
    record.caps=discovery::K6_CAP_DIRECT_INDEX_V1; ++record.epoch; bytes.clear();
    Require(kad6::SignK6RouterRecord(hooks,secret.bytes.data(),secret.bytes.size(),record,bytes)==kad6::Kad6Status::Ok &&
        manager.ImportDirectKad6Contact(record.node_pub,bytes.data(),bytes.size()),"negative discovery signed silent W");
    std::array<std::uint8_t,16> unavailableFile{}; unavailableFile[0]=0x7b;
    Require(manager.TryBeginQueuedKad6Resolution(unavailableFile,123) &&
        manager.GetKad6DiscoveryOutcome()==discovery::DiscoveryOutcome::Pending,"negative normal discovery pending");
    unsigned silentPackets=0; inbox.packets.clear(); const auto silentDeadline=Now()+5500;
    while(Now()<silentDeadline && manager.GetKad6DiscoveryOutcome()==discovery::DiscoveryOutcome::Pending) {
        manager.TickDirectConnections(); witness.memory->Deliver();
        silentPackets+=static_cast<unsigned>(inbox.packets.size()); inbox.packets.clear(); SwitchToThread();
    }
    Require(manager.GetKad6DiscoveryOutcome()==discovery::DiscoveryOutcome::DiscoveryUnavailable &&
        silentPackets>0 && silentPackets<=3 && !manager.TryBeginQueuedKad6Resolution(unavailableFile,123),
        "silent W bounded lookup unavailable and cooldown prevents immediate retry");
    manager.TickDirectConnections(); diagnostic=manager.GetDirectStatusJson();
    Require(diagnostic.find("\"kad6_discovery\":\"DISCOVERY_UNAVAILABLE\"")!=std::string::npos,
        "immutable normal API reports DISCOVERY_UNAVAILABLE");
    record.caps=0; ++record.epoch; bytes.clear();
    Require(kad6::SignK6RouterRecord(hooks,secret.bytes.data(),secret.bytes.size(),record,bytes)==kad6::Kad6Status::Ok &&
        manager.ImportDirectKad6Contact(record.node_pub,bytes.data(),bytes.size()),"negative discovery signed W withdrawal");
    Log(_T("REACH_SELFTEST V171 PASS: normal manager and immutable API report BOOTSTRAP_REQUIRED NO_ROUTE and silent W DISCOVERY_UNAVAILABLE; bounded bootstrap sends global lookup deadline cooldown retained; simulated silent W no queue transfer claim"));
}
} }
