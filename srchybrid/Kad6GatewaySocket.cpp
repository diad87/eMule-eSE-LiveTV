#include "stdafx.h"
#include "Kad6GatewaySocket.h"
#include "emule.h"

#include "LiveTunnel.h"
#include "LiveTunnelGatewayLeaseState.h"
#include "LiveTunnelTicketPolicy.h"
#include "Kad6CryptoHost.h"
#include "DownloadQueue.h"
#include "ClientList.h"
#include "IPFilter.h"
#include "PartFile.h"
#include "LiveStreamManager.h"
#include "LiveKadBridge.h"
#include "Log.h"
#include "NodeIdentity.h"
#include "Packets.h"
#include "SafeFile.h"
#include "Preferences.h"
#include "Opcodes.h"
#include "DirectReachabilityManager.h"
#include "FirewallProberV6.h"
#include "eMuleAI/Address.h"
#include "kademlia/kademlia/Kademlia.h"
#include "kademlia/kademlia/KadV2ModeSelector.h"
#include "kademlia/kademlia/Search.h"
#include "kademlia/kademlia/SearchManager.h"
#include "kademlia/net/KademliaUDPListener.h"
#include "kad6/kad6_ed2k_policy.h"
#include "kad6/kad6_endpoint.h"
#include "kad6/kad6_live_search.h"

namespace eSELive {
namespace {
LiveSourceEndpointKey BuildLiveSourceEndpointKey(
    const kad6::K6Endpoint& endpoint,
    uint8 origin)
{
    return {origin, static_cast<uint8>(endpoint.addr.family),
        endpoint.addr.addr, endpoint.tcp_port};
}
} // namespace
uint64_t M2A_LT3_K6ShapeNowUs();
std::vector<uint8_t> M2A_LT3_EseCStringUtf8(const CString&);
CString M2A_LT3_EseUtf8CString(const std::string&);
bool M2A_LT3_AppendLegacyK6Result(
    const kad6::K6LiveSearchMetadata&, std::vector<uint8_t>&);
bool M2A_LT3_PlanGatewayFrameBridge(const M2AModuleHandle& handle, const std::uint8_t* wire, std::size_t length, std::uint32_t requestId, bool response, void* output) { if (!handle.Get() || !wire || length == 0 || !output) return false; kad6::K6Frame frame; std::size_t consumed=0; if (kad6::DecodeK6Frame(wire,length,frame,&consumed)!=kad6::Kad6Status::Ok || consumed!=length || frame.request_id!=requestId || frame.session_id!=0 || ((frame.flags&kad6::kK6FlagResponse)!=0)!=response || (frame.flags&kad6::kK6FlagReservedMask)!=0 || (!response && (frame.flags&(kad6::kK6FlagMore|kad6::kK6FlagFinal))!=0)) return false; *static_cast<kad6::K6Frame*>(output)=std::move(frame); return true; }
bool M2A_LT3_OperateStoresBridge(const M2AModuleHandle& handle, LiveTunnelGatewayStoreOperation operation, void* a, void* b, void* c, void* d, void* e, void* f) {
    auto* owner=static_cast<LiveTunnelGatewayLeaseState*>(const_cast<void*>(handle.Get())); if (!owner) return false; std::lock_guard<std::mutex> lock(owner->m_storeMutex);
    if (!owner->m_k6SourceLeases || !owner->m_k6CohortScheduler || !owner->m_k6PublishBudget || !owner->m_k6PublishCoalescer) return false;
    auto& leases=*static_cast<kad6::K6SourceLeaseTable*>(owner->m_k6SourceLeases.get()); auto& cohorts=*static_cast<kad6::K6CohortScheduler*>(owner->m_k6CohortScheduler.get()); auto& budget=*static_cast<kad6::K6PublishBudget*>(owner->m_k6PublishBudget.get()); auto& coalescer=*static_cast<kad6::K6PublishCoalescer*>(owner->m_k6PublishCoalescer.get());
    switch(operation) {
    case LiveTunnelGatewayStoreOperation::Entries: for(const auto& entry:leases.Entries())static_cast<std::map<std::uint64_t,kad6::K6SourceLease>*>(a)->insert(entry);return true; case LiveTunnelGatewayStoreOperation::Find:{const auto* value=leases.Find(*static_cast<std::uint64_t*>(a));if(value){*static_cast<kad6::K6SourceLease*>(b)=*value;*static_cast<bool*>(c)=true;}return true;} case LiveTunnelGatewayStoreOperation::ActiveSize:*static_cast<std::size_t*>(a)=leases.ActiveSize();return true; case LiveTunnelGatewayStoreOperation::CanPublish:*static_cast<bool*>(b)=leases.CanPublish(*static_cast<std::uint64_t*>(a));return true; case LiveTunnelGatewayStoreOperation::CanAccept:*static_cast<bool*>(b)=leases.CanAccept(*static_cast<std::uint64_t*>(a));return true;
    case LiveTunnelGatewayStoreOperation::AddBound:*static_cast<kad6::Kad6Status*>(f)=leases.AddBound(*static_cast<std::uint32_t*>(a),*static_cast<kad6::Hash16*>(b),*static_cast<kad6::K6SourceBind*>(c),*static_cast<kad6::K6SourceBound*>(d),*static_cast<std::uint64_t*>(e));return true; case LiveTunnelGatewayStoreOperation::MarkPublished:*static_cast<kad6::Kad6Status*>(b)=leases.MarkPublished(*static_cast<std::uint64_t*>(a));return true; case LiveTunnelGatewayStoreOperation::MarkServing:*static_cast<kad6::Kad6Status*>(b)=leases.MarkServing(*static_cast<std::uint64_t*>(a));return true; case LiveTunnelGatewayStoreOperation::BeginDrain:*static_cast<kad6::Kad6Status*>(b)=leases.BeginDrain(*static_cast<std::uint64_t*>(a));return true; case LiveTunnelGatewayStoreOperation::Close:*static_cast<bool*>(b)=leases.Close(*static_cast<std::uint64_t*>(a));return true;
    case LiveTunnelGatewayStoreOperation::EraseClosed:*static_cast<std::size_t*>(b)=*static_cast<std::size_t*>(a)==static_cast<std::size_t>(-1)?leases.EraseClosed():leases.EraseClosedSome(*static_cast<std::size_t*>(a));return true; case LiveTunnelGatewayStoreOperation::QueueCircuitTeardown:leases.QueueCircuitTeardown(*static_cast<std::uint32_t*>(a));return true; case LiveTunnelGatewayStoreOperation::DrainQueuedCircuits:*static_cast<std::size_t*>(c)=leases.DrainQueuedCircuits(*static_cast<std::size_t*>(a),static_cast<std::vector<std::uint64_t>*>(b));return true; case LiveTunnelGatewayStoreOperation::Expire:*static_cast<std::size_t*>(d)=leases.ExpireSome(*static_cast<std::uint64_t*>(a),*static_cast<std::size_t*>(b),static_cast<std::vector<std::uint64_t>*>(c));return true; case LiveTunnelGatewayStoreOperation::CohortRegister:*static_cast<bool*>(b)=cohorts.Register(*static_cast<kad6::K6CohortBackend*>(a));return true;
    case LiveTunnelGatewayStoreOperation::CohortSetServing:*static_cast<bool*>(c)=cohorts.SetServing(*static_cast<std::uint64_t*>(a),*static_cast<bool*>(b));return true; case LiveTunnelGatewayStoreOperation::CohortSelect:*static_cast<bool*>(e)=cohorts.Select(*static_cast<kad6::Hash16*>(a),*static_cast<kad6::Hash16*>(b),*static_cast<std::uint64_t*>(c),*static_cast<kad6::K6CohortBackend*>(d));return true; case LiveTunnelGatewayStoreOperation::CohortReleaseStream:*static_cast<bool*>(b)=cohorts.ReleaseStream(*static_cast<std::uint64_t*>(a));return true; case LiveTunnelGatewayStoreOperation::AdmissionPermille:*static_cast<std::uint32_t*>(b)=budget.AdmissionPermille(*static_cast<std::uint64_t*>(a));return true; case LiveTunnelGatewayStoreOperation::Admit:*static_cast<bool*>(c)=budget.Admit(*static_cast<kad6::K6PublishBudgetKey*>(a),*static_cast<std::uint64_t*>(b));return true;
    case LiveTunnelGatewayStoreOperation::NoteOverload:budget.NoteOverload(*static_cast<std::uint64_t*>(a));return true; case LiveTunnelGatewayStoreOperation::Enqueue:*static_cast<bool*>(d)=coalescer.Enqueue(*static_cast<kad6::K6PublishSchedule*>(a),*static_cast<std::uint32_t*>(b),*static_cast<std::uint64_t*>(c));return true; case LiveTunnelGatewayStoreOperation::TakeDue:*static_cast<std::vector<kad6::K6PublishSchedule>*>(c)=coalescer.TakeDue(*static_cast<std::uint64_t*>(a),*static_cast<std::size_t*>(b));return true; case LiveTunnelGatewayStoreOperation::Remove:*static_cast<bool*>(b)=coalescer.Remove(*static_cast<std::uint64_t*>(a));return true; case LiveTunnelGatewayStoreOperation::PublishExpire:*static_cast<std::size_t*>(b)=coalescer.Expire(*static_cast<std::uint64_t*>(a));return true;
    } return false;
}

IMPLEMENT_DYNCREATE(CKad6ExitSocket,CClientReqSocket)
IMPLEMENT_DYNCREATE(CKad6OriginSocket,CClientReqSocket)

CKad6ExitSocket::CKad6ExitSocket() : CClientReqSocket(NULL) {}
CKad6OriginSocket::CKad6OriginSocket() : CClientReqSocket(NULL) {}

void CKad6ExitSocket::Initialize(std::uint64_t streamId){m_streamId=streamId;}

void CKad6ExitSocket::InitializeInboundFrontDoor(){
    m_inboundFrontDoor=true;m_inboundBypass=false;m_streamId=0;
    m_inboundFrames.clear();m_inboundFrameBytes=0;
}

bool CKad6ExitSocket::BindInboundStream(std::uint64_t streamId){
    if(!m_inboundFrontDoor||m_inboundBypass||m_streamId||!streamId)return false;
    m_streamId=streamId;m_inboundFrames.clear();m_inboundFrameBytes=0;return true;
}

bool CKad6ExitSocket::SendRawFrame(const uint8_t* frame,std::size_t length){
    kad6::K6Ed2kFrameView view;
    if(kad6::DecodeK6Ed2kFrame(frame,length,view)!=kad6::Kad6Status::Ok||!IsConnected())return false;
    Packet* packet=new Packet(view.opcode,view.payload_size,view.protocol,false);
    if(view.payload_size)memcpy(packet->pBuffer,view.payload,view.payload_size);
    CClientReqSocket::SendPacket(packet,true);
    return true;
}

bool CKad6ExitSocket::SetKad6ReadPaused(bool paused){
    if(m_kad6ReadPaused==paused)return true;
    const long events=FD_WRITE|FD_CLOSE|FD_CONNECT|(paused?0:FD_READ);
    if(!AsyncSelect(events))return false;
    m_kad6ReadPaused=paused;
    if(!paused)OnReceive(0);
    return true;
}

void CKad6ExitSocket::OnConnect(int error){
    const std::uint64_t stream=m_streamId;
    CClientReqSocket::OnConnect(error);
    // A superseded IPv6 error is not the result of this logical dial. The base
    // keeps SS_Half while its one-shot IPv4 retry is pending; report only the
    // final success or error delivered by that attempt.
    if(IsConnectRetryPending())return;
    if(stream)CLiveTunnel::Get().OnK6ExitSocketConnect(stream,this,error);
}

void CKad6ExitSocket::OnClose(int error){
    const std::uint64_t stream=m_streamId;
    m_streamId=0;
    if(stream)CLiveTunnel::Get().OnK6ExitSocketClosed(stream,this,error);
    CClientReqSocket::OnClose(error);
}

bool CKad6ExitSocket::PacketReceived(Packet* packet){
    if(!packet)return false;
    if(packet->prot==OP_PACKEDPROT){
        if(!packet->UnPackPacket())return false;
    }
    std::vector<uint8_t> raw;
    if(kad6::EncodeK6Ed2kFrame(packet->prot,packet->opcode,
            reinterpret_cast<const uint8_t*>(packet->pBuffer),packet->size,raw)!=kad6::Kad6Status::Ok)
        return false;
    if(m_inboundFrontDoor&&m_streamId==0&&!m_inboundBypass){
        if(m_inboundFrames.size()>=16||m_inboundFrameBytes+raw.size()>64u*1024u){
            m_inboundBypass=true;m_inboundFrames.clear();m_inboundFrameBytes=0;
            return CClientReqSocket::PacketReceived(packet);
        }
        m_inboundFrameBytes+=raw.size();m_inboundFrames.push_back(raw);
        const bool fileRequest=packet->prot==OP_EDONKEYPROT&&
            (packet->opcode==OP_REQUESTFILENAME||packet->opcode==OP_SETREQFILEID)&&
            packet->size>=16;
        if(fileRequest){
            kad6::Hash16 hash{};memcpy(hash.data(),packet->pBuffer,hash.size());
            if(CLiveTunnel::Get().ActivateK6Inbound(this,hash,m_inboundFrames))return true;
            m_inboundBypass=true;m_inboundFrames.clear();m_inboundFrameBytes=0;
            return CClientReqSocket::PacketReceived(packet);
        }
        return CClientReqSocket::PacketReceived(packet);
    }
    if(m_streamId==0)return CClientReqSocket::PacketReceived(packet);
    const bool exitTerminated=packet->prot==OP_EMULEPROT&&
        (packet->opcode==OP_EMULEINFO||packet->opcode==OP_EMULEINFOANSWER||
         packet->opcode==OP_PUBLICKEY||packet->opcode==OP_SIGNATURE||
         packet->opcode==OP_SECIDENTSTATE||packet->opcode==OP_PUBLICIP_REQ);
    if(exitTerminated)return CClientReqSocket::PacketReceived(packet);
    CLiveTunnel& tunnel=CLiveTunnel::Get();
    {
        // Socket callbacks are dispatched on the main thread.  Validate the
        // concrete socket immediately before entering the legacy coordinator
        // signature so a retired socket cannot target a reused stream id.
        CSingleLock pl(&tunnel.m_pendingLock,TRUE);
        K6ExitStreamRuntime active;
        if(!tunnel.m_exitServices.LT5FindExit(m_streamId,this,active))return false;
    }
    return tunnel.OnK6ExitPacket(m_streamId,raw.data(),raw.size());
}

bool CKad6OriginSocket::Initialize(std::uint64_t streamId,CUpDownClient* owner){
    if(!streamId||!owner)return false;m_streamId=streamId;SetClient(owner);
    CEMSocket::SetConState(EMS_CONNECTED);ResetTimeOutTimer();return true;
}

bool CKad6OriginSocket::InitializeInbound(std::uint64_t streamId,
                                          const kad6::K6Endpoint& pseudonymousPeer){
    if(!streamId||pseudonymousPeer.addr.family!=kad6::Kad6Address::Family::IPv4)
        return false;
    m_streamId=streamId;memcpy(&m_pseudonymousPeerV4,
        pseudonymousPeer.addr.addr.data(),sizeof m_pseudonymousPeerV4);SetClient(NULL);
    CEMSocket::SetConState(EMS_CONNECTED);ResetTimeOutTimer();return true;
}

uint32 CKad6OriginSocket::GetPeerAddressV4(){return m_pseudonymousPeerV4;}

CAddress CKad6OriginSocket::GetPeerCAddress(){
    return m_pseudonymousPeerV4?CAddress(m_pseudonymousPeerV4,false):CAddress();
}

void CKad6OriginSocket::Disconnect(LPCTSTR reason){
    const std::uint64_t stream=m_streamId;
    m_streamId=0;
    if(stream)CLiveTunnel::Get().OnK6OriginSocketClosed(stream,this);
    CClientReqSocket::Disconnect(reason);
}

void CKad6OriginSocket::SendPacket(Packet* packet,bool controlpacket,uint32 actualPayloadSize,
                                   bool forceImmediate){
    (void)controlpacket;(void)actualPayloadSize;(void)forceImmediate;
    if(!packet)return;
    if(m_suppressReplies){delete packet;return;}
    char* bytes=packet->GetPacket();const std::size_t length=packet->GetRealPacketSize();
    CLiveTunnel& tunnel=CLiveTunnel::Get();
    bool active=false;
    {
        // As above, main-thread serialization makes this source check and the
        // immediately following call one callback transaction.
        CSingleLock pl(&tunnel.m_pendingLock,TRUE);
        K6OriginStreamRuntime runtime;
        active=tunnel.m_exitServices.LT5FindOrigin(m_streamId,this,runtime);
    }
    const bool ok=bytes&&active&&tunnel.K6SendEd2kFrameNoWait(m_streamId,
        reinterpret_cast<const uint8_t*>(bytes),length);
    delete packet;
    if(!ok)Disconnect(_T("Kad6 stream send failed"));
}

bool CKad6OriginSocket::IsBusyQuickCheck() const{
    return m_kad6FlowBlocked||CClientReqSocket::IsBusyQuickCheck();
}

bool CKad6OriginSocket::InjectRawFrame(const uint8_t* frame,std::size_t length,
                                       bool suppressReplies){
    kad6::K6Ed2kFrameView view;
    if(kad6::DecodeK6Ed2kFrame(frame,length,view)!=kad6::Kad6Status::Ok)return false;
    Packet* packet=new Packet(view.opcode,view.payload_size,view.protocol,false);
    if(view.payload_size)memcpy(packet->pBuffer,view.payload,view.payload_size);
    const bool old=m_suppressReplies;m_suppressReplies=suppressReplies;
    const bool ok=CClientReqSocket::PacketReceived(packet);m_suppressReplies=old;
    delete packet;return ok;
}

bool SanitizeK6HelloFrame(const uint8_t* frame,std::size_t length,
                          const kad6::K6Endpoint& apparent,std::vector<uint8_t>& out){
    out.clear();kad6::K6Ed2kFrameView view;
    if(kad6::DecodeK6Ed2kFrame(frame,length,view)!=kad6::Kad6Status::Ok||
       view.protocol!=OP_EDONKEYPROT||(view.opcode!=OP_HELLO&&view.opcode!=OP_HELLOANSWER)||
       apparent.tcp_port==0)return false;
    try{
        CSafeMemFile input(view.payload,view.payload_size),body(256);
        if(view.opcode==OP_HELLO){if(input.ReadUInt8()!=16)return false;body.WriteUInt8(16);}
        uchar userHash[16];input.ReadHash16(userHash);(void)input.ReadUInt32();(void)input.ReadUInt16();
        const uint32 count=input.ReadUInt32();if(count>64)return false;
        body.WriteHash16(userHash);
        uint32 apparentId=0;if(apparent.addr.family==kad6::Kad6Address::Family::IPv4)
            memcpy(&apparentId,apparent.addr.addr.data(),4);
        body.WriteUInt32(apparentId);body.WriteUInt16(apparent.tcp_port);
        const ULONGLONG countPos=body.GetPosition();body.WriteUInt32(0);uint32 kept=0;
        for(uint32 i=0;i<count;++i){
            CTag tag(input,true);const UINT id=tag.GetNameID();
            // Privacy-mode HELLO is allow-list based. Unknown extension tags
            // are not forwarded because a future/private tag may carry A's
            // endpoint or stable Kad6 node identity.
            const bool safe=id==CT_NAME||id==CT_VERSION||id==CT_MOD_VERSION||
                id==CT_EMULECOMPAT_OPTIONS1||id==CT_EMULE_MISCOPTIONS1||
                id==CT_EMULE_MISCOPTIONS2||id==CT_EMULE_VERSION;
            if(!safe)continue;
            if(id==CT_EMULE_MISCOPTIONS2&&tag.IsInt())tag.SetInt(tag.GetInt()&~(1u<<12));
            if(!tag.WriteTagToFile(body,UTF8strRaw))return false;++kept;
        }
        // Advertise only the exit's UDP endpoint; Kad/callback reachability is
        // intentionally zero because this outgoing K6-4 stream grants TCP only.
        CTag udp(CT_EMULE_UDPPORTS,static_cast<uint32>(theApp.GetAdvertisedUdpPort()));
        if(!udp.WriteTagToFile(body)){return false;}++kept;
        if(apparent.addr.family==kad6::Kad6Address::Family::IPv6){
            CTag v6(static_cast<uint8>(0x66),static_cast<size_t>(16),
                reinterpret_cast<const BYTE*>(apparent.addr.addr.data()));
            if(!v6.WriteTagToFile(body)){return false;}++kept;
            CTag forkCaps(CT_FORK_CAPABILITIES,static_cast<uint32>(CAP_FORK_IPV6_WIRE));
            if(!forkCaps.WriteTagToFile(body)){return false;}++kept;
        }
        const uint32 ignoredServer=input.ReadUInt32();const uint16 ignoredPort=input.ReadUInt16();
        (void)ignoredServer;(void)ignoredPort;if(input.GetPosition()!=input.GetLength())return false;
        body.WriteUInt32(0);body.WriteUInt16(0);const ULONGLONG end=body.GetPosition();
        body.Seek(countPos,CFile::begin);body.WriteUInt32(kept);body.Seek(end,CFile::begin);
        Packet packet(body,OP_EDONKEYPROT,view.opcode);char* raw=packet.GetPacket();
        out.assign(reinterpret_cast<uint8_t*>(raw),reinterpret_cast<uint8_t*>(raw)+packet.GetRealPacketSize());
        return true;
    }catch(CFileException* e){e->Delete();}catch(...){}
    return false;
}

bool CKad6OriginSocket::LT3ExecuteSearchReply( CLiveTunnel& host, const std::shared_ptr<CLiveCircuit>& circ, const kad6::K6Frame& frame, const std::vector<uint8_t>& wire)
{
    if(!circ)return false;const uint32_t req_id=frame.request_id;size_t consumed=0;
    if(frame.msg_type==kad6::kK6MsgAccept){
        if((frame.flags&kad6::kK6FlagFinal)==0)return false;
        kad6::K6DialResult accepted;
        if(kad6::DecodeK6DialResult(frame.body.data(),frame.body.size(),accepted,&consumed)!=kad6::Kad6Status::Ok||consumed!=frame.body.size()||accepted.status!=kad6::K6DialStatus::Ok||!accepted.stream_id)return false;
        auto* socket=new CKad6OriginSocket();
        if(!socket->InitializeInbound(accepted.stream_id,accepted.remote_endpoint)){socket->Safe_Delete();return false;}
        {
            CSingleLock pl(&host.m_pendingLock, TRUE);
            K6OriginStreamRuntime runtime;runtime.circ_id=circ->Id();runtime.dial=accepted;runtime.socket=socket;
            runtime.flow=kad6::K6StreamFlowState(accepted.max_bytes);runtime.initial_data_sent=true;
            runtime.last_activity=static_cast<uint64>(time(NULL));runtime.idle_deadline=runtime.last_activity+((accepted.idle_timeout_ms+999u)/1000u);
            if(!host.m_exitServices.LT5CreateOrigin(accepted.stream_id,runtime)){pl.Unlock();socket->Safe_Delete();return false;}
        }
        if(!host.SendK6InitialCredit(circ->Id(),accepted.stream_id,1,circ,false)){
            CSingleLock pl(&host.m_pendingLock, TRUE);
            K6OriginStreamRuntime failed;if(host.m_exitServices.LT5FindOrigin(accepted.stream_id,socket,failed))host.m_exitServices.LT5TakeOrigin(accepted.stream_id,socket,failed.generation,failed);
            pl.Unlock();socket->Safe_Delete();return false;
        }
        LIVE_LOG("K6","inbound ACCEPT stream=%llu circuit=%u",static_cast<unsigned long long>(accepted.stream_id),circ->Id());return true;
    }
    if(frame.msg_type==kad6::kK6MsgQuotaKey){
        if((frame.flags&kad6::kK6FlagFinal)==0)return false;
        kad6::K6QuotaIssuerCertificate certificate;
        if(kad6::DecodeK6QuotaIssuerCertificate(frame.body.data(),frame.body.size(),certificate,&consumed)!=kad6::Kad6Status::Ok||consumed!=frame.body.size()||kad6::VerifyK6QuotaIssuerCertificate(MakeKad6HostCryptoHooks(),certificate,kad6::K6QuotaEpoch(static_cast<uint64>(time(NULL))))!=kad6::Kad6Status::Ok)return false;
        const uint8_t* expected=circ->HopCount()>=2&&circ->m_expectedNodePub2Set?circ->m_expectedNodePub2:circ->m_expectedNodePubSet?circ->m_expectedNodePub:NULL;
        if(!expected||!kad6::Kad6CtEqual(expected,certificate.issuer_node_pub.data(),32))return false;
        host.SignalReply(req_id,wire.data(),wire.size(),0);return true;
    }
    if(frame.msg_type==kad6::kK6MsgQuotaIssued){
        kad6::K6QuotaBlindResponse response;consumed=0;
        if((frame.flags&kad6::kK6FlagFinal)==0||kad6::DecodeK6QuotaBlindResponse(frame.body.data(),frame.body.size(),response,&consumed)!=kad6::Kad6Status::Ok||consumed!=frame.body.size())return false;
        host.SignalReply(req_id,wire.data(),wire.size(),0);return true;
    }
    if(frame.msg_type==kad6::kK6MsgQuotaStatus){
        kad6::K6QuotaPresentationResult response;consumed=0;
        if((frame.flags&kad6::kK6FlagFinal)==0||kad6::DecodeK6QuotaPresentationResult(frame.body.data(),frame.body.size(),response,&consumed)!=kad6::Kad6Status::Ok||consumed!=frame.body.size())return false;
        host.SignalReply(req_id,wire.data(),wire.size(),0);return true;
    }
    if(frame.msg_type==kad6::kK6MsgVep){
        kad6::K6VirtualIdentityEndpoint vep;consumed=0;
        if(kad6::DecodeK6Vep(frame.body.data(),frame.body.size(),vep,&consumed)!=kad6::Kad6Status::Ok||consumed!=frame.body.size()||kad6::VerifyK6Vep(MakeKad6HostCryptoHooks(),vep,static_cast<uint64_t>(time(NULL)))!=kad6::Kad6Status::Ok)return false;
        const uint8_t* expected=circ->HopCount()>=2&&circ->m_expectedNodePub2Set?circ->m_expectedNodePub2:circ->m_expectedNodePubSet?circ->m_expectedNodePub:NULL;
        if(!expected||memcmp(expected,vep.exit_node_pub.data(),32)!=0)return false;
        CUpDownClient* client=NULL;uint32 ip=0;{CSingleLock pl(&host.m_pendingLock,TRUE);K6OriginStreamRuntime stream;
        if(!host.m_exitServices.LT5FindOrigin(vep.source_lease_id,stream))return false;CKad6OriginSocket* expectedSocket=stream.socket;const uint64 generation=stream.generation;
        stream.vep=vep;stream.has_vep=true;client=stream.client;if(!host.m_exitServices.LT5UpdateOrigin(vep.source_lease_id,expectedSocket,generation,stream))return false;}
        if(client&&vep.apparent_source_ip.family==kad6::Kad6Address::Family::IPv4){memcpy(&ip,vep.apparent_source_ip.addr.data(),4);client->SetK6SecureIdentVepIPv4(ip);}
        return true;
    }
    if(frame.msg_type==kad6::kK6MsgSourceHints){
        kad6::K6SourceHints hints;consumed=0;
        if(kad6::DecodeK6SourceHints(frame.body.data(),frame.body.size(),hints,&consumed)!=kad6::Kad6Status::Ok||consumed!=frame.body.size())return false;
        CSingleLock pl(&host.m_pendingLock, TRUE);
        K6OriginStreamRuntime stream;if(!host.m_exitServices.LT5FindOrigin(hints.source_stream_id,stream)||stream.hints.size()>=32)return false;
        CKad6OriginSocket* expected=stream.socket;const uint64 generation=stream.generation;stream.hints.push_back(std::move(hints));
        return host.m_exitServices.LT5UpdateOrigin(hints.source_stream_id,expected,generation,stream);
    }
    if(frame.msg_type==kad6::kK6MsgMaxStreamData){
        kad6::K6MaxStreamData credit;consumed=0;
        if(kad6::DecodeK6MaxStreamData(frame.body.data(),frame.body.size(),credit,&consumed)!=kad6::Kad6Status::Ok||consumed!=frame.body.size()||credit.direction)return false;
        {
            CSingleLock pl(&host.m_pendingLock, TRUE);
            K6OriginStreamRuntime stream;
            if(!host.m_exitServices.LT5FindOrigin(credit.stream_id,stream)||stream.circ_id!=circ->Id()||!host.m_exitServices.LT5Grant(circ->Id(),credit))
                return false;
        }
        host.FlushK6OriginCredit(circ->Id());return true;
    }
    if(frame.msg_type==kad6::kK6MsgMaxData){
        kad6::K6MaxData credit;consumed=0;
        if(kad6::DecodeK6MaxData(frame.body.data(),frame.body.size(),credit,&consumed)!=kad6::Kad6Status::Ok||consumed!=frame.body.size()||credit.direction)return false;
        {
            CSingleLock pl(&host.m_pendingLock, TRUE);
            if(!host.m_exitServices.LT5Grant(circ->Id(),credit))
                return false;
        }
        host.FlushK6OriginCredit(circ->Id());return true;
    }
    if(frame.msg_type==kad6::kK6MsgStreamData){
        kad6::K6StreamData data;consumed=0;
        if(kad6::DecodeK6StreamData(frame.body.data(),frame.body.size(),data,&consumed)!=kad6::Kad6Status::Ok||consumed!=frame.body.size()||data.direction!=1||(data.flags&0x02)==0)return false;
        kad6::K6Ed2kFrameView inboundView;
        if(kad6::DecodeK6Ed2kFrame(data.data.data(),data.data.size(),inboundView)!=kad6::Kad6Status::Ok)return false;
        const bool suppressHandshakeReply=kad6::ClassifyK6Ed2kFrame(inboundView.protocol,inboundView.opcode)==kad6::K6Ed2kFrameClass::Hello;
        CKad6OriginSocket* socket=NULL;
        {
            CSingleLock pl(&host.m_pendingLock, TRUE);
            K6OriginStreamRuntime stream;if(!host.m_exitServices.LT5FindOrigin(data.stream_id,stream))return false;
            const uint64 maxBytes=stream.dial.max_bytes,txBytes=stream.flow.total_bytes(0),rxBytes=stream.flow.total_bytes(1);
            const bool bufferForAttach=stream.socket==NULL;
            if((maxBytes&&(txBytes>maxBytes||rxBytes>maxBytes-txBytes||stream.queued_tx_bytes>maxBytes-txBytes-rxBytes||data.data.size()>maxBytes-txBytes-rxBytes-stream.queued_tx_bytes))||(bufferForAttach&&(stream.pending_frames.size()>=64||stream.pending_frame_bytes+data.data.size()>256u*1024u))||!host.m_exitServices.LT5CanAccept(circ->Id(),data.stream_id,1,data.data.size())||stream.flow.CanAccept(data)!=kad6::Kad6Status::Ok)
                return false;
            if(!host.m_exitServices.LT5Accept(circ->Id(),data.stream_id,1,data.data.size(),M2A_LT3_K6ShapeNowUs()/1000u)||stream.flow.Accept(data)!=kad6::Kad6Status::Ok)
                return false;
            const uint64 now=static_cast<uint64>(time(NULL)),idle=(stream.dial.idle_timeout_ms+999u)/1000u;
            stream.last_activity=now;stream.idle_deadline=now+idle;socket=stream.socket;
            if(!socket){stream.pending_frame_bytes+=data.data.size();stream.pending_frames.push_back(std::move(data.data));}
            if(!host.m_exitServices.LT5UpdateOrigin(data.stream_id,socket,stream.generation,stream))return false;
            if(!socket)return true;
        }
        const bool injected=socket->InjectRawFrame(data.data.data(),data.data.size(),suppressHandshakeReply);
        if(!injected){socket->Disconnect(_T("Kad6 downstream application rejected frame"));return false;}
        if(injected){
            CSingleLock pl(&host.m_pendingLock, TRUE);
            K6OriginStreamRuntime stream;
            if(host.m_exitServices.LT5FindOrigin(data.stream_id,socket,stream)){stream.client=socket->client;host.m_exitServices.LT5UpdateOrigin(data.stream_id,socket,stream.generation,stream);}
        }
        return host.ConsumeK6ReceiveCredit(circ->Id(),data.stream_id,1,data.data.size(),circ,false);
    }
    if(frame.msg_type==kad6::kK6MsgStreamHalfClose){
        kad6::K6StreamHalfClose close;consumed=0;
        if(kad6::DecodeK6StreamHalfClose(frame.body.data(),frame.body.size(),close,&consumed)!=kad6::Kad6Status::Ok||consumed!=frame.body.size()||close.direction!=1)return false;
        CSingleLock pl(&host.m_pendingLock, TRUE);
        return host.m_exitServices.LT5HalfCloseOrigin(circ->Id(),close);
    }
    if(frame.msg_type==kad6::kK6MsgStreamClose){
        kad6::K6StreamClose close;consumed=0;
        if(kad6::DecodeK6StreamClose(frame.body.data(),frame.body.size(),close,&consumed)!=kad6::Kad6Status::Ok||consumed!=frame.body.size())return false;
        CKad6OriginSocket* socket=NULL;CUpDownClient* client=NULL;
        {
            CSingleLock pl(&host.m_pendingLock, TRUE);
            K6OriginStreamRuntime stream;if(!host.m_exitServices.LT5CloseOrigin(circ->Id(),close,stream))return false;
            socket=stream.socket;client=stream.client;
        }
        if(client)client->ClearK6SecureIdentVep();if(socket)socket->Disconnect(_T("Kad6 remote stream closed"));return true;
    }
    if (frame.msg_type == kad6::kK6MsgDialOk) {
        if ((frame.flags & kad6::kK6FlagFinal) == 0) return false;
        kad6::K6DialResult result;consumed=0;
        if(kad6::DecodeK6DialResult(frame.body.data(),frame.body.size(),result,&consumed)!=kad6::Kad6Status::Ok||consumed!=frame.body.size())return false;
        LiveTunnelOriginDownloadActivation activation;
        const bool hasActivation=host.m_kadBridge.LT6TakeDownloadActivation(req_id,circ->Id(),activation);
        auto* activationClient=hasActivation?reinterpret_cast<CUpDownClient*>(activation.client_token):NULL;
        bool streamRegistered=result.status!=kad6::K6DialStatus::Ok;
        if(result.status==kad6::K6DialStatus::Ok){
            CSingleLock pl(&host.m_pendingLock, TRUE);
            if(result.stream_id!=0){
                K6OriginStreamRuntime runtime;runtime.circ_id=circ->Id();runtime.dial=result;
                runtime.flow=kad6::K6StreamFlowState(result.max_bytes);runtime.last_activity=static_cast<uint64>(time(NULL));
                runtime.idle_deadline=runtime.last_activity+((result.idle_timeout_ms+999u)/1000u);
                streamRegistered=host.m_exitServices.LT5CreateOrigin(result.stream_id,runtime);
            }
        }
        if(result.status==kad6::K6DialStatus::Ok&&streamRegistered&&!host.SendK6InitialCredit(circ->Id(),result.stream_id,1,circ,false)){
            CSingleLock pl(&host.m_pendingLock, TRUE);
            K6OriginStreamRuntime failed;if(host.m_exitServices.LT5FindOrigin(result.stream_id,failed))host.m_exitServices.LT5TakeOrigin(result.stream_id,failed.socket,failed.generation,failed);
            streamRegistered=false;
        }
        if(hasActivation){
            if(activationClient&&result.status==kad6::K6DialStatus::Ok&&streamRegistered&&host.K6AttachOriginClient(result.stream_id,activationClient)){
                LIVE_LOG("K6","download stream attached req=%u stream=%llu",req_id,static_cast<unsigned long long>(result.stream_id));return true;
            }
            if(streamRegistered&&result.status==kad6::K6DialStatus::Ok){
                K6OriginStreamRuntime orphan;bool found=false;
                {
                    CSingleLock pl(&host.m_pendingLock, TRUE);
                    K6OriginStreamRuntime stream;
                    if(host.m_exitServices.LT5FindOrigin(result.stream_id,stream)&&!stream.socket)
                        found=host.m_exitServices.LT5TakeOrigin(result.stream_id,NULL,stream.generation,orphan);
                }
                if(found){
                    kad6::K6StreamClose close;close.stream_id=result.stream_id;close.reason_code=1;
                    std::vector<uint8_t> closeBody, closeWire;
                    kad6::K6Frame closeFrame;closeFrame.msg_type=kad6::kK6MsgStreamClose;closeFrame.flags=kad6::kK6FlagLegacyEd2k|kad6::kK6FlagFinal;closeFrame.request_id=host.NewCircuitId();
                    if(kad6::EncodeK6StreamClose(close,closeBody)==kad6::Kad6Status::Ok){
                        closeFrame.body=std::move(closeBody);
                        if(kad6::EncodeK6Frame(closeFrame,closeWire)==kad6::Kad6Status::Ok)host.SendMessagePinned(closeFrame.request_id,CLiveTunnel::TUN_OP_KAD6_GATEWAY,closeWire.data(),closeWire.size(),ESE_CAP_KAD6,orphan.circ_id);
                    }
                }
            }
            if(activationClient&&activationClient->Disconnected(_T("Kad6 gateway DIAL failed")))delete activationClient;
            return true;
        }
        if(!streamRegistered)return false;host.SignalReply(req_id,wire.data(),wire.size(),0);return true;
    }
    if(frame.msg_type==kad6::kK6MsgTargetTicket){
        kad6::K6TargetTicketResponse response;consumed=0;
        if((frame.flags&kad6::kK6FlagFinal)==0||kad6::DecodeK6TargetTicketResponse(frame.body.data(),frame.body.size(),response,&consumed)!=kad6::Kad6Status::Ok||consumed!=frame.body.size())return false;
        host.SignalReply(req_id,wire.data(),wire.size(),0);return true;
    }
    if(frame.msg_type==kad6::kK6MsgSourceBound||frame.msg_type==kad6::kK6MsgPublishAck){
        if((frame.flags&kad6::kK6FlagFinal)==0||(frame.flags&kad6::kK6FlagMore))return false;
        if(frame.msg_type==kad6::kK6MsgSourceBound){
            kad6::K6SourceBound value;consumed=0;
            if(kad6::DecodeK6SourceBound(frame.body.data(),frame.body.size(),value,&consumed)!=kad6::Kad6Status::Ok||consumed!=frame.body.size())return false;
        }else{
            kad6::K6PublishAck value;consumed=0;
            if(kad6::DecodeK6PublishAck(frame.body.data(),frame.body.size(),value,&consumed)!=kad6::Kad6Status::Ok||consumed!=frame.body.size())return false;
        }
        host.SignalReply(req_id,wire.data(),wire.size(),0);return true;
    }
    const uint64_t key = LiveRequestKey(circ->Id(), req_id);
    if (frame.msg_type == kad6::kK6MsgSearchResult) {
        if ((frame.flags & kad6::kK6FlagMore) == 0 || (frame.flags & kad6::kK6FlagFinal) != 0)
            return false;
        kad6::K6SearchResult result;
        consumed = 0;
        if (kad6::DecodeK6SearchResult(frame.body.data(), frame.body.size(), result, &consumed) != kad6::Kad6Status::Ok || consumed != frame.body.size())
            return false;
        if (result.result_kind == kad6::kK6SearchKindSourceHash) {
            LiveTunnelOriginSourceLookup lookup;
            if(!host.m_kadBridge.LT6BindSourceLookup(req_id,circ->Id(),lookup))return false;
            bool materialized=false;
            for(const auto& ticket:result.tickets){
                if(ticket.service!=static_cast<kad6::Byte>(kad6::K6TicketService::Ed2kTcp)||(ticket.provenance_kind!=static_cast<kad6::Byte>(kad6::K6Provenance::KadResult)&&ticket.provenance_kind!=static_cast<kad6::Byte>(kad6::K6Provenance::Routing))||ticket.provenance_session!=circ->Id()||ticket.provenance_stream!=req_id||ticket.object_hash!=lookup.file_hash||ticket.max_connections!=1||!ticket.max_bytes||ticket.expires_at<=static_cast<uint64>(time(NULL))||!ticket.target_endpoint.tcp_port)continue;
                std::vector<uint8_t> ticketWire;
                if(kad6::EncodeK6TargetTicket(ticket,ticketWire)!=kad6::Kad6Status::Ok)continue;
                Kademlia::CUInt128 contact(result.result_id.data()),buddy;uint32 ip=0;
                CAddress sourceV6;const CAddress* sourceV6Ptr=NULL;
                if(ticket.target_endpoint.addr.family==kad6::Kad6Address::Family::IPv4)memcpy(&ip,ticket.target_endpoint.addr.addr.data(),4);
                else if(ticket.target_endpoint.addr.family==kad6::Kad6Address::Family::IPv6){
                    sourceV6=CAddress(ticket.target_endpoint.addr.addr.data());
                    if(sourceV6.GetType()!=CAddress::IPv6||!sourceV6.IsPublicIP())continue;
                    sourceV6Ptr=&sourceV6;ip=0x01000001u;
                }else continue;
                if(!theApp.downloadqueue)return false;
                theApp.downloadqueue->KademliaSearchFile(req_id,&contact,&buddy,1,ip,ticket.target_endpoint.tcp_port,ticket.target_endpoint.udp_port,0,0,0,0,sourceV6Ptr,&ticketWire);
                materialized=true;break;
            }
            if(materialized)host.m_kadBridge.LT6NoteSourceLookupResult(req_id);
            return materialized;
        }
        if (!host.m_pendingRequests.IsLive(req_id)) return false;
        kad6::K6LiveSearchMetadata live;
        if (kad6::ParseK6LiveSearchResult(result, live) != kad6::Kad6Status::Ok || !result.tickets.empty())
            return false;
        std::vector<uint8_t> one;
        if (!M2A_LT3_AppendLegacyK6Result(live, one)) return false;
        one[0] = 1;
        one[1] = 0;
        one[2] = 0x02;
        one[3] = 0;
        {
            CSingleLock pl(&host.m_pendingLock, TRUE);
            auto& agg=host.m_k6SearchReplies[key];
            if(agg.legacy.empty()){agg.legacy.assign(4,0);agg.started=GetTickCount();}
            if(agg.count>=kad6::kK6SearchMaxResults||agg.legacy.size()+one.size()-4>TUN_MSG_MAX_BYTES)return false;
            agg.legacy.insert(agg.legacy.end(),one.begin()+4,one.end());
            ++agg.count;
            LiveTunnelOriginTargetRoute route;route.circuit_id=circ->Id();route.source_request_id=req_id;
            route.expires_at=static_cast<uint64>(time(NULL))+120;
            host.m_kadBridge.LT6AddTargetRoute(host.K6AuthorizedTargetKey(0,req_id,result.result_id),route);
            host.m_kadBridge.LT6AddLiveRoute(host.K6BinaryKey(result.result_id.data(),result.result_id.size()),route);
        }
        if (theApp.liveStreamManager)
            theApp.liveStreamManager->GetKadBridge().FeedTunneledSearchResults(one);
        return true;
    }
    if (frame.msg_type == kad6::kK6MsgSearchEnd) {
        if ((frame.flags & kad6::kK6FlagFinal) == 0 || (frame.flags & kad6::kK6FlagMore) != 0)
            return false;
        kad6::K6SearchEnd end;
        consumed = 0;
        if (kad6::DecodeK6SearchEnd(frame.body.data(), frame.body.size(), end, &consumed) != kad6::Kad6Status::Ok || consumed != frame.body.size())
            return false;
        uint16 sourceReceived=0;
        LiveTunnelOriginSourceLookup lookup;
        const bool sourceLookup=host.m_kadBridge.LT6TakeSourceLookup(req_id,circ->Id(),lookup);
        if(sourceLookup){
            sourceReceived=lookup.received;
            if(theApp.downloadqueue){CPartFile* file=theApp.downloadqueue->GetFileByKadFileSearchID(req_id);if(file)file->SetKadFileSearchID(0);}
            return sourceReceived==end.result_count;
        }
        if (!host.m_pendingRequests.IsLive(req_id)) return false;
        std::vector<uint8_t> legacy(4, 0);
        uint16_t count=0;
        {
            CSingleLock pl(&host.m_pendingLock, TRUE);
            auto it=host.m_k6SearchReplies.find(key);
            if(it!=host.m_k6SearchReplies.end()){
                legacy=std::move(it->second.legacy);count=it->second.count;
                host.m_k6SearchReplies.erase(it);
            }
        }
        if(count!=end.result_count)return false;
        legacy[0]=(uint8_t)count;legacy[1]=(uint8_t)(count>>8);legacy[2]=0x02;legacy[3]=0;
        host.SignalReply(req_id,legacy.data(),legacy.size(),0);return true;
    }
    return false;
}
void CKad6OriginSocket::LT3ExecuteExitGateway( CLiveTunnel& host, const LiveTunnelRequestCtx& ctx, const kad6::K6Frame& frame)
{
    if (!thePrefs.GetEseV9Experimental() || (g_uEseCapsRuntime & ESE_CAP_KAD6) == 0 || !ctx.circ)
        return;
    size_t consumed = 0;
    switch (frame.msg_type) {
    case kad6::kK6MsgQuotaKeyReq:
        host.ExitHandle_Kad6QuotaKey(ctx, frame);
        return;
    case kad6::kK6MsgQuotaIssue:
        host.ExitHandle_Kad6QuotaIssue(ctx, frame);
        return;
    case kad6::kK6MsgQuotaPresent:
        host.ExitHandle_Kad6QuotaPresent(ctx, frame);
        return;
    case kad6::kK6MsgSourceBind:
        host.ExitHandle_Kad6SourceBind(ctx, frame);
        return;
    case kad6::kK6MsgSourceUnbind:
        host.ExitHandle_Kad6SourceUnbind(ctx, frame);
        return;
    case kad6::kK6MsgPublish:
        host.ExitHandle_Kad6Publish(ctx, frame);
        return;
    case kad6::kK6MsgUnpublish:
        host.ExitHandle_Kad6Unpublish(ctx, frame);
        return;
    case kad6::kK6MsgTargetTicketReq:
        host.ExitHandle_Kad6TargetTicketReq(ctx, frame);
        return;
    case kad6::kK6MsgDial:
        host.ExitHandle_Kad6Dial(ctx, frame);
        return;
    case kad6::kK6MsgStreamData:
        host.ExitHandle_Kad6StreamData(ctx, frame);
        return;
    case kad6::kK6MsgStreamHalfClose:
        host.ExitHandle_Kad6StreamHalfClose(ctx, frame);
        return;
    case kad6::kK6MsgStreamClose:
        host.ExitHandle_Kad6StreamClose(ctx, frame);
        return;
    case kad6::kK6MsgMaxStreamData:
        host.ExitHandle_Kad6MaxStreamData(ctx, frame);
        return;
    case kad6::kK6MsgMaxData:
        host.ExitHandle_Kad6MaxData(ctx, frame);
        return;
    case kad6::kK6MsgSearchStart:
        break;
    default:
        return;
    }
    kad6::K6SearchStart start;
    consumed = 0;
    if (kad6::DecodeK6SearchStart(frame.body.data(), frame.body.size(), start, &consumed) != kad6::Kad6Status::Ok || consumed != frame.body.size())
        return;
    if (!host.BeginExitOperation( ctx, CLiveTunnel::TUN_OP_KAD6_GATEWAY)) return;
    auto finishNow = [&](kad6::K6SearchEndStatus status) {
        kad6::K6SearchEnd end;
        end.status = status;
        std::vector<uint8_t> endBody, endWire;
        if (kad6::EncodeK6SearchEnd(end, endBody) != kad6::Kad6Status::Ok) {
            host.AbortExitOperation(ctx.circ->Id(), ctx.req_id);
            return;
        }
        kad6::K6Frame response;
        response.msg_type = kad6::kK6MsgSearchEnd;
        response.flags = kad6::kK6FlagResponse | kad6::kK6FlagFinal | kad6::kK6FlagLegacyKad2;
        response.request_id = ctx.req_id;
        response.body = std::move(endBody);
        if (kad6::EncodeK6Frame(response, endWire) != kad6::Kad6Status::Ok) {
            host.AbortExitOperation(ctx.circ->Id(), ctx.req_id);
            return;
        }
        host.CompleteExitOperation(ctx.circ->Id(), ctx.req_id, endWire.data(), endWire.size());
    };
    if (!host.ConsumeK6QuotaGrant(ctx, kad6::K6QuotaService::Control, frame)) {
        finishNow(kad6::K6SearchEndStatus::PolicyDenied);
        return;
    }
    if (!host.m_scheduler.LT2HardeningCanAdmit(kad6::K6Service::Control)) {
        const uint64 now = static_cast<uint64>(time(NULL));
        host.m_metrics.Add(kad6::K6MetricFamily::ExitRejectTotal, 8, 0, 0, 1, now);
        host.m_metrics.Add(kad6::K6MetricFamily::SearchTotal, 0, 1, 0, 1, now);
        finishNow(kad6::K6SearchEndStatus::PolicyDenied);
        return;
    }
    if ((start.search_kind != kad6::kK6SearchKindLive && start.search_kind != kad6::kK6SearchKindSourceHash) || (start.search_kind == kad6::kK6SearchKindLive && start.network_mask != kad6::kK6NetMaskKad2) || !start.options.empty()) {
        finishNow(kad6::K6SearchEndStatus::PolicyDenied);
        return;
    }
    if (start.search_kind == kad6::kK6SearchKindSourceHash) {
        if (!start.query.empty()) {
            finishNow(kad6::K6SearchEndStatus::PolicyDenied);
            return;
        }
        CLiveTunnel::TunnelSearchJob job;
        job.circ_id = ctx.circ->Id();
        job.req_id = ctx.req_id;
        job.canonicalK6 = true;
        job.searchKind = kad6::kK6SearchKindSourceHash;
        job.targetHash = start.target_hash;
        job.maxResults = start.max_results;
        job.networkMask = start.network_mask;
        job.started = GetTickCount();
        job.deadline = job.started + (std::min<DWORD>)(TUN_SEARCH_WINDOW_MS, (DWORD)start.deadline_ms);
        const bool wantKad2 = (start.network_mask & kad6::kK6NetMaskKad2) != 0;
        const bool wantKad6 = (start.network_mask & kad6::kK6NetMaskKad6) != 0;
        const bool kad2Reachable = wantKad2 && Kademlia::CKademlia::IsConnected();
        job.kadReachable = kad2Reachable;
        Kademlia::CUInt128 target(start.target_hash.data());
        Kademlia::CSearch* search = kad2Reachable ? Kademlia::CSearchManager::PrepareLookup(Kademlia::CSearch::FILE, false, target) : NULL;
        const uint64_t jobKey = LiveRequestKey(job.circ_id, job.req_id);
        {
            CSingleLock pl(&host.m_pendingLock, TRUE);
            host.m_searchJobs[jobKey] = job;
        }
        if (search != NULL) {
            search->SetK6GatewaySourceLookup(job.circ_id, job.req_id);
            const uint32 searchId = search->GetSearchID();
            const bool started = Kademlia::CSearchManager::StartSearch(search);
            CSingleLock pl(&host.m_pendingLock, TRUE);
            auto registered = host.m_searchJobs.find(jobKey);
            if (registered != host.m_searchJobs.end()) {
                registered->second.lookupStarted = started;
                registered->second.kad2LookupStarted = started;
                if (started) registered->second.kadSearchIds.push_back(searchId);
            }
        }
        bool nativeStarted = false;
        if (wantKad6 && Kademlia::CKademlia::GetUDPListener() != NULL)
            nativeStarted = Kademlia::CKademlia::GetUDPListener()->StartKad6SourceLookup( start.target_hash, job.circ_id, job.req_id, job.maxResults);
        if (nativeStarted) {
            CSingleLock pl(&host.m_pendingLock, TRUE);
            auto registered = host.m_searchJobs.find(jobKey);
            if (registered != host.m_searchJobs.end()) {
                registered->second.lookupStarted = true;
                registered->second.kad6LookupStarted = true;
                registered->second.kadReachable = true;
            }
        }
        return;
    }
    if (start.query.empty() || !kad6::Kad6IsValidUtf8NoNul(start.query.data(), start.query.size())) {
        finishNow(kad6::K6SearchEndStatus::PolicyDenied);
        return;
    }
    const std::string queryUtf8(start.query.begin(), start.query.end());
    CString searchWord = M2A_LT3_EseUtf8CString(queryUtf8);
    searchWord.MakeLower();
    searchWord.Trim();
    const std::vector<uint8_t> normalized = M2A_LT3_EseCStringUtf8(searchWord);
    if (normalized.empty() || normalized.size() != start.query.size() || memcmp(normalized.data(), start.query.data(), normalized.size()) != 0) {
        finishNow(kad6::K6SearchEndStatus::PolicyDenied);
        return;
    }
    const std::string keyword(normalized.begin(), normalized.end());
    Kademlia::CUInt128 expectedTarget;
    const CStringA keywordA(keyword.data(), (int)keyword.size());
    EseLiveGetKeywordHash(keywordA, &expectedTarget);
    uint8_t expectedBytes[16];
    expectedTarget.ToByteArray(expectedBytes);
    if (memcmp(expectedBytes, start.target_hash.data(), sizeof expectedBytes) != 0) {
        finishNow(kad6::K6SearchEndStatus::PolicyDenied);
        return;
    }
    CLiveTunnel::TunnelSearchJob job;
    job.circ_id = ctx.circ->Id();
    job.req_id = ctx.req_id;
    job.keyword = keyword;
    job.canonicalK6 = true;
    job.searchKind = kad6::kK6SearchKindLive;
    job.targetHash = start.target_hash;
    job.maxResults = start.max_results;
    job.started = GetTickCount();
    job.deadline = job.started + (std::min<DWORD>)(TUN_SEARCH_WINDOW_MS, (DWORD)start.deadline_ms);
    job.kadReachable = Kademlia::CKademlia::IsConnected();
    try { job.lookupStarted = host.m_kadBridge.SearchStreams( searchWord, &job.kadSearchIds, /*forceDirect*/true); } catch (...) {}
    CSingleLock pl(&host.m_pendingLock, TRUE);
    host.m_searchJobs[LiveRequestKey(job.circ_id, job.req_id)] = std::move(job);
}
void CKad6OriginSocket::LT3GetHardeningSnapshot( CLiveTunnel& host, LiveK6HardeningRuntimeSnapshot& out)
{
    out = LiveK6HardeningRuntimeSnapshot{};
    out.control = host.m_scheduler.LT2HardeningSnapshot();
    out.metrics = host.m_metrics.WindowInfo(static_cast<uint64>(time(NULL)));
    {
        CSingleLock pl(&host.m_pendingLock, TRUE);
        for (const auto& pair : host.m_kadBridge.LT3SourceLeaseEntries())
            if (pair.second.state != kad6::K6SourceLeaseState::Closed)
                ++out.active_leases;
        out.active_publishes = static_cast<uint64>(
            host.m_exitServices.LT4PublishCount());
        for (const auto& pair : host.m_exitServices.LT5ExitSnapshot()) {
            if (pair.second.inbound) ++out.full_streams;
            else ++out.dial_streams;
        }
        out.source_epoch_store_failed = host.m_kadBridge.LT3SourceEpochStoreFailed();
        host.m_scheduler.LT2FillEconomySnapshot( out.economy_measurement_ready, out.rho, out.economy);
        kad6::K6StrictReleaseEvidence evidence;
        kad6::K6SupplyInputs supply;
        out.strict_recommended = kad6::K6MayRecommendStrictObserved( 0, supply, out.economy[static_cast<size_t>(kad6::K6Service::ExitEd2kFull)], evidence);
    }
    {
        CSingleLock lock(&host.m_lock, TRUE);
        for (const auto& circuit : host.m_circuitRegistry.GetSnapshot())
            if (circuit && circuit->m_traffic_shaping_exposed)
                ++out.shaping_exposed_circuits;
    }
}
bool CKad6OriginSocket::LT3ApplyServiceSwitch( CLiveTunnel& host, kad6::K6Service service, bool enabled, uint32 drainSeconds)
{
    if (static_cast<size_t>(service) >= static_cast<size_t>(kad6::K6Service::Count))
        return false;
    if (enabled && !host.IsK6PublicReleaseEnabled())
        return false;
    const uint64 now = static_cast<uint64>(time(NULL));
    std::array<uint64, static_cast<size_t>(kad6::K6Service::Count)> active{};
    {
        CSingleLock pl(&host.m_pendingLock, TRUE);
        active[static_cast<size_t>(kad6::K6Service::Control)] = static_cast<uint64>(host.m_searchJobs.size());
        for (const auto& pair : host.m_kadBridge.LT3SourceLeaseEntries())
            if (pair.second.state != kad6::K6SourceLeaseState::Closed)
                ++active[static_cast<size_t>(kad6::K6Service::ExitKad)];
        for (const auto& pair : host.m_exitServices.LT5ExitSnapshot())
            ++active[static_cast<size_t>(pair.second.inbound ? kad6::K6Service::ExitEd2kFull : kad6::K6Service::ExitEd2kDial)];
    }
    if (!host.m_scheduler.LT2HardeningSetEnabled(service, enabled, now, drainSeconds, active[static_cast<size_t>(service)]))
        return false;
    std::vector<uint64> stoppedLeases;
    if (!enabled) {
        {
            CSingleLock pl(&host.m_pendingLock, TRUE);
            if (service == kad6::K6Service::ExitKad) {
            std::vector<uint64> leases;
            leases.reserve(host.m_kadBridge.LT3SourceLeaseEntries().size());
            for (const auto& pair : host.m_kadBridge.LT3SourceLeaseEntries())
                if (pair.second.state != kad6::K6SourceLeaseState::Closed)
                    leases.push_back(pair.first);
            for (uint64 lease : leases) {
                host.m_kadBridge.LT3BeginDrain(lease);
                stoppedLeases.push_back(lease);
                if (drainSeconds == 0) host.m_kadBridge.LT3CloseSourceLease(lease);
            }
            for (uint64 id : host.m_exitServices.LT4DisableAll(drainSeconds == 0))
                host.m_kadBridge.LT3PublishRemove(id);
            if (drainSeconds == 0) {
                host.m_kadBridge.LT3EraseClosedSourceLeases(static_cast<size_t>(-1));
            }
            } else if (drainSeconds == 0 && (service == kad6::K6Service::ExitEd2kDial || service == kad6::K6Service::ExitEd2kFull)) {
                for (auto pair : host.m_exitServices.LT5ExitSnapshot()) {
                    const bool matches = pair.second.inbound ? service == kad6::K6Service::ExitEd2kFull : service == kad6::K6Service::ExitEd2kDial;
                    if (matches) {
                        pair.second.kill_switch_close = true;
                        pair.second.idle_deadline = now;
                        host.m_exitServices.LT5UpdateExit(pair.first,pair.second.socket,pair.second.generation,pair.second);
                    }
                }
            }
        }
        for (uint64 lease : stoppedLeases)
            host.m_kadBridge.LT3CohortSetServing(lease, false);
    }
    const kad6::K6HardeningSnapshot snapshot = host.m_scheduler.LT2HardeningSnapshot();
    volatile LONG* caps = reinterpret_cast<volatile LONG*>(&g_uEseCapsRuntime);
    if (snapshot.admission_mask == 0) { ::InterlockedAnd(caps, ~static_cast<LONG>(ESE_CAP_KAD6));
    } else if (thePrefs.GetEseV9Experimental() && NodeIdentityIsPersistent() && Kademlia::CKadV2ModeSelector::Get().GetDefaultMode() != Kademlia::CKadV2Mode::Direct) { ::InterlockedOr(caps, static_cast<LONG>(ESE_CAP_KAD6));
    }
    AddDebugLogLine(false, _T("Kad6 K6-7: service=%hs state=%s drain=%us revision=%llu"), kad6::K6ServiceName(service), enabled ? _T("enabled") : _T("stopped"), drainSeconds, static_cast<unsigned long long>(snapshot.revision));
    return true;
}
void CKad6OriginSocket::LT3SourceUnbind( CLiveTunnel& host, const LiveTunnelRequestCtx& ctx, const kad6::K6Frame& frame)
{
    kad6::K6SourceUnbind unbind;
    size_t consumed = 0;
    if (kad6::DecodeK6SourceUnbind(frame.body.data(), frame.body.size(), unbind, &consumed) != kad6::Kad6Status::Ok || consumed != frame.body.size()) return;
    {
        CSingleLock pl(&host.m_pendingLock, TRUE);
        const auto lease = host.m_kadBridge.LT3FindSourceLease(unbind.source_lease_id);
        if (!lease || lease->circuit_id != ctx.circ->Id() || unbind.source_epoch < lease->bind.source_epoch || !kad6::Kad6CtEqual(unbind.bind_nonce.data(), lease->bind.bind_nonce.data(), 16))
            return;
        host.m_kadBridge.LT3BeginDrain(unbind.source_lease_id);
        for (uint64 id : host.m_exitServices.LT4DisableSource(unbind.source_lease_id))
            host.m_kadBridge.LT3PublishRemove(id);
    }
    host.m_kadBridge.LT3CohortSetServing(unbind.source_lease_id, false);
}
void CKad6OriginSocket::LT3Unpublish( CLiveTunnel& host, const LiveTunnelRequestCtx& ctx, const kad6::K6Frame& frame)
{
    kad6::K6Unpublish value;
    size_t consumed = 0;
    if (kad6::DecodeK6Unpublish(frame.body.data(), frame.body.size(), value, &consumed) != kad6::Kad6Status::Ok || consumed != frame.body.size()) return;
    uint64 sourceLeaseId = 0;
    {
        CSingleLock pl(&host.m_pendingLock, TRUE);
        LiveTunnelPublishRuntime runtime;
        if (!host.m_exitServices.LT4FindPublish(
                value.publish_lease_id, runtime)) return;
        const auto source =
            host.m_kadBridge.LT3FindSourceLease(runtime.source_lease_id);
        if (!source || source->circuit_id != ctx.circ->Id() ||
            runtime.request.record_epoch > value.record_epoch ||
            !kad6::Kad6CtEqual(runtime.request.target_hash.data(), value.target_hash.data(), 16) ||
            !kad6::Kad6CtEqual(runtime.request.source_id.data(), value.source_id.data(), 16)) return;
        host.m_exitServices.LT4DisablePublish(value.publish_lease_id);
        host.m_kadBridge.LT3PublishRemove(value.publish_lease_id);
        sourceLeaseId = runtime.source_lease_id;
        host.m_kadBridge.LT3BeginDrain(sourceLeaseId);
    }
    host.m_kadBridge.LT3CohortSetServing(sourceLeaseId, false);
}
bool CKad6OriginSocket::LT3HasServingLeases(const CLiveTunnel& host)
{
    CSingleLock pl(&host.m_pendingLock, TRUE);
    for (const auto& pair : host.m_kadBridge.LT3SourceLeaseEntries())
        if (host.m_kadBridge.LT3SourceLeaseCanAccept(pair.first)) return true;
    return false;
}
bool CKad6OriginSocket::LT3MarkServing( CLiveTunnel& host, uint64 sourceLeaseId, kad6::K6CohortBackend& backend)
{
    host.m_kadBridge.LT3MarkPublished(sourceLeaseId);
    if (host.m_kadBridge.LT3MarkServing(sourceLeaseId) != kad6::Kad6Status::Ok || !host.m_kadBridge.LT3SourceLeaseCanAccept(sourceLeaseId))
        return false;
    const auto lease = host.m_kadBridge.LT3FindSourceLease(sourceLeaseId);
    if (!lease) return false;
    backend.lease_id = lease->lease_id;
    backend.circuit_id = lease->circuit_id;
    backend.file_hash = lease->bind.file_hash;
    backend.cohort_id = lease->bound.cohort_id;
    backend.serving = true;
    return true;
}
bool CKad6OriginSocket::LT3EnsureEpochsLoaded(CLiveTunnel& host)
{
    if (host.m_kadBridge.LT3SourceEpochStoreInitialized())
        return host.m_kadBridge.LT3SourceEpochStoreHealthy();
    const CString path = thePrefs.GetMuleDirectory(EMULE_CONFIGDIR) + _T("kad6_source_epochs.dat");
    if (GetFileAttributes(path) == INVALID_FILE_ATTRIBUTES)
        return host.m_kadBridge.LT3LoadSourceEpochs({}, false);
    try {
        CFile file;
        if (!file.Open(path, CFile::modeRead | CFile::shareDenyWrite))
            return host.m_kadBridge.LT3LoadSourceEpochs({}, true);
        const ULONGLONG length = file.GetLength();
        const ULONGLONG maximum = 12ull + 8192ull * 40ull;
        if (length < 12 || length > maximum)
            return file.Close(), host.m_kadBridge.LT3LoadSourceEpochs({}, true);
        std::vector<uint8_t> wire(static_cast<size_t>(length));
        const bool read = file.Read(wire.data(), static_cast<UINT>(wire.size())) == wire.size();
        file.Close();
        return host.m_kadBridge.LT3LoadSourceEpochs(read ? wire : std::vector<uint8_t>(), true);
    }
    catch (CFileException* error) {
        error->Delete();
        return host.m_kadBridge.LT3LoadSourceEpochs({}, true);
    }
}
void CKad6OriginSocket::LT3QueueRefreshes(CLiveTunnel& host,uint64 now)
{
    if(!Kademlia::CKademlia::IsKad2Running())return;CSingleLock lock(&host.m_pendingLock,TRUE);auto publishes=host.m_exitServices.LT4PublishSnapshot();auto shadows=host.m_exitServices.LT4ShadowSnapshot();
    for(auto it=shadows.begin();it!=shadows.end();){auto runtime=publishes.find(it->second);const auto lease=runtime==publishes.end()?LT3SourceLeaseValue{}:host.m_kadBridge.LT3FindSourceLease(runtime->second.source_lease_id);if(runtime==publishes.end()||!runtime->second.refresh_enabled||runtime->second.expires_at<=now||!lease||!host.m_kadBridge.LT3SourceLeaseCanPublish(runtime->second.source_lease_id)||host.K6ShadowKey(*lease)!=it->first){host.m_exitServices.LT4ForgetShadow(it->first);it=shadows.erase(it);}else++it;}
    for(const auto& pair:publishes){const auto& r=pair.second;if(!r.refresh_enabled||r.expires_at<=now||(r.request.network_mask&kad6::kK6PublishNetKad2)==0)continue;const auto lease=host.m_kadBridge.LT3FindSourceLease(r.source_lease_id);if(!lease||!host.m_kadBridge.LT3SourceLeaseCanPublish(r.source_lease_id))continue;uint64 primary=0;bool created=false;if(host.m_exitServices.LT4EnsureShadow(host.K6ShadowKey(*lease),r.publish_lease_id,primary,created))host.m_exitServices.LT4SetQueueState(r.publish_lease_id,r.kad2_queued,primary,created&&!r.kad2_queued&&!r.next_refresh_at?now:0);}
    for(const auto& pair:host.m_exitServices.LT4PublishSnapshot()){const auto& r=pair.second;if(r.primary_publish_lease_id!=r.publish_lease_id||!r.refresh_enabled||!r.auto_refresh||r.kad2_queued||!r.next_refresh_at||r.next_refresh_at>now||r.expires_at<=now+kad6::kK6PublishMinTtlSeconds)continue;const auto lease=host.m_kadBridge.LT3FindSourceLease(r.source_lease_id);if(!lease||!host.m_kadBridge.LT3SourceLeaseCanPublish(r.source_lease_id))continue;kad6::K6PublishSchedule s;s.publish_lease_id=r.publish_lease_id;s.target_hash=r.request.target_hash;s.endpoint[0]=static_cast<uint8_t>(lease->bound.endpoint_slot);memcpy(s.endpoint.data()+1,lease->bound.virtual_endpoint.addr.addr.data(),4);s.endpoint[5]=static_cast<uint8_t>(lease->bound.virtual_endpoint.tcp_port);s.endpoint[6]=static_cast<uint8_t>(lease->bound.virtual_endpoint.tcp_port>>8);s.endpoint[7]=static_cast<uint8_t>(lease->bound.virtual_endpoint.udp_port);s.endpoint[8]=static_cast<uint8_t>(lease->bound.virtual_endpoint.udp_port>>8);s.record_class=static_cast<uint8_t>(r.request.record_kind);s.due_at=now;s.expires_at=r.expires_at;uint64 effective=0;const bool queued=host.m_kadBridge.LT3PublishEnqueue(s,30,effective);host.m_exitServices.LT4SetQueueState(r.publish_lease_id,queued,effective,0);}
}
void CKad6OriginSocket::LT3SweepLeases( CLiveTunnel& host, const std::set<uint32_t>& activeCircuits, const std::set<uint32_t>& teardownQueue, uint64 nowSeconds)
{
    const uint64 startedUs = M2A_LT3_K6ShapeNowUs();
    const size_t transitionCap = 256;
    size_t remaining = transitionCap;
    std::vector<uint64_t> stoppedLeases;
    {
        CSingleLock pl(&host.m_pendingLock, TRUE);
        for (uint32_t circuitId : teardownQueue)
            if (activeCircuits.find(circuitId) == activeCircuits.end())
                host.m_kadBridge.LT3QueueCircuitTeardown(circuitId);
        if (remaining != 0 && M2A_LT3_K6ShapeNowUs() - startedUs < 2000) {
            const size_t changed = host.m_kadBridge.LT3DrainQueuedCircuits( remaining, &stoppedLeases);
            remaining -= changed;
        }
        if (remaining != 0 && M2A_LT3_K6ShapeNowUs() - startedUs < 2000) {
            const size_t changed = host.m_kadBridge.LT3ExpireSourceLeases( nowSeconds, remaining, &stoppedLeases);
            remaining -= changed;
        }
        host.m_kadBridge.LT3PublishExpire(nowSeconds);
        for (const auto& pair : host.m_exitServices.LT4PublishSnapshot()) {
            const auto source =
                host.m_kadBridge.LT3FindSourceLease(pair.second.source_lease_id);
            if (pair.second.expires_at <= nowSeconds || !source ||
                source->state == kad6::K6SourceLeaseState::Draining ||
                source->state == kad6::K6SourceLeaseState::Closed) {
                std::vector<LiveTunnelPublishAction> actions;
                host.m_exitServices.LT4RemovePublish(pair.first, actions);
            }
        }
        host.m_kadBridge.LT3EraseClosedSourceLeases(transitionCap);
    }
    for (uint64_t leaseId : stoppedLeases)
        host.m_kadBridge.LT3CohortSetServing(leaseId, false);
}
std::string CKad6OriginSocket::LT4AuthorizedKey(std::uint32_t circId,std::uint32_t requestId,const void* value)
{const auto& id=*static_cast<const kad6::Hash16*>(value);std::string key;key.resize(8+id.size());for(int i=0;i<4;++i){key[i]=static_cast<char>(circId>>(8*i));key[4+i]=static_cast<char>(requestId>>(8*i));}memcpy(&key[8],id.data(),id.size());return key;}
bool CKad6OriginSocket::LT4AllowTarget(std::uint8_t service,const kad6::K6Endpoint& endpoint)
{if(!LiveTunnelTicketPolicy::AllowTarget(service,endpoint,thePrefs.GetPort(),thePrefs.GetWSPort()))return false;if(endpoint.addr.family==kad6::Kad6Address::Family::IPv4){uint32 ip=0;memcpy(&ip,endpoint.addr.addr.data(),4);return IsGoodIPPort(ip,endpoint.tcp_port)&&theApp.ipfilter&&!theApp.ipfilter->IsFiltered(ip)&&(!theApp.clientlist||!theApp.clientlist->IsBannedClient(ip));}if(endpoint.addr.family==kad6::Kad6Address::Family::IPv6){CAddress address(endpoint.addr.addr.data());return address.GetType()==CAddress::IPv6&&address.IsPublicIP();}return false;}
kad6::K6TargetPolicy CKad6OriginSocket::LT4TicketPolicy(CLiveTunnel& host)
{kad6::K6TargetPolicy policy;policy.context=&host;policy.allow_target=&CLiveTunnel::K6AllowTicketTarget;policy.consume_use=&CLiveTunnel::K6ConsumeTicket;return policy;}
bool CKad6OriginSocket::LT4IssueTicket(CLiveTunnel& host,const void* targetValue,std::uint64_t maxBytes,kad6::K6Provenance provenance,std::uint64_t session,std::uint64_t stream,std::uint64_t sequence,std::vector<std::uint8_t>& wire)
{const auto& target=*static_cast<const LiveTunnelAuthorizedTarget*>(targetValue);wire.clear();if(!host.m_exitServices.LT4TicketSecretReady()||!maxBytes)return false;const uint64 now=static_cast<uint64>(time(NULL));kad6::K6TargetTicket ticket;ticket.service=static_cast<kad6::Byte>(kad6::K6TicketService::Ed2kTcp);ticket.provenance_kind=static_cast<kad6::Byte>(provenance);ticket.provenance_flags=target.network_origin==kad6::kK6NetOriginKad6?kad6::kK6ProvenanceFlagNativeKad6:0;ticket.provenance_session=session;ticket.provenance_stream=stream;ticket.provenance_seq=sequence;ticket.provenance_digest=target.digest;ticket.target_endpoint=target.endpoint;ticket.target_endpoint.valid_until=now+kad6::kK6TicketMaxTtlSeconds;ticket.object_hash=target.object_hash;ticket.issued_at=now;ticket.expires_at=now+kad6::kK6TicketMaxTtlSeconds;ticket.max_bytes=(std::min<uint64>)(maxBytes,16ull*1024ull*1024ull*1024ull);ticket.max_connections=1;const kad6::Kad6CryptoHooks crypto=MakeKad6HostCryptoHooks();uint8 random[24];if(!crypto.random_bytes||!crypto.random_bytes(random,sizeof random))return false;ticket.lease_id=0;for(int i=0;i<8;++i)ticket.lease_id|=static_cast<uint64>(random[i])<<(8*i);memcpy(ticket.nonce.data(),random+8,16);if(!ticket.lease_id)ticket.lease_id=1;const std::array<uint8_t,32> secret=host.m_exitServices.LT4TicketSecret();return kad6::IssueK6TargetTicket(crypto,host.K6TicketPolicy(),secret.data(),secret.size(),ticket,wire)==kad6::Kad6Status::Ok;}
std::string CKad6OriginSocket::LT4BinaryKey(const std::uint8_t* bytes,std::size_t length){return bytes&&length?std::string(reinterpret_cast<const char*>(bytes),length):std::string();}
std::string CKad6OriginSocket::LT4ShadowKey(const void* value)
{const auto& lease=*static_cast<const kad6::K6SourceLease*>(value);std::string key=CLiveTunnel::K6BinaryKey(lease.bind.file_hash.data(),lease.bind.file_hash.size());key.append(CLiveTunnel::K6BinaryKey(lease.bound.virtual_endpoint.addr.addr.data(),lease.bound.virtual_endpoint.addr.family==kad6::Kad6Address::Family::IPv6?16:4));key.push_back(static_cast<char>(lease.bound.virtual_endpoint.tcp_port&0xff));key.push_back(static_cast<char>(lease.bound.virtual_endpoint.tcp_port>>8));key.push_back(static_cast<char>(lease.bound.virtual_endpoint.udp_port&0xff));key.push_back(static_cast<char>(lease.bound.virtual_endpoint.udp_port>>8));return key;}
void CKad6OriginSocket::LT4SourceBind(CLiveTunnel& host,const LiveTunnelRequestCtx& ctx,const kad6::K6Frame& frame) { kad6::K6SourceBind bind; size_t consumed = 0; if (kad6::DecodeK6SourceBind(frame.body.data(), frame.body.size(), bind, &consumed) != kad6::Kad6Status::Ok || consumed != frame.body.size()) return; if (!host.BeginExitOperation(ctx, CLiveTunnel::TUN_OP_KAD6_GATEWAY)) return;
const kad6::Kad6CryptoHooks crypto = MakeKad6HostCryptoHooks(); const uint8_t* exitPub = NodeIdentityPub(); auto finish = [&](kad6::K6SourceBoundStatus status, kad6::K6SourceBound* accepted) { kad6::K6SourceBound result; if (accepted) result = *accepted; else { result.status = status; result.bind_nonce = bind.bind_nonce; if (exitPub) memcpy(result.exit_node_pub.data(), exitPub, result.exit_node_pub.size()); }
std::vector<uint8_t> body; if (!exitPub || kad6::SignK6SourceBound(crypto, NULL, 0, bind, result, body) != kad6::Kad6Status::Ok) { host.AbortExitOperation(ctx.circ->Id(), ctx.req_id); return; } host.SendK6GatewayResponse(ctx, kad6::kK6MsgSourceBound, body); }; if (!host.ConsumeK6QuotaGrant(ctx, kad6::K6QuotaService::ExitKad, frame)) { finish(kad6::K6SourceBoundStatus::Overloaded, NULL); return; }
if (!host.m_scheduler.LT2HardeningCanAdmit(kad6::K6Service::ExitKad) || !host.K6EconomyAdmit(kad6::K6Service::ExitKad)) { const uint64 now = static_cast<uint64>(time(NULL)); host.m_metrics.Add(kad6::K6MetricFamily::ExitRejectTotal, 8, 0, 0, 1, now); host.m_metrics.Add(kad6::K6MetricFamily::ExitAdmissionTotal, 1, 1, 0, 1, now); finish(kad6::K6SourceBoundStatus::Overloaded, NULL); return; }
if (!exitPub || kad6::VerifyK6CompatProofV1(crypto, bind) != kad6::Kad6Status::Ok) { finish(kad6::K6SourceBoundStatus::BadProof, NULL); return; } if (!host.EnsureK6SourceEpochsLoaded()) return finish(kad6::K6SourceBoundStatus::Overloaded, NULL); { const auto leases = host.m_kadBridge.LT3SourceLeaseEntries(); for (const auto& oldPair : leases) { const auto& old = oldPair.second; if (old.state != kad6::K6SourceLeaseState::Closed &&
old.state != kad6::K6SourceLeaseState::Draining && old.expires_at > static_cast<uint64_t>(time(NULL)) && old.circuit_id == ctx.circ->Id() && old.bind.source_epoch == bind.source_epoch && kad6::Kad6CtEqual(old.bind.bind_nonce.data(), bind.bind_nonce.data(), 16) && kad6::Kad6CtEqual(old.bind.file_hash.data(), bind.file_hash.data(), 16)) { kad6::K6SourceBound copy = old.bound; finish(kad6::K6SourceBoundStatus::Ok, &copy); return;
} } } if (!host.m_kadBridge.LT3CanAcceptSourceEpoch(bind.compat_pub_fingerprint, bind.source_epoch)) return finish(kad6::K6SourceBoundStatus::StaleEpoch, NULL); kad6::K6BindingMode effective = bind.requested_mode; if (effective == kad6::K6BindingMode::Auto) effective = bind.commitment_kind == kad6::K6CommitmentKind::None ? kad6::K6BindingMode::DedicatedVep : kad6::K6BindingMode::Cohort;
if (effective != kad6::K6BindingMode::Cohort || bind.commitment_kind == kad6::K6CommitmentKind::None || (bind.transport_mask & kad6::kK6TransportTcp) == 0 || (bind.flags & kad6::kK6SourceAllowInbound) == 0) { finish(kad6::K6SourceBoundStatus::Unsupported, NULL); return; } { const auto leases = host.m_kadBridge.LT3SourceLeaseEntries(); for (const auto& existingPair : leases) { const auto& existing = existingPair.second;
if (existing.state == kad6::K6SourceLeaseState::Closed || existing.state == kad6::K6SourceLeaseState::Draining || !kad6::Kad6CtEqual(existing.bind.file_hash.data(), bind.file_hash.data(), 16)) continue; if (existing.bind.file_size != bind.file_size || existing.bind.commitment_kind != bind.commitment_kind || !kad6::Kad6CtEqual(existing.bind.content_commitment.data(), bind.content_commitment.data(), 32)) {
finish(kad6::K6SourceBoundStatus::Unsupported, NULL); return; } } } const uint32_t publicIp = theApp.GetPublicIP(); const uint16_t udpPort = theApp.GetAdvertisedUdpPort(); if (publicIp == 0 || theApp.GetAdvertisedTcpPort() == 0 || udpPort == 0) { finish(kad6::K6SourceBoundStatus::Overloaded, NULL); return; } uint8_t randomLease[8]; if (!crypto.random_bytes || !crypto.random_bytes(randomLease, sizeof randomLease)) {
finish(kad6::K6SourceBoundStatus::Overloaded, NULL); return; } { CSingleLock pl(&host.m_pendingLock, TRUE); const uint32_t admission = host.m_kadBridge.LT3PublishAdmissionPermille(static_cast<uint64_t>(time(NULL))); const uint32_t sample = (static_cast<uint32_t>(randomLease[0]) | (static_cast<uint32_t>(randomLease[1]) << 8)) % 1000u; if (host.m_kadBridge.LT3SourceLeaseActiveSize() >= 4096 || sample >= admission) { pl.Unlock();
finish(kad6::K6SourceBoundStatus::Overloaded, NULL); return; } } uint64_t leaseId = 0; for (size_t i = 0; i < sizeof randomLease; ++i) leaseId |= static_cast<uint64_t>(randomLease[i]) << (8 * i); if (leaseId == 0) leaseId = 1; const uint64_t now = static_cast<uint64_t>(time(NULL)); kad6::K6SourceBound bound; bound.status = kad6::K6SourceBoundStatus::Ok; bound.transport_mask = bind.transport_mask; bound.flags = bind.flags;
bound.binding_mode = kad6::K6BindingMode::Cohort; bound.identity_mode = kad6::K6IdentityMode::ExitTerminated;
bound.endpoint_slot = 1; // shared, explicit cohort front-door slot
bound.source_lease_id = leaseId; bound.lifetime_s = (std::min)(bind.requested_lifetime_s, 2u * 60u * 60u); bound.refresh_after_s = (std::max)(1u, bound.lifetime_s / 2u); bound.commitment_kind = bind.commitment_kind; bound.content_commitment = bind.content_commitment; bound.virtual_endpoint.addr.family = kad6::Kad6Address::Family::IPv4; bound.virtual_endpoint.addr.addr = {
static_cast<uint8_t>(publicIp), static_cast<uint8_t>(publicIp >> 8), static_cast<uint8_t>(publicIp >> 16), static_cast<uint8_t>(publicIp >> 24)}; bound.virtual_endpoint.tcp_port = theApp.GetAdvertisedTcpPort(); bound.virtual_endpoint.udp_port = udpPort; bound.virtual_endpoint.transport_flags = kad6::kK6EpTcpEd2k | kad6::kK6EpKad2Gateway | kad6::kK6EpEd2kGateway; bound.virtual_endpoint.valid_until = now + bound.lifetime_s;
bound.exit_apparent_ip = bound.virtual_endpoint.addr; memcpy(bound.exit_node_pub.data(), exitPub, bound.exit_node_pub.size()); bound.bind_nonce = bind.bind_nonce; std::vector<uint8_t> cohortMaterial; static const char cohortLabel[] = "Kad6-Cohort-v1"; cohortMaterial.insert(cohortMaterial.end(), cohortLabel, cohortLabel + sizeof cohortLabel - 1); cohortMaterial.insert(cohortMaterial.end(), exitPub, exitPub + 32);
cohortMaterial.insert(cohortMaterial.end(), bind.file_hash.begin(), bind.file_hash.end()); for (size_t i = 0; i < 8; ++i) cohortMaterial.push_back(static_cast<uint8_t>(bind.file_size >> (8 * i))); cohortMaterial.insert(cohortMaterial.end(), bind.content_commitment.begin(), bind.content_commitment.end()); uint8_t digest[32]; if (!crypto.sha256(cohortMaterial.data(), cohortMaterial.size(), digest)) {
finish(kad6::K6SourceBoundStatus::Overloaded, NULL); return; } memcpy(bound.cohort_id.data(), digest, bound.cohort_id.size()); std::vector<uint8_t> pseudoMaterial(bind.compat_proof.begin(), bind.compat_proof.begin() + 32); pseudoMaterial.insert(pseudoMaterial.end(), bind.bind_nonce.begin(), bind.bind_nonce.end()); if (!crypto.sha256(pseudoMaterial.data(), pseudoMaterial.size(), digest)) {
finish(kad6::K6SourceBoundStatus::Overloaded, NULL); return; } kad6::Hash16 pseudonym{}; memcpy(pseudonym.data(), digest, pseudonym.size()); std::vector<uint8_t> encoded; if (kad6::SignK6SourceBound(crypto, NULL, 0, bind, bound, encoded) != kad6::Kad6Status::Ok) { finish(kad6::K6SourceBoundStatus::Overloaded, NULL); return; } uint64 epochToken = 0; std::vector<uint8_t> epochWire;
if (!host.m_kadBridge.LT3PrepareSourceEpochUpdate(bind.compat_pub_fingerprint, bind.source_epoch, epochToken, epochWire)) return finish(kad6::K6SourceBoundStatus::Overloaded, NULL); bool epochSaved = false; const CString epochPath = (thePrefs.GetMuleDirectory(EMULE_CONFIGDIR)+_T("kad6_source_epochs.dat")), epochTemporary = epochPath + _T(".new"); try {
CFile epochFile(epochTemporary, CFile::modeCreate | CFile::modeWrite | CFile::shareExclusive); epochFile.Write(epochWire.data(), static_cast<UINT>(epochWire.size())); epochFile.Flush(); epochFile.Close(); epochSaved = MoveFileEx(epochTemporary, epochPath, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != FALSE; } catch (CFileException* error) { error->Delete(); }
if (!epochSaved) { DeleteFile(epochTemporary); host.m_kadBridge.LT3RollbackSourceEpochUpdate(epochToken); return finish(kad6::K6SourceBoundStatus::Overloaded, NULL); } if (!host.m_kadBridge.LT3CommitSourceEpochUpdate(epochToken)) return finish(kad6::K6SourceBoundStatus::Overloaded, NULL); { CSingleLock pl(&host.m_pendingLock, TRUE); if (host.m_kadBridge.LT3AddBound(ctx.circ->Id(), pseudonym, bind, bound, now) != kad6::Kad6Status::Ok) {
pl.Unlock(); finish(kad6::K6SourceBoundStatus::Overloaded, NULL); return; } } host.m_metrics.Add(kad6::K6MetricFamily::ExitAdmissionTotal, 1, 0, 0, 1, now); host.SendK6GatewayResponse(ctx, kad6::kK6MsgSourceBound, encoded); }
void CKad6OriginSocket::LT4Publish(CLiveTunnel& host,const LiveTunnelRequestCtx& ctx,const kad6::K6Frame& frame) { kad6::K6Publish publish; size_t consumed = 0; if (kad6::DecodeK6Publish(frame.body.data(), frame.body.size(), publish, &consumed) != kad6::Kad6Status::Ok || consumed != frame.body.size()) return; if (!host.BeginExitOperation(ctx, CLiveTunnel::TUN_OP_KAD6_GATEWAY)) return; auto reject = [&](const char* detail) {
kad6::K6PublishAck ack; ack.status = kad6::K6PublishStatus::Rejected; ack.error_detail = detail; std::vector<uint8_t> body; if (kad6::EncodeK6PublishAck(ack, body) != kad6::Kad6Status::Ok) host.AbortExitOperation(ctx.circ->Id(), ctx.req_id); else host.SendK6GatewayResponse(ctx, kad6::kK6MsgPublishAck, body); }; if (!host.ConsumeK6QuotaGrant(ctx, kad6::K6QuotaService::ExitKad, frame)) { reject("anonymous quota required or context mismatch");
return; } if (!host.m_scheduler.LT2HardeningCanAdmit(kad6::K6Service::ExitKad)) { const uint64 now = static_cast<uint64>(time(NULL)); host.m_metrics.Add(kad6::K6MetricFamily::ExitRejectTotal, 8, 0, 0, 1, now); host.m_metrics.Add(kad6::K6MetricFamily::ExitAdmissionTotal, 1, 1, 0, 1, now); reject("EXIT_KAD disabled by local kill switch"); return; } if (publish.record_kind != kad6::K6RecordKind::Source &&
publish.record_kind != kad6::K6RecordKind::Kad6SourceDescriptor) { reject("K6-3 accepts source records only"); return; } uint64_t sourceLeaseId = 0; kad6::K6SourceRecord nativeRecord; if (publish.record_kind == kad6::K6RecordKind::Source) { if (publish.record.size() != 17 || publish.record[0] != 1) { reject("bad shadow source descriptor"); return; } for (size_t i = 0; i < 8; ++i)
sourceLeaseId |= static_cast<uint64_t>(publish.record[1 + i]) << (8 * i); } else { consumed = 0; const kad6::Kad6CryptoHooks crypto = MakeKad6HostCryptoHooks(); if (kad6::DecodeK6SourceRecord(publish.record.data(), publish.record.size(), nativeRecord, &consumed) != kad6::Kad6Status::Ok || consumed != publish.record.size() || kad6::VerifyK6SourceRecord(crypto, nativeRecord) != kad6::Kad6Status::Ok ||
kad6::K6SourceRecordCheckFresh(nativeRecord, static_cast<uint64_t>(time(NULL))) != kad6::Kad6Status::Ok || nativeRecord.source_epoch != publish.record_epoch || !kad6::Kad6CtEqual(nativeRecord.object_hash.data(), publish.target_hash.data(), 16) || !kad6::Kad6CtEqual(nativeRecord.source_pseudonym.data(), publish.source_id.data(), 16)) { reject("invalid signed Kad6 source record"); return; }
const uint8_t* exitPub = NodeIdentityPub(); if (exitPub) for (const auto& descriptor : nativeRecord.exits) if (kad6::Kad6CtEqual(descriptor.exit_node_pub.data(), exitPub, 32)) { sourceLeaseId = descriptor.lease_hint; break; } } kad6::K6SourceLease leaseCopy; kad6::K6CohortBackend servingBackend; bool registerServing = false; { CSingleLock pl(&host.m_pendingLock, TRUE);
const auto lease = host.m_kadBridge.LT3FindSourceLease(sourceLeaseId); if (!lease || lease->circuit_id != ctx.circ->Id() || !host.m_kadBridge.LT3SourceLeaseCanPublish(sourceLeaseId) || !kad6::Kad6CtEqual(lease->bind.file_hash.data(), publish.target_hash.data(), 16) || publish.record_epoch < lease->bind.source_epoch) { pl.Unlock(); reject("no matching active SourceLease"); return; }
if (publish.record_kind == kad6::K6RecordKind::Source) { uint64_t descriptorSize = 0; for (size_t i = 0; i < 8; ++i) descriptorSize |= static_cast<uint64_t>(publish.record[9 + i]) << (8 * i); if (descriptorSize != lease->bind.file_size || !kad6::Kad6CtEqual(lease->bind.compat_user_hash.data(), publish.source_id.data(), 16)) { pl.Unlock(); reject("source descriptor does not match lease"); return; } } else {
bool matchingExit = false; for (const auto& descriptor : nativeRecord.exits) if (descriptor.lease_hint == sourceLeaseId && kad6::Kad6CtEqual(descriptor.exit_node_pub.data(), lease->bound.exit_node_pub.data(), 32) && descriptor.endpoint.addr == lease->bound.virtual_endpoint.addr && descriptor.endpoint.tcp_port == lease->bound.virtual_endpoint.tcp_port && descriptor.endpoint.udp_port == lease->bound.virtual_endpoint.udp_port &&
descriptor.exit_expires_at <= lease->expires_at) { matchingExit = true; break; } if (!matchingExit) { pl.Unlock(); reject("native exit descriptor does not match lease"); return; } } const uint8_t* publishKey = publish.record_kind == kad6::K6RecordKind::Source ? lease->bind.compat_proof.data() : nativeRecord.pub_key.data(); if ((publish.flags & kad6::kK6PublishFlagSigned) == 0 ||
kad6::VerifyK6Publish(MakeKad6HostCryptoHooks(), publishKey, publish) != kad6::Kad6Status::Ok) { pl.Unlock(); reject("invalid publish signature"); return; } for (const auto& pair : host.m_exitServices.LT4PublishSnapshot()) { const LiveTunnelPublishRuntime& old = pair.second; if (old.source_lease_id == sourceLeaseId && old.request.record_epoch == publish.record_epoch && old.request.network_mask == publish.network_mask &&
old.request.record == publish.record && old.refresh_enabled) { kad6::K6PublishAck ack; ack.status = old.status; ack.published_networks = old.published_networks; ack.replica_count = old.replicas; ack.effective_ttl_s = static_cast<uint32_t>((std::min<uint64_t>)( old.expires_at > static_cast<uint64_t>(time(NULL)) ? old.expires_at - static_cast<uint64_t>(time(NULL)) : 0, kad6::kK6PublishMaxTtlSeconds));
ack.publish_lease_id = old.publish_lease_id; ack.record_epoch = old.request.record_epoch; ack.refresh_after_s = (std::max)(1u, ack.effective_ttl_s / 2u); std::vector<uint8_t> body; const bool ok = kad6::EncodeK6PublishAck(ack, body) == kad6::Kad6Status::Ok; pl.Unlock(); if (ok) host.SendK6GatewayResponse(ctx, kad6::kK6MsgPublishAck, body); else reject("expired publish lease"); return; } } leaseCopy = *lease; }
uint8_t randomLease[8]; const kad6::Kad6CryptoHooks crypto = MakeKad6HostCryptoHooks(); if (!crypto.random_bytes || !crypto.random_bytes(randomLease, sizeof randomLease)) { reject("CSPRNG unavailable"); return; } uint64_t publishLeaseId = 0; for (size_t i = 0; i < 8; ++i) publishLeaseId |= static_cast<uint64_t>(randomLease[i]) << (8 * i); if (publishLeaseId == 0) publishLeaseId = 1;
const uint64_t now = static_cast<uint64_t>(time(NULL)); uint32_t ttl = (std::min)(publish.requested_ttl_s, static_cast<uint32_t>((std::min<uint64_t>)( leaseCopy.expires_at > now ? leaseCopy.expires_at - now : 0, kad6::kK6PublishMaxTtlSeconds))); if (publish.record_kind == kad6::K6RecordKind::Kad6SourceDescriptor) ttl = (std::min)(ttl, static_cast<uint32_t>((std::min<uint64_t>)(
nativeRecord.expires_at > now ? nativeRecord.expires_at - now : 0, kad6::kK6PublishMaxTtlSeconds))); if (ttl < kad6::kK6PublishMinTtlSeconds) { reject("SourceLease expires too soon"); return; } LiveTunnelPublishRuntime runtime; runtime.request = publish; runtime.publish_lease_id = publishLeaseId; runtime.source_lease_id = sourceLeaseId; runtime.expires_at = now + ttl; runtime.primary_publish_lease_id = publishLeaseId;
runtime.auto_refresh=(publish.flags&kad6::kK6PublishFlagRefresh)!=0;
const bool wantsShadow=(publish.network_mask&kad6::kK6PublishNetKad2)!=0
    &&Kademlia::CKademlia::IsKad2Connected();
const std::string shadowKey=wantsShadow?host.K6ShadowKey(leaseCopy):std::string();
LiveTunnelPublishRuntime duplicate;
bool exterior=false;
bool queuedKad2=wantsShadow;
{
    CSingleLock pl(&host.m_pendingLock,TRUE);
    const auto mutation=host.m_exitServices.LT4OpenPublish(
        runtime,shadowKey,duplicate,exterior);
    if(mutation==LiveTunnelPublishMutation::DuplicatePublish){
        kad6::K6PublishAck ack;
        ack.status=duplicate.status;
        ack.published_networks=duplicate.published_networks;
        ack.replica_count=duplicate.replicas;
        ack.effective_ttl_s=static_cast<uint32_t>((std::min<uint64_t>)(
            duplicate.expires_at>now?duplicate.expires_at-now:0,
            kad6::kK6PublishMaxTtlSeconds));
        ack.publish_lease_id=duplicate.publish_lease_id;
        ack.record_epoch=duplicate.request.record_epoch;
        ack.refresh_after_s=(std::max)(1u,ack.effective_ttl_s/2u);
        std::vector<uint8_t> body;
        const bool ok=kad6::EncodeK6PublishAck(ack,body)==kad6::Kad6Status::Ok;
        pl.Unlock();
        if(ok)
            host.SendK6GatewayResponse(ctx,kad6::kK6MsgPublishAck,body);
        else
            reject("expired publish lease");
        return;
    }
    if(mutation!=LiveTunnelPublishMutation::Created){
        pl.Unlock();
        reject("publish lease capacity exhausted");
        return;
    }
    if(wantsShadow&&exterior){
        kad6::K6PublishSchedule schedule;
        schedule.publish_lease_id=publishLeaseId;
        schedule.target_hash=publish.target_hash;
        schedule.endpoint[0]=static_cast<uint8_t>(leaseCopy.bound.endpoint_slot);
        memcpy(schedule.endpoint.data()+1,leaseCopy.bound.virtual_endpoint.addr.addr.data(),4);
        schedule.endpoint[5]=static_cast<uint8_t>(leaseCopy.bound.virtual_endpoint.tcp_port);
        schedule.endpoint[6]=static_cast<uint8_t>(leaseCopy.bound.virtual_endpoint.tcp_port>>8);
        schedule.endpoint[7]=static_cast<uint8_t>(leaseCopy.bound.virtual_endpoint.udp_port);
        schedule.endpoint[8]=static_cast<uint8_t>(leaseCopy.bound.virtual_endpoint.udp_port>>8);
        schedule.record_class=static_cast<uint8_t>(publish.record_kind);
        schedule.due_at=now;
        schedule.expires_at=now+ttl;
        uint64 effective=0;
        const bool queued=host.m_kadBridge.LT3PublishEnqueue(schedule,30,effective);
        host.m_exitServices.LT4SetQueueState(publishLeaseId,queued,effective,0);
    }
}
bool queuedNative=false;if((publish.network_mask&kad6::kK6PublishNetKad6)!=0&&publish.record_kind==kad6::K6RecordKind::Kad6SourceDescriptor&&Kademlia::CKademlia::GetUDPListener())queuedNative=Kademlia::CKademlia::GetUDPListener()->PublishKad6SourceRecord(publishLeaseId,nativeRecord);if(queuedNative){CSingleLock pl(&host.m_pendingLock,TRUE);uint64 source=0;if(host.m_exitServices.LT4MarkNativeSent(publishLeaseId,now,ttl,source))registerServing=host.MarkK6SourceServingLocked(source,servingBackend);}
if(registerServing)host.m_kadBridge.LT3CohortRegister(servingBackend);if(!queuedKad2&&!queuedNative){CSingleLock pl(&host.m_pendingLock,TRUE);std::vector<LiveTunnelPublishAction> actions;host.m_exitServices.LT4RemovePublish(publishLeaseId,actions);pl.Unlock();reject("requested network unavailable");return;}kad6::K6PublishAck ack;{CSingleLock pl(&host.m_pendingLock,TRUE);LiveTunnelPublishRuntime stored;
if(host.m_exitServices.LT4FindPublish(publishLeaseId,stored)){ack.status=stored.status;ack.published_networks=stored.published_networks;}else ack.status=kad6::K6PublishStatus::Queued; } ack.effective_ttl_s = ttl; ack.publish_lease_id = publishLeaseId; ack.record_epoch = publish.record_epoch; ack.refresh_after_s = (std::max)(1u, ttl / 2u); std::vector<uint8_t> body; if (kad6::EncodeK6PublishAck(ack, body) != kad6::Kad6Status::Ok)
host.AbortExitOperation(ctx.circ->Id(), ctx.req_id); else { host.m_metrics.Add(kad6::K6MetricFamily::PublishTotal, (publish.network_mask & kad6::kK6PublishNetKad6) != 0 ? 1 : 0, 0, 0, 1, now); host.SendK6GatewayResponse(ctx, kad6::kK6MsgPublishAck, body); } }
bool CKad6OriginSocket::LT4AllowShadow(CLiveTunnel& host,std::uint64_t id,const std::uint8_t* custodian)
{if(!custodian)return false;CSingleLock lock(&host.m_pendingLock,TRUE);host.m_scheduler.LT2RecordPublishAttempt(1);LiveTunnelPublishRuntime r;if(!host.m_exitServices.LT4FindPublish(id,r)||!r.refresh_enabled||r.expires_at<=static_cast<uint64_t>(time(NULL)))return false;const auto lease=host.m_kadBridge.LT3FindSourceLease(r.source_lease_id);if(!lease||!host.m_kadBridge.LT3SourceLeaseCanPublish(lease->lease_id))return false;kad6::K6PublishBudgetKey k;k.target_hash=r.request.target_hash;memcpy(k.custodian.data(),custodian,16);k.record_class=static_cast<uint8_t>(r.request.record_kind);k.endpoint[0]=static_cast<uint8_t>(lease->bound.endpoint_slot);memcpy(k.endpoint.data()+1,lease->bound.virtual_endpoint.addr.addr.data(),4);k.endpoint[5]=static_cast<uint8_t>(lease->bound.virtual_endpoint.tcp_port);k.endpoint[6]=static_cast<uint8_t>(lease->bound.virtual_endpoint.tcp_port>>8);k.endpoint[7]=static_cast<uint8_t>(lease->bound.virtual_endpoint.udp_port);k.endpoint[8]=static_cast<uint8_t>(lease->bound.virtual_endpoint.udp_port>>8);return host.m_kadBridge.LT3PublishAdmit(k,static_cast<uint64_t>(time(NULL)));}
void CKad6OriginSocket::LT4ShadowSent(CLiveTunnel& host,std::uint64_t id)
{
    std::vector<kad6::K6CohortBackend> serving;
    {
        CSingleLock lock(&host.m_pendingLock,TRUE);
        for(const auto source:host.m_exitServices.LT4MarkShadowSent(id)){
            kad6::K6CohortBackend backend;
            if(host.MarkK6SourceServingLocked(source,backend))
                serving.push_back(backend);
        }
    }
    for(const auto& backend:serving)
        host.m_kadBridge.LT3CohortRegister(backend);
}
void CKad6OriginSocket::LT4ShadowAck(CLiveTunnel& host,std::uint64_t id,std::uint8_t load,bool response)
{
    const uint64 now=static_cast<uint64>(time(NULL));
    CSingleLock lock(&host.m_pendingLock,TRUE);
    if(!host.m_exitServices.LT4MarkShadowAck(id,load,now))
        return;
    if(response&&load>=80)
        host.m_kadBridge.LT3PublishNoteOverload(now);
}
void CKad6OriginSocket::LT4ShadowVerified(CLiveTunnel& host,std::uint64_t id)
{
    CSingleLock lock(&host.m_pendingLock,TRUE);
    host.m_exitServices.LT4MarkShadowVerified(id);
}
void CKad6OriginSocket::LT4NativeAck(CLiveTunnel& host,std::uint64_t id,kad6::K6StoreStatus status,std::uint8_t load,std::uint64_t epoch)
{
    const uint64 now=static_cast<uint64>(time(NULL));
    bool overload=false;
    CSingleLock lock(&host.m_pendingLock,TRUE);
    if(!host.m_exitServices.LT4MarkNativeResult(id,status,load,epoch,now,overload))
        return;
    if(overload)
        host.m_kadBridge.LT3PublishNoteOverload(now);
}
bool CKad6OriginSocket::LT4ConsumeTicket(void* context,const kad6::K6TargetTicket& ticket) {CLiveTunnel* self=static_cast<CLiveTunnel*>(context);return self&&self->m_exitServices.LT4ConsumeTicket(ticket,static_cast<uint64>(time(NULL)));}
void CKad6OriginSocket::LT4TargetTicketReq(CLiveTunnel& host,const LiveTunnelRequestCtx& ctx,const kad6::K6Frame& frame)
{kad6::K6TargetTicketRequest request;size_t consumed=0;if(kad6::DecodeK6TargetTicketRequest(frame.body.data(),frame.body.size(),request,&consumed)!=kad6::Kad6Status::Ok||consumed!=frame.body.size()||!host.BeginExitOperation(ctx,CLiveTunnel::TUN_OP_KAD6_GATEWAY))return;kad6::K6TargetTicketResponse response;response.status=kad6::K6TargetTicketStatus::NotFound;LiveTunnelAuthorizedTarget target;const bool found=host.m_exitServices.LT4FindAuthorizedTarget(host.K6AuthorizedTargetKey(ctx.circ->Id(),request.source_request_id,request.result_id),static_cast<uint64>(time(NULL)),target)&&target.object_hash==request.object_hash;if(found){if(request.service!=static_cast<kad6::Byte>(kad6::K6TicketService::Ed2kTcp))response.status=kad6::K6TargetTicketStatus::PolicyDenied;else if(host.IssueK6RuntimeTicket(target,request.requested_max_bytes,kad6::K6Provenance::KadResult,ctx.circ->Id(),request.source_request_id,0,response.ticket))response.status=kad6::K6TargetTicketStatus::Ok;else response.status=kad6::K6TargetTicketStatus::PolicyDenied;}std::vector<uint8_t> body;if(kad6::EncodeK6TargetTicketResponse(response,body)!=kad6::Kad6Status::Ok)host.AbortExitOperation(ctx.circ->Id(),ctx.req_id);else host.SendK6GatewayResponse(ctx,kad6::kK6MsgTargetTicket,body);}
void CKad6OriginSocket::LT4RefreshNative(CLiveTunnel& host,std::uint64_t nowSeconds)
{
    if(!Kademlia::CKademlia::IsKad6Running())
        return;
    struct Work{uint64 id;kad6::K6SourceRecord record;};
    std::vector<Work> due;
    {
        CSingleLock lock(&host.m_pendingLock,TRUE);
        for(const auto& runtime:host.m_exitServices.LT4TakeNativeRefreshes(nowSeconds)){
            kad6::K6SourceRecord record;
            size_t used=0;
            if(kad6::DecodeK6SourceRecord(runtime.request.record.data(),runtime.request.record.size(),record,&used)==kad6::Kad6Status::Ok
                &&used==runtime.request.record.size()
                &&kad6::K6SourceRecordCheckFresh(record,nowSeconds)==kad6::Kad6Status::Ok)
                due.push_back({runtime.publish_lease_id,std::move(record)});
            else
                host.m_exitServices.LT4CompleteNativeRefresh(runtime.publish_lease_id,false,nowSeconds);
        }
    }
    auto* listener=Kademlia::CKademlia::GetUDPListener();
    for(const auto& work:due){
        const bool sent=listener&&listener->PublishKad6SourceRecord(work.id,work.record);
        CSingleLock lock(&host.m_pendingLock,TRUE);
        host.m_exitServices.LT4CompleteNativeRefresh(work.id,sent,nowSeconds);
    }
}
void CKad6OriginSocket::LT4StartShadow(CLiveTunnel& host,std::uint64_t nowSeconds)
{
    if(!Kademlia::CKademlia::IsKad2Running())
        return;
    std::vector<kad6::K6PublishSchedule> due;
    {
        CSingleLock lock(&host.m_pendingLock,TRUE);
        due=host.m_kadBridge.LT3PublishTakeDue(nowSeconds,8);
    }
    for(const auto& schedule:due){
        LiveTunnelPublishRuntime runtime;
        kad6::K6SourceLease lease;
        bool ready=false;
        {
            CSingleLock lock(&host.m_pendingLock,TRUE);
            if(host.m_exitServices.LT4TakeShadow(schedule.publish_lease_id,runtime)){
                const auto source=host.m_kadBridge.LT3FindSourceLease(runtime.source_lease_id);
                if(source&&runtime.refresh_enabled
                    &&runtime.primary_publish_lease_id==schedule.publish_lease_id
                    &&runtime.expires_at>nowSeconds
                    &&host.m_kadBridge.LT3SourceLeaseCanPublish(source->lease_id)){
                    lease=*source;
                    ready=true;
                }
            }
        }
        if(!ready)
            continue;
        Kademlia::CUInt128 target(runtime.request.target_hash.data());
        auto* search=Kademlia::CSearchManager::PrepareLookup(Kademlia::CSearch::STOREFILE,false,target);
        bool started=search!=NULL;
        if(started){
            search->SetK6ShadowSource(runtime.publish_lease_id,lease.bind.file_size,
                lease.bind.compat_user_hash.data(),lease.bound.virtual_endpoint.tcp_port,
                lease.bound.virtual_endpoint.udp_port);
            started=Kademlia::CSearchManager::StartSearch(search);
        }
        CSingleLock lock(&host.m_pendingLock,TRUE);
        host.m_exitServices.LT4CompleteShadow(runtime.publish_lease_id,started,nowSeconds);
    }
}
void CKad6OriginSocket::LT4StartProbes(CLiveTunnel& host,std::uint64_t nowSeconds)
{
    struct Probe{uint64 id;kad6::Hash16 target,user;uint32 ip;uint16 tcp,udp;};
    std::vector<Probe> due;
    {
        bool overload=false;
        CSingleLock lock(&host.m_pendingLock,TRUE);
        const auto candidates=host.m_exitServices.LT4TakeVisibilityProbes(nowSeconds,overload);
        if(overload)
            host.m_kadBridge.LT3PublishNoteOverload(nowSeconds);
        for(const auto& runtime:candidates){
            const auto lease=host.m_kadBridge.LT3FindSourceLease(runtime.source_lease_id);
            if(!lease||!host.m_kadBridge.LT3SourceLeaseCanPublish(runtime.source_lease_id)){
                host.m_exitServices.LT4CompleteVisibilityProbe(runtime.publish_lease_id,false,nowSeconds);
                continue;
            }
            const auto& addr=lease->bound.virtual_endpoint.addr.addr;
            const uint32 ip=static_cast<uint32>(addr[0])
                |(static_cast<uint32>(addr[1])<<8)
                |(static_cast<uint32>(addr[2])<<16)
                |(static_cast<uint32>(addr[3])<<24);
            due.push_back({runtime.publish_lease_id,runtime.request.target_hash,
                lease->bind.compat_user_hash,ip,lease->bound.virtual_endpoint.tcp_port,
                lease->bound.virtual_endpoint.udp_port});
        }
    }
    for(const auto& probe:due){
        Kademlia::CUInt128 target(probe.target.data());
        auto* search=Kademlia::CSearchManager::PrepareLookup(Kademlia::CSearch::FILE,false,target);
        bool started=search!=NULL;
        if(started){
            search->SetK6VisibilityProbe(probe.id,probe.user.data(),probe.ip,probe.tcp,probe.udp);
            started=Kademlia::CSearchManager::StartSearch(search);
        }
        CSingleLock lock(&host.m_pendingLock,TRUE);
        host.m_exitServices.LT4CompleteVisibilityProbe(probe.id,started,nowSeconds);
    }
}

void CLiveTunnel::ExitHandle_Kad6Dial(const TunnelRequestCtx& ctx,
                                      const kad6::K6Frame& frame)
{
    kad6::K6Dial dial; size_t consumed = 0;
    if (kad6::DecodeK6Dial(frame.body.data(), frame.body.size(), dial, &consumed) !=
            kad6::Kad6Status::Ok || consumed != frame.body.size()) return;
    if (!BeginExitOperation(ctx, TUN_OP_KAD6_GATEWAY)) return;
    uint64 quotaAllocation = 0;
    auto reject = [&](kad6::K6DialStatus status) {
        if (quotaAllocation != 0) {
            m_scheduler.ReleaseFairAllocation(quotaAllocation);
            quotaAllocation = 0;
        }
        kad6::K6DialResult result; result.stream_id = NewCircuitId();
        result.status = status; result.transport = dial.protocol;
        result.apparent_local_endpoint.addr.family = kad6::Kad6Address::Family::None;
        result.remote_endpoint.addr.family = kad6::Kad6Address::Family::None;
        std::vector<uint8_t> body;
        if (kad6::EncodeK6DialResult(result, body) == kad6::Kad6Status::Ok)
            SendK6GatewayResponse(ctx, kad6::kK6MsgDialOk, body);
        else AbortExitOperation(ctx.circ->Id(), ctx.req_id);
    };
    if (!ConsumeK6QuotaGrant(ctx, kad6::K6QuotaService::ExitEd2kDial,
            frame, &quotaAllocation)) {
        reject(kad6::K6DialStatus::PolicyDenied);
        return;
    }
    if (!m_scheduler.LT2HardeningCanAdmit(kad6::K6Service::ExitEd2kDial) ||
        !K6EconomyAdmit(kad6::K6Service::ExitEd2kDial)) {
        const uint64 now = static_cast<uint64>(time(NULL));
        m_metrics.Add(kad6::K6MetricFamily::ExitRejectTotal, 8, 0, 0, 1, now);
        m_metrics.Add(kad6::K6MetricFamily::ExitAdmissionTotal, 2, 1, 0, 1, now);
        reject(kad6::K6DialStatus::PolicyDenied);
        return;
    }
    if (dial.protocol != kad6::K6GatewayTransport::TcpEd2k) { reject(kad6::K6DialStatus::Unsupported); return; }
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        if (m_exitServices.LT5ExitCount() >= 512) { pl.Unlock(); reject(kad6::K6DialStatus::Overloaded); return; }
    }
    kad6::K6TargetTicket ticket;
    if (kad6::VerifyK6TargetTicket(MakeKad6HostCryptoHooks(), K6TicketPolicy(),
            m_exitServices.LT4TicketSecret().data(), 32, dial.ticket.data(),
            dial.ticket.size(), static_cast<uint64>(time(NULL)), ticket) != kad6::Kad6Status::Ok ||
        ticket.service != static_cast<kad6::Byte>(kad6::K6TicketService::Ed2kTcp)) {
        reject(kad6::K6DialStatus::TicketRejected); return;
    }

    kad6::K6Endpoint apparent; apparent.tcp_port = theApp.GetAdvertisedTcpPort();
    apparent.udp_port = theApp.GetAdvertisedUdpPort(); apparent.transport_flags = kad6::kK6EpEd2kGateway;
    apparent.valid_until = static_cast<uint64>(time(NULL)) + kad6::kK6VepMaxTtlSeconds;
    if (ticket.target_endpoint.addr.family == kad6::Kad6Address::Family::IPv4) {
        const uint32 publicIp = theApp.GetPublicIP();
        if (publicIp == 0 || !IsGoodIP(publicIp)) {
            reject(kad6::K6DialStatus::PolicyDenied); return;
        }
        apparent.addr.family = kad6::Kad6Address::Family::IPv4;
        memcpy(apparent.addr.addr.data(), &publicIp, 4);
    } else if (ticket.target_endpoint.addr.family == kad6::Kad6Address::Family::IPv6) {
		const uint64 topologyGeneration = theApp.directreachability != NULL
			? theApp.directreachability->GetTopologyGeneration() : 0;
		const natmap::CandidateObservation v6TcpObservation =
			CFirewallProberV6::Instance().GetDirectRouteObservation(
				topologyGeneration, natmap::Transport::Tcp);
        const CAddress v6 = CFirewallProberV6::Instance().GetDetectedV6IP();
		if (v6.GetType() != CAddress::IPv6 || !v6.IsPublicIP()
			|| !v6TcpObservation.IsVerifiedFor(topologyGeneration)) {
            reject(kad6::K6DialStatus::PolicyDenied); return;
        }
        apparent.addr.family = kad6::Kad6Address::Family::IPv6;
        memcpy(apparent.addr.addr.data(), v6.Data(), 16);
    } else { reject(kad6::K6DialStatus::PolicyDenied); return; }

    std::vector<uint8_t> initial; size_t offset = 0; bool initialOk = true;
    while (offset < dial.initial_data.size()) {
        if (dial.initial_data.size() - offset < kad6::kK6Ed2kHeaderSize) { initialOk = false; break; }
        const uint8_t* p = dial.initial_data.data() + offset;
        const uint32 packetLength = static_cast<uint32>(p[1]) |
            (static_cast<uint32>(p[2]) << 8) | (static_cast<uint32>(p[3]) << 16) |
            (static_cast<uint32>(p[4]) << 24);
        const size_t frameLength = 5ull + packetLength;
        if (packetLength == 0 || frameLength > dial.initial_data.size() - offset) { initialOk = false; break; }
        kad6::K6Ed2kFrameView view;
        if (kad6::DecodeK6Ed2kFrame(p, frameLength, view) != kad6::Kad6Status::Ok) { initialOk = false; break; }
        const kad6::K6Ed2kDisposition disposition = kad6::K6Ed2kPolicy(
            kad6::K6Ed2kDirection::OriginToRemote,
            kad6::ClassifyK6Ed2kFrame(view.protocol, view.opcode));
        std::vector<uint8_t> rewritten;
        if (disposition == kad6::K6Ed2kDisposition::RewriteEndpoint) {
            if (view.opcode == OP_HELLO || view.opcode == OP_HELLOANSWER)
                initialOk = SanitizeK6HelloFrame(p, frameLength, apparent, rewritten);
            else
                initialOk = kad6::RewriteK6Ed2kPublicIpAnswer(view, apparent.addr, rewritten) == kad6::Kad6Status::Ok;
        } else if (disposition == kad6::K6Ed2kDisposition::Pass)
            rewritten.assign(p, p + frameLength);
        else if (disposition == kad6::K6Ed2kDisposition::Drop) {
            offset += frameLength; continue;
        } else initialOk = false;
        if (!initialOk) break;
        initial.insert(initial.end(), rewritten.begin(), rewritten.end()); offset += frameLength;
    }
    if (!initialOk) { reject(kad6::K6DialStatus::BadInitialData); return; }
    if (initial.size() > ticket.max_bytes) {
        reject(kad6::K6DialStatus::PolicyDenied); return;
    }
    const uint64 streamMaxBytes = (std::min<uint64>)(
        ticket.max_bytes - initial.size(), quotaAllocation != 0
            ? 4ull * 1024ull * 1024ull * 1024ull
            : ticket.max_bytes - initial.size());

    uint64 streamId = 0; const kad6::Kad6CryptoHooks crypto = MakeKad6HostCryptoHooks();
    uint8 randomId[8];
    do { if (!crypto.random_bytes || !crypto.random_bytes(randomId, 8)) { reject(kad6::K6DialStatus::Overloaded); return; }
        streamId = 0; for (int i=0;i<8;++i) streamId |= static_cast<uint64>(randomId[i]) << (8*i);
    } while(streamId==0);

    if (quotaAllocation != 0) {
        // Exit handlers run under OnCellReceived's tunnel lock. Arm the
        // shared timer before entering any pending-rank section so the global
        // order remains tunnel -> pending on every fair-queue path.
        if (!EnsureK6ShapeTimerLocked()) {
            reject(kad6::K6DialStatus::Overloaded);
            return;
        }
        kad6::Hash32 targetHash{};
        std::vector<uint8_t> target(ticket.target_endpoint.addr.addr.begin(),
                                    ticket.target_endpoint.addr.addr.end());
        target.push_back(static_cast<uint8_t>(ticket.target_endpoint.tcp_port));
        target.push_back(static_cast<uint8_t>(ticket.target_endpoint.tcp_port >> 8));
        bool fairRegistered = false;
        if (crypto.sha256
            && crypto.sha256(target.data(), target.size(), targetHash.data())) {
            CSingleLock pl(&m_pendingLock, TRUE);
            fairRegistered = m_scheduler.RegisterFairStream(
                quotaAllocation, streamId, targetHash, ticket.max_bytes,
                16ull * 1024ull * 1024ull * 1024ull);
        }
        if (!fairRegistered) {
            reject(kad6::K6DialStatus::Overloaded);
            return;
        }
    }

    uint32 ip = 0; uint32 id = 0x01000001u;
    if (ticket.target_endpoint.addr.family == kad6::Kad6Address::Family::IPv4) {
        memcpy(&ip, ticket.target_endpoint.addr.addr.data(), 4); id = ntohl(ip);
    }
    CKad6ExitClient* client = new CKad6ExitClient(NULL, ticket.target_endpoint.tcp_port,
        id, 0, 0, false);
    if (ip) client->SetIP(ip);
    else {
        CAddress target(ticket.target_endpoint.addr.addr.data());
        client->SetIPv6Address(target); client->SetConnectIP(target.ToSyntheticUInt32());
        client->SetUserIDHybrid(0x01000001u);
    }
    theApp.clientlist->AddClient(client);
    K6ExitStreamRuntime runtime; runtime.circ_id = ctx.circ->Id(); runtime.dial_request_id = ctx.req_id;
    runtime.quota_allocation_id = quotaAllocation;
    runtime.circuit = ctx.circ; runtime.ticket = ticket; runtime.apparent = apparent;
    runtime.network_origin = (ticket.provenance_flags &
        kad6::kK6ProvenanceFlagNativeKad6) != 0
        ? kad6::kK6NetOriginKad6 : kad6::kK6NetOriginKad2;
    runtime.client = client; runtime.flow = kad6::K6StreamFlowState(streamMaxBytes);
    runtime.stream_max_bytes = streamMaxBytes;
    runtime.initial_data = std::move(initial); runtime.created_at = runtime.last_activity = static_cast<uint64>(time(NULL));
    runtime.idle_timeout_ms = dial.idle_timeout_ms;
    runtime.connect_deadline = runtime.created_at + ((dial.connect_timeout_ms + 999u) / 1000u);
    runtime.idle_deadline = runtime.created_at + ((dial.idle_timeout_ms + 999u) / 1000u);
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        if(!m_exitServices.LT5CreateExit(streamId,runtime)){
            pl.Unlock();
            ReleaseK6FairStreamLocked(streamId);
            reject(kad6::K6DialStatus::Overloaded);
            if (client->Disconnected(_T("Kad6 flow-control capacity"))) delete client;
            return;
        }
    }
    const bool connecting = client->TryToConnect(true, true, RUNTIME_CLASS(CKad6ExitSocket));
    CKad6ExitSocket* socket = connecting ? DYNAMIC_DOWNCAST(CKad6ExitSocket, client->socket) : NULL;
    if (!socket) {
        CSingleLock pl(&m_pendingLock,TRUE);K6ExitStreamRuntime removed;m_exitServices.LT5TakeExit(streamId,NULL,runtime.generation,removed);
        m_peerState.RecordSourceFailure(BuildLiveSourceEndpointKey(
            runtime.ticket.target_endpoint, runtime.network_origin),
            static_cast<uint64>(time(NULL)));
        ReleaseK6FairStreamLocked(streamId); pl.Unlock();
        m_metrics.Add(kad6::K6MetricFamily::SourceDialTotal,
            runtime.network_origin == kad6::kK6NetOriginKad6 ? 1 : 0,
            2, 0, 1, static_cast<uint64>(time(NULL)));
        reject(kad6::K6DialStatus::ConnectFailed);
        if (connecting && client->Disconnected(_T("Kad6 outgoing connect failed")))
            delete client;
        return;
    }
    socket->Initialize(streamId);
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        K6ExitStreamRuntime stream;if(m_exitServices.LT5FindExit(streamId,NULL,stream)){stream.socket=socket;m_exitServices.LT5UpdateExit(streamId,NULL,stream.generation,stream);}
    }
}

bool CLiveTunnel::ActivateK6Inbound(CKad6ExitSocket* socket,
                                    const kad6::Hash16& fileHash,
                                    const std::vector<std::vector<uint8_t>>& initialFrames)
{
    if (!socket || initialFrames.empty()) return false;
    if (!m_scheduler.LT2HardeningCanAdmit(kad6::K6Service::ExitEd2kFull) ||
        !K6EconomyAdmit(kad6::K6Service::ExitEd2kFull)) {
        const uint64 now = static_cast<uint64>(time(NULL));
        m_metrics.Add(kad6::K6MetricFamily::ExitRejectTotal, 8, 0, 0, 1, now);
        m_metrics.Add(kad6::K6MetricFamily::ExitAdmissionTotal, 3, 1, 0, 1, now);
        return false;
    }

    const std::vector<uint8_t>* hello = NULL;
    for (const std::vector<uint8_t>& raw : initialFrames) {
        kad6::K6Ed2kFrameView view;
        if (kad6::DecodeK6Ed2kFrame(raw.data(), raw.size(), view) != kad6::Kad6Status::Ok)
            return false;
        if (!hello && kad6::ClassifyK6Ed2kFrame(view.protocol, view.opcode) ==
                kad6::K6Ed2kFrameClass::Hello)
            hello = &raw;
    }
    const std::vector<uint8_t>& request = initialFrames.back();
    kad6::K6Ed2kFrameView requestView;
    if (!hello || kad6::DecodeK6Ed2kFrame(request.data(), request.size(), requestView) !=
            kad6::Kad6Status::Ok || requestView.protocol != OP_EDONKEYPROT ||
        (requestView.opcode != OP_REQUESTFILENAME && requestView.opcode != OP_SETREQFILEID) ||
        requestView.payload_size < fileHash.size() ||
        !kad6::Kad6CtEqual(requestView.payload, fileHash.data(), fileHash.size()))
        return false;

    uint8 randomId[8];
    uint64 streamId = 0;
    const kad6::Kad6CryptoHooks crypto = MakeKad6HostCryptoHooks();
    if (!crypto.random_bytes) return false;
    do {
        if (!crypto.random_bytes(randomId, sizeof randomId)) return false;
        streamId = 0;
        for (size_t i = 0; i < sizeof randomId; ++i)
            streamId |= static_cast<uint64>(randomId[i]) << (8 * i);
    } while (streamId == 0);

    kad6::K6CohortBackend selected;
    kad6::K6SourceLease lease;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        K6ExitStreamRuntime collision;if(m_exitServices.LT5ExitCount()>=512||m_exitServices.LT5FindExit(streamId,collision))return false;
        kad6::Hash16 cohort{};
        bool cohortSet = false;
        for (const auto& pair : m_kadBridge.LT3SourceLeaseEntries()) {
            const kad6::K6SourceLease& candidate = pair.second;
            if (!m_kadBridge.LT3SourceLeaseCanAccept(pair.first) ||
                !kad6::Kad6CtEqual(candidate.bind.file_hash.data(), fileHash.data(),
                    fileHash.size()))
                continue;
            if (!cohortSet) {
                cohort = candidate.bound.cohort_id;
                cohortSet = true;
            } else if (!kad6::Kad6CtEqual(cohort.data(),
                           candidate.bound.cohort_id.data(), cohort.size())) {
                // One shared endpoint cannot disambiguate distinct identities
                // for the same eD2K hash. Dedicated VEPs must handle that case.
                return false;
            }
        }
        if (!cohortSet || !m_kadBridge.LT3CohortSelect(fileHash, cohort, streamId, selected))
            return false;
        const auto selectedLease = m_kadBridge.LT3FindSourceLease(selected.lease_id);
        if (!selectedLease || !m_kadBridge.LT3SourceLeaseCanAccept(selected.lease_id)) {
            m_kadBridge.LT3CohortReleaseStream(streamId);
            ReleaseK6FairStreamLocked(streamId);
            return false;
        }
        lease = *selectedLease;
    }

    std::shared_ptr<CLiveCircuit> circuit;
    {
        CSingleLock lock(&m_lock, TRUE);
        for (const auto& candidate : m_circuitRegistry.GetSnapshot())
            if (candidate && candidate->Id() == selected.circuit_id &&
                candidate->State() == CircuitState::Active) {
                circuit = candidate;
                break;
            }
    }
    if (!circuit) {
        CSingleLock pl(&m_pendingLock, TRUE);
        m_kadBridge.LT3CohortReleaseStream(streamId);
        ReleaseK6FairStreamLocked(streamId);
        return false;
    }

    const uint64 idleMs = 120000;
    uint64 maxBytes = 4ull * 1024ull * 1024ull * 1024ull;
    if (lease.bind.max_upload_bps != 0)
        maxBytes = (std::min)(maxBytes,
            static_cast<uint64>(lease.bind.max_upload_bps) * (idleMs / 1000u));
    if (!socket->BindInboundStream(streamId)) {
        CSingleLock pl(&m_pendingLock, TRUE);
        m_kadBridge.LT3CohortReleaseStream(streamId);
        ReleaseK6FairStreamLocked(streamId);
        return false;
    }

    K6ExitStreamRuntime runtime;
    runtime.circ_id = selected.circuit_id;
    runtime.circuit = circuit;
    runtime.apparent = lease.bound.virtual_endpoint;
    runtime.socket = socket;
    runtime.client = socket->client;
    runtime.flow = kad6::K6StreamFlowState(maxBytes);
    runtime.stream_max_bytes = maxBytes;
    runtime.ticket.max_bytes = maxBytes;
    runtime.created_at = runtime.last_activity = static_cast<uint64>(time(NULL));
    runtime.idle_timeout_ms = static_cast<uint32>(idleMs);
    runtime.idle_deadline = runtime.created_at + (idleMs / 1000u);
    runtime.connected = true;
    runtime.inbound = true;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        if(!m_exitServices.LT5CreateExit(streamId,runtime)){
            pl.Unlock();
            socket->Disconnect(_T("Kad6 flow-control capacity"));
            return false;
        }
    }
    m_metrics.Add(kad6::K6MetricFamily::ExitAdmissionTotal, 3, 0, 0, 1,
                    runtime.created_at);

    kad6::K6DialResult accept;
    accept.stream_id = streamId;
    accept.status = kad6::K6DialStatus::Ok;
    accept.transport = kad6::K6GatewayTransport::TcpEd2k;
    accept.flags = 0x0001; // inbound front-door stream
    accept.apparent_local_endpoint = lease.bound.virtual_endpoint;
    // A needs a nonzero peer address for unchanged credit/client bookkeeping,
    // but disclosing the vanilla peer's network endpoint is unnecessary. Use
    // a stream-scoped RFC1918 pseudonym which can never be published or dialed.
    accept.remote_endpoint.addr.family = kad6::Kad6Address::Family::IPv4;
    accept.remote_endpoint.addr.addr = {10,
        static_cast<uint8_t>(streamId >> 16),
        static_cast<uint8_t>(streamId >> 8),
        static_cast<uint8_t>(streamId)};
    accept.max_bytes = maxBytes;
    accept.idle_timeout_ms = static_cast<uint32>(idleMs);
    std::vector<uint8_t> body;
    if (kad6::EncodeK6DialResult(accept, body) != kad6::Kad6Status::Ok ||
        !SendK6GatewayPush(circuit, selected.circuit_id, 0,
            kad6::kK6MsgAccept, kad6::kK6FlagFinal, body) ||
        !SendK6InitialCredit(selected.circuit_id, streamId, 0, circuit, true) ||
        !OnK6ExitPacket(streamId,hello->data(),hello->size()) ||
        !OnK6ExitPacket(streamId,request.data(),request.size())) {
        CSingleLock pl(&m_pendingLock,TRUE);K6ExitStreamRuntime removed;m_exitServices.LT5TakeExit(streamId,socket,runtime.generation,removed);
        m_kadBridge.LT3CohortReleaseStream(streamId);
        ReleaseK6FairStreamLocked(streamId);
        pl.Unlock();
        socket->Disconnect(_T("Kad6 inbound activation failed"));
        return false;
    }
    LIVE_LOG("K6", "front-door selected lease=%llu stream=%llu circuit=%u",
        static_cast<unsigned long long>(selected.lease_id),
        static_cast<unsigned long long>(streamId), selected.circuit_id);
    return true;
}

bool CLiveTunnel::OnK6ExitPacket(uint64 streamId,const uint8_t* raw,size_t length)
{
    kad6::K6Ed2kFrameView view;
    if (kad6::DecodeK6Ed2kFrame(raw, length, view) != kad6::Kad6Status::Ok) return false;
    K6ExitStreamRuntime runtime; CKad6ExitSocket* source=NULL; uint64 sequence = 0;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        if(!m_exitServices.LT5FindExit(streamId,runtime)||!runtime.socket||!runtime.connected)return false;
        source=runtime.socket;
        sequence=runtime.tx_sequence;
        const uint64 now = static_cast<uint64>(time(NULL));
        const uint64 idle=(runtime.idle_timeout_ms+999u)/1000u;runtime.last_activity=now;runtime.idle_deadline=now+idle;
        if(!m_exitServices.LT5UpdateExit(streamId,source,runtime.generation,runtime))return false;
    }
    const kad6::K6Ed2kFrameClass frameClass = kad6::ClassifyK6Ed2kFrame(view.protocol, view.opcode);
    const kad6::K6Ed2kDisposition disposition = kad6::K6Ed2kPolicy(
        kad6::K6Ed2kDirection::RemoteToOrigin, frameClass);
    if (disposition == kad6::K6Ed2kDisposition::ConvertToHints) {
        kad6::K6ParsedPex pex;
        if (kad6::DecodeEd2kSourceExchange(view.opcode, view.payload, view.payload_size, pex) !=
                kad6::Kad6Status::Ok) return false;
        kad6::Hash32 digest{}; const kad6::Kad6CryptoHooks crypto = MakeKad6HostCryptoHooks();
        if (!crypto.sha256 || !crypto.sha256(raw, length, digest.data())) return false;
        kad6::K6SourceHints hints; hints.source_session_id = runtime.circ_id;
        hints.source_stream_id = streamId; hints.pex_version = pex.version;
        hints.object_hash = pex.object_hash; hints.exterior_message_hash = digest;
        {
            CSingleLock pl(&m_pendingLock, TRUE);
            K6ExitStreamRuntime stream;if(!m_exitServices.LT5FindExit(streamId,source,stream))return false;
            hints.source_message_seq=stream.pex_sequence++;
            if(!m_exitServices.LT5UpdateExit(streamId,source,stream.generation,stream))return false;
        }
        std::set<std::string> dedupe;
        for (size_t i = 0; i < pex.sources.size() && hints.sources.size() < kad6::kK6SourceHintsMaxSources; ++i) {
            const kad6::K6ParsedPexSource& source = pex.sources[i];
            if (source.low_id || source.endpoint.tcp_port == 0) continue;
            std::string key(reinterpret_cast<const char*>(source.endpoint.addr.addr.data()), 16);
            key.push_back(static_cast<char>(source.endpoint.tcp_port));
            key.push_back(static_cast<char>(source.endpoint.tcp_port >> 8));
            if (!dedupe.insert(key).second) continue;
            LiveTunnelAuthorizedTarget target; target.circ_id = runtime.circ_id;
            target.object_hash = pex.object_hash; target.digest = digest;
            target.endpoint = source.endpoint;
            target.endpoint.valid_until = static_cast<uint64>(time(NULL)) + kad6::kK6TicketMaxTtlSeconds;
            if (!K6AllowTicketTarget(this, static_cast<kad6::Byte>(kad6::K6TicketService::Ed2kTcp), target.endpoint))
                continue;
            kad6::K6SourceHint hint; hint.endpoint = target.endpoint;
            hint.user_hash = source.user_hash; hint.crypt_options = source.crypt_options;
            if (!IssueK6RuntimeTicket(target, runtime.ticket.max_bytes,
                    kad6::K6Provenance::Pex, runtime.circ_id, streamId,
                    hints.source_message_seq, hint.ticket)) continue;
            hints.sources.push_back(std::move(hint));
        }
        std::vector<uint8_t> body;
        return kad6::EncodeK6SourceHints(hints, body) == kad6::Kad6Status::Ok &&
            SendK6GatewayPush(runtime.circuit, runtime.circ_id, 0,
                kad6::kK6MsgSourceHints, kad6::kK6FlagFinal, body);
    }
    if (disposition == kad6::K6Ed2kDisposition::Drop) return true;
    if (disposition != kad6::K6Ed2kDisposition::Pass) return false;
    CKad6ExitSocket* pauseSocket = NULL;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        K6ExitStreamRuntime stream;if(!m_exitServices.LT5FindExit(streamId,source,stream))return false;
        const uint64 sent=m_exitServices.LT5Sent(stream.circ_id,streamId,1);
        const uint64 received=stream.flow.total_bytes(0);
        const uint64 remaining = stream.stream_max_bytes == 0 ||
                sent + received >= stream.stream_max_bytes
            ? (stream.stream_max_bytes == 0
                ? (std::numeric_limits<uint64>::max)() : 0)
            : stream.stream_max_bytes - sent - received;
        const bool waitForCredit = !stream.pending_credit_frames.empty() ||
            m_exitServices.LT5Available(stream.circ_id,streamId,1,remaining,
                (std::numeric_limits<uint64>::max)(),
                2u*1024u*1024u-stream.pending_credit_bytes)<length;
        if (waitForCredit) {
            if (stream.pending_credit_frames.size() >= 64 ||
                length > 2u * 1024u * 1024u - stream.pending_credit_bytes)
                return false;
            stream.pending_credit_frames.emplace_back(raw,raw+length);stream.pending_credit_bytes+=length;
            if(stream.credit_stall_since_ms==0)stream.credit_stall_since_ms=
                    M2A_LT3_K6ShapeNowUs() / 1000u;
            pauseSocket=stream.socket;
            if(!m_exitServices.LT5UpdateExit(streamId,source,stream.generation,stream))return false;
        }
    }
    if (pauseSocket) {
        pauseSocket->SetKad6ReadPaused(true);
        return true;
    }
    kad6::K6StreamData data; data.stream_id = streamId; data.sequence = sequence;
    data.direction = 1; data.flags = 0x02; data.data.assign(raw, raw + length);
    std::vector<uint8_t> body;
    if (kad6::EncodeK6StreamData(data, body) != kad6::Kad6Status::Ok) return false;
    if (runtime.quota_allocation_id != 0) {
        CSingleLock pl(&m_pendingLock, TRUE);
        K6ExitStreamRuntime stream;if(!m_exitServices.LT5FindExit(streamId,source,stream)||
            stream.flow.CanAccept(data)!=kad6::Kad6Status::Ok)
            return false;
        if (!QueueK6FairPayloadLocked(streamId, 1, std::move(body))) {
            ReleaseK6FairStreamLocked(streamId);
            return false;
        }
        const uint64 sent=m_exitServices.LT5Sent(stream.circ_id,streamId,1);
        const uint64 received=stream.flow.total_bytes(0);
        const uint64 remaining = stream.stream_max_bytes == 0 ||
                sent + received >= stream.stream_max_bytes
            ? (stream.stream_max_bytes == 0
                ? (std::numeric_limits<uint64>::max)() : 0)
            : stream.stream_max_bytes - sent - received;
        if(!m_exitServices.LT5CommitExitSend(source,streamId,stream.generation,1,length,remaining,
                (std::numeric_limits<uint64>::max)(),2u*1024u*1024u)||
            stream.flow.Accept(data)!=kad6::Kad6Status::Ok) {
            ReleaseK6FairStreamLocked(streamId);
            return false;
        }
        ++stream.tx_sequence;if(!m_exitServices.LT5UpdateExit(streamId,source,stream.generation,stream)){ReleaseK6FairStreamLocked(streamId);return false;}return true;
    }
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        K6ExitStreamRuntime stream;if(!m_exitServices.LT5FindExit(streamId,source,stream)||
            stream.flow.CanAccept(data)!=kad6::Kad6Status::Ok)
            return false;
        const uint64 sent=m_exitServices.LT5Sent(stream.circ_id,streamId,1);
        const uint64 received=stream.flow.total_bytes(0);
        const uint64 remaining = stream.stream_max_bytes == 0 ||
                sent + received >= stream.stream_max_bytes
            ? (stream.stream_max_bytes == 0
                ? (std::numeric_limits<uint64>::max)() : 0)
            : stream.stream_max_bytes - sent - received;
        if(!m_exitServices.LT5CommitExitSend(source,streamId,stream.generation,1,length,remaining,
                (std::numeric_limits<uint64>::max)(),2u*1024u*1024u)||
            stream.flow.Accept(data)!=kad6::Kad6Status::Ok)
            return false;
        ++stream.tx_sequence;if(!m_exitServices.LT5UpdateExit(streamId,source,stream.generation,stream))return false;
    }
    if (!SendK6GatewayPush(runtime.circuit, runtime.circ_id, 0,
            kad6::kK6MsgStreamData, kad6::kK6FlagFinal, body)) {
        CKad6ExitSocket* socket = NULL;
        {
            CSingleLock pl(&m_pendingLock, TRUE);
            K6ExitStreamRuntime stream;if(m_exitServices.LT5FindExit(streamId,source,stream))socket=stream.socket;
        }
        if (socket) socket->Disconnect(_T("Kad6 tunnel rejected accepted frame"));
        return false;
    }
    m_metrics.Add(kad6::K6MetricFamily::ExitBytesTotal, 0,
        runtime.inbound ? 3 : 2, 0, static_cast<uint64>(length),
        static_cast<uint64>(time(NULL)));
    m_metrics.Add(kad6::K6MetricFamily::TransportBytesTotal, 0, 0, 0,
        static_cast<uint64>(length), static_cast<uint64>(time(NULL)));
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        m_scheduler.LT2RecordUsefulBytes(static_cast<uint64>(length));
    }
    return true;
}

bool CLiveTunnel::SendK6FlowCredit(
    uint32 circId, const std::weak_ptr<CLiveCircuit>& circuit, bool fromExit,
    const kad6::K6MaxStreamData& streamCredit,const kad6::K6MaxData& circuitCredit)
{
    auto sendOne = [&](uint8 msgType, const std::vector<uint8_t>& body) -> bool {
        if(fromExit)return SendK6GatewayPush(circuit,circId,0,msgType,kad6::kK6FlagFinal,body);
        kad6::K6Frame frame;frame.msg_type=msgType;frame.request_id=NewCircuitId();frame.body=body;
        std::vector<uint8_t> wire;
        return kad6::EncodeK6Frame(frame,wire)==kad6::Kad6Status::Ok&&
            SendMessagePinned(frame.request_id,TUN_OP_KAD6_GATEWAY,wire.data(),
                wire.size(),ESE_CAP_KAD6,circId)==circId;
    };
    std::vector<uint8_t> streamBody,circuitBody;
    return kad6::EncodeK6MaxStreamData(streamCredit,streamBody)==kad6::Kad6Status::Ok&&
        kad6::EncodeK6MaxData(circuitCredit,circuitBody)==kad6::Kad6Status::Ok&&
        sendOne(kad6::kK6MsgMaxStreamData,streamBody)&&sendOne(kad6::kK6MsgMaxData,circuitBody);
}

bool CLiveTunnel::SendK6InitialCredit(
    uint32 circId, uint64 streamId, uint8 direction,
    const std::weak_ptr<CLiveCircuit>& circuit, bool fromExit)
{
    kad6::K6MaxStreamData streamCredit;kad6::K6MaxData circuitCredit;
    {
        CSingleLock pl(&m_pendingLock,TRUE);
        if(!m_exitServices.LT5InitialCredit(circId,streamId,direction,streamCredit,circuitCredit))return false;
    }
    return SendK6FlowCredit(circId,circuit,fromExit,streamCredit,circuitCredit);
}

bool CLiveTunnel::ConsumeK6ReceiveCredit(
    uint32 circId, uint64 streamId, uint8 direction, size_t bytes,
    const std::weak_ptr<CLiveCircuit>& circuit, bool fromExit)
{
    kad6::K6MaxStreamData streamCredit;kad6::K6MaxData circuitCredit;bool stillPaused=false;
    {
        CSingleLock pl(&m_pendingLock,TRUE);
        if(!m_exitServices.LT5Consume(circId,streamId,direction,bytes,M2A_LT3_K6ShapeNowUs()/1000u,streamCredit,circuitCredit))return false;
        stillPaused=m_exitServices.LT5ReadsPaused(circId);
    }
    return stillPaused||SendK6FlowCredit(circId,circuit,fromExit,streamCredit,circuitCredit);
}

void CLiveTunnel::FlushK6OriginCredit(uint32 circId)
{
    std::vector<CKad6OriginSocket*> resumed;std::vector<MainThreadReq> requests;
    CSingleLock pl(&m_pendingLock, TRUE);
    for(auto pair:m_exitServices.LT5OriginSnapshot()){
        K6OriginStreamRuntime& stream = pair.second;
        if (stream.circ_id != circId) continue;
        bool changed=false;
        while (!stream.pending_credit_frames.empty()) {
            K6QueuedOriginFrame& queued = stream.pending_credit_frames.front();
            const uint64 sent=m_exitServices.LT5Sent(circId,pair.first,0);
            const uint64 received = stream.flow.total_bytes(1);
            const uint64 remaining = stream.dial.max_bytes == 0 ||
                    sent + received >= stream.dial.max_bytes
                ? (stream.dial.max_bytes == 0 ? (std::numeric_limits<uint64>::max)() : 0)
                : stream.dial.max_bytes - sent - received;
            if(!m_exitServices.LT5CommitOriginSend(stream.socket,pair.first,stream.generation,0,queued.data_bytes,
                    remaining,(std::numeric_limits<uint64>::max)(),2u*1024u*1024u))
                break;
            MainThreadReq request;
            request.op = MT_SEND_MSG;
            request.reqId = queued.request_id;
            request.subCmd = TUN_OP_KAD6_GATEWAY;
            request.requiredExitCaps = ESE_CAP_KAD6;
            request.pinnedCircId = circId;
            request.k6StreamId = pair.first;
            request.k6Generation = stream.generation;
            request.k6FlowBytes = queued.wire.size();
            request.k6Sequence = queued.sequence;
            request.k6DataBytes = queued.data_bytes;
            request.payload = std::move(queued.wire);
            stream.pending_credit_bytes -= (std::min)(stream.pending_credit_bytes,
                queued.data_bytes);
            stream.pending_credit_frames.pop_front();
            requests.push_back(std::move(request));changed=true;
        }
        if (stream.pending_credit_frames.empty()) {
            stream.credit_stall_since_ms = 0;
            if (stream.socket) resumed.push_back(stream.socket);
        }
        if(changed)m_exitServices.LT5UpdateOrigin(pair.first,stream.socket,stream.generation,stream);
    }
    pl.Unlock();
    for(auto& request:requests)(void)m_scheduler.Enqueue(std::move(request));
    for (CKad6OriginSocket* socket : resumed)
        if (socket) socket->SetKad6FlowBlocked(false);
}

void CLiveTunnel::FlushK6ExitCredit(uint32 circId)
{
    struct Push {
        std::weak_ptr<CLiveCircuit> circuit;
        uint32 circ_id = 0;
        uint64 stream_id = 0;
        std::vector<uint8_t> body;
    };
    std::vector<Push> pushes;
    std::vector<CKad6ExitSocket*> resumed;
    std::vector<CKad6ExitSocket*> failed;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        for(auto pair:m_exitServices.LT5ExitSnapshot()){
            K6ExitStreamRuntime& stream = pair.second;
            if (stream.circ_id != circId || !stream.connected) continue;
            bool changed=false;
            while (!stream.pending_credit_frames.empty()) {
                const std::vector<uint8_t>& raw = stream.pending_credit_frames.front();
                const uint64 sent=m_exitServices.LT5Sent(circId,pair.first,1);
                const uint64 received = stream.flow.total_bytes(0);
                const uint64 remaining = stream.stream_max_bytes == 0 ||
                        sent + received >= stream.stream_max_bytes
                    ? (stream.stream_max_bytes == 0
                        ? (std::numeric_limits<uint64>::max)() : 0)
                    : stream.stream_max_bytes - sent - received;
                if (m_exitServices.LT5Available(circId,pair.first,1,remaining,
                        (std::numeric_limits<uint64>::max)(),
                        2u * 1024u * 1024u) < raw.size())
                    break;
                kad6::K6StreamData data;
                data.stream_id = pair.first;
                data.sequence = stream.tx_sequence;
                data.direction = 1;
                data.flags = 0x02;
                data.data = raw;
                std::vector<uint8_t> body;
                if (kad6::EncodeK6StreamData(data, body) != kad6::Kad6Status::Ok ||
                    stream.flow.CanAccept(data) != kad6::Kad6Status::Ok)
                    break;
                bool queued = false;
                if (stream.quota_allocation_id != 0) {
                    queued = QueueK6FairPayloadLocked(pair.first, 1, std::move(body));
                    if (!queued) break;
                }
                if(!m_exitServices.LT5CommitExitSend(stream.socket,pair.first,stream.generation,1,raw.size(),remaining,
                        (std::numeric_limits<uint64>::max)(),2u*1024u*1024u)||
                    stream.flow.Accept(data) != kad6::Kad6Status::Ok) {
                    if (queued) ReleaseK6FairStreamLocked(pair.first);
                    break;
                }
                ++stream.tx_sequence;
                if (stream.quota_allocation_id == 0) {
                    Push push;
                    push.circuit = stream.circuit;
                    push.circ_id = stream.circ_id;
                    push.stream_id = pair.first;
                    push.body = std::move(body);
                    pushes.push_back(std::move(push));
                    queued = true;
                }
                stream.pending_credit_bytes -= (std::min)(stream.pending_credit_bytes,
                    raw.size());
                stream.pending_credit_frames.pop_front();
                changed=true;
            }
            if (stream.pending_credit_frames.empty()) {
                stream.credit_stall_since_ms = 0;
                if (stream.socket) resumed.push_back(stream.socket);
            }
            if(changed)m_exitServices.LT5UpdateExit(pair.first,stream.socket,stream.generation,stream);
        }
    }
    for (const Push& push : pushes)
        if (!SendK6GatewayPush(push.circuit, push.circ_id, 0,
                kad6::kK6MsgStreamData, kad6::kK6FlagFinal, push.body)) {
            CSingleLock pl(&m_pendingLock, TRUE);
            K6ExitStreamRuntime stream;if(m_exitServices.LT5FindExit(push.stream_id,stream)&&stream.socket)failed.push_back(stream.socket);
        }
    for (CKad6ExitSocket* socket : failed)
        if (socket) socket->Disconnect(_T("Kad6 credit flush failed"));
    for (CKad6ExitSocket* socket : resumed)
        if (socket) socket->SetKad6ReadPaused(false);
}

void CLiveTunnel::OnK6ExitSocketConnect(uint64 streamId, CKad6ExitSocket* socket, int error)
{
    K6ExitStreamRuntime runtime; bool found = false;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        if(m_exitServices.LT5FindExit(streamId,socket,runtime)){
            found=true;
            if (error == 0) {
                const uint64 now = static_cast<uint64>(time(NULL));
                runtime.connected=true;runtime.last_activity=now;
                runtime.idle_deadline=now+((runtime.idle_timeout_ms+999u)/1000u);
                found=m_exitServices.LT5UpdateExit(streamId,socket,runtime.generation,runtime);
            }
            else {
                ReleaseK6FairStreamLocked(streamId);
                found=m_exitServices.LT5TakeExit(streamId,socket,runtime.generation,runtime);
            }
        }
    }
    if (!found) return;
    kad6::K6DialResult result; result.stream_id = streamId;
    result.status = error == 0 ? kad6::K6DialStatus::Ok : kad6::K6DialStatus::ConnectFailed;
    result.transport = kad6::K6GatewayTransport::TcpEd2k; result.apparent_local_endpoint = runtime.apparent;
    result.remote_endpoint = runtime.ticket.target_endpoint; result.max_bytes = runtime.stream_max_bytes;
    result.idle_timeout_ms = runtime.idle_timeout_ms;
    std::vector<uint8_t> body;
    if (kad6::EncodeK6DialResult(result, body) != kad6::Kad6Status::Ok) {
        CSingleLock pl(&m_pendingLock,TRUE);K6ExitStreamRuntime removed;m_exitServices.LT5TakeExit(streamId,socket,runtime.generation,removed);
        ReleaseK6FairStreamLocked(streamId); pl.Unlock();
        AbortExitOperation(runtime.circ_id, runtime.dial_request_id);
        if (socket) socket->Disconnect(_T("Kad6 DIAL result encode failed"));
        return;
    }
    if (error == 0) {
        size_t offset = 0;
        while (offset < runtime.initial_data.size()) {
            const uint8_t* p = runtime.initial_data.data() + offset;
            const uint32 n = static_cast<uint32>(p[1]) | (static_cast<uint32>(p[2]) << 8) |
                (static_cast<uint32>(p[3]) << 16) | (static_cast<uint32>(p[4]) << 24);
            const size_t total = 5ull + n;
            if (!socket->SendRawFrame(p, total)) { result.status = kad6::K6DialStatus::ConnectFailed; break; }
            offset += total;
        }
        kad6::EncodeK6DialResult(result, body);
    }
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        m_peerState.RecordSourceResult(BuildLiveSourceEndpointKey(
            runtime.ticket.target_endpoint, runtime.network_origin),
            result.status == kad6::K6DialStatus::Ok,
            static_cast<uint64>(time(NULL)));
    }
    m_metrics.Add(kad6::K6MetricFamily::SourceDialTotal,
        runtime.network_origin == kad6::kK6NetOriginKad6 ? 1 : 0,
        result.status == kad6::K6DialStatus::Ok ? 0 : 2, 0, 1,
        static_cast<uint64>(time(NULL)));
    if (result.status != kad6::K6DialStatus::Ok) {
        CSingleLock pl(&m_pendingLock,TRUE);K6ExitStreamRuntime removed;m_exitServices.LT5TakeExit(streamId,socket,runtime.generation,removed);
        ReleaseK6FairStreamLocked(streamId);
    }
    kad6::K6Frame response; response.msg_type = kad6::kK6MsgDialOk;
    response.flags = kad6::kK6FlagResponse | kad6::kK6FlagFinal;
    response.request_id = runtime.dial_request_id; response.body = body;
    std::vector<uint8_t> wire;
    if (kad6::EncodeK6Frame(response, wire) != kad6::Kad6Status::Ok ||
        !CompleteExitOperation(runtime.circ_id, runtime.dial_request_id,
                               wire.data(), wire.size())) {
        CSingleLock pl(&m_pendingLock,TRUE);K6ExitStreamRuntime removed;m_exitServices.LT5TakeExit(streamId,socket,runtime.generation,removed);
        ReleaseK6FairStreamLocked(streamId); pl.Unlock();
        if (socket) socket->Disconnect(_T("Kad6 DIAL reply failed"));
        return;
    }

    if (result.status != kad6::K6DialStatus::Ok) {
        if (socket) socket->Disconnect(_T("Kad6 initial data failed"));
        return;
    }

    if (result.status == kad6::K6DialStatus::Ok) {
        if (!SendK6InitialCredit(runtime.circ_id, streamId, 0,
                runtime.circuit, true)) {
            if (socket) socket->Disconnect(_T("Kad6 initial credit failed"));
            return;
        }
        const uint64 metricNow = static_cast<uint64>(time(NULL));
        m_metrics.Add(kad6::K6MetricFamily::ExitAdmissionTotal, 2, 0, 0, 1,
                        metricNow);
        const uint8_t* pub = NodeIdentityPub();
        if (!pub) return;
        kad6::K6VirtualIdentityEndpoint vep;
        vep.apparent_source_ip = runtime.apparent.addr;
        vep.apparent_tcp_port = runtime.apparent.tcp_port;
        vep.apparent_udp_port = runtime.apparent.udp_port;
        memcpy(vep.exit_node_pub.data(), pub, 32);
        vep.source_lease_id = streamId;
        vep.valid_until = static_cast<uint64>(time(NULL)) + kad6::kK6VepMaxTtlSeconds;
        std::vector<uint8_t> vepBody;
        if (kad6::SignK6Vep(MakeKad6HostCryptoHooks(), vep, vepBody) == kad6::Kad6Status::Ok)
            SendK6GatewayPush(runtime.circuit, runtime.circ_id, 0,
                kad6::kK6MsgVep, kad6::kK6FlagFinal, vepBody);
    }
}

void CLiveTunnel::OnK6ExitSocketClosed(uint64 streamId, CKad6ExitSocket* socket, int error)
{
    (void)error;
    K6ExitStreamRuntime runtime; bool found = false;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        if(m_exitServices.LT5FindExit(streamId,socket,runtime)){
            m_kadBridge.LT3CohortReleaseStream(streamId);
            ReleaseK6FairStreamLocked(streamId);
            found=m_exitServices.LT5TakeExit(streamId,socket,runtime.generation,runtime);
        }
    }
    if (!found || !runtime.connected) return;
    kad6::K6StreamClose close; close.stream_id = streamId; close.reason_code = 1;
    close.last_tx_sequence = runtime.flow.next_sequence(0)
        ? runtime.flow.next_sequence(0) - 1 : 0;
    close.last_rx_sequence = runtime.flow.next_sequence(1)
        ? runtime.flow.next_sequence(1) - 1 : 0;
    close.total_tx_bytes = runtime.flow.total_bytes(0);
    close.total_rx_bytes = runtime.flow.total_bytes(1);
    std::vector<uint8_t> body;
    if (kad6::EncodeK6StreamClose(close, body) == kad6::Kad6Status::Ok)
        SendK6GatewayPush(runtime.circuit, runtime.circ_id, 0,
            kad6::kK6MsgStreamClose, kad6::kK6FlagFinal, body);
}

void CLiveTunnel::OnK6OriginSocketClosed(uint64 streamId, CKad6OriginSocket* socket)
{
    K6OriginStreamRuntime runtime;
    bool found = false;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        if(m_exitServices.LT5FindOrigin(streamId,socket,runtime))
            found=m_exitServices.LT5TakeOrigin(streamId,socket,runtime.generation,runtime);
    }
    if (!found) return;
    if (runtime.client) runtime.client->ClearK6SecureIdentVep();

    kad6::K6StreamClose close;
    close.stream_id = streamId;
    close.reason_code = 1;
    close.last_tx_sequence = runtime.flow.next_sequence(0)
        ? runtime.flow.next_sequence(0) - 1 : 0;
    close.last_rx_sequence = runtime.flow.next_sequence(1)
        ? runtime.flow.next_sequence(1) - 1 : 0;
    close.total_tx_bytes = runtime.flow.total_bytes(0);
    close.total_rx_bytes = runtime.flow.total_bytes(1);
    std::vector<uint8_t> body, wire;
    kad6::K6Frame frame;
    frame.msg_type = kad6::kK6MsgStreamClose;
    frame.flags = kad6::kK6FlagLegacyEd2k | kad6::kK6FlagFinal;
    frame.request_id = NewCircuitId();
    if (kad6::EncodeK6StreamClose(close, body) == kad6::Kad6Status::Ok) {
        frame.body = std::move(body);
        if (kad6::EncodeK6Frame(frame, wire) == kad6::Kad6Status::Ok)
            SendMessagePinned(frame.request_id, TUN_OP_KAD6_GATEWAY,
                wire.data(), wire.size(), ESE_CAP_KAD6, runtime.circ_id);
    }
}

void CLiveTunnel::ExitHandle_Kad6StreamData(const TunnelRequestCtx& ctx,
                                             const kad6::K6Frame& frame)
{
    kad6::K6StreamData data; size_t consumed = 0;
    if (kad6::DecodeK6StreamData(frame.body.data(), frame.body.size(), data, &consumed) !=
            kad6::Kad6Status::Ok || consumed != frame.body.size() || data.direction != 0 ||
        (data.flags & 0x02) == 0) return;
    kad6::K6Ed2kFrameView view;
    if (kad6::DecodeK6Ed2kFrame(data.data.data(), data.data.size(), view) != kad6::Kad6Status::Ok)
        return;
    CKad6ExitSocket* socket = NULL; kad6::K6Endpoint apparent;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        K6ExitStreamRuntime stream;if(!m_exitServices.LT5FindExit(data.stream_id,stream)||
            stream.circ_id!=ctx.circ->Id()||!stream.connected||
            !m_exitServices.LT5CanAccept(ctx.circ->Id(),data.stream_id,0,data.data.size())||
            stream.flow.CanAccept(data)!=kad6::Kad6Status::Ok)return;
        if(!m_exitServices.LT5Accept(ctx.circ->Id(),data.stream_id,0,data.data.size(),M2A_LT3_K6ShapeNowUs()/1000u)||
            stream.flow.Accept(data)!=kad6::Kad6Status::Ok)return;
        socket=stream.socket;apparent=stream.apparent;
        const uint64 now = static_cast<uint64>(time(NULL));
        const uint64 idle=(stream.idle_timeout_ms+999u)/1000u;stream.last_activity=now;stream.idle_deadline=now+idle;
        if(!m_exitServices.LT5UpdateExit(data.stream_id,socket,stream.generation,stream))return;
    }
    const kad6::K6Ed2kDisposition disposition = kad6::K6Ed2kPolicy(
        kad6::K6Ed2kDirection::OriginToRemote,
        kad6::ClassifyK6Ed2kFrame(view.protocol, view.opcode));
    std::vector<uint8_t> rewritten;
    if (disposition == kad6::K6Ed2kDisposition::Pass)
        rewritten = data.data;
    else if (disposition == kad6::K6Ed2kDisposition::RewriteEndpoint) {
        const bool ok = (view.opcode == OP_HELLO || view.opcode == OP_HELLOANSWER)
            ? SanitizeK6HelloFrame(data.data.data(), data.data.size(), apparent, rewritten)
            : kad6::RewriteK6Ed2kPublicIpAnswer(view, apparent.addr, rewritten) == kad6::Kad6Status::Ok;
        if (!ok) {
            ConsumeK6ReceiveCredit(ctx.circ->Id(), data.stream_id, 0,
                data.data.size(), ctx.circ, true);
            return;
        }
    } else if (disposition == kad6::K6Ed2kDisposition::Drop) {
        ConsumeK6ReceiveCredit(ctx.circ->Id(), data.stream_id, 0,
            data.data.size(), ctx.circ, true);
        return;
    } else {
        ConsumeK6ReceiveCredit(ctx.circ->Id(), data.stream_id, 0,
            data.data.size(), ctx.circ, true);
        return;
    }
    bool fairStream = false;
    bool fairQueued = false;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        fairStream = m_scheduler.HasFairStream(data.stream_id);
        if (fairStream)
            fairQueued = QueueK6FairPayloadLocked(data.stream_id, 0,
                std::move(rewritten), data.data.size());
        if (fairStream && !fairQueued) ReleaseK6FairStreamLocked(data.stream_id);
    }
    if (fairStream) {
        if (!fairQueued && socket)
            socket->Disconnect(_T("Kad6 fair queue capacity exhausted"));
        return;
    }
    if (socket && socket->SendRawFrame(rewritten.data(), rewritten.size())) {
        bool inbound = false;
        {
            CSingleLock pl(&m_pendingLock, TRUE);
            K6ExitStreamRuntime stream;inbound=m_exitServices.LT5FindExit(data.stream_id,stream)&&stream.inbound;
        }
        m_metrics.Add(kad6::K6MetricFamily::ExitBytesTotal, 1,
            inbound ? 3 : 2, 0, static_cast<uint64>(rewritten.size()),
            static_cast<uint64>(time(NULL)));
        m_metrics.Add(kad6::K6MetricFamily::TransportBytesTotal, 0, 1, 0,
            static_cast<uint64>(rewritten.size()), static_cast<uint64>(time(NULL)));
        {
            CSingleLock pl(&m_pendingLock, TRUE);
            m_scheduler.LT2RecordUsefulBytes(static_cast<uint64>(rewritten.size()));
        }
        ConsumeK6ReceiveCredit(ctx.circ->Id(), data.stream_id, 0,
            data.data.size(), ctx.circ, true);
    } else if (socket) {
        socket->Disconnect(_T("Kad6 downstream socket rejected frame"));
    }
}

void CLiveTunnel::ExitHandle_Kad6StreamHalfClose(const TunnelRequestCtx& ctx,
                                                  const kad6::K6Frame& frame)
{
    kad6::K6StreamHalfClose close;size_t consumed=0;
    if(kad6::DecodeK6StreamHalfClose(frame.body.data(),frame.body.size(),close,&consumed)!=kad6::Kad6Status::Ok||
       consumed!=frame.body.size()||close.direction!=0)return;
    CSingleLock pl(&m_pendingLock,TRUE);m_exitServices.LT5HalfCloseExit(ctx.circ->Id(),close);
}

void CLiveTunnel::ExitHandle_Kad6StreamClose(const TunnelRequestCtx& ctx,
                                              const kad6::K6Frame& frame)
{
    kad6::K6StreamClose close;size_t consumed=0;CKad6ExitSocket* socket=NULL;
    if(kad6::DecodeK6StreamClose(frame.body.data(),frame.body.size(),close,&consumed)!=kad6::Kad6Status::Ok||consumed!=frame.body.size())return;
    {
        CSingleLock pl(&m_pendingLock,TRUE);K6ExitStreamRuntime stream;
        if(!m_exitServices.LT5CloseExit(ctx.circ->Id(),close,stream))return;socket=stream.socket;
        m_kadBridge.LT3CohortReleaseStream(close.stream_id);ReleaseK6FairStreamLocked(close.stream_id);
    }
    if(socket)socket->Disconnect(_T("Kad6 stream closed"));
}

void CLiveTunnel::ExitHandle_Kad6MaxStreamData(const TunnelRequestCtx& ctx,
                                                const kad6::K6Frame& frame)
{
    kad6::K6MaxStreamData credit;size_t consumed=0;
    if(kad6::DecodeK6MaxStreamData(frame.body.data(),frame.body.size(),credit,&consumed)!=kad6::Kad6Status::Ok||
       consumed!=frame.body.size()||credit.direction!=1)return;
    {
        CSingleLock pl(&m_pendingLock,TRUE);
        K6ExitStreamRuntime stream;if(!m_exitServices.LT5FindExit(credit.stream_id,stream)||
           stream.circ_id!=ctx.circ->Id()||!m_exitServices.LT5Grant(ctx.circ->Id(),credit))return;
    }
    FlushK6ExitCredit(ctx.circ->Id());
}

void CLiveTunnel::ExitHandle_Kad6MaxData(const TunnelRequestCtx& ctx,
                                          const kad6::K6Frame& frame)
{
    kad6::K6MaxData credit;size_t consumed=0;
    if(kad6::DecodeK6MaxData(frame.body.data(),frame.body.size(),credit,&consumed)!=kad6::Kad6Status::Ok||
       consumed!=frame.body.size()||credit.direction!=1)return;
    {
        CSingleLock pl(&m_pendingLock,TRUE);if(!m_exitServices.LT5Grant(ctx.circ->Id(),credit))return;
    }
    FlushK6ExitCredit(ctx.circ->Id());
}

void CLiveTunnel::SweepK6Gateway(uint64 nowSeconds, const std::set<uint32_t>& activeCircuits) {
    struct ExpiredExit { uint64 stream_id = 0; K6ExitStreamRuntime runtime; uint16 reason = 0; };
    struct ExpiredOrigin { uint64 stream_id = 0; K6OriginStreamRuntime runtime; uint16 reason = 0; };
    std::vector<ExpiredExit> exits; std::vector<ExpiredOrigin> origins;
    LiveTunnelOriginSweepResult originSweep;
    std::vector<uint64> stoppedLeases,releasedCohortStreams;
    const DWORD nowTick = GetTickCount();
    const uint64 nowFlowMs=M2A_LT3_K6ShapeNowUs()/1000u;
    std::array<uint64, static_cast<size_t>(kad6::K6Service::Count)> serviceActive{};
    double streamProfiles[4][3] = {};
    std::set<uint32> strictCircuits;
    for(const auto& circuit:m_circuitRegistry.GetSnapshot())
        if(circuit&&circuit->m_strict3&&circuit->m_shaped_ok&&circuit->State()==CircuitState::Active)
            strictCircuits.insert(circuit->Id());
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        serviceActive[static_cast<size_t>(kad6::K6Service::Control)]=static_cast<uint64>(m_searchJobs.size());
        for(const auto& pair:m_kadBridge.LT3SourceLeaseEntries())
            if(pair.second.state!=kad6::K6SourceLeaseState::Closed)
                ++serviceActive[static_cast<size_t>(kad6::K6Service::ExitKad)];
        for(const auto& pair:m_exitServices.LT5ExitSnapshot()){
            const size_t service=static_cast<size_t>(pair.second.inbound?kad6::K6Service::ExitEd2kFull:kad6::K6Service::ExitEd2kDial);
            ++serviceActive[service];
            const size_t profile=strictCircuits.find(pair.second.circ_id)!=strictCircuits.end()?2:1;
            streamProfiles[service][profile]+=1.0;
        }
    }
    const kad6::K6DrainResult drain = m_scheduler.LT2HardeningTick(nowSeconds, serviceActive);
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        if((drain.force_close_mask&kad6::K6ServiceBit(kad6::K6Service::ExitKad))!=0){
            std::vector<uint64> leases;
            leases.reserve(m_kadBridge.LT3SourceLeaseEntries().size());
            for(const auto& pair:m_kadBridge.LT3SourceLeaseEntries())
                if(pair.second.state!=kad6::K6SourceLeaseState::Closed)
                    leases.push_back(pair.first);
            for(uint64 lease:leases){m_kadBridge.LT3CloseSourceLease(lease);stoppedLeases.push_back(lease);}
            m_exitServices.LT4ResetPublishes();
            m_kadBridge.LT3EraseClosedSourceLeases(static_cast<size_t>(-1));
        }
        m_exitServices.LT4PruneTicketState(nowSeconds);
        m_scheduler.LT2PruneQuotaGrants(nowSeconds);
        originSweep=m_kadBridge.LT6Sweep(nowSeconds,static_cast<std::uint32_t>(nowTick),activeCircuits);

        for(auto pair:m_exitServices.LT5ExitSnapshot()){
            uint16 reason = 0;
            const auto streamService=pair.second.inbound?kad6::K6Service::ExitEd2kFull:kad6::K6Service::ExitEd2kDial;
            if(pair.second.kill_switch_close||(drain.force_close_mask&kad6::K6ServiceBit(streamService)))reason=5;
            else if(activeCircuits.find(pair.second.circ_id)==activeCircuits.end())reason=3;
            else if(!pair.second.connected&&pair.second.connect_deadline&&pair.second.connect_deadline<=nowSeconds)reason=4;
            else if(pair.second.credit_stall_since_ms&&nowFlowMs>=pair.second.credit_stall_since_ms&&nowFlowMs-pair.second.credit_stall_since_ms>=kad6::kK6CreditStallDeadlineMs)reason=6;
            else if(pair.second.idle_deadline&&pair.second.idle_deadline<=nowSeconds)reason=2;
            if(!reason)continue;
            ExpiredExit expired;expired.stream_id=pair.first;expired.reason=reason;
            if(!m_exitServices.LT5TakeExit(pair.first,pair.second.socket,pair.second.generation,expired.runtime))continue;
            exits.push_back(std::move(expired));
            releasedCohortStreams.push_back(pair.first);ReleaseK6FairStreamLocked(pair.first);
        }
        for(auto pair:m_exitServices.LT5OriginSnapshot()){
            const bool creditStalled=pair.second.credit_stall_since_ms&&nowFlowMs>=pair.second.credit_stall_since_ms&&nowFlowMs-pair.second.credit_stall_since_ms>=kad6::kK6CreditStallDeadlineMs;
            if(!creditStalled&&activeCircuits.find(pair.second.circ_id)!=activeCircuits.end()&&(!pair.second.idle_deadline||pair.second.idle_deadline>nowSeconds))continue;
            ExpiredOrigin expired;expired.stream_id=pair.first;
            expired.reason=activeCircuits.find(pair.second.circ_id)==activeCircuits.end()?3:creditStalled?6:2;
            if(!m_exitServices.LT5TakeOrigin(pair.first,pair.second.socket,pair.second.generation,expired.runtime))continue;
            origins.push_back(std::move(expired));
        }
        m_peerState.SweepSourceHistory(nowSeconds);
    }

    // All callbacks stay outside m_pendingLock because they may re-enter.
    for(uint64 lease:stoppedLeases)m_kadBridge.LT3CohortSetServing(lease,false);
    for(uint64 stream:releasedCohortStreams)m_kadBridge.LT3CohortReleaseStream(stream);
    for(const auto& action:originSweep.actions){
        if(action.kind==LiveTunnelOriginActionKind::SourceLookupExpired){
            if(!theApp.downloadqueue)continue;
            CPartFile* file=theApp.downloadqueue->GetFileByKadFileSearchID(action.request_id);
            if(file)file->SetKadFileSearchID(0);
        }else if(action.kind==LiveTunnelOriginActionKind::DownloadActivationExpired){
            auto* client=reinterpret_cast<CUpDownClient*>(action.client_token);if(!client)continue;
            if(client->Disconnected(_T("Kad6 gateway DIAL timeout or circuit closed")))delete client;
        }
    }
    for (const ExpiredExit& expired : exits) {
        const auto& runtime=expired.runtime;
        if(expired.reason==4){
            {
                CSingleLock pl(&m_pendingLock, TRUE);
                m_peerState.RecordSourceFailure(BuildLiveSourceEndpointKey(runtime.ticket.target_endpoint,runtime.network_origin),nowSeconds);
            }
            m_metrics.Add(kad6::K6MetricFamily::SourceDialTotal,runtime.network_origin==kad6::kK6NetOriginKad6?1:0,3,0,1,nowSeconds);
        }
        if(!runtime.connected){
            if(expired.reason==4){
                kad6::K6DialResult result; result.stream_id = expired.stream_id;
                result.status=kad6::K6DialStatus::Timeout;result.transport=kad6::K6GatewayTransport::TcpEd2k;
                result.apparent_local_endpoint=runtime.apparent;result.remote_endpoint=runtime.ticket.target_endpoint;
                result.max_bytes=runtime.stream_max_bytes;result.idle_timeout_ms=runtime.idle_timeout_ms;
                std::vector<uint8_t> body, wire;
                kad6::K6Frame frame;frame.msg_type=kad6::kK6MsgDialOk;frame.flags=kad6::kK6FlagResponse|kad6::kK6FlagFinal;frame.request_id=runtime.dial_request_id;
                if(kad6::EncodeK6DialResult(result,body)==kad6::Kad6Status::Ok){
                    frame.body=std::move(body);
                    if(kad6::EncodeK6Frame(frame,wire)==kad6::Kad6Status::Ok)CompleteExitOperation(runtime.circ_id,runtime.dial_request_id,wire.data(),wire.size());
                }
            }else AbortExitOperation(runtime.circ_id,runtime.dial_request_id);
        }else{
            kad6::K6StreamClose close;close.stream_id=expired.stream_id;close.reason_code=expired.reason;
            close.last_tx_sequence=runtime.flow.next_sequence(0)?runtime.flow.next_sequence(0)-1:0;
            close.last_rx_sequence=runtime.flow.next_sequence(1)?runtime.flow.next_sequence(1)-1:0;
            close.total_tx_bytes=runtime.flow.total_bytes(0);close.total_rx_bytes=runtime.flow.total_bytes(1);
            std::vector<uint8_t> body;
            if(kad6::EncodeK6StreamClose(close,body)==kad6::Kad6Status::Ok)SendK6GatewayPush(runtime.circuit,runtime.circ_id,0,kad6::kK6MsgStreamClose,kad6::kK6FlagFinal,body);
        }
        if(runtime.socket)runtime.socket->Disconnect(expired.reason==2?_T("Kad6 idle timeout"):expired.reason==4?_T("Kad6 connect timeout"):expired.reason==5?_T("Kad6 local kill switch"):_T("Kad6 circuit closed"));
    }
    for (const ExpiredOrigin& expired : origins) {
        const auto& runtime=expired.runtime;
        if(activeCircuits.find(runtime.circ_id)!=activeCircuits.end()){
            kad6::K6StreamClose close;close.stream_id=expired.stream_id;close.reason_code=expired.reason;
            close.last_tx_sequence=runtime.flow.next_sequence(0)?runtime.flow.next_sequence(0)-1:0;
            close.last_rx_sequence=runtime.flow.next_sequence(1)?runtime.flow.next_sequence(1)-1:0;
            close.total_tx_bytes=runtime.flow.total_bytes(0);close.total_rx_bytes=runtime.flow.total_bytes(1);
            std::vector<uint8_t> body, wire;
            kad6::K6Frame frame;frame.msg_type=kad6::kK6MsgStreamClose;frame.flags=kad6::kK6FlagLegacyEd2k|kad6::kK6FlagFinal;frame.request_id=NewCircuitId();
            if(kad6::EncodeK6StreamClose(close,body)==kad6::Kad6Status::Ok){
                frame.body=std::move(body);
                if(kad6::EncodeK6Frame(frame,wire)==kad6::Kad6Status::Ok)SendMessagePinned(frame.request_id,TUN_OP_KAD6_GATEWAY,wire.data(),wire.size(),ESE_CAP_KAD6,runtime.circ_id);
            }
        }
        if(runtime.client)runtime.client->ClearK6SecureIdentVep();
        if(runtime.socket)runtime.socket->Disconnect(_T("Kad6 stream expired"));
    }

    const double leaseCapacity=static_cast<double>(serviceActive[static_cast<size_t>(kad6::K6Service::ExitKad)])/4096.0;
    const double dialCapacity=static_cast<double>(serviceActive[static_cast<size_t>(kad6::K6Service::ExitEd2kDial)])/512.0;
    const double fullCapacity=static_cast<double>(serviceActive[static_cast<size_t>(kad6::K6Service::ExitEd2kFull)])/512.0;
    m_metrics.Observe(kad6::K6MetricFamily::ExitCapacityRatio,1,0,0,leaseCapacity,nowSeconds);
    m_metrics.Observe(kad6::K6MetricFamily::ExitCapacityRatio,2,0,0,dialCapacity,nowSeconds);
    m_metrics.Observe(kad6::K6MetricFamily::ExitCapacityRatio,3,0,0,fullCapacity,nowSeconds);
    for(uint8 service=2;service<=3;++service)for(uint8 profile=1;profile<=2;++profile)for(uint8 state=0;state<4;++state)
        m_metrics.Observe(kad6::K6MetricFamily::Sessions,service,profile,state,state==1?streamProfiles[service][profile]:0.0,nowSeconds);
    RefreshK6EconomyMeasurements(nowSeconds, serviceActive);
    EnsureK6QuotaAuthority(nowSeconds);
    RefreshK6PublicRelease(nowSeconds);
}

bool CLiveTunnel::K6BindSource(const kad6::K6SourceBind& bind, kad6::K6SourceBound& boundOut, uint32_t timeoutMs) {
    boundOut = kad6::K6SourceBound{};
    const uint32_t requiredCaps = ESE_CAP_KAD6 | ((bind.flags & kad6::kK6SourceStrict) ? (ESE_CAP_TUNNEL_STRICT3 | ESE_CAP_TUNNEL_SHAPED) : 0);
    const uint32 targetCircuit = K6SelectOriginCircuit(requiredCaps, 0, 2);
    if (targetCircuit == 0) return false;
    std::vector<uint8_t> body;
    if (kad6::EncodeK6SourceBind(bind, body) != kad6::Kad6Status::Ok) return false;
    if (K6CircuitHasExitCaps(targetCircuit, ESE_CAP_KAD6_ECONOMY, 2) && !K6AcquireAnonymousQuota(targetCircuit, kad6::K6QuotaService::ExitKad, kad6::kK6MsgSourceBind, body, (std::max<uint32>)(3, timeoutMs / 2)) && IsK6PublicReleaseEnabled())
        return false;
    uint32 pinnedCircuit=targetCircuit;
    kad6::K6Frame response;
    size_t consumed = 0;
    if(!K6QuotaRoundTrip(targetCircuit,kad6::kK6MsgSourceBind,body,kad6::kK6MsgSourceBound,timeoutMs,response)|| kad6::DecodeK6SourceBound(response.body.data(),response.body.size(),boundOut, &consumed) != kad6::Kad6Status::Ok || consumed != response.body.size())
        return false;
    if (boundOut.status != kad6::K6SourceBoundStatus::Ok || pinnedCircuit == 0)
        return false;
    std::array<uint8_t, kad6::kEd25519PubSize> expectedExit{};
    bool exitPinned = false;
    {
        CSingleLock lock(&m_lock, TRUE);
        for (const auto& circuit : m_circuitRegistry.GetSnapshot()) {
            if (!circuit || circuit->Id() != pinnedCircuit || circuit->m_role != CircuitRole::Originator || circuit->State() != CircuitState::Active || !circuit->m_auth_ok || circuit->HopCount() == 0)
                continue;
            memcpy(expectedExit.data(), circuit->Hop(circuit->HopCount() - 1).pub_long, expectedExit.size());
            exitPinned = true;
            break;
        }
    }
    // Bind the signature to the authenticated final hop of this response.
    if (!exitPinned || kad6::VerifyK6SourceBound(MakeKad6HostCryptoHooks(), bind, boundOut, expectedExit.data()) != kad6::Kad6Status::Ok)
        return false;
    m_kadBridge.LT6AddSourceRoute( boundOut.source_lease_id, pinnedCircuit);
    return true;
}

bool CLiveTunnel::K6PublishRecord(const kad6::K6Publish& publish, kad6::K6PublishAck& ackOut, uint32_t timeoutMs) {
    ackOut = kad6::K6PublishAck{};
    if (!HasActiveCircuitWithExitCaps(ESE_CAP_KAD6)) return false;
    std::vector<uint8_t> body;
    if (kad6::EncodeK6Publish(publish, body) != kad6::Kad6Status::Ok) return false;
    uint64 sourceLeaseId = 0;
    uint32 pinnedCircuit = 0;
    if (publish.record_kind == kad6::K6RecordKind::Source && publish.record.size() == 17 && publish.record[0] == 1) {
        for (size_t i = 0; i < 8; ++i)
            sourceLeaseId |= static_cast<uint64>(publish.record[1 + i]) << (8 * i);
    } else if (publish.record_kind == kad6::K6RecordKind::Kad6SourceDescriptor) {
        kad6::K6SourceRecord record;
        size_t used = 0;
        if (kad6::DecodeK6SourceRecord(publish.record.data(), publish.record.size(), record, &used) == kad6::Kad6Status::Ok && used == publish.record.size()) {
            for (const auto& descriptor : record.exits)
                if (m_kadBridge.LT6FindSourceRoute( descriptor.lease_hint, pinnedCircuit)) {
                    sourceLeaseId = descriptor.lease_hint;
                    break;
                }
        }
    }
    m_kadBridge.LT6FindSourceRoute(sourceLeaseId, pinnedCircuit);
    if (sourceLeaseId == 0 || pinnedCircuit == 0) return false;

    if (K6CircuitHasExitCaps(pinnedCircuit, ESE_CAP_KAD6_ECONOMY, 2) && !K6AcquireAnonymousQuota(pinnedCircuit, kad6::K6QuotaService::ExitKad, kad6::kK6MsgPublish, body, (std::max<uint32>)(3, timeoutMs / 2)) && IsK6PublicReleaseEnabled())
        return false;

    kad6::K6Frame response;
    size_t consumed = 0;
    if(!K6QuotaRoundTrip(pinnedCircuit,kad6::kK6MsgPublish,body,kad6::kK6MsgPublishAck,timeoutMs,response)|| kad6::DecodeK6PublishAck(response.body.data(), response.body.size(), ackOut, &consumed) != kad6::Kad6Status::Ok || consumed != response.body.size())
        return false;
    if (ackOut.status == kad6::K6PublishStatus::Rejected) return false;
    m_kadBridge.LT6AddPublishRoute( ackOut.publish_lease_id, pinnedCircuit);
    return true;
}

void CLiveTunnel::K6SourceUnbindNoWait(const kad6::K6SourceUnbind& unbind) {
    if (!HasActiveCircuitWithExitCaps(ESE_CAP_KAD6)) return;
    std::vector<uint8_t> body, wire;
    if (kad6::EncodeK6SourceUnbind(unbind, body) != kad6::Kad6Status::Ok) return;
    const uint32_t reqId = NewCircuitId();
    kad6::K6Frame frame; frame.msg_type = kad6::kK6MsgSourceUnbind;
    frame.request_id = reqId; frame.body = std::move(body);
    uint32 pinnedCircuit = 0;
    m_kadBridge.LT6TakeSourceRoute( unbind.source_lease_id, pinnedCircuit);
    if (pinnedCircuit != 0 && kad6::EncodeK6Frame(frame, wire) == kad6::Kad6Status::Ok)
        EnqueueSendMsg(reqId, TUN_OP_KAD6_GATEWAY, wire.data(), wire.size(), ESE_CAP_KAD6, pinnedCircuit);
}

void CLiveTunnel::K6UnpublishNoWait(const kad6::K6Unpublish& unpublish) {
    if (!HasActiveCircuitWithExitCaps(ESE_CAP_KAD6)) return;
    std::vector<uint8_t> body, wire;
    if (kad6::EncodeK6Unpublish(unpublish, body) != kad6::Kad6Status::Ok) return;
    const uint32_t reqId = NewCircuitId();
    kad6::K6Frame frame; frame.msg_type = kad6::kK6MsgUnpublish;
    frame.request_id = reqId; frame.body = std::move(body);
    uint32 pinnedCircuit = 0;
    m_kadBridge.LT6TakePublishRoute( unpublish.publish_lease_id, pinnedCircuit);
    if (pinnedCircuit != 0 && kad6::EncodeK6Frame(frame, wire) == kad6::Kad6Status::Ok)
        EnqueueSendMsg(reqId, TUN_OP_KAD6_GATEWAY, wire.data(), wire.size(), ESE_CAP_KAD6, pinnedCircuit);
}

static void FinishK6OriginAdvertise(LiveTunnelKadBridge& bridge,const std::string& key,
    uint64 generation,bool success,uint64 sourceLeaseId,uint64 publishLeaseId,uint32 refreshAfter){
    LiveTunnelOriginAdvertiseCompletion completion;completion.success=success;
    completion.source_lease_id=sourceLeaseId;completion.publish_lease_id=publishLeaseId;
    completion.refresh_after=(std::max)(30u,refreshAfter);completion.now=static_cast<uint64>(time(NULL));
    if(!bridge.LT6FinishAdvertise(key,generation,completion))return;
    if(success)LIVE_LOG("K6","source advertised lease=%llu publish=%llu refresh=%u",static_cast<unsigned long long>(sourceLeaseId),static_cast<unsigned long long>(publishLeaseId),refreshAfter);
    else LIVE_LOG("K6","source advertise failed; retry in %u s",refreshAfter);}
void CLiveTunnel::QueueK6SourceAdvertise(const uint8_t fileHash[16], uint64 fileSize, kad6::K6CommitmentKind commitmentKind, const uint8_t commitment[32]) {
    if (!fileHash || !commitment || fileSize == 0 || theApp.IsClosing() || !thePrefs.IsKad2Enabled() || commitmentKind == kad6::K6CommitmentKind::None || !NodeIdentityIsPersistent() || !HasActiveCircuitWithExitCaps(ESE_CAP_KAD6))
        return;
    uint8 anyHash = 0, anyCommitment = 0;
    for (size_t i = 0; i < 16; ++i) anyHash |= fileHash[i];
    for (size_t i = 0; i < 32; ++i) anyCommitment |= commitment[i];
    if (!anyHash || !anyCommitment) return;

    const uint64 now = static_cast<uint64>(time(NULL));
    const std::string key = K6BinaryKey(fileHash, 16);
    const uint64 timeBase = now <= ((std::numeric_limits<uint64>::max)() >> 20) ? now << 20 : now;
    const LiveTunnelOriginAdvertiseReservation reservation = m_kadBridge.LT6ReserveAdvertise(key, now, timeBase);
    if (!reservation.accepted)
        return;

    const uint8_t* publicKey = NodeIdentityPub();
    const kad6::Kad6CryptoHooks crypto = MakeKad6HostCryptoHooks();
    kad6::K6SourceBind bind;
    memcpy(bind.file_hash.data(), fileHash, bind.file_hash.size());
    bind.file_size = fileSize;
    memcpy(bind.compat_user_hash.data(), thePrefs.GetUserHash(), bind.compat_user_hash.size());
    bind.desired_family = 4;
    bind.transport_mask = kad6::kK6TransportTcp;
    bind.flags = kad6::kK6SourceAllowInbound | kad6::kK6SourceStrict | kad6::kK6SourceFile;
    bind.requested_lifetime_s = 2u * 60u * 60u;
    const uint64 maxUpload = static_cast<uint64>(thePrefs.GetMaxUpload()) * 1024ull;
    bind.max_upload_bps = static_cast<uint32>((std::min<uint64>)( maxUpload, kad6::kK6SourceMaxUploadBps));
    bind.source_epoch = reservation.epoch;
    bind.requested_mode = kad6::K6BindingMode::Cohort;
    bind.commitment_kind = commitmentKind;
    memcpy(bind.content_commitment.data(), commitment, bind.content_commitment.size());
    bool prepared = publicKey && crypto.random_bytes && crypto.random_bytes(bind.bind_nonce.data(), bind.bind_nonce.size()) && kad6::MakeK6CompatProofV1(crypto, NULL, 0, publicKey, bind) == kad6::Kad6Status::Ok;
    const bool submitted = prepared && m_kadBridge.LT6SubmitAdvertise( reservation.generation, [this, key, generation=reservation.generation, bind]() mutable { kad6::K6SourceBound bound; kad6::K6PublishAck ack; bool success = K6BindSource(bind, bound, 15000); if (success) { kad6::K6Publish publish; publish.record_kind = kad6::K6RecordKind::Source; publish.network_mask = kad6::kK6PublishNetKad2; publish.flags = kad6::kK6PublishFlagSigned | kad6::kK6PublishFlagRefresh; publish.requested_ttl_s = bound.lifetime_s; publish.record_epoch = bind.source_epoch; publish.target_hash = bind.file_hash; publish.source_id = bind.compat_user_hash; publish.record.resize(17); publish.record[0] = 1; for (size_t i = 0; i < 8; ++i) { publish.record[1 + i] = static_cast<uint8_t>( bound.source_lease_id >> (8 * i)); publish.record[9 + i] = static_cast<uint8_t>( bind.file_size >> (8 * i)); } std::vector<uint8_t> canonical; success = kad6::SignK6Publish( MakeKad6HostCryptoHooks(), NULL, 0, publish, canonical) == kad6::Kad6Status::Ok && K6PublishRecord(publish, ack, 15000); } if (!success && bound.source_lease_id != 0) { kad6::K6SourceUnbind unbind; unbind.source_lease_id = bound.source_lease_id; unbind.source_epoch = bind.source_epoch; unbind.reason = kad6::K6SourceUnbindReason::Policy; unbind.bind_nonce = bind.bind_nonce; K6SourceUnbindNoWait(unbind); } const uint32 refresh = success && bound.lifetime_s > 120 ? bound.lifetime_s - 60 : 60; FinishK6OriginAdvertise(m_kadBridge,key,generation,success,success?bound.source_lease_id:0,success?ack.publish_lease_id:0,refresh); });
    if (!submitted)
        FinishK6OriginAdvertise(m_kadBridge,key,reservation.generation,false,0,0,60);
}

bool CLiveTunnel::StartK6SourceLookup(const uint8_t fileHash[16], uint32_t& requestIdOut) {
    requestIdOut = 0;
    if (fileHash == NULL || !HasActiveCircuitWithExitCaps(ESE_CAP_KAD6)) return false;
    uint8_t any = 0;
    for (size_t i = 0; i < 16; ++i) any |= fileHash[i];
    if (any == 0) return false;

    LiveTunnelOriginSourceLookup lookup;
    memcpy(lookup.file_hash.data(), fileHash, lookup.file_hash.size());
    lookup.deadline_tick = GetTickCount() + TUN_SEARCH_WINDOW_MS + 15000u;
    uint32_t reqId = 0;
    for (;;) {
        reqId = NewCircuitId();
        if (reqId != 0 && m_kadBridge.LT6AddSourceLookup(reqId, lookup))
            break;
    }

    kad6::K6SearchStart start;
    start.search_kind = kad6::kK6SearchKindSourceHash;
    start.network_mask = m_kadBridge.SelectedNetworkMask( kad6::kK6NetMaskKad2, kad6::kK6NetMaskKad6);
    if (start.network_mask == 0) {
        LiveTunnelOriginSourceLookup ignored;
        m_kadBridge.LT6TakeSourceLookup(reqId, 0, ignored);
        return false;
    }
    start.max_results = 100;
    start.deadline_ms = TUN_SEARCH_WINDOW_MS;
    memcpy(start.target_hash.data(), fileHash, start.target_hash.size());
    std::vector<uint8_t> body, wire;
    if (kad6::EncodeK6SearchStart(start, body) != kad6::Kad6Status::Ok) {
        LiveTunnelOriginSourceLookup ignored;
        m_kadBridge.LT6TakeSourceLookup(reqId, 0, ignored);
        return false;
    }
    kad6::K6Frame frame;
    frame.msg_type = kad6::kK6MsgSearchStart;
    frame.flags = kad6::kK6FlagCancelable | LiveTunnelKadBridge::BuildSearchFlags( start.network_mask, kad6::kK6NetMaskKad2, kad6::kK6NetMaskKad6, kad6::kK6FlagLegacyKad2, kad6::kK6FlagNativeKad6);
    frame.request_id = reqId;
    frame.body = std::move(body);
    if (kad6::EncodeK6Frame(frame, wire) != kad6::Kad6Status::Ok) {
        LiveTunnelOriginSourceLookup ignored;
        m_kadBridge.LT6TakeSourceLookup(reqId, 0, ignored);
        return false;
    }
    EnqueueSendMsg(reqId, TUN_OP_KAD6_GATEWAY, wire.data(), wire.size(), ESE_CAP_KAD6);
    requestIdOut = reqId;
    LIVE_LOG("K6", "source-hash lookup queued req=%u", reqId);
    return true;
}

bool CLiveTunnel::BeginK6Download(CUpDownClient* client) {
    if (client == NULL || client->GetRequestFile() == NULL || !HasActiveCircuitWithExitCaps(ESE_CAP_KAD6))
        return false;

    std::vector<uint8_t> ticketWire;
    if (!client->TakeK6TargetTicket(ticketWire)) return false;
    kad6::K6TargetTicket ticket;
    size_t used = 0;
    if (kad6::DecodeK6TargetTicket(ticketWire.data(), ticketWire.size(), ticket, &used) != kad6::Kad6Status::Ok || used != ticketWire.size() || ticket.service != static_cast<kad6::Byte>(kad6::K6TicketService::Ed2kTcp) || (ticket.provenance_kind != static_cast<kad6::Byte>(kad6::K6Provenance::KadResult) && ticket.provenance_kind != static_cast<kad6::Byte>(kad6::K6Provenance::Routing)) || ticket.provenance_session == 0 || ticket.provenance_session > 0xffffffffULL || ticket.max_connections != 1 || ticket.max_bytes == 0 || ticket.expires_at <= static_cast<uint64>(time(NULL)) || kad6::K6TicketTargetForbidden(ticket) || memcmp(ticket.object_hash.data(), client->GetRequestFile()->GetFileHash(), 16) != 0)
        return false;

    kad6::K6Dial dial;
    dial.ticket = std::move(ticketWire);
    dial.protocol = kad6::K6GatewayTransport::TcpEd2k;
    dial.connect_timeout_ms = 10000;
    dial.idle_timeout_ms = 120000;
    std::vector<uint8_t> body, wire;
    if (kad6::EncodeK6Dial(dial, body) != kad6::Kad6Status::Ok) return false;

    LiveTunnelOriginDownloadActivation activation;
    activation.client_token = reinterpret_cast<std::uintptr_t>(client);
    activation.circuit_id = static_cast<uint32>(ticket.provenance_session);
    activation.deadline_tick = GetTickCount() + kad6::kK6DialMaxConnectTimeoutMs + 5000u;
    uint32_t reqId = 0;
    for (;;) {
        reqId = NewCircuitId();
        if (reqId != 0 && m_kadBridge.LT6AddDownloadActivation(reqId, activation))
            break;
    }

    kad6::K6Frame frame;
    frame.msg_type = kad6::kK6MsgDial;
    frame.flags = kad6::kK6FlagLegacyEd2k;
    frame.request_id = reqId;
    frame.body = std::move(body);
    if (kad6::EncodeK6Frame(frame, wire) != kad6::Kad6Status::Ok) {
        m_kadBridge.LT6RemoveDownloadActivation(reqId);
        return false;
    }
    EnqueueSendMsg(reqId, TUN_OP_KAD6_GATEWAY, wire.data(), wire.size(), ESE_CAP_KAD6, static_cast<uint32>(ticket.provenance_session));
    LIVE_LOG("K6", "download DIAL queued req=%u", reqId);
    return true;
}

bool CLiveTunnel::K6RequestTargetTicket(const kad6::K6TargetTicketRequest& request, std::vector<uint8_t>& ticketOut, uint32_t timeoutMs) {
    ticketOut.clear(); if (!HasActiveCircuitWithExitCaps(ESE_CAP_KAD6)) return false;
    LiveTunnelOriginTargetRoute route;
    if (!m_kadBridge.LT6FindTargetRoute( K6AuthorizedTargetKey( 0, request.source_request_id, request.result_id), static_cast<uint64>(time(NULL)), route))
        return false;
    const uint32 pinnedCircId = route.circuit_id;
    std::vector<uint8_t> body;
    if (kad6::EncodeK6TargetTicketRequest(request, body) != kad6::Kad6Status::Ok) return false;
    kad6::K6Frame response; size_t used = 0; kad6::K6TargetTicketResponse ticket;
    if(!K6QuotaRoundTrip(pinnedCircId,kad6::kK6MsgTargetTicketReq,body,kad6::kK6MsgTargetTicket,timeoutMs,response)|| kad6::DecodeK6TargetTicketResponse(response.body.data(), response.body.size(), ticket, &used) != kad6::Kad6Status::Ok || used != response.body.size() || ticket.status != kad6::K6TargetTicketStatus::Ok) return false;
    ticketOut = std::move(ticket.ticket); return true;
}

bool CLiveTunnel::K6DialEd2k(const std::vector<uint8_t>& ticket, const std::vector<uint8_t>& initialData, kad6::K6DialResult& resultOut, uint32_t timeoutMs) {
    resultOut = kad6::K6DialResult{};
    if (!HasActiveCircuitWithExitCaps(ESE_CAP_KAD6)) return false;
    kad6::K6TargetTicket ticketMeta; size_t ticketUsed = 0;
    if (kad6::DecodeK6TargetTicket(ticket.data(), ticket.size(), ticketMeta, &ticketUsed) != kad6::Kad6Status::Ok || ticketUsed != ticket.size() || ticketMeta.provenance_session == 0 || ticketMeta.provenance_session > 0xffffffffULL) return false;
    const uint32 pinnedCircId = static_cast<uint32>(ticketMeta.provenance_session);
    bool initialHasHello=false;size_t initialOffset=0;
    while(initialOffset<initialData.size()){
        kad6::K6Ed2kFrameView initialFrame;
        if(initialData.size()-initialOffset<kad6::kK6Ed2kHeaderSize)return false;
        const uint8_t* p=initialData.data()+initialOffset;
        const uint32 packetLength=static_cast<uint32>(p[1])|(static_cast<uint32>(p[2])<<8)|(static_cast<uint32>(p[3])<<16)|(static_cast<uint32>(p[4])<<24);
        const size_t frameLength=5ull+packetLength;
        if(!packetLength||frameLength>initialData.size()-initialOffset||kad6::DecodeK6Ed2kFrame(p,frameLength,initialFrame)!=kad6::Kad6Status::Ok)return false;
        initialHasHello=initialHasHello||kad6::ClassifyK6Ed2kFrame(initialFrame.protocol,initialFrame.opcode)==kad6::K6Ed2kFrameClass::Hello;
        initialOffset+=frameLength;
    }
    kad6::K6Dial dial; dial.ticket = ticket; dial.protocol = kad6::K6GatewayTransport::TcpEd2k;
    dial.connect_timeout_ms = (std::max<uint32>)(kad6::kK6DialMinConnectTimeoutMs, (std::min<uint32>)(timeoutMs, kad6::kK6DialMaxConnectTimeoutMs));
    dial.idle_timeout_ms = 120000; dial.initial_data = initialData;
    std::vector<uint8_t> body;
    if (kad6::EncodeK6Dial(dial, body) != kad6::Kad6Status::Ok) return false;
    if (K6CircuitHasExitCaps(pinnedCircId, ESE_CAP_KAD6_ECONOMY, 2) && !K6AcquireAnonymousQuota(pinnedCircId, kad6::K6QuotaService::ExitEd2kDial, kad6::kK6MsgDial, body, (std::max<uint32>)(3, timeoutMs / 2)) && IsK6PublicReleaseEnabled())
        return false;
    kad6::K6Frame response; size_t used = 0;
    if(!K6QuotaRoundTrip(pinnedCircId,kad6::kK6MsgDial,body,kad6::kK6MsgDialOk,timeoutMs,response)|| kad6::DecodeK6DialResult(response.body.data(), response.body.size(), resultOut, &used) != kad6::Kad6Status::Ok || used != response.body.size()) return false;
    if (resultOut.status == kad6::K6DialStatus::Ok) {
        CSingleLock pl(&m_pendingLock, TRUE);
        K6OriginStreamRuntime stream;if(!m_exitServices.LT5FindOrigin(resultOut.stream_id,stream))return false;
        stream.initial_data_sent=initialHasHello;
        if(!m_exitServices.LT5UpdateOrigin(resultOut.stream_id,stream.socket,stream.generation,stream))return false;
    }
    return resultOut.status == kad6::K6DialStatus::Ok;
}

bool CLiveTunnel::K6AttachOriginClient(uint64 streamId, CUpDownClient* client) {
    if(!streamId||!client||client->socket)return false;
    auto* socket=new CKad6OriginSocket();
    if(!socket->Initialize(streamId,client)){socket->Safe_Delete();return false;}
    std::deque<std::vector<uint8_t>> pendingFrames;
    bool sendHello=true;uint32 flowCircId=0;
    bool applyVep=false;uint32 vepIp=0;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        K6OriginStreamRuntime stream;
        if(!m_exitServices.LT5FindOrigin(streamId,stream)||stream.socket){pl.Unlock();socket->Safe_Delete();return false;}
        flowCircId=stream.circ_id;sendHello=!stream.initial_data_sent;pendingFrames.swap(stream.pending_frames);
        stream.pending_frame_bytes=0;applyVep=stream.has_vep&&stream.vep.apparent_source_ip.family==kad6::Kad6Address::Family::IPv4;
        if(applyVep)memcpy(&vepIp,stream.vep.apparent_source_ip.addr.data(),4);
        stream.socket=socket;stream.client=client;
        if(!m_exitServices.LT5UpdateOrigin(streamId,NULL,stream.generation,stream)){pl.Unlock();socket->Safe_Delete();return false;}
    }
    if(applyVep)client->SetK6SecureIdentVepIPv4(vepIp);if(sendHello)client->SendHelloPacket();
    for(const auto& frame:pendingFrames)if(!socket->InjectRawFrame(frame.data(),frame.size())|| !ConsumeK6ReceiveCredit(flowCircId,streamId,1,frame.size(),std::weak_ptr<CLiveCircuit>(),false)){
        socket->Disconnect(_T("Kad6 buffered frame rejected"));return false;}
    return true;
}

bool CLiveTunnel::K6SendEd2kFrameNoWait(uint64 streamId,const uint8_t* raw,size_t length) {
    kad6::K6Ed2kFrameView view;if(!raw||kad6::DecodeK6Ed2kFrame(raw,length,view)!=kad6::Kad6Status::Ok)return false;
    kad6::K6StreamData data;data.stream_id=streamId;data.direction=0;data.flags=0x02;data.data.assign(raw,raw+length);
    CSingleLock pl(&m_pendingLock, TRUE);
    K6OriginStreamRuntime stream;if(!m_exitServices.LT5FindOrigin(streamId,stream)||!stream.socket)return false;
    CKad6OriginSocket* source=stream.socket;
    data.sequence=stream.next_tx_sequence;

    std::vector<uint8_t> body,wire;if(kad6::EncodeK6StreamData(data,body)!=kad6::Kad6Status::Ok)return false;
    const uint32 reqId=NewCircuitId();kad6::K6Frame frame;frame.msg_type=kad6::kK6MsgStreamData;
    frame.flags=kad6::kK6FlagLegacyEd2k;frame.request_id=reqId;frame.body=std::move(body);
    if(kad6::EncodeK6Frame(frame,wire)!=kad6::Kad6Status::Ok)return false;

    // Bound work waiting to reach the main-thread circuit sender. The queue is
    // released as requests are popped; no socket thread blocks for credit.
    const auto queuedUsage=m_scheduler.MeasureK6Flow(streamId);
    size_t streamMessages=queuedUsage.stream_messages,streamBytes=queuedUsage.stream_bytes,globalBytes=queuedUsage.global_bytes;
    for(const auto& origin:m_exitServices.LT5OriginSnapshot())for(const auto& queued:origin.second.pending_credit_frames){
        globalBytes+=queued.wire.size();if(origin.first==streamId){++streamMessages;streamBytes+=queued.wire.size();}}
    const size_t perStreamLimit=2u*1024u*1024u,globalLimit=32u*1024u*1024u;
    if(wire.size()>perStreamLimit||wire.size()>globalLimit||streamMessages>=64|| streamBytes>perStreamLimit-wire.size()||globalBytes>globalLimit-wire.size())return false;
    const uint64 maxBytes=stream.dial.max_bytes,txBytes=stream.flow.total_bytes(0),rxBytes=stream.flow.total_bytes(1);
    if (stream.next_tx_sequence == (std::numeric_limits<uint64>::max)() || (maxBytes && (txBytes > maxBytes || rxBytes > maxBytes - txBytes || stream.queued_tx_bytes > maxBytes - txBytes - rxBytes || data.data.size() > maxBytes - txBytes - rxBytes - stream.queued_tx_bytes))) return false;
    ++stream.next_tx_sequence;stream.queued_tx_bytes+=data.data.size();
    const uint64 sent=m_exitServices.LT5Sent(stream.circ_id,streamId,0);
    const uint64 remaining=maxBytes==0||sent+rxBytes>=maxBytes?(maxBytes==0?(std::numeric_limits<uint64>::max)():0):maxBytes-sent-rxBytes;
    const bool waitForCredit=!stream.pending_credit_frames.empty()|| !m_exitServices.LT5CommitOriginSend(source,streamId,stream.generation,0,data.data.size(),remaining,(std::numeric_limits<uint64>::max)(),perStreamLimit-streamBytes);
    if(waitForCredit){
        K6QueuedOriginFrame queued;queued.request_id=reqId;queued.sequence=data.sequence;
        queued.data_bytes=data.data.size();queued.wire=std::move(wire);
        stream.pending_credit_bytes+=queued.data_bytes;stream.pending_credit_frames.push_back(std::move(queued));
        if(stream.credit_stall_since_ms==0)stream.credit_stall_since_ms=M2A_LT3_K6ShapeNowUs()/1000u;
        if(!m_exitServices.LT5UpdateOrigin(streamId,source,stream.generation,stream))return false;
        pl.Unlock();source->SetKad6FlowBlocked(true);
        return true;
    }

    MainThreadReq request;request.op=MT_SEND_MSG;request.reqId=reqId;request.subCmd=TUN_OP_KAD6_GATEWAY;
    request.requiredExitCaps=ESE_CAP_KAD6;request.pinnedCircId=stream.circ_id;request.k6StreamId=streamId;
    request.k6Generation=stream.generation;request.k6FlowBytes=wire.size();request.k6Sequence=data.sequence;
    request.k6DataBytes=data.data.size();request.payload=std::move(wire);
    if(!m_exitServices.LT5UpdateOrigin(streamId,source,stream.generation,stream))return false;
    pl.Unlock();
    return m_scheduler.Enqueue(std::move(request));
}

bool CLiveTunnel::K6TakeSourceHints(uint64 streamId,kad6::K6SourceHints& hintsOut){
    hintsOut=kad6::K6SourceHints{};CSingleLock pl(&m_pendingLock,TRUE);
    K6OriginStreamRuntime stream;if(!m_exitServices.LT5FindOrigin(streamId,stream)||stream.hints.empty())return false;
    hintsOut=std::move(stream.hints.front());stream.hints.pop_front();
    return m_exitServices.LT5UpdateOrigin(streamId,stream.socket,stream.generation,stream);
}

bool CLiveTunnel::K6GetVirtualIdentity(uint64 streamId,kad6::K6VirtualIdentityEndpoint& vepOut)const{
    vepOut=kad6::K6VirtualIdentityEndpoint{};CSingleLock pl(&m_pendingLock,TRUE);
    K6OriginStreamRuntime stream;if(!m_exitServices.LT5FindOrigin(streamId,stream)||!stream.has_vep)return false;
    vepOut=stream.vep;return true;
}



bool CLiveTunnel::SendK6LiveSubscribeNoWait(const uint8_t streamKey[16])
{
    if(!streamKey)return false;
    LiveTunnelOriginTargetRoute route;
    if(!m_kadBridge.LT6FindLiveRoute(K6BinaryKey(streamKey,16),static_cast<uint64>(time(NULL)),route)||
        !route.circuit_id||!route.source_request_id||K6SelectOriginCircuit(ESE_CAP_KAD6,route.circuit_id,2)!=route.circuit_id)return false;
    const uint32_t reqId=NewCircuitId();std::vector<uint8_t> body(24,0);
    memcpy(body.data(),streamKey,16);for(size_t i=0;i<4;++i)body[16+i]=static_cast<uint8_t>(route.source_request_id>>(8*i));body[20]=2;
    EnqueueSendMsg(reqId,TUN_OP_LIVE_SUBSCRIBE,body.data(),body.size(),ESE_CAP_KAD6,route.circuit_id);
    return true;
}


} // namespace eSELive
