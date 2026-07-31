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
    return CLiveTunnel::Get().OnK6ExitPacket(m_streamId,raw.data(),raw.size());
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
    const bool ok=bytes&&CLiveTunnel::Get().K6SendEd2kFrameNoWait(m_streamId,
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
    if (!circ) return false;
    const uint32_t req_id = frame.request_id;
    size_t consumed = 0;
    if (frame.msg_type == kad6::kK6MsgAccept) {
        if ((frame.flags & kad6::kK6FlagFinal) == 0) return false;
        kad6::K6DialResult accepted;
        consumed = 0;
        if (kad6::DecodeK6DialResult(frame.body.data(), frame.body.size(), accepted, &consumed) != kad6::Kad6Status::Ok || consumed != frame.body.size() || accepted.status != kad6::K6DialStatus::Ok || accepted.stream_id == 0)
            return false;
        CKad6OriginSocket* socket = new CKad6OriginSocket();
        if (!socket->InitializeInbound(accepted.stream_id, accepted.remote_endpoint)) {
            socket->Safe_Delete();
            return false;
        }
        {
            CSingleLock pl(&host.m_pendingLock, TRUE);
            if (host.m_k6OriginStreams.size() >= 512 || host.m_k6OriginStreams.find(accepted.stream_id) != host.m_k6OriginStreams.end() || !host.RegisterK6FlowControlLocked(circ->Id(), accepted.stream_id)) { pl.Unlock(); socket->Safe_Delete(); return false; }
            CLiveTunnel::K6OriginStreamRuntime runtime;
            runtime.circ_id = circ->Id();
            runtime.dial = accepted;
            runtime.socket = socket;
            runtime.flow = kad6::K6StreamFlowState(accepted.max_bytes);
            runtime.initial_data_sent = true;
            runtime.last_activity = static_cast<uint64>(time(NULL));
            runtime.idle_deadline = runtime.last_activity +
                ((accepted.idle_timeout_ms + 999u) / 1000u);
            host.m_k6OriginStreams[accepted.stream_id] = runtime;
        }
        if (!host.SendK6InitialCredit(circ->Id(), accepted.stream_id, 1, circ, false)) {
            CSingleLock pl(&host.m_pendingLock, TRUE);
            host.m_k6OriginStreams.erase(accepted.stream_id);
            host.RemoveK6FlowControlLocked(circ->Id(), accepted.stream_id);
            pl.Unlock();
            socket->Safe_Delete();
            return false;
        }
        LIVE_LOG("K6", "inbound ACCEPT stream=%llu circuit=%u", static_cast<unsigned long long>(accepted.stream_id), circ->Id());
        return true;
    }
    if (frame.msg_type == kad6::kK6MsgQuotaKey) {
        if ((frame.flags & kad6::kK6FlagFinal) == 0) return false;
        kad6::K6QuotaIssuerCertificate certificate;
        consumed = 0;
        if (kad6::DecodeK6QuotaIssuerCertificate(frame.body.data(), frame.body.size(), certificate, &consumed) != kad6::Kad6Status::Ok || consumed != frame.body.size() || kad6::VerifyK6QuotaIssuerCertificate(MakeKad6HostCryptoHooks(), certificate, kad6::K6QuotaEpoch(static_cast<uint64>(time(NULL)))) != kad6::Kad6Status::Ok)
            return false;
        const uint8_t* expected = NULL;
        if (circ->HopCount() >= 2 && circ->m_expectedNodePub2Set)
            expected = circ->m_expectedNodePub2;
        else if (circ->m_expectedNodePubSet)
            expected = circ->m_expectedNodePub;
        if (!expected || !kad6::Kad6CtEqual(expected, certificate.issuer_node_pub.data(), 32)) return false;
        host.SignalReply(req_id, wire.data(), wire.size(), 0);
        return true;
    }
    if (frame.msg_type == kad6::kK6MsgQuotaIssued) {
        kad6::K6QuotaBlindResponse response;
        consumed = 0;
        if ((frame.flags & kad6::kK6FlagFinal) == 0 || kad6::DecodeK6QuotaBlindResponse(frame.body.data(), frame.body.size(), response, &consumed) != kad6::Kad6Status::Ok || consumed != frame.body.size()) return false;
        host.SignalReply(req_id, wire.data(), wire.size(), 0);
        return true;
    }
    if (frame.msg_type == kad6::kK6MsgQuotaStatus) {
        kad6::K6QuotaPresentationResult response;
        consumed = 0;
        if ((frame.flags & kad6::kK6FlagFinal) == 0 || kad6::DecodeK6QuotaPresentationResult(frame.body.data(), frame.body.size(), response, &consumed) != kad6::Kad6Status::Ok || consumed != frame.body.size()) return false;
        host.SignalReply(req_id, wire.data(), wire.size(), 0);
        return true;
    }
    if (frame.msg_type == kad6::kK6MsgVep) {
        kad6::K6VirtualIdentityEndpoint vep;
        consumed = 0;
        if (kad6::DecodeK6Vep(frame.body.data(), frame.body.size(), vep, &consumed) != kad6::Kad6Status::Ok || consumed != frame.body.size() || kad6::VerifyK6Vep(MakeKad6HostCryptoHooks(), vep, static_cast<uint64_t>(time(NULL))) != kad6::Kad6Status::Ok)
            return false;
        const uint8_t* expected = NULL;
        if (circ->HopCount() >= 2 && circ->m_expectedNodePub2Set)
            expected = circ->m_expectedNodePub2;
        else if (circ->m_expectedNodePubSet)
            expected = circ->m_expectedNodePub;
        if (!expected || memcmp(expected, vep.exit_node_pub.data(), 32) != 0)
            return false;
        CSingleLock pl(&host.m_pendingLock, TRUE);
        auto stream = host.m_k6OriginStreams.find(vep.source_lease_id);
        if (stream == host.m_k6OriginStreams.end()) return false;
        stream->second.vep = vep;
        stream->second.has_vep = true;
        if (stream->second.client && vep.apparent_source_ip.family == kad6::Kad6Address::Family::IPv4) {
            uint32 ip = 0;
            memcpy(&ip, vep.apparent_source_ip.addr.data(), 4);
            stream->second.client->SetK6SecureIdentVepIPv4(ip);
        }
        return true;
    }
    if (frame.msg_type == kad6::kK6MsgSourceHints) {
        kad6::K6SourceHints hints;
        consumed = 0;
        if (kad6::DecodeK6SourceHints(frame.body.data(), frame.body.size(), hints, &consumed) != kad6::Kad6Status::Ok || consumed != frame.body.size())
            return false;
        CSingleLock pl(&host.m_pendingLock, TRUE);
        auto stream = host.m_k6OriginStreams.find(hints.source_stream_id);
        if (stream == host.m_k6OriginStreams.end() || stream->second.hints.size() >= 32)
            return false;
        stream->second.hints.push_back(std::move(hints));
        return true;
    }
    if (frame.msg_type == kad6::kK6MsgMaxStreamData) {
        kad6::K6MaxStreamData credit;
        consumed = 0;
        if (kad6::DecodeK6MaxStreamData(frame.body.data(), frame.body.size(), credit, &consumed) != kad6::Kad6Status::Ok || consumed != frame.body.size() || credit.direction != 0)
            return false;
        {
            CSingleLock pl(&host.m_pendingLock, TRUE);
            const auto stream = host.m_k6OriginStreams.find(credit.stream_id);
            const auto ledger = host.m_k6SendCredits.find(circ->Id());
            if (stream == host.m_k6OriginStreams.end() || stream->second.circ_id != circ->Id() || ledger == host.m_k6SendCredits.end() || ledger->second.Grant(credit) != kad6::Kad6Status::Ok)
                return false;
        }
        host.FlushK6OriginCredit(circ->Id());
        return true;
    }
    if (frame.msg_type == kad6::kK6MsgMaxData) {
        kad6::K6MaxData credit;
        consumed = 0;
        if (kad6::DecodeK6MaxData(frame.body.data(), frame.body.size(), credit, &consumed) != kad6::Kad6Status::Ok || consumed != frame.body.size() || credit.direction != 0)
            return false;
        {
            CSingleLock pl(&host.m_pendingLock, TRUE);
            const auto ledger = host.m_k6SendCredits.find(circ->Id());
            if (ledger == host.m_k6SendCredits.end() || ledger->second.Grant(credit) != kad6::Kad6Status::Ok)
                return false;
        }
        host.FlushK6OriginCredit(circ->Id());
        return true;
    }
    if (frame.msg_type == kad6::kK6MsgStreamData) {
        kad6::K6StreamData data;
        consumed = 0;
        if (kad6::DecodeK6StreamData(frame.body.data(), frame.body.size(), data, &consumed) != kad6::Kad6Status::Ok || consumed != frame.body.size() || data.direction != 1 || (data.flags & 0x02) == 0)
            return false;
        kad6::K6Ed2kFrameView inboundView;
        if (kad6::DecodeK6Ed2kFrame(data.data.data(), data.data.size(), inboundView) != kad6::Kad6Status::Ok) return false;
        const bool suppressHandshakeReply = kad6::ClassifyK6Ed2kFrame(inboundView.protocol, inboundView.opcode) == kad6::K6Ed2kFrameClass::Hello;
        CKad6OriginSocket* socket = NULL;
        {
            CSingleLock pl(&host.m_pendingLock, TRUE);
            auto stream = host.m_k6OriginStreams.find(data.stream_id);
            if (stream == host.m_k6OriginStreams.end()) return false;
            const uint64 maxBytes = stream->second.dial.max_bytes;
            const uint64 txBytes = stream->second.flow.total_bytes(0);
            const uint64 rxBytes = stream->second.flow.total_bytes(1);
            auto receiver = host.m_k6ReceiveCredits.find(circ->Id());
            const bool bufferForAttach = stream->second.socket == NULL;
            if ((maxBytes && (txBytes > maxBytes || rxBytes > maxBytes - txBytes || stream->second.queued_tx_bytes > maxBytes - txBytes - rxBytes || data.data.size() > maxBytes - txBytes - rxBytes - stream->second.queued_tx_bytes)) || receiver == host.m_k6ReceiveCredits.end() || (bufferForAttach && (stream->second.pending_frames.size() >= 64 || stream->second.pending_frame_bytes + data.data.size() > 256u * 1024u)) || receiver->second.CanAccept(data.stream_id, 1, data.data.size()) != kad6::Kad6Status::Ok || stream->second.flow.CanAccept(data) != kad6::Kad6Status::Ok)
                return false;
            if (receiver->second.Accept(data.stream_id, 1, data.data.size(), M2A_LT3_K6ShapeNowUs() / 1000u) != kad6::Kad6Status::Ok || stream->second.flow.Accept(data) != kad6::Kad6Status::Ok)
                return false;
            const uint64 now = static_cast<uint64>(time(NULL));
            const uint64 idle = (stream->second.dial.idle_timeout_ms + 999u) / 1000u;
            stream->second.last_activity = now;
            stream->second.idle_deadline = now + idle;
            socket = stream->second.socket;
            if (!socket) {
                stream->second.pending_frame_bytes += data.data.size();
                stream->second.pending_frames.push_back(std::move(data.data));
                return true;
            }
        }
        const bool injected = socket->InjectRawFrame(data.data.data(), data.data.size(), suppressHandshakeReply);
        if (!injected) {
            socket->Disconnect(_T("Kad6 downstream application rejected frame"));
            return false;
        }
        if (injected) {
            CSingleLock pl(&host.m_pendingLock, TRUE);
            auto stream = host.m_k6OriginStreams.find(data.stream_id);
            if (stream != host.m_k6OriginStreams.end() && stream->second.socket == socket)
                stream->second.client = socket->client;
        }
        return host.ConsumeK6ReceiveCredit(circ->Id(), data.stream_id, 1, data.data.size(), circ, false);
    }
    if (frame.msg_type == kad6::kK6MsgStreamHalfClose) {
        kad6::K6StreamHalfClose close;
        consumed = 0;
        if (kad6::DecodeK6StreamHalfClose(frame.body.data(), frame.body.size(), close, &consumed) != kad6::Kad6Status::Ok || consumed != frame.body.size() || close.direction != 1) return false;
        CSingleLock pl(&host.m_pendingLock, TRUE);
        auto stream = host.m_k6OriginStreams.find(close.stream_id);
        return stream != host.m_k6OriginStreams.end() && stream->second.flow.HalfClose(close) == kad6::Kad6Status::Ok;
    }
    if (frame.msg_type == kad6::kK6MsgStreamClose) {
        kad6::K6StreamClose close;
        consumed = 0;
        if (kad6::DecodeK6StreamClose(frame.body.data(), frame.body.size(), close, &consumed) != kad6::Kad6Status::Ok || consumed != frame.body.size())
            return false;
        CKad6OriginSocket* socket = NULL;
        CUpDownClient* client = NULL;
        {
            CSingleLock pl(&host.m_pendingLock, TRUE);
            auto stream = host.m_k6OriginStreams.find(close.stream_id);
            if (stream == host.m_k6OriginStreams.end() || stream->second.flow.Close(close) != kad6::Kad6Status::Ok) return false;
            socket = stream->second.socket;
            client = stream->second.client;
            host.RemoveK6FlowControlLocked(stream->second.circ_id, close.stream_id);
            host.m_k6OriginStreams.erase(stream);
        }
        if (client) client->ClearK6SecureIdentVep();
        if (socket) socket->Disconnect(_T("Kad6 remote stream closed"));
        return true;
    }
    if (frame.msg_type == kad6::kK6MsgDialOk) {
        if ((frame.flags & kad6::kK6FlagFinal) == 0) return false;
        kad6::K6DialResult result;
        consumed = 0;
        if (kad6::DecodeK6DialResult(frame.body.data(), frame.body.size(), result, &consumed) != kad6::Kad6Status::Ok || consumed != frame.body.size())
            return false;
        CUpDownClient* activationClient = NULL;
        bool hasActivation = false;
        {
            CSingleLock pl(&host.m_pendingLock, TRUE);
            auto activation = host.m_k6DownloadActivations.find(req_id);
            if (activation != host.m_k6DownloadActivations.end()) {
                if (activation->second.circ_id != circ->Id()) return false;
                activationClient = activation->second.client;
                hasActivation = true;
                host.m_k6DownloadActivations.erase(activation);
            }
        }
        bool streamRegistered = result.status != kad6::K6DialStatus::Ok;
        if (result.status == kad6::K6DialStatus::Ok) {
            CSingleLock pl(&host.m_pendingLock, TRUE);
            if (host.m_k6OriginStreams.size() < 512 && result.stream_id != 0 && host.m_k6OriginStreams.find(result.stream_id) == host.m_k6OriginStreams.end() && host.RegisterK6FlowControlLocked(circ->Id(), result.stream_id)) {
                CLiveTunnel::K6OriginStreamRuntime runtime;
                runtime.circ_id = circ->Id();
                runtime.dial = result;
                runtime.flow = kad6::K6StreamFlowState(result.max_bytes);
                runtime.last_activity = static_cast<uint64>(time(NULL));
                runtime.idle_deadline = runtime.last_activity +
                    ((result.idle_timeout_ms + 999u) / 1000u);
                host.m_k6OriginStreams[result.stream_id] = runtime;
                streamRegistered = true;
            }
        }
        if (result.status == kad6::K6DialStatus::Ok && streamRegistered && !host.SendK6InitialCredit(circ->Id(), result.stream_id, 1, circ, false)) {
            CSingleLock pl(&host.m_pendingLock, TRUE);
            host.m_k6OriginStreams.erase(result.stream_id);
            host.RemoveK6FlowControlLocked(circ->Id(), result.stream_id);
            streamRegistered = false;
        }
        if (hasActivation) {
            if (activationClient != NULL && result.status == kad6::K6DialStatus::Ok && streamRegistered && host.K6AttachOriginClient(result.stream_id, activationClient)) {
                LIVE_LOG("K6", "download stream attached req=%u stream=%llu", req_id, static_cast<unsigned long long>(result.stream_id));
                return true;
            }
            if (streamRegistered && result.status == kad6::K6DialStatus::Ok) {
                CLiveTunnel::K6OriginStreamRuntime orphan;
                bool found = false;
                {
                    CSingleLock pl(&host.m_pendingLock, TRUE);
                    auto stream = host.m_k6OriginStreams.find(result.stream_id);
                    if (stream != host.m_k6OriginStreams.end() && stream->second.socket == NULL) {
                        orphan = stream->second;
                        host.RemoveK6FlowControlLocked(stream->second.circ_id, result.stream_id);
                        host.m_k6OriginStreams.erase(stream);
                        found = true;
                    }
                }
                if (found) {
                    kad6::K6StreamClose close;
                    close.stream_id = result.stream_id;
                    close.reason_code = 1;
                    std::vector<uint8_t> closeBody, closeWire;
                    kad6::K6Frame closeFrame;
                    closeFrame.msg_type = kad6::kK6MsgStreamClose;
                    closeFrame.flags = kad6::kK6FlagLegacyEd2k | kad6::kK6FlagFinal;
                    closeFrame.request_id = host.NewCircuitId();
                    if (kad6::EncodeK6StreamClose(close, closeBody) == kad6::Kad6Status::Ok) {
                        closeFrame.body = std::move(closeBody);
                        if (kad6::EncodeK6Frame(closeFrame, closeWire) == kad6::Kad6Status::Ok)
                            host.SendMessagePinned( closeFrame.request_id, CLiveTunnel::TUN_OP_KAD6_GATEWAY, closeWire.data(), closeWire.size(), ESE_CAP_KAD6, orphan.circ_id);
                    }
                }
            }
            if (activationClient != NULL) {
                const bool deleteClient = activationClient->Disconnected( _T("Kad6 gateway DIAL failed"));
                if (deleteClient) delete activationClient;
            }
            return true;
        }
        if (!streamRegistered) return false;
        host.SignalReply(req_id, wire.data(), wire.size(), 0);
        return true;
    }
    if (frame.msg_type == kad6::kK6MsgTargetTicket) {
        kad6::K6TargetTicketResponse response;
        consumed = 0;
        if ((frame.flags & kad6::kK6FlagFinal) == 0 || kad6::DecodeK6TargetTicketResponse(frame.body.data(), frame.body.size(), response, &consumed) != kad6::Kad6Status::Ok || consumed != frame.body.size()) return false;
        host.SignalReply(req_id, wire.data(), wire.size(), 0);
        return true;
    }
    if (frame.msg_type == kad6::kK6MsgSourceBound || frame.msg_type == kad6::kK6MsgPublishAck) {
        if ((frame.flags & kad6::kK6FlagFinal) == 0 || (frame.flags & kad6::kK6FlagMore) != 0)
            return false;
        if (frame.msg_type == kad6::kK6MsgSourceBound) {
            kad6::K6SourceBound value;
            consumed = 0;
            if (kad6::DecodeK6SourceBound(frame.body.data(), frame.body.size(), value, &consumed) != kad6::Kad6Status::Ok || consumed != frame.body.size()) return false;
        } else {
            kad6::K6PublishAck value;
            consumed = 0;
            if (kad6::DecodeK6PublishAck(frame.body.data(), frame.body.size(), value, &consumed) != kad6::Kad6Status::Ok || consumed != frame.body.size()) return false;
        }
        host.SignalReply(req_id, wire.data(), wire.size(), 0);
        return true;
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
            CLiveTunnel::K6OriginSourceLookup lookup;
            {
                CSingleLock pl(&host.m_pendingLock, TRUE);
                auto pendingLookup = host.m_k6OriginSourceLookups.find(req_id);
                if (pendingLookup == host.m_k6OriginSourceLookups.end() || (pendingLookup->second.circ_id != 0 && pendingLookup->second.circ_id != circ->Id()))
                    return false;
                pendingLookup->second.circ_id = circ->Id();
                lookup = pendingLookup->second;
            }
            bool materialized = false;
            for (const kad6::K6TargetTicket& ticket : result.tickets) {
                if (ticket.service != static_cast<kad6::Byte>(kad6::K6TicketService::Ed2kTcp) || (ticket.provenance_kind != static_cast<kad6::Byte>(kad6::K6Provenance::KadResult) && ticket.provenance_kind != static_cast<kad6::Byte>(kad6::K6Provenance::Routing)) || ticket.provenance_session != circ->Id() || ticket.provenance_stream != req_id || ticket.object_hash != lookup.file_hash || ticket.max_connections != 1 || ticket.max_bytes == 0 || ticket.expires_at <= static_cast<uint64>(time(NULL)) || ticket.target_endpoint.tcp_port == 0)
                    continue;
                std::vector<uint8_t> ticketWire;
                if (kad6::EncodeK6TargetTicket(ticket, ticketWire) != kad6::Kad6Status::Ok)
                    continue;
                Kademlia::CUInt128 contact(result.result_id.data());
                Kademlia::CUInt128 buddy;
                uint32 ip = 0;
                CAddress sourceV6;
                const CAddress* sourceV6Ptr = NULL;
                if (ticket.target_endpoint.addr.family == kad6::Kad6Address::Family::IPv4) { memcpy(&ip, ticket.target_endpoint.addr.addr.data(), 4); } else if (ticket.target_endpoint.addr.family == kad6::Kad6Address::Family::IPv6) {
                    sourceV6 = CAddress(ticket.target_endpoint.addr.addr.data());
                    if (sourceV6.GetType() != CAddress::IPv6 || !sourceV6.IsPublicIP())
                        continue;
                    sourceV6Ptr = &sourceV6;
                    ip = 0x01000001u; // HighID-shaped placeholder; no direct dial is allowed.
                } else {
                    continue;
                }
                if (theApp.downloadqueue == NULL) return false;
                theApp.downloadqueue->KademliaSearchFile(req_id, &contact, &buddy, 1, ip, ticket.target_endpoint.tcp_port, ticket.target_endpoint.udp_port, 0, 0, 0, 0, sourceV6Ptr, &ticketWire);
                materialized = true;
                break;
            }
            if (materialized) {
                CSingleLock pl(&host.m_pendingLock, TRUE);
                auto pendingLookup = host.m_k6OriginSourceLookups.find(req_id);
                if (pendingLookup != host.m_k6OriginSourceLookups.end() && pendingLookup->second.received != 0xffff)
                    ++pendingLookup->second.received;
            }
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
            CLiveTunnel::K6SearchReplyAggregate& agg = host.m_k6SearchReplies[key];
            if (agg.legacy.empty()) {
                agg.legacy.assign(4, 0);
                agg.started = GetTickCount();
            }
            if (agg.count >= kad6::kK6SearchMaxResults || agg.legacy.size() + one.size() - 4 > TUN_MSG_MAX_BYTES)
                return false;
            agg.legacy.insert(agg.legacy.end(), one.begin() + 4, one.end());
            ++agg.count;
            CLiveTunnel::K6OriginTargetRoute route; route.circ_id = circ->Id();
            route.source_request_id = req_id;
            route.expires_at = static_cast<uint64>(time(NULL)) + 120;
            host.m_k6OriginTargetRoutes[host.K6AuthorizedTargetKey(0, req_id, result.result_id)] = route;
            host.m_k6OriginLiveRoutes[host.K6BinaryKey(result.result_id.data(), result.result_id.size())] = route;
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
        uint16 sourceReceived = 0;
        bool sourceLookup = false;
        {
            CSingleLock pl(&host.m_pendingLock, TRUE);
            auto lookup = host.m_k6OriginSourceLookups.find(req_id);
            if (lookup != host.m_k6OriginSourceLookups.end()) {
                if (lookup->second.circ_id != 0 && lookup->second.circ_id != circ->Id())
                    return false;
                sourceReceived = lookup->second.received;
                host.m_k6OriginSourceLookups.erase(lookup);
                sourceLookup = true;
            }
        }
        if (sourceLookup) {
            if (theApp.downloadqueue != NULL) {
                CPartFile* file = theApp.downloadqueue->GetFileByKadFileSearchID(req_id);
                if (file != NULL) file->SetKadFileSearchID(0);
            }
            return sourceReceived == end.result_count;
        }
        if (!host.m_pendingRequests.IsLive(req_id)) return false;
        std::vector<uint8_t> legacy(4, 0);
        uint16_t count = 0;
        {
            CSingleLock pl(&host.m_pendingLock, TRUE);
            auto it = host.m_k6SearchReplies.find(key);
            if (it != host.m_k6SearchReplies.end()) {
                legacy = std::move(it->second.legacy);
                count = it->second.count;
                host.m_k6SearchReplies.erase(it);
            }
        }
        if (count != end.result_count) return false;
        legacy[0] = (uint8_t)count;
        legacy[1] = (uint8_t)(count >> 8);
        legacy[2] = 0x02;
        legacy[3] = 0;
        host.SignalReply(req_id, legacy.data(), legacy.size(), 0);
        return true;
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
        for (const auto& pair : host.m_k6ExitStreams) {
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
        for (const auto& pair : host.m_k6ExitStreams)
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
                for (auto& pair : host.m_k6ExitStreams) {
                    const bool matches = pair.second.inbound ? service == kad6::K6Service::ExitEd2kFull : service == kad6::K6Service::ExitEd2kDial;
                    if (matches) {
                        pair.second.kill_switch_close = true;
                        pair.second.idle_deadline = now;
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

} // namespace eSELive
