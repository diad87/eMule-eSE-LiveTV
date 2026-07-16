#include "stdafx.h"
#include "Kad6GatewaySocket.h"

#include "LiveTunnel.h"
#include "Packets.h"
#include "SafeFile.h"
#include "Preferences.h"
#include "Opcodes.h"
#include "kad6/kad6_ed2k_policy.h"
#include "kad6/kad6_endpoint.h"

namespace eSELive {

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

void CKad6ExitSocket::OnConnect(int error){
    const std::uint64_t stream=m_streamId;
    if(error!=0&&stream)CLiveTunnel::Get().OnK6ExitSocketConnect(stream,this,error);
    CClientReqSocket::OnConnect(error);
    if(error==0&&stream)CLiveTunnel::Get().OnK6ExitSocketConnect(stream,this,0);
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
        CTag udp(CT_EMULE_UDPPORTS,static_cast<uint32>(thePrefs.GetUDPPort()));
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

} // namespace eSELive
