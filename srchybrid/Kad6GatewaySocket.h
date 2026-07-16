#pragma once

#include "ListenSocket.h"
#include "UpDownClient.h"

#include <cstdint>
#include <vector>

namespace kad6 { struct K6Endpoint; }

namespace eSELive {

class CKad6ExitClient : public CUpDownClient {
public:
    CKad6ExitClient(CPartFile* file,uint16 port,uint32 id,uint32 serverIp,
                    uint16 serverPort,bool ed2kId=false)
        : CUpDownClient(file,port,id,serverIp,serverPort,ed2kId) {}
    void SendHelloPacket() override {} // A supplies the identity-bearing HELLO.
};

class CKad6ExitSocket : public CClientReqSocket {
    DECLARE_DYNCREATE(CKad6ExitSocket)
public:
    CKad6ExitSocket();
    void Initialize(std::uint64_t streamId);
    void InitializeInboundFrontDoor();
    bool BindInboundStream(std::uint64_t streamId);
    bool SendRawFrame(const uint8_t* frame,std::size_t length);
    bool SetKad6ReadPaused(bool paused);
    bool Kad6ReadPaused() const { return m_kad6ReadPaused; }
    void OnConnect(int error) override;
    void OnClose(int error) override;
protected:
    bool PacketReceived(Packet* packet) override;
private:
    std::uint64_t m_streamId = 0;
    bool m_inboundFrontDoor = false;
    bool m_inboundBypass = false;
    std::vector<std::vector<uint8_t>> m_inboundFrames;
    std::size_t m_inboundFrameBytes = 0;
    bool m_kad6ReadPaused = false;
};

// Origin-side virtual eD2K socket. It is marked connected but never owns a
// kernel socket: outgoing Packets become K6 STREAM_DATA and injected remote
// frames run through the unchanged CClientReqSocket parser/download engine.
class CKad6OriginSocket : public CClientReqSocket {
    DECLARE_DYNCREATE(CKad6OriginSocket)
public:
    CKad6OriginSocket();
    bool Initialize(std::uint64_t streamId,CUpDownClient* client);
    bool InitializeInbound(std::uint64_t streamId,
                           const kad6::K6Endpoint& pseudonymousPeer);
    uint32 GetPeerAddressV4() override;
    CAddress GetPeerCAddress() override;
    void Disconnect(LPCTSTR reason) override;
    void SendPacket(Packet* packet,bool controlpacket=true,uint32 actualPayloadSize=0,
                    bool forceImmediate=false) override;
    bool IsBusyQuickCheck() const override;
    void SetKad6FlowBlocked(bool blocked) { m_kad6FlowBlocked = blocked; }
    bool InjectRawFrame(const uint8_t* frame,std::size_t length,
                        bool suppressReplies=false);
private:
    std::uint64_t m_streamId = 0;
    bool m_suppressReplies = false;
    uint32 m_pseudonymousPeerV4 = 0;
    bool m_kad6FlowBlocked = false;
};

bool SanitizeK6HelloFrame(const uint8_t* frame,std::size_t length,
                          const kad6::K6Endpoint& apparent,
                          std::vector<uint8_t>& out);

} // namespace eSELive
