#pragma once

#include "ListenSocket.h"
#include "UpDownClient.h"

#include <cstdint>
#include <memory>
#include <set>
#include <string>
#include <vector>

namespace kad6 { enum class K6Service : std::uint8_t; enum class K6StoreStatus : std::uint8_t; enum class K6Provenance : std::uint8_t; struct K6CohortBackend; struct K6Endpoint; struct K6Frame; struct K6TargetPolicy; struct K6TargetTicket; }

namespace eSELive {

class CLiveCircuit; class CLiveTunnel;
struct LiveK6HardeningRuntimeSnapshot; struct LiveTunnelRequestCtx;

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
    static bool LT3ExecuteSearchReply(CLiveTunnel&, const std::shared_ptr<CLiveCircuit>&, const kad6::K6Frame&, const std::vector<std::uint8_t>&);
    static void LT3ExecuteExitGateway(CLiveTunnel&, const LiveTunnelRequestCtx&, const kad6::K6Frame&);
    static void LT3GetHardeningSnapshot(CLiveTunnel&, LiveK6HardeningRuntimeSnapshot&); static bool LT3ApplyServiceSwitch(CLiveTunnel&, kad6::K6Service, bool, std::uint32_t);
    static void LT3SourceUnbind(CLiveTunnel&, const LiveTunnelRequestCtx&, const kad6::K6Frame&); static void LT3Unpublish(CLiveTunnel&, const LiveTunnelRequestCtx&, const kad6::K6Frame&);
    static bool LT3HasServingLeases(const CLiveTunnel&); static bool LT3MarkServing(CLiveTunnel&, std::uint64_t, kad6::K6CohortBackend&); static bool LT3EnsureEpochsLoaded(CLiveTunnel&);
    static void LT3QueueRefreshes(CLiveTunnel&, std::uint64_t); static void LT3SweepLeases(CLiveTunnel&, const std::set<std::uint32_t>&, const std::set<std::uint32_t>&, std::uint64_t);
    static void LT4SourceBind(CLiveTunnel&,const LiveTunnelRequestCtx&,const kad6::K6Frame&); static void LT4Publish(CLiveTunnel&,const LiveTunnelRequestCtx&,const kad6::K6Frame&);
    static bool LT4AllowShadow(CLiveTunnel&,std::uint64_t,const std::uint8_t*); static void LT4ShadowSent(CLiveTunnel&,std::uint64_t); static void LT4ShadowAck(CLiveTunnel&,std::uint64_t,std::uint8_t,bool); static void LT4ShadowVerified(CLiveTunnel&,std::uint64_t); static void LT4NativeAck(CLiveTunnel&,std::uint64_t,kad6::K6StoreStatus,std::uint8_t,std::uint64_t);
    static void LT4RefreshNative(CLiveTunnel&,std::uint64_t); static void LT4StartShadow(CLiveTunnel&,std::uint64_t); static void LT4StartProbes(CLiveTunnel&,std::uint64_t); static bool LT4ConsumeTicket(void*,const kad6::K6TargetTicket&); static void LT4TargetTicketReq(CLiveTunnel&,const LiveTunnelRequestCtx&,const kad6::K6Frame&);
    static std::string LT4AuthorizedKey(std::uint32_t,std::uint32_t,const void*); static bool LT4AllowTarget(std::uint8_t,const kad6::K6Endpoint&); static kad6::K6TargetPolicy LT4TicketPolicy(CLiveTunnel&); static bool LT4IssueTicket(CLiveTunnel&,const void*,std::uint64_t,kad6::K6Provenance,std::uint64_t,std::uint64_t,std::uint64_t,std::vector<std::uint8_t>&); static std::string LT4BinaryKey(const std::uint8_t*,std::size_t); static std::string LT4ShadowKey(const void*);
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
