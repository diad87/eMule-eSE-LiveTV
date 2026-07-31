// this file is part of eMule eSE - LT5 Kad6 stream transport boundary
#pragma once
#include "M2ABindingPort.h"
#include "LiveTunnelStreamFlowPort.h"
namespace eSELive {
class Kad6StreamTransportAdapter final {
public:
    explicit Kad6StreamTransportAdapter(const M2AParentPort&) noexcept;
    std::size_t ExitCount() const noexcept; std::size_t OriginCount() const noexcept;
    LiveTunnelExitStreams ExitSnapshot() const; LiveTunnelOriginStreams OriginSnapshot() const;
    bool FindExit(std::uint64_t,LiveTunnelExitStreamRuntime&) const; bool FindOrigin(std::uint64_t,LiveTunnelOriginStreamRuntime&) const;
    bool FindExit(std::uint64_t,CKad6ExitSocket*,LiveTunnelExitStreamRuntime&) const; bool FindOrigin(std::uint64_t,CKad6OriginSocket*,LiveTunnelOriginStreamRuntime&) const;
    bool CreateExit(std::uint64_t,LiveTunnelExitStreamRuntime&); bool CreateOrigin(std::uint64_t,LiveTunnelOriginStreamRuntime&);
    bool UpdateExit(std::uint64_t,CKad6ExitSocket*,std::uint64_t,const LiveTunnelExitStreamRuntime&); bool UpdateOrigin(std::uint64_t,CKad6OriginSocket*,std::uint64_t,const LiveTunnelOriginStreamRuntime&);
    bool TakeExit(std::uint64_t,CKad6ExitSocket*,std::uint64_t,LiveTunnelExitStreamRuntime&); bool TakeOrigin(std::uint64_t,CKad6OriginSocket*,std::uint64_t,LiveTunnelOriginStreamRuntime&);
    bool HalfCloseExit(std::uint32_t,const kad6::K6StreamHalfClose&); bool HalfCloseOrigin(std::uint32_t,const kad6::K6StreamHalfClose&);
    bool CloseExit(std::uint32_t,const kad6::K6StreamClose&,LiveTunnelExitStreamRuntime&); bool CloseOrigin(std::uint32_t,const kad6::K6StreamClose&,LiveTunnelOriginStreamRuntime&);
    bool Grant(std::uint32_t,const kad6::K6MaxStreamData&); bool Grant(std::uint32_t,const kad6::K6MaxData&);
    std::uint64_t Available(std::uint32_t,std::uint64_t,std::uint8_t,std::uint64_t,std::uint64_t,std::uint64_t) const; std::uint64_t Sent(std::uint32_t,std::uint64_t,std::uint8_t) const;
    bool CommitSend(std::uint32_t,std::uint64_t,std::uint8_t,std::uint64_t,std::uint64_t,std::uint64_t,std::uint64_t);
    bool CommitExitSend(CKad6ExitSocket*,std::uint64_t,std::uint64_t,std::uint8_t,std::uint64_t,std::uint64_t,std::uint64_t,std::uint64_t);
    bool CommitOriginSend(CKad6OriginSocket*,std::uint64_t,std::uint64_t,std::uint8_t,std::uint64_t,std::uint64_t,std::uint64_t,std::uint64_t);
    bool InitialCredit(std::uint32_t,std::uint64_t,std::uint8_t,kad6::K6MaxStreamData&,kad6::K6MaxData&) const;
    bool CanAccept(std::uint32_t,std::uint64_t,std::uint8_t,std::uint64_t) const; bool Accept(std::uint32_t,std::uint64_t,std::uint8_t,std::uint64_t,std::uint64_t);
    bool Consume(std::uint32_t,std::uint64_t,std::uint8_t,std::uint64_t,std::uint64_t,kad6::K6MaxStreamData&,kad6::K6MaxData&); bool ReadsPaused(std::uint32_t) const;
    void Clear() noexcept;
private:
    LiveTunnelExitStreams* m_exit=nullptr; LiveTunnelOriginStreams* m_origin=nullptr; LiveTunnelSendCredits* m_send=nullptr; LiveTunnelReceiveCredits* m_receive=nullptr; LiveTunnelFlowStreamsByCircuit* m_circuits=nullptr; std::uint64_t* m_nextGeneration=nullptr;
    bool Register(std::uint32_t,std::uint64_t); void Remove(std::uint32_t,std::uint64_t) noexcept;
};
M2AModuleHandle M2A_BIND_LT5_AF2808989D(const M2AParentPort&);
Kad6StreamTransportAdapter* ResolveKad6StreamTransportAdapter(M2AModuleHandle&) noexcept;
} // namespace eSELive
