// this file is part of eMule eSE - LT5 stream and credit state owner
#pragma once
#include "LiveTunnelStreamFlowPort.h"
#include "M2ABindingPort.h"
namespace eSELive {
class Kad6StreamTransportAdapter;
class LiveTunnelStreamFlow final {
public:
    explicit LiveTunnelStreamFlow(const M2AParentPort&) noexcept;
    LiveTunnelStreamFlow(const LiveTunnelStreamFlow&)=delete;
    LiveTunnelStreamFlow& operator=(const LiveTunnelStreamFlow&)=delete;
    Kad6StreamTransportAdapter* Adapter() noexcept;
    const Kad6StreamTransportAdapter* Adapter() const noexcept;
private:
    LiveTunnelExitStreams m_k6ExitStreams;
    LiveTunnelOriginStreams m_k6OriginStreams;
    LiveTunnelSendCredits m_k6SendCredits;
    LiveTunnelReceiveCredits m_k6ReceiveCredits;
    LiveTunnelFlowStreamsByCircuit m_k6FlowStreamsByCircuit;
    std::uint64_t m_nextGeneration=1;
    M2AModuleHandle m_m2a_binding_af2808989d;
};
M2AModuleHandle M2A_BIND_LT5_AE4815B275(const M2AParentPort&);
LiveTunnelStreamFlow* ResolveLiveTunnelStreamFlow(M2AModuleHandle&) noexcept;
const LiveTunnelStreamFlow* ResolveLiveTunnelStreamFlow(const M2AModuleHandle&) noexcept;
bool RunLiveTunnelStreamFlowCharacterizationSelfTest();
} // namespace eSELive
