// this file is part of eMule eSE - LT5 stream and credit state owner
#include "stdafx.h"
#include "LiveTunnelStreamFlow.h"
namespace eSELive {
M2AModuleHandle M2A_BIND_LT5_AF2808989D(const M2AParentPort&);
Kad6StreamTransportAdapter* ResolveKad6StreamTransportAdapter(M2AModuleHandle&) noexcept;
bool RunKad6StreamTransportAdapterCharacterizationSelfTest(Kad6StreamTransportAdapter*);
LiveTunnelStreamFlow::LiveTunnelStreamFlow(const M2AParentPort&) noexcept {
    LT5StreamStateBinding state{&m_k6ExitStreams,&m_k6OriginStreams,&m_k6SendCredits,&m_k6ReceiveCredits,
        &m_k6FlowStreamsByCircuit,&m_nextGeneration};
    m_m2a_binding_af2808989d=M2A_BIND_LT5_AF2808989D(M2AParentPort{&state});
}
Kad6StreamTransportAdapter* LiveTunnelStreamFlow::Adapter() noexcept{return ResolveKad6StreamTransportAdapter(m_m2a_binding_af2808989d);}
const Kad6StreamTransportAdapter* LiveTunnelStreamFlow::Adapter() const noexcept{return static_cast<const Kad6StreamTransportAdapter*>(m_m2a_binding_af2808989d.Get());}
M2AModuleHandle M2A_BIND_LT5_AE4815B275(const M2AParentPort& parent){
    return MakeM2AModuleHandle(new LiveTunnelStreamFlow(parent));
}
LiveTunnelStreamFlow* ResolveLiveTunnelStreamFlow(M2AModuleHandle& h) noexcept{
    return static_cast<LiveTunnelStreamFlow*>(h.Get());
}
const LiveTunnelStreamFlow* ResolveLiveTunnelStreamFlow(const M2AModuleHandle& h) noexcept{
    return static_cast<const LiveTunnelStreamFlow*>(h.Get());
}
Kad6StreamTransportAdapter* M2A_LT5_AdapterBridge(M2AModuleHandle& h) noexcept{return ResolveLiveTunnelStreamFlow(h)->Adapter();} const Kad6StreamTransportAdapter* M2A_LT5_AdapterBridge(const M2AModuleHandle& h) noexcept{return ResolveLiveTunnelStreamFlow(h)->Adapter();}
bool RunLiveTunnelStreamFlowCharacterizationSelfTest(){int parent=0;LiveTunnelStreamFlow flow(M2AParentPort{&parent});return RunKad6StreamTransportAdapterCharacterizationSelfTest(flow.Adapter());}
bool M2A_LT5_CharacterizationBridge(){return RunLiveTunnelStreamFlowCharacterizationSelfTest();}
} // namespace eSELive
