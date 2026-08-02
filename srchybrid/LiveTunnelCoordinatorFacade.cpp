// this file is part of eMule eSE - LT9 coordinator state owner
#include "stdafx.h"
#include "LiveTunnelCoordinatorFacade.h"
#include <cstring>
namespace eSELive {
LiveTunnelCoordinatorFacade::LiveTunnelCoordinatorFacade(const M2AParentPort& parent)noexcept:m_parent(parent.context){}
LiveTunnelGuardLoadDecision LiveTunnelCoordinatorFacade::BeginGuardLoad(std::uint64_t now)noexcept{
    if(m_k6GuardLoaded)return m_k6GuardExpiresAt>now?LiveTunnelGuardLoadDecision::CachedValid:LiveTunnelGuardLoadDecision::CachedExpired;
    m_k6GuardLoaded=true;m_k6GuardNodePub.fill(0);m_k6GuardExpiresAt=0;return LiveTunnelGuardLoadDecision::NeedStorage;
}
void LiveTunnelCoordinatorFacade::SetGuard(const std::uint8_t nodePub[32],std::uint64_t expiresAt)noexcept{
    if(nodePub)std::memcpy(m_k6GuardNodePub.data(),nodePub,m_k6GuardNodePub.size());else m_k6GuardNodePub.fill(0);
    m_k6GuardExpiresAt=expiresAt;m_k6GuardLoaded=true;
}
bool LiveTunnelCoordinatorFacade::CopyGuard(std::array<std::uint8_t,32>& nodePub)const noexcept{
    nodePub=m_k6GuardNodePub;return m_k6GuardLoaded&&m_k6GuardExpiresAt!=0;
}
bool LiveTunnelCoordinatorFacade::ConsumeRtt(std::uint32_t requestId,std::uint32_t now,std::uint32_t& elapsed)noexcept{
    if(!requestId||requestId!=m_rttPingReqId||!m_rttPingSentTick)return false;
    elapsed=now-m_rttPingSentTick;m_rttPingReqId=0;return true;
}
void LiveTunnelCoordinatorFacade::RecordRtt(std::uint32_t requestId,std::uint32_t sentAt)noexcept{m_rttPingReqId=requestId;m_rttPingSentTick=sentAt;}
void LiveTunnelCoordinatorFacade::ClearRtt()noexcept{m_rttPingReqId=0;}
bool LiveTunnelCoordinatorFacade::ShouldAttemptQuotaGuard(
    std::uint32_t now,std::uint32_t interval)noexcept{
    if(static_cast<std::uint32_t>(now-m_lastK6QuotaGuardAttemptTick)<interval)
        return false;
    m_lastK6QuotaGuardAttemptTick=now;return true;
}
M2AModuleHandle M2A_BIND_LT9_A14692E28F(const M2AParentPort& parent){return MakeM2AModuleHandle(new LiveTunnelCoordinatorFacade(parent));}
namespace {
LiveTunnelCoordinatorFacade* Resolve(M2AModuleHandle& h)noexcept{return static_cast<LiveTunnelCoordinatorFacade*>(h.Get());}
const LiveTunnelCoordinatorFacade* Resolve(const M2AModuleHandle& h)noexcept{return static_cast<const LiveTunnelCoordinatorFacade*>(h.Get());}
}
bool M2A_LT9_BeginGuardLoadBridge(M2AModuleHandle& h,std::uint64_t n,bool& valid){auto* o=Resolve(h);const auto d=o?o->BeginGuardLoad(n):LiveTunnelGuardLoadDecision::CachedExpired;valid=d==LiveTunnelGuardLoadDecision::CachedValid;return d==LiveTunnelGuardLoadDecision::NeedStorage;}
void M2A_LT9_SetGuardBridge(M2AModuleHandle& h,const std::uint8_t p[32],std::uint64_t e){auto* o=Resolve(h);if(o)o->SetGuard(p,e);}
bool M2A_LT9_CopyGuardBridge(const M2AModuleHandle& h,std::array<std::uint8_t,32>& p){auto* o=Resolve(h);return o&&o->CopyGuard(p);}
bool M2A_LT9_ConsumeRttBridge(M2AModuleHandle& h,std::uint32_t r,std::uint32_t n,std::uint32_t& e){auto* o=Resolve(h);return o&&o->ConsumeRtt(r,n,e);}
void M2A_LT9_RecordRttBridge(M2AModuleHandle& h,std::uint32_t r,std::uint32_t n){auto* o=Resolve(h);if(o)o->RecordRtt(r,n);}
void M2A_LT9_ClearRttBridge(M2AModuleHandle& h){auto* o=Resolve(h);if(o)o->ClearRtt();}
bool M2A_LT9_ShouldAttemptQuotaGuardBridge(M2AModuleHandle& h,std::uint32_t n,
    std::uint32_t i){auto* o=Resolve(h);return o&&o->ShouldAttemptQuotaGuard(n,i);}
bool RunLiveTunnelCoordinatorFacadeCharacterizationSelfTest(){
    LiveTunnelCoordinatorFacade owner(M2AParentPort{reinterpret_cast<void*>(1)});
    if(owner.BeginGuardLoad(100)!=LiveTunnelGuardLoadDecision::NeedStorage)return false;
    if(owner.BeginGuardLoad(100)!=LiveTunnelGuardLoadDecision::CachedExpired)return false;
    std::uint8_t guard[32]={7};owner.SetGuard(guard,200);std::array<std::uint8_t,32> copy{};
    if(owner.BeginGuardLoad(199)!=LiveTunnelGuardLoadDecision::CachedValid||!owner.CopyGuard(copy)||copy[0]!=7)return false;
    if(owner.BeginGuardLoad(200)!=LiveTunnelGuardLoadDecision::CachedExpired)return false;
    owner.RecordRtt(9,0xfffffffau);std::uint32_t elapsed=0;
    if(!owner.ConsumeRtt(9,3,elapsed)||elapsed!=9||owner.ConsumeRtt(9,4,elapsed))return false;
    owner.RecordRtt(10,8);owner.ClearRtt();
    if(owner.ConsumeRtt(10,9,elapsed))return false;
    if(owner.ShouldAttemptQuotaGuard(4999,5000)||
        !owner.ShouldAttemptQuotaGuard(5000,5000)||
        owner.ShouldAttemptQuotaGuard(9999,5000)||
        !owner.ShouldAttemptQuotaGuard(10000,5000))return false;
    return true;
}
} // namespace eSELive
