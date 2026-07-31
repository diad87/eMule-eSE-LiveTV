// this file is part of eMule eSE - LT6 origin state owner
#pragma once
#include "LiveTunnelGatewayLeaseState.h"
#include "LiveTunnelOriginPort.h"
#include "M2ABindingPort.h"
#include <cstdint>
#include <map>
#include <mutex>
#include <set>
#include <string>
namespace eSELive{
class LiveTunnelOriginService final {
public:
    explicit LiveTunnelOriginService(const M2AParentPort&);~LiveTunnelOriginService() noexcept;
    LiveTunnelOriginService(const LiveTunnelOriginService&)=delete;LiveTunnelOriginService& operator=(const LiveTunnelOriginService&)=delete;

    bool AddSourceLookup(std::uint32_t,const LiveTunnelOriginSourceLookup&);bool BindSourceLookup(std::uint32_t,std::uint32_t,LiveTunnelOriginSourceLookup&);
    bool NoteSourceLookupResult(std::uint32_t);bool TakeSourceLookup(std::uint32_t,std::uint32_t,LiveTunnelOriginSourceLookup&);
    bool AddDownloadActivation(std::uint32_t,const LiveTunnelOriginDownloadActivation&);bool TakeDownloadActivation(std::uint32_t,std::uint32_t,LiveTunnelOriginDownloadActivation&);
    bool RemoveDownloadActivation(std::uint32_t,LiveTunnelOriginDownloadActivation* =nullptr);
    void RemoveDownloadActivationsByClient(std::uintptr_t clientToken);
    void AddSourceRoute(std::uint64_t,std::uint32_t);bool FindSourceRoute(std::uint64_t,std::uint32_t&)const;bool TakeSourceRoute(std::uint64_t,std::uint32_t&);
    void AddPublishRoute(std::uint64_t,std::uint32_t);bool TakePublishRoute(std::uint64_t,std::uint32_t&);
    LiveTunnelOriginAdvertiseReservation ReserveAdvertise(const std::string&,std::uint64_t,std::uint64_t);
    bool FinishAdvertise(const std::string&,std::uint64_t,bool,std::uint64_t,std::uint64_t,std::uint32_t,std::uint64_t);
    bool SubmitAdvertise(std::uint64_t,LiveTunnelOriginWorkerTask);
    void AddTargetRoute(const std::string&,const LiveTunnelOriginTargetRoute&);bool FindTargetRoute(const std::string&,std::uint64_t,LiveTunnelOriginTargetRoute&)const;
    void AddLiveRoute(const std::string&,const LiveTunnelOriginTargetRoute&);bool FindLiveRoute(const std::string&,std::uint64_t,LiveTunnelOriginTargetRoute&)const;
    LiveTunnelOriginSweepResult Sweep(std::uint64_t,std::uint32_t,const std::set<std::uint32_t>&);
    void Cancel() noexcept; void Join() noexcept;

private:
    struct AdvertiseState{bool in_flight=false;std::uint64_t next_attempt=0,source_lease_id=0,publish_lease_id=0,generation=0;};
    mutable std::mutex m_mutex;
    std::map<std::uint32_t,LiveTunnelOriginSourceLookup> m_k6OriginSourceLookups;
    std::map<std::uint32_t,LiveTunnelOriginDownloadActivation> m_k6DownloadActivations;
    std::map<std::uint64_t, std::uint32_t> m_k6OriginSourceLeaseRoutes;
    std::map<std::uint64_t, std::uint32_t> m_k6OriginPublishLeaseRoutes;
    std::map<std::string, AdvertiseState> m_k6OriginAdvertisements;
    std::uint64_t m_k6OriginSourceEpoch = 0;
    std::map<std::string, LiveTunnelOriginTargetRoute> m_k6OriginTargetRoutes;
    std::map<std::string, LiveTunnelOriginTargetRoute> m_k6OriginLiveRoutes;
    std::uint64_t m_lastSweepSecond = 0;
    M2AModuleHandle m_m2a_binding_6f855b99c0;
};
M2AModuleHandle M2A_BIND_LT6_8E07B736A1(const M2AParentPort&);
LiveTunnelOriginService* ResolveLiveTunnelOriginService(M2AModuleHandle&) noexcept;
const LiveTunnelOriginService* ResolveLiveTunnelOriginService(const M2AModuleHandle&) noexcept;
bool RunLiveTunnelOriginServiceCharacterizationSelfTest();
} // namespace eSELive
