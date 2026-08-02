// this file is part of eMule eSE - LT8 search state owner
#pragma once
#include "LiveTunnelSearchPort.h"
#include "M2ABindingPort.h"
#include <map>
namespace eSELive {
class LiveTunnelSearchService {
public:
    explicit LiveTunnelSearchService(const M2AParentPort& parent) noexcept;
    bool AddJob(std::uint64_t key,const LiveTunnelSearchJob& job);
    bool UpdateJob(std::uint64_t key,const LiveTunnelSearchJob& job);
    bool FindJob(std::uint64_t key,LiveTunnelSearchJob& job) const;
    bool TakeJob(std::uint64_t key,LiveTunnelSearchJob& job);
    std::vector<LiveTunnelSearchJob> TakeDue(DWORD now);
    bool AppendReply(std::uint64_t key,const std::vector<std::uint8_t>& one,std::uint16_t maxResults,std::size_t maxBytes,DWORD now);
    bool TakeReply(std::uint64_t key,std::vector<std::uint8_t>& legacy,std::uint16_t& count);
    std::size_t SweepReplies(DWORD now,DWORD ttl);
    std::size_t JobCount() const noexcept;
private:
    const void* m_parent=nullptr;
    std::map<std::uint64_t,LiveTunnelSearchJob> m_searchJobs;
    std::map<std::uint64_t,LiveTunnelSearchReplyAggregate> m_k6SearchReplies;
};
M2AModuleHandle M2A_BIND_LT8_17641C1557(const M2AParentPort&);
bool RunLiveTunnelSearchServiceCharacterizationSelfTest();
} // namespace eSELive
