// this file is part of eMule eSE - explicit Kad2/Kad6 tunnel adapter boundary
#pragma once
#include "M2ABindingPort.h"
#include "kad6/kad6_frontdoor.h"
#include "kad6/kad6_frame.h"
#include "kad6/kad6_hardening.h"
#include "kad6/kad6_lease.h"
#include "kad6/kad6_publish.h"
#include <array>
#include <cstdint>
#include <functional>
#include <map>
#include <vector>
namespace eSELive {
struct LiveTunnelKadPorts {
    std::function<bool(const wchar_t*, std::uint8_t)> should_route;
    std::function<bool(const wchar_t*, std::vector<std::uint32_t>*, bool)>
        search_streams;
    std::function<void(std::uint32_t)> stop_search;
    std::function<std::uint8_t()> selected_networks;
};
struct LT3SourceLeaseValue {
    kad6::K6SourceLease value{};
    bool found = false;
    explicit operator bool() const noexcept { return found; }
    const kad6::K6SourceLease& operator*() const noexcept { return value; }
    const kad6::K6SourceLease* operator->() const noexcept { return &value; }
};
class LiveTunnelKadBridge {
public:
    static const std::uint8_t kSelectedKad2 = 0x01;
    static const std::uint8_t kSelectedKad6 = 0x02;
    explicit LiveTunnelKadBridge(LiveTunnelKadPorts ports);
    LiveTunnelKadBridge(const LiveTunnelKadBridge&) = delete;
    LiveTunnelKadBridge& operator=(const LiveTunnelKadBridge&) = delete;
    bool ShouldRouteThroughTunnel(const wchar_t* keyword,
                                  std::uint8_t operation_class) const;
    bool SearchStreams(const wchar_t* keyword,
                       std::vector<std::uint32_t>* search_ids,
                       bool force_direct) const;
    void StopSearches(const std::vector<std::uint32_t>& search_ids) const noexcept;
    std::uint8_t SelectedNetworkMask(std::uint8_t kad2_mask,
                                     std::uint8_t kad6_mask) const;
    bool LT3LoadSourceEpochs( const std::vector<std::uint8_t>& wire, bool filePresent);
    bool LT3SourceEpochStoreHealthy() const noexcept;
    bool LT3SourceEpochStoreInitialized() const noexcept;
    bool LT3SourceEpochStoreFailed() const noexcept;
    bool LT3CanAcceptSourceEpoch( const std::array<std::uint8_t, 32>& identity, std::uint64_t epoch) const noexcept;
    bool LT3PrepareSourceEpochUpdate( const std::array<std::uint8_t, 32>& identity, std::uint64_t epoch, std::uint64_t& token, std::vector<std::uint8_t>& encoded);
    bool LT3CommitSourceEpochUpdate(std::uint64_t token) noexcept;
    void LT3RollbackSourceEpochUpdate(std::uint64_t token) noexcept;
    bool LT3PlanSearchReply(std::uint32_t, const std::vector<std::uint8_t>&, kad6::K6Frame&) const; bool LT3PlanExitGateway(std::uint32_t, const std::uint8_t*, std::size_t, kad6::K6Frame&) const;
    std::map<std::uint64_t, kad6::K6SourceLease> LT3SourceLeaseEntries() const;
    LT3SourceLeaseValue LT3FindSourceLease(std::uint64_t leaseId) const;
    std::size_t LT3SourceLeaseActiveSize();
    bool LT3SourceLeaseCanPublish(std::uint64_t leaseId);
    bool LT3SourceLeaseCanAccept(std::uint64_t leaseId) const;
    kad6::Kad6Status LT3AddBound( std::uint32_t circuitId, const kad6::Hash16& pseudonym, const kad6::K6SourceBind& bind, const kad6::K6SourceBound& bound, std::uint64_t now);
    kad6::Kad6Status LT3MarkPublished(std::uint64_t leaseId);
    kad6::Kad6Status LT3MarkServing(std::uint64_t leaseId);
    kad6::Kad6Status LT3BeginDrain(std::uint64_t leaseId);
    bool LT3CloseSourceLease(std::uint64_t leaseId);
    std::size_t LT3EraseClosedSourceLeases(std::size_t maximum);
    void LT3QueueCircuitTeardown(std::uint32_t circuitId);
    std::size_t LT3DrainQueuedCircuits( std::size_t maximum, std::vector<std::uint64_t>* transitioned);
    std::size_t LT3ExpireSourceLeases( std::uint64_t now, std::size_t maximum, std::vector<std::uint64_t>* transitioned);
    bool LT3CohortRegister(const kad6::K6CohortBackend& backend);
    bool LT3CohortSetServing(std::uint64_t leaseId, bool serving);
    bool LT3CohortSelect( const kad6::Hash16& fileHash, const kad6::Hash16& cohortId, std::uint64_t streamId, kad6::K6CohortBackend& selected);
    bool LT3CohortReleaseStream(std::uint64_t streamId);
    std::uint32_t LT3PublishAdmissionPermille(std::uint64_t now);
    bool LT3PublishAdmit( const kad6::K6PublishBudgetKey& key, std::uint64_t now);
    void LT3PublishNoteOverload(std::uint64_t now);
    bool LT3PublishEnqueue( const kad6::K6PublishSchedule& schedule, std::uint32_t jitter, std::uint64_t& effectiveLeaseId);
    std::vector<kad6::K6PublishSchedule> LT3PublishTakeDue( std::uint64_t now, std::size_t maximum);
    bool LT3PublishRemove(std::uint64_t leaseId);
    std::size_t LT3PublishExpire(std::uint64_t now);
    static std::uint8_t BuildNetworkMask(bool kad2_selected,
                                         bool kad6_selected,
                                         std::uint8_t kad2_mask,
                                         std::uint8_t kad6_mask) noexcept;
    static std::uint8_t BuildSearchFlags(std::uint8_t network_mask,
                                         std::uint8_t kad2_mask,
                                         std::uint8_t kad6_mask,
                                         std::uint8_t kad2_flag,
                                         std::uint8_t kad6_flag) noexcept;
    static std::size_t NetworkIndex(std::uint8_t network_origin,
                                    std::uint8_t kad6_origin) noexcept;
private:
    friend bool RunLiveTunnelKadBridgeCharacterizationSelfTest();
    LiveTunnelKadPorts m_ports;
    M2AModuleHandle m_m2a_binding_876b98a826;
};
bool RunLiveTunnelKadBridgeCharacterizationSelfTest();
} // namespace eSELive
