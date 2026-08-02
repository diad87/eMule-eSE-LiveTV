// this file is part of eMule eSE - LT4 publish and ticket state owner
#pragma once

#include "M2ABindingPort.h"
#include "LiveTunnelTicketPolicy.h"
#include "LiveTunnelSourcePublisherPort.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace eSELive {

class LiveTunnelSourcePublisher final {
public:
    explicit LiveTunnelSourcePublisher(const M2AParentPort&) noexcept;
    LiveTunnelSourcePublisher(const LiveTunnelSourcePublisher&) = delete;
    LiveTunnelSourcePublisher& operator=(const LiveTunnelSourcePublisher&) =
        delete;

    bool InitializeTicketSecret(
        const std::array<std::uint8_t, 32>& secret) noexcept;
    bool TicketSecretReady() const noexcept;
    std::array<std::uint8_t, 32> TicketSecretSnapshot() const noexcept;
    void AuthorizeTarget(
        const std::string& key,
        const LiveTunnelAuthorizedTarget& target);
    bool FindAuthorizedTarget(
        const std::string& key,
        std::uint64_t now,
        LiveTunnelAuthorizedTarget& target) const;
    bool ConsumeTicket(
        const kad6::K6TargetTicket& ticket,
        std::uint64_t now) noexcept;

    LiveTunnelPublishMutation PreparePublish(
        const LiveTunnelPublishRuntime& runtime,
        const std::string& shadowKey);
    LiveTunnelPublishMutation OpenPublish(
        LiveTunnelPublishRuntime& runtime,
        const std::string& shadowKey,
        LiveTunnelPublishRuntime& duplicate,
        bool& exteriorPublish);
    LiveTunnelPublishMutation CommitPublish(
        std::uint64_t publishLeaseId,
        kad6::K6PublishStatus status,
        std::uint8_t networks);
    LiveTunnelPublishMutation Unpublish(
        std::uint64_t publishLeaseId,
        std::vector<LiveTunnelPublishAction>& actions);
    LiveTunnelPublishMutation RecordShadowAck(
        std::uint64_t publishLeaseId,
        std::uint16_t replicas,
        std::uint8_t load);
    LiveTunnelPublishMutation RecordNativeAck(
        std::uint64_t publishLeaseId,
        kad6::K6PublishStatus status);
    std::vector<LiveTunnelPublishAction> CollectRefreshes(
        std::uint64_t now) const;
    std::vector<LiveTunnelPublishAction> Sweep(std::uint64_t now);
    bool DisablePublish(std::uint64_t publishLeaseId);
    std::vector<std::uint64_t> DisableSource(std::uint64_t sourceLeaseId);
    std::vector<std::uint64_t> DisableAll(bool clear);
    bool EnsureShadow(const std::string& key,std::uint64_t candidate,
                      std::uint64_t& primary,bool& created);
    bool ForgetShadow(const std::string& key);
    bool SetQueueState(std::uint64_t publishLeaseId,bool queued,
                       std::uint64_t primary,std::uint64_t nextRefresh);
    bool MarkNativeSent(std::uint64_t publishLeaseId,std::uint64_t now,
                        std::uint64_t ttl,std::uint64_t& sourceLeaseId);
    std::vector<std::uint64_t> MarkShadowSent(std::uint64_t publishLeaseId);
    bool MarkShadowAckFamily(std::uint64_t publishLeaseId,
                             std::uint8_t load,std::uint64_t now);
    bool MarkShadowVerifiedFamily(std::uint64_t publishLeaseId);
    bool MarkNativeResult(std::uint64_t publishLeaseId,
                          kad6::K6StoreStatus status,std::uint8_t load,
                          std::uint64_t acceptedEpoch,std::uint64_t now,
                          bool& overload);
    std::vector<LiveTunnelPublishRuntime> TakeNativeRefreshes(std::uint64_t now);
    bool CompleteNativeRefresh(std::uint64_t publishLeaseId,bool sent,
                               std::uint64_t now);
    bool TakeShadow(std::uint64_t publishLeaseId,
                    LiveTunnelPublishRuntime& runtime);
    bool CompleteShadow(std::uint64_t publishLeaseId,bool started,
                        std::uint64_t now);
    std::vector<LiveTunnelPublishRuntime> TakeVisibilityProbes(
        std::uint64_t now,bool& overload);
    bool CompleteVisibilityProbe(std::uint64_t publishLeaseId,bool started,
                                 std::uint64_t now);
    void ResetPublishes();
    void PruneTicketState(std::uint64_t now);
    std::size_t PublishCount() const noexcept;
    std::map<std::uint64_t, LiveTunnelPublishRuntime>
        PublishSnapshot() const;
    bool FindPublish(
        std::uint64_t publishLeaseId,
        LiveTunnelPublishRuntime& runtime) const;
    std::map<std::string, std::uint64_t> ShadowSnapshot() const;

private:
    std::map<std::uint64_t, LiveTunnelPublishRuntime> m_k6Publishes;
    std::map<std::string, std::uint64_t> m_k6ShadowPrimary;
    std::array<std::uint8_t, 32> m_k6TicketSecret{};
    bool m_k6TicketSecretReady = false;
    std::map<std::string, LiveTunnelAuthorizedTarget> m_k6AuthorizedTargets;
    std::map<std::string, LiveTunnelUsedTicket> m_k6UsedTickets;
    mutable std::mutex m_mutex;
    M2AModuleHandle m_m2a_binding_15f4a995ea;
};

M2AModuleHandle M2A_BIND_LT4_6E698BD4A3(const M2AParentPort&);
LiveTunnelSourcePublisher* ResolveLiveTunnelSourcePublisher(
    M2AModuleHandle&) noexcept;
const LiveTunnelSourcePublisher* ResolveLiveTunnelSourcePublisher(
    const M2AModuleHandle&) noexcept;
bool RunLiveTunnelSourcePublisherCharacterizationSelfTest();

} // namespace eSELive
