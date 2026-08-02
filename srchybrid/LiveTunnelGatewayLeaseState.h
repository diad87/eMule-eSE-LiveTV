#pragma once
#include "M2ABindingPort.h"
#include "LiveTunnelGatewayStorePort.h"
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>
namespace eSELive {
struct LiveTunnelGatewayLeaseSnapshot { std::uint64_t lease_id = 0, source_epoch = 0; bool publishable = false; };
struct LiveTunnelGatewayLeaseBridge;
class LiveTunnelGatewayLeaseState {
public:
    explicit LiveTunnelGatewayLeaseState(const M2AParentPort&) noexcept;
    ~LiveTunnelGatewayLeaseState() noexcept;
    LiveTunnelGatewayLeaseState(const LiveTunnelGatewayLeaseState&) = delete;
private:
    friend struct LiveTunnelGatewayLeaseBridge;
    friend void M2A_LT3_InitializeBridge(M2AModuleHandle&, void*, void (*)(void*), void*, void (*)(void*), void*, void (*)(void*), void*, void (*)(void*));
    friend bool M2A_LT3_LoadEpochsBridge(M2AModuleHandle&, const std::vector<std::uint8_t>&, bool);
    friend bool M2A_LT3_EpochStoreHealthyBridge(const M2AModuleHandle&) noexcept;
    friend bool M2A_LT3_EpochStoreInitializedBridge(const M2AModuleHandle&) noexcept;
    friend bool M2A_LT3_EpochStoreFailedBridge(const M2AModuleHandle&) noexcept;
    friend bool M2A_LT3_CanAcceptEpochBridge(const M2AModuleHandle&, const std::uint8_t*, std::size_t, std::uint64_t) noexcept;
    friend bool M2A_LT3_PrepareEpochUpdateBridge(M2AModuleHandle&, const std::uint8_t*, std::size_t, std::uint64_t, std::uint64_t&, std::vector<std::uint8_t>&);
    friend bool M2A_LT3_CommitEpochUpdateBridge(M2AModuleHandle&, std::uint64_t) noexcept; friend void M2A_LT3_RollbackEpochUpdateBridge(M2AModuleHandle&, std::uint64_t) noexcept;
    friend bool M2A_LT3_PlanGatewayFrameBridge(const M2AModuleHandle&, const std::uint8_t*, std::size_t, std::uint32_t, bool, void*);
    friend bool M2A_LT3_OperateStoresBridge(const M2AModuleHandle&, LiveTunnelGatewayStoreOperation, void*, void*, void*, void*, void*, void*);
    using Store = std::unique_ptr<void, void (*)(void*)>;
    Store m_k6SourceLeases{nullptr, nullptr};
    Store m_k6CohortScheduler{nullptr, nullptr};
    Store m_k6PublishBudget{nullptr, nullptr};
    Store m_k6PublishCoalescer{nullptr, nullptr};
    std::map<std::string, std::uint64_t> m_k6SourceEpochs;
    bool m_k6SourceEpochsLoaded = false;
    bool m_k6SourceEpochsLoadFailed = false;
    bool m_epochReservationActive = false;
    std::uint64_t m_epochReservationToken = 0;
    std::string m_epochReservationKey;
    std::uint64_t m_epochReservationValue = 0;
    mutable std::mutex m_mutex;
    mutable std::mutex m_storeMutex;
};
M2AModuleHandle M2A_BIND_LT3_876B98A826(const M2AParentPort&);
} // namespace eSELive
