// SPDX-License-Identifier: MIT
// Bounded KRP reliable-flow state machine and shared session memory budget.
#pragma once

#include "relay/krp_authority.h"

#include <array>
#include <cstddef>
#include <cstdint>

namespace relay {

constexpr std::size_t kKrpLogicalFlowIdSize = 16;
constexpr std::uint64_t kKrpMaxBufferPerFlow = 8ull * 1024ull * 1024ull;
constexpr std::uint64_t kKrpMaxBufferPerSession = 128ull * 1024ull * 1024ull;
constexpr std::uint64_t kKrpMaxPressureTimeoutMs = 60000;
constexpr std::size_t kKrpSoftActiveFlows = 256;
constexpr std::size_t kKrpHardRegisteredFlows = 1024;

using KrpLogicalFlowId = std::array<Byte, kKrpLogicalFlowIdSize>;

enum class KrpFlowState : std::uint8_t {
    Requested = 0,
    Authorizing,
    Connecting,
    Open,
    Pressured,
    HalfClosed,
    Closed,
    Reset,
};

struct KrpFlowConfig {
    std::uint64_t flow_id = 0;
    KrpLogicalFlowId logical_flow_id{};
    KrpService service = KrpService::Control;
    std::uint64_t session_epoch = 0;
    std::uint64_t route_generation = 0;
    std::uint64_t soft_buffer_bytes = 0;
    std::uint64_t hard_buffer_bytes = 0;
    std::uint64_t pressure_timeout_ms = 0;
};

class KrpMemoryBudget {
public:
    explicit KrpMemoryBudget(std::uint64_t maximum_bytes) noexcept;

    std::uint64_t maximum() const noexcept { return maximum_bytes_; }
    std::uint64_t used() const noexcept { return used_bytes_; }
    std::uint64_t available() const noexcept { return maximum_bytes_ - used_bytes_; }

    RelayStatus Reserve(std::uint64_t bytes) noexcept;
    RelayStatus Release(std::uint64_t bytes) noexcept;

private:
    std::uint64_t maximum_bytes_ = 0;
    std::uint64_t used_bytes_ = 0;
};

class KrpFlowIdRegistry {
public:
    explicit KrpFlowIdRegistry(std::uint64_t session_epoch,
                               std::size_t active_limit = kKrpSoftActiveFlows) noexcept;

    RelayStatus Register(std::uint64_t flow_id,
                         std::uint64_t session_epoch) noexcept;
    RelayStatus MarkTerminal(std::uint64_t flow_id,
                             std::uint64_t session_epoch) noexcept;
    std::size_t registered_count() const noexcept { return registered_count_; }
    std::size_t active_count() const noexcept { return active_count_; }

private:
    struct Entry {
        std::uint64_t flow_id = 0;
        bool active = false;
    };

    std::uint64_t session_epoch_ = 0;
    std::size_t active_limit_ = 0;
    std::size_t registered_count_ = 0;
    std::size_t active_count_ = 0;
    std::array<Entry, kKrpHardRegisteredFlows> entries_{};
};

class KrpFlow {
public:
    KrpFlow() noexcept = default;

    RelayStatus Initialize(const KrpFlowConfig& config) noexcept;
    RelayStatus BeginAuthorization() noexcept;
    RelayStatus AcceptAuthority(const KrpAuthorityGrant& grant,
                                std::uint64_t now) noexcept;
    RelayStatus ConnectionEstablished() noexcept;
    RelayStatus ConnectionFailed() noexcept;

    RelayStatus QueueBytes(std::uint64_t bytes,
                           std::uint64_t now_ms,
                           KrpMemoryBudget& session_budget) noexcept;
    RelayStatus ConsumeQueuedBytes(std::uint64_t bytes,
                                   KrpMemoryBudget& session_budget) noexcept;
    RelayStatus CheckPressureDeadline(std::uint64_t now_ms,
                                      KrpMemoryBudget& session_budget) noexcept;
    RelayStatus AcceptReceiveSequence(std::uint64_t sequence) noexcept;

    RelayStatus HalfCloseLocal(KrpMemoryBudget& session_budget) noexcept;
    RelayStatus HalfCloseRemote(KrpMemoryBudget& session_budget) noexcept;
    RelayStatus Reset(KrpMemoryBudget& session_budget) noexcept;

    bool initialized() const noexcept { return initialized_; }
    KrpFlowState state() const noexcept { return state_; }
    const KrpFlowConfig& config() const noexcept { return config_; }
    const KrpAuthorityGrant& grant() const noexcept { return grant_; }
    std::uint64_t queued_bytes() const noexcept { return queued_bytes_; }
    std::uint64_t transferred_bytes() const noexcept { return transferred_bytes_; }
    std::uint64_t next_receive_sequence() const noexcept { return next_receive_sequence_; }
    bool pressure_active() const noexcept { return pressure_active_; }

private:
    RelayStatus CloseIfBothDirectionsEnded(KrpMemoryBudget& session_budget) noexcept;
    void RestoreDataState() noexcept;

    bool initialized_ = false;
    bool authority_accepted_ = false;
    bool local_send_open_ = true;
    bool remote_send_open_ = true;
    bool pressure_active_ = false;
    bool receive_sequence_exhausted_ = false;
    KrpFlowState state_ = KrpFlowState::Requested;
    KrpFlowConfig config_{};
    KrpAuthorityGrant grant_{};
    std::uint64_t queued_bytes_ = 0;
    std::uint64_t transferred_bytes_ = 0;
    std::uint64_t pressure_deadline_ms_ = 0;
    std::uint64_t next_receive_sequence_ = 0;
};

const char* KrpFlowStateName(KrpFlowState state) noexcept;

} // namespace relay
