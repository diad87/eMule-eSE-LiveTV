#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <set>
#include <vector>

namespace eSELive {

class CLiveCircuit;
enum class CircuitState : std::uint8_t;

// Owns circuit collection identity, lookup order, round-robin position and
// state transitions. CLiveTunnel remains the composition root and serializes
// every call with its rank-10 registry lock; this class deliberately adds no
// second mutex and therefore cannot create a new lock-order edge.
class LiveCircuitRegistry
{
public:
    using CircuitPtr = std::shared_ptr<CLiveCircuit>;
    using Snapshot = std::vector<CircuitPtr>;

    LiveCircuitRegistry() = default;
    ~LiveCircuitRegistry() = default;

    LiveCircuitRegistry(const LiveCircuitRegistry&) = delete;
    LiveCircuitRegistry& operator=(const LiveCircuitRegistry&) = delete;
    LiveCircuitRegistry(LiveCircuitRegistry&&) = delete;
    LiveCircuitRegistry& operator=(LiveCircuitRegistry&&) = delete;

    // Adds one fully prepared circuit and commits its initial state. Incoming
    // identity zero, null records, duplicate identities and terminal initial
    // state are rejected without mutating the registry.
    bool Add(const CircuitPtr& circuit, CircuitState initial_state);

    // Clears collection ownership and resets round-robin position. Returned
    // identities let the coordinator retire circuit-bound adjacent domains
    // after releasing the registry lock.
    std::vector<std::uint32_t> Clear();

    // Removes terminal circuits and optionally snapshots their identities.
    // The cursor remains valid for the surviving collection.
    std::size_t RemoveDestroyed(std::set<std::uint32_t>* retired_ids = nullptr);

    bool Empty() const noexcept;
    std::size_t Size() const noexcept;
    CircuitPtr At(std::size_t index) const noexcept;
    CircuitPtr Back() const noexcept;
    // Read-only view valid only while the caller keeps its serialization
    // boundary. Returning a reference avoids repeated shared_ptr churn on the
    // hot Tick path without transferring collection ownership.
    const Snapshot& GetSnapshot() const noexcept;

    // Incoming IDs name local circuit records. Any-leg IDs additionally
    // include relay outbound IDs and are used when allocating an outbound leg.
    bool ContainsIncomingId(std::uint32_t circuit_id) const noexcept;
    bool ContainsAnyLegId(std::uint32_t circuit_id) const noexcept;

    CircuitPtr FindById(std::uint32_t circuit_id) const noexcept;
    CircuitPtr FindRelayByOutgoingId(std::uint32_t circuit_id) const noexcept;

    // Returns the next record and advances exactly once. Eligibility remains
    // a coordinator concern, so callers can try at most Size() candidates
    // without running a callback under registry ownership.
    CircuitPtr NextRoundRobin() noexcept;

    // The state machine is single-owner and fail-closed. Same-state commits
    // are idempotent; Destroyed is terminal.
    bool Transition(const CircuitPtr& circuit, CircuitState target) noexcept;

private:
    bool Owns(const CircuitPtr& circuit) const noexcept;
    static bool IsInitialState(CircuitState state) noexcept;
    static bool CanTransition(CircuitState from, CircuitState to) noexcept;

    Snapshot m_circuits;
    std::size_t m_roundRobinIndex = 0;
};

enum class CircuitRegistrySelfTestResult : std::uint8_t
{
    Pass = 0,
    AddOrLookupFailed,
    IdentityFenceFailed,
    RoundRobinFailed,
    TransitionFailed,
    TerminalStateFailed,
    RemovalFailed,
    ClearFailed
};

// Executes deterministic production registry code without network or UI work.
CircuitRegistrySelfTestResult RunCircuitRegistryCharacterizationSelfTest();

}  // namespace eSELive
