#include "stdafx.h"
#include "LiveCircuitRegistry.h"

#include "LiveCircuit.h"

#include <algorithm>

namespace eSELive {

bool LiveCircuitRegistry::Add(
    const CircuitPtr& circuit,
    CircuitState initial_state)
{
    if (!circuit || circuit->Id() == 0 || !IsInitialState(initial_state)
        || !CanTransition(circuit->State(), initial_state)
        || ContainsAnyLegId(circuit->Id())) {
        return false;
    }

    circuit->SetState(initial_state);
    m_circuits.push_back(circuit);
    return true;
}

std::vector<std::uint32_t> LiveCircuitRegistry::Clear()
{
    std::vector<std::uint32_t> identities;
    identities.reserve(m_circuits.size());
    for (const CircuitPtr& circuit : m_circuits) {
        if (circuit)
            identities.push_back(circuit->Id());
    }
    m_circuits.clear();
    m_roundRobinIndex = 0;
    return identities;
}

std::size_t LiveCircuitRegistry::RemoveDestroyed(
    std::set<std::uint32_t>* retired_ids)
{
    const std::size_t before = m_circuits.size();
    m_circuits.erase(
        std::remove_if(
            m_circuits.begin(),
            m_circuits.end(),
            [retired_ids](const CircuitPtr& circuit) {
                if (circuit && circuit->State() != CircuitState::Destroyed)
                    return false;
                if (retired_ids && circuit)
                    retired_ids->insert(circuit->Id());
                return true;
            }),
        m_circuits.end());

    if (m_circuits.empty())
        m_roundRobinIndex = 0;
    else
        m_roundRobinIndex %= m_circuits.size();
    return before - m_circuits.size();
}

bool LiveCircuitRegistry::Empty() const noexcept
{
    return m_circuits.empty();
}

std::size_t LiveCircuitRegistry::Size() const noexcept
{
    return m_circuits.size();
}

LiveCircuitRegistry::CircuitPtr LiveCircuitRegistry::At(
    std::size_t index) const noexcept
{
    return index < m_circuits.size() ? m_circuits[index] : CircuitPtr{};
}

LiveCircuitRegistry::CircuitPtr LiveCircuitRegistry::Back() const noexcept
{
    return m_circuits.empty() ? CircuitPtr{} : m_circuits.back();
}

const LiveCircuitRegistry::Snapshot&
LiveCircuitRegistry::GetSnapshot() const noexcept
{
    return m_circuits;
}

bool LiveCircuitRegistry::ContainsIncomingId(
    std::uint32_t circuit_id) const noexcept
{
    return static_cast<bool>(FindById(circuit_id));
}

bool LiveCircuitRegistry::ContainsAnyLegId(
    std::uint32_t circuit_id) const noexcept
{
    if (circuit_id == 0)
        return false;
    for (const CircuitPtr& circuit : m_circuits) {
        if (circuit
            && (circuit->Id() == circuit_id
                || circuit->m_nextCircId == circuit_id)) {
            return true;
        }
    }
    return false;
}

LiveCircuitRegistry::CircuitPtr LiveCircuitRegistry::FindById(
    std::uint32_t circuit_id) const noexcept
{
    if (circuit_id == 0)
        return {};
    for (const CircuitPtr& circuit : m_circuits) {
        if (circuit && circuit->Id() == circuit_id)
            return circuit;
    }
    return {};
}

LiveCircuitRegistry::CircuitPtr LiveCircuitRegistry::FindRelayByOutgoingId(
    std::uint32_t circuit_id) const noexcept
{
    if (circuit_id == 0)
        return {};
    for (const CircuitPtr& circuit : m_circuits) {
        if (circuit
            && circuit->m_role == CircuitRole::Relay
            && circuit->m_nextCircId == circuit_id) {
            return circuit;
        }
    }
    return {};
}

LiveCircuitRegistry::CircuitPtr LiveCircuitRegistry::NextRoundRobin() noexcept
{
    if (m_circuits.empty()) {
        m_roundRobinIndex = 0;
        return {};
    }
    const std::size_t index = m_roundRobinIndex % m_circuits.size();
    m_roundRobinIndex = (m_roundRobinIndex + 1) % m_circuits.size();
    return m_circuits[index];
}

bool LiveCircuitRegistry::Transition(
    const CircuitPtr& circuit,
    CircuitState target) noexcept
{
    if (!Owns(circuit) || !CanTransition(circuit->State(), target))
        return false;
    circuit->SetState(target);
    return true;
}

bool LiveCircuitRegistry::Owns(const CircuitPtr& circuit) const noexcept
{
    if (!circuit)
        return false;
    for (const CircuitPtr& candidate : m_circuits) {
        if (candidate == circuit)
            return true;
    }
    return false;
}

bool LiveCircuitRegistry::IsInitialState(CircuitState state) noexcept
{
    return state == CircuitState::Pending || state == CircuitState::Active;
}

bool LiveCircuitRegistry::CanTransition(
    CircuitState from,
    CircuitState to) noexcept
{
    if (from == to)
        return true;
    if (from == CircuitState::Destroyed)
        return false;
    if (to == CircuitState::Destroyed)
        return true;

    switch (from) {
    case CircuitState::Pending:
        return to == CircuitState::HalfBuilt || to == CircuitState::Active;
    case CircuitState::HalfBuilt:
        return to == CircuitState::Built || to == CircuitState::Active;
    case CircuitState::Built:
        return to == CircuitState::Active;
    case CircuitState::Active:
        return false;
    case CircuitState::Destroyed:
        return false;
    }
    return false;
}

CircuitRegistrySelfTestResult RunCircuitRegistryCharacterizationSelfTest()
{
    LiveCircuitRegistry registry;
    auto pending = std::make_shared<CLiveCircuit>(7);
    auto activeRelay = std::make_shared<CLiveCircuit>(8);
    activeRelay->m_role = CircuitRole::Relay;
    activeRelay->m_nextCircId = 80;
    auto activeOrigin = std::make_shared<CLiveCircuit>(9);

    if (!registry.Add(pending, CircuitState::Pending)
        || !registry.Add(activeRelay, CircuitState::Active)
        || !registry.Add(activeOrigin, CircuitState::Active)
        || registry.Size() != 3
        || registry.FindById(7) != pending
        || registry.FindRelayByOutgoingId(80) != activeRelay) {
        return CircuitRegistrySelfTestResult::AddOrLookupFailed;
    }

    auto duplicate = std::make_shared<CLiveCircuit>(7);
    auto outgoingCollision = std::make_shared<CLiveCircuit>(80);
    auto zero = std::make_shared<CLiveCircuit>(0);
    if (registry.Add({}, CircuitState::Pending)
        || registry.Add(zero, CircuitState::Pending)
        || registry.Add(duplicate, CircuitState::Pending)
        || registry.Add(outgoingCollision, CircuitState::Pending)
        || registry.Add(std::make_shared<CLiveCircuit>(10),
                        CircuitState::Destroyed)
        || !registry.ContainsIncomingId(7)
        || registry.ContainsIncomingId(80)
        || !registry.ContainsAnyLegId(80)) {
        return CircuitRegistrySelfTestResult::IdentityFenceFailed;
    }

    if (registry.NextRoundRobin() != pending
        || registry.NextRoundRobin() != activeRelay
        || registry.NextRoundRobin() != activeOrigin
        || registry.NextRoundRobin() != pending) {
        return CircuitRegistrySelfTestResult::RoundRobinFailed;
    }

    auto directActive = std::make_shared<CLiveCircuit>(10);
    auto directHalfBuilt = std::make_shared<CLiveCircuit>(11);
    if (registry.Transition(pending, CircuitState::Built)
        || !registry.Transition(pending, CircuitState::HalfBuilt)
        || registry.Transition(pending, CircuitState::Pending)
        || !registry.Transition(pending, CircuitState::Built)
        || registry.Transition(pending, CircuitState::HalfBuilt)
        || registry.Transition(pending, CircuitState::Pending)
        || !registry.Transition(pending, CircuitState::Active)
        || registry.Transition(pending, CircuitState::HalfBuilt)
        || registry.Transition(activeRelay, CircuitState::HalfBuilt)
        || registry.Transition(activeRelay, CircuitState::Pending)
        || !registry.Add(directActive, CircuitState::Pending)
        || !registry.Transition(directActive, CircuitState::Active)
        || registry.Transition(directActive, CircuitState::HalfBuilt)
        || !registry.Add(directHalfBuilt, CircuitState::Pending)
        || !registry.Transition(directHalfBuilt, CircuitState::HalfBuilt)
        || !registry.Transition(directHalfBuilt, CircuitState::Active)
        || registry.Transition(directHalfBuilt, CircuitState::HalfBuilt)
        || registry.Transition(duplicate, CircuitState::Destroyed)) {
        return CircuitRegistrySelfTestResult::TransitionFailed;
    }

    if (!registry.Transition(pending, CircuitState::Destroyed)
        || !registry.Transition(directActive, CircuitState::Destroyed)
        || !registry.Transition(directHalfBuilt, CircuitState::Destroyed)
        || !registry.Transition(pending, CircuitState::Destroyed)
        || registry.Transition(pending, CircuitState::Active)) {
        return CircuitRegistrySelfTestResult::TerminalStateFailed;
    }

    std::set<std::uint32_t> retired;
    if (registry.RemoveDestroyed(&retired) != 3
        || retired != std::set<std::uint32_t>({7, 10, 11})
        || registry.Size() != 2
        || registry.FindById(7)
        || registry.Add(pending, CircuitState::Active)) {
        return CircuitRegistrySelfTestResult::RemovalFailed;
    }

    const std::vector<std::uint32_t> cleared = registry.Clear();
    if (!registry.Empty()
        || cleared != std::vector<std::uint32_t>({8, 9})
        || registry.NextRoundRobin()) {
        return CircuitRegistrySelfTestResult::ClearFailed;
    }
    return CircuitRegistrySelfTestResult::Pass;
}

}  // namespace eSELive
