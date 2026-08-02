#pragma once

#include "natmap/address_policy.h"
#include "natmap/direct_route_selection.h"

#include <cstdint>
#include <array>

namespace natmap {

// Closed MX04 admission outcome.  This policy is the only authority that may
// turn IPv6 evidence into a globally consumable direct-route observation.
enum class Ipv6ScopeDisposition : std::uint8_t {
    RejectGlobal = 0,
    Candidate = 1,
    VerifiedGlobal = 2,
    Withdraw = 3,
    SameLanOnly = 4,
    RejectSameLan = 5,
};

enum class Ipv6ScopeRequest : std::uint8_t {
    Global = 0,
    SameLan = 1,
};

struct PinholeEvidence {
    bool present = false;
    bool owned_by_us = false;
    bool authorized = false;
    Endpoint endpoint{};
    Endpoint public_endpoint{};
    Transport transport = Transport::Tcp;
    RouteBindingIdentity route_binding{};
    std::uint64_t generation = 0;
    std::uint64_t expires_monotonic_ms = 0;
};

struct InboundEvidence {
    bool present = false;
    Endpoint endpoint{};
    Transport transport = Transport::Tcp;
    RouteBindingIdentity route_binding{};
    std::uint64_t generation = 0;
    std::uint64_t expires_monotonic_ms = 0;
};

struct PrivateSameLanEvidence {
    bool present = false;
    bool positive_same_lan_domain = false;
    Endpoint endpoint{};
    Endpoint peer_endpoint{};
    Transport transport = Transport::Tcp;
    RouteBindingIdentity route_binding{};
    std::uint64_t generation = 0;
    std::uint64_t expires_monotonic_ms = 0;
    PrivateAddressScope scope{};
};

struct Ipv6ScopeInput {
    Endpoint current_endpoint{};
    Transport transport = Transport::Tcp;
    RouteBindingIdentity current_route_binding{};
    std::uint64_t current_generation = 0;
    std::uint64_t now_monotonic_ms = 0;
    Ipv6ScopeRequest requested_scope = Ipv6ScopeRequest::Global;
    PinholeEvidence pinhole{};
    InboundEvidence inbound{};
    PrivateSameLanEvidence same_lan{};
};

struct Ipv6ScopeDecision {
    Ipv6ScopeDisposition disposition = Ipv6ScopeDisposition::RejectGlobal;
    CandidateObservation observation{};
    ReasonCode reason = ReasonCode::NoRoute;
    AddressReason address_reason = AddressReason::FamilyUnspecified;
    bool may_select_direct_v6 = false;
    bool may_advertise_kad = false;
    bool may_advertise_remote_hello = false;
    bool may_publish_global = false;
    bool may_emit_unsanitized_report = false;
};

Ipv6ScopeDecision EvaluateIpv6ScopeAdmission(
    const Ipv6ScopeInput& input) noexcept;

// A typed fence between scope admission and global route selection.  LAN
// evidence can be locally useful but is never a DirectV6 selector input.
CandidateObservation GlobalRouteObservation(
    const Ipv6ScopeDecision& decision) noexcept;
bool CanUseSameLanEndpoint(const Ipv6ScopeDecision& decision) noexcept;

// MX04 lifecycle fences are pure so worker races can be exhaustively tested
// without a Windows socket, router or UI thread.
struct ProbeIncarnation {
    std::uint64_t generation = 0;
    std::uint64_t token = 0;
    bool shutdown = false;
};
bool CanPublishProbeVerdict(const ProbeIncarnation& captured,
                            const ProbeIncarnation& current) noexcept;

enum class PcpExchangeDisposition : std::uint8_t {
    RequestNotSent = 0,
    RequestSentNoResponse = 1,
    ResponseRejected = 2,
    Mapped = 3,
    ZeroLifetime = 4,
    Deleted = 5,
};
bool MustCleanupPcpNonce(PcpExchangeDisposition disposition) noexcept;

struct PcpLeaseOwnerIdentity {
    std::uint64_t generation = 0;
    std::uint64_t token = 0;
    std::array<std::uint8_t, 12> nonce{};
};
bool IsCurrentPcpLeaseOwner(const PcpLeaseOwnerIdentity& expected,
                            const PcpLeaseOwnerIdentity& current) noexcept;

enum class TopologyApplyDecision : std::uint8_t {
    Ignore = 0,
    Initialize = 1,
    Invalidate = 2,
};
TopologyApplyDecision EvaluateTopologyGenerationApply(
    std::uint64_t applied_generation,
    std::uint64_t published_generation) noexcept;

enum class ScopedSocketBindDecision : std::uint8_t {
    Reject = 0,
    Connect = 1,
};
ScopedSocketBindDecision EvaluateScopedSocketBind(
    bool same_lan_proof, std::uint32_t interface_index,
    int setsockopt_result) noexcept;

// PCP serialisation is represented as a pure decision so a waiting worker
// cannot publish an "unreachable" verdict or wake a retry twice.
enum class PcpCascadeOutcome : std::uint8_t {
    Failed = 0,
    Mapped = 1,
    Deferred = 2,
};
bool MayPublishCascadeVerdict(PcpCascadeOutcome outcome) noexcept;

enum class PcpBusyRetryOwner : std::uint8_t {
    ExistingOwner = 0,
    WaitingWorker = 1,
};
PcpBusyRetryOwner SelectPcpBusyRetryOwner(
    bool operation_still_active_after_pending) noexcept;

// UI-driven topology/shutdown cleanup consumes a pending PCP retry but never
// schedules it: the topology owner decides whether exactly one new probe runs.
bool UiPcpCleanupMayScheduleRetry() noexcept;

} // namespace natmap
