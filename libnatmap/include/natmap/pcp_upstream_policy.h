#pragma once

#include "natmap/mapped_candidate_adapter.h"
#include "natmap/natmap_chain.h"
#include "natmap/pcp_codec.h"

#include <cstdint>

namespace natmap {

// This is policy only. It neither discovers a PCP server nor sends a PCP
// packet. Upstream gateways must already have been supplied by the bounded
// M02 authorized-evidence path.
enum class PcpUpstreamOutcome : std::uint8_t {
    Absent = 0,
    Denied = 1,
    Mapped = 2,
    Failed = 3,
};

enum class PcpUpstreamDisposition : std::uint8_t {
    NoGlobalCandidate = 0,
    UpstreamDenied = 1,
    ChainIncomplete = 2,
    EndpointRejected = 3,
    Candidate = 4,
    Verified = 5,
    StaleProof = 6,
    ProofFailed = 7,
};

// Stable projection onto the already-frozen MX01 ReasonCode enum:
//   upstream absent   -> NoGateway
//   upstream denied   -> OperatorDenied
//   incomplete chain  -> CgnatWithoutLease
//   exact proof fail  -> ServerCallbackFailed
// An unusable final endpoint is NoRoute. No new persisted or wire reason is
// introduced by MX03.
struct PcpUpstreamDecision {
    PcpUpstreamDisposition disposition =
        PcpUpstreamDisposition::NoGlobalCandidate;
    ReasonCode reason = ReasonCode::NoGateway;
    MappedCandidateUpdate update = MappedCandidateUpdate::Rejected;
    MappedCandidatePromotion promotion =
        MappedCandidatePromotion::Rejected;

    bool allows_global_candidate() const noexcept {
        return disposition == PcpUpstreamDisposition::Candidate ||
               disposition == PcpUpstreamDisposition::Verified;
    }
};

// FILTER has no range representation: a requested filter must carry exactly
// one concrete peer endpoint. This policy intentionally does not add a PCP
// FILTER wire encoder in v9.2.
struct PcpMapRequestPolicyInput {
    const PcpMapRequest* request = nullptr;
    std::uint16_t documented_exact_port = 0;
    bool netlab_enabled = false;
    bool filter_requested = false;
    Endpoint filter_peer{};
};

enum class PcpMapRequestPolicyStatus : std::uint8_t {
    Allowed = 0,
    InvalidRequest = 1,
    PreferFailureRequiresDocumentedExactPort = 2,
    FilterRequiresConcretePeer = 3,
    PortSetRequiresNetLabOrOne = 4,
};

PcpMapRequestPolicyStatus ValidatePcpMapRequestPolicy(
    const PcpMapRequestPolicyInput& input) noexcept;

// Production-only emission boundary. The generic codec remains available to
// deterministic codec tests and decoders, but network callers must supply a
// policy context. FILTER is deliberately refused here: v9.2 has no FILTER
// wire encoder, even for a concrete peer.
std::size_t EncodePcpMapRequestForProduction(
    const PcpMapRequest& request,
    const PcpMapRequestPolicyInput& policy,
    std::uint8_t* out, std::size_t capacity) noexcept;

// Evaluates an already completed CPE->upstream attempt. A PCP CPE MAP alone
// is never global proof: the CPE chain must need an authorized upstream,
// that upstream must be supplied by M02 evidence and must return an owned,
// current, public PCP result.
PcpUpstreamDecision EvaluatePcpUpstreamCandidate(
    const NatChainTransaction& cpe_tcp_chain,
    const NatChainTransaction& cpe_udp_chain,
    const UpstreamGatewayCandidates& upstream_gateways,
    PcpUpstreamOutcome upstream_outcome,
    const MapperResult& upstream_result,
    std::uint64_t current_generation) noexcept;

// Projects the two physical PCP layers onto the one actionable listener
// mapping consumed by MX02. The local endpoints and route remain the original
// LAN listeners; only the granted public endpoints and upstream ownership
// come from layer two.
bool ProjectPcpFinalMapperResult(
    const MapperResult& cpe_result,
    const MapperResult& upstream_result,
    MapperResultData& final_result) noexcept;

// Numeric PCP epochs are renewal metadata, not identity. A typed reset or any
// ownership, route, gateway or endpoint discontinuity replaces the CPE layer.
bool SamePcpCpeMappingIdentity(
    const MapperResultData& current,
    const MapperResultData& next) noexcept;

// The only MX03 bridge to MX02. It leaves a public upstream MAP as a
// Candidate and invokes MappedCandidatePublisher::Promote only with an exact,
// current proof. Caller-owned route and ownership validation remain enforced
// by the publisher.
PcpUpstreamDecision PublishPcpUpstreamCandidate(
    MappedCandidatePublisher& publisher,
    const NatChainTransaction& cpe_tcp_chain,
    const NatChainTransaction& cpe_udp_chain,
    const UpstreamGatewayCandidates& upstream_gateways,
    PcpUpstreamOutcome upstream_outcome,
    const MapperResult& cpe_result,
    const MapperResult& upstream_result,
    const RouteBindingIdentity& route_binding,
    const MappedCandidateProof* proof,
    std::uint64_t now_monotonic_ms,
    std::uint64_t committed_generation = 0) noexcept;

} // namespace natmap
