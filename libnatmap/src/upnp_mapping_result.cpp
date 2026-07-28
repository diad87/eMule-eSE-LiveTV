#include "natmap/upnp_mapping_result.h"

#include <algorithm>
#include <limits>

namespace natmap {
namespace {

template <std::size_t Size>
bool IsZero(const std::array<std::uint8_t, Size>& value) noexcept {
    return std::all_of(value.begin(), value.end(),
                       [](std::uint8_t byte) { return byte == 0; });
}

bool IsExactObservation(const UpnpTransportObservation& observation,
                        Transport expected) noexcept {
    return observation.transport == expected &&
           observation.local_port != 0 &&
           observation.requested_external_port != 0 &&
           observation.granted_external_port != 0 &&
           observation.readback_matches &&
           observation.ownership_matches;
}

std::uint64_t EffectiveExpiry(std::uint32_t lifetime,
                              std::uint64_t now) noexcept {
    if (lifetime == 0)
        return 0;
    const std::uint64_t duration =
        static_cast<std::uint64_t>(lifetime) * 1000u;
    const std::uint64_t maximum =
        (std::numeric_limits<std::uint64_t>::max)();
    return duration > maximum - now ? maximum : now + duration;
}

TransportMappingResult Mapping(
    const UpnpTransportObservation& observation,
    const UpnpPairResultInput& input,
    std::uint64_t expiry) noexcept {
    TransportMappingResult result{};
    result.transport = observation.transport;
    result.local_endpoint = Endpoint{
        input.local_address, observation.local_port,
        EndpointSource::LocalInterface};
    result.requested_external_port =
        observation.requested_external_port;
    result.granted_external_endpoint = Endpoint{
        input.external_address, observation.granted_external_port,
        EndpointSource::UpnpExternalAddress};
    result.lifetime_seconds = input.lifetime_seconds;
    result.effective_expiry_monotonic_ms = expiry;
    return result;
}

} // namespace

MapperResultData BuildUpnpPairMapperResult(
    const UpnpPairResultInput& input) noexcept {
    MapperResultData data{};
    data.mapper = MapperKind::UpnpIgd;
    data.source = MapperSource::UpnpIgd;
    data.gateway = Endpoint{
        input.gateway_address, 1900, EndpointSource::LocalInterface};
    data.request_id = input.request.request_id;
    data.topology_generation = input.request.topology_generation;
    data.operation = input.request.operation;

    const bool exactPair =
        input.request.IsValid() &&
        (input.request.operation == MappingOperation::Initial ||
         input.request.operation == MappingOperation::Refresh) &&
        input.gateway_address.IsSpecified() &&
        !input.gateway_address.IsUnspecified() &&
        input.local_address.IsSpecified() &&
        !input.local_address.IsUnspecified() &&
        input.external_address.IsSpecified() &&
        !input.external_address.IsUnspecified() &&
        IsExactObservation(input.tcp, Transport::Tcp) &&
        IsExactObservation(input.udp, Transport::Udp) &&
        !IsZero(input.ownership_identity_digest);
    if (!exactPair) {
        data.status = MappingStatus::Failed;
        data.protocol_result_code = input.failure_protocol_code;
        data.reason = input.failure_reason == ReasonCode::None
            ? ReasonCode::InvalidResponse : input.failure_reason;
        data.verification = VerificationState::Failed;
        return data;
    }

    const std::uint64_t expiry = EffectiveExpiry(
        input.lifetime_seconds, input.now_monotonic_ms);
    data.mapping_count = 2;
    data.mappings[0] = Mapping(input.tcp, input, expiry);
    data.mappings[1] = Mapping(input.udp, input, expiry);
    data.ownership_identity_digest =
        input.ownership_identity_digest;
    data.ownership = OwnershipState::OwnedByUs;
    data.verification = VerificationState::Pending;
    data.status = input.request.operation == MappingOperation::Refresh
        ? MappingStatus::Renewed : MappingStatus::Created;
    return data;
}

bool ShouldRollbackUpnpMappingAfterAtomicFailure(
    const UpnpTransportObservation& observation) noexcept {
    return (observation.transport == Transport::Tcp ||
            observation.transport == Transport::Udp) &&
           observation.local_port != 0 &&
           observation.granted_external_port != 0 &&
           observation.readback_matches &&
           observation.ownership_matches &&
           observation.created_by_operation;
}

} // namespace natmap
