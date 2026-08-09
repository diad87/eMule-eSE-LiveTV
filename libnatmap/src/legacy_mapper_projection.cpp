#include "natmap/legacy_mapper_projection.h"
#include "natmap/address_policy.h"

#include <limits>

namespace natmap {
namespace {

bool SameAddress(const IpAddress& left,
                 const IpAddress& right) noexcept {
    return left.family == right.family &&
           left.bytes == right.bytes;
}

bool IsCanonicalV4(const IpAddress& address) noexcept {
    if (address.family != AddressFamily::IPv4 ||
        address.IsUnspecified())
        return false;
    for (std::size_t i = 4; i < address.bytes.size(); ++i)
        if (address.bytes[i] != 0)
            return false;
    return true;
}

bool IsUnroutableExternalV4(
    const IpAddress& address) noexcept {
    if (!IsCanonicalV4(address))
        return true;
    const AddressClass address_class =
        ClassifyAddress(address).address_class;
    // RFC1918 and shared space are deliberately admitted here so M02 can
    // continue through an authorized upper NAT layer or fail closed as
    // native CGNAT. Every other non-public class is unusable as a mapper WAN.
    return address_class != AddressClass::Public &&
           address_class != AddressClass::Rfc1918 &&
           address_class != AddressClass::SharedCgnat;
}

bool IdentityMatches(MapperKind mapper, MapperSource source,
                     EndpointSource endpoint_source) noexcept {
    switch (mapper) {
    case MapperKind::UpnpIgd:
        return source == MapperSource::UpnpIgd &&
               endpoint_source ==
                   EndpointSource::UpnpExternalAddress;
    case MapperKind::Pcp:
        return (source == MapperSource::PcpCpe ||
                source == MapperSource::PcpUpstream) &&
               endpoint_source == EndpointSource::PcpMap;
    case MapperKind::NatPmp:
        return source == MapperSource::NatPmp &&
               endpoint_source ==
                   EndpointSource::NatPmpPublicAddress;
    default:
        return false;
    }
}

bool IsKnownMapper(MapperKind mapper) noexcept {
    return mapper == MapperKind::UpnpIgd ||
           mapper == MapperKind::Pcp ||
           mapper == MapperKind::NatPmp;
}

bool SourceMatchesMapper(
    MapperKind mapper,
    MapperSource source) noexcept {
    return (mapper == MapperKind::UpnpIgd &&
            source == MapperSource::UpnpIgd) ||
           (mapper == MapperKind::Pcp &&
            (source == MapperSource::PcpCpe ||
             source == MapperSource::PcpUpstream)) ||
           (mapper == MapperKind::NatPmp &&
            source == MapperSource::NatPmp);
}

bool SameTopologyIdentity(
    const MapperTopologyIdentity& left,
    const MapperTopologyIdentity& right) noexcept {
    return left.mapper == right.mapper &&
           left.mapper_source == right.mapper_source &&
           SameAddress(
               left.gateway_address, right.gateway_address) &&
           SameAddress(
               left.external_address, right.external_address) &&
           left.local_tcp_port == right.local_tcp_port &&
           left.external_tcp_port == right.external_tcp_port &&
           left.local_udp_port == right.local_udp_port &&
           left.external_udp_port == right.external_udp_port;
}

} // namespace

bool MapperTopologyIdentity::IsValid() const noexcept {
    return IsKnownMapper(mapper) &&
           SourceMatchesMapper(mapper, mapper_source) &&
           IsCanonicalV4(gateway_address) &&
           IsCanonicalV4(external_address) &&
           local_tcp_port != 0 &&
           external_tcp_port != 0 &&
           ((local_udp_port == 0 &&
             external_udp_port == 0) ||
            (local_udp_port != 0 &&
             external_udp_port != 0));
}

bool ProjectLegacyMapperObservation(
    const MapperResult& result,
    LegacyMapperObservation& observation) noexcept {
    const MapperResultData& data = result.data();
    const bool initial =
        data.operation == MappingOperation::Initial &&
        data.status == MappingStatus::Created;
    const bool refresh =
        data.operation == MappingOperation::Refresh &&
        data.status == MappingStatus::Renewed;
    if ((!initial && !refresh) ||
        data.request_id == 0 ||
        data.topology_generation == 0 ||
        data.gateway.source != EndpointSource::LocalInterface ||
        !IsCanonicalV4(data.gateway.address) ||
        data.mapping_count == 0 ||
        data.mapping_count > data.mappings.size())
        return false;

    const TransportMappingResult* tcp = nullptr;
    const TransportMappingResult* udp = nullptr;
    for (std::size_t i = 0; i < data.mapping_count; ++i) {
        const TransportMappingResult& mapping = data.mappings[i];
        if (mapping.transport == Transport::Tcp) {
            if (tcp != nullptr)
                return false;
            tcp = &mapping;
        } else if (mapping.transport == Transport::Udp) {
            if (udp != nullptr)
                return false;
            udp = &mapping;
        } else {
            return false;
        }
    }
    if (tcp == nullptr ||
        tcp->local_endpoint.port == 0 ||
        tcp->local_endpoint.source != EndpointSource::LocalInterface ||
        tcp->requested_external_port == 0 ||
        tcp->granted_external_endpoint.port == 0 ||
        !IsCanonicalV4(
            tcp->granted_external_endpoint.address) ||
        !IdentityMatches(data.mapper, data.source,
                         tcp->granted_external_endpoint.source))
        return false;
    if (udp != nullptr &&
        (udp->local_endpoint.port == 0 ||
         udp->local_endpoint.source !=
             EndpointSource::LocalInterface ||
         udp->requested_external_port == 0 ||
         udp->granted_external_endpoint.port == 0 ||
         !SameAddress(udp->local_endpoint.address,
                      tcp->local_endpoint.address) ||
         !SameAddress(udp->granted_external_endpoint.address,
                      tcp->granted_external_endpoint.address) ||
         !IdentityMatches(data.mapper, data.source,
                          udp->granted_external_endpoint.source) ||
         udp->lifetime_seconds != tcp->lifetime_seconds))
        return false;

    LegacyMapperObservation projected{};
    projected.mapper = data.mapper;
    projected.mapper_source = data.source;
    projected.gateway_address = data.gateway.address;
    projected.external_address =
        tcp->granted_external_endpoint.address;
    projected.local_tcp_port = tcp->local_endpoint.port;
    projected.external_tcp_port =
        tcp->granted_external_endpoint.port;
    if (udp != nullptr) {
        projected.local_udp_port = udp->local_endpoint.port;
        projected.external_udp_port =
            udp->granted_external_endpoint.port;
    }
    projected.lifetime_seconds = tcp->lifetime_seconds;
    projected.mapper_epoch = data.mapper_epoch;
    projected.topology_generation =
        data.topology_generation;
    projected.mapper_epoch_reset = data.mapper_epoch_reset;
    projected.refresh =
        data.operation == MappingOperation::Refresh;
    observation = projected;
    return true;
}

LegacyMapperAdmissionStatus AdmitLegacyMapperObservation(
    const MapperResult& result,
    std::uint64_t expected_topology_generation,
    LegacyMapperObservation& observation) noexcept {
    if (!result.IsStructurallyValid())
        return LegacyMapperAdmissionStatus::InvalidResult;
    if (!result.IsCurrent(expected_topology_generation))
        return LegacyMapperAdmissionStatus::StaleGeneration;

    LegacyMapperObservation candidate{};
    if (!ProjectLegacyMapperObservation(result, candidate))
        return LegacyMapperAdmissionStatus::UnsupportedResult;
    if (IsUnroutableExternalV4(candidate.external_address))
        return LegacyMapperAdmissionStatus::UnroutableEndpoint;

    observation = candidate;
    return LegacyMapperAdmissionStatus::Accepted;
}

bool LegacyObservationAllowsSilentRenewal(
    const LegacyMapperObservation& observation) noexcept {
    return observation.refresh && !observation.mapper_epoch_reset;
}

bool BuildMapperTopologyIdentity(
    const LegacyMapperObservation& observation,
    MapperTopologyIdentity& identity) noexcept {
    MapperTopologyIdentity candidate{};
    candidate.mapper = observation.mapper;
    candidate.mapper_source = observation.mapper_source;
    candidate.gateway_address = observation.gateway_address;
    candidate.external_address = observation.external_address;
    candidate.local_tcp_port = observation.local_tcp_port;
    candidate.external_tcp_port =
        observation.external_tcp_port;
    candidate.local_udp_port = observation.local_udp_port;
    candidate.external_udp_port =
        observation.external_udp_port;
    if (!candidate.IsValid())
        return false;
    identity = candidate;
    return true;
}

TopologyGenerationDecision ResolveTopologyGeneration(
    std::uint64_t current_generation,
    const MapperTopologyIdentity& current_identity,
    const LegacyMapperObservation& observation) noexcept {
    TopologyGenerationDecision decision{};
    MapperTopologyIdentity candidate{};
    if (current_generation == 0 ||
        observation.topology_generation == 0 ||
        !BuildMapperTopologyIdentity(observation, candidate))
        return decision;
    if (observation.topology_generation != current_generation) {
        decision.disposition =
            TopologyGenerationDisposition::RejectStale;
        decision.generation = current_generation;
        return decision;
    }
    if (LegacyObservationAllowsSilentRenewal(observation) &&
        current_identity.IsValid() &&
        SameTopologyIdentity(current_identity, candidate)) {
        decision.disposition =
            TopologyGenerationDisposition::Keep;
        decision.generation = current_generation;
        return decision;
    }
    const std::uint64_t maximum =
        (std::numeric_limits<std::uint64_t>::max)();
    if (current_generation == maximum) {
        decision.disposition =
            TopologyGenerationDisposition::RejectOverflow;
        decision.generation = current_generation;
        return decision;
    }
    decision.disposition =
        TopologyGenerationDisposition::Advance;
    decision.generation = current_generation + 1;
    return decision;
}

TopologyGenerationDecision ResolveMapperRejectionGeneration(
    std::uint64_t current_generation,
    std::uint64_t expected_generation) noexcept {
    TopologyGenerationDecision decision{};
    if (expected_generation == 0 || current_generation == 0)
        return decision;
    const std::uint64_t maximum =
        (std::numeric_limits<std::uint64_t>::max)();
    if (expected_generation == maximum) {
        decision.disposition = current_generation == expected_generation
            ? TopologyGenerationDisposition::RejectOverflow
            : TopologyGenerationDisposition::RejectStale;
        decision.generation = current_generation;
        return decision;
    }
    const std::uint64_t rejected_generation = expected_generation + 1;
    if (current_generation == expected_generation) {
        decision.disposition = TopologyGenerationDisposition::Advance;
        decision.generation = rejected_generation;
        return decision;
    }
    if (current_generation == rejected_generation) {
        decision.disposition = TopologyGenerationDisposition::Keep;
        decision.generation = rejected_generation;
        return decision;
    }
    decision.disposition = TopologyGenerationDisposition::RejectStale;
    decision.generation = current_generation;
    return decision;
}

} // namespace natmap
