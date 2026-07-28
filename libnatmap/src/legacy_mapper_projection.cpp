#include "natmap/legacy_mapper_projection.h"

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

} // namespace

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
    projected.mapper_epoch_reset = data.mapper_epoch_reset;
    projected.refresh =
        data.operation == MappingOperation::Refresh;
    observation = projected;
    return true;
}

bool LegacyObservationAllowsSilentRenewal(
    const LegacyMapperObservation& observation) noexcept {
    return observation.refresh && !observation.mapper_epoch_reset;
}

} // namespace natmap
