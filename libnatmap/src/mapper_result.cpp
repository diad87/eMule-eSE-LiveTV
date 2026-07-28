#include "natmap/mapper_result.h"

#include <algorithm>
#include <utility>

namespace natmap {
namespace {

template <std::size_t Size>
bool IsZero(const std::array<std::uint8_t, Size>& value) noexcept {
    return std::all_of(value.begin(), value.end(),
                       [](std::uint8_t byte) { return byte == 0; });
}

bool SourceMatchesMapper(MapperKind mapper, MapperSource source) noexcept {
    switch (mapper) {
    case MapperKind::UpnpIgd:
        return source == MapperSource::UpnpIgd;
    case MapperKind::Pcp:
        return source == MapperSource::PcpCpe ||
               source == MapperSource::PcpUpstream;
    case MapperKind::NatPmp:
        return source == MapperSource::NatPmp;
    default:
        return false;
    }
}

bool EndpointSourceMatchesMapper(MapperKind mapper,
                                 EndpointSource source) noexcept {
    switch (mapper) {
    case MapperKind::UpnpIgd:
        return source == EndpointSource::UpnpExternalAddress;
    case MapperKind::Pcp:
        return source == EndpointSource::PcpMap;
    case MapperKind::NatPmp:
        return source == EndpointSource::NatPmpPublicAddress;
    default:
        return false;
    }
}

bool StatusMatchesOperation(MappingOperation operation,
                            MappingStatus status) noexcept {
    switch (operation) {
    case MappingOperation::Initial:
        return status == MappingStatus::Created ||
               status == MappingStatus::Partial ||
               status == MappingStatus::Failed;
    case MappingOperation::Refresh:
        return status == MappingStatus::Renewed ||
               status == MappingStatus::Partial ||
               status == MappingStatus::Failed;
    case MappingOperation::Delete:
        return status == MappingStatus::Deleted ||
               status == MappingStatus::Failed;
    }
    return false;
}

bool IsKnownOwnership(OwnershipState ownership) noexcept {
    switch (ownership) {
    case OwnershipState::Unknown:
    case OwnershipState::OwnedByUs:
    case OwnershipState::Foreign:
    case OwnershipState::Unverifiable:
        return true;
    }
    return false;
}

bool IsKnownVerification(VerificationState verification) noexcept {
    switch (verification) {
    case VerificationState::NotAttempted:
    case VerificationState::Pending:
    case VerificationState::Verified:
    case VerificationState::Failed:
        return true;
    }
    return false;
}

bool IsKnownReason(ReasonCode reason) noexcept {
    return static_cast<std::uint16_t>(reason) <=
           static_cast<std::uint16_t>(
               ReasonCode::RouterRejectedAllCandidates);
}

bool HasOwnershipProof(const MapperResultData& data) noexcept {
    if (data.ownership != OwnershipState::OwnedByUs)
        return false;
    if (data.mapper == MapperKind::Pcp)
        return !IsZero(data.ownership_nonce);
    return IsZero(data.ownership_nonce) &&
           !IsZero(data.ownership_identity_digest);
}

bool HasAtomicPair(const MapperResultData& data) noexcept {
    if (data.mapping_count != 2)
        return false;
    return data.mappings[0].transport != data.mappings[1].transport &&
           ((data.mappings[0].transport == Transport::Tcp &&
             data.mappings[1].transport == Transport::Udp) ||
            (data.mappings[0].transport == Transport::Udp &&
             data.mappings[1].transport == Transport::Tcp));
}

bool IsCanonicalAddress(const IpAddress& address) noexcept {
    if (address.family == AddressFamily::IPv4) {
        return std::all_of(
            address.bytes.begin() + 4, address.bytes.end(),
            [](std::uint8_t byte) { return byte == 0; });
    }
    return address.family == AddressFamily::IPv6;
}

bool IsConcreteEndpoint(const Endpoint& endpoint) noexcept {
    return endpoint.IsUsable() &&
           !endpoint.address.IsUnspecified() &&
           IsCanonicalAddress(endpoint.address);
}

bool IsCanonicalEmptyEndpoint(const Endpoint& endpoint) noexcept {
    return endpoint.address.family == AddressFamily::Unspecified &&
           IsZero(endpoint.address.bytes) &&
           endpoint.port == 0 &&
           endpoint.source == EndpointSource::None;
}

bool IsPublicEndpoint(const Endpoint& endpoint) noexcept {
    return IsConcreteEndpoint(endpoint) &&
           !endpoint.address.IsPrivateOrSharedV4();
}

} // namespace

bool TransportMappingResult::IsStructurallyValid(
    MapperKind mapper) const noexcept {
    if ((transport != Transport::Tcp && transport != Transport::Udp) ||
        !IsConcreteEndpoint(local_endpoint) ||
        local_endpoint.source != EndpointSource::LocalInterface ||
        !IsConcreteEndpoint(granted_external_endpoint) ||
        !EndpointSourceMatchesMapper(
            mapper, granted_external_endpoint.source))
        return false;
    if (lifetime_seconds == 0)
        return mapper == MapperKind::UpnpIgd &&
               effective_expiry_monotonic_ms == 0;
    const std::uint64_t minimumExpiry =
        static_cast<std::uint64_t>(lifetime_seconds) * 1000u;
    return effective_expiry_monotonic_ms >= minimumExpiry;
}

bool TransportMappingResult::IsEmpty() const noexcept {
    return transport == Transport::Tcp &&
           IsCanonicalEmptyEndpoint(local_endpoint) &&
           requested_external_port == 0 &&
           IsCanonicalEmptyEndpoint(granted_external_endpoint) &&
           lifetime_seconds == 0 &&
           effective_expiry_monotonic_ms == 0;
}

MapperResult::MapperResult(MapperResultData data) noexcept
    : data_(std::move(data)) {
}

bool MapperResult::IsStructurallyValid() const noexcept {
    if (!SourceMatchesMapper(data_.mapper, data_.source) ||
        !IsConcreteEndpoint(data_.gateway) ||
        data_.gateway.source != EndpointSource::LocalInterface ||
        data_.request_id == 0 ||
        data_.generation == 0 ||
        data_.mapping_count > data_.mappings.size() ||
        !IsKnownOwnership(data_.ownership) ||
        !IsKnownVerification(data_.verification) ||
        !IsKnownReason(data_.reason) ||
        !StatusMatchesOperation(data_.operation, data_.status))
        return false;

    for (std::size_t i = 0; i < data_.mappings.size(); ++i) {
        if (i < data_.mapping_count) {
            if (!data_.mappings[i].IsStructurallyValid(data_.mapper))
                return false;
        } else if (!data_.mappings[i].IsEmpty()) {
            return false;
        }
    }
    if (data_.mapping_count == 2 &&
        data_.mappings[0].transport == data_.mappings[1].transport)
        return false;

    const bool mapped = data_.status == MappingStatus::Created ||
                        data_.status == MappingStatus::Renewed;
    const bool partial = data_.status == MappingStatus::Partial;
    const bool deleted = data_.status == MappingStatus::Deleted;
    const bool failed = data_.status == MappingStatus::Failed;

    if (mapped && !HasAtomicPair(data_))
        return false;
    if (partial && (data_.mapping_count != 1 ||
                    data_.verification != VerificationState::Failed))
        return false;
    if ((deleted || failed) && data_.mapping_count != 0)
        return false;
    if (failed && data_.verification != VerificationState::NotAttempted &&
        data_.verification != VerificationState::Failed)
        return false;
    if ((mapped || partial || deleted) && !HasOwnershipProof(data_))
        return false;
    if (failed && data_.ownership == OwnershipState::OwnedByUs &&
        !HasOwnershipProof(data_))
        return false;
    if (data_.ownership != OwnershipState::OwnedByUs &&
        (!IsZero(data_.ownership_nonce) ||
         !IsZero(data_.ownership_identity_digest)))
        return false;

    if (data_.mapper == MapperKind::UpnpIgd && data_.mapper_epoch != 0)
        return false;
    if (mapped || deleted) {
        if (data_.protocol_result_code != 0)
            return false;
    }

    const bool hasEvidence = !IsZero(data_.evidence_digest);
    if (data_.verification == VerificationState::Verified) {
        if (!hasEvidence || !mapped || data_.reason != ReasonCode::None ||
            !IsPublicEndpoint(
                data_.mappings[0].granted_external_endpoint) ||
            !IsPublicEndpoint(
                data_.mappings[1].granted_external_endpoint))
            return false;
    } else if (data_.verification == VerificationState::Pending ||
               data_.verification == VerificationState::NotAttempted) {
        if (hasEvidence)
            return false;
    } else if (data_.verification == VerificationState::Failed &&
               data_.reason == ReasonCode::None) {
        return false;
    }

    if ((partial || failed) && data_.reason == ReasonCode::None)
        return false;
    if (deleted && (data_.reason != ReasonCode::None ||
                    data_.verification !=
                        VerificationState::NotAttempted))
        return false;
    if (mapped && data_.verification != VerificationState::Failed &&
        data_.reason != ReasonCode::None)
        return false;

    return true;
}

bool MapperResult::IsCurrent(
    std::uint64_t expected_generation) const noexcept {
    return expected_generation != 0 &&
           data_.generation == expected_generation;
}

bool MapperResult::IsPublishable(
    std::uint64_t expected_generation) const noexcept {
    if (!IsStructurallyValid() ||
        !IsCurrent(expected_generation) ||
        (data_.status != MappingStatus::Created &&
         data_.status != MappingStatus::Renewed) ||
        data_.verification != VerificationState::Verified ||
        data_.reason != ReasonCode::None ||
        !HasAtomicPair(data_))
        return false;

    return IsPublicEndpoint(
               data_.mappings[0].granted_external_endpoint) &&
           IsPublicEndpoint(
               data_.mappings[1].granted_external_endpoint);
}

} // namespace natmap
