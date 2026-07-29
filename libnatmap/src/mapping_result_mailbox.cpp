#include "natmap/mapping_result_mailbox.h"

#include "natmap/mapping_request.h"
#include "natmap/pcp_codec.h"

#include <algorithm>

namespace natmap {
namespace {

bool SameAddress(const IpAddress& left, const IpAddress& right) noexcept {
    return left.family == right.family && left.bytes == right.bytes;
}

bool IsCanonicalRfc1918(const IpAddress& address) noexcept {
    return address.family == AddressFamily::IPv4 &&
        ClassifyAddress(address).address_class == AddressClass::Rfc1918;
}

const TransportMappingResult* FindMapping(
    const MapperResultData& data, Transport transport) noexcept {
    for (std::size_t i = 0; i < data.mapping_count; ++i)
        if (data.mappings[i].transport == transport)
            return &data.mappings[i];
    return nullptr;
}

bool HasExactLanRoute(const MapperResultData& data,
                      const MapperResultData& cpe) noexcept {
    return data.request_interface_index != 0 &&
        data.request_interface_index == cpe.request_interface_index &&
        SameAddress(data.request_local_address,
                    cpe.request_local_address);
}

bool IsCanonicalEmptyEvidence(
    const UpstreamDiscoveryInput& input) noexcept {
    if (input.evidence_count != 0 ||
        input.mapper_wan_address.family !=
            AddressFamily::Unspecified ||
        std::any_of(
            input.mapper_wan_address.bytes.begin(),
            input.mapper_wan_address.bytes.end(),
            [](std::uint8_t byte) { return byte != 0; }) ||
        input.mapper_origin != NetworkOrigin::Unknown ||
        input.interface_index != 0)
        return false;
    for (const UpstreamGatewayEvidence& evidence :
         input.evidence)
        if (evidence.address.family !=
                AddressFamily::Unspecified ||
            std::any_of(
                evidence.address.bytes.begin(),
                evidence.address.bytes.end(),
                [](std::uint8_t byte) {
                    return byte != 0;
                }) ||
            evidence.interface_index != 0 ||
            evidence.source != GatewayCandidateSource::None ||
            evidence.interface_present)
            return false;
    return true;
}

bool IsKnownPcpResultCode(std::uint32_t code) noexcept {
    return code <= static_cast<std::uint32_t>(
        PcpResultCode::ExcessiveRemotePeers);
}

bool IsOperatorDenialPcpResultCode(std::uint32_t code) noexcept {
    return code == static_cast<std::uint32_t>(
            PcpResultCode::NotAuthorized) ||
        code == static_cast<std::uint32_t>(
            PcpResultCode::UserExceededQuota);
}

bool IsTransportFailurePcpResultCode(std::uint32_t code) noexcept {
    return IsKnownPcpResultCode(code) &&
        code != static_cast<std::uint32_t>(PcpResultCode::Success) &&
        !IsOperatorDenialPcpResultCode(code);
}

} // namespace

bool PcpUpstreamResultBundle::IsValid() const noexcept {
    const MappingRequestContext cpeEnvelope{
        cpe.request_id, cpe.topology_generation, cpe.operation};
    const MappingRequestContext upstreamEnvelope{
        upstream.request_id, upstream.topology_generation, upstream.operation};
    if (!cpeEnvelope.IsValid() || !upstreamEnvelope.IsValid() ||
        authorized_evidence.evidence_count >
            authorized_evidence.evidence.size())
        return false;
    if (!(cpeEnvelope.request_id == upstreamEnvelope.request_id &&
        cpeEnvelope.topology_generation == upstreamEnvelope.topology_generation &&
        cpeEnvelope.operation == upstreamEnvelope.operation &&
        cpe.mapper == MapperKind::Pcp && cpe.source == MapperSource::PcpCpe &&
        upstream.mapper == MapperKind::Pcp && upstream.source == MapperSource::PcpUpstream &&
        cpe.ownership == OwnershipState::OwnedByUs &&
        MapperResult(cpe).IsStructurallyValid() &&
        MapperResult(upstream).IsStructurallyValid() &&
        HasExactLanRoute(upstream, cpe) &&
        IsCanonicalRfc1918(cpe.request_local_address) &&
        IsCanonicalRfc1918(cpe.gateway.address) &&
        cpe.gateway.port == 5351))
        return false;

    const TransportMappingResult* cpeTcp = nullptr;
    const TransportMappingResult* cpeUdp = nullptr;
    cpeTcp = FindMapping(cpe, Transport::Tcp);
    cpeUdp = FindMapping(cpe, Transport::Udp);
    if (cpeTcp == nullptr || cpeUdp == nullptr ||
        !SameAddress(cpeTcp->local_endpoint.address,
                     cpe.request_local_address) ||
        !SameAddress(cpeUdp->local_endpoint.address,
                     cpe.request_local_address) ||
        !IsCanonicalRfc1918(
            cpeTcp->granted_external_endpoint.address) ||
        !SameAddress(cpeTcp->granted_external_endpoint.address,
                     cpeUdp->granted_external_endpoint.address) ||
        !SameAddress(pcp_client_address,
                     cpeTcp->granted_external_endpoint.address))
        return false;

    if (outcome == Outcome::Absent) {
        return IsCanonicalEmptyEvidence(authorized_evidence) &&
            upstream.mapping_count == 0 &&
            upstream.ownership != OwnershipState::OwnedByUs &&
            upstream.status == MappingStatus::Failed &&
            upstream.verification == VerificationState::Failed &&
            upstream.protocol_result_code == static_cast<std::uint32_t>(
                PcpResultCode::Success) &&
            upstream.reason == ReasonCode::NoGateway &&
            upstream.gateway.SameSocketEndpoint(cpe.gateway);
    }

    if (authorized_evidence.evidence_count != 1)
        return false;
    const UpstreamGatewayEvidence& evidence =
        authorized_evidence.evidence[0];
    if (!evidence.interface_present ||
        evidence.source !=
            GatewayCandidateSource::ExplicitConfiguration ||
        evidence.interface_index == 0 ||
        evidence.interface_index != cpe.request_interface_index ||
        authorized_evidence.mapper_origin != NetworkOrigin::Native ||
        authorized_evidence.interface_index !=
            cpe.request_interface_index ||
        !SameAddress(authorized_evidence.mapper_wan_address,
                     pcp_client_address) ||
        !IsCanonicalRfc1918(evidence.address) ||
        !SameAddress(evidence.address, upstream.gateway.address) ||
        upstream.gateway.port != 5351)
        return false;

    if (outcome == Outcome::Denied ||
        outcome == Outcome::Failed) {
        return upstream.mapping_count == 0 &&
            upstream.ownership != OwnershipState::OwnedByUs &&
            upstream.status == MappingStatus::Failed &&
            upstream.verification == VerificationState::Failed &&
            (outcome != Outcome::Denied ||
                IsOperatorDenialPcpResultCode(
                    upstream.protocol_result_code)) &&
            (outcome != Outcome::Failed ||
                IsTransportFailurePcpResultCode(
                    upstream.protocol_result_code)) &&
            upstream.reason ==
                (outcome == Outcome::Denied
                    ? ReasonCode::OperatorDenied
                    : ReasonCode::NoRoute);
    }

    if (outcome != Outcome::Mapped ||
        upstream.ownership != OwnershipState::OwnedByUs ||
        upstream.reason != ReasonCode::None)
        return false;
    const TransportMappingResult* upstreamTcp =
        FindMapping(upstream, Transport::Tcp);
    const TransportMappingResult* upstreamUdp =
        FindMapping(upstream, Transport::Udp);
    return upstreamTcp && upstreamUdp &&
        upstreamTcp->local_endpoint.SameSocketEndpoint(cpeTcp->granted_external_endpoint) &&
        upstreamUdp->local_endpoint.SameSocketEndpoint(cpeUdp->granted_external_endpoint);
}

MappingResultMailbox::MappingResultMailbox(
    std::uint32_t first_delivery_id) noexcept
    : next_delivery_id_(first_delivery_id),
      exhausted_(first_delivery_id == 0 ||
                 first_delivery_id > kMaximumDeliveryId) {
}

MailboxPublish MappingResultMailbox::Publish(
    const MapperResultData& data) {
    const MappingRequestContext envelope{
        data.request_id, data.topology_generation, data.operation};
    if (!envelope.IsValid())
        return {MailboxPublishStatus::InvalidEnvelope, 0};

    std::lock_guard<std::mutex> lock(mutex_);
    if (closed_)
        return {MailboxPublishStatus::Closed, 0};
    if (exhausted_)
        return {MailboxPublishStatus::Exhausted, 0};
    if (entries_.size() >= kMaximumPending)
        return {MailboxPublishStatus::Full, 0};

    const std::uint32_t deliveryId = next_delivery_id_;
    entries_.push_back(Entry{deliveryId, data, PcpUpstreamResultBundle{}, false});
    if (next_delivery_id_ == kMaximumDeliveryId)
        exhausted_ = true;
    else
        ++next_delivery_id_;
    return {MailboxPublishStatus::Published, deliveryId};
}

MailboxPublish MappingResultMailbox::PublishPcpUpstreamBundle(
    const PcpUpstreamResultBundle& bundle) {
    if (!bundle.IsValid()) return {MailboxPublishStatus::InvalidEnvelope, 0};
    std::lock_guard<std::mutex> lock(mutex_);
    if (closed_) return {MailboxPublishStatus::Closed, 0};
    if (exhausted_) return {MailboxPublishStatus::Exhausted, 0};
    if (entries_.size() >= kMaximumPending) return {MailboxPublishStatus::Full, 0};
    const std::uint32_t deliveryId = next_delivery_id_;
    entries_.push_back(Entry{deliveryId, MapperResultData{}, bundle, true});
    if (next_delivery_id_ == kMaximumDeliveryId) exhausted_ = true; else ++next_delivery_id_;
    return {MailboxPublishStatus::Published, deliveryId};
}

bool MappingResultMailbox::Take(
    std::uint32_t delivery_id,
    MapperResultData& data) {
    if (delivery_id == 0 || delivery_id > kMaximumDeliveryId)
        return false;
    std::lock_guard<std::mutex> lock(mutex_);
    const std::deque<Entry>::iterator found = std::find_if(
        entries_.begin(), entries_.end(),
        [delivery_id](const Entry& entry) {
            return entry.delivery_id == delivery_id;
        });
    if (found == entries_.end())
        return false;
    // A consumer probing the wrong payload type must not consume another
    // consumer's correlated delivery.  The exact owner can still Take it.
    if (found->is_bundle)
        return false;
    data = found->data;
    entries_.erase(found);
    return true;
}

bool MappingResultMailbox::TakePcpUpstreamBundle(std::uint32_t delivery_id,
    PcpUpstreamResultBundle& bundle) {
    if (delivery_id == 0 || delivery_id > kMaximumDeliveryId) return false;
    std::lock_guard<std::mutex> lock(mutex_);
    const auto found = std::find_if(entries_.begin(), entries_.end(),
        [delivery_id](const Entry& entry) { return entry.delivery_id == delivery_id; });
    if (found == entries_.end() || !found->is_bundle) return false;
    bundle = found->bundle;
    entries_.erase(found);
    return true;
}

bool MappingResultMailbox::Discard(std::uint32_t delivery_id) {
    if (delivery_id == 0 || delivery_id > kMaximumDeliveryId) return false;
    std::lock_guard<std::mutex> lock(mutex_);
    const auto found = std::find_if(entries_.begin(), entries_.end(),
        [delivery_id](const Entry& entry) { return entry.delivery_id == delivery_id; });
    if (found == entries_.end()) return false;
    entries_.erase(found);
    return true;
}

void MappingResultMailbox::Clear() noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    entries_.clear();
}

bool MappingResultMailbox::Close() noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    entries_.clear();
    if (closed_)
        return false;
    closed_ = true;
    return true;
}

std::size_t MappingResultMailbox::pending_count() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return entries_.size();
}

} // namespace natmap
