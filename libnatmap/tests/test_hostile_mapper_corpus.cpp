#include "natmap/legacy_mapper_projection.h"
#include "natmap/mapping_result_mailbox.h"
#include "natmap/natpmp_epoch_policy.h"
#include "natmap/pcp_codec.h"
#include "natmap/pcp_map_projection.h"
#include "natmap/pcp_mapping_identity.h"
#include "natmap/pcp_response_guard.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <vector>

using namespace natmap;

namespace {

int checks = 0;
int failures = 0;

#define CHECK(expr) do { ++checks; if (!(expr)) { ++failures; \
    std::printf("FAIL line %d: %s\n", __LINE__, #expr); } } while (0)

void Put16(std::uint8_t* out, std::uint16_t value) {
    out[0] = static_cast<std::uint8_t>(value >> 8);
    out[1] = static_cast<std::uint8_t>(value);
}

void Put32(std::uint8_t* out, std::uint32_t value) {
    out[0] = static_cast<std::uint8_t>(value >> 24);
    out[1] = static_cast<std::uint8_t>(value >> 16);
    out[2] = static_cast<std::uint8_t>(value >> 8);
    out[3] = static_cast<std::uint8_t>(value);
}

PcpMapRequest Request() {
    PcpMapRequest request{};
    request.lifetime_seconds = 7200;
    request.client_ip = PcpIpv4Mapped(192, 168, 68, 54);
    for (std::size_t i = 0; i < request.nonce.size(); ++i)
        request.nonce[i] = static_cast<std::uint8_t>(i + 1);
    request.protocol = 6;
    request.internal_port = 4662;
    request.suggested_external_port = 4662;
    return request;
}

std::array<std::uint8_t, kPcpBaseMessageSize> Response(
    const PcpMapRequest& request) {
    std::array<std::uint8_t, kPcpBaseMessageSize> raw{};
    raw[0] = 2;
    raw[1] = 0x81;
    Put32(raw.data() + 4, 3600);
    Put32(raw.data() + 8, 1234);
    std::memcpy(raw.data() + 24, request.nonce.data(),
                request.nonce.size());
    raw[36] = request.protocol;
    Put16(raw.data() + 40, request.internal_port);
    Put16(raw.data() + 42, 52144);
    const auto external = PcpIpv4Mapped(88, 11, 22, 4);
    std::memcpy(raw.data() + 44, external.data(), external.size());
    return raw;
}

PcpMapResponse SentinelPcpResponse() {
    PcpMapResponse value{};
    value.result = PcpResultCode::NoResources;
    value.lifetime_seconds = 123;
    value.epoch = 456;
    value.nonce.fill(0xA5);
    value.protocol = 17;
    value.internal_port = 1111;
    value.external_port = 2222;
    value.external_ip.fill(0x5A);
    value.has_port_set = true;
    value.port_set_size = 32;
    value.first_internal_port = 1111;
    value.preserve_parity = true;
    return value;
}

bool SamePcpResponse(const PcpMapResponse& left,
                     const PcpMapResponse& right) {
    return left.result == right.result &&
           left.lifetime_seconds == right.lifetime_seconds &&
           left.epoch == right.epoch &&
           left.nonce == right.nonce &&
           left.protocol == right.protocol &&
           left.internal_port == right.internal_port &&
           left.external_port == right.external_port &&
           left.external_ip == right.external_ip &&
           left.has_port_set == right.has_port_set &&
           left.port_set_size == right.port_set_size &&
           left.first_internal_port == right.first_internal_port &&
           left.preserve_parity == right.preserve_parity;
}

Endpoint Ep(std::uint8_t a, std::uint8_t b, std::uint8_t c,
            std::uint8_t d, std::uint16_t port,
            EndpointSource source) {
    return Endpoint{IpAddress::V4(a, b, c, d), port, source};
}

MapperResultData ValidMapperResult(std::uint64_t generation = 7) {
    MapperResultData data{};
    data.mapper = MapperKind::Pcp;
    data.source = MapperSource::PcpCpe;
    data.gateway = Ep(192, 168, 68, 1, 5351,
                      EndpointSource::LocalInterface);
    data.request_id = 101;
    data.topology_generation = generation;
    data.operation = MappingOperation::Initial;
    data.status = MappingStatus::Created;
    data.mapping_count = 2;
    for (std::size_t i = 0; i < data.mapping_count; ++i) {
        TransportMappingResult& mapping = data.mappings[i];
        mapping.transport = i == 0 ? Transport::Tcp : Transport::Udp;
        mapping.local_endpoint = Ep(
            192, 168, 68, 54,
            static_cast<std::uint16_t>(i == 0 ? 4662 : 4672),
            EndpointSource::LocalInterface);
        mapping.requested_external_port =
            static_cast<std::uint16_t>(i == 0 ? 4662 : 4672);
        mapping.granted_external_endpoint = Ep(
            88, 11, 22, 4,
            static_cast<std::uint16_t>(i == 0 ? 52144 : 52145),
            EndpointSource::PcpMap);
        mapping.lifetime_seconds = 3600;
        mapping.effective_expiry_monotonic_ms = 3601000;
    }
    for (std::size_t i = 0; i < data.ownership_nonce.size(); ++i)
        data.ownership_nonce[i] = static_cast<std::uint8_t>(i + 1);
    data.ownership = OwnershipState::OwnedByUs;
    data.verification = VerificationState::Pending;
    return data;
}

LegacyMapperObservation SentinelObservation() {
    LegacyMapperObservation value{};
    value.mapper = MapperKind::NatPmp;
    value.mapper_source = MapperSource::NatPmp;
    value.gateway_address = IpAddress::V4(10, 0, 0, 1);
    value.external_address = IpAddress::V4(203, 0, 113, 9);
    value.local_tcp_port = 1111;
    value.external_tcp_port = 2222;
    value.local_udp_port = 3333;
    value.external_udp_port = 4444;
    value.lifetime_seconds = 55;
    value.mapper_epoch = 66;
    value.topology_generation = 77;
    value.mapper_epoch_reset = true;
    value.refresh = true;
    return value;
}

bool SameObservation(const LegacyMapperObservation& left,
                     const LegacyMapperObservation& right) {
    return left.mapper == right.mapper &&
           left.mapper_source == right.mapper_source &&
           left.gateway_address.family == right.gateway_address.family &&
           left.gateway_address.bytes == right.gateway_address.bytes &&
           left.external_address.family == right.external_address.family &&
           left.external_address.bytes == right.external_address.bytes &&
           left.local_tcp_port == right.local_tcp_port &&
           left.external_tcp_port == right.external_tcp_port &&
           left.local_udp_port == right.local_udp_port &&
           left.external_udp_port == right.external_udp_port &&
           left.lifetime_seconds == right.lifetime_seconds &&
           left.mapper_epoch == right.mapper_epoch &&
           left.topology_generation == right.topology_generation &&
           left.mapper_epoch_reset == right.mapper_epoch_reset &&
           left.refresh == right.refresh;
}

void TestEverySizeFromZeroThroughMaximumPlusOneFailsClosed() {
    const PcpMapRequest request = Request();
    std::vector<std::uint8_t> raw(kPcpMaximumMessageSize + 1, 0);
    for (std::size_t size = 0; size <= kPcpMaximumMessageSize + 1;
         ++size) {
        PcpMapResponse output = SentinelPcpResponse();
        const PcpMapResponse before = output;
        const PcpDecodeStatus status = DecodePcpMapResponse(
            size == 0 ? nullptr : raw.data(), size, request, output);
        CHECK(status != PcpDecodeStatus::Ok);
        CHECK(SamePcpResponse(output, before));
    }
}

void TestReservedFieldsAreIgnoredWithoutSemanticChange() {
    const PcpMapRequest request = Request();
    PcpMapResponse expected{};
    const auto baseline = Response(request);
    CHECK(DecodePcpMapResponse(
              baseline.data(), baseline.size(), request, expected) ==
          PcpDecodeStatus::Ok);
    auto raw = Response(request);
    raw[2] = 1;
    raw[12] = 2;
    raw[37] = 3;
    PcpMapResponse output{};
    CHECK(DecodePcpMapResponse(raw.data(), raw.size(), request, output) ==
          PcpDecodeStatus::Ok);
    CHECK(SamePcpResponse(output, expected));

    std::array<std::uint8_t, kPcpBaseMessageSize + 4> option_raw{};
    const auto base_response = Response(request);
    std::copy(base_response.begin(), base_response.end(), option_raw.begin());
    option_raw[kPcpBaseMessageSize] = 200;
    option_raw[kPcpBaseMessageSize + 1] = 1;
    output = {};
    CHECK(DecodePcpMapResponse(
              option_raw.data(), option_raw.size(), request, output) ==
          PcpDecodeStatus::Ok);
    CHECK(SamePcpResponse(output, expected));
}

void TestZeroExternalPortIsRejectedAtSemanticBoundary() {
    const PcpMapRequest request = Request();
    auto raw = Response(request);
    Put16(raw.data() + 42, 0);
    PcpMapResponse output{};
    CHECK(DecodePcpMapResponse(raw.data(), raw.size(), request, output) ==
          PcpDecodeStatus::Ok);
    PcpMappingIdentity identity{};
    CHECK(InitializePcpMappingIdentity(
              identity, Transport::Tcp, request.internal_port,
              request.nonce) == PcpIdentityStatus::Valid);
    const PcpMapProjectionResult projected =
        ProjectPcpMapResponse(
            identity, request.suggested_external_port, output);
    CHECK(projected.status ==
          PcpMapProjectionStatus::InvalidGrantedPort);
    CHECK(!projected.IsProjected());
}

void TestExtremeLifetimeIsBoundedWithoutOverflow() {
    const PcpMapRequest request = Request();
    auto raw = Response(request);
    Put32(raw.data() + 4, (std::numeric_limits<std::uint32_t>::max)());
    PcpMapResponse output{};
    CHECK(DecodePcpMapResponse(raw.data(), raw.size(), request, output) ==
          PcpDecodeStatus::Ok);
    CHECK(output.lifetime_seconds ==
          (std::numeric_limits<std::uint32_t>::max)());
    CHECK(PcpEffectiveLifetime(output.lifetime_seconds) == 86400);
    CHECK(PcpEffectiveLifetime(7200) == 7200);
}

void TestEpochWrapInvalidatesPriorSnapshotWithoutMutatingInput() {
    NatPmpEpochSequence sequence{};
    sequence.previous_snapshot = {
        true, true,
        (std::numeric_limits<std::uint32_t>::max)() - 1u, 100};
    sequence.tcp_map = {true, true, 1, 104};
    const NatPmpEpochSequence before = sequence;
    const NatPmpEpochDecision decision =
        EvaluateNatPmpEpochSequence(sequence);
    CHECK(decision.strongest_boundary ==
          NatPmpEpochBoundary::ResetBeforeTcpMap);
    CHECK(decision.previous_pair_invalidated);
    CHECK(!decision.pair_can_commit);
    CHECK(sequence.previous_snapshot.epoch ==
          before.previous_snapshot.epoch);
    CHECK(sequence.tcp_map.epoch == before.tcp_map.epoch);
}

void TestWrongNonceIsRejectedWithoutOutputMutation() {
    const PcpMapRequest request = Request();
    auto raw = Response(request);
    raw[24] ^= 1;
    PcpMapResponse output = SentinelPcpResponse();
    const PcpMapResponse before = output;
    CHECK(DecodePcpMapResponse(raw.data(), raw.size(), request, output) ==
          PcpDecodeStatus::WrongNonce);
    CHECK(SamePcpResponse(output, before));
}

void TestUnroutableAddressIsRejectedWithoutSnapshotMutation() {
    MapperResultData data = ValidMapperResult();
    for (std::size_t i = 0; i < data.mapping_count; ++i)
        data.mappings[i].granted_external_endpoint.address =
            IpAddress::V4(127, 0, 0, 1);
    LegacyMapperObservation output = SentinelObservation();
    const LegacyMapperObservation before = output;
    CHECK(AdmitLegacyMapperObservation(MapperResult(data), 7, output) ==
          LegacyMapperAdmissionStatus::UnroutableEndpoint);
    CHECK(SameObservation(output, before));
}

void TestWrongGatewayIsRejectedWithoutSnapshotMutation() {
    PcpResponseExpectation expected{};
    expected.source_address = {192, 168, 68, 1};
    expected.source_port = 5351;
    expected.request_id = 101;
    expected.nonce = Request().nonce;
    PcpResponseObservation observed{};
    observed.source_address = {192, 168, 68, 2};
    observed.source_port = expected.source_port;
    observed.active_request_id = expected.request_id;
    observed.nonce = expected.nonce;
    LegacyMapperObservation snapshot = SentinelObservation();
    const LegacyMapperObservation before = snapshot;
    CHECK(ValidatePcpResponseObservation(expected, observed) ==
          PcpResponseGuardStatus::WrongSource);
    CHECK(SameObservation(snapshot, before));
}

void TestDuplicateResponseCannotMutateDeliveryOutput() {
    MappingResultMailbox mailbox;
    MapperResultData data = ValidMapperResult();
    const MailboxPublish published = mailbox.Publish(data);
    CHECK(published.IsPublished());
    MapperResultData first{};
    CHECK(mailbox.Take(published.delivery_id, first));
    MapperResultData duplicate = ValidMapperResult(99);
    const MapperResultData before = duplicate;
    CHECK(!mailbox.Take(published.delivery_id, duplicate));
    CHECK(duplicate.request_id == before.request_id);
    CHECK(duplicate.topology_generation == before.topology_generation);
    CHECK(duplicate.mappings[0].granted_external_endpoint.port ==
          before.mappings[0].granted_external_endpoint.port);
}

void TestReplayAfterNewGenerationIsRejectedWithoutMutation() {
    LegacyMapperObservation output = SentinelObservation();
    const LegacyMapperObservation before = output;
    CHECK(AdmitLegacyMapperObservation(
              MapperResult(ValidMapperResult(7)), 8, output) ==
          LegacyMapperAdmissionStatus::StaleGeneration);
    CHECK(SameObservation(output, before));
}

void TestAdmissionReasonsAreDistinctAndNonMutating() {
    MapperResultData malformed = ValidMapperResult();
    malformed.request_id = 0;
    LegacyMapperObservation output = SentinelObservation();
    const LegacyMapperObservation before = output;
    CHECK(AdmitLegacyMapperObservation(
              MapperResult(malformed), 7, output) ==
          LegacyMapperAdmissionStatus::InvalidResult);
    CHECK(SameObservation(output, before));

    MapperResultData unsupported{};
    unsupported.mapper = MapperKind::Pcp;
    unsupported.source = MapperSource::PcpCpe;
    unsupported.gateway = Ep(192, 168, 68, 1, 5351,
                             EndpointSource::LocalInterface);
    unsupported.request_id = 202;
    unsupported.topology_generation = 7;
    unsupported.operation = MappingOperation::Initial;
    unsupported.status = MappingStatus::Failed;
    unsupported.verification = VerificationState::Failed;
    unsupported.reason = ReasonCode::MappingTimeout;
    CHECK(AdmitLegacyMapperObservation(
              MapperResult(unsupported), 7, output) ==
          LegacyMapperAdmissionStatus::UnsupportedResult);
    CHECK(SameObservation(output, before));
}

void TestValidControlCommitsOnlyAfterAdmission() {
    LegacyMapperObservation output = SentinelObservation();
    CHECK(AdmitLegacyMapperObservation(
              MapperResult(ValidMapperResult()), 7, output) ==
          LegacyMapperAdmissionStatus::Accepted);
    CHECK(output.mapper == MapperKind::Pcp);
    CHECK(output.external_tcp_port == 52144);
    CHECK(output.external_udp_port == 52145);
    CHECK(output.topology_generation == 7);
}

} // namespace

int main() {
    TestEverySizeFromZeroThroughMaximumPlusOneFailsClosed();
    TestReservedFieldsAreIgnoredWithoutSemanticChange();
    TestZeroExternalPortIsRejectedAtSemanticBoundary();
    TestExtremeLifetimeIsBoundedWithoutOverflow();
    TestEpochWrapInvalidatesPriorSnapshotWithoutMutatingInput();
    TestWrongNonceIsRejectedWithoutOutputMutation();
    TestUnroutableAddressIsRejectedWithoutSnapshotMutation();
    TestWrongGatewayIsRejectedWithoutSnapshotMutation();
    TestDuplicateResponseCannotMutateDeliveryOutput();
    TestReplayAfterNewGenerationIsRejectedWithoutMutation();
    TestAdmissionReasonsAreDistinctAndNonMutating();
    TestValidControlCommitsOnlyAfterAdmission();
    std::printf("hostile corpus L07: %d checks, %d failures\n",
                checks, failures);
    return failures == 0 ? 0 : 1;
}
