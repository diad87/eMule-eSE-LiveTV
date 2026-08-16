#include "natmap/legacy_mapper_projection.h"

#include <cstdio>
#include <limits>

using namespace natmap;

namespace {

int failures = 0;
int checks = 0;

#define CHECK(expr) do { ++checks; if (!(expr)) { ++failures; \
    std::printf("FAIL line %d: %s\n", __LINE__, #expr); } } while (0)

Endpoint Ep(std::uint8_t a, std::uint8_t b, std::uint8_t c,
            std::uint8_t d, std::uint16_t port,
            EndpointSource source) {
    return Endpoint{IpAddress::V4(a, b, c, d), port, source};
}

bool SameAddress(const IpAddress& left, const IpAddress& right) {
    return left.family == right.family && left.bytes == right.bytes;
}

MapperResultData LegacySuccess(MappingOperation operation) {
    MapperResultData data{};
    data.mapper = MapperKind::Pcp;
    data.source = MapperSource::PcpCpe;
    data.gateway.address = IpAddress::V4(192, 168, 68, 1);
    data.gateway.port = 5351;
    data.gateway.source = EndpointSource::LocalInterface;
    data.mapping_count = 2;
    data.mappings[0].transport = Transport::Tcp;
    data.mappings[0].local_endpoint =
        Ep(192, 168, 68, 54, 4662, EndpointSource::LocalInterface);
    data.mappings[0].requested_external_port = 4662;
    data.mappings[0].granted_external_endpoint =
        Ep(88, 11, 22, 4, 52144, EndpointSource::PcpMap);
    data.mappings[0].lifetime_seconds = 3600;
    data.mappings[0].effective_expiry_monotonic_ms = 3601000;
    data.mappings[1].transport = Transport::Udp;
    data.mappings[1].local_endpoint =
        Ep(192, 168, 68, 54, 4672, EndpointSource::LocalInterface);
    data.mappings[1].requested_external_port = 4672;
    data.mappings[1].granted_external_endpoint =
        Ep(88, 11, 22, 4, 52145, EndpointSource::PcpMap);
    data.mappings[1].lifetime_seconds = 3600;
    data.mappings[1].effective_expiry_monotonic_ms = 3601000;
    data.mapper_epoch = 17;
    data.ownership = OwnershipState::OwnedByUs;
    data.ownership_nonce[0] = 1;
    data.verification = VerificationState::Pending;
    data.request_id = 9;
    data.request_interface_index = 7;
    data.request_local_address = IpAddress::V4(192, 168, 68, 54);
    data.topology_generation = 4;
    data.operation = operation;
    data.status = operation == MappingOperation::Refresh
        ? MappingStatus::Renewed : MappingStatus::Created;
    return data;
}

void SetExternalAddress(MapperResultData& data,
                        const IpAddress& address) {
    for (std::size_t i = 0; i < data.mapping_count; ++i)
        data.mappings[i].granted_external_endpoint.address = address;
}

void TestProjectsExactLegacyValues() {
    const MapperResult result(LegacySuccess(MappingOperation::Initial));
    LegacyMapperObservation observation{};
    CHECK(ProjectLegacyMapperObservation(result, observation));
    CHECK(observation.mapper == MapperKind::Pcp);
    CHECK(observation.mapper_source == MapperSource::PcpCpe);
    CHECK(SameAddress(observation.gateway_address,
                      IpAddress::V4(192, 168, 68, 1)));
    CHECK(SameAddress(observation.external_address,
                      IpAddress::V4(88, 11, 22, 4)));
    CHECK(observation.local_tcp_port == 4662);
    CHECK(observation.external_tcp_port == 52144);
    CHECK(observation.local_udp_port == 4672);
    CHECK(observation.external_udp_port == 52145);
    CHECK(observation.lifetime_seconds == 3600);
    CHECK(observation.mapper_epoch == 17);
    CHECK(observation.topology_generation == 4);
    CHECK(!observation.refresh);
    CHECK(!LegacyObservationAllowsSilentRenewal(observation));
}

void TestRefreshOnlyChangesLegacyRefreshFlag() {
    MapperResultData data = LegacySuccess(MappingOperation::Refresh);
    data.mapper = MapperKind::NatPmp;
    data.source = MapperSource::NatPmp;
    data.mappings[0].granted_external_endpoint.source =
        EndpointSource::NatPmpPublicAddress;
    data.mappings[1].granted_external_endpoint.source =
        EndpointSource::NatPmpPublicAddress;
    data.mapper_epoch_reset = true;
    const MapperResult result(data);
    LegacyMapperObservation observation{};
    CHECK(ProjectLegacyMapperObservation(result, observation));
    CHECK(observation.refresh);
    CHECK(observation.mapper_epoch_reset);
    CHECK(!LegacyObservationAllowsSilentRenewal(observation));
    CHECK(observation.external_tcp_port == 52144);

    data.mapper_epoch_reset = false;
    CHECK(ProjectLegacyMapperObservation(
        MapperResult(data), observation));
    CHECK(LegacyObservationAllowsSilentRenewal(observation));
}

void TestProjectionFailsClosedWithoutMutatingOutput() {
    LegacyMapperObservation sentinel{};
    sentinel.mapper = MapperKind::NatPmp;
    sentinel.local_tcp_port = 1234;

    MapperResultData bad = LegacySuccess(MappingOperation::Initial);
    bad.status = MappingStatus::Failed;
    CHECK(!ProjectLegacyMapperObservation(MapperResult(bad), sentinel));
    CHECK(sentinel.mapper == MapperKind::NatPmp);
    CHECK(sentinel.local_tcp_port == 1234);

    bad = LegacySuccess(MappingOperation::Initial);
    bad.mapping_count = 1;
    bad.mappings[0].transport = Transport::Udp;
    CHECK(!ProjectLegacyMapperObservation(MapperResult(bad), sentinel));

    bad = LegacySuccess(MappingOperation::Initial);
    bad.mappings[1].granted_external_endpoint.address =
        IpAddress::V4(88, 11, 22, 5);
    CHECK(!ProjectLegacyMapperObservation(MapperResult(bad), sentinel));

    bad = LegacySuccess(MappingOperation::Initial);
    bad.operation = MappingOperation::Delete;
    bad.status = MappingStatus::Deleted;
    CHECK(!ProjectLegacyMapperObservation(MapperResult(bad), sentinel));

    bad = LegacySuccess(MappingOperation::Initial);
    bad.source = MapperSource::NatPmp;
    CHECK(!ProjectLegacyMapperObservation(MapperResult(bad), sentinel));

    bad = LegacySuccess(MappingOperation::Initial);
    bad.mappings[0].granted_external_endpoint.source =
        EndpointSource::NatPmpPublicAddress;
    CHECK(!ProjectLegacyMapperObservation(MapperResult(bad), sentinel));

    bad = LegacySuccess(MappingOperation::Initial);
    bad.mappings[1].lifetime_seconds = 60;
    CHECK(!ProjectLegacyMapperObservation(MapperResult(bad), sentinel));

    bad = LegacySuccess(MappingOperation::Initial);
    bad.request_id = 0;
    CHECK(!ProjectLegacyMapperObservation(MapperResult(bad), sentinel));

    bad = LegacySuccess(MappingOperation::Initial);
    bad.mappings[1].granted_external_endpoint.port = 0;
    CHECK(!ProjectLegacyMapperObservation(MapperResult(bad), sentinel));

    bad = LegacySuccess(MappingOperation::Initial);
    bad.gateway.address = {};
    CHECK(!ProjectLegacyMapperObservation(MapperResult(bad), sentinel));

    bad = LegacySuccess(MappingOperation::Initial);
    bad.gateway.source = EndpointSource::PcpMap;
    CHECK(!ProjectLegacyMapperObservation(MapperResult(bad), sentinel));
}

void TestTcpOnlyPreservesLegacyOptionalUdp() {
    MapperResultData data = LegacySuccess(MappingOperation::Initial);
    data.mapping_count = 1;
    data.mappings[1] = {};
    const MapperResult result(data);
    LegacyMapperObservation observation{};
    CHECK(ProjectLegacyMapperObservation(result, observation));
    CHECK(observation.local_tcp_port == 4662);
    CHECK(observation.local_udp_port == 0);
    CHECK(observation.external_udp_port == 0);
}

void TestProductMapperResultsRequireGatewayAndOwnership() {
    LegacyMapperObservation observation{};
    MapperResultData pcp = LegacySuccess(MappingOperation::Initial);
    CHECK(AdmitLegacyMapperObservation(
              MapperResult(pcp), 4, observation) ==
          LegacyMapperAdmissionStatus::Accepted);

    MapperResultData hostile = pcp;
    hostile.gateway.port = 0;
    CHECK(AdmitLegacyMapperObservation(
              MapperResult(hostile), 4, observation) ==
          LegacyMapperAdmissionStatus::InvalidResult);

    hostile = pcp;
    hostile.ownership = OwnershipState::Unverifiable;
    hostile.ownership_nonce.fill(0);
    CHECK(AdmitLegacyMapperObservation(
              MapperResult(hostile), 4, observation) ==
          LegacyMapperAdmissionStatus::InvalidResult);

    hostile = pcp;
    hostile.ownership_nonce.fill(0);
    CHECK(AdmitLegacyMapperObservation(
              MapperResult(hostile), 4, observation) ==
          LegacyMapperAdmissionStatus::InvalidResult);

    MapperResultData natpmp = pcp;
    natpmp.mapper = MapperKind::NatPmp;
    natpmp.source = MapperSource::NatPmp;
    natpmp.mappings[0].granted_external_endpoint.source =
        EndpointSource::NatPmpPublicAddress;
    natpmp.mappings[1].granted_external_endpoint.source =
        EndpointSource::NatPmpPublicAddress;
    natpmp.ownership_nonce.fill(0);
    natpmp.ownership_identity_digest[0] = 1;
    CHECK(AdmitLegacyMapperObservation(
              MapperResult(natpmp), 4, observation) ==
          LegacyMapperAdmissionStatus::Accepted);

    hostile = natpmp;
    hostile.gateway.port = 0;
    CHECK(AdmitLegacyMapperObservation(
              MapperResult(hostile), 4, observation) ==
          LegacyMapperAdmissionStatus::InvalidResult);

    hostile = natpmp;
    hostile.ownership_identity_digest.fill(0);
    CHECK(AdmitLegacyMapperObservation(
              MapperResult(hostile), 4, observation) ==
          LegacyMapperAdmissionStatus::InvalidResult);
}

void TestAdmissionRejectsEveryNonPublishableExternalClass() {
    const IpAddress rejected[] = {
        IpAddress::V4(127, 0, 0, 1),
        IpAddress::V4(169, 254, 1, 1),
        IpAddress::V4(192, 0, 2, 1),
        IpAddress::V4(198, 51, 100, 1),
        IpAddress::V4(203, 0, 113, 1),
        IpAddress::V4(224, 0, 0, 1),
        IpAddress::V4(240, 0, 0, 1),
        IpAddress::V4(255, 255, 255, 255),
    };
    for (const IpAddress& address : rejected) {
        MapperResultData data =
            LegacySuccess(MappingOperation::Initial);
        SetExternalAddress(data, address);
        LegacyMapperObservation sentinel{};
        sentinel.local_tcp_port = 1234;
        CHECK(AdmitLegacyMapperObservation(
                  MapperResult(data), 4, sentinel) ==
              LegacyMapperAdmissionStatus::UnroutableEndpoint);
        CHECK(sentinel.local_tcp_port == 1234);
    }

    MapperResultData unspecified =
        LegacySuccess(MappingOperation::Initial);
    SetExternalAddress(unspecified, IpAddress::V4(0, 0, 0, 0));
    LegacyMapperObservation sentinel{};
    CHECK(AdmitLegacyMapperObservation(
              MapperResult(unspecified), 4, sentinel) ==
          LegacyMapperAdmissionStatus::InvalidResult);

    MapperResultData noncanonical =
        LegacySuccess(MappingOperation::Initial);
    IpAddress malformed = IpAddress::V4(88, 11, 22, 4);
    malformed.bytes[4] = 1;
    SetExternalAddress(noncanonical, malformed);
    CHECK(AdmitLegacyMapperObservation(
              MapperResult(noncanonical), 4, sentinel) ==
          LegacyMapperAdmissionStatus::InvalidResult);

    const IpAddress allowed[] = {
        IpAddress::V4(88, 11, 22, 4),
        IpAddress::V4(192, 168, 1, 77),
        IpAddress::V4(100, 69, 24, 30),
    };
    for (const IpAddress& address : allowed) {
        MapperResultData data =
            LegacySuccess(MappingOperation::Initial);
        SetExternalAddress(data, address);
        CHECK(AdmitLegacyMapperObservation(
                  MapperResult(data), 4, sentinel) ==
              LegacyMapperAdmissionStatus::Accepted);
    }
}

void TestTopologyGenerationRules() {
    LegacyMapperObservation current{};
    CHECK(ProjectLegacyMapperObservation(
        MapperResult(LegacySuccess(MappingOperation::Initial)),
        current));
    MapperTopologyIdentity identity{};
    CHECK(BuildMapperTopologyIdentity(current, identity));
    CHECK(identity.IsValid());

    LegacyMapperObservation renewal = current;
    renewal.refresh = true;
    TopologyGenerationDecision decision =
        ResolveTopologyGeneration(4, identity, renewal);
    CHECK(decision.disposition ==
          TopologyGenerationDisposition::Keep);
    CHECK(decision.generation == 4);

    LegacyMapperObservation changed = renewal;
    changed.external_tcp_port = 52146;
    decision = ResolveTopologyGeneration(4, identity, changed);
    CHECK(decision.disposition ==
          TopologyGenerationDisposition::Advance);
    CHECK(decision.generation == 5);

    changed = renewal;
    changed.local_tcp_port = 4663;
    CHECK(ResolveTopologyGeneration(4, identity, changed).disposition ==
          TopologyGenerationDisposition::Advance);

    changed = renewal;
    changed.local_udp_port = 0;
    changed.external_udp_port = 0;
    CHECK(ResolveTopologyGeneration(4, identity, changed).disposition ==
          TopologyGenerationDisposition::Advance);

    changed = renewal;
    changed.external_address = IpAddress::V4(88, 11, 22, 5);
    CHECK(ResolveTopologyGeneration(4, identity, changed).disposition ==
          TopologyGenerationDisposition::Advance);

    changed = renewal;
    changed.mapper = MapperKind::NatPmp;
    changed.mapper_source = MapperSource::NatPmp;
    CHECK(ResolveTopologyGeneration(4, identity, changed).disposition ==
          TopologyGenerationDisposition::Advance);

    changed = renewal;
    changed.mapper_source = MapperSource::PcpUpstream;
    CHECK(ResolveTopologyGeneration(4, identity, changed).disposition ==
          TopologyGenerationDisposition::Advance);

    changed = renewal;
    changed.gateway_address = IpAddress::V4(192, 168, 68, 254);
    CHECK(ResolveTopologyGeneration(4, identity, changed).disposition ==
          TopologyGenerationDisposition::Advance);

    changed = renewal;
    changed.mapper_epoch_reset = true;
    CHECK(ResolveTopologyGeneration(4, identity, changed).disposition ==
          TopologyGenerationDisposition::Advance);

    changed = renewal;
    changed.topology_generation = 3;
    decision = ResolveTopologyGeneration(4, identity, changed);
    CHECK(decision.disposition ==
          TopologyGenerationDisposition::RejectStale);
    CHECK(decision.generation == 4);
}

void TestTopologyGenerationRejectsInvalidAndOverflow() {
    LegacyMapperObservation observation{};
    CHECK(ProjectLegacyMapperObservation(
        MapperResult(LegacySuccess(MappingOperation::Refresh)),
        observation));
    MapperTopologyIdentity identity{};
    CHECK(BuildMapperTopologyIdentity(observation, identity));

    LegacyMapperObservation invalid = observation;
    invalid.gateway_address = {};
    CHECK(ResolveTopologyGeneration(
              4, identity, invalid).disposition ==
          TopologyGenerationDisposition::RejectInvalid);

    const std::uint64_t maximum =
        (std::numeric_limits<std::uint64_t>::max)();
    observation.topology_generation = maximum;
    CHECK(ResolveTopologyGeneration(
              maximum, identity, observation).disposition ==
          TopologyGenerationDisposition::Keep);
    observation.mapper_epoch_reset = true;
    const TopologyGenerationDecision overflow =
        ResolveTopologyGeneration(maximum, identity, observation);
    CHECK(overflow.disposition ==
          TopologyGenerationDisposition::RejectOverflow);
    CHECK(overflow.generation == maximum);
}

void TestMapperRejectionGenerationIsAtomicAndIdempotent() {
    TopologyGenerationDecision decision =
        ResolveMapperRejectionGeneration(40, 40);
    CHECK(decision.disposition ==
          TopologyGenerationDisposition::Advance);
    CHECK(decision.generation == 41);

    // ObserveMappedPorts already advanced the snapshot before ApplyMapping
    // rejected. The compensating transition must not advance it again.
    decision = ResolveMapperRejectionGeneration(41, 40);
    CHECK(decision.disposition == TopologyGenerationDisposition::Keep);
    CHECK(decision.generation == 41);

    // Repeating the same rejection is harmless; unrelated generations are
    // fenced rather than overwritten.
    decision = ResolveMapperRejectionGeneration(41, 40);
    CHECK(decision.disposition == TopologyGenerationDisposition::Keep);
    CHECK(ResolveMapperRejectionGeneration(42, 40).disposition ==
          TopologyGenerationDisposition::RejectStale);
    CHECK(ResolveMapperRejectionGeneration(40, 41).disposition ==
          TopologyGenerationDisposition::RejectStale);
    const std::uint64_t maximum =
        (std::numeric_limits<std::uint64_t>::max)();
    CHECK(ResolveMapperRejectionGeneration(maximum, maximum).disposition ==
          TopologyGenerationDisposition::RejectOverflow);
    decision = ResolveMapperRejectionGeneration(40, maximum);
    CHECK(decision.disposition ==
          TopologyGenerationDisposition::RejectStale);
    CHECK(decision.generation == 40);
    decision = ResolveMapperRejectionGeneration(maximum, 40);
    CHECK(decision.disposition ==
          TopologyGenerationDisposition::RejectStale);
    CHECK(decision.generation == maximum);
}

} // namespace

int main() {
    TestProjectsExactLegacyValues();
    TestRefreshOnlyChangesLegacyRefreshFlag();
    TestProjectionFailsClosedWithoutMutatingOutput();
    TestTcpOnlyPreservesLegacyOptionalUdp();
    TestProductMapperResultsRequireGatewayAndOwnership();
    TestAdmissionRejectsEveryNonPublishableExternalClass();
    TestTopologyGenerationRules();
    TestTopologyGenerationRejectsInvalidAndOverflow();
    TestMapperRejectionGenerationIsAtomicAndIdempotent();
    std::printf(
        "test_legacy_mapper_projection: %d checks, %d failures\n",
        checks, failures);
    return failures == 0 ? 0 : 1;
}
