#include "natmap/legacy_mapper_projection.h"

#include <cstdio>

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
    data.ownership = OwnershipState::Unverifiable;
    data.verification = VerificationState::Pending;
    data.request_id = 9;
    data.topology_generation = 4;
    data.operation = operation;
    data.status = operation == MappingOperation::Refresh
        ? MappingStatus::Renewed : MappingStatus::Created;
    return data;
}

void TestProjectsExactLegacyValues() {
    const MapperResult result(LegacySuccess(MappingOperation::Initial));
    LegacyMapperObservation observation{};
    CHECK(ProjectLegacyMapperObservation(result, observation));
    CHECK(observation.mapper == MapperKind::Pcp);
    CHECK(SameAddress(observation.external_address,
                      IpAddress::V4(88, 11, 22, 4)));
    CHECK(observation.local_tcp_port == 4662);
    CHECK(observation.external_tcp_port == 52144);
    CHECK(observation.local_udp_port == 4672);
    CHECK(observation.external_udp_port == 52145);
    CHECK(observation.lifetime_seconds == 3600);
    CHECK(observation.mapper_epoch == 17);
    CHECK(!observation.refresh);
}

void TestRefreshOnlyChangesLegacyRefreshFlag() {
    const MapperResult result(LegacySuccess(MappingOperation::Refresh));
    LegacyMapperObservation observation{};
    CHECK(ProjectLegacyMapperObservation(result, observation));
    CHECK(observation.refresh);
    CHECK(observation.external_tcp_port == 52144);
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

} // namespace

int main() {
    TestProjectsExactLegacyValues();
    TestRefreshOnlyChangesLegacyRefreshFlag();
    TestProjectionFailsClosedWithoutMutatingOutput();
    TestTcpOnlyPreservesLegacyOptionalUdp();
    std::printf(
        "test_legacy_mapper_projection: %d checks, %d failures\n",
        checks, failures);
    return failures == 0 ? 0 : 1;
}
