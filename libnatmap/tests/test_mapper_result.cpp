#include "natmap/mapper_result.h"

#include <cstdio>
#include <type_traits>
#include <utility>

using namespace natmap;

namespace {

int failures = 0;
int checks = 0;

#define CHECK(expr) do { ++checks; if (!(expr)) { ++failures; \
    std::printf("FAIL line %d: %s\n", __LINE__, #expr); } } while (0)

Endpoint Ep(std::uint8_t a, std::uint8_t b, std::uint8_t c,
            std::uint8_t d, std::uint16_t port,
            EndpointSource source = EndpointSource::LocalInterface) {
    return Endpoint{IpAddress::V4(a, b, c, d), port, source};
}

std::array<std::uint8_t, 12> Nonce(std::uint8_t seed) {
    std::array<std::uint8_t, 12> value{};
    for (std::size_t i = 0; i < value.size(); ++i)
        value[i] = static_cast<std::uint8_t>(seed + i);
    return value;
}

std::array<std::uint8_t, 32> Digest(std::uint8_t seed) {
    std::array<std::uint8_t, 32> value{};
    for (std::size_t i = 0; i < value.size(); ++i)
        value[i] = static_cast<std::uint8_t>(seed + i);
    return value;
}

IpAddress ZeroV6() {
    IpAddress value{};
    value.family = AddressFamily::IPv6;
    return value;
}

EndpointSource EndpointSourceFor(MapperKind mapper) {
    switch (mapper) {
    case MapperKind::UpnpIgd:
        return EndpointSource::UpnpExternalAddress;
    case MapperKind::Pcp:
        return EndpointSource::PcpMap;
    case MapperKind::NatPmp:
        return EndpointSource::NatPmpPublicAddress;
    default:
        return EndpointSource::None;
    }
}

TransportMappingResult Mapping(MapperKind mapper, Transport transport,
                               std::uint16_t local_port,
                               std::uint16_t requested_port,
                               std::uint16_t granted_port,
                               std::uint32_t lifetime_seconds = 3600,
                               bool private_external = false) {
    TransportMappingResult mapping{};
    mapping.transport = transport;
    mapping.local_endpoint = Ep(192, 168, 68, 54, local_port);
    mapping.requested_external_port = requested_port;
    mapping.granted_external_endpoint = private_external
        ? Ep(100, 69, 24, 30, granted_port, EndpointSourceFor(mapper))
        : Ep(88, 11, 22, 4, granted_port, EndpointSourceFor(mapper));
    mapping.lifetime_seconds = lifetime_seconds;
    mapping.effective_expiry_monotonic_ms =
        lifetime_seconds == 0 ? 0 : 1000u +
            static_cast<std::uint64_t>(lifetime_seconds) * 1000u;
    return mapping;
}

MapperResultData Base(MapperKind mapper, MapperSource source,
                      MappingOperation operation, MappingStatus status,
                      std::uint64_t generation = 7) {
    MapperResultData data{};
    data.mapper = mapper;
    data.source = source;
    data.gateway = Ep(192, 168, 68, 1, 5351);
    data.request_id = 101;
    data.topology_generation = generation;
    data.operation = operation;
    data.status = status;
    return data;
}

void AddAtomicPair(MapperResultData& data, std::uint16_t tcp_requested,
                   std::uint16_t tcp_granted,
                   std::uint16_t udp_requested,
                   std::uint16_t udp_granted,
                   bool private_external = false) {
    data.mappings[0] = Mapping(data.mapper, Transport::Tcp, 4662,
                               tcp_requested, tcp_granted, 3600,
                               private_external);
    data.mappings[1] = Mapping(data.mapper, Transport::Udp, 4672,
                               udp_requested, udp_granted, 3600,
                               private_external);
    data.mapping_count = 2;
}

void MarkOwnedAndVerified(MapperResultData& data) {
    data.ownership = OwnershipState::OwnedByUs;
    if (data.mapper == MapperKind::Pcp)
        data.ownership_nonce = Nonce(1);
    else
        data.ownership_identity_digest = Digest(2);
    data.verification = VerificationState::Verified;
    data.evidence_digest = Digest(3);
}

void TestUpnpSuccess() {
    MapperResultData data = Base(MapperKind::UpnpIgd,
                                 MapperSource::UpnpIgd,
                                 MappingOperation::Initial,
                                 MappingStatus::Created);
    AddAtomicPair(data, 4662, 4662, 4672, 4672);
    MarkOwnedAndVerified(data);
    const MapperResult result(data);

    CHECK(result.IsStructurallyValid());
    CHECK(result.IsCurrent(7));
    CHECK(result.IsPublishable(7));
    CHECK(result.data().mapper == MapperKind::UpnpIgd);
    CHECK(result.data().source == MapperSource::UpnpIgd);
    CHECK(result.data().mappings[0].granted_external_endpoint.port == 4662);
}

void TestPcpSuccessWithAlternatePort() {
    MapperResultData data = Base(MapperKind::Pcp, MapperSource::PcpCpe,
                                 MappingOperation::Initial,
                                 MappingStatus::Created);
    AddAtomicPair(data, 4662, 52144, 4672, 52145);
    data.mapper_epoch = 17;
    MarkOwnedAndVerified(data);
    const MapperResult result(data);

    CHECK(result.IsStructurallyValid());
    CHECK(result.IsPublishable(7));
    CHECK(result.data().mappings[0].requested_external_port == 4662);
    CHECK(result.data().mappings[0].granted_external_endpoint.port == 52144);
    CHECK(result.data().ownership_nonce == Nonce(1));
}

void TestNatPmpRenewal() {
    MapperResultData data = Base(MapperKind::NatPmp,
                                 MapperSource::NatPmp,
                                 MappingOperation::Refresh,
                                 MappingStatus::Renewed, 9);
    AddAtomicPair(data, 4662, 4662, 4672, 4672);
    data.mapper_epoch = 44;
    data.mapper_epoch_reset = true;
    MarkOwnedAndVerified(data);
    const MapperResult result(data);

    CHECK(result.IsStructurallyValid());
    CHECK(result.IsCurrent(9));
    CHECK(result.IsPublishable(9));
    CHECK(result.data().status == MappingStatus::Renewed);
    CHECK(result.data().mapper_epoch == 44);
    CHECK(result.data().mapper_epoch_reset);

    MapperResultData invalid = data;
    invalid.mapper = MapperKind::Pcp;
    invalid.source = MapperSource::PcpCpe;
    invalid.mappings[0].granted_external_endpoint.source =
        EndpointSource::PcpMap;
    invalid.mappings[1].granted_external_endpoint.source =
        EndpointSource::PcpMap;
    CHECK(!MapperResult(invalid).IsStructurallyValid());

    invalid = data;
    invalid.operation = MappingOperation::Initial;
    invalid.status = MappingStatus::Created;
    CHECK(!MapperResult(invalid).IsStructurallyValid());

    MapperResultData failedReset = Base(
        MapperKind::NatPmp, MapperSource::NatPmp,
        MappingOperation::Refresh, MappingStatus::Failed, 9);
    failedReset.mapper_epoch = 2;
    failedReset.mapper_epoch_reset = true;
    failedReset.verification = VerificationState::Failed;
    failedReset.reason = ReasonCode::MappingDenied;
    CHECK(MapperResult(failedReset).IsStructurallyValid());
    CHECK(!MapperResult(failedReset).IsPublishable(9));

    MapperResultData pcpAtomicReset = Base(
        MapperKind::Pcp, MapperSource::PcpCpe,
        MappingOperation::Initial, MappingStatus::Failed, 9);
    pcpAtomicReset.mapper_epoch = 2;
    pcpAtomicReset.mapper_epoch_reset = true;
    pcpAtomicReset.verification = VerificationState::Failed;
    pcpAtomicReset.reason = ReasonCode::CgnatWithoutLease;
    CHECK(MapperResult(pcpAtomicReset).IsStructurallyValid());
    CHECK(!MapperResult(pcpAtomicReset).IsPublishable(9));
}

void TestTimeout() {
    MapperResultData data = Base(MapperKind::Pcp, MapperSource::PcpUpstream,
                                 MappingOperation::Initial,
                                 MappingStatus::Failed, 12);
    data.verification = VerificationState::Failed;
    data.reason = ReasonCode::MappingTimeout;
    const MapperResult result(data);

    CHECK(result.IsStructurallyValid());
    CHECK(result.IsCurrent(12));
    CHECK(!result.IsPublishable(12));
    CHECK(result.data().mapping_count == 0);
    CHECK(result.data().reason == ReasonCode::MappingTimeout);
}

void TestStaleGeneration() {
    MapperResultData data = Base(MapperKind::UpnpIgd,
                                 MapperSource::UpnpIgd,
                                 MappingOperation::Initial,
                                 MappingStatus::Created, 21);
    AddAtomicPair(data, 4662, 4662, 4672, 4672);
    MarkOwnedAndVerified(data);
    const MapperResult result(data);

    CHECK(result.IsStructurallyValid());
    CHECK(result.IsCurrent(21));
    CHECK(!result.IsCurrent(22));
    CHECK(!result.IsPublishable(22));
}

void TestPartialTcpCannotPublish() {
    MapperResultData data = Base(MapperKind::UpnpIgd,
                                 MapperSource::UpnpIgd,
                                 MappingOperation::Initial,
                                 MappingStatus::Partial, 30);
    data.mappings[0] = Mapping(data.mapper, Transport::Tcp,
                               4662, 4662, 4662);
    data.mapping_count = 1;
    data.ownership = OwnershipState::OwnedByUs;
    data.ownership_identity_digest = Digest(4);
    data.verification = VerificationState::Failed;
    data.reason = ReasonCode::MappingDenied;
    data.evidence_digest = Digest(5);
    const MapperResult result(data);

    CHECK(result.IsStructurallyValid());
    CHECK(result.data().mappings[0].transport == Transport::Tcp);
    CHECK(!result.IsPublishable(30));
}

void TestPrivateExternalIpCannotPublish() {
    MapperResultData data = Base(MapperKind::NatPmp,
                                 MapperSource::NatPmp,
                                 MappingOperation::Initial,
                                 MappingStatus::Created, 31);
    AddAtomicPair(data, 4662, 4662, 4672, 4672, true);
    data.ownership = OwnershipState::OwnedByUs;
    data.ownership_identity_digest = Digest(6);
    data.verification = VerificationState::Failed;
    data.reason = ReasonCode::CgnatWithoutLease;
    data.evidence_digest = Digest(7);
    const MapperResult result(data);

    CHECK(result.IsStructurallyValid());
    CHECK(result.data().mappings[0].granted_external_endpoint.address.
          IsPrivateOrSharedV4());
    CHECK(!result.IsPublishable(31));

    MapperResultData falselyVerified = data;
    falselyVerified.verification = VerificationState::Verified;
    falselyVerified.reason = ReasonCode::None;
    CHECK(!MapperResult(falselyVerified).IsStructurallyValid());
}

void TestClosedInvariants() {
    MapperResultData good = Base(MapperKind::Pcp, MapperSource::PcpCpe,
                                 MappingOperation::Initial,
                                 MappingStatus::Created, 40);
    AddAtomicPair(good, 4662, 52000, 4672, 52001);
    good.mapper_epoch = 1;
    MarkOwnedAndVerified(good);

    MapperResultData bad = good;
    bad.source = MapperSource::UpnpIgd;
    CHECK(!MapperResult(bad).IsStructurallyValid());

    bad = good;
    bad.mappings[1].transport = Transport::Tcp;
    CHECK(!MapperResult(bad).IsStructurallyValid());

    bad = good;
    bad.mappings[0].effective_expiry_monotonic_ms = 0;
    CHECK(!MapperResult(bad).IsStructurallyValid());

    bad = good;
    bad.ownership_nonce = {};
    CHECK(!MapperResult(bad).IsStructurallyValid());

    bad = good;
    bad.evidence_digest = {};
    CHECK(!MapperResult(bad).IsStructurallyValid());

    bad = good;
    bad.operation = MappingOperation::Delete;
    CHECK(!MapperResult(bad).IsStructurallyValid());

    bad = good;
    bad.mappings[0].transport = static_cast<Transport>(0);
    CHECK(!MapperResult(bad).IsStructurallyValid());

    bad = good;
    bad.ownership = OwnershipState::Foreign;
    CHECK(!MapperResult(bad).IsStructurallyValid());

    bad = Base(MapperKind::Pcp, MapperSource::PcpCpe,
               MappingOperation::Initial, MappingStatus::Failed, 42);
    bad.verification = VerificationState::Failed;
    bad.reason = ReasonCode::MappingTimeout;
    bad.ownership = OwnershipState::Foreign;
    bad.ownership_nonce = Nonce(9);
    CHECK(!MapperResult(bad).IsStructurallyValid());

    bad = good;
    bad.mappings[0].requested_external_port = 0;
    CHECK(MapperResult(bad).IsStructurallyValid());

    bad = good;
    bad.protocol_result_code = 7;
    CHECK(!MapperResult(bad).IsStructurallyValid());

    bad = good;
    bad.mappings[0].lifetime_seconds = 0;
    CHECK(!MapperResult(bad).IsStructurallyValid());

    bad = good;
    for (std::size_t i = 0; i < bad.mapping_count; ++i) {
        bad.mappings[i].lifetime_seconds = 0;
        bad.mappings[i].effective_expiry_monotonic_ms = 0;
    }
    CHECK(!MapperResult(bad).IsStructurallyValid());

    bad = good;
    bad.mapper = MapperKind::NatPmp;
    bad.source = MapperSource::NatPmp;
    bad.ownership_nonce = {};
    bad.ownership_identity_digest = Digest(8);
    for (std::size_t i = 0; i < bad.mapping_count; ++i) {
        bad.mappings[i].granted_external_endpoint.source =
            EndpointSource::NatPmpPublicAddress;
        bad.mappings[i].lifetime_seconds = 0;
        bad.mappings[i].effective_expiry_monotonic_ms = 0;
    }
    CHECK(!MapperResult(bad).IsStructurallyValid());

    bad = Base(MapperKind::UpnpIgd, MapperSource::UpnpIgd,
               MappingOperation::Initial, MappingStatus::Created, 41);
    AddAtomicPair(bad, 4662, 4662, 4672, 4672);
    for (std::size_t i = 0; i < bad.mapping_count; ++i) {
        bad.mappings[i].lifetime_seconds = 0;
        bad.mappings[i].effective_expiry_monotonic_ms = 0;
    }
    MarkOwnedAndVerified(bad);
    CHECK(MapperResult(bad).IsStructurallyValid());
    CHECK(MapperResult(bad).IsPublishable(41));

    bad = good;
    bad.mappings[0].effective_expiry_monotonic_ms = 1;
    CHECK(!MapperResult(bad).IsStructurallyValid());

    bad = good;
    bad.ownership = static_cast<OwnershipState>(255);
    CHECK(!MapperResult(bad).IsStructurallyValid());

    bad = good;
    bad.verification = static_cast<VerificationState>(255);
    CHECK(!MapperResult(bad).IsStructurallyValid());

    bad = good;
    bad.reason = static_cast<ReasonCode>(65535);
    CHECK(!MapperResult(bad).IsStructurallyValid());

    bad = good;
    bad.verification = VerificationState::Failed;
    bad.evidence_digest = Digest(9);
    CHECK(!MapperResult(bad).IsStructurallyValid());

    bad = good;
    bad.gateway.address = IpAddress::V4(0, 0, 0, 0);
    CHECK(!MapperResult(bad).IsStructurallyValid());

    bad = good;
    bad.mappings[0].local_endpoint.address =
        IpAddress::V4(0, 0, 0, 0);
    CHECK(!MapperResult(bad).IsStructurallyValid());

    bad = good;
    bad.mappings[0].granted_external_endpoint.address =
        IpAddress::V4(0, 0, 0, 0);
    CHECK(!MapperResult(bad).IsStructurallyValid());

    bad = good;
    bad.mappings[0].granted_external_endpoint.address = ZeroV6();
    CHECK(!MapperResult(bad).IsStructurallyValid());

    bad = good;
    bad.mapping_count = 1;
    bad.status = MappingStatus::Partial;
    bad.verification = VerificationState::Failed;
    bad.reason = ReasonCode::MappingDenied;
    bad.evidence_digest = Digest(10);
    bad.mappings[1] = {};
    bad.mappings[1].local_endpoint =
        Ep(192, 168, 68, 54, 0);
    CHECK(!MapperResult(bad).IsStructurallyValid());

    bad.mappings[1] = {};
    bad.mappings[1].granted_external_endpoint.address =
        IpAddress::V4(88, 11, 22, 4);
    bad.mappings[1].granted_external_endpoint.source =
        EndpointSource::PcpMap;
    CHECK(!MapperResult(bad).IsStructurallyValid());

    bad = good;
    bad.mappings[0].local_endpoint.address.bytes[15] = 1;
    CHECK(!MapperResult(bad).IsStructurallyValid());

    bad = good;
    bad.mappings[0].granted_external_endpoint.address.bytes[4] = 1;
    CHECK(!MapperResult(bad).IsStructurallyValid());

    bad = good;
    bad.gateway.address.bytes[8] = 1;
    CHECK(!MapperResult(bad).IsStructurallyValid());

    bad = good;
    bad.gateway.source = static_cast<EndpointSource>(255);
    CHECK(!MapperResult(bad).IsStructurallyValid());

    bad = good;
    bad.mappings[0].local_endpoint.source =
        EndpointSource::PcpMap;
    CHECK(!MapperResult(bad).IsStructurallyValid());

    bad = good;
    bad.mappings[0].local_endpoint.source =
        static_cast<EndpointSource>(255);
    CHECK(!MapperResult(bad).IsStructurallyValid());

    bad = good;
    bad.status = MappingStatus::Partial;
    bad.mapping_count = 1;
    bad.mappings[1] = {};
    bad.verification = VerificationState::Pending;
    bad.evidence_digest = {};
    bad.reason = ReasonCode::MappingDenied;
    CHECK(!MapperResult(bad).IsStructurallyValid());

    bad = Base(MapperKind::Pcp, MapperSource::PcpCpe,
               MappingOperation::Initial, MappingStatus::Failed, 43);
    bad.verification = VerificationState::Pending;
    bad.reason = ReasonCode::MappingTimeout;
    CHECK(!MapperResult(bad).IsStructurallyValid());
}

void TestConstructionSnapshotsInput() {
    MapperResultData data = Base(MapperKind::UpnpIgd,
                                 MapperSource::UpnpIgd,
                                 MappingOperation::Initial,
                                 MappingStatus::Created, 51);
    AddAtomicPair(data, 4662, 4662, 4672, 4672);
    MarkOwnedAndVerified(data);
    const MapperResult result(data);

    data.mapper = MapperKind::None;
    data.mappings[0].granted_external_endpoint.port = 1;
    data.evidence_digest = {};
    CHECK(result.IsStructurallyValid());
    CHECK(result.data().mapper == MapperKind::UpnpIgd);
    CHECK(result.data().mappings[0].granted_external_endpoint.port == 4662);
    CHECK(result.IsPublishable(51));
}

} // namespace

int main() {
    static_assert(std::is_copy_constructible<MapperResult>::value,
                  "mapper result must be safely copyable");
    static_assert(std::is_move_constructible<MapperResult>::value,
                  "mapper result must be safely movable");
    static_assert(std::is_trivially_copyable<MapperResultData>::value,
                  "mapper result data must contain values only");
    static_assert(std::is_standard_layout<MapperResultData>::value,
                  "mapper result data must remain a simple value boundary");
    static_assert(!std::is_pointer<MapperResult>::value,
                  "mapper result is a value contract");

    TestUpnpSuccess();
    TestPcpSuccessWithAlternatePort();
    TestNatPmpRenewal();
    TestTimeout();
    TestStaleGeneration();
    TestPartialTcpCannotPublish();
    TestPrivateExternalIpCannotPublish();
    TestClosedInvariants();
    TestConstructionSnapshotsInput();
    std::printf("test_mapper_result: %d checks, %d failures\n",
                checks, failures);
    return failures == 0 ? 0 : 1;
}
