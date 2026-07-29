#include "natmap/mapped_candidate_adapter.h"

#include <cstdio>
#include <limits>
#include <thread>
#include <type_traits>

using namespace natmap;

namespace natmap {

struct MappedCandidatePublisherTestAccess {
    static void SetTopologyGeneration(
        MappedCandidatePublisher& publisher,
        std::uint64_t value) {
        publisher.snapshot_.topology_generation_ = value;
    }

    static void SetPublicationSequence(
        MappedCandidatePublisher& publisher,
        std::uint64_t value) {
        publisher.snapshot_.publication_sequence_ = value;
    }

    static void SetNextCandidateId(
        MappedCandidatePublisher& publisher,
        std::uint64_t value) {
        publisher.next_candidate_id_ = value;
    }
};

} // namespace natmap

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

RouteBindingIdentity NativeRoute(std::uint32_t interface_index = 7) {
    RouteBindingIdentity route{};
    route.local_address = IpAddress::V4(192, 168, 68, 54);
    route.interface_index = interface_index;
    route.family = AddressFamily::IPv4;
    route.origin = NetworkOrigin::Native;
    route.interface_present = true;
    return route;
}

MapperResultData Mapping(MappingOperation operation,
                         std::uint64_t generation = 7) {
    MapperResultData data{};
    data.mapper = MapperKind::Pcp;
    data.source = MapperSource::PcpCpe;
    data.gateway =
        Ep(192, 168, 68, 1, 5351, EndpointSource::LocalInterface);
    data.request_interface_index = 7;
    data.request_local_address = IpAddress::V4(192, 168, 68, 54);
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
    data.topology_generation = generation;
    data.operation = operation;
    data.status = operation == MappingOperation::Refresh
        ? MappingStatus::Renewed : MappingStatus::Created;
    return data;
}

void UseUpnpOwnership(MapperResultData& data,
                      std::uint8_t digest_seed) {
    data.mapper = MapperKind::UpnpIgd;
    data.source = MapperSource::UpnpIgd;
    data.mapper_epoch = 0;
    data.ownership_nonce = {};
    data.ownership_identity_digest = {};
    data.ownership_identity_digest[0] = digest_seed;
    for (std::size_t i = 0; i < data.mapping_count; ++i)
        data.mappings[i].granted_external_endpoint.source =
            EndpointSource::UpnpExternalAddress;
}

void UseNatPmpOwnership(MapperResultData& data,
                        std::uint8_t digest_seed) {
    data.mapper = MapperKind::NatPmp;
    data.source = MapperSource::NatPmp;
    data.ownership_nonce = {};
    data.ownership_identity_digest = {};
    data.ownership_identity_digest[0] = digest_seed;
    for (std::size_t i = 0; i < data.mapping_count; ++i)
        data.mappings[i].granted_external_endpoint.source =
            EndpointSource::NatPmpPublicAddress;
}

MappedCandidateProof TcpProof(const MappedCandidate& candidate,
                              std::uint64_t attempt_id = 31,
                              std::uint64_t started = 1000,
                              std::uint64_t deadline = 2000) {
    MappedCandidateProof proof{};
    proof.attempt.attempt_id = attempt_id;
    proof.attempt.topology_generation =
        candidate.topology_generation();
    proof.attempt.endpoint = candidate.published_endpoint();
    proof.attempt.transport = Transport::Tcp;
    proof.attempt.path = VerificationPath::Direct;
    proof.attempt.started_monotonic_ms = started;
    proof.attempt.deadline_monotonic_ms = deadline;
    proof.primary.kind = EvidenceKind::ServerHighId;
    proof.primary.endpoint = proof.attempt.endpoint;
    proof.primary.generation = proof.attempt.topology_generation;
    proof.primary.observed_monotonic_ms = started + 10;
    proof.primary.verification_attempt_id = attempt_id;
    proof.inbound.kind = EvidenceKind::InboundTcpAccept;
    proof.inbound.endpoint = proof.attempt.endpoint;
    proof.inbound.generation = proof.attempt.topology_generation;
    proof.inbound.observed_monotonic_ms = started + 20;
    proof.inbound.verification_attempt_id = attempt_id;
    return proof;
}

void TestMapReadbackNeverPromotesWithoutInboundProof() {
    MapperResultData data = Mapping(MappingOperation::Initial);
    data.verification = VerificationState::Verified;
    data.evidence_digest[0] = 1;
    MappedCandidatePublisher publisher(7);
    CHECK(publisher.ApplyMapping(
              MapperResult(data), NativeRoute(), 1000) ==
          MappedCandidateUpdate::Published);
    const MappedCandidateSnapshot& snapshot = publisher.snapshot();
    CHECK(snapshot.topology_generation() == 7);
    CHECK(snapshot.candidate_count() == 2);
    CHECK(snapshot.Find(Transport::Tcp) != nullptr);
    CHECK(snapshot.Find(Transport::Udp) != nullptr);
    CHECK(snapshot.Find(Transport::Tcp)->verification() ==
          MappedCandidateVerification::Candidate);
    CHECK(snapshot.Find(Transport::Udp)->verification() ==
          MappedCandidateVerification::Candidate);
    CHECK(!snapshot.HasVerifiedGlobalCandidate());
}

void TestMixedTcpUdpPairDoesNotOverpromote() {
    MappedCandidatePublisher publisher(7);
    CHECK(publisher.ApplyMapping(
              MapperResult(Mapping(MappingOperation::Initial)),
              NativeRoute(), 1000) ==
          MappedCandidateUpdate::Published);
    const MappedCandidate* tcp =
        publisher.snapshot().Find(Transport::Tcp);
    CHECK(tcp != nullptr);
    const std::uint64_t tcp_id = tcp->candidate_id();
    const MappedCandidateProof proof = TcpProof(*tcp);
    CHECK(publisher.Promote(proof, 1100) ==
          MappedCandidatePromotion::Promoted);
    tcp = publisher.snapshot().Find(Transport::Tcp);
    const MappedCandidate* udp =
        publisher.snapshot().Find(Transport::Udp);
    CHECK(tcp != nullptr && udp != nullptr);
    CHECK(tcp->candidate_id() == tcp_id);
    CHECK(tcp->verification() ==
          MappedCandidateVerification::Verified);
    CHECK(udp->verification() ==
          MappedCandidateVerification::Candidate);
    CHECK(publisher.snapshot().HasVerifiedGlobalCandidate());
}

void TestStaleProofCannotPromote() {
    MappedCandidatePublisher publisher(7);
    publisher.ApplyMapping(
        MapperResult(Mapping(MappingOperation::Initial)),
        NativeRoute(), 1000);
    const MappedCandidate* tcp =
        publisher.snapshot().Find(Transport::Tcp);
    CHECK(tcp != nullptr);

    MappedCandidateProof wrong_generation = TcpProof(*tcp);
    wrong_generation.attempt.topology_generation = 6;
    wrong_generation.primary.generation = 6;
    wrong_generation.inbound.generation = 6;
    CHECK(publisher.Promote(wrong_generation, 1100) ==
          MappedCandidatePromotion::Stale);
    CHECK(!publisher.snapshot().HasVerifiedGlobalCandidate());

    const MappedCandidateProof expired_window =
        TcpProof(*tcp, 32, 1000, 1050);
    CHECK(publisher.Promote(expired_window, 1100) ==
          MappedCandidatePromotion::Stale);
    CHECK(!publisher.snapshot().HasVerifiedGlobalCandidate());
}

void TestIdenticalRenewalKeepsIdsAndGeneration() {
    MappedCandidatePublisher publisher(7);
    publisher.ApplyMapping(
        MapperResult(Mapping(MappingOperation::Initial)),
        NativeRoute(), 1000);
    const std::uint64_t tcp_id =
        publisher.snapshot().Find(Transport::Tcp)->candidate_id();
    const std::uint64_t udp_id =
        publisher.snapshot().Find(Transport::Udp)->candidate_id();
    const std::uint64_t publication =
        publisher.snapshot().publication_sequence();

    MapperResultData renewal = Mapping(MappingOperation::Refresh);
    renewal.mappings[0].effective_expiry_monotonic_ms = 7201000;
    renewal.mappings[1].effective_expiry_monotonic_ms = 7201000;
    CHECK(publisher.ApplyMapping(
              MapperResult(renewal), NativeRoute(), 2000) ==
          MappedCandidateUpdate::Renewed);
    CHECK(publisher.snapshot().topology_generation() == 7);
    CHECK(publisher.snapshot().Find(Transport::Tcp)->candidate_id() ==
          tcp_id);
    CHECK(publisher.snapshot().Find(Transport::Udp)->candidate_id() ==
          udp_id);
    CHECK(publisher.snapshot().publication_sequence() ==
          publication + 1);
}

void CheckIdentityChangeAdvances(MapperResultData changed,
                                 const RouteBindingIdentity& route) {
    MappedCandidatePublisher publisher(7);
    publisher.ApplyMapping(
        MapperResult(Mapping(MappingOperation::Initial)),
        NativeRoute(), 1000);
    const std::uint64_t old_id =
        publisher.snapshot().Find(Transport::Tcp)->candidate_id();
    const MappedCandidateProof old_proof =
        TcpProof(*publisher.snapshot().Find(Transport::Tcp));
    CHECK(publisher.ApplyMapping(MapperResult(changed), route, 1100) ==
          MappedCandidateUpdate::Replaced);
    CHECK(publisher.snapshot().topology_generation() == 8);
    CHECK(publisher.snapshot().Find(Transport::Tcp)->candidate_id() !=
          old_id);
    CHECK(!publisher.snapshot().HasVerifiedGlobalCandidate());
    CHECK(publisher.Promote(old_proof, 1100) ==
          MappedCandidatePromotion::Stale);
}

void TestEndpointGatewayAndRouteChangesInvalidate() {
    MapperResultData endpoint = Mapping(MappingOperation::Refresh);
    endpoint.mappings[0].granted_external_endpoint.port = 52146;
    CheckIdentityChangeAdvances(endpoint, NativeRoute());

    MapperResultData gateway = Mapping(MappingOperation::Refresh);
    gateway.gateway.address = IpAddress::V4(192, 168, 68, 2);
    CheckIdentityChangeAdvances(gateway, NativeRoute());

    MapperResultData route_data = Mapping(MappingOperation::Refresh);
    route_data.request_interface_index = 8;
    route_data.request_local_address = IpAddress::V4(192, 168, 68, 55);
    RouteBindingIdentity route = NativeRoute(8);
    route.local_address = route_data.request_local_address;
    for (std::size_t i = 0; i < route_data.mapping_count; ++i)
        route_data.mappings[i].local_endpoint.address =
            route_data.request_local_address;
    CheckIdentityChangeAdvances(route_data, route);
}

void TestMonotonicEpochRenewalKeepsIdentityAndUpdatesEpoch() {
    MappedCandidatePublisher publisher(7);
    publisher.ApplyMapping(
        MapperResult(Mapping(MappingOperation::Initial)),
        NativeRoute(), 1000);
    const std::uint64_t old_id =
        publisher.snapshot().Find(Transport::Tcp)->candidate_id();
    MapperResultData renewal = Mapping(MappingOperation::Refresh);
    renewal.mapper_epoch = 18;
    const MapperResult result(renewal);
    CHECK(!publisher.RequiresReplacement(
        result, NativeRoute(), 1100));
    CHECK(publisher.ApplyMapping(
              result, NativeRoute(), 1100) ==
          MappedCandidateUpdate::Renewed);
    const MappedCandidate* tcp =
        publisher.snapshot().Find(Transport::Tcp);
    CHECK(tcp != nullptr);
    CHECK(tcp->candidate_id() == old_id);
    CHECK(tcp->topology_generation() == 7);
    CHECK(tcp->mapper_epoch() == 18);
}

void TestEpochResetRequiresReplacement() {
    MapperResultData initial = Mapping(MappingOperation::Initial);
    UseNatPmpOwnership(initial, 1);
    MappedCandidatePublisher publisher(7);
    publisher.ApplyMapping(
        MapperResult(initial), NativeRoute(), 1000);
    const std::uint64_t old_id =
        publisher.snapshot().Find(Transport::Tcp)->candidate_id();
    MapperResultData reset = Mapping(MappingOperation::Refresh);
    UseNatPmpOwnership(reset, 1);
    reset.mapper_epoch = 1;
    reset.mapper_epoch_reset = true;
    const MapperResult result(reset);
    CHECK(publisher.RequiresReplacement(
        result, NativeRoute(), 1100));
    CHECK(publisher.ApplyMapping(
              result, NativeRoute(), 1100, 8) ==
          MappedCandidateUpdate::Replaced);
    CHECK(publisher.snapshot().topology_generation() == 8);
    CHECK(publisher.snapshot().Find(Transport::Tcp)
              ->candidate_id() != old_id);
}

void TestOwnershipNonceChangeReplacesIdAndWithdrawsProof() {
    MappedCandidatePublisher publisher(7);
    publisher.ApplyMapping(
        MapperResult(Mapping(MappingOperation::Initial)),
        NativeRoute(), 1000);
    const MappedCandidate* tcp =
        publisher.snapshot().Find(Transport::Tcp);
    CHECK(tcp != nullptr);
    const std::uint64_t old_id = tcp->candidate_id();
    const MappedCandidateProof old_proof = TcpProof(*tcp);
    CHECK(publisher.Promote(old_proof, 1100) ==
          MappedCandidatePromotion::Promoted);

    MapperResultData renewal = Mapping(MappingOperation::Refresh);
    renewal.ownership_nonce[0] = 2;
    const MapperResult result(renewal);
    CHECK(publisher.RequiresReplacement(
        result, NativeRoute(), 1200));
    CHECK(publisher.ApplyMapping(
              result, NativeRoute(), 1200, 8) ==
          MappedCandidateUpdate::Replaced);
    tcp = publisher.snapshot().Find(Transport::Tcp);
    CHECK(tcp != nullptr);
    CHECK(tcp->candidate_id() != old_id);
    CHECK(tcp->topology_generation() == 8);
    CHECK(tcp->verification() ==
          MappedCandidateVerification::Candidate);
    CHECK(publisher.Promote(old_proof, 1300) ==
          MappedCandidatePromotion::Stale);
}

void TestOwnershipDigestChangeReplacesIdAndWithdrawsProof() {
    MapperResultData initial = Mapping(MappingOperation::Initial);
    UseUpnpOwnership(initial, 1);
    MappedCandidatePublisher publisher(7);
    CHECK(publisher.ApplyMapping(
              MapperResult(initial), NativeRoute(), 1000) ==
          MappedCandidateUpdate::Published);
    const MappedCandidate* tcp =
        publisher.snapshot().Find(Transport::Tcp);
    CHECK(tcp != nullptr);
    const std::uint64_t old_id = tcp->candidate_id();
    const MappedCandidateProof old_proof = TcpProof(*tcp);
    CHECK(publisher.Promote(old_proof, 1100) ==
          MappedCandidatePromotion::Promoted);

    MapperResultData renewal = Mapping(MappingOperation::Refresh);
    UseUpnpOwnership(renewal, 2);
    const MapperResult result(renewal);
    CHECK(publisher.RequiresReplacement(
        result, NativeRoute(), 1200));
    CHECK(publisher.ApplyMapping(
              result, NativeRoute(), 1200, 8) ==
          MappedCandidateUpdate::Replaced);
    tcp = publisher.snapshot().Find(Transport::Tcp);
    CHECK(tcp != nullptr);
    CHECK(tcp->candidate_id() != old_id);
    CHECK(tcp->topology_generation() == 8);
    CHECK(tcp->verification() ==
          MappedCandidateVerification::Candidate);
    CHECK(publisher.Promote(old_proof, 1300) ==
          MappedCandidatePromotion::Stale);
}

void TestGatewayPortPreflightForcesCommittedReplacement() {
    MappedCandidatePublisher publisher(7);
    publisher.ApplyMapping(
        MapperResult(Mapping(MappingOperation::Initial)),
        NativeRoute(), 1000);
    const std::uint64_t old_id =
        publisher.snapshot().Find(Transport::Tcp)->candidate_id();
    MapperResultData renewal = Mapping(MappingOperation::Refresh);
    renewal.gateway.port = 5352;
    const MapperResult result(renewal);
    CHECK(publisher.RequiresReplacement(
        result, NativeRoute(), 1100));
    CHECK(publisher.ApplyMapping(
              result, NativeRoute(), 1100, 8) ==
          MappedCandidateUpdate::Replaced);
    CHECK(publisher.snapshot().topology_generation() == 8);
    CHECK(publisher.snapshot().Find(Transport::Tcp)
              ->candidate_id() != old_id);
}

void TestTcpOnlyCommonResultRemainsFailClosed() {
    MapperResultData tcp_only = Mapping(MappingOperation::Initial);
    tcp_only.mapping_count = 1;
    tcp_only.mappings[1] = {};
    const MapperResult result(tcp_only);
    CHECK(!result.IsStructurallyValid());
    MappedCandidatePublisher publisher(7);
    CHECK(publisher.ApplyMapping(result, NativeRoute(), 1000) ==
          MappedCandidateUpdate::Rejected);
    CHECK(publisher.snapshot().candidate_count() == 0);
    CHECK(publisher.snapshot().topology_generation() == 7);
}

void TestExpiryAndShutdownWithdrawAndFenceCallbacks() {
    MapperResultData short_lease = Mapping(MappingOperation::Initial);
    short_lease.mappings[0].lifetime_seconds = 1;
    short_lease.mappings[0].effective_expiry_monotonic_ms = 2000;
    short_lease.mappings[1].lifetime_seconds = 1;
    short_lease.mappings[1].effective_expiry_monotonic_ms = 2000;
    MappedCandidatePublisher publisher(7);
    publisher.ApplyMapping(
        MapperResult(short_lease), NativeRoute(), 1000);
    const MappedCandidateProof proof =
        TcpProof(*publisher.snapshot().Find(Transport::Tcp));
    CHECK(publisher.WithdrawExpired(1999) ==
          MappedCandidateRetirement::NoChange);
    CHECK(publisher.WithdrawExpired(2000) ==
          MappedCandidateRetirement::Retired);
    CHECK(publisher.snapshot().candidate_count() == 0);
    CHECK(publisher.Promote(proof, 1500) ==
          MappedCandidatePromotion::Stale);

    CHECK(publisher.ApplyMapping(
              MapperResult(Mapping(MappingOperation::Initial, 8)),
              NativeRoute(), 2100) ==
          MappedCandidateUpdate::Published);
    const std::uint64_t cleanup_generation =
        publisher.snapshot().topology_generation();
    CHECK(publisher.Shutdown() ==
          MappedCandidateRetirement::Retired);
    CHECK(publisher.snapshot().candidate_count() == 0);
    CHECK(publisher.snapshot().topology_generation() ==
          cleanup_generation);
    CHECK(publisher.ApplyMapping(
              MapperResult(Mapping(MappingOperation::Initial, 8)),
              NativeRoute(), 2200) ==
          MappedCandidateUpdate::Closed);
    CHECK(publisher.Promote(proof, 1500) ==
          MappedCandidatePromotion::Closed);
}

void CheckAtomicExpiryOrder(bool tcp_expires_first) {
    MapperResultData lease = Mapping(MappingOperation::Initial);
    lease.mappings[0].lifetime_seconds = 1;
    lease.mappings[1].lifetime_seconds = 1;
    lease.mappings[0].effective_expiry_monotonic_ms =
        tcp_expires_first ? 1500 : 1800;
    lease.mappings[1].effective_expiry_monotonic_ms =
        tcp_expires_first ? 1800 : 1500;
    MappedCandidatePublisher publisher(7);
    CHECK(publisher.ApplyMapping(
              MapperResult(lease), NativeRoute(), 1000) ==
          MappedCandidateUpdate::Published);
    const MappedCandidateProof proof =
        TcpProof(*publisher.snapshot().Find(Transport::Tcp),
                 tcp_expires_first ? 41 : 42, 1000, 2000);
    CHECK(publisher.Promote(proof, 1400) ==
          MappedCandidatePromotion::Promoted);
    CHECK(publisher.snapshot().HasVerifiedGlobalCandidate());
    if (tcp_expires_first) {
        CHECK(publisher.WithdrawExpired(1499) ==
              MappedCandidateRetirement::NoChange);
        CHECK(publisher.WithdrawExpired(1500) ==
              MappedCandidateRetirement::Retired);
    } else {
        CHECK(publisher.Promote(proof, 1500) ==
              MappedCandidatePromotion::Stale);
    }
    CHECK(publisher.snapshot().candidate_count() == 0);
    CHECK(publisher.snapshot().topology_generation() == 8);
    CHECK(!publisher.snapshot().HasVerifiedGlobalCandidate());
}

void TestAtomicPairExpiryAtExactBoundaryBothOrders() {
    CheckAtomicExpiryOrder(true);
    CheckAtomicExpiryOrder(false);
}

void TestRenewalAfterExpiredPairReplacesIdentityAndProof() {
    MapperResultData lease = Mapping(MappingOperation::Initial);
    lease.mappings[0].lifetime_seconds = 1;
    lease.mappings[1].lifetime_seconds = 1;
    lease.mappings[0].effective_expiry_monotonic_ms = 1500;
    lease.mappings[1].effective_expiry_monotonic_ms = 1800;
    MappedCandidatePublisher publisher(7);
    publisher.ApplyMapping(
        MapperResult(lease), NativeRoute(), 1000);
    const MappedCandidate* tcp =
        publisher.snapshot().Find(Transport::Tcp);
    const std::uint64_t old_id = tcp->candidate_id();
    const MappedCandidateProof proof =
        TcpProof(*tcp, 43, 1000, 2000);
    CHECK(publisher.Promote(proof, 1400) ==
          MappedCandidatePromotion::Promoted);

    MapperResultData renewal = Mapping(MappingOperation::Refresh);
    const MapperResult result(renewal);
    CHECK(publisher.RequiresReplacement(
        result, NativeRoute(), 1500));
    CHECK(publisher.ApplyMapping(
              result, NativeRoute(), 1500, 8) ==
          MappedCandidateUpdate::Replaced);
    tcp = publisher.snapshot().Find(Transport::Tcp);
    CHECK(tcp != nullptr);
    CHECK(tcp->candidate_id() != old_id);
    CHECK(tcp->topology_generation() == 8);
    CHECK(tcp->verification() ==
          MappedCandidateVerification::Candidate);
    CHECK(publisher.Promote(proof, 1500) ==
          MappedCandidatePromotion::Stale);
}

void PublishUnevenExpiryAndVerify(
    MappedCandidatePublisher& publisher,
    std::uint64_t attempt_id) {
    MapperResultData lease = Mapping(MappingOperation::Initial);
    lease.mappings[0].lifetime_seconds = 1;
    lease.mappings[1].lifetime_seconds = 1;
    lease.mappings[0].effective_expiry_monotonic_ms = 1500;
    lease.mappings[1].effective_expiry_monotonic_ms = 1800;
    CHECK(publisher.ApplyMapping(
              MapperResult(lease), NativeRoute(), 1000) ==
          MappedCandidateUpdate::Published);
    CHECK(publisher.Promote(
              TcpProof(
                  *publisher.snapshot().Find(Transport::Tcp),
                  attempt_id, 1000, 2000),
              1400) ==
          MappedCandidatePromotion::Promoted);
}

void TestExpiredRenewalRejectedCommittedOldWithdrawsPair() {
    MappedCandidatePublisher publisher(7);
    PublishUnevenExpiryAndVerify(publisher, 44);
    const MapperResult renewal(
        Mapping(MappingOperation::Refresh));
    CHECK(publisher.ApplyMapping(
              renewal, NativeRoute(), 1500, 7) ==
          MappedCandidateUpdate::Rejected);
    CHECK(publisher.snapshot().candidate_count() == 0);
    CHECK(publisher.snapshot().topology_generation() == 8);
    CHECK(!publisher.snapshot().HasVerifiedGlobalCandidate());
}

void TestExpiredStaleAndInvalidResultsWithdrawPair() {
    MappedCandidatePublisher stale(7);
    PublishUnevenExpiryAndVerify(stale, 45);
    CHECK(stale.ApplyMapping(
              MapperResult(Mapping(
                  MappingOperation::Refresh, 6)),
              NativeRoute(), 1500) ==
          MappedCandidateUpdate::Rejected);
    CHECK(stale.snapshot().candidate_count() == 0);
    CHECK(stale.snapshot().topology_generation() == 8);
    CHECK(!stale.snapshot().HasVerifiedGlobalCandidate());

    MappedCandidatePublisher invalid(7);
    PublishUnevenExpiryAndVerify(invalid, 46);
    MapperResultData tcp_only =
        Mapping(MappingOperation::Refresh);
    tcp_only.mapping_count = 1;
    tcp_only.mappings[1] = {};
    CHECK(invalid.ApplyMapping(
              MapperResult(tcp_only), NativeRoute(), 1500) ==
          MappedCandidateUpdate::Rejected);
    CHECK(invalid.snapshot().candidate_count() == 0);
    CHECK(invalid.snapshot().topology_generation() == 8);
    CHECK(!invalid.snapshot().HasVerifiedGlobalCandidate());
}

void TestRejectedResultJustBeforeExpiryKeepsPair() {
    MappedCandidatePublisher publisher(7);
    PublishUnevenExpiryAndVerify(publisher, 47);
    CHECK(publisher.ApplyMapping(
              MapperResult(Mapping(
                  MappingOperation::Refresh, 6)),
              NativeRoute(), 1499) ==
          MappedCandidateUpdate::Rejected);
    CHECK(publisher.snapshot().candidate_count() == 2);
    CHECK(publisher.snapshot().topology_generation() == 7);
    CHECK(publisher.snapshot().HasVerifiedGlobalCandidate());
}

void PublishAndVerify(MappedCandidatePublisher& publisher,
                      std::uint64_t generation = 7) {
    CHECK(publisher.ApplyMapping(
              MapperResult(Mapping(
                  MappingOperation::Initial, generation)),
              NativeRoute(), 1000) ==
          MappedCandidateUpdate::Published);
    CHECK(publisher.Promote(
              TcpProof(*publisher.snapshot().Find(Transport::Tcp)),
              1100) ==
          MappedCandidatePromotion::Promoted);
}

void CheckClosedAndEmpty(
    const MappedCandidatePublisher& publisher) {
    CHECK(publisher.is_closed());
    CHECK(publisher.snapshot().candidate_count() == 0);
    CHECK(!publisher.snapshot().HasVerifiedGlobalCandidate());
}

void TestOverflowOnExpiryAndIdentityChangeClosesEmpty() {
    const std::uint64_t maximum =
        (std::numeric_limits<std::uint64_t>::max)();
    MapperResultData lease =
        Mapping(MappingOperation::Initial, maximum);
    lease.mappings[0].lifetime_seconds = 1;
    lease.mappings[1].lifetime_seconds = 1;
    lease.mappings[0].effective_expiry_monotonic_ms = 2000;
    lease.mappings[1].effective_expiry_monotonic_ms = 3000;
    MappedCandidatePublisher expiry(maximum);
    CHECK(expiry.ApplyMapping(
              MapperResult(lease), NativeRoute(), 1000) ==
          MappedCandidateUpdate::Published);
    CHECK(expiry.Promote(
              TcpProof(*expiry.snapshot().Find(Transport::Tcp)),
              1100) ==
          MappedCandidatePromotion::Promoted);
    CHECK(expiry.WithdrawExpired(2000) ==
          MappedCandidateRetirement::Closed);
    CheckClosedAndEmpty(expiry);

    MappedCandidatePublisher replacement(maximum);
    PublishAndVerify(replacement, maximum);
    MapperResultData changed =
        Mapping(MappingOperation::Refresh, maximum);
    changed.gateway.port = 5352;
    CHECK(replacement.ApplyMapping(
              MapperResult(changed), NativeRoute(), 1200) ==
          MappedCandidateUpdate::Exhausted);
    CheckClosedAndEmpty(replacement);
}

void TestRejectedObservationAtGenerationLimitClosesEmpty() {
    const std::uint64_t maximum =
        (std::numeric_limits<std::uint64_t>::max)();
    MappedCandidatePublisher publisher(7);
    PublishAndVerify(publisher);
    MappedCandidatePublisherTestAccess::SetTopologyGeneration(
        publisher, maximum);
    CHECK(publisher.WithdrawRejectedObservation() ==
          MappedCandidateRetirement::Closed);
    CHECK(publisher.is_closed());
    CHECK(publisher.snapshot().candidate_count() == 0);
    CHECK(!publisher.snapshot().HasVerifiedGlobalCandidate());
}

void TestCandidateIdExhaustionClosesEmpty() {
    const std::uint64_t maximum =
        (std::numeric_limits<std::uint64_t>::max)();
    MappedCandidatePublisher publisher(7);
    PublishAndVerify(publisher);
    MappedCandidatePublisherTestAccess::SetNextCandidateId(
        publisher, maximum);
    MapperResultData changed = Mapping(MappingOperation::Refresh);
    changed.gateway.port = 5352;
    CHECK(publisher.ApplyMapping(
              MapperResult(changed), NativeRoute(), 1200, 8) ==
          MappedCandidateUpdate::Exhausted);
    CheckClosedAndEmpty(publisher);
}

void TestPublicationSequenceOverflowClosesEmptyEveryPath() {
    const std::uint64_t maximum =
        (std::numeric_limits<std::uint64_t>::max)();

    MappedCandidatePublisher apply(7);
    MappedCandidatePublisherTestAccess::SetPublicationSequence(
        apply, maximum);
    CHECK(apply.ApplyMapping(
              MapperResult(Mapping(MappingOperation::Initial)),
              NativeRoute(), 1000) ==
          MappedCandidateUpdate::Exhausted);
    CheckClosedAndEmpty(apply);

    MappedCandidatePublisher promote(7);
    CHECK(promote.ApplyMapping(
              MapperResult(Mapping(MappingOperation::Initial)),
              NativeRoute(), 1000) ==
          MappedCandidateUpdate::Published);
    const MappedCandidateProof proof =
        TcpProof(*promote.snapshot().Find(Transport::Tcp));
    MappedCandidatePublisherTestAccess::SetPublicationSequence(
        promote, maximum);
    CHECK(promote.Promote(proof, 1100) ==
          MappedCandidatePromotion::Closed);
    CheckClosedAndEmpty(promote);

    MappedCandidatePublisher invalidate(7);
    PublishAndVerify(invalidate);
    MappedCandidatePublisherTestAccess::SetPublicationSequence(
        invalidate, maximum);
    CHECK(invalidate.Invalidate(8) ==
          MappedCandidateRetirement::Closed);
    CheckClosedAndEmpty(invalidate);

    MappedCandidatePublisher shutdown(7);
    PublishAndVerify(shutdown);
    MappedCandidatePublisherTestAccess::SetPublicationSequence(
        shutdown, maximum);
    CHECK(shutdown.Shutdown() ==
          MappedCandidateRetirement::Closed);
    CheckClosedAndEmpty(shutdown);

    MapperResultData lease = Mapping(MappingOperation::Initial);
    lease.mappings[0].lifetime_seconds = 1;
    lease.mappings[1].lifetime_seconds = 1;
    lease.mappings[0].effective_expiry_monotonic_ms = 2000;
    lease.mappings[1].effective_expiry_monotonic_ms = 3000;
    MappedCandidatePublisher expiry(7);
    CHECK(expiry.ApplyMapping(
              MapperResult(lease), NativeRoute(), 1000) ==
          MappedCandidateUpdate::Published);
    MappedCandidatePublisherTestAccess::SetPublicationSequence(
        expiry, maximum);
    CHECK(expiry.WithdrawExpired(2000) ==
          MappedCandidateRetirement::Closed);
    CheckClosedAndEmpty(expiry);
}

void TestOnlyOwnerThreadCanPublishSnapshot() {
    MappedCandidatePublisher publisher(7);
    MappedCandidateUpdate update = MappedCandidateUpdate::Rejected;
    std::thread worker([&publisher, &update]() {
        update = publisher.ApplyMapping(
            MapperResult(Mapping(MappingOperation::Initial)),
            NativeRoute(), 1000);
    });
    worker.join();
    CHECK(update == MappedCandidateUpdate::WrongThread);
    CHECK(publisher.snapshot().candidate_count() == 0);
}

void TestCommittedMainThreadGenerationPublishesWholePair() {
    MappedCandidatePublisher publisher(7);
    CHECK(publisher.ApplyMapping(
              MapperResult(Mapping(MappingOperation::Initial)),
              NativeRoute(), 1000, 8) ==
          MappedCandidateUpdate::Published);
    CHECK(publisher.snapshot().topology_generation() == 8);
    CHECK(publisher.snapshot().candidate_count() == 2);
    CHECK(publisher.snapshot().Find(Transport::Tcp)
              ->topology_generation() == 8);
    CHECK(publisher.snapshot().Find(Transport::Udp)
              ->topology_generation() == 8);
    CHECK(publisher.snapshot().publication_sequence() == 1);
}

static_assert(
    std::is_same<
        decltype(std::declval<const MappedCandidate&>()
                     .published_endpoint()),
        const Endpoint&>::value,
    "actionable endpoint access must remain immutable");

} // namespace

int main() {
    TestMapReadbackNeverPromotesWithoutInboundProof();
    TestMixedTcpUdpPairDoesNotOverpromote();
    TestStaleProofCannotPromote();
    TestIdenticalRenewalKeepsIdsAndGeneration();
    TestEndpointGatewayAndRouteChangesInvalidate();
    TestMonotonicEpochRenewalKeepsIdentityAndUpdatesEpoch();
    TestEpochResetRequiresReplacement();
    TestOwnershipNonceChangeReplacesIdAndWithdrawsProof();
    TestOwnershipDigestChangeReplacesIdAndWithdrawsProof();
    TestGatewayPortPreflightForcesCommittedReplacement();
    TestTcpOnlyCommonResultRemainsFailClosed();
    TestExpiryAndShutdownWithdrawAndFenceCallbacks();
    TestAtomicPairExpiryAtExactBoundaryBothOrders();
    TestRenewalAfterExpiredPairReplacesIdentityAndProof();
    TestExpiredRenewalRejectedCommittedOldWithdrawsPair();
    TestExpiredStaleAndInvalidResultsWithdrawPair();
    TestRejectedResultJustBeforeExpiryKeepsPair();
    TestOverflowOnExpiryAndIdentityChangeClosesEmpty();
    TestRejectedObservationAtGenerationLimitClosesEmpty();
    TestCandidateIdExhaustionClosesEmpty();
    TestPublicationSequenceOverflowClosesEmptyEveryPath();
    TestOnlyOwnerThreadCanPublishSnapshot();
    TestCommittedMainThreadGenerationPublishesWholePair();
    std::printf(
        "test_mapped_candidate_adapter: %d checks, %d failures\n",
        checks, failures);
    return failures == 0 ? 0 : 1;
}
