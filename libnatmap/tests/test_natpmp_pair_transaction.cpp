#include "natmap/natpmp_pair_transaction.h"
#include "natmap/natpmp_product_policy.h"
#include "natmap/legacy_mapper_projection.h"

#include <algorithm>
#include <cstdio>
#include <limits>

using namespace natmap;

namespace {

int failures = 0;
int checks = 0;

#define CHECK(expr) do { ++checks; if (!(expr)) { ++failures; \
    std::printf("FAIL line %d: %s\n", __LINE__, #expr); } } while (0)

NatPmpMapProjection Projection(
    NatPmpTransport transport,
    std::uint16_t internal_port,
    std::uint16_t requested_external_port,
    std::uint16_t granted_external_port) {
    NatPmpMapProjection projection{};
    projection.transport = transport;
    projection.requested_external_port = requested_external_port;
    projection.response.result_code = 0;
    projection.response.epoch = 1234;
    projection.response.internal_port = internal_port;
    projection.response.external_port = granted_external_port;
    projection.response.lifetime_seconds = 7200;
    return projection;
}

NatPmpMapProjection Tcp() {
    return Projection(
        NatPmpTransport::Tcp, 4662, 4662, 52144);
}

NatPmpMapProjection Udp() {
    return Projection(
        NatPmpTransport::Udp, 4672, 4672, 52145);
}

void TestCompletePairCommitsAlternativePortsExactlyOnce() {
    NatPmpPairTransaction transaction(true, true);
    NatPmpPairCommit commit{};
    CHECK(transaction.StageTcp(Tcp()));
    CHECK(transaction.status()
        == NatPmpPairTransactionStatus::AwaitingUdp);
    CHECK(!transaction.TryCommit(commit));
    CHECK(!commit.IsValid());
    CHECK(transaction.StageUdp(Udp()));
    CHECK(transaction.status()
        == NatPmpPairTransactionStatus::Ready);
    CHECK(transaction.TryCommit(commit));
    CHECK(commit.IsValid());
    CHECK(commit.has_udp);
    CHECK(commit.tcp.requested_external_port == 4662);
    CHECK(commit.tcp.response.external_port == 52144);
    CHECK(commit.udp.requested_external_port == 4672);
    CHECK(commit.udp.response.external_port == 52145);
    CHECK(transaction.status()
        == NatPmpPairTransactionStatus::Committed);

    NatPmpPairCommit reused = commit;
    CHECK(!transaction.TryCommit(reused));
    CHECK(!reused.IsValid());
}

void TestInitialUdpFailureRequiresExactTcpRollback() {
    NatPmpPairTransaction transaction(true, true);
    CHECK(transaction.StageTcp(Tcp()));
    transaction.RecordUdpFailure();
    CHECK(transaction.status()
        == NatPmpPairTransactionStatus::TcpRollbackRequired);

    NatPmpPairCommit partial{};
    CHECK(!transaction.TryCommit(partial));
    CHECK(!partial.IsValid());
    CHECK(!transaction.StageUdp(Udp()));

    NatPmpRollbackTarget rollback{};
    CHECK(transaction.GetTcpRollbackTarget(rollback));
    CHECK(rollback.transport == NatPmpTransport::Tcp);
    CHECK(rollback.internal_port == 4662);
}

void TestRefreshUdpFailurePreservesPreviousPair() {
    NatPmpPairTransaction transaction(true, false);
    CHECK(transaction.StageTcp(Tcp()));
    transaction.RecordUdpFailure();
    CHECK(transaction.status()
        == NatPmpPairTransactionStatus::Failed);

    NatPmpRollbackTarget rollback{};
    CHECK(!transaction.GetTcpRollbackTarget(rollback));
    CHECK(!rollback.IsValid());
    NatPmpPairCommit partial{};
    CHECK(!transaction.TryCommit(partial));
    CHECK(!partial.IsValid());
}

void TestFailureDispositionInvalidatesAPreResetPair() {
    CHECK(ResolveNatPmpPairFailureDisposition(true, false)
        == NatPmpPairFailureDisposition::ClearProvisional);
    CHECK(ResolveNatPmpPairFailureDisposition(false, false)
        == NatPmpPairFailureDisposition::PreservePrevious);
    CHECK(ResolveNatPmpPairFailureDisposition(false, true)
        == NatPmpPairFailureDisposition::InvalidatePrevious);
    CHECK(ResolveNatPmpPairFailureDisposition(true, true)
        == NatPmpPairFailureDisposition::InvalidatePrevious);

    const bool external_address_observed_reset = true;
    const bool map_completed = false;
    CHECK(!map_completed &&
        ResolveNatPmpPairFailureDisposition(
            false, external_address_observed_reset)
        == NatPmpPairFailureDisposition::InvalidatePrevious);
}

void TestRejectedResponsesStillCarryCorrelatedEpochEvidence() {
    NatPmpMapResponse rejected{};
    rejected.result_code = 4;
    rejected.epoch = 2;
    rejected.internal_port = 4662;
    CHECK(HasCorrelatedNatPmpMapObservation(rejected, 4662));
    CHECK(rejected.epoch == 2);
    CHECK(!HasCorrelatedNatPmpMapObservation(rejected, 4672));
    CHECK(!HasCorrelatedNatPmpMapObservation({}, 4662));
    CHECK(!HasCorrelatedNatPmpMapObservation(rejected, 0));
}

void TestTcpFailurePublishesAndRollsBackNothing() {
    NatPmpPairTransaction transaction(true, true);
    transaction.RecordTcpFailure();
    CHECK(transaction.status()
        == NatPmpPairTransactionStatus::Failed);

    NatPmpPairCommit commit{};
    NatPmpRollbackTarget rollback{};
    CHECK(!transaction.TryCommit(commit));
    CHECK(!commit.IsValid());
    CHECK(!transaction.GetTcpRollbackTarget(rollback));
    CHECK(!rollback.IsValid());
    CHECK(!transaction.StageTcp(Tcp()));
}

void TestTcpOnlyOperationCanCommit() {
    NatPmpPairTransaction transaction(false, true);
    CHECK(transaction.StageTcp(Tcp()));
    CHECK(transaction.status()
        == NatPmpPairTransactionStatus::Ready);
    NatPmpPairCommit commit{};
    CHECK(transaction.TryCommit(commit));
    CHECK(commit.IsValid());
    CHECK(!commit.has_udp);
    CHECK(commit.tcp.response.external_port == 52144);
}

void TestMalformedOrWrongTransportProjectionsFailClosed() {
    NatPmpPairTransaction transaction(true, true);
    CHECK(!transaction.StageTcp(Udp()));

    NatPmpMapProjection rejected = Tcp();
    rejected.response.result_code = 2;
    CHECK(!transaction.StageTcp(rejected));
    NatPmpMapProjection zero_internal = Tcp();
    zero_internal.response.internal_port = 0;
    CHECK(!transaction.StageTcp(zero_internal));
    NatPmpMapProjection zero_external = Tcp();
    zero_external.response.external_port = 0;
    CHECK(!transaction.StageTcp(zero_external));
    NatPmpMapProjection zero_lifetime = Tcp();
    zero_lifetime.response.lifetime_seconds = 0;
    CHECK(!transaction.StageTcp(zero_lifetime));

    CHECK(transaction.StageTcp(Tcp()));
    CHECK(!transaction.StageUdp(Tcp()));
    CHECK(transaction.status()
        == NatPmpPairTransactionStatus::AwaitingUdp);
}

void TestLeaseDeadlineStartsBeforeMapAndSaturates() {
    CHECK(ConservativeNatPmpLeaseDeadline(100, 7200) == 7300);
    CHECK(ConservativeNatPmpLeaseDeadline(0, 7200) == 0);
    CHECK(ConservativeNatPmpLeaseDeadline(100, 0) == 0);
    const std::uint64_t maximum =
        (std::numeric_limits<std::uint64_t>::max)();
    CHECK(ConservativeNatPmpLeaseDeadline(
        maximum - 5, 10) == maximum);
}

void TestCleanupGenerationMatchesHostAcceptance() {
    CHECK(ResolveNatPmpCleanupGeneration(
        31, true, true, false, true) == 32);
    CHECK(ResolveNatPmpCleanupGeneration(
        31, true, true, false, false) == 31);
    CHECK(ResolveNatPmpCleanupGeneration(
        31, true, false, true, false) == 32);
    CHECK(ResolveNatPmpCleanupGeneration(
        31, false, true, true, true) == 31);
    CHECK(ResolveNatPmpCleanupGeneration(
        31, false, true, false, true) == 31);
    CHECK(ResolveNatPmpCleanupGeneration(
        0, true, true, false, true) == 0);
    const std::uint64_t maximum =
        (std::numeric_limits<std::uint64_t>::max)();
    CHECK(ResolveNatPmpCleanupGeneration(
        maximum, true, true, false, true) == 0);
}

NatPmpCleanupProof CleanupProof() {
    NatPmpCleanupProof proof{};
    proof.gateway_address = {192, 168, 1, 1};
    proof.interface_index = 17;
    proof.generation = 31;
    proof.expires_monotonic_seconds = 10000;
    proof.mappings[0] = NatPmpCleanupMapping{
        NatPmpTransport::Tcp, 4662, 52144};
    proof.mappings[1] = NatPmpCleanupMapping{
        NatPmpTransport::Udp, 4672, 52145};
    proof.mapping_count = 2;
    proof.in_process_proof = true;
    return proof;
}

NatPmpCleanupRequest CleanupRequest(
    const NatPmpCleanupMapping& mapping) {
    NatPmpCleanupRequest request{};
    request.gateway_address = {192, 168, 1, 1};
    request.interface_index = 17;
    request.generation = 31;
    request.observed_monotonic_seconds = 9998;
    request.mapping = mapping;
    return request;
}

MapperResultData OwnershipResult() {
    MapperResultData data{};
    data.mapper = MapperKind::NatPmp;
    data.source = MapperSource::NatPmp;
    data.gateway.address = IpAddress::V4(192, 168, 1, 1);
    data.gateway.port = 5351;
    data.gateway.source = EndpointSource::LocalInterface;
    data.request_interface_index = 17;
    data.topology_generation = 30;
    data.request_id = 7;
    data.operation = MappingOperation::Initial;
    data.status = MappingStatus::Created;
    data.verification = VerificationState::Pending;
    data.ownership = OwnershipState::Unverifiable;
    data.mapping_count = 2;
    data.mappings[0].transport = Transport::Tcp;
    data.mappings[0].local_endpoint.port = 4662;
    data.mappings[0].local_endpoint.address = IpAddress::V4(192,168,1,20);
    data.mappings[0].local_endpoint.source = EndpointSource::LocalInterface;
    data.mappings[0].requested_external_port = 4662;
    data.mappings[0].granted_external_endpoint.port = 52144;
    data.mappings[0].granted_external_endpoint.address = IpAddress::V4(88,11,22,4);
    data.mappings[0].granted_external_endpoint.source = EndpointSource::NatPmpPublicAddress;
    data.mappings[0].lifetime_seconds = 7200;
    data.mappings[0].effective_expiry_monotonic_ms = 7200000;
    data.mappings[1].transport = Transport::Udp;
    data.mappings[1].local_endpoint.port = 4672;
    data.mappings[1].local_endpoint.address = IpAddress::V4(192,168,1,20);
    data.mappings[1].local_endpoint.source = EndpointSource::LocalInterface;
    data.mappings[1].requested_external_port = 4672;
    data.mappings[1].granted_external_endpoint.port = 52145;
    data.mappings[1].granted_external_endpoint.address = IpAddress::V4(88,11,22,4);
    data.mappings[1].granted_external_endpoint.source = EndpointSource::NatPmpPublicAddress;
    data.mappings[1].lifetime_seconds = 7200;
    data.mappings[1].effective_expiry_monotonic_ms = 7200000;
    return data;
}

void TestOwnershipProofRequiresExactPublishedPair() {
    NatPmpCleanupProof proof = CleanupProof();
    MapperResultData data = OwnershipResult();
    CHECK(CorrelatesNatPmpOwnershipProof(proof, data, 30));
    std::swap(proof.mappings[0], proof.mappings[1]);
    CHECK(CorrelatesNatPmpOwnershipProof(proof, data, 30));
    proof = CleanupProof();
    proof.mappings[2] = NatPmpCleanupMapping{
        NatPmpTransport::Tcp, 4711, 53111};
    proof.mapping_count = 3;
    CHECK(CorrelatesNatPmpOwnershipProof(proof, data, 30));
    NatPmpCleanupProof hostile = CleanupProof();
    hostile.gateway_address[3] = 2;
    CHECK(!CorrelatesNatPmpOwnershipProof(hostile, data, 30));
    hostile = CleanupProof(); hostile.interface_index = 18;
    CHECK(!CorrelatesNatPmpOwnershipProof(hostile, data, 30));
    hostile = CleanupProof(); hostile.generation = 32;
    CHECK(!CorrelatesNatPmpOwnershipProof(hostile, data, 30));
    hostile = CleanupProof(); hostile.mappings[0].external_port++;
    CHECK(!CorrelatesNatPmpOwnershipProof(hostile, data, 30));
    hostile = CleanupProof(); hostile.mapping_count = 1;
    CHECK(!CorrelatesNatPmpOwnershipProof(hostile, data, 30));
    data.mappings[1] = data.mappings[0];
    CHECK(!CorrelatesNatPmpOwnershipProof(CleanupProof(), data, 30));

    data = OwnershipResult();
    std::array<std::uint8_t, 32> digest{};
    digest[0] = 1;
    CHECK(ApplyNatPmpOwnershipProof(
        CleanupProof(), 30, digest, data));
    const MapperResult result(data);
    CHECK(result.IsStructurallyValid());
    LegacyMapperObservation observation{};
    CHECK(AdmitLegacyMapperObservation(result, 30, observation) ==
          LegacyMapperAdmissionStatus::Accepted);
    data = OwnershipResult();
    CHECK(!ApplyNatPmpOwnershipProof(
        CleanupProof(), 30, {}, data));
    CHECK(data.ownership == OwnershipState::Unverifiable);
    CHECK(!MapperResult(data).IsStructurallyValid());
}

void TestProductOwnershipPreimageAndCleanupDispatchPolicy() {
    const NatPmpCleanupProof proof = CleanupProof();
    const MapperResultData source = OwnershipResult();
    const NatPmpOwnershipPreimage first =
        BuildNatPmpOwnershipPreimage(proof, source, 30, 0x1234);
    CHECK(first.valid);
    CHECK(first.size > 0 && first.size <= first.bytes.size());

    MapperResultData reordered = source;
    std::swap(reordered.mappings[0], reordered.mappings[1]);
    const NatPmpOwnershipPreimage reordered_preimage =
        BuildNatPmpOwnershipPreimage(proof, reordered, 30, 0x1234);
    CHECK(reordered_preimage.valid);
    CHECK(first.size == reordered_preimage.size);
    CHECK(std::equal(first.bytes.begin(), first.bytes.begin() + first.size,
        reordered_preimage.bytes.begin()));

    NatPmpCleanupProof with_web = proof;
    with_web.mappings[2] = NatPmpCleanupMapping{
        NatPmpTransport::Tcp, 4711, 53111};
    with_web.mapping_count = 3;
    const NatPmpOwnershipPreimage web_preimage =
        BuildNatPmpOwnershipPreimage(with_web, source, 30, 0x1234);
    CHECK(web_preimage.valid);
    CHECK(first.size == web_preimage.size);
    CHECK(std::equal(first.bytes.begin(), first.bytes.begin() + first.size,
        web_preimage.bytes.begin()));

    const NatPmpOwnershipPreimage different_token =
        BuildNatPmpOwnershipPreimage(proof, source, 30, 0x1235);
    CHECK(different_token.valid);
    CHECK(!std::equal(first.bytes.begin(), first.bytes.begin() + first.size,
        different_token.bytes.begin()));
    CHECK(!BuildNatPmpOwnershipPreimage(proof, source, 30, 0).valid);
    CHECK(!BuildNatPmpOwnershipPreimage(proof, source, 31, 1).valid);

    std::array<std::uint8_t, 32> digest{};
    digest[0] = 0x5a;
    MapperResultData applied = source;
    CHECK(ApplyNatPmpOwnershipDigest(
        first, digest, proof, 30, applied));
    CHECK(applied.ownership == OwnershipState::OwnedByUs);
    CHECK(applied.ownership_identity_digest == digest);
    const MapperResult result(applied);
    CHECK(result.IsStructurallyValid());
    LegacyMapperObservation observation{};
    CHECK(AdmitLegacyMapperObservation(result, 30, observation) ==
          LegacyMapperAdmissionStatus::Accepted);
    MapperResultData unchanged = source;
    const MapperResultData original = unchanged;
    CHECK(!ApplyNatPmpOwnershipDigest(
        first, {}, proof, 30, unchanged));
    CHECK(unchanged.ownership == original.ownership);
    CHECK(unchanged.ownership_identity_digest ==
          original.ownership_identity_digest);

    MapperResultData altered = source;
    altered.mappings[0].granted_external_endpoint.port++;
    const MapperResultData altered_original = altered;
    CHECK(!ApplyNatPmpOwnershipDigest(
        first, digest, proof, 30, altered));
    CHECK(altered.ownership == altered_original.ownership);
    CHECK(altered.ownership_identity_digest ==
          altered_original.ownership_identity_digest);

    NatPmpOwnershipPreimage forged{};
    forged.valid = true;
    forged.size = 1;
    MapperResultData forged_target = source;
    const MapperResultData forged_original = forged_target;
    CHECK(!ApplyNatPmpOwnershipDigest(
        forged, digest, NatPmpCleanupProof{}, 30, forged_target));
    CHECK(forged_target.ownership == forged_original.ownership);
    CHECK(forged_target.ownership_identity_digest ==
          forged_original.ownership_identity_digest);

    CHECK(ResolveNatPmpCleanupGeneration(proof, 30) == 31);
    CHECK(ResolveNatPmpCleanupGeneration(proof, 31) == 31);
    CHECK(ResolveNatPmpCleanupGeneration(proof, 0) == 31);
    CHECK(ResolveNatPmpCleanupGeneration(proof, 29) == 29);
    CHECK(ResolveNatPmpCleanupGeneration(proof,
        (std::numeric_limits<std::uint64_t>::max)()) ==
        (std::numeric_limits<std::uint64_t>::max)());

    NatPmpCleanupProof live = proof;
    NatPmpCleanupContext context{};
    context.gateway_address = live.gateway_address;
    context.interface_index = live.interface_index;
    context.generation = ResolveNatPmpCleanupGeneration(live, 30);
    context.observed_monotonic_seconds = 9000;
    const NatPmpCleanupPlan plan = TakeNatPmpCleanupPlan(live, context);
    CHECK(plan.mapping_count == 2);
    CHECK(plan.mappings[0].internal_port == 4662);
    CHECK(plan.mappings[1].internal_port == 4672);
    CHECK(!live.IsValid());
    CHECK(TakeNatPmpCleanupPlan(live, context).IsEmpty());
}

void TestCleanupRequiresExactLiveSessionProof() {
    const NatPmpCleanupProof proof = CleanupProof();
    CHECK(proof.IsValid());
    CHECK(AllowsNatPmpCleanup(
        proof, CleanupRequest(proof.mappings[0])));
    CHECK(AllowsNatPmpCleanup(
        proof, CleanupRequest(proof.mappings[1])));

    NatPmpCleanupRequest wrong =
        CleanupRequest(proof.mappings[0]);
    wrong.gateway_address[3] = 2;
    CHECK(!AllowsNatPmpCleanup(proof, wrong));
    wrong = CleanupRequest(proof.mappings[0]);
    wrong.interface_index = 18;
    CHECK(!AllowsNatPmpCleanup(proof, wrong));
    wrong = CleanupRequest(proof.mappings[0]);
    wrong.generation = 30;
    CHECK(!AllowsNatPmpCleanup(proof, wrong));
    wrong = CleanupRequest(proof.mappings[0]);
    wrong.observed_monotonic_seconds = 9999;
    CHECK(!AllowsNatPmpCleanup(proof, wrong));
    wrong = CleanupRequest(proof.mappings[0]);
    wrong.observed_monotonic_seconds = 10000;
    CHECK(!AllowsNatPmpCleanup(proof, wrong));
    wrong = CleanupRequest(proof.mappings[0]);
    wrong.observed_monotonic_seconds = 10001;
    CHECK(!AllowsNatPmpCleanup(proof, wrong));
    wrong = CleanupRequest(proof.mappings[0]);
    wrong.mapping.internal_port = 4663;
    CHECK(!AllowsNatPmpCleanup(proof, wrong));
    wrong = CleanupRequest(proof.mappings[0]);
    wrong.mapping.external_port = 52145;
    CHECK(!AllowsNatPmpCleanup(proof, wrong));
    wrong = CleanupRequest(proof.mappings[0]);
    wrong.mapping.transport = NatPmpTransport::Udp;
    CHECK(!AllowsNatPmpCleanup(proof, wrong));
}

void TestCrashOrMalformedCleanupProofNeverDeletes() {
    const NatPmpCleanupProof proof = CleanupProof();
    CHECK(!AllowsNatPmpCleanup(
        NatPmpCleanupProof{},
        CleanupRequest(proof.mappings[0])));

    NatPmpCleanupProof malformed = proof;
    malformed.in_process_proof = false;
    CHECK(!malformed.IsValid());
    malformed = proof;
    malformed.generation = 0;
    CHECK(!malformed.IsValid());
    malformed = proof;
    malformed.expires_monotonic_seconds = 0;
    CHECK(!malformed.IsValid());
    malformed = proof;
    malformed.mapping_count = 0;
    CHECK(!malformed.IsValid());
    malformed = proof;
    malformed.mapping_count = 4;
    CHECK(!malformed.IsValid());
    malformed = proof;
    malformed.mappings[2] = malformed.mappings[0];
    malformed.mapping_count = 3;
    CHECK(!malformed.IsValid());
    malformed = proof;
    malformed.mappings[2] = malformed.mappings[0];
    malformed.mappings[2].external_port = 60000;
    malformed.mapping_count = 3;
    CHECK(!malformed.IsValid());
    malformed = proof;
    malformed.mappings[2] = NatPmpCleanupMapping{
        NatPmpTransport::Tcp, 4711, 0};
    malformed.mapping_count = 3;
    CHECK(!malformed.IsValid());

    malformed = proof;
    malformed.gateway_address = {127, 0, 0, 1};
    CHECK(!malformed.IsValid());
    malformed = proof;
    malformed.interface_index =
        kNatPmpMaximumInterfaceIndex + 1;
    CHECK(!malformed.IsValid());
}

void TestSessionCrashAndNaturalExpiryLifecycle() {
    NatPmpCleanupProof live = CleanupProof();
    const NatPmpCleanupRequest current =
        CleanupRequest(live.mappings[0]);
    NatPmpCleanupContext context{};
    context.gateway_address = current.gateway_address;
    context.interface_index = current.interface_index;
    context.generation = current.generation;
    context.observed_monotonic_seconds =
        current.observed_monotonic_seconds;
    const NatPmpCleanupPlan active =
        TakeNatPmpCleanupPlan(live, context);
    CHECK(active.mapping_count == 2);
    CHECK(active.mappings[0].internal_port == 4662);
    CHECK(active.mappings[1].internal_port == 4672);
    CHECK(!live.IsValid());

    // A restarted process has no in-memory proof. Port coincidence alone
    // must never recreate authority to delete the router rule.
    NatPmpCleanupProof after_crash{};
    const NatPmpCleanupPlan restarted =
        TakeNatPmpCleanupPlan(after_crash, context);
    CHECK(restarted.IsEmpty());
    CHECK(!after_crash.IsValid());

    // Once the conservative deadline is reached, the bounded lease is left
    // for the router to expire naturally; no ambiguous DELETE is emitted.
    NatPmpCleanupProof expired = CleanupProof();
    context.observed_monotonic_seconds =
        expired.expires_monotonic_seconds;
    const NatPmpCleanupPlan natural_expiry =
        TakeNatPmpCleanupPlan(expired, context);
    CHECK(natural_expiry.IsEmpty());
    CHECK(!expired.IsValid());
}

void TestWrongGenerationDoesNotConsumeCleanupProof() {
    NatPmpCleanupProof proof = CleanupProof();
    NatPmpCleanupContext context{};
    context.gateway_address = proof.gateway_address;
    context.interface_index = proof.interface_index;
    context.generation = proof.generation - 1;
    context.observed_monotonic_seconds = 100;
    CHECK(TakeNatPmpCleanupPlan(proof, context).IsEmpty());
    CHECK(proof.IsValid());
    context.generation = proof.generation;
    CHECK(TakeNatPmpCleanupPlan(proof, context).mapping_count == 2);
    CHECK(!proof.IsValid());
    proof = CleanupProof();
    context.generation = proof.generation - 2;
    CHECK(TakeNatPmpCleanupPlan(proof, context).IsEmpty());
    CHECK(!proof.IsValid());
    proof = CleanupProof();
    context.generation = proof.generation + 1;
    CHECK(TakeNatPmpCleanupPlan(proof, context).IsEmpty());
    CHECK(!proof.IsValid());
    proof = CleanupProof();
    context.gateway_address[3]++;
    context.generation = proof.generation;
    CHECK(TakeNatPmpCleanupPlan(proof, context).IsEmpty());
    CHECK(!proof.IsValid());
    proof = CleanupProof();
    proof.in_process_proof = false;
    context.gateway_address = CleanupProof().gateway_address;
    CHECK(TakeNatPmpCleanupPlan(proof, context).IsEmpty());
    CHECK(!proof.IsValid());
}

} // namespace

int main() {
    TestCompletePairCommitsAlternativePortsExactlyOnce();
    TestInitialUdpFailureRequiresExactTcpRollback();
    TestRefreshUdpFailurePreservesPreviousPair();
    TestFailureDispositionInvalidatesAPreResetPair();
    TestRejectedResponsesStillCarryCorrelatedEpochEvidence();
    TestTcpFailurePublishesAndRollsBackNothing();
    TestTcpOnlyOperationCanCommit();
    TestMalformedOrWrongTransportProjectionsFailClosed();
    TestLeaseDeadlineStartsBeforeMapAndSaturates();
    TestCleanupGenerationMatchesHostAcceptance();
    TestCleanupRequiresExactLiveSessionProof();
    TestCrashOrMalformedCleanupProofNeverDeletes();
    TestSessionCrashAndNaturalExpiryLifecycle();
    TestWrongGenerationDoesNotConsumeCleanupProof();
    TestOwnershipProofRequiresExactPublishedPair();
    TestProductOwnershipPreimageAndCleanupDispatchPolicy();
    std::printf(
        "test_natpmp_pair_transaction: %d checks, %d failures\n",
        checks, failures);
    return failures == 0 ? 0 : 1;
}
