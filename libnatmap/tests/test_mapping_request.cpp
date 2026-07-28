#include "natmap/mapping_request.h"

#include <cstdio>
#include <limits>
#include <type_traits>

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

std::array<std::uint8_t, 12> Nonce() {
    std::array<std::uint8_t, 12> value{};
    value[0] = 1;
    return value;
}

std::array<std::uint8_t, 32> Digest() {
    std::array<std::uint8_t, 32> value{};
    value[0] = 1;
    return value;
}

MapperResult ResultFor(const MappingRequestContext& context) {
    MapperResultData data{};
    data.mapper = MapperKind::Pcp;
    data.source = MapperSource::PcpCpe;
    data.gateway = Ep(192, 168, 68, 1, 5351);
    data.mapping_count = 2;
    data.mappings[0].transport = Transport::Tcp;
    data.mappings[0].local_endpoint = Ep(192, 168, 68, 54, 4662);
    data.mappings[0].requested_external_port = 4662;
    data.mappings[0].granted_external_endpoint =
        Ep(88, 11, 22, 4, 52144, EndpointSource::PcpMap);
    data.mappings[0].lifetime_seconds = 3600;
    data.mappings[0].effective_expiry_monotonic_ms = 3601000;
    data.mappings[1].transport = Transport::Udp;
    data.mappings[1].local_endpoint = Ep(192, 168, 68, 54, 4672);
    data.mappings[1].requested_external_port = 4672;
    data.mappings[1].granted_external_endpoint =
        Ep(88, 11, 22, 4, 52145, EndpointSource::PcpMap);
    data.mappings[1].lifetime_seconds = 3600;
    data.mappings[1].effective_expiry_monotonic_ms = 3601000;
    data.ownership_nonce = Nonce();
    data.ownership = OwnershipState::OwnedByUs;
    data.verification = VerificationState::Verified;
    data.evidence_digest = Digest();
    data.request_id = context.request_id;
    data.topology_generation = context.topology_generation;
    data.operation = context.operation;
    data.status = context.operation == MappingOperation::Refresh
        ? MappingStatus::Renewed : MappingStatus::Created;
    return MapperResult(data);
}

MapperResult DeletedResultFor(const MappingRequestContext& context) {
    MapperResultData data{};
    data.mapper = MapperKind::Pcp;
    data.source = MapperSource::PcpCpe;
    data.gateway = Ep(192, 168, 68, 1, 5351);
    data.ownership_nonce = Nonce();
    data.ownership = OwnershipState::OwnedByUs;
    data.verification = VerificationState::NotAttempted;
    data.request_id = context.request_id;
    data.topology_generation = context.topology_generation;
    data.operation = MappingOperation::Delete;
    data.status = MappingStatus::Deleted;
    return MapperResult(data);
}

void TestSequenceIssuesUniqueTypedRequests() {
    MappingRequestSequence sequence;
    const RequestIssue initial =
        sequence.Issue(7, MappingOperation::Initial);
    const RequestIssue refresh =
        sequence.Issue(7, MappingOperation::Refresh);
    const RequestIssue deletion =
        sequence.Issue(8, MappingOperation::Delete);

    CHECK(initial.IsIssued());
    CHECK(refresh.IsIssued());
    CHECK(deletion.IsIssued());
    CHECK(initial.context.request_id == 1);
    CHECK(refresh.context.request_id == 2);
    CHECK(deletion.context.request_id == 3);
    CHECK(initial.context.topology_generation == 7);
    CHECK(refresh.context.operation == MappingOperation::Refresh);
    CHECK(deletion.context.topology_generation == 8);
}

void TestSequenceRejectsInvalidAndNeverWraps() {
    MappingRequestSequence sequence;
    CHECK(sequence.Issue(0, MappingOperation::Initial).status ==
          RequestIssueStatus::InvalidTopology);
    CHECK(sequence.Issue(1, static_cast<MappingOperation>(255)).status ==
          RequestIssueStatus::InvalidOperation);
    CHECK(sequence.Issue(1, MappingOperation::Initial).
          context.request_id == 1);

    MappingRequestSequence last(
        std::numeric_limits<std::uint64_t>::max());
    const RequestIssue maximum =
        last.Issue(9, MappingOperation::Initial);
    CHECK(maximum.IsIssued());
    CHECK(maximum.context.request_id ==
          std::numeric_limits<std::uint64_t>::max());
    CHECK(last.Issue(9, MappingOperation::Refresh).status ==
          RequestIssueStatus::Exhausted);

    MappingRequestSequence invalid(0);
    CHECK(invalid.Issue(9, MappingOperation::Initial).status ==
          RequestIssueStatus::Exhausted);
}

void TestCoordinatorStateCannotBeDuplicated() {
    CHECK(!std::is_copy_constructible<MappingRequestSequence>::value);
    CHECK(!std::is_copy_assignable<MappingRequestSequence>::value);
    CHECK(!std::is_move_constructible<MappingRequestSequence>::value);
    CHECK(!std::is_move_assignable<MappingRequestSequence>::value);
    CHECK(!std::is_copy_constructible<MappingResultGate>::value);
    CHECK(!std::is_copy_assignable<MappingResultGate>::value);
    CHECK(!std::is_move_constructible<MappingResultGate>::value);
    CHECK(!std::is_move_assignable<MappingResultGate>::value);
}

void TestGateAppliesExactlyOnce() {
    MappingRequestSequence sequence;
    const MappingRequestContext context =
        sequence.Issue(10, MappingOperation::Initial).context;
    const MapperResult result = ResultFor(context);
    MappingResultGate gate;

    CHECK(gate.Arm(context, 10));
    CHECK(gate.has_pending());
    CHECK(gate.Consume(result, 10) == ResultAcceptance::Apply);
    CHECK(!gate.has_pending());
    CHECK(gate.Consume(result, 10) ==
          ResultAcceptance::NoPendingRequest);
    CHECK(!gate.Arm(context, 10));
}

void TestDeleteResultAppliesExactlyOnce() {
    MappingRequestSequence sequence;
    const MappingRequestContext context =
        sequence.Issue(10, MappingOperation::Delete).context;
    const MapperResult result = DeletedResultFor(context);
    MappingResultGate gate;

    CHECK(result.IsStructurallyValid());
    CHECK(gate.Arm(context, 10));
    CHECK(gate.Consume(result, 10) == ResultAcceptance::Apply);
    CHECK(gate.Consume(result, 10) ==
          ResultAcceptance::NoPendingRequest);
}

void TestNewerRequestSurvivesStaleResponse() {
    MappingRequestSequence sequence;
    const MappingRequestContext oldContext =
        sequence.Issue(11, MappingOperation::Initial).context;
    const MappingRequestContext newContext =
        sequence.Issue(11, MappingOperation::Refresh).context;
    MappingResultGate gate;

    CHECK(gate.Arm(oldContext, 11));
    CHECK(gate.Arm(newContext, 11));
    CHECK(gate.Consume(ResultFor(oldContext), 11) ==
          ResultAcceptance::StaleRequest);
    CHECK(gate.has_pending());
    CHECK(gate.pending().request_id == newContext.request_id);
    CHECK(gate.Consume(ResultFor(newContext), 11) ==
          ResultAcceptance::Apply);
}

void TestTopologyChangeInvalidatesPending() {
    MappingRequestSequence sequence;
    const MappingRequestContext context =
        sequence.Issue(12, MappingOperation::Initial).context;
    MappingResultGate gate;
    CHECK(gate.Arm(context, 12));
    CHECK(gate.Consume(ResultFor(context), 13) ==
          ResultAcceptance::StaleTopology);
    CHECK(!gate.has_pending());
    CHECK(!gate.Arm(context, 13));
    const MappingRequestContext replacement =
        sequence.Issue(13, MappingOperation::Initial).context;
    CHECK(gate.Arm(replacement, 13));
    CHECK(gate.Consume(ResultFor(replacement), 13) ==
          ResultAcceptance::Apply);
}

void TestResultTopologyMismatchDoesNotDisplaceCurrent() {
    MappingRequestSequence sequence;
    const MappingRequestContext context =
        sequence.Issue(14, MappingOperation::Initial).context;
    MappingRequestContext stale = context;
    stale.topology_generation = 13;
    MappingResultGate gate;
    CHECK(gate.Arm(context, 14));
    CHECK(gate.Consume(ResultFor(stale), 14) ==
          ResultAcceptance::StaleTopology);
    CHECK(gate.has_pending());
    CHECK(gate.Consume(ResultFor(context), 14) ==
          ResultAcceptance::Apply);
}

void TestOperationMismatchDoesNotDisplaceCurrent() {
    MappingRequestSequence sequence;
    const MappingRequestContext context =
        sequence.Issue(15, MappingOperation::Initial).context;
    MappingRequestContext wrong = context;
    wrong.operation = MappingOperation::Refresh;
    MappingResultGate gate;
    CHECK(gate.Arm(context, 15));
    CHECK(gate.Consume(ResultFor(wrong), 15) ==
          ResultAcceptance::OperationMismatch);
    CHECK(gate.has_pending());
    CHECK(gate.Consume(ResultFor(context), 15) ==
          ResultAcceptance::Apply);
}

void TestRequestIdMismatchDoesNotDisplaceCurrent() {
    MappingRequestSequence sequence;
    const MappingRequestContext context =
        sequence.Issue(15, MappingOperation::Initial).context;
    MappingRequestContext wrong = context;
    ++wrong.request_id;
    MappingResultGate gate;
    CHECK(gate.Arm(context, 15));
    CHECK(gate.Consume(ResultFor(wrong), 15) ==
          ResultAcceptance::StaleRequest);
    CHECK(gate.has_pending());
    CHECK(gate.pending().request_id == context.request_id);
    CHECK(gate.Consume(ResultFor(context), 15) ==
          ResultAcceptance::Apply);
}

void TestInvalidResultDoesNotDisplaceCurrent() {
    MappingRequestSequence sequence;
    const MappingRequestContext context =
        sequence.Issue(16, MappingOperation::Initial).context;
    MapperResultData invalid = ResultFor(context).data();
    invalid.request_id = 0;
    MappingResultGate gate;
    CHECK(gate.Arm(context, 16));
    CHECK(gate.Consume(MapperResult(invalid), 16) ==
          ResultAcceptance::Invalid);
    CHECK(gate.has_pending());
    CHECK(gate.Consume(ResultFor(context), 16) ==
          ResultAcceptance::Apply);
}

void TestArmIsMonotonicAndClosed() {
    MappingResultGate gate;
    CHECK(!gate.Arm({}, 1));
    CHECK(!gate.Arm(
        MappingRequestContext{1, 1,
            static_cast<MappingOperation>(255)}, 1));
    CHECK(!gate.Arm(
        MappingRequestContext{1, 1, MappingOperation::Initial}, 0));
    CHECK(!gate.Arm(
        MappingRequestContext{1, 2, MappingOperation::Initial}, 1));
    CHECK(gate.Arm(
        MappingRequestContext{1, 1, MappingOperation::Initial}, 1));
    CHECK(!gate.Arm(
        MappingRequestContext{1, 1, MappingOperation::Refresh}, 1));
    CHECK(!gate.Arm(
        MappingRequestContext{0, 1, MappingOperation::Initial}, 1));
    CHECK(gate.pending().request_id == 1);
}

} // namespace

int main() {
    TestSequenceIssuesUniqueTypedRequests();
    TestSequenceRejectsInvalidAndNeverWraps();
    TestCoordinatorStateCannotBeDuplicated();
    TestGateAppliesExactlyOnce();
    TestDeleteResultAppliesExactlyOnce();
    TestNewerRequestSurvivesStaleResponse();
    TestTopologyChangeInvalidatesPending();
    TestResultTopologyMismatchDoesNotDisplaceCurrent();
    TestOperationMismatchDoesNotDisplaceCurrent();
    TestRequestIdMismatchDoesNotDisplaceCurrent();
    TestInvalidResultDoesNotDisplaceCurrent();
    TestArmIsMonotonicAndClosed();
    std::printf("test_mapping_request: %d checks, %d failures\n",
                checks, failures);
    return failures == 0 ? 0 : 1;
}
