#include "natmap/upnp_mapping_result.h"

#include <cstdio>
#include <limits>

using namespace natmap;

namespace {

int failures = 0;
int checks = 0;

#define CHECK(expr) do { ++checks; if (!(expr)) { ++failures; \
    std::printf("FAIL line %d: %s\n", __LINE__, #expr); } } while (0)

UpnpPairResultInput ValidInput() {
    UpnpPairResultInput input{};
    input.request = MappingRequestContext{
        71, 9, MappingOperation::Initial};
    input.gateway_address = IpAddress::V4(192, 168, 68, 1);
    input.local_address = IpAddress::V4(192, 168, 68, 54);
    input.external_address = IpAddress::V4(88, 11, 22, 44);
    input.tcp = UpnpTransportObservation{
        Transport::Tcp, 4662, 4662, 52144, true, true, true};
    input.udp = UpnpTransportObservation{
        Transport::Udp, 4672, 4672, 52145, true, true, true};
    input.lifetime_seconds = 3600;
    input.now_monotonic_ms = 1000;
    input.ownership_identity_digest[0] = 1;
    input.failure_protocol_code = 501;
    input.failure_reason = ReasonCode::InvalidResponse;
    return input;
}

void TestExactInitialPair() {
    const MapperResultData data =
        BuildUpnpPairMapperResult(ValidInput());
    CHECK(data.mapper == MapperKind::UpnpIgd);
    CHECK(data.source == MapperSource::UpnpIgd);
    CHECK(data.gateway.address.bytes[0] == 192);
    CHECK(data.gateway.port == 1900);
    CHECK(data.mapping_count == 2);
    CHECK(data.mappings[0].transport == Transport::Tcp);
    CHECK(data.mappings[0].local_endpoint.port == 4662);
    CHECK(data.mappings[0].requested_external_port == 4662);
    CHECK(data.mappings[0].granted_external_endpoint.port == 52144);
    CHECK(data.mappings[1].transport == Transport::Udp);
    CHECK(data.mappings[1].granted_external_endpoint.port == 52145);
    CHECK(data.mappings[0].lifetime_seconds == 3600);
    CHECK(data.mappings[0].effective_expiry_monotonic_ms == 3601000);
    CHECK(data.ownership == OwnershipState::OwnedByUs);
    CHECK(data.verification == VerificationState::Pending);
    CHECK(data.status == MappingStatus::Created);
    CHECK(data.reason == ReasonCode::None);
    CHECK(data.protocol_result_code == 0);
    CHECK(MapperResult(data).IsStructurallyValid());
}

void TestExactRefreshPair() {
    UpnpPairResultInput input = ValidInput();
    input.request.operation = MappingOperation::Refresh;
    input.lifetime_seconds = 0;
    const MapperResultData data =
        BuildUpnpPairMapperResult(input);
    CHECK(data.status == MappingStatus::Renewed);
    CHECK(data.mappings[0].effective_expiry_monotonic_ms == 0);
    CHECK(data.mappings[1].effective_expiry_monotonic_ms == 0);
    CHECK(MapperResult(data).IsStructurallyValid());
}

void TestFailureIsAtomic() {
    UpnpPairResultInput input = ValidInput();
    input.udp.readback_matches = false;
    const MapperResultData data =
        BuildUpnpPairMapperResult(input);
    CHECK(data.status == MappingStatus::Failed);
    CHECK(data.mapping_count == 0);
    CHECK(data.ownership == OwnershipState::Unknown);
    CHECK(data.verification == VerificationState::Failed);
    CHECK(data.reason == ReasonCode::InvalidResponse);
    CHECK(data.protocol_result_code == 501);
    CHECK(MapperResult(data).IsStructurallyValid());

    input = ValidInput();
    input.tcp.ownership_matches = false;
    CHECK(BuildUpnpPairMapperResult(input).mapping_count == 0);
    input = ValidInput();
    input.ownership_identity_digest = {};
    CHECK(BuildUpnpPairMapperResult(input).mapping_count == 0);
    input = ValidInput();
    input.udp.granted_external_port = 0;
    CHECK(BuildUpnpPairMapperResult(input).mapping_count == 0);
    input = ValidInput();
    input.external_address = {};
    CHECK(BuildUpnpPairMapperResult(input).mapping_count == 0);
}

void TestReasonNeverEmptyOnFailure() {
    UpnpPairResultInput input = ValidInput();
    input.tcp.readback_matches = false;
    input.failure_reason = ReasonCode::None;
    const MapperResultData data =
        BuildUpnpPairMapperResult(input);
    CHECK(data.reason == ReasonCode::InvalidResponse);
    CHECK(MapperResult(data).IsStructurallyValid());
}

void TestDeleteCannotProduceAPair() {
    UpnpPairResultInput input = ValidInput();
    input.request.operation = MappingOperation::Delete;
    const MapperResultData data =
        BuildUpnpPairMapperResult(input);
    CHECK(data.status == MappingStatus::Failed);
    CHECK(data.mapping_count == 0);
    CHECK(data.operation == MappingOperation::Delete);
    CHECK(data.reason == ReasonCode::InvalidResponse);
    CHECK(MapperResult(data).IsStructurallyValid());
}

void TestRollbackRequiresExactOwnedReadback() {
    UpnpTransportObservation tcp =
        ValidInput().tcp;
    CHECK(ShouldRollbackUpnpMappingAfterAtomicFailure(tcp));
    tcp.created_by_operation = false;
    CHECK(!ShouldRollbackUpnpMappingAfterAtomicFailure(tcp));
    tcp = ValidInput().tcp;
    tcp.readback_matches = false;
    CHECK(!ShouldRollbackUpnpMappingAfterAtomicFailure(tcp));
    tcp = ValidInput().tcp;
    tcp.ownership_matches = false;
    CHECK(!ShouldRollbackUpnpMappingAfterAtomicFailure(tcp));
    tcp = ValidInput().tcp;
    tcp.transport = static_cast<Transport>(255);
    CHECK(!ShouldRollbackUpnpMappingAfterAtomicFailure(tcp));
    tcp = ValidInput().tcp;
    tcp.granted_external_port = 0;
    CHECK(!ShouldRollbackUpnpMappingAfterAtomicFailure(tcp));
    UpnpTransportObservation udp = ValidInput().udp;
    CHECK(ShouldRollbackUpnpMappingAfterAtomicFailure(udp));
}

void TestExpirySaturates() {
    UpnpPairResultInput input = ValidInput();
    input.now_monotonic_ms =
        (std::numeric_limits<std::uint64_t>::max)() - 1;
    const MapperResultData data =
        BuildUpnpPairMapperResult(input);
    CHECK(data.mappings[0].effective_expiry_monotonic_ms ==
          (std::numeric_limits<std::uint64_t>::max)());
    CHECK(MapperResult(data).IsStructurallyValid());
}

} // namespace

int main() {
    TestExactInitialPair();
    TestExactRefreshPair();
    TestFailureIsAtomic();
    TestReasonNeverEmptyOnFailure();
    TestDeleteCannotProduceAPair();
    TestRollbackRequiresExactOwnedReadback();
    TestExpirySaturates();
    std::printf("test_upnp_mapping_result: %d checks, %d failures\n",
                checks, failures);
    return failures == 0 ? 0 : 1;
}
