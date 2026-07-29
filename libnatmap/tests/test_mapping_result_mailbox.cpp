#include "natmap/mapping_result_mailbox.h"
#include "natmap/pcp_codec.h"

#include <cstdio>

using namespace natmap;

namespace {

int failures = 0;
int checks = 0;

#define CHECK(expr) do { ++checks; if (!(expr)) { ++failures; \
    std::printf("FAIL line %d: %s\n", __LINE__, #expr); } } while (0)

MapperResultData Envelope(std::uint64_t request_id) {
    MapperResultData data{};
    data.request_id = request_id;
    data.topology_generation = 7;
    data.operation = MappingOperation::Initial;
    data.protocol_result_code =
        static_cast<std::uint32_t>(request_id);
    return data;
}

IpAddress V4(std::uint8_t a, std::uint8_t b,
             std::uint8_t c, std::uint8_t d) {
    IpAddress address{};
    address.family = AddressFamily::IPv4;
    address.bytes[0] = a;
    address.bytes[1] = b;
    address.bytes[2] = c;
    address.bytes[3] = d;
    return address;
}

Endpoint Ep(const IpAddress& address, std::uint16_t port,
            EndpointSource source) {
    Endpoint endpoint{};
    endpoint.address = address;
    endpoint.port = port;
    endpoint.source = source;
    return endpoint;
}

TransportMappingResult Mapping(
    Transport transport, const Endpoint& local,
    const Endpoint& external) {
    TransportMappingResult mapping{};
    mapping.transport = transport;
    mapping.local_endpoint = local;
    mapping.requested_external_port = local.port;
    mapping.granted_external_endpoint = external;
    mapping.lifetime_seconds = 3600;
    mapping.effective_expiry_monotonic_ms = 3600001;
    return mapping;
}

PcpUpstreamResultBundle ValidPcpBundle(
    PcpUpstreamResultBundle::Outcome outcome) {
    const IpAddress lan = V4(192, 168, 68, 54);
    const IpAddress cpeGateway = V4(192, 168, 68, 1);
    const IpAddress intermediate = V4(10, 0, 0, 9);
    const IpAddress upstreamGateway = V4(10, 0, 0, 1);
    const IpAddress publicAddress = V4(8, 8, 8, 8);

    PcpUpstreamResultBundle bundle{};
    bundle.cpe = Envelope(41);
    bundle.cpe.mapper = MapperKind::Pcp;
    bundle.cpe.source = MapperSource::PcpCpe;
    bundle.cpe.gateway = Ep(cpeGateway, 5351,
                            EndpointSource::LocalInterface);
    bundle.cpe.request_interface_index = 12;
    bundle.cpe.request_local_address = lan;
    bundle.cpe.mapping_count = 2;
    bundle.cpe.mappings[0] = Mapping(
        Transport::Tcp,
        Ep(lan, 4662, EndpointSource::LocalInterface),
        Ep(intermediate, 14662, EndpointSource::PcpMap));
    bundle.cpe.mappings[1] = Mapping(
        Transport::Udp,
        Ep(lan, 4672, EndpointSource::LocalInterface),
        Ep(intermediate, 14672, EndpointSource::PcpMap));
    bundle.cpe.status = MappingStatus::Created;
    bundle.cpe.protocol_result_code = 0;
    bundle.cpe.ownership = OwnershipState::OwnedByUs;
    bundle.cpe.ownership_nonce[0] = 1;

    bundle.upstream = bundle.cpe;
    bundle.upstream.source = MapperSource::PcpUpstream;
    bundle.upstream.gateway =
        Ep(upstreamGateway, 5351,
           EndpointSource::LocalInterface);
    bundle.upstream.mappings[0] = Mapping(
        Transport::Tcp,
        Ep(intermediate, 14662, EndpointSource::LocalInterface),
        Ep(publicAddress, 24662, EndpointSource::PcpMap));
    bundle.upstream.mappings[1] = Mapping(
        Transport::Udp,
        Ep(intermediate, 14672, EndpointSource::LocalInterface),
        Ep(publicAddress, 24672, EndpointSource::PcpMap));
    bundle.upstream.ownership_nonce[0] = 2;
    bundle.pcp_client_address = intermediate;
    bundle.authorized_evidence.mapper_wan_address = intermediate;
    bundle.authorized_evidence.mapper_origin = NetworkOrigin::Native;
    bundle.authorized_evidence.interface_index = 12;
    bundle.authorized_evidence.evidence_count = 1;
    bundle.authorized_evidence.evidence[0].address =
        upstreamGateway;
    bundle.authorized_evidence.evidence[0].interface_index = 12;
    bundle.authorized_evidence.evidence[0].source =
        GatewayCandidateSource::ExplicitConfiguration;
    bundle.authorized_evidence.evidence[0].interface_present = true;
    bundle.outcome = outcome;

    if (outcome != PcpUpstreamResultBundle::Outcome::Mapped) {
        bundle.upstream.mapping_count = 0;
        bundle.upstream.mappings = {};
        bundle.upstream.ownership = OwnershipState::Unknown;
        bundle.upstream.ownership_nonce = {};
        bundle.upstream.status = MappingStatus::Failed;
        bundle.upstream.reason =
            outcome == PcpUpstreamResultBundle::Outcome::Denied
                ? ReasonCode::OperatorDenied
                : ReasonCode::NoRoute;
        bundle.upstream.verification = VerificationState::Failed;
        bundle.upstream.protocol_result_code =
            outcome == PcpUpstreamResultBundle::Outcome::Denied
                ? static_cast<std::uint32_t>(
                    PcpResultCode::NotAuthorized)
                : static_cast<std::uint32_t>(
                    PcpResultCode::NetworkFailure);
    }
    if (outcome == PcpUpstreamResultBundle::Outcome::Absent) {
        bundle.authorized_evidence = {};
        bundle.upstream.gateway = bundle.cpe.gateway;
        bundle.upstream.reason = ReasonCode::NoGateway;
        bundle.upstream.protocol_result_code =
            static_cast<std::uint32_t>(PcpResultCode::Success);
    }
    return bundle;
}

void TestExactOutOfOrderDelivery() {
    MappingResultMailbox mailbox;
    const MailboxPublish first = mailbox.Publish(Envelope(11));
    const MailboxPublish second = mailbox.Publish(Envelope(12));
    CHECK(first.IsPublished());
    CHECK(second.IsPublished());
    CHECK(first.delivery_id == 1);
    CHECK(second.delivery_id == 2);
    CHECK(mailbox.pending_count() == 2);

    MapperResultData data{};
    CHECK(mailbox.Take(second.delivery_id, data));
    CHECK(data.request_id == 12);
    CHECK(mailbox.Take(first.delivery_id, data));
    CHECK(data.request_id == 11);
    CHECK(mailbox.pending_count() == 0);
    CHECK(!mailbox.Take(first.delivery_id, data));
}

void TestInvalidIdsAndEnvelopesFailClosed() {
    MappingResultMailbox mailbox;
    MapperResultData invalid = Envelope(1);
    invalid.request_id = 0;
    CHECK(mailbox.Publish(invalid).status ==
          MailboxPublishStatus::InvalidEnvelope);
    CHECK(mailbox.pending_count() == 0);

    MapperResultData output = Envelope(99);
    CHECK(!mailbox.Take(0, output));
    CHECK(!mailbox.Take(0x80000000u, output));
    CHECK(output.request_id == 99);
}

void TestDiscardAndClear() {
    MappingResultMailbox mailbox;
    const MailboxPublish first = mailbox.Publish(Envelope(1));
    const MailboxPublish second = mailbox.Publish(Envelope(2));
    CHECK(mailbox.Discard(first.delivery_id));
    CHECK(!mailbox.Discard(first.delivery_id));
    CHECK(mailbox.pending_count() == 1);
    mailbox.Clear();
    CHECK(mailbox.pending_count() == 0);
    MapperResultData output{};
    CHECK(!mailbox.Take(second.delivery_id, output));
}

void TestBoundAndNoWrap() {
    MappingResultMailbox mailbox;
    for (std::size_t i = 0;
         i < MappingResultMailbox::kMaximumPending; ++i)
        CHECK(mailbox.Publish(Envelope(i + 1)).IsPublished());
    CHECK(mailbox.Publish(Envelope(1000)).status ==
          MailboxPublishStatus::Full);
    CHECK(mailbox.pending_count() ==
          MappingResultMailbox::kMaximumPending);

    MappingResultMailbox last(
        MappingResultMailbox::kMaximumDeliveryId);
    const MailboxPublish maximum = last.Publish(Envelope(1));
    CHECK(maximum.IsPublished());
    CHECK(maximum.delivery_id ==
          MappingResultMailbox::kMaximumDeliveryId);
    CHECK(last.Publish(Envelope(2)).status ==
          MailboxPublishStatus::Exhausted);

    MappingResultMailbox invalid(0);
    CHECK(invalid.Publish(Envelope(1)).status ==
          MailboxPublishStatus::Exhausted);
}

void TestCloseFencesLatePublish() {
    MappingResultMailbox mailbox;
    const MailboxPublish queued = mailbox.Publish(Envelope(1));
    CHECK(queued.IsPublished());
    CHECK(mailbox.pending_count() == 1);
    CHECK(mailbox.Close());
    CHECK(mailbox.pending_count() == 0);
    CHECK(!mailbox.Close());
    CHECK(mailbox.Publish(Envelope(2)).status ==
          MailboxPublishStatus::Closed);
    MapperResultData output{};
    CHECK(!mailbox.Take(queued.delivery_id, output));
}

void TestPcpUpstreamBundleIsAtomicAndOrdered() {
    PcpUpstreamResultBundle bundle =
        ValidPcpBundle(PcpUpstreamResultBundle::Outcome::Mapped);
    MappingResultMailbox mailbox;
    const MailboxPublish published =
        mailbox.PublishPcpUpstreamBundle(bundle);
    CHECK(published.IsPublished());
    PcpUpstreamResultBundle taken{};
    CHECK(mailbox.TakePcpUpstreamBundle(
        published.delivery_id, taken));
    CHECK(taken.cpe.request_id == 41);
    CHECK(taken.upstream.source == MapperSource::PcpUpstream);
    CHECK(mailbox.pending_count() == 0);
}

void TestWrongPayloadTypeDoesNotConsumeDelivery() {
    MappingResultMailbox mailbox;
    const MailboxPublish ordinary = mailbox.Publish(Envelope(51));
    CHECK(ordinary.IsPublished());
    PcpUpstreamResultBundle bundle{};
    CHECK(!mailbox.TakePcpUpstreamBundle(ordinary.delivery_id, bundle));
    MapperResultData ordinaryTaken{};
    CHECK(mailbox.Take(ordinary.delivery_id, ordinaryTaken));
    CHECK(ordinaryTaken.request_id == 51);
    CHECK(!mailbox.Take(ordinary.delivery_id, ordinaryTaken));

    const MailboxPublish bundled = mailbox.PublishPcpUpstreamBundle(
        ValidPcpBundle(PcpUpstreamResultBundle::Outcome::Mapped));
    CHECK(bundled.IsPublished());
    CHECK(!mailbox.Take(bundled.delivery_id, ordinaryTaken));
    CHECK(mailbox.TakePcpUpstreamBundle(bundled.delivery_id, bundle));
    CHECK(bundle.cpe.request_id == 41);
    CHECK(!mailbox.TakePcpUpstreamBundle(bundled.delivery_id, bundle));
}

void TestPcpNegativeEvidenceAndRouteValidation() {
    PcpUpstreamResultBundle absent =
        ValidPcpBundle(PcpUpstreamResultBundle::Outcome::Absent);
    CHECK(absent.IsValid());
    absent.authorized_evidence.evidence_count = 1;
    CHECK(!absent.IsValid());
    absent =
        ValidPcpBundle(PcpUpstreamResultBundle::Outcome::Absent);
    absent.authorized_evidence.evidence[0].address =
        V4(10, 0, 0, 1);
    CHECK(!absent.IsValid());

    PcpUpstreamResultBundle denied =
        ValidPcpBundle(PcpUpstreamResultBundle::Outcome::Denied);
    CHECK(denied.IsValid());
    PcpUpstreamResultBundle hostile = denied;
    hostile.upstream.gateway.address.bytes[3] = 2;
    CHECK(!hostile.IsValid());
    hostile = denied;
    hostile.authorized_evidence.evidence[0].address.bytes[4] = 1;
    CHECK(!hostile.IsValid());
    hostile = denied;
    hostile.upstream.request_interface_index = 13;
    CHECK(!hostile.IsValid());
    hostile = denied;
    hostile.upstream.request_id = 42;
    CHECK(!hostile.IsValid());
    hostile = denied;
    hostile.pcp_client_address.bytes[3] = 10;
    CHECK(!hostile.IsValid());
    hostile = denied;
    hostile.upstream.verification = VerificationState::NotAttempted;
    CHECK(!hostile.IsValid());
    hostile = denied;
    hostile.upstream.protocol_result_code = 0;
    CHECK(!hostile.IsValid());
    PcpUpstreamResultBundle failed =
        ValidPcpBundle(PcpUpstreamResultBundle::Outcome::Failed);
    CHECK(failed.IsValid());
    failed.upstream.protocol_result_code =
        static_cast<std::uint32_t>(PcpResultCode::NotAuthorized);
    CHECK(!failed.IsValid());
}

} // namespace

int main() {
    TestExactOutOfOrderDelivery();
    TestInvalidIdsAndEnvelopesFailClosed();
    TestDiscardAndClear();
    TestBoundAndNoWrap();
    TestCloseFencesLatePublish();
    TestPcpUpstreamBundleIsAtomicAndOrdered();
    TestWrongPayloadTypeDoesNotConsumeDelivery();
    TestPcpNegativeEvidenceAndRouteValidation();
    std::printf(
        "test_mapping_result_mailbox: %d checks, %d failures\n",
        checks, failures);
    return failures == 0 ? 0 : 1;
}
