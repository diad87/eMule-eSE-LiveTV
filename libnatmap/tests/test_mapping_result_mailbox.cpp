#include "natmap/mapping_result_mailbox.h"

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

} // namespace

int main() {
    TestExactOutOfOrderDelivery();
    TestInvalidIdsAndEnvelopesFailClosed();
    TestDiscardAndClear();
    TestBoundAndNoWrap();
    std::printf(
        "test_mapping_result_mailbox: %d checks, %d failures\n",
        checks, failures);
    return failures == 0 ? 0 : 1;
}
