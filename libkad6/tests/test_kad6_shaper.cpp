#include "kad6/kad6_shaper.h"

#include <iostream>
#include <vector>

using namespace kad6;
static int checks = 0;
#define CHECK(x) do { ++checks; if (!(x)) { std::cerr << "FAIL " << __LINE__ << ": " #x "\n"; return 1; } } while (0)

int main()
{
    K6Class5Scheduler s;
    CHECK(s.Configure(63, 2000, 1000, 0) == Kad6Status::BadValue);
    CHECK(s.Configure(64, 1999, 1000, 0) == Kad6Status::BadValue);
    CHECK(s.Configure(4096, 5001, 1000, 0) == Kad6Status::BadValue);
    CHECK(s.Configure(64, 2000, 1000, 0) == Kad6Status::BadValue);
    CHECK(s.Configure(64, 2000, 1000, 7) == Kad6Status::Ok);
    CHECK(s.configured());
    CHECK(s.slot_interval_us() == 259400);
    CHECK(s.reservoir_capacity() == 8);

    std::vector<K6ShapeSlot> slots;
    CHECK(s.Poll(1006, 4, slots) == 0);
    CHECK(s.Poll(1007, 4, slots) == 1);
    CHECK(slots[0].kind == K6ShapeSlotKind::Padding);
    CHECK(slots[0].scheduled_us == 1007);
    const std::uint64_t firstDue = s.next_slot_us();
    const std::uint64_t firstInterval = firstDue - 1007;
    CHECK(firstInterval >= s.slot_interval_us() * 95 / 100);
    CHECK(firstInterval <= s.slot_interval_us() * 105 / 100);

    CHECK(s.Enqueue(10, 2)); CHECK(s.Enqueue(20, 2));
    CHECK(s.queued_records() == 4);
    CHECK(s.Poll(firstDue, 1, slots) == 1);
    CHECK(slots[0].stream_id == 10);
    const std::uint64_t secondDue = s.next_slot_us();
    const std::uint64_t secondInterval = secondDue - firstDue;
    CHECK(firstInterval + secondInterval == 2 * s.slot_interval_us());
    CHECK(s.Poll(secondDue, 1, slots) == 1);
    CHECK(slots[0].stream_id == 20);
    CHECK(s.Poll(s.next_slot_us(), 1, slots) == 1);
    CHECK(slots[0].stream_id == 10); // record-level DRR, no monopolisation

    // Reservoir overflow is fail-closed and sticky-visible.
    CHECK(!s.Enqueue(30, s.reservoir_capacity()));
    CHECK(s.exposed()); s.ClearExposure(); CHECK(!s.exposed());

    // Long suspend emits one slot and rephases; never a large catch-up burst.
    const std::uint64_t resumedAt = s.next_slot_us() + 100 * s.slot_interval_us();
    CHECK(s.Poll(resumedAt, 100, slots) == 1);
    CHECK(s.next_slot_us() > resumedAt);
    CHECK(s.exposed()); s.ClearExposure(); CHECK(!s.exposed());

    // Every supported power-of-two bucket is accepted; intermediate values fail.
    for (std::uint32_t bucket = 64; bucket <= 4096; bucket *= 2)
        CHECK(s.Configure(bucket, 5000, 0, bucket) == Kad6Status::Ok);
    CHECK(s.Configure(96, 3000, 0, 0) == Kad6Status::BadValue);

    // Stream cardinality is bounded independently of reservoir bytes.
    CHECK(s.Configure(4096, 5000, 0, 1) == Kad6Status::Ok);
    for (std::uint64_t id = 1; id <= kK6ShapeMaxStreams; ++id) CHECK(s.Enqueue(id));
    CHECK(!s.Enqueue(999)); CHECK(s.exposed());

    // Jitter is bounded, zero-sum over every pair and independently seeded.
    K6Class5Scheduler a, b;
    CHECK(a.Configure(2048, 3000, 500, 0x1111) == Kad6Status::Ok);
    CHECK(b.Configure(2048, 3000, 500, 0x2222) == Kad6Status::Ok);
    bool schedulesDiffer = a.next_slot_us() != b.next_slot_us();
    std::uint64_t previousA = a.next_slot_us();
    std::uint64_t previousB = b.next_slot_us();
    std::uint64_t pairDebt = 0;
    for (int i = 0; i < 20; ++i) {
        CHECK(a.Poll(previousA, 1, slots) == 1);
        const std::uint64_t intervalA = a.next_slot_us() - previousA;
        CHECK(intervalA >= a.slot_interval_us() * 95 / 100);
        CHECK(intervalA <= a.slot_interval_us() * 105 / 100 + 1);
        if ((i & 1) == 0) pairDebt = intervalA;
        else CHECK(pairDebt + intervalA == 2 * a.slot_interval_us());
        previousA = a.next_slot_us();

        CHECK(b.Poll(previousB, 1, slots) == 1);
        schedulesDiffer = schedulesDiffer || b.next_slot_us() != a.next_slot_us();
        previousB = b.next_slot_us();
    }
    CHECK(schedulesDiffer);

    std::cout << "kad6 class-5 scheduler tests: " << checks << " checks, PASS\n";
    return 0;
}
