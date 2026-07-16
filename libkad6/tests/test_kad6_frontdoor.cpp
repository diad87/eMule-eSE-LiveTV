// SPDX-License-Identifier: MIT
#include "kad6/kad6_frontdoor.h"

#include <array>
#include <cassert>
#include <cstdint>
#include <iostream>

namespace {

kad6::K6RemoteGroup V4(std::uint32_t value) {
    kad6::K6RemoteGroup group;
    group.family = 4;
    group.address[0] = static_cast<kad6::Byte>(value >> 24);
    group.address[1] = static_cast<kad6::Byte>(value >> 16);
    group.address[2] = static_cast<kad6::Byte>(value >> 8);
    group.address[3] = static_cast<kad6::Byte>(value);
    return group;
}

kad6::K6RemoteGroup V6(std::uint8_t host) {
    kad6::K6RemoteGroup group;
    group.family = 6;
    const kad6::Byte prefix[8] = {0x20, 0x01, 0x0d, 0xb8, 1, 2, 3, 4};
    for (std::size_t i = 0; i < 8; ++i) group.address[i] = prefix[i];
    group.address[15] = host;
    return group;
}

kad6::Hash16 Hash(std::uint8_t seed) {
    kad6::Hash16 hash{};
    for (std::size_t i = 0; i < hash.size(); ++i)
        hash[i] = static_cast<kad6::Byte>(seed + i);
    return hash;
}

std::array<kad6::Byte, 10> Hello() {
    // E3, packet length=5 (opcode + 4-byte payload), OP_HELLO.
    return {0xE3, 0x05, 0, 0, 0, 0x01, 1, 2, 3, 4};
}

void GateG10() {
    kad6::K6PreAuthGate gate;
    const auto hello = Hello();

    const kad6::K6RemoteGroup one = V4(0xCB007101u);
    int quota[4]{};
    for (int& slot : quota) { slot = gate.Admit(one, 0); assert(slot >= 0); }
    assert(gate.Admit(one, 0) < 0);
    for (int slot : quota) gate.Release(static_cast<std::size_t>(slot));

    int quota6[8]{};
    for (int i = 0; i < 8; ++i) {
        quota6[i] = gate.Admit(V6(static_cast<std::uint8_t>(i + 1)), 0);
        assert(quota6[i] >= 0);
    }
    assert(gate.Admit(V6(9), 0) < 0);
    for (int slot : quota6) gate.Release(static_cast<std::size_t>(slot));

    // A 5,000-connection Slowloris wave cannot exceed fixed capacity. Unique
    // groups avoid the per-origin quota so this specifically tests the cap.
    std::array<int, kad6::kK6PreAuthMaxSlots> admitted{};
    std::size_t count = 0;
    for (std::uint32_t i = 0; i < 5000; ++i) {
        const int slot = gate.Admit(V4(0x0A000000u + i), 100);
        if (slot >= 0) admitted[count++] = slot;
    }
    assert(count == kad6::kK6PreAuthMaxSlots);
    assert(gate.Stats().active == kad6::kK6PreAuthMaxSlots);
    assert(gate.Stats().peak == kad6::kK6PreAuthMaxSlots);
    assert(gate.Stats().rejected_capacity == 5000 - kad6::kK6PreAuthMaxSlots);

    for (int slot : admitted) {
        const kad6::Byte prefix[1] = {0xE3};
        assert(gate.Observe(static_cast<std::size_t>(slot), prefix, 1, 2201) ==
               kad6::K6PreAuthDecision::Reject);
        gate.Release(static_cast<std::size_t>(slot));
    }
    assert(gate.Stats().active == 0);

    const int ready = gate.Admit(V4(0xC6336401u), 3000);
    assert(ready >= 0);
    std::size_t frame_size = 0;
    assert(gate.Observe(static_cast<std::size_t>(ready), hello.data(), hello.size(),
                        3001, &frame_size) == kad6::K6PreAuthDecision::Ready);
    assert(frame_size == hello.size());
    gate.Release(static_cast<std::size_t>(ready));

    std::array<kad6::Byte, 12> pipelined{};
    for (std::size_t i = 0; i < hello.size(); ++i) pipelined[i] = hello[i];
    pipelined[10] = 0xC5; pipelined[11] = 0x01;
    const int eager = gate.Admit(V4(0xC6336403u), 3500);
    assert(eager >= 0);
    assert(gate.Observe(static_cast<std::size_t>(eager), pipelined.data(),
                        pipelined.size(), 3501, &frame_size) ==
           kad6::K6PreAuthDecision::Ready);
    assert(frame_size == hello.size());
    gate.Release(static_cast<std::size_t>(eager));

    std::array<kad6::Byte, kad6::kK6PreAuthMaxHelloBytes + 1> oversized{};
    for (std::size_t i = 0; i < hello.size(); ++i) oversized[i] = hello[i];
    const int tooLarge = gate.Admit(V4(0xC6336404u), 3600);
    assert(tooLarge >= 0);
    assert(gate.Observe(static_cast<std::size_t>(tooLarge), oversized.data(),
                        oversized.size(), 3601) == kad6::K6PreAuthDecision::Reject);
    gate.Release(static_cast<std::size_t>(tooLarge));

    const int absolute = gate.Admit(V4(0xC6336405u), 5000);
    assert(absolute >= 0);
    assert(gate.Tick(static_cast<std::size_t>(absolute), 15000) ==
           kad6::K6PreAuthDecision::Reject);
    gate.Release(static_cast<std::size_t>(absolute));

    auto malformed = hello;
    malformed[0] = 0xD4; // packed input is forbidden pre-auth
    const int bad = gate.Admit(V4(0xC6336402u), 4000);
    assert(bad >= 0);
    assert(gate.Observe(static_cast<std::size_t>(bad), malformed.data(), malformed.size(),
                        4001) == kad6::K6PreAuthDecision::Reject);
    gate.Release(static_cast<std::size_t>(bad));
    std::cout << "G10: attempts=5000 peak_slots=" << gate.Stats().peak
              << " capacity_rejected=" << gate.Stats().rejected_capacity
              << " slowloris_timed_out=" << gate.Stats().timed_out << "\n";
}

void SchedulerG11() {
    kad6::K6CohortScheduler scheduler;
    const kad6::Hash16 file = Hash(1);
    const kad6::Hash16 cohort = Hash(90);
    kad6::K6CohortBackend a;
    a.lease_id = 11; a.circuit_id = 101; a.file_hash = file;
    a.cohort_id = cohort; a.serving = true;
    kad6::K6CohortBackend b = a;
    b.lease_id = 12; b.circuit_id = 102;
    assert(scheduler.Register(a));
    assert(scheduler.Register(b));

    // A selection in an unrelated cohort must not perturb equal-quantum
    // scheduling for the two origins serving this file.
    kad6::K6CohortBackend unrelated = a;
    unrelated.lease_id = 13; unrelated.circuit_id = 103;
    unrelated.file_hash = Hash(40); unrelated.cohort_id = Hash(41);
    assert(scheduler.Register(unrelated));

    kad6::K6CohortBackend selected{};
    assert(scheduler.Select(file, cohort, 1001, selected));
    const std::uint64_t first = selected.lease_id;
    assert(scheduler.Select(file, cohort, 1001, selected));
    assert(selected.lease_id == first);

    assert(scheduler.Select(unrelated.file_hash, unrelated.cohort_id, 2001, selected));
    assert(selected.lease_id == unrelated.lease_id);

    assert(scheduler.Select(file, cohort, 1002, selected));
    assert(selected.lease_id != first);
    assert(scheduler.PinnedCount() == 3);

    assert(!scheduler.Select(file, Hash(91), 1003, selected));
    assert(scheduler.PinnedCount() == 3);
    assert(scheduler.ReleaseStream(1001));
    assert(scheduler.ReleaseStream(1002));
    assert(scheduler.ReleaseStream(2001));
    assert(scheduler.PinnedCount() == 0);
    std::cout << "G11: target_backends=2 isolation_backends=1 streams=3"
                 " fanout=0 stable_pins=3 fair_after_interleave=1\n";
}

} // namespace

int main() {
    GateG10();
    SchedulerG11();
    std::cout << "K6-5 front-door gates G10/G11: PASS\n";
    return 0;
}
