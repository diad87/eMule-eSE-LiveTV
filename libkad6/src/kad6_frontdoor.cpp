// SPDX-License-Identifier: MIT
#include "kad6/kad6_frontdoor.h"

#include <algorithm>

namespace kad6 {
namespace {

bool ValidGroup(const K6RemoteGroup& group) noexcept {
    return group.family == 4 || group.family == 6;
}

bool SameGroup(const K6RemoteGroup& a, const K6RemoteGroup& b) noexcept {
    if (a.family != b.family) return false;
    const std::size_t bytes = a.family == 4 ? 4 : 8; // v4 /32, v6 /64
    for (std::size_t i = 0; i < bytes; ++i)
        if (a.address[i] != b.address[i]) return false;
    return true;
}

bool SameHash(const Hash16& a, const Hash16& b) noexcept {
    Byte different = 0;
    for (std::size_t i = 0; i < a.size(); ++i)
        different = static_cast<Byte>(different | (a[i] ^ b[i]));
    return different == 0;
}

} // namespace

int K6PreAuthGate::Admit(const K6RemoteGroup& group, std::uint64_t now_ms) noexcept {
    if (!ValidGroup(group)) {
        ++stats_.rejected_protocol;
        return -1;
    }
    const std::size_t group_limit = group.family == 4
        ? kK6PreAuthMaxV4Per32 : kK6PreAuthMaxV6Per64;
    std::size_t same_group = 0;
    int free_slot = -1;
    for (std::size_t i = 0; i < slots_.size(); ++i) {
        if (!slots_[i].active) {
            if (free_slot < 0) free_slot = static_cast<int>(i);
        } else if (SameGroup(slots_[i].group, group)) {
            ++same_group;
        }
    }
    if (same_group >= group_limit) {
        ++stats_.rejected_group;
        return -1;
    }
    if (free_slot < 0) {
        ++stats_.rejected_capacity;
        return -1;
    }
    Slot& slot = slots_[static_cast<std::size_t>(free_slot)];
    slot = Slot{};
    slot.group = group;
    slot.accepted_at_ms = now_ms;
    slot.active = true;
    ++stats_.admitted;
    ++stats_.active;
    stats_.peak = (std::max)(stats_.peak, stats_.active);
    return free_slot;
}

K6PreAuthDecision K6PreAuthGate::CheckTime(Slot& slot, std::uint64_t now_ms) noexcept {
    const std::uint64_t elapsed = now_ms >= slot.accepted_at_ms
        ? now_ms - slot.accepted_at_ms : 0;
    if (elapsed >= kK6PreAuthDeadlineMs ||
        (elapsed > kK6PreAuthRateGraceMs &&
         slot.observed_bytes * 1000ull < kK6PreAuthMinBytesPerSecond * elapsed)) {
        ++stats_.timed_out;
        return K6PreAuthDecision::Reject;
    }
    return K6PreAuthDecision::NeedMore;
}

K6PreAuthDecision K6PreAuthGate::Observe(std::size_t slot_index, const Byte* peeked,
                                         std::size_t peeked_len, std::uint64_t now_ms,
                                         std::size_t* hello_frame_size) noexcept {
    if (hello_frame_size) *hello_frame_size = 0;
    if (slot_index >= slots_.size() || !slots_[slot_index].active ||
        (!peeked && peeked_len != 0))
        return K6PreAuthDecision::Reject;
    Slot& slot = slots_[slot_index];
    slot.observed_bytes = (std::max)(slot.observed_bytes, peeked_len);
    const K6PreAuthDecision time = CheckTime(slot, now_ms);
    if (time == K6PreAuthDecision::Reject) return time;
    if (peeked_len > kK6PreAuthMaxHelloBytes) {
        ++stats_.rejected_protocol;
        return K6PreAuthDecision::Reject;
    }
    if (peeked_len < 6) return K6PreAuthDecision::NeedMore;
    const std::uint32_t packet_len = static_cast<std::uint32_t>(peeked[1]) |
        (static_cast<std::uint32_t>(peeked[2]) << 8) |
        (static_cast<std::uint32_t>(peeked[3]) << 16) |
        (static_cast<std::uint32_t>(peeked[4]) << 24);
    const std::uint64_t frame_size = 5ull + packet_len;
    if (peeked[0] != 0xE3 || peeked[5] != 0x01 || packet_len < 2 ||
        frame_size > kK6PreAuthMaxHelloBytes) {
        ++stats_.rejected_protocol;
        return K6PreAuthDecision::Reject;
    }
    if (peeked_len < frame_size) return K6PreAuthDecision::NeedMore;
    // Bytes pipelined after the complete HELLO are post-auth input. They stay
    // in the kernel buffer and enter the ordinary bounded packet parser after
    // promotion; rejecting them would break compatible eager clients.
    if (hello_frame_size) *hello_frame_size = static_cast<std::size_t>(frame_size);
    ++stats_.promoted;
    return K6PreAuthDecision::Ready;
}

K6PreAuthDecision K6PreAuthGate::Tick(std::size_t slot_index,
                                      std::uint64_t now_ms) noexcept {
    if (slot_index >= slots_.size() || !slots_[slot_index].active)
        return K6PreAuthDecision::Reject;
    return CheckTime(slots_[slot_index], now_ms);
}

void K6PreAuthGate::Release(std::size_t slot_index) noexcept {
    if (slot_index >= slots_.size() || !slots_[slot_index].active) return;
    slots_[slot_index] = Slot{};
    if (stats_.active != 0) --stats_.active;
}

bool K6PreAuthGate::IsActive(std::size_t slot) const noexcept {
    return slot < slots_.size() && slots_[slot].active;
}

void K6CohortScheduler::Reset() noexcept {
    backends_ = {};
    pins_ = {};
    cursor_ = 0;
}

bool K6CohortScheduler::Register(const K6CohortBackend& backend) noexcept {
    if (backend.lease_id == 0 || backend.circuit_id == 0) return false;
    BackendSlot* free_slot = nullptr;
    for (BackendSlot& slot : backends_) {
        if (slot.used && slot.value.lease_id == backend.lease_id) {
            // Refreshing a lease must not reset its scheduler history: otherwise
            // a noisy origin could repeatedly re-register to steal the next slot.
            slot.value = backend;
            return true;
        }
        if (!slot.used && !free_slot) free_slot = &slot;
    }
    if (!free_slot) return false;
    free_slot->value = backend;
    free_slot->used = true;
    return true;
}

bool K6CohortScheduler::Unregister(std::uint64_t lease_id) noexcept {
    bool found = false;
    for (BackendSlot& slot : backends_) {
        if (slot.used && slot.value.lease_id == lease_id) {
            slot = BackendSlot{};
            found = true;
        }
    }
    for (StreamPin& pin : pins_)
        if (pin.used && pin.lease_id == lease_id) pin = StreamPin{};
    return found;
}

bool K6CohortScheduler::SetServing(std::uint64_t lease_id, bool serving) noexcept {
    for (BackendSlot& slot : backends_) {
        if (slot.used && slot.value.lease_id == lease_id) {
            slot.value.serving = serving;
            return true;
        }
    }
    return false;
}

bool K6CohortScheduler::Select(const Hash16& file_hash, const Hash16& cohort_id,
                               std::uint64_t stream_id,
                               K6CohortBackend& selected) noexcept {
    if (stream_id == 0) return false;
    for (const StreamPin& pin : pins_) {
        if (!pin.used || pin.stream_id != stream_id) continue;
        for (const BackendSlot& slot : backends_) {
            if (slot.used && slot.value.serving && slot.value.lease_id == pin.lease_id) {
                selected = slot.value;
                return true;
            }
        }
        return false;
    }
    StreamPin* free_pin = nullptr;
    for (StreamPin& pin : pins_)
        if (!pin.used) { free_pin = &pin; break; }
    if (!free_pin) return false;
    BackendSlot* chosen = nullptr;
    std::size_t chosen_index = 0;
    for (std::size_t offset = 0; offset < backends_.size(); ++offset) {
        const std::size_t index = (cursor_ + offset) % backends_.size();
        BackendSlot& slot = backends_[index];
        if (!slot.used || !slot.value.serving ||
            !SameHash(slot.value.file_hash, file_hash) ||
            !SameHash(slot.value.cohort_id, cohort_id))
            continue;
        if (!chosen || slot.served_streams < chosen->served_streams) {
            chosen = &slot;
            chosen_index = index;
        }
    }
    if (!chosen) return false;
    free_pin->stream_id = stream_id;
    free_pin->lease_id = chosen->value.lease_id;
    free_pin->used = true;
    selected = chosen->value;
    ++chosen->served_streams;
    cursor_ = (chosen_index + 1) % backends_.size();
    return true;
}

bool K6CohortScheduler::ReleaseStream(std::uint64_t stream_id) noexcept {
    for (StreamPin& pin : pins_) {
        if (pin.used && pin.stream_id == stream_id) {
            pin = StreamPin{};
            return true;
        }
    }
    return false;
}

std::size_t K6CohortScheduler::BackendCount() const noexcept {
    std::size_t count = 0;
    for (const BackendSlot& slot : backends_) if (slot.used) ++count;
    return count;
}

std::size_t K6CohortScheduler::PinnedCount() const noexcept {
    std::size_t count = 0;
    for (const StreamPin& pin : pins_) if (pin.used) ++count;
    return count;
}

} // namespace kad6
