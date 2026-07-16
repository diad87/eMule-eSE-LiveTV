// SPDX-License-Identifier: MIT
#include "kad6/kad6_frontdoor.h"
#include "kad6/kad6_bytes.h"

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

void RetryMessage(const K6RemoteGroup& group, std::uint64_t epoch,
                  const std::array<Byte, kNonce16Size>& nonce,
                  std::vector<Byte>& message) {
    static const char domain[] = "eSE-Kad6-FrontDoorRetry-v1";
    const Byte* prefix = reinterpret_cast<const Byte*>(domain);
    message.assign(prefix, prefix + sizeof(domain) - 1);
    ByteWriter writer(message); writer.u8(group.family);
    writer.bytes(group.address.data(), group.family == 4 ? 4 : 8);
    writer.u64le(epoch); writer.bytes(nonce.data(), nonce.size());
}

bool NonZero(const Byte* bytes, std::size_t size) noexcept {
    Byte aggregate = 0; for (std::size_t i=0;i<size;++i) aggregate=static_cast<Byte>(aggregate|bytes[i]);
    return aggregate != 0;
}

} // namespace

Kad6Status IssueK6RetryCookie(const Kad6CryptoHooks& hooks,
        const Byte* secret, std::size_t secretLen, const K6RemoteGroup& group,
        std::uint64_t nowMs, K6RetryCookie& out) noexcept {
    out = {};
    if (!hooks.hmac_sha256 || !secret || secretLen < 16 || !ValidGroup(group))
        return Kad6Status::BadValue;
    out.family = group.family; out.epoch = nowMs / kK6RetryCookieEpochMs;
    std::vector<Byte> seed;
    static const char nonceDomain[] = "eSE-Kad6-FrontDoorNonce-v1";
    const Byte* domain = reinterpret_cast<const Byte*>(nonceDomain);
    seed.assign(domain, domain + sizeof(nonceDomain) - 1);
    ByteWriter seedWriter(seed); seedWriter.u8(group.family);
    seedWriter.bytes(group.address.data(), group.family == 4 ? 4 : 8);
    seedWriter.u64le(out.epoch);
    Hash32 digest{};
    if (!hooks.hmac_sha256(secret, secretLen, seed.data(), seed.size(), digest.data()))
        return Kad6Status::AuthFailed;
    std::copy(digest.begin(), digest.begin() + out.nonce.size(), out.nonce.begin());
    std::vector<Byte> message; RetryMessage(group, out.epoch, out.nonce, message);
    if (!hooks.hmac_sha256(secret, secretLen, message.data(), message.size(), out.mac.data())) {
        out = {}; return Kad6Status::AuthFailed;
    }
    return Kad6Status::Ok;
}

Kad6Status VerifyK6RetryCookie(const Kad6CryptoHooks& hooks,
        const Byte* secret, std::size_t secretLen, const K6RemoteGroup& group,
        std::uint64_t nowMs, const K6RetryCookie& cookie) noexcept {
    if (!hooks.hmac_sha256 || !secret || secretLen < 16 || !ValidGroup(group) ||
        cookie.version != 1 || cookie.family != group.family ||
        !NonZero(cookie.nonce.data(), cookie.nonce.size()) ||
        !NonZero(cookie.mac.data(), cookie.mac.size())) return Kad6Status::BadValue;
    const std::uint64_t current = nowMs / kK6RetryCookieEpochMs;
    if (cookie.epoch > current || current - cookie.epoch > 1) return Kad6Status::Expired;
    std::vector<Byte> message; RetryMessage(group, cookie.epoch, cookie.nonce, message);
    Hash32 expected{};
    if (!hooks.hmac_sha256(secret, secretLen, message.data(), message.size(), expected.data()))
        return Kad6Status::AuthFailed;
    return Kad6CtEqual(expected.data(), cookie.mac.data(), expected.size())
        ? Kad6Status::Ok : Kad6Status::AuthFailed;
}

Kad6Status EncodeK6RetryCookie(const K6RetryCookie& cookie, std::vector<Byte>& out) {
    out.clear();
    if (cookie.version != 1 || (cookie.family != 4 && cookie.family != 6) ||
        !NonZero(cookie.nonce.data(), cookie.nonce.size()) ||
        !NonZero(cookie.mac.data(), cookie.mac.size())) return Kad6Status::BadValue;
    ByteWriter writer(out); writer.u8(cookie.version); writer.u8(cookie.family); writer.u16le(0);
    writer.u64le(cookie.epoch); writer.bytes(cookie.nonce.data(), cookie.nonce.size());
    writer.bytes(cookie.mac.data(), cookie.mac.size()); return Kad6Status::Ok;
}

Kad6Status DecodeK6RetryCookie(const Byte* in, std::size_t len, K6RetryCookie& out,
        std::size_t* consumed) noexcept {
    out = {}; if (consumed) *consumed = 0; if (!in && len) return Kad6Status::NullArgument;
    ByteReader reader(in, len); out.version=reader.u8();out.family=reader.u8();
    const std::uint16_t reserved=reader.u16le();out.epoch=reader.u64le();
    reader.bytes(out.nonce.data(),out.nonce.size());reader.bytes(out.mac.data(),out.mac.size());
    if(!reader.ok()){out={};return Kad6Status::Truncated;}
    if(reader.pos()!=len||reserved||out.version!=1||(out.family!=4&&out.family!=6)||
       !NonZero(out.nonce.data(),out.nonce.size())||!NonZero(out.mac.data(),out.mac.size())){
        out={};return Kad6Status::Malformed;}
    if(consumed)*consumed=len;return Kad6Status::Ok;
}

int K6PreAuthGate::Admit(const K6RemoteGroup& group, std::uint64_t now_ms) noexcept {
    return AdmitLane(group, now_ms, true);
}

int K6PreAuthGate::AdmitAfterRetry(const K6RemoteGroup& group,
        const K6RetryCookie& cookie, const Kad6CryptoHooks& hooks,
        const Byte* secret, std::size_t secretLen, std::uint64_t now_ms) noexcept {
    if (VerifyK6RetryCookie(hooks, secret, secretLen, group, now_ms, cookie) !=
            Kad6Status::Ok) {
        ++stats_.rejected_cookie;
        return -1;
    }
    ++stats_.retry_validated;
    return AdmitLane(group, now_ms, false);
}

int K6PreAuthGate::AdmitAuthenticated(const K6RemoteGroup& group,
                                      std::uint64_t now_ms) noexcept {
    const int slot = AdmitLane(group, now_ms, true);
    if (slot >= 0) ++stats_.reserved_admitted;
    return slot;
}

int K6PreAuthGate::AdmitLane(const K6RemoteGroup& group, std::uint64_t now_ms,
                             bool reservedLane) noexcept {
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
    if (free_slot < 0 || (!reservedLane && stats_.active >= kK6PreAuthAnonymousSlots)) {
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
