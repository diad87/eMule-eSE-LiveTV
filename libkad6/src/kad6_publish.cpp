// SPDX-License-Identifier: MIT
#include "kad6/kad6_publish.h"
#include "kad6/kad6_bytes.h"
#include "kad6/kad6_tags.h"

#include <algorithm>
#include <cstring>

namespace kad6 {
namespace {
template <std::size_t N>
bool AllZero(const std::array<Byte, N>& value) noexcept {
    Byte any = 0; for (Byte b : value) any = static_cast<Byte>(any | b); return any == 0;
}
bool ValidKind(K6RecordKind kind) noexcept {
    return static_cast<Byte>(kind) <= static_cast<Byte>(K6RecordKind::Kad6SourceDescriptor);
}
std::string BytesKey(const Byte* data, std::size_t size) {
    return std::string(reinterpret_cast<const char*>(data), size);
}
std::uint64_t Fnv1a(const std::string& value) noexcept {
    std::uint64_t h = 1469598103934665603ull;
    for (unsigned char c : value) { h ^= c; h *= 1099511628211ull; }
    return h;
}
const char kPublishDomain[] = "eSE-Kad6-Publish-v1";

Kad6Status SerializePublishUnsigned(const K6Publish& value,
                                    std::vector<Byte>& out) {
    out.clear();
    if (!ValidKind(value.record_kind) || value.network_mask == 0 ||
        (value.network_mask & ~kK6PublishNetMask) != 0 ||
        (value.flags & ~kK6PublishFlagMask) != 0 ||
        value.requested_ttl_s < kK6PublishMinTtlSeconds ||
        value.requested_ttl_s > kK6PublishMaxTtlSeconds || value.record_epoch == 0 ||
        AllZero(value.target_hash) || AllZero(value.source_id) || value.record.empty())
        return Kad6Status::BadValue;
    if (value.record.size() > kK6PublishMaxRecordBytes) return Kad6Status::TooLarge;
    ByteWriter w(out);
    w.u8(static_cast<Byte>(value.record_kind));
    w.u8(value.network_mask);
    w.u16le(value.flags);
    w.u32le(value.requested_ttl_s);
    w.u64le(value.record_epoch);
    w.bytes(value.target_hash.data(), value.target_hash.size());
    w.bytes(value.source_id.data(), value.source_id.size());
    w.u32le(static_cast<std::uint32_t>(value.record.size()));
    w.bytes(value.record.data(), value.record.size());
    return Kad6Status::Ok;
}
} // namespace

Kad6Status EncodeK6Publish(const K6Publish& value, std::vector<Byte>& out) {
    const Kad6Status status = SerializePublishUnsigned(value, out);
    if (status != Kad6Status::Ok) return status;
    if ((value.flags & kK6PublishFlagSigned) != 0)
        out.insert(out.end(), value.signature.begin(), value.signature.end());
    return Kad6Status::Ok;
}

Kad6Status K6PublishSerializeSigned(const K6Publish& value,
                                    std::vector<Byte>& out) {
    std::vector<Byte> canonical;
    const Kad6Status status = SerializePublishUnsigned(value, canonical);
    if (status != Kad6Status::Ok) { out.clear(); return status; }
    out.assign(kPublishDomain, kPublishDomain + sizeof(kPublishDomain) - 1);
    out.insert(out.end(), canonical.begin(), canonical.end());
    return Kad6Status::Ok;
}

Kad6Status SignK6Publish(const Kad6CryptoHooks& hooks,
                         const Byte* secret, std::size_t secret_len,
                         K6Publish& value, std::vector<Byte>& out) {
    out.clear();
    if (!hooks.ed25519_sign) return Kad6Status::NullArgument;
    value.flags |= kK6PublishFlagSigned;
    std::vector<Byte> message;
    Kad6Status status = K6PublishSerializeSigned(value, message);
    if (status != Kad6Status::Ok) return status;
    if (!hooks.ed25519_sign(secret, secret_len, message.data(), message.size(),
                            value.signature.data()))
        return Kad6Status::AuthFailed;
    return EncodeK6Publish(value, out);
}

Kad6Status VerifyK6Publish(const Kad6CryptoHooks& hooks,
                           const Byte pub[kEd25519PubSize],
                           const K6Publish& value) {
    if (!hooks.ed25519_verify || !pub) return Kad6Status::NullArgument;
    if ((value.flags & kK6PublishFlagSigned) == 0)
        return Kad6Status::AuthFailed;
    std::vector<Byte> message;
    const Kad6Status status = K6PublishSerializeSigned(value, message);
    if (status != Kad6Status::Ok) return status;
    return hooks.ed25519_verify(pub, message.data(), message.size(),
                                value.signature.data())
        ? Kad6Status::Ok : Kad6Status::AuthFailed;
}

Kad6Status DecodeK6Publish(const Byte* in, std::size_t len, K6Publish& out,
                           std::size_t* consumed) noexcept {
    out = K6Publish{};
    if (consumed) *consumed = 0;
    if (!in && len != 0) return Kad6Status::NullArgument;
    ByteReader r(in, len);
    K6Publish candidate;
    candidate.record_kind = static_cast<K6RecordKind>(r.u8());
    candidate.network_mask = r.u8();
    candidate.flags = r.u16le();
    candidate.requested_ttl_s = r.u32le();
    candidate.record_epoch = r.u64le();
    r.bytes(candidate.target_hash.data(), candidate.target_hash.size());
    r.bytes(candidate.source_id.data(), candidate.source_id.size());
    const std::uint32_t record_len = r.u32le();
    if (!r.ok()) return Kad6Status::Truncated;
    if (record_len > kK6PublishMaxRecordBytes) return Kad6Status::TooLarge;
    const Byte* record = r.take(record_len);
    if (!r.ok()) return Kad6Status::Truncated;
    candidate.record.assign(record, record + record_len);
    if ((candidate.flags & kK6PublishFlagSigned) != 0)
        r.bytes(candidate.signature.data(), candidate.signature.size());
    if (!r.ok()) return Kad6Status::Truncated;
    std::vector<Byte> check;
    if (EncodeK6Publish(candidate, check) != Kad6Status::Ok) return Kad6Status::Malformed;
    out = std::move(candidate);
    if (consumed) *consumed = r.pos();
    return Kad6Status::Ok;
}

Kad6Status EncodeK6PublishAck(const K6PublishAck& value, std::vector<Byte>& out) {
    out.clear();
    if (static_cast<Byte>(value.status) > static_cast<Byte>(K6PublishStatus::Partial) ||
        (value.published_networks & ~kK6PublishNetMask) != 0 ||
        value.error_detail.size() > kK6PublishMaxErrorBytes)
        return value.error_detail.size() > kK6PublishMaxErrorBytes
            ? Kad6Status::TooLarge : Kad6Status::BadValue;
    if (!value.error_detail.empty() && !Kad6IsValidUtf8NoNul(
            reinterpret_cast<const Byte*>(value.error_detail.data()), value.error_detail.size()))
        return Kad6Status::BadValue;
    if (value.status == K6PublishStatus::Rejected) {
        if (value.published_networks != 0 || value.replica_count != 0) return Kad6Status::BadValue;
    } else if (value.publish_lease_id == 0 || value.record_epoch == 0 ||
               value.effective_ttl_s < kK6PublishMinTtlSeconds ||
               value.effective_ttl_s > kK6PublishMaxTtlSeconds ||
               value.refresh_after_s == 0 || value.refresh_after_s >= value.effective_ttl_s) {
        return Kad6Status::BadValue;
    }
    ByteWriter w(out);
    w.u8(static_cast<Byte>(value.status));
    w.u8(value.published_networks);
    w.u16le(value.replica_count);
    w.u32le(value.effective_ttl_s);
    w.u64le(value.publish_lease_id);
    w.u64le(value.record_epoch);
    w.u32le(value.refresh_after_s);
    w.u16le(static_cast<std::uint16_t>(value.error_detail.size()));
    w.bytes(reinterpret_cast<const Byte*>(value.error_detail.data()), value.error_detail.size());
    return Kad6Status::Ok;
}

Kad6Status DecodeK6PublishAck(const Byte* in, std::size_t len, K6PublishAck& out,
                              std::size_t* consumed) noexcept {
    out = K6PublishAck{};
    if (consumed) *consumed = 0;
    if (!in && len != 0) return Kad6Status::NullArgument;
    ByteReader r(in, len);
    K6PublishAck candidate;
    candidate.status = static_cast<K6PublishStatus>(r.u8());
    candidate.published_networks = r.u8();
    candidate.replica_count = r.u16le();
    candidate.effective_ttl_s = r.u32le();
    candidate.publish_lease_id = r.u64le();
    candidate.record_epoch = r.u64le();
    candidate.refresh_after_s = r.u32le();
    const std::uint16_t error_len = r.u16le();
    if (!r.ok()) return Kad6Status::Truncated;
    if (error_len > kK6PublishMaxErrorBytes) return Kad6Status::TooLarge;
    const Byte* detail = r.take(error_len);
    if (!r.ok()) return Kad6Status::Truncated;
    candidate.error_detail.assign(reinterpret_cast<const char*>(detail), error_len);
    std::vector<Byte> check;
    if (EncodeK6PublishAck(candidate, check) != Kad6Status::Ok) return Kad6Status::Malformed;
    out = std::move(candidate);
    if (consumed) *consumed = r.pos();
    return Kad6Status::Ok;
}

Kad6Status EncodeK6Unpublish(const K6Unpublish& value, std::vector<Byte>& out) {
    out.clear();
    if (value.publish_lease_id == 0 || value.record_epoch == 0 ||
        static_cast<Byte>(value.reason) > static_cast<Byte>(K6UnpublishReason::Policy) ||
        AllZero(value.target_hash) || AllZero(value.source_id)) return Kad6Status::BadValue;
    for (Byte b : value.reserved) if (b != 0) return Kad6Status::BadValue;
    ByteWriter w(out);
    w.u64le(value.publish_lease_id); w.u64le(value.record_epoch);
    w.u8(static_cast<Byte>(value.reason)); w.bytes(value.reserved.data(), value.reserved.size());
    w.bytes(value.target_hash.data(), value.target_hash.size());
    w.bytes(value.source_id.data(), value.source_id.size());
    return Kad6Status::Ok;
}

Kad6Status DecodeK6Unpublish(const Byte* in, std::size_t len, K6Unpublish& out,
                             std::size_t* consumed) noexcept {
    out = K6Unpublish{};
    if (consumed) *consumed = 0;
    if (!in && len != 0) return Kad6Status::NullArgument;
    ByteReader r(in, len);
    K6Unpublish candidate;
    candidate.publish_lease_id = r.u64le(); candidate.record_epoch = r.u64le();
    candidate.reason = static_cast<K6UnpublishReason>(r.u8());
    r.bytes(candidate.reserved.data(), candidate.reserved.size());
    r.bytes(candidate.target_hash.data(), candidate.target_hash.size());
    r.bytes(candidate.source_id.data(), candidate.source_id.size());
    if (!r.ok()) return Kad6Status::Truncated;
    std::vector<Byte> check;
    if (EncodeK6Unpublish(candidate, check) != Kad6Status::Ok) return Kad6Status::Malformed;
    out = candidate;
    if (consumed) *consumed = r.pos();
    return Kad6Status::Ok;
}

K6PublishBudget::K6PublishBudget(K6PublishBudgetConfig config) : config_(config) {
    if (config_.window_seconds == 0) config_.window_seconds = 1;
}

bool K6PublishBudget::CheckAndTake(std::map<std::string, Counter>& counters,
                                   const std::string& key, std::uint32_t limit,
                                   std::uint64_t window, bool commit) {
    const auto found = counters.find(key);
    const std::uint32_t used = found != counters.end() && found->second.window == window
        ? found->second.used : 0;
    if (used >= limit || limit == 0) return false;
    if (commit) {
        Counter& c = counters[key];
        if (c.window != window) { c.window = window; c.used = 0; }
        ++c.used;
    }
    return true;
}

bool K6PublishBudget::Admit(const K6PublishBudgetKey& key, std::uint64_t now) {
    const std::uint64_t window = now / config_.window_seconds;
    // All dimensions use the same fixed window. Clear stale identities on an
    // advance and fail closed on a wall-clock rollback; this both bounds state
    // by total_per_window and prevents a rollback from resetting the budget.
    if (!have_active_window_) {
        active_window_ = window;
        have_active_window_ = true;
    } else if (window < active_window_) {
        return false;
    } else if (window > active_window_) {
        total_ = Counter{};
        endpoint_.clear(); hash_.clear(); custodian_.clear(); record_class_.clear();
        active_window_ = window;
    }
    const std::uint32_t total_used = total_.window == window ? total_.used : 0;
    const std::uint32_t effective_total = overload_until_ > now
        ? (std::max)(1u, config_.total_per_window / 4u) : config_.total_per_window;
    if (total_used >= effective_total ||
        !CheckAndTake(endpoint_, BytesKey(key.endpoint.data(), key.endpoint.size()), config_.endpoint_per_window, window, false) ||
        !CheckAndTake(hash_, BytesKey(key.target_hash.data(), key.target_hash.size()), config_.hash_per_window, window, false) ||
        !CheckAndTake(custodian_, BytesKey(key.custodian.data(), key.custodian.size()), config_.custodian_per_window, window, false) ||
        !CheckAndTake(record_class_, std::string(1, static_cast<char>(key.record_class)), config_.record_class_per_window, window, false))
        return false;
    if (total_.window != window) { total_.window = window; total_.used = 0; }
    ++total_.used;
    CheckAndTake(endpoint_, BytesKey(key.endpoint.data(), key.endpoint.size()), config_.endpoint_per_window, window, true);
    CheckAndTake(hash_, BytesKey(key.target_hash.data(), key.target_hash.size()), config_.hash_per_window, window, true);
    CheckAndTake(custodian_, BytesKey(key.custodian.data(), key.custodian.size()), config_.custodian_per_window, window, true);
    CheckAndTake(record_class_, std::string(1, static_cast<char>(key.record_class)), config_.record_class_per_window, window, true);
    return true;
}

void K6PublishBudget::NoteOverload(std::uint64_t now) {
    overload_until_ = (std::max)(overload_until_, now + config_.window_seconds * 4ull);
}
std::uint32_t K6PublishBudget::AdmissionPermille(std::uint64_t now) const noexcept {
    return overload_until_ > now ? 250u : 1000u;
}
std::size_t K6PublishBudget::TrackedKeyCount() const noexcept {
    return endpoint_.size() + hash_.size() + custodian_.size() + record_class_.size();
}
void K6PublishBudget::Reset() {
    total_ = Counter{}; endpoint_.clear(); hash_.clear(); custodian_.clear();
    record_class_.clear(); active_window_ = 0; have_active_window_ = false;
    overload_until_ = 0;
}

std::string K6PublishCoalescer::Key(const K6PublishSchedule& item) {
    std::string key = BytesKey(item.endpoint.data(), item.endpoint.size());
    key.append(BytesKey(item.target_hash.data(), item.target_hash.size()));
    return key;
}

bool K6PublishCoalescer::Enqueue(const K6PublishSchedule& item,
                                 std::uint32_t jitter_seconds,
                                 std::uint64_t& effective_lease_id) {
    effective_lease_id = 0;
    if (item.publish_lease_id == 0 || item.expires_at <= item.due_at ||
        AllZero(item.endpoint) || AllZero(item.target_hash)) return false;
    const std::string key = Key(item);
    auto found = by_key_.find(key);
    if (found != by_key_.end()) {
        ++found->second.members;
        found->second.expires_at = (std::max)(found->second.expires_at, item.expires_at);
        lease_to_key_[item.publish_lease_id] = key;
        effective_lease_id = found->second.publish_lease_id;
        return false;
    }
    K6PublishSchedule scheduled = item;
    if (jitter_seconds != 0) {
        const std::uint64_t jitter = Fnv1a(key + BytesKey(
            reinterpret_cast<const Byte*>(&item.publish_lease_id), sizeof(item.publish_lease_id))) %
            (static_cast<std::uint64_t>(jitter_seconds) + 1u);
        scheduled.due_at = (std::min)(scheduled.expires_at - 1, scheduled.due_at + jitter);
    }
    by_key_[key] = scheduled;
    lease_to_key_[item.publish_lease_id] = key;
    effective_lease_id = item.publish_lease_id;
    return true;
}

std::vector<K6PublishSchedule> K6PublishCoalescer::TakeDue(std::uint64_t now,
                                                           std::size_t max_count) {
    std::vector<K6PublishSchedule> due;
    for (auto it = by_key_.begin(); it != by_key_.end() && due.size() < max_count; ) {
        if (it->second.due_at <= now && it->second.expires_at > now) {
            due.push_back(it->second);
            const std::string key = it->first;
            for (auto lit = lease_to_key_.begin(); lit != lease_to_key_.end(); )
                lit = lit->second == key ? lease_to_key_.erase(lit) : std::next(lit);
            it = by_key_.erase(it);
        } else ++it;
    }
    return due;
}

bool K6PublishCoalescer::Remove(std::uint64_t lease_id) {
    auto lit = lease_to_key_.find(lease_id);
    if (lit == lease_to_key_.end()) return false;
    auto it = by_key_.find(lit->second);
    lease_to_key_.erase(lit);
    if (it == by_key_.end()) return true;
    if (it->second.publish_lease_id == lease_id || it->second.members <= 1) {
        const std::string key = it->first;
        by_key_.erase(it);
        for (auto other = lease_to_key_.begin(); other != lease_to_key_.end(); )
            other = other->second == key ? lease_to_key_.erase(other) : std::next(other);
    } else --it->second.members;
    return true;
}

std::size_t K6PublishCoalescer::Expire(std::uint64_t now) {
    std::size_t count = 0;
    for (auto it = by_key_.begin(); it != by_key_.end(); ) {
        if (it->second.expires_at <= now) {
            const std::string key = it->first;
            for (auto lit = lease_to_key_.begin(); lit != lease_to_key_.end(); )
                lit = lit->second == key ? lease_to_key_.erase(lit) : std::next(lit);
            it = by_key_.erase(it); ++count;
        } else ++it;
    }
    return count;
}

} // namespace kad6
