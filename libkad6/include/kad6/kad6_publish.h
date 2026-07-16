// SPDX-License-Identifier: MIT
// Kad6 publish wire objects plus deterministic coalescing/QPS accounting.
#pragma once

#include "kad6/kad6_crypto.h"
#include "kad6/kad6_types.h"

#include <array>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace kad6 {

constexpr Byte kK6MsgPublish    = 0x18;
constexpr Byte kK6MsgPublishAck = 0x19;
constexpr Byte kK6MsgUnpublish  = 0x1A;
constexpr std::size_t kK6PublishFixedSize = 52;
constexpr std::size_t kK6PublishMaxRecordBytes = 64u * 1024u;
constexpr std::size_t kK6PublishSignatureSize = 64;
constexpr std::size_t kK6PublishMaxErrorBytes = 1024;
constexpr std::uint32_t kK6PublishMinTtlSeconds = 60;
constexpr std::uint32_t kK6PublishMaxTtlSeconds = 7u * 24u * 60u * 60u;

constexpr Byte kK6PublishNetKad2 = 0x01;
constexpr Byte kK6PublishNetKad6 = 0x02;
constexpr Byte kK6PublishNetMask = 0x03;
constexpr std::uint16_t kK6PublishFlagSigned = 0x0001;
constexpr std::uint16_t kK6PublishFlagRefresh = 0x0002;
constexpr std::uint16_t kK6PublishFlagMask = 0x0003;

enum class K6RecordKind : Byte {
    Keyword = 0, Source = 1, Notes = 2, LivePublic = 3,
    SealedOpaque = 4, Kad6SourceDescriptor = 5
};
enum class K6PublishStatus : Byte {
    Rejected = 0, Queued = 1, Sent = 2, RemoteAck = 3,
    VerifiedVisible = 4, Partial = 5
};
enum class K6UnpublishReason : Byte {
    Requested = 0, LeaseClosed = 1, EpochSuperseded = 2, Policy = 3
};

struct K6Publish {
    K6RecordKind record_kind = K6RecordKind::Source;
    Byte network_mask = 0;
    std::uint16_t flags = 0;
    std::uint32_t requested_ttl_s = kK6PublishMinTtlSeconds;
    std::uint64_t record_epoch = 0;
    Hash16 target_hash{};
    Hash16 source_id{};
    std::vector<Byte> record;
    std::array<Byte, kK6PublishSignatureSize> signature{};
};

struct K6PublishAck {
    K6PublishStatus status = K6PublishStatus::Rejected;
    Byte published_networks = 0;
    std::uint16_t replica_count = 0;
    std::uint32_t effective_ttl_s = 0;
    std::uint64_t publish_lease_id = 0;
    std::uint64_t record_epoch = 0;
    std::uint32_t refresh_after_s = 0;
    std::string error_detail;
};

struct K6Unpublish {
    std::uint64_t publish_lease_id = 0;
    std::uint64_t record_epoch = 0;
    K6UnpublishReason reason = K6UnpublishReason::Requested;
    std::array<Byte, 7> reserved{};
    Hash16 target_hash{};
    Hash16 source_id{};
};

Kad6Status EncodeK6Publish(const K6Publish& value, std::vector<Byte>& out);
Kad6Status DecodeK6Publish(const Byte* in, std::size_t len, K6Publish& out,
                           std::size_t* consumed = nullptr) noexcept;
// Domain-separated signature over the canonical publish fields and record;
// the detached signature bytes themselves are excluded.
Kad6Status K6PublishSerializeSigned(const K6Publish& value,
                                    std::vector<Byte>& out);
Kad6Status SignK6Publish(const Kad6CryptoHooks& hooks,
                         const Byte* secret, std::size_t secret_len,
                         K6Publish& value, std::vector<Byte>& out);
Kad6Status VerifyK6Publish(const Kad6CryptoHooks& hooks,
                           const Byte pub[kEd25519PubSize],
                           const K6Publish& value);
Kad6Status EncodeK6PublishAck(const K6PublishAck& value, std::vector<Byte>& out);
Kad6Status DecodeK6PublishAck(const Byte* in, std::size_t len, K6PublishAck& out,
                              std::size_t* consumed = nullptr) noexcept;
Kad6Status EncodeK6Unpublish(const K6Unpublish& value, std::vector<Byte>& out);
Kad6Status DecodeK6Unpublish(const Byte* in, std::size_t len, K6Unpublish& out,
                             std::size_t* consumed = nullptr) noexcept;

struct K6PublishBudgetConfig {
    std::uint32_t window_seconds = 60;
    std::uint32_t total_per_window = 120;
    std::uint32_t endpoint_per_window = 40;
    std::uint32_t hash_per_window = 12;
    std::uint32_t custodian_per_window = 30;
    std::uint32_t record_class_per_window = 80;
};

struct K6PublishBudgetKey {
    Hash16 endpoint{};
    Hash16 target_hash{};
    Hash16 custodian{};
    Byte record_class = 0;
};

class K6PublishBudget {
public:
    explicit K6PublishBudget(K6PublishBudgetConfig config = {});
    bool Admit(const K6PublishBudgetKey& key, std::uint64_t now_seconds);
    void NoteOverload(std::uint64_t now_seconds);
    std::uint32_t AdmissionPermille(std::uint64_t now_seconds) const noexcept;
    void Reset();
private:
    struct Counter { std::uint64_t window = 0; std::uint32_t used = 0; };
    bool CheckAndTake(std::map<std::string, Counter>& counters,
                      const std::string& key, std::uint32_t limit,
                      std::uint64_t window, bool commit);
    K6PublishBudgetConfig config_;
    Counter total_;
    std::map<std::string, Counter> endpoint_;
    std::map<std::string, Counter> hash_;
    std::map<std::string, Counter> custodian_;
    std::map<std::string, Counter> record_class_;
    std::uint64_t overload_until_ = 0;
};

struct K6PublishSchedule {
    std::uint64_t publish_lease_id = 0;
    Hash16 endpoint{};
    Hash16 target_hash{};
    Byte record_class = 0;
    std::uint64_t due_at = 0;
    std::uint64_t expires_at = 0;
    std::uint32_t members = 1;
};

class K6PublishCoalescer {
public:
    // Same (endpoint,target) joins one exterior publish. Record class remains
    // a budget dimension, but cannot manufacture duplicate exterior sources.
    // Jitter is
    // deterministic from the key and lease id, bounded by jitter_seconds.
    bool Enqueue(const K6PublishSchedule& item, std::uint32_t jitter_seconds,
                 std::uint64_t& effective_lease_id);
    std::vector<K6PublishSchedule> TakeDue(std::uint64_t now, std::size_t max_count);
    bool Remove(std::uint64_t publish_lease_id);
    std::size_t Expire(std::uint64_t now);
    std::size_t Size() const noexcept { return by_key_.size(); }
private:
    static std::string Key(const K6PublishSchedule& item);
    std::map<std::string, K6PublishSchedule> by_key_;
    std::map<std::uint64_t, std::string> lease_to_key_;
};

} // namespace kad6
