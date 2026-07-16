// SPDX-License-Identifier: MIT
// K6-8 anonymous admission quota.  The portable layer owns the canonical
// token/certificate/wire formats, issuer limits and epoch-bounded spent set.
// RFC 9474 arithmetic is injected by the host so libkad6 never implements or
// vendors an RSA primitive.
#pragma once

#include "kad6/kad6_crypto.h"
#include "kad6/kad6_types.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace kad6 {

constexpr Byte kK6MsgQuotaKeyReq = 0x36;
constexpr Byte kK6MsgQuotaKey = 0x37;
constexpr Byte kK6MsgQuotaIssue = 0x38;
constexpr Byte kK6MsgQuotaIssued = 0x39;
constexpr Byte kK6MsgQuotaPresent = 0x3A;
constexpr Byte kK6MsgQuotaStatus = 0x3B;

constexpr std::uint64_t kK6QuotaEpochSeconds = 15u * 60u;
constexpr std::uint64_t kK6QuotaSubepochSeconds = 60u;
constexpr std::uint16_t kK6QuotaSubepochsPerEpoch =
    static_cast<std::uint16_t>(kK6QuotaEpochSeconds / kK6QuotaSubepochSeconds);
constexpr std::size_t kK6QuotaRandomizerSize = 32;
constexpr std::size_t kK6QuotaUnitSize = 32;
constexpr std::size_t kK6QuotaTokenV1BodySize = 80;
constexpr std::size_t kK6QuotaTokenV2BodySize = 116;
constexpr std::size_t kK6QuotaTokenBodySize = kK6QuotaTokenV2BodySize;
constexpr std::size_t kK6QuotaPreparedV1Size =
    kK6QuotaRandomizerSize + kK6QuotaTokenV1BodySize;
constexpr std::size_t kK6QuotaPreparedV2Size =
    kK6QuotaRandomizerSize + kK6QuotaTokenV2BodySize;
constexpr std::size_t kK6QuotaPreparedSize = kK6QuotaPreparedV2Size;
constexpr std::size_t kK6QuotaMinModulusBytes = 256; // RSA-2048 floor
constexpr std::size_t kK6QuotaMaxModulusBytes = 512; // RSA-4096 profile ceiling
constexpr std::size_t kK6QuotaMaxBatch = 16;
constexpr std::size_t kK6QuotaMaxIssuerPrincipals = 4096;
constexpr std::size_t kK6QuotaDefaultSpentCapacity = 65536;
constexpr std::uint32_t kK6QuotaPublicExponent = 65537;
constexpr const char kK6QuotaContextDomain[] = "eSE-Kad6-QuotaContext-v1";

enum class K6QuotaSuite : Byte {
    RsabssaSha384PssRandomized = 1
};

// Values deliberately match K6Service without including the hardening module.
enum class K6QuotaService : Byte {
    Control = 0,
    ExitKad = 1,
    ExitEd2kDial = 2,
    ExitEd2kFull = 3
};

enum class K6QuotaStatus : Byte {
    Ok = 0,
    BadRequest = 1,
    UnknownIssuer = 2,
    RateLimited = 3,
    InvalidProof = 4,
    WrongContext = 5,
    WrongEpoch = 6,
    AlreadySpent = 7,
    Capacity = 8,
    PolicyDenied = 9,
    CryptoFailure = 10
};

struct K6QuotaPublicKey {
    K6QuotaSuite suite = K6QuotaSuite::RsabssaSha384PssRandomized;
    std::vector<Byte> modulus; // unsigned big-endian n
    std::uint32_t exponent = kK6QuotaPublicExponent;
};

struct K6QuotaIssuerCertificate {
    Byte version = 1;
    K6QuotaPublicKey key;
    Hash32 key_id{};
    std::array<Byte, kEd25519PubSize> issuer_node_pub{};
    std::uint32_t policy_id = 1;
    Byte service_mask = 0;
    std::uint64_t valid_from_epoch = 0;
    std::uint64_t valid_until_epoch = 0;
    std::array<Byte, kEd25519SigSize> signature{};
};

// Canonical application message hidden from the issuer. PrepareRandomize adds
// a 32-byte prefix before this exact body, as required by the recommended RFC
// 9474 randomized variants.
struct K6QuotaToken {
    // Producers write v2. V1 remains readable for rolling compatibility, but
    // only v2 binds issuance to one issuer certificate and one short slot.
    Byte version = 2;
    K6QuotaSuite suite = K6QuotaSuite::RsabssaSha384PssRandomized;
    K6QuotaService service = K6QuotaService::ExitEd2kFull;
    Byte reserved = 0;
    std::uint32_t policy_id = 1;
    std::uint64_t valid_epoch = 0;
    std::uint16_t subepoch_slot = 0;
    std::uint16_t reserved2 = 0;
    Hash32 issuer_key_id{};
    std::array<Byte, kK6QuotaUnitSize> admission_unit{};
    Hash32 presentation_context_hash{};
};

struct K6QuotaBlindRequest {
    Byte version = 2;
    Hash32 issuer_key_id{};
    K6QuotaService service = K6QuotaService::Control;
    std::uint16_t subepoch_slot = 0;
    std::vector<std::vector<Byte> > blinded_messages;
};

struct K6QuotaBlindResponse {
    K6QuotaStatus status = K6QuotaStatus::BadRequest;
    std::vector<Byte> issuer_certificate;
    std::vector<std::vector<Byte> > blind_signatures;
};

struct K6QuotaPresentation {
    std::vector<Byte> issuer_certificate;
    std::vector<Byte> prepared_message;
    std::vector<Byte> signature;
};

struct K6QuotaPresentationResult {
    K6QuotaStatus status = K6QuotaStatus::BadRequest;
    Hash32 admission_unit_hash{};
    std::uint64_t valid_epoch = 0;
};

// Provider contract for RFC 9474. The production adapter is Crypto++; tests
// can inject a deterministic oracle. `blind` performs PrepareRandomize + Blind.
struct K6QuotaCryptoHooks {
    void* context = nullptr;
    bool (*blind)(void* context, const K6QuotaPublicKey& public_key,
                  const Byte* message, std::size_t message_size,
                  std::vector<Byte>& prepared_message,
                  std::vector<Byte>& blinded_message,
                  std::vector<Byte>& inverse) = nullptr;
    bool (*blind_sign)(void* context, const Hash32& key_id,
                       const Byte* blinded, std::size_t blinded_size,
                       std::vector<Byte>& blind_signature) = nullptr;
    bool (*finalize)(void* context, const K6QuotaPublicKey& public_key,
                     const Byte* prepared, std::size_t prepared_size,
                     const Byte* blind_signature, std::size_t blind_signature_size,
                     const Byte* inverse, std::size_t inverse_size,
                     std::vector<Byte>& signature) = nullptr;
    bool (*verify)(void* context, const K6QuotaPublicKey& public_key,
                   const Byte* prepared, std::size_t prepared_size,
                   const Byte* signature, std::size_t signature_size) = nullptr;
};

bool K6QuotaCryptoReady(const K6QuotaCryptoHooks& hooks) noexcept;
std::uint64_t K6QuotaEpoch(std::uint64_t unix_seconds) noexcept;
std::uint16_t K6QuotaSubepoch(std::uint64_t unix_seconds) noexcept;
std::size_t K6QuotaTokenBodySize(Byte version) noexcept;
std::size_t K6QuotaPreparedSize(Byte version) noexcept;
bool K6QuotaServiceValid(K6QuotaService service) noexcept;
Kad6Status K6QuotaContextHash(const Kad6CryptoHooks& crypto, Byte msg_type,
                              const Byte* body, std::size_t body_size,
                              Hash32& out);

Kad6Status K6QuotaPublicKeySerialize(const K6QuotaPublicKey& value,
                                      std::vector<Byte>& out);
Kad6Status K6QuotaPublicKeyId(const Kad6CryptoHooks& crypto,
                              const K6QuotaPublicKey& value, Hash32& out);

Kad6Status K6QuotaIssuerCertificateSerializeSigned(
    const K6QuotaIssuerCertificate& value, std::vector<Byte>& out);
Kad6Status SignK6QuotaIssuerCertificate(const Kad6CryptoHooks& crypto,
                                         K6QuotaIssuerCertificate& value,
                                         std::vector<Byte>& out);
Kad6Status EncodeK6QuotaIssuerCertificate(const K6QuotaIssuerCertificate& value,
                                           std::vector<Byte>& out);
Kad6Status DecodeK6QuotaIssuerCertificate(const Byte* in, std::size_t len,
                                           K6QuotaIssuerCertificate& out,
                                           std::size_t* consumed = nullptr) noexcept;
Kad6Status VerifyK6QuotaIssuerCertificate(const Kad6CryptoHooks& crypto,
                                           const K6QuotaIssuerCertificate& value,
                                           std::uint64_t current_epoch);

Kad6Status EncodeK6QuotaToken(const K6QuotaToken& value, std::vector<Byte>& out);
Kad6Status DecodeK6QuotaToken(const Byte* in, std::size_t len, K6QuotaToken& out,
                              std::size_t* consumed = nullptr) noexcept;
Kad6Status DecodeK6QuotaPreparedMessage(const Byte* in, std::size_t len,
                                        K6QuotaToken& out) noexcept;

Kad6Status EncodeK6QuotaBlindRequest(const K6QuotaBlindRequest& value,
                                      std::vector<Byte>& out);
Kad6Status DecodeK6QuotaBlindRequest(const Byte* in, std::size_t len,
                                      K6QuotaBlindRequest& out,
                                      std::size_t* consumed = nullptr) noexcept;
Kad6Status EncodeK6QuotaBlindResponse(const K6QuotaBlindResponse& value,
                                       std::vector<Byte>& out);
Kad6Status DecodeK6QuotaBlindResponse(const Byte* in, std::size_t len,
                                       K6QuotaBlindResponse& out,
                                       std::size_t* consumed = nullptr) noexcept;
Kad6Status EncodeK6QuotaPresentation(const K6QuotaPresentation& value,
                                      std::vector<Byte>& out);
Kad6Status DecodeK6QuotaPresentation(const Byte* in, std::size_t len,
                                      K6QuotaPresentation& out,
                                      std::size_t* consumed = nullptr) noexcept;
Kad6Status EncodeK6QuotaPresentationResult(const K6QuotaPresentationResult& value,
                                            std::vector<Byte>& out);
Kad6Status DecodeK6QuotaPresentationResult(const Byte* in, std::size_t len,
                                            K6QuotaPresentationResult& out,
                                            std::size_t* consumed = nullptr) noexcept;

struct K6QuotaBlindState {
    K6QuotaToken token;
    std::vector<Byte> prepared_message;
    std::vector<Byte> blinded_message;
    std::vector<Byte> inverse;
};

Kad6Status BlindK6QuotaToken(const K6QuotaCryptoHooks& crypto,
                             const K6QuotaPublicKey& issuer_key,
                             const K6QuotaToken& token, K6QuotaBlindState& out);
Kad6Status FinalizeK6QuotaToken(const K6QuotaCryptoHooks& crypto,
                                const K6QuotaIssuerCertificate& certificate,
                                const K6QuotaBlindState& state,
                                const std::vector<Byte>& blind_signature,
                                K6QuotaPresentation& out);

// Guard-side pre-crypto limiter. A principal is a LOCAL hash of the directly
// connected neighbour/prefix; it never goes on wire or into public telemetry.
class K6QuotaIssuerLimiter {
public:
    explicit K6QuotaIssuerLimiter(std::uint16_t units_per_epoch = 16) noexcept;
    K6QuotaStatus Reserve(const Hash32& principal, std::uint64_t epoch,
                          std::size_t units) noexcept;
    void Prune(std::uint64_t current_epoch) noexcept;
    std::size_t principal_count() const noexcept { return entries_.size(); }
private:
    struct Entry { std::uint64_t epoch = 0; std::uint16_t units = 0; };
    std::uint16_t units_per_epoch_;
    std::map<std::string, Entry> entries_;
};

// L6/Q28 continuously-refilled, fail-closed issuance budgets. One reservation
// atomically debits every scope; an epoch boundary never replenishes capacity.
struct K6QuotaBucketPolicy {
    std::uint32_t capacity_units = 1;
    std::uint32_t refill_units_per_epoch = 1;
};

struct K6QuotaHierarchyPolicy {
    K6QuotaBucketPolicy principal{16, 16};
    K6QuotaBucketPolicy prefix48{64, 64};
    K6QuotaBucketPolicy issuer{256, 256};
    K6QuotaBucketPolicy asn{512, 512};
    K6QuotaBucketPolicy service{1024, 1024};
    K6QuotaBucketPolicy global{2048, 2048};
    std::size_t max_principals = 4096;
    std::size_t max_prefixes = 4096;
    std::size_t max_issuers = 64;
    std::size_t max_asns = 1024;
};

struct K6QuotaHierarchyRequest {
    Hash32 principal{};             // guard-local, never serialized
    std::array<Byte, 6> prefix48{}; // canonical network-order /48
    Hash32 issuer_key_id{};
    std::uint32_t asn = 0;
    K6QuotaService service = K6QuotaService::Control;
    std::uint64_t now_ms = 0;       // monotonic host clock
    std::size_t units = 1;
};

class K6QuotaHierarchy {
public:
    explicit K6QuotaHierarchy(const K6QuotaHierarchyPolicy& policy = {}) noexcept;
    K6QuotaStatus Reserve(const K6QuotaHierarchyRequest& request) noexcept;
    void Prune(std::uint64_t now_ms, std::uint64_t idle_ms =
               2u * kK6QuotaEpochSeconds * 1000u) noexcept;
    std::size_t principal_count() const noexcept { return principals_.size(); }
    std::size_t prefix_count() const noexcept { return prefixes_.size(); }
    std::size_t issuer_count() const noexcept { return issuers_.size(); }
    std::size_t asn_count() const noexcept { return asns_.size(); }
private:
    static constexpr std::uint64_t kScale = 1024;
    struct Bucket {
        std::uint64_t tokens = 0;
        std::uint64_t updated_ms = 0;
        std::uint64_t last_used_ms = 0;
        // Numerator remainder for sub-token refill. Without this accumulator,
        // frequent probes could repeatedly truncate progress and starve an
        // otherwise continuously refilled bucket.
        std::uint64_t refill_remainder = 0;
    };
    using BucketMap = std::map<std::string, Bucket>;

    bool PolicyValid() const noexcept;
    Bucket* Get(BucketMap& buckets, const std::string& key,
                std::size_t maximum, const K6QuotaBucketPolicy& policy,
                std::uint64_t now_ms) noexcept;
    static void Refill(Bucket& bucket, const K6QuotaBucketPolicy& policy,
                       std::uint64_t now_ms) noexcept;
    static bool Has(const Bucket& bucket, std::size_t units) noexcept;
    static void Debit(Bucket& bucket, std::size_t units,
                      std::uint64_t now_ms) noexcept;
    static void PruneMap(BucketMap& buckets, std::uint64_t now_ms,
                         std::uint64_t idle_ms) noexcept;

    K6QuotaHierarchyPolicy policy_;
    BucketMap principals_, prefixes_, issuers_, asns_;
    std::array<Bucket, 4> services_{};
    Bucket global_{};
    std::uint64_t monotonic_floor_ms_ = 0;
};

// Exit-side bounded nullifier set. Consume is intentionally a single operation:
// callers verify signature/context first and then atomically decide first-use.
class K6QuotaSpentSet {
public:
    explicit K6QuotaSpentSet(std::size_t capacity_per_epoch =
                             kK6QuotaDefaultSpentCapacity) noexcept;
    K6QuotaStatus Consume(std::uint64_t epoch,
                          const std::array<Byte, kK6QuotaUnitSize>& unit,
                          std::uint64_t current_epoch) noexcept;
    void Prune(std::uint64_t current_epoch) noexcept;
    std::size_t size(std::uint64_t epoch) const noexcept;
private:
    std::size_t capacity_per_epoch_;
    std::map<std::uint64_t, std::map<std::string, bool> > epochs_;
    // Monotonic floor independent of wall-clock regressions. Once an exit has
    // observed epoch N it never admits or prunes as if it were in N-1.
    std::uint64_t epoch_floor_ = 0;
};

// Full verifier, including certificate, application structure, context and
// single-use enforcement. `issuer_trusted` is a host decision based on its
// verified routing/allowlist policy, never on a key self-assertion.
K6QuotaStatus VerifyAndSpendK6Quota(
    const Kad6CryptoHooks& identity_crypto,
    const K6QuotaCryptoHooks& quota_crypto,
    K6QuotaSpentSet& spent,
    const K6QuotaPresentation& presentation,
    K6QuotaService expected_service,
    std::uint32_t expected_policy,
    std::uint64_t current_epoch,
    std::uint16_t current_subepoch,
    const Hash32& expected_context,
    bool issuer_trusted,
    K6QuotaToken* token_out = nullptr,
    K6QuotaIssuerCertificate* certificate_out = nullptr);

} // namespace kad6
