// SPDX-License-Identifier: MIT
// Kad6 source-lease wire objects and the side-effect-free lease state machine.
#pragma once

#include "kad6/kad6_crypto.h"
#include "kad6/kad6_endpoint.h"
#include "kad6/kad6_types.h"

#include <array>
#include <cstdint>
#include <map>
#include <vector>

namespace kad6 {

constexpr Byte kK6MsgSourceBind   = 0x20;
constexpr Byte kK6MsgSourceBound  = 0x21;
constexpr Byte kK6MsgSourceUnbind = 0x22;

constexpr std::size_t kK6SourceBindFixedSize = 150;
constexpr std::size_t kK6SourceBindMaxProof = 512;
constexpr std::size_t kK6CompatProofV1Size = 32 + 64;
constexpr std::uint32_t kK6SourceMinLifetimeSeconds = 60;
constexpr std::uint32_t kK6SourceMaxLifetimeSeconds = 24u * 60u * 60u;
constexpr std::uint32_t kK6SourceMaxUploadBps = 1024u * 1024u * 1024u;

constexpr Byte kK6TransportTcp = 0x01;
constexpr Byte kK6TransportUdp = 0x02;
constexpr Byte kK6TransportUtp = 0x04;
constexpr Byte kK6TransportMask = 0x07;

constexpr std::uint16_t kK6SourceAllowInbound  = 0x0001;
constexpr std::uint16_t kK6SourceAllowCallback = 0x0002;
constexpr std::uint16_t kK6SourceStablePseudo  = 0x0004;
constexpr std::uint16_t kK6SourceStrict        = 0x0008;
constexpr std::uint16_t kK6SourceLive          = 0x0010;
constexpr std::uint16_t kK6SourceFile          = 0x0020;
constexpr std::uint16_t kK6SourceFlagMask      = 0x003F;

enum class K6BindingMode : Byte { Auto = 0, DedicatedVep = 1, Cohort = 2 };
enum class K6IdentityMode : Byte { None = 0, OriginatorVep = 1, ExitTerminated = 2 };
enum class K6CommitmentKind : Byte { None = 0, AichRoot = 1, Sha256Hashset = 2 };
enum class K6SourceBoundStatus : Byte {
    Ok = 0, Rejected = 1, Overloaded = 2, BadProof = 3, StaleEpoch = 4,
    Unsupported = 5
};
enum class K6SourceUnbindReason : Byte {
    Requested = 0, CircuitClosed = 1, Expired = 2, Policy = 3
};

struct K6SourceBind {
    Hash16 file_hash{};
    std::uint64_t file_size = 0;
    Hash16 compat_user_hash{};
    Hash32 compat_pub_fingerprint{};
    Byte desired_family = 0;
    Byte transport_mask = 0;
    std::uint16_t flags = 0;
    std::uint32_t requested_lifetime_s = kK6SourceMinLifetimeSeconds;
    std::uint32_t max_upload_bps = 0;
    std::uint64_t source_epoch = 0;
    std::array<Byte, kNonce16Size> bind_nonce{};
    K6BindingMode requested_mode = K6BindingMode::Auto;
    std::uint16_t requested_endpoint_slots = 1;
    K6CommitmentKind commitment_kind = K6CommitmentKind::None;
    Hash32 content_commitment{};
    std::vector<Byte> compat_proof;
};

struct K6SourceBound {
    K6SourceBoundStatus status = K6SourceBoundStatus::Rejected;
    Byte transport_mask = 0;
    std::uint16_t flags = 0;
    K6BindingMode binding_mode = K6BindingMode::Auto;
    K6IdentityMode identity_mode = K6IdentityMode::None;
    std::uint16_t endpoint_slot = 0;
    std::uint64_t source_lease_id = 0;
    std::uint32_t lifetime_s = 0;
    std::uint32_t refresh_after_s = 0;
    Hash16 cohort_id{};
    K6CommitmentKind commitment_kind = K6CommitmentKind::None;
    Hash32 content_commitment{};
    K6Endpoint virtual_endpoint;
    Kad6Address exit_apparent_ip;
    std::array<Byte, kEd25519PubSize> exit_node_pub{};
    std::array<Byte, kNonce16Size> bind_nonce{};
    std::array<Byte, kEd25519SigSize> signature{};
};

struct K6SourceUnbind {
    std::uint64_t source_lease_id = 0;
    std::uint64_t source_epoch = 0;
    K6SourceUnbindReason reason = K6SourceUnbindReason::Requested;
    std::array<Byte, 7> reserved{};
    std::array<Byte, kNonce16Size> bind_nonce{};
};

Kad6Status EncodeK6SourceBind(const K6SourceBind& value, std::vector<Byte>& out);
Kad6Status DecodeK6SourceBind(const Byte* in, std::size_t len, K6SourceBind& out,
                              std::size_t* consumed = nullptr) noexcept;

// Canonical binding context used both by CompatProofV1 and SOURCE_BOUND.
// It excludes compat_proof, so the proof cannot recursively sign itself.
Kad6Status K6SourceBindSerializeProofContext(const K6SourceBind& value,
                                              std::vector<Byte>& out);
Kad6Status MakeK6CompatProofV1(const Kad6CryptoHooks& hooks,
                               const Byte* secret, std::size_t secret_len,
                               const Byte pub[kEd25519PubSize],
                               K6SourceBind& value);
Kad6Status VerifyK6CompatProofV1(const Kad6CryptoHooks& hooks,
                                 const K6SourceBind& value);

Kad6Status K6SourceBoundSerializeSigned(const K6SourceBind& bind,
                                         const K6SourceBound& bound,
                                         std::vector<Byte>& out);
Kad6Status EncodeK6SourceBound(const K6SourceBound& value, std::vector<Byte>& out);
Kad6Status DecodeK6SourceBound(const Byte* in, std::size_t len, K6SourceBound& out,
                               std::size_t* consumed = nullptr) noexcept;
Kad6Status SignK6SourceBound(const Kad6CryptoHooks& hooks,
                             const Byte* secret, std::size_t secret_len,
                             const K6SourceBind& bind, K6SourceBound& bound,
                             std::vector<Byte>& out);
Kad6Status VerifyK6SourceBound(const Kad6CryptoHooks& hooks,
                               const K6SourceBind& bind,
                               const K6SourceBound& bound);

Kad6Status EncodeK6SourceUnbind(const K6SourceUnbind& value, std::vector<Byte>& out);
Kad6Status DecodeK6SourceUnbind(const Byte* in, std::size_t len, K6SourceUnbind& out,
                                std::size_t* consumed = nullptr) noexcept;

enum class K6SourceLeaseState : Byte {
    Binding = 0,
    BoundDedicatedNotPublished = 1,
    JoinedCohortNotPublished = 2,
    Published = 3,
    Serving = 4,
    Draining = 5,
    Closed = 6
};

struct K6SourceLease {
    std::uint64_t lease_id = 0;
    std::uint32_t circuit_id = 0;
    Hash16 pseudonym{};
    K6SourceBind bind;
    K6SourceBound bound;
    K6SourceLeaseState state = K6SourceLeaseState::Binding;
    std::uint64_t created_at = 0;
    std::uint64_t expires_at = 0;
    std::uint64_t next_refresh_at = 0;
    bool accept_new_sessions = false;
};

// Pure state table: host code supplies already-validated/signed BIND/BOUND
// objects and owns socket/publish side effects. Transitions enforce K6-SM-004,
// K6-SM-005 and K6-SM-007 in one reusable place.
class K6SourceLeaseTable {
public:
    Kad6Status AddBound(std::uint32_t circuit_id, const Hash16& pseudonym,
                        const K6SourceBind& bind, const K6SourceBound& bound,
                        std::uint64_t now);
    Kad6Status MarkPublished(std::uint64_t lease_id);
    Kad6Status MarkServing(std::uint64_t lease_id);
    Kad6Status BeginDrain(std::uint64_t lease_id);
    std::size_t DrainCircuit(std::uint32_t circuit_id);
    std::size_t Expire(std::uint64_t now);
    std::size_t EraseClosed();
    bool Close(std::uint64_t lease_id);
    K6SourceLease* Find(std::uint64_t lease_id);
    const K6SourceLease* Find(std::uint64_t lease_id) const;
    bool CanPublish(std::uint64_t lease_id) const;
    bool CanAccept(std::uint64_t lease_id) const;
    std::size_t Size() const noexcept { return leases_.size(); }
    std::size_t ActiveSize() const noexcept;
    const std::map<std::uint64_t, K6SourceLease>& Entries() const noexcept { return leases_; }
private:
    std::map<std::uint64_t, K6SourceLease> leases_;
};

} // namespace kad6
