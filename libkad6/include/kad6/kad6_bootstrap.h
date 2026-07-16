// SPDX-License-Identifier: MIT
//
// Signed private-bootstrap bundle for Kad6 (spec 17.4). Verification is
// deliberately ordered: bounded envelope -> hash/key pin -> bundle signature
// -> time/sequence -> inner K6RouterRecord parsing and signatures.
#pragma once

#include "kad6/kad6_crypto.h"
#include "kad6/kad6_records.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace kad6 {

constexpr std::uint16_t kK6BootstrapBundleVersion = 1;
constexpr std::size_t kK6BootstrapMinEntries = 32;
constexpr std::size_t kK6BootstrapMaxEntries = 256;
constexpr std::size_t kK6BootstrapMaxEntriesBytes = 1024 * 1024;
constexpr std::size_t kK6BootstrapHeaderSize = 44;
constexpr std::size_t kK6BootstrapTrailerSize =
    kHash32Size + kHash32Size + kEd25519SigSize;
constexpr std::size_t kK6BootstrapMaxWireSize =
    kK6BootstrapHeaderSize + kK6BootstrapMaxEntriesBytes +
    kK6BootstrapTrailerSize;

struct K6BootstrapBundle {
    std::uint16_t version = kK6BootstrapBundleVersion;
    std::uint16_t flags = 0;
    std::uint64_t sequence = 0;
    std::uint64_t valid_from = 0;
    std::uint64_t valid_until = 0;
    std::vector<K6RouterRecord> records;
    Hash32 bundle_hash{};
    Hash32 signer_key_id{};
    Ed25519Sig signature{};
};

// Signs a bundle with the release-distribution key. Inner router records must
// already carry their node signatures; this function preserves them verbatim.
Kad6Status SignK6BootstrapBundle(const Kad6CryptoHooks& hooks,
                                 const Ed25519Pub& distributionPub,
                                 const Byte* distributionSecret,
                                 std::size_t distributionSecretLen,
                                 K6BootstrapBundle& bundle,
                                 std::vector<Byte>& out);

// Verifies and decodes against an out-of-band pinned distribution key.
// `lastSequence` is not modified. The caller persists bundle.sequence only
// after this returns Ok and the candidates have been accepted atomically.
Kad6Status VerifyAndDecodeK6BootstrapBundle(
    const Kad6CryptoHooks& hooks,
    const Ed25519Pub& pinnedDistributionPub,
    const Byte* in, std::size_t len,
    std::uint64_t lastSequence,
    std::uint64_t nowUnix,
    K6BootstrapBundle& out) noexcept;

} // namespace kad6
