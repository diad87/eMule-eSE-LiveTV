// SPDX-License-Identifier: MIT
// K6-8 signed public-exit notice. The portable module owns the exact schema,
// RFC 8785-compatible canonical JSON subset, key binding and Ed25519 domain.
#pragma once

#include "kad6/kad6_address.h"
#include "kad6/kad6_crypto.h"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace kad6 {

constexpr const char kK6ExitNoticeDomain[] = "eSE-Kad6-ExitNotice-v1";
constexpr const char kK6ExitNoticeText[] =
    "This address operates a Kad6 relay; traffic may originate from other users.";
constexpr std::uint64_t kK6ExitNoticeMaxValiditySeconds = 7u * 24u * 60u * 60u;
constexpr std::size_t kK6ExitNoticeMaxEndpoints = 8;
constexpr std::size_t kK6ExitNoticeMaxJsonBytes = 8192;

enum class K6ExitNoticeService : Byte {
    Control = 0,
    ExitKad = 1,
    ExitEd2kDial = 2,
    ExitEd2kFull = 3
};

enum class K6ExitLoggingPolicy : Byte {
    OperatorDeclared = 0,
    AggregateOnly = 1,
    SystemMetadataPossible = 2,
    MinimumLegal = 3
};

struct K6ExitNoticeEndpoint {
    Kad6Address address;
    std::uint16_t port = 0;
};

struct K6ExitConfiguredLimits {
    std::uint32_t max_kbps = 0;
    std::uint32_t max_sessions = 0;
};

struct K6ExitNotice {
    Byte version = 1;
    std::array<Byte, kEd25519PubSize> node_pub{};
    Hash32 key_id{};
    std::vector<K6ExitNoticeEndpoint> endpoints;
    std::vector<K6ExitNoticeService> service_classes;
    std::string software;
    K6ExitConfiguredLimits configured_limits;
    std::uint64_t valid_from = 0;
    std::uint64_t valid_until = 0;
    K6ExitLoggingPolicy logging_policy = K6ExitLoggingPolicy::OperatorDeclared;
    std::string abuse_contact;
    std::string policy_url;
    std::string notice = kK6ExitNoticeText;
    std::array<Byte, kEd25519SigSize> signature{};
};

const char* K6ExitNoticeServiceName(K6ExitNoticeService value) noexcept;
const char* K6ExitLoggingPolicyName(K6ExitLoggingPolicy value) noexcept;

// Canonical I-JSON/JCS representation. Arrays are protocol-canonicalized by
// service enum and endpoint tuple before JCS object serialization.
Kad6Status K6ExitNoticeCanonicalJson(const K6ExitNotice& value,
                                     bool include_signature,
                                     std::string& output);
Kad6Status SignK6ExitNotice(const Kad6CryptoHooks& crypto,
                            K6ExitNotice& value, std::string& signed_json);
Kad6Status VerifyK6ExitNotice(const Kad6CryptoHooks& crypto,
                              const K6ExitNotice& value);

} // namespace kad6
