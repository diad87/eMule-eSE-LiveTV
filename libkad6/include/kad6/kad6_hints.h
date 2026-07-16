// SPDX-License-Identifier: MIT
// Validated legacy source exchange -> provenance-bound Kad6 source hints.
#pragma once

#include "kad6/kad6_gateway.h"

#include <array>
#include <vector>

namespace kad6 {

constexpr Byte kEd2kOpAnswerSources  = 0x82;
constexpr Byte kEd2kOpAnswerSources2 = 0x84;
constexpr std::size_t kK6PexMaxWireSources = 500;
constexpr std::size_t kK6SourceHintsMaxSources = 50;

struct K6ParsedPexSource {
    K6Endpoint endpoint;
    Hash16 user_hash{};
    Byte crypt_options = 0;
    bool low_id = false;
    std::uint32_t legacy_id = 0;
    std::uint32_t server_ip = 0;   // evidence only; never dial authority
    std::uint16_t server_port = 0; // evidence only; never dial authority
};

struct K6ParsedPex {
    Byte version = 0;
    Hash16 object_hash{};
    std::vector<K6ParsedPexSource> sources;
    std::size_t omitted = 0;
};

struct K6SourceHint {
    K6Endpoint endpoint;
    Hash16 user_hash{};
    Byte crypt_options = 0;
    std::vector<Byte> ticket;
};

struct K6SourceHints {
    std::uint64_t source_session_id = 0;
    std::uint64_t source_stream_id = 0;
    std::uint64_t source_message_seq = 0;
    Byte pex_version = 0;
    Byte flags = 0;
    Hash16 object_hash{};
    Hash32 exterior_message_hash{};
    std::vector<K6SourceHint> sources;
};

// `payload` starts after the eMule opcode. SX2 carries an explicit version;
// SX1's exact record width determines v1/v2-v3/v4. Every length/count is
// validated before allocation. LowID records are retained as evidence but the
// host must not mint a direct ticket for them.
Kad6Status DecodeEd2kSourceExchange(Byte opcode, const Byte* payload, std::size_t len,
                                     K6ParsedPex& out) noexcept;

Kad6Status EncodeK6SourceHints(const K6SourceHints&, std::vector<Byte>&);
Kad6Status DecodeK6SourceHints(const Byte*, std::size_t, K6SourceHints&,
                               std::size_t* consumed = nullptr) noexcept;

} // namespace kad6
