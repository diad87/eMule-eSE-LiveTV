// SPDX-License-Identifier: MIT
//
// Host-neutral mapping between a Live directory entry and the canonical
// K6M_SEARCH_RESULT tag set used by Kad6 K6-1 Option A.  This adapter owns the
// names, widths and byte order so MFC hosts do not grow a second wire dialect.
#pragma once

#include "kad6/kad6_search.h"

#include <array>
#include <cstdint>
#include <vector>

namespace kad6 {

struct K6LiveSearchMetadata {
    std::array<Byte, kHash16Size> result_id{};
    std::array<Byte, 4> ipv4{}; // network byte order
    std::uint16_t tcp_port = 0;
    std::uint16_t udp_port = 0;
    std::uint16_t bitrate_kbps = 0;
    std::uint32_t viewer_count = 0;
    std::uint32_t started_at = 0;
    Byte discovery_namespace = 0;
    Byte network_origin = kK6NetOriginKad2;
    std::vector<Byte> title_utf8;
    std::vector<Byte> category_utf8;
    std::vector<Byte> language_utf8;
};

// Build the exact K6-1 Live result tag set:
// SRCIP(CADDRESS), PORT/UDPPORT/BITRATE(U16), VIEWERS/STARTED(U32),
// NS(U8), TITLE/CAT/LANG(UTF8).  The output is canonical-sortable and is
// validated through the real K6SearchResult encoder before success.
Kad6Status BuildK6LiveSearchResult(const K6LiveSearchMetadata& live,
                                    K6SearchResult& out);

// Parse the recognized Live tags from an already-decoded K6SearchResult.
// Unknown tags are ignored for forward compatibility.  Missing, repeated or
// wrong-typed recognized tags are rejected; CADDRESS must be exactly IPv4.
Kad6Status ParseK6LiveSearchResult(const K6SearchResult& result,
                                    K6LiveSearchMetadata& out) noexcept;

} // namespace kad6
