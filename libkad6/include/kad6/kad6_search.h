// SPDX-License-Identifier: MIT
//
// libkad6 — kad6_search.h: the three Kad6 search message bodies (ticket K6-1.2)
// — K6M_SEARCH_START / K6M_SEARCH_RESULT / K6M_SEARCH_END. Each rides inside a
// K6Frame's `body` (see kad6_frame.h); this file only serializes/parses the
// bodies, not the frame envelope. All multi-byte scalars are little-endian
// (via kad6_bytes.h).
//
// K6M_SEARCH_START (msg_type 0x10) — begin a search:
//   0  search_kind      u8   (kK6SearchKind* below)
//   1  network_mask     u8   (bit0 Kad2, bit1 Kad6 — kK6NetMask*)
//   2  max_results      u16 LE  (1..200)
//   4  deadline_ms      u32 LE  (1000..120000)
//   8  target_hash      [16]
//   24 query_len        u32 LE
//   28 query            query_len bytes
//      options_len      u16 LE
//      options          options_len bytes  (opaque TLV blob at this layer)
//
// K6M_SEARCH_RESULT (msg_type 0x11) — one hit:
//   0  result_id           [16]
//   16 result_kind         u8
//   17 network_origin      u8   (1 Kad2, 2 Kad6 — kK6NetOrigin*)
//   18 tag_count           u16 LE
//   20 canonical_tags_len  u32 LE
//   24 tags                canonical_tags_len bytes (a K6TagListV1 blob, see kad6_tags.h)
//      ticket_count        u8   (<= kK6SearchResultMaxTickets)
//      tickets             ticket_count * K6TargetTicketV1 (each self-delimiting
//                          via DecodeK6TargetTicket's `consumed`, see kad6_ticket.h)
//
// K6M_SEARCH_END (msg_type 0x12) — fixed 13-byte body, search finished:
//   0  status         u8   (K6SearchEndStatus)
//   1  result_count   u16 LE
//   3  queried_nodes  u16 LE
//   5  elapsed_ms     u32 LE
//   9  load_hint      u8
//   10 reserved[3]    = 0  (encoder writes 0; decoder requires 0, else Malformed)
//
// Producer strict, consumer prudent (Postel): every range/count/length is
// validated against its rule BEFORE any buffer sized off it is allocated.
// A partial parse is never returned — on any Decode failure `out` is left at
// its default value.
#pragma once

#include "kad6/kad6_bytes.h"
#include "kad6/kad6_tags.h"
#include "kad6/kad6_ticket.h"
#include "kad6/kad6_types.h"

#include <array>
#include <cstdint>
#include <vector>

namespace kad6 {

// ── K6Frame msg_type values (spec) ──────────────────────────────────────────
constexpr Byte kK6MsgSearchStart  = 0x10;
constexpr Byte kK6MsgSearchResult = 0x11;
constexpr Byte kK6MsgSearchEnd    = 0x12;

// ── K6SearchStart::search_kind ───────────────────────────────────────────────
constexpr Byte kK6SearchKindKeyword    = 0;
constexpr Byte kK6SearchKindSourceHash = 1; // source / file-hash search
constexpr Byte kK6SearchKindNotes      = 2;
constexpr Byte kK6SearchKindLive       = 3; // live / channel search
constexpr Byte kK6SearchKindSealed     = 4;
constexpr Byte kK6SearchKindRouter     = 5;

// ── K6SearchStart::network_mask bits ─────────────────────────────────────────
constexpr Byte kK6NetMaskKad2 = 0x01; // bit 0
constexpr Byte kK6NetMaskKad6 = 0x02; // bit 1

// ── K6SearchResult::network_origin ──────────────────────────────────────────
constexpr Byte kK6NetOriginKad2 = 1;
constexpr Byte kK6NetOriginKad6 = 2;

// ── K6SearchStart limits (spec K6-SEARCH-001) ───────────────────────────────
constexpr std::uint16_t kK6SearchMinResults     = 1;
constexpr std::uint16_t kK6SearchMaxResults     = 200;
constexpr std::uint32_t kK6SearchMinDeadlineMs  = 1000;
constexpr std::uint32_t kK6SearchMaxDeadlineMs  = 120000;
constexpr std::size_t   kK6SearchMaxQueryBytes  = 4096;
constexpr std::size_t   kK6SearchMaxOptionsBytes = 4096;
// Fixed bytes before `query` (search_kind+network_mask+max_results+deadline_ms
// +target_hash+query_len).
constexpr std::size_t kK6SearchStartFixedSize = 1 + 1 + 2 + 4 + kHash16Size + 4;

// ── K6SearchResult limits ────────────────────────────────────────────────────
// Ticket count is capped independently of kK6TagListVersion's own limits —
// a search result is not expected to carry more than a handful of dial
// tickets (one per candidate exit/service).
constexpr std::size_t kK6SearchResultMaxTickets = 16;
// Fixed bytes before `tags` (result_id+result_kind+network_origin+tag_count
// +canonical_tags_len).
constexpr std::size_t kK6SearchResultFixedSize = kHash16Size + 1 + 1 + 2 + 4;

// ── K6SearchEnd ──────────────────────────────────────────────────────────────
enum class K6SearchEndStatus : Byte {
    Ok           = 0,
    Partial      = 1,
    Cancelled    = 2,
    Timeout      = 3,
    Overloaded   = 4,
    NoRoute      = 5,
    PolicyDenied = 6,
};

// Exact serialized size of a K6SearchEnd body (fixed; no variable-length part).
constexpr std::size_t kK6SearchEndBodySize = 13;

// ── Models ───────────────────────────────────────────────────────────────────
struct K6SearchStart {
    Byte               search_kind = kK6SearchKindKeyword;
    Byte               network_mask = 0;
    std::uint16_t      max_results = kK6SearchMinResults;
    std::uint32_t      deadline_ms = kK6SearchMinDeadlineMs;
    std::array<Byte, kHash16Size> target_hash{};
    std::vector<Byte>  query;
    std::vector<Byte>  options; // opaque TLV blob at this layer
};

struct K6SearchResult {
    std::array<Byte, kHash16Size> result_id{};
    Byte     result_kind = 0;
    Byte     network_origin = kK6NetOriginKad2;
    K6TagList tags;
    std::vector<K6TargetTicket> tickets;
};

struct K6SearchEnd {
    K6SearchEndStatus status = K6SearchEndStatus::Ok;
    std::uint16_t     result_count = 0;
    std::uint16_t     queried_nodes = 0;
    std::uint32_t     elapsed_ms = 0;
    Byte              load_hint = 0;
};

// ── K6M_SEARCH_START ─────────────────────────────────────────────────────────
// Serialize `s` into `out` (cleared first, and on any failure).
//   - search_kind outside the six v1 values -> BadValue
//   - network_mask empty or containing unknown bits -> BadValue
//   - max_results outside [kK6SearchMinResults, kK6SearchMaxResults] -> BadValue
//   - deadline_ms outside [kK6SearchMinDeadlineMs, kK6SearchMaxDeadlineMs] -> BadValue
//   - query.size()   > kK6SearchMaxQueryBytes   -> TooLarge
//   - options.size() > kK6SearchMaxOptionsBytes -> TooLarge
//   - all-zero target_hash -> BadValue
Kad6Status EncodeK6SearchStart(const K6SearchStart& s, std::vector<Byte>& out);

// Parse a K6M_SEARCH_START body from [in, in+len) using ByteReader exclusively.
//   - (in == nullptr, len != 0) -> NullArgument
//   - short input at any field  -> Truncated
//   - invalid search_kind/network_mask or all-zero target_hash -> Malformed
//   - max_results / deadline_ms outside their range -> Malformed (values are
//     well-formed integers, just out of the accepted range — a wire-level
//     policy violation, not a truncated/garbled buffer)
//   - query_len   > kK6SearchMaxQueryBytes   -> TooLarge (checked BEFORE the
//     query bytes are read/allocated)
//   - options_len > kK6SearchMaxOptionsBytes -> TooLarge (checked BEFORE the
//     options bytes are read/allocated)
// On success `out` is fully overwritten and, if `consumed` is non-null,
// receives the total bytes occupied. On any failure `out` is left at its
// default value.
Kad6Status DecodeK6SearchStart(const Byte* in, std::size_t len, K6SearchStart& out,
                                std::size_t* consumed = nullptr) noexcept;

// ── K6M_SEARCH_RESULT ────────────────────────────────────────────────────────
// Serialize `r` into `out` (cleared first, and on any failure).
//   - all-zero result_id, unknown result_kind, or invalid network_origin -> BadValue
//   - r.tickets.size() > kK6SearchResultMaxTickets -> TooLarge
//   - the tag list is serialized via EncodeK6TagList; any failure there
//     (TooLarge / BadValue / Malformed) propagates unchanged
//   - each ticket is serialized via EncodeK6TargetTicket; any failure there
//     propagates unchanged
// `canonical_tags_len` and `tag_count` are DERIVED from the encoded tag blob
// and `r.tags.size()` respectively — there is no separate, desyncable field.
Kad6Status EncodeK6SearchResult(const K6SearchResult& r, std::vector<Byte>& out);

// Parse a K6M_SEARCH_RESULT body from [in, in+len).
//   - (in == nullptr, len != 0) -> NullArgument
//   - short input at any fixed field -> Truncated
//   - all-zero result_id, unknown result_kind, or invalid network_origin -> Malformed
//   - canonical_tags_len > kK6MaxTagListBytes -> TooLarge, checked BEFORE the
//     tag bytes are read
//   - fewer than canonical_tags_len bytes remain -> Truncated
//   - the tag blob is decoded via DecodeK6TagList; any failure there
//     propagates unchanged; on success, the number of bytes DecodeK6TagList
//     reports as consumed MUST equal canonical_tags_len exactly, else
//     Malformed (the declared length disagrees with the actual blob)
//   - the decoded tag list's size MUST equal tag_count exactly, else Malformed
//   - ticket_count > kK6SearchResultMaxTickets -> TooLarge, checked BEFORE any
//     ticket is decoded
//   - each ticket is decoded via DecodeK6TargetTicket, advancing the cursor by
//     its own `consumed`; any ticket decode failure propagates unchanged
//     (the mac is NOT verified here — use VerifyK6TargetTicket for that)
// On success `out` is fully overwritten and, if `consumed` is non-null,
// receives the total bytes occupied. On any failure `out` is left at its
// default value.
Kad6Status DecodeK6SearchResult(const Byte* in, std::size_t len, K6SearchResult& out,
                                 std::size_t* consumed = nullptr) noexcept;

// ── K6M_SEARCH_END ───────────────────────────────────────────────────────────
// Serialize `e` into `out` (cleared first). A status outside the seven v1
// enumerators is BadValue; otherwise it writes reserved[3] as zero.
Kad6Status EncodeK6SearchEnd(const K6SearchEnd& e, std::vector<Byte>& out);

// Parse a K6M_SEARCH_END body from [in, in+len).
//   - (in == nullptr, len != 0) -> NullArgument
//   - len < kK6SearchEndBodySize -> Truncated
//   - status outside the seven v1 enumerators -> Malformed
//   - any of the 3 reserved bytes != 0 -> Malformed
// On success `out` is fully overwritten and, if `consumed` is non-null,
// receives kK6SearchEndBodySize. On any failure `out` is left at its default
// value.
Kad6Status DecodeK6SearchEnd(const Byte* in, std::size_t len, K6SearchEnd& out,
                              std::size_t* consumed = nullptr) noexcept;

} // namespace kad6
