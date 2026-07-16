// SPDX-License-Identifier: MIT
//
// libkad6 — kad6_search.cpp: implementation of the three Kad6 search message
// bodies (ticket K6-1.2). New code, MIT, no MFC / sockets / threads /
// embedded crypto — see kad6_search.h for the wire layout and the invariants
// each check below enforces.
#include "kad6/kad6_search.h"

#include <utility>

namespace kad6 {

namespace {

template <std::size_t N>
bool IsAllZero(const std::array<Byte, N>& value) noexcept {
    Byte any = 0;
    for (Byte b : value)
        any = static_cast<Byte>(any | b);
    return any == 0;
}

bool IsValidSearchKind(Byte kind) noexcept {
    return kind <= kK6SearchKindRouter;
}

bool IsValidNetworkMask(Byte mask) noexcept {
    constexpr Byte kKnown = kK6NetMaskKad2 | kK6NetMaskKad6;
    return mask != 0 && (mask & static_cast<Byte>(~kKnown)) == 0;
}

bool IsValidNetworkOrigin(Byte origin) noexcept {
    return origin == kK6NetOriginKad2 || origin == kK6NetOriginKad6;
}

bool IsValidEndStatus(K6SearchEndStatus status) noexcept {
    return static_cast<Byte>(status) <= static_cast<Byte>(K6SearchEndStatus::PolicyDenied);
}

} // namespace

// ══════════════════════════════════════════════════════════════════════════
// K6M_SEARCH_START
// ══════════════════════════════════════════════════════════════════════════

Kad6Status EncodeK6SearchStart(const K6SearchStart& s, std::vector<Byte>& out) {
    out.clear();

    if (!IsValidSearchKind(s.search_kind) || !IsValidNetworkMask(s.network_mask))
        return Kad6Status::BadValue;
    if (s.max_results < kK6SearchMinResults || s.max_results > kK6SearchMaxResults)
        return Kad6Status::BadValue;
    if (s.deadline_ms < kK6SearchMinDeadlineMs || s.deadline_ms > kK6SearchMaxDeadlineMs)
        return Kad6Status::BadValue;
    if (s.query.size() > kK6SearchMaxQueryBytes)
        return Kad6Status::TooLarge;
    if (s.options.size() > kK6SearchMaxOptionsBytes)
        return Kad6Status::TooLarge;
    if (IsAllZero(s.target_hash))
        return Kad6Status::BadValue;

    ByteWriter w(out);
    w.u8(s.search_kind);
    w.u8(s.network_mask);
    w.u16le(s.max_results);
    w.u32le(s.deadline_ms);
    w.bytes(s.target_hash.data(), s.target_hash.size());
    w.u32le(static_cast<std::uint32_t>(s.query.size()));
    w.bytes(s.query.data(), s.query.size());
    w.u16le(static_cast<std::uint16_t>(s.options.size()));
    w.bytes(s.options.data(), s.options.size());
    return Kad6Status::Ok;
}

Kad6Status DecodeK6SearchStart(const Byte* in, std::size_t len, K6SearchStart& out,
                                std::size_t* consumed) noexcept {
    out = K6SearchStart{};
    if (consumed != nullptr)
        *consumed = 0;

    ByteReader r(in, len);
    if (r.null_arg())
        return Kad6Status::NullArgument;

    // Parse into a local value; `out` stays default until the whole body is
    // verified, so a failure partway through never leaks a partial parse.
    K6SearchStart tmp;

    if (!r.need(1 + 1 + 2 + 4))
        return Kad6Status::Truncated;
    tmp.search_kind  = r.u8();
    tmp.network_mask = r.u8();
    tmp.max_results  = r.u16le();
    tmp.deadline_ms  = r.u32le();

    if (!IsValidSearchKind(tmp.search_kind) || !IsValidNetworkMask(tmp.network_mask))
        return Kad6Status::Malformed;
    if (tmp.max_results < kK6SearchMinResults || tmp.max_results > kK6SearchMaxResults)
        return Kad6Status::Malformed;
    if (tmp.deadline_ms < kK6SearchMinDeadlineMs || tmp.deadline_ms > kK6SearchMaxDeadlineMs)
        return Kad6Status::Malformed;

    if (!r.bytes(tmp.target_hash.data(), tmp.target_hash.size()))
        return Kad6Status::Truncated;
    if (IsAllZero(tmp.target_hash))
        return Kad6Status::Malformed;

    if (!r.need(4))
        return Kad6Status::Truncated;
    const std::uint32_t query_len = r.u32le();
    if (query_len > kK6SearchMaxQueryBytes)
        return Kad6Status::TooLarge; // checked before the query bytes are read/allocated
    const Byte* queryPtr = r.take(query_len);
    if (queryPtr == nullptr)
        return Kad6Status::Truncated;
    tmp.query.assign(queryPtr, queryPtr + query_len);

    if (!r.need(2))
        return Kad6Status::Truncated;
    const std::uint16_t options_len = r.u16le();
    if (options_len > kK6SearchMaxOptionsBytes)
        return Kad6Status::TooLarge; // checked before the options bytes are read/allocated
    const Byte* optionsPtr = r.take(options_len);
    if (optionsPtr == nullptr)
        return Kad6Status::Truncated;
    tmp.options.assign(optionsPtr, optionsPtr + options_len);

    if (!r.ok())
        return Kad6Status::Truncated;

    out = std::move(tmp);
    if (consumed != nullptr)
        *consumed = r.pos();
    return Kad6Status::Ok;
}

// ══════════════════════════════════════════════════════════════════════════
// K6M_SEARCH_RESULT
// ══════════════════════════════════════════════════════════════════════════

Kad6Status EncodeK6SearchResult(const K6SearchResult& r, std::vector<Byte>& out) {
    out.clear();

    if (IsAllZero(r.result_id) || !IsValidSearchKind(r.result_kind) ||
        !IsValidNetworkOrigin(r.network_origin))
        return Kad6Status::BadValue;
    if (r.tickets.size() > kK6SearchResultMaxTickets)
        return Kad6Status::TooLarge;

    // Serialize the tag list and every ticket into scratch buffers FIRST —
    // if any sub-encode fails, `out` is never touched (stays empty).
    std::vector<Byte> tagsWire;
    const Kad6Status tagsStatus = EncodeK6TagList(r.tags, tagsWire);
    if (tagsStatus != Kad6Status::Ok)
        return tagsStatus;

    std::vector<std::vector<Byte>> ticketWires;
    ticketWires.reserve(r.tickets.size());
    for (const K6TargetTicket& tk : r.tickets) {
        std::vector<Byte> tw;
        const Kad6Status tks = EncodeK6TargetTicket(tk, tw);
        if (tks != Kad6Status::Ok)
            return tks;
        ticketWires.push_back(std::move(tw));
    }

    ByteWriter w(out);
    w.bytes(r.result_id.data(), r.result_id.size());
    w.u8(r.result_kind);
    w.u8(r.network_origin);
    w.u16le(static_cast<std::uint16_t>(r.tags.size()));      // tag_count, derived
    w.u32le(static_cast<std::uint32_t>(tagsWire.size()));     // canonical_tags_len, derived
    w.bytes(tagsWire.data(), tagsWire.size());
    w.u8(static_cast<Byte>(r.tickets.size()));                // ticket_count, derived
    for (const std::vector<Byte>& tw : ticketWires)
        w.bytes(tw.data(), tw.size());
    return Kad6Status::Ok;
}

Kad6Status DecodeK6SearchResult(const Byte* in, std::size_t len, K6SearchResult& out,
                                 std::size_t* consumed) noexcept {
    out = K6SearchResult{};
    if (consumed != nullptr)
        *consumed = 0;

    ByteReader r(in, len);
    if (r.null_arg())
        return Kad6Status::NullArgument;

    K6SearchResult tmp;

    if (!r.bytes(tmp.result_id.data(), tmp.result_id.size()))
        return Kad6Status::Truncated;
    if (!r.need(1 + 1 + 2 + 4))
        return Kad6Status::Truncated;
    tmp.result_kind    = r.u8();
    tmp.network_origin = r.u8();
    const std::uint16_t tag_count          = r.u16le();
    const std::uint32_t canonical_tags_len = r.u32le();

    if (IsAllZero(tmp.result_id) || !IsValidSearchKind(tmp.result_kind) ||
        !IsValidNetworkOrigin(tmp.network_origin))
        return Kad6Status::Malformed;

    // Bound canonical_tags_len BEFORE reading/allocating any tag bytes.
    if (canonical_tags_len > kK6MaxTagListBytes)
        return Kad6Status::TooLarge;
    const Byte* tagsPtr = r.take(canonical_tags_len);
    if (tagsPtr == nullptr)
        return Kad6Status::Truncated;

    std::size_t tagsConsumed = 0;
    const Kad6Status tagsStatus = DecodeK6TagList(tagsPtr, canonical_tags_len, tmp.tags,
                                                  &tagsConsumed);
    if (tagsStatus != Kad6Status::Ok)
        return tagsStatus;
    // The declared blob length must match what the embedded codec actually
    // consumed -- otherwise canonical_tags_len disagrees with the real blob.
    if (tagsConsumed != canonical_tags_len)
        return Kad6Status::Malformed;
    if (tmp.tags.size() != tag_count)
        return Kad6Status::Malformed;

    if (!r.need(1))
        return Kad6Status::Truncated;
    const Byte ticket_count = r.u8();
    if (ticket_count > kK6SearchResultMaxTickets)
        return Kad6Status::TooLarge; // checked before any ticket is decoded

    tmp.tickets.reserve(ticket_count);
    for (Byte i = 0; i < ticket_count; ++i) {
        K6TargetTicket tk;
        std::size_t tkConsumed = 0;
        const Kad6Status tks = DecodeK6TargetTicket(in + r.pos(), len - r.pos(), tk, &tkConsumed);
        if (tks != Kad6Status::Ok)
            return tks;
        (void)r.take(tkConsumed); // advance the cursor past this ticket
        tmp.tickets.push_back(std::move(tk));
    }

    if (!r.ok())
        return Kad6Status::Truncated;

    out = std::move(tmp);
    if (consumed != nullptr)
        *consumed = r.pos();
    return Kad6Status::Ok;
}

// ══════════════════════════════════════════════════════════════════════════
// K6M_SEARCH_END
// ══════════════════════════════════════════════════════════════════════════

Kad6Status EncodeK6SearchEnd(const K6SearchEnd& e, std::vector<Byte>& out) {
    out.clear();
    if (!IsValidEndStatus(e.status))
        return Kad6Status::BadValue;
    ByteWriter w(out);
    w.u8(static_cast<Byte>(e.status));
    w.u16le(e.result_count);
    w.u16le(e.queried_nodes);
    w.u32le(e.elapsed_ms);
    w.u8(e.load_hint);
    w.u8(0); w.u8(0); w.u8(0); // reserved[3] = 0
    return Kad6Status::Ok;
}

Kad6Status DecodeK6SearchEnd(const Byte* in, std::size_t len, K6SearchEnd& out,
                              std::size_t* consumed) noexcept {
    out = K6SearchEnd{};
    if (consumed != nullptr)
        *consumed = 0;

    ByteReader r(in, len);
    if (r.null_arg())
        return Kad6Status::NullArgument;

    if (!r.need(kK6SearchEndBodySize))
        return Kad6Status::Truncated;

    K6SearchEnd tmp;
    tmp.status         = static_cast<K6SearchEndStatus>(r.u8());
    tmp.result_count   = r.u16le();
    tmp.queried_nodes  = r.u16le();
    tmp.elapsed_ms     = r.u32le();
    tmp.load_hint      = r.u8();
    if (!IsValidEndStatus(tmp.status))
        return Kad6Status::Malformed;
    Byte reserved[3] = {0, 0, 0};
    if (!r.bytes(reserved, 3) || !r.ok())
        return Kad6Status::Truncated;
    if (reserved[0] != 0 || reserved[1] != 0 || reserved[2] != 0)
        return Kad6Status::Malformed;

    out = tmp;
    if (consumed != nullptr)
        *consumed = r.pos();
    return Kad6Status::Ok;
}

} // namespace kad6
