// SPDX-License-Identifier: MIT
//
// test_kad6_search.cpp — the three Kad6 search message body codecs (ticket
// K6-1.2): round trip, every reject path documented in kad6_search.h, prefix
// truncation, and a fixed-seed fuzz per message. Rejects are exercised twice
// where practical: once through the EncodeX validation (in-memory model ->
// wire) and once through hand-built wire bytes fed to DecodeX, since the two
// validate independently and the decoder is the one facing attacker-
// controlled input.
//
//   from libkad6/:  make.bat test_kad6_search tests\test_kad6_search.cpp ^
//                   src\kad6_search.cpp src\kad6_tags.cpp src\kad6_ticket.cpp ^
//                   src\kad6_endpoint.cpp src\kad6_address.cpp
#include "kad6/kad6_search.h"

#include <array>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

using namespace kad6;

static int g_fail = 0;
static int g_pass = 0;

#define CHECK(cond, msg) do { if (cond) { ++g_pass; } else { ++g_fail; \
    std::printf("  FAIL: %s  (%s:%d)\n", msg, __FILE__, __LINE__); } } while (0)

namespace {

// ── shared helpers ──────────────────────────────────────────────────────────

K6Tag MakeNumericTag(Byte nameByte, Byte valueKind, std::vector<Byte> value) {
    K6Tag t;
    t.name_kind = kK6NameKindNumericU8;
    t.name = {nameByte};
    t.value_kind = valueKind;
    t.value = std::move(value);
    return t;
}

K6Tag MakeUtf8Tag(const std::string& name, Byte valueKind, std::vector<Byte> value) {
    K6Tag t;
    t.name_kind = kK6NameKindUtf8;
    t.name.assign(name.begin(), name.end());
    t.value_kind = valueKind;
    t.value = std::move(value);
    return t;
}

// A structurally valid, already-mac'd ticket. Decode never verifies the mac
// (that is VerifyK6TargetTicket's job, tested separately in
// test_kad6_ticket.cpp), so a dummy mac pattern is fine here — this file only
// exercises the K6SearchResult codec's plumbing around ticket_count/consumed.
K6TargetTicket MakeSimpleTicket(Byte seed) {
    K6TargetTicket t;
    t.service = static_cast<Byte>(K6TicketService::Ed2kTcp);
    t.provenance_kind = static_cast<Byte>(K6Provenance::KadResult);
    t.lease_id = 0x1000u + seed;
    t.provenance_session = 42;
    t.provenance_stream = 7;
    t.provenance_seq = seed;
    for (Byte i = 0; i < 32; ++i) t.provenance_digest[i] = static_cast<Byte>(seed + i);
    t.target_endpoint.addr.family = Kad6Address::Family::IPv4;
    t.target_endpoint.addr.addr = {203, 0, 113, seed};
    t.target_endpoint.tcp_port = 4662;
    t.target_endpoint.udp_port = 4672;
    for (Byte i = 0; i < 16; ++i) t.object_hash[i] = static_cast<Byte>(i + seed);
    t.issued_at = 1000;
    t.expires_at = 1300;
    t.max_bytes = 12345;
    t.max_connections = 1;
    for (Byte i = 0; i < 16; ++i) t.nonce[i] = static_cast<Byte>(0xE0 + i);
    for (Byte i = 0; i < 32; ++i) t.mac[i] = static_cast<Byte>(0xAA + i); // dummy, unverified
    return t;
}

const std::array<Byte, 16> kZeroHash16{};
const std::array<Byte, 16> kNonZeroHash16{1};

K6SearchStart MakeMinimalStart() {
    K6SearchStart s;
    s.network_mask = kK6NetMaskKad6;
    s.target_hash = kNonZeroHash16;
    return s;
}

K6SearchResult MakeMinimalResult() {
    K6SearchResult r;
    r.result_id = kNonZeroHash16;
    r.result_kind = kK6SearchKindKeyword;
    r.network_origin = kK6NetOriginKad2;
    return r;
}

// Hand-build a raw K6M_SEARCH_START body, bypassing EncodeK6SearchStart's own
// validation entirely -- lets a test feed the decoder deliberately
// out-of-range/oversize wire bytes it still must reject independently.
std::vector<Byte> RawStart(Byte search_kind, Byte network_mask,
                            std::uint16_t max_results, std::uint32_t deadline_ms,
                            const std::array<Byte, 16>& hash,
                            std::uint32_t query_len_field, const std::vector<Byte>& query_bytes,
                            std::uint16_t options_len_field, const std::vector<Byte>& options_bytes) {
    std::vector<Byte> out;
    ByteWriter w(out);
    w.u8(search_kind);
    w.u8(network_mask);
    w.u16le(max_results);
    w.u32le(deadline_ms);
    w.bytes(hash.data(), hash.size());
    w.u32le(query_len_field);
    w.bytes(query_bytes.data(), query_bytes.size());
    w.u16le(options_len_field);
    w.bytes(options_bytes.data(), options_bytes.size());
    return out;
}

std::vector<Byte> ValidStartWire() {
    K6SearchStart s;
    s.search_kind = kK6SearchKindSourceHash;
    s.network_mask = kK6NetMaskKad2 | kK6NetMaskKad6;
    s.max_results = 50;
    s.deadline_ms = 30000;
    for (Byte i = 0; i < 16; ++i) s.target_hash[i] = static_cast<Byte>(0x10 + i);
    s.query = {'h', 'e', 'l', 'l', 'o'};
    s.options = {0x01, 0x02, 0x03};
    std::vector<Byte> wire;
    EncodeK6SearchStart(s, wire);
    return wire;
}

std::vector<Byte> ValidResultWire() {
    K6SearchResult r;
    for (Byte i = 0; i < 16; ++i) r.result_id[i] = static_cast<Byte>(0x30 + i);
    r.result_kind = 2;
    r.network_origin = kK6NetOriginKad6;
    r.tags.push_back(MakeNumericTag(0x01, kK6ValU32, {0x01, 0x02, 0x03, 0x04}));
    r.tags.push_back(MakeUtf8Tag("hi", kK6ValUtf8, {'h', 'i'}));
    r.tickets.push_back(MakeSimpleTicket(1));
    std::vector<Byte> wire;
    EncodeK6SearchResult(r, wire);
    return wire;
}

std::vector<Byte> ValidEndWire() {
    K6SearchEnd e;
    e.status = K6SearchEndStatus::Partial;
    e.result_count = 12;
    e.queried_nodes = 34;
    e.elapsed_ms = 56789;
    e.load_hint = 200;
    std::vector<Byte> wire;
    EncodeK6SearchEnd(e, wire);
    return wire;
}

// Generic "no proper prefix decodes Ok" check, parameterized over a Decode fn.
template <typename Out, typename DecodeFn>
void CheckNoPrefixOk(const std::vector<Byte>& wire, DecodeFn decode, const char* label) {
    bool anyOk = false;
    for (std::size_t n = 0; n < wire.size(); ++n) {
        Out out{};
        if (decode(wire.data(), n, out, nullptr) == Kad6Status::Ok)
            anyOk = true;
    }
    CHECK(!anyOk, label);
}

// Generic fixed-seed LCG fuzz: random buffers never crash, never report Ok
// with consumed > the buffer length actually supplied.
template <typename Out, typename DecodeFn>
void FuzzNeverCrashNeverOverconsume(DecodeFn decode, std::uint32_t seed, const char* label) {
    std::uint32_t st = seed;
    auto rnd = [&]() { st = st * 1664525u + 1013904223u; return static_cast<Byte>(st >> 24); };
    bool spuriousOk = false;
    for (int iter = 0; iter < 5000; ++iter) {
        const std::size_t n = rnd() % 300;
        std::vector<Byte> buf(n);
        for (auto& b : buf) b = rnd();
        Out out{};
        std::size_t c = 0;
        if (decode(buf.empty() ? nullptr : buf.data(), n, out, &c) == Kad6Status::Ok) {
            if (c > n) spuriousOk = true;
        }
    }
    CHECK(!spuriousOk, label);
}

} // namespace

// ══════════════════════════════════════════════════════════════════════════
// K6M_SEARCH_START
// ══════════════════════════════════════════════════════════════════════════

static void test_start_roundtrip() {
    K6SearchStart s;
    s.search_kind = kK6SearchKindSourceHash;
    s.network_mask = kK6NetMaskKad2 | kK6NetMaskKad6;
    s.max_results = 50;
    s.deadline_ms = 30000;
    for (Byte i = 0; i < 16; ++i) s.target_hash[i] = static_cast<Byte>(0x10 + i);
    s.query = {'h', 'e', 'l', 'l', 'o'};
    s.options = {0x01, 0x02, 0x03};

    std::vector<Byte> wire;
    CHECK(EncodeK6SearchStart(s, wire) == Kad6Status::Ok, "start encode ok");

    K6SearchStart dec;
    std::size_t consumed = 0;
    CHECK(DecodeK6SearchStart(wire.data(), wire.size(), dec, &consumed) == Kad6Status::Ok,
          "start decode ok");
    CHECK(consumed == wire.size(), "start consumed == wire size");
    CHECK(dec.search_kind == s.search_kind, "start search_kind round trip");
    CHECK(dec.network_mask == s.network_mask, "start network_mask round trip");
    CHECK(dec.max_results == s.max_results, "start max_results round trip");
    CHECK(dec.deadline_ms == s.deadline_ms, "start deadline_ms round trip");
    CHECK(dec.target_hash == s.target_hash, "start target_hash round trip");
    CHECK(dec.query == s.query, "start query round trip");
    CHECK(dec.options == s.options, "start options round trip");

    // Empty query/options round-trip too (both are optional-length, not optional).
    K6SearchStart s2 = MakeMinimalStart();
    s2.max_results = 1;
    s2.deadline_ms = 1000;
    std::vector<Byte> wire2;
    CHECK(EncodeK6SearchStart(s2, wire2) == Kad6Status::Ok, "start encode (empty q/opts) ok");
    K6SearchStart dec2;
    std::size_t consumed2 = 0;
    CHECK(DecodeK6SearchStart(wire2.data(), wire2.size(), dec2, &consumed2) == Kad6Status::Ok,
          "start decode (empty q/opts) ok");
    CHECK(consumed2 == wire2.size(), "start (empty) consumed == wire size");
    CHECK(dec2.query.empty() && dec2.options.empty(), "start (empty) query/options empty");
}

static void test_start_rejects() {
    {
        K6SearchStart s = MakeMinimalStart(); s.search_kind = 6;
        std::vector<Byte> wire;
        CHECK(EncodeK6SearchStart(s, wire) == Kad6Status::BadValue,
              "start encode rejects unknown search_kind");
    }
    {
        K6SearchStart s = MakeMinimalStart(); s.network_mask = 0;
        std::vector<Byte> wire;
        CHECK(EncodeK6SearchStart(s, wire) == Kad6Status::BadValue,
              "start encode rejects empty network_mask");
        s.network_mask = 0x04;
        CHECK(EncodeK6SearchStart(s, wire) == Kad6Status::BadValue,
              "start encode rejects unknown network_mask bits");
    }
    {
        K6SearchStart s = MakeMinimalStart(); s.target_hash = kZeroHash16;
        std::vector<Byte> wire;
        CHECK(EncodeK6SearchStart(s, wire) == Kad6Status::BadValue,
              "start encode rejects all-zero target_hash");
    }
    // ── Encode-side range/size rejects ──────────────────────────────────────
    {
        K6SearchStart s = MakeMinimalStart(); s.max_results = 0; s.deadline_ms = 30000;
        std::vector<Byte> wire;
        CHECK(EncodeK6SearchStart(s, wire) == Kad6Status::BadValue, "start encode max_results=0 BadValue");
        CHECK(wire.empty(), "start encode max_results=0 clears out");
    }
    {
        K6SearchStart s = MakeMinimalStart(); s.max_results = 201; s.deadline_ms = 30000;
        std::vector<Byte> wire;
        CHECK(EncodeK6SearchStart(s, wire) == Kad6Status::BadValue, "start encode max_results=201 BadValue");
    }
    {
        K6SearchStart s = MakeMinimalStart(); s.max_results = 10; s.deadline_ms = 999;
        std::vector<Byte> wire;
        CHECK(EncodeK6SearchStart(s, wire) == Kad6Status::BadValue, "start encode deadline_ms=999 BadValue");
    }
    {
        K6SearchStart s = MakeMinimalStart(); s.max_results = 10; s.deadline_ms = 120001;
        std::vector<Byte> wire;
        CHECK(EncodeK6SearchStart(s, wire) == Kad6Status::BadValue, "start encode deadline_ms=120001 BadValue");
    }
    {
        K6SearchStart s = MakeMinimalStart(); s.max_results = 10; s.deadline_ms = 30000;
        s.query.assign(kK6SearchMaxQueryBytes + 1, 0x41);
        std::vector<Byte> wire;
        CHECK(EncodeK6SearchStart(s, wire) == Kad6Status::TooLarge, "start encode oversize query TooLarge");
    }
    {
        K6SearchStart s = MakeMinimalStart(); s.max_results = 10; s.deadline_ms = 30000;
        s.options.assign(kK6SearchMaxOptionsBytes + 1, 0x42);
        std::vector<Byte> wire;
        CHECK(EncodeK6SearchStart(s, wire) == Kad6Status::TooLarge, "start encode oversize options TooLarge");
    }
    // Boundary values (1, 200, 1000, 120000) must be accepted.
    {
        K6SearchStart s = MakeMinimalStart(); s.max_results = 1; s.deadline_ms = 1000;
        std::vector<Byte> wire;
        CHECK(EncodeK6SearchStart(s, wire) == Kad6Status::Ok, "start encode boundary low ok");
    }
    {
        K6SearchStart s = MakeMinimalStart(); s.max_results = 200; s.deadline_ms = 120000;
        std::vector<Byte> wire;
        CHECK(EncodeK6SearchStart(s, wire) == Kad6Status::Ok, "start encode boundary high ok");
    }

    // ── Decode-side: independent validation against hand-built wire bytes ───
    {
        auto raw = RawStart(6, kK6NetMaskKad6, 10, 30000, kNonZeroHash16, 0, {}, 0, {});
        K6SearchStart dec;
        CHECK(DecodeK6SearchStart(raw.data(), raw.size(), dec) == Kad6Status::Malformed,
              "start decode rejects unknown search_kind");
    }
    {
        auto raw = RawStart(0, 0, 10, 30000, kNonZeroHash16, 0, {}, 0, {});
        K6SearchStart dec;
        CHECK(DecodeK6SearchStart(raw.data(), raw.size(), dec) == Kad6Status::Malformed,
              "start decode rejects empty network_mask");
        raw = RawStart(0, 0x04, 10, 30000, kNonZeroHash16, 0, {}, 0, {});
        CHECK(DecodeK6SearchStart(raw.data(), raw.size(), dec) == Kad6Status::Malformed,
              "start decode rejects unknown network_mask bits");
    }
    {
        auto raw = RawStart(0, kK6NetMaskKad6, 10, 30000, kZeroHash16, 0, {}, 0, {});
        K6SearchStart dec;
        CHECK(DecodeK6SearchStart(raw.data(), raw.size(), dec) == Kad6Status::Malformed,
              "start decode rejects all-zero target_hash");
    }
    {
        auto raw = RawStart(0, kK6NetMaskKad6, 0, 30000, kNonZeroHash16, 0, {}, 0, {});
        K6SearchStart dec;
        CHECK(DecodeK6SearchStart(raw.data(), raw.size(), dec) == Kad6Status::Malformed,
              "start decode max_results=0 Malformed");
        CHECK(dec.query.empty() && dec.options.empty(), "start decode failure leaves out default");
    }
    {
        auto raw = RawStart(0, kK6NetMaskKad6, 201, 30000, kNonZeroHash16, 0, {}, 0, {});
        K6SearchStart dec;
        CHECK(DecodeK6SearchStart(raw.data(), raw.size(), dec) == Kad6Status::Malformed,
              "start decode max_results=201 Malformed");
    }
    {
        auto raw = RawStart(0, kK6NetMaskKad6, 10, 999, kNonZeroHash16, 0, {}, 0, {});
        K6SearchStart dec;
        CHECK(DecodeK6SearchStart(raw.data(), raw.size(), dec) == Kad6Status::Malformed,
              "start decode deadline_ms=999 Malformed");
    }
    {
        auto raw = RawStart(0, kK6NetMaskKad6, 10, 120001, kNonZeroHash16, 0, {}, 0, {});
        K6SearchStart dec;
        CHECK(DecodeK6SearchStart(raw.data(), raw.size(), dec) == Kad6Status::Malformed,
              "start decode deadline_ms=120001 Malformed");
    }
    {
        // query_len declares an over-cap value; TooLarge must fire before the
        // (absent) query bytes would ever be read.
        auto raw = RawStart(0, kK6NetMaskKad6, 10, 30000, kNonZeroHash16,
                             static_cast<std::uint32_t>(kK6SearchMaxQueryBytes + 1), {}, 0, {});
        K6SearchStart dec;
        CHECK(DecodeK6SearchStart(raw.data(), raw.size(), dec) == Kad6Status::TooLarge,
              "start decode query_len over cap TooLarge");
    }
    {
        auto raw = RawStart(0, kK6NetMaskKad6, 10, 30000, kNonZeroHash16, 0, {},
                             static_cast<std::uint16_t>(kK6SearchMaxOptionsBytes + 1), {});
        K6SearchStart dec;
        CHECK(DecodeK6SearchStart(raw.data(), raw.size(), dec) == Kad6Status::TooLarge,
              "start decode options_len over cap TooLarge");
    }
    // Null buffer handling.
    {
        K6SearchStart dec;
        CHECK(DecodeK6SearchStart(nullptr, 0, dec) == Kad6Status::Truncated,
              "start decode null+len0 -> Truncated");
        CHECK(DecodeK6SearchStart(nullptr, 5, dec) == Kad6Status::NullArgument,
              "start decode null+len!=0 -> NullArgument");
    }
}

static void test_start_truncation_and_fuzz() {
    const std::vector<Byte> wire = ValidStartWire();
    CHECK(!wire.empty(), "start: valid wire non-empty (fixture sanity)");

    auto decode = [](const Byte* p, std::size_t n, K6SearchStart& out, std::size_t* c) {
        return DecodeK6SearchStart(p, n, out, c);
    };
    CheckNoPrefixOk<K6SearchStart>(wire, decode, "start: no proper prefix decodes Ok");
    FuzzNeverCrashNeverOverconsume<K6SearchStart>(decode, 0xC0FFEEu,
        "start fuzz: consumed never exceeds input");
}

// ══════════════════════════════════════════════════════════════════════════
// K6M_SEARCH_RESULT
// ══════════════════════════════════════════════════════════════════════════

static void test_result_roundtrip() {
    K6SearchResult r;
    for (Byte i = 0; i < 16; ++i) r.result_id[i] = static_cast<Byte>(0x30 + i);
    r.result_kind = 2;
    r.network_origin = kK6NetOriginKad6;
    r.tags.push_back(MakeNumericTag(0x01, kK6ValU32, {0x01, 0x02, 0x03, 0x04}));
    r.tags.push_back(MakeUtf8Tag("hi", kK6ValUtf8, {'h', 'i'}));
    r.tickets.push_back(MakeSimpleTicket(1));

    std::vector<Byte> wire;
    CHECK(EncodeK6SearchResult(r, wire) == Kad6Status::Ok, "result encode ok");

    K6SearchResult dec;
    std::size_t consumed = 0;
    CHECK(DecodeK6SearchResult(wire.data(), wire.size(), dec, &consumed) == Kad6Status::Ok,
          "result decode ok");
    CHECK(consumed == wire.size(), "result consumed == wire size");
    CHECK(dec.result_id == r.result_id, "result result_id round trip");
    CHECK(dec.result_kind == r.result_kind, "result result_kind round trip");
    CHECK(dec.network_origin == r.network_origin, "result network_origin round trip");
    CHECK(dec.tags.size() == 2, "result tags size round trip");
    if (dec.tags.size() == 2) {
        CHECK(dec.tags[0].value_kind == kK6ValU32, "result tag0 value_kind");
        CHECK(dec.tags[1].value_kind == kK6ValUtf8, "result tag1 value_kind");
    }
    CHECK(dec.tickets.size() == 1, "result tickets size round trip");
    if (dec.tickets.size() == 1) {
        CHECK(dec.tickets[0].lease_id == r.tickets[0].lease_id, "result ticket lease_id round trip");
        CHECK(dec.tickets[0].mac == r.tickets[0].mac, "result ticket mac round trip (unverified)");
    }

    // Zero tags, zero tickets round-trips too.
    K6SearchResult r2 = MakeMinimalResult();
    std::vector<Byte> wire2;
    CHECK(EncodeK6SearchResult(r2, wire2) == Kad6Status::Ok, "result encode (empty) ok");
    K6SearchResult dec2;
    std::size_t consumed2 = 0;
    CHECK(DecodeK6SearchResult(wire2.data(), wire2.size(), dec2, &consumed2) == Kad6Status::Ok,
          "result decode (empty) ok");
    CHECK(consumed2 == wire2.size(), "result (empty) consumed == wire size");
    CHECK(dec2.tags.empty() && dec2.tickets.empty(), "result (empty) tags/tickets empty");

    // Two tickets round-trip (exercises the ticket loop advancing more than once).
    K6SearchResult r3 = MakeMinimalResult();
    r3.tickets.push_back(MakeSimpleTicket(3));
    r3.tickets.push_back(MakeSimpleTicket(4));
    std::vector<Byte> wire3;
    CHECK(EncodeK6SearchResult(r3, wire3) == Kad6Status::Ok, "result encode (2 tickets) ok");
    K6SearchResult dec3;
    std::size_t consumed3 = 0;
    CHECK(DecodeK6SearchResult(wire3.data(), wire3.size(), dec3, &consumed3) == Kad6Status::Ok,
          "result decode (2 tickets) ok");
    CHECK(consumed3 == wire3.size(), "result (2 tickets) consumed == wire size");
    CHECK(dec3.tickets.size() == 2, "result (2 tickets) size round trip");
    if (dec3.tickets.size() == 2) {
        CHECK(dec3.tickets[0].lease_id == r3.tickets[0].lease_id, "result ticket0 lease_id");
        CHECK(dec3.tickets[1].lease_id == r3.tickets[1].lease_id, "result ticket1 lease_id");
    }
}

static void test_result_rejects() {
    {
        K6SearchResult r = MakeMinimalResult();
        std::vector<Byte> wire;
        r.result_id = kZeroHash16;
        CHECK(EncodeK6SearchResult(r, wire) == Kad6Status::BadValue,
              "result encode rejects all-zero result_id");
        r = MakeMinimalResult(); r.result_kind = 6;
        CHECK(EncodeK6SearchResult(r, wire) == Kad6Status::BadValue,
              "result encode rejects unknown result_kind");
        r = MakeMinimalResult(); r.network_origin = 0;
        CHECK(EncodeK6SearchResult(r, wire) == Kad6Status::BadValue,
              "result encode rejects invalid network_origin");
    }
    {
        std::vector<Byte> raw = ValidResultWire();
        for (std::size_t i = 0; i < 16; ++i) raw[i] = 0;
        K6SearchResult dec;
        CHECK(DecodeK6SearchResult(raw.data(), raw.size(), dec) == Kad6Status::Malformed,
              "result decode rejects all-zero result_id");
        raw = ValidResultWire(); raw[16] = 6;
        CHECK(DecodeK6SearchResult(raw.data(), raw.size(), dec) == Kad6Status::Malformed,
              "result decode rejects unknown result_kind");
        raw = ValidResultWire(); raw[17] = 0;
        CHECK(DecodeK6SearchResult(raw.data(), raw.size(), dec) == Kad6Status::Malformed,
              "result decode rejects invalid network_origin");
    }
    // ── Encode-side: ticket_count over cap ──────────────────────────────────
    {
        K6SearchResult r = MakeMinimalResult();
        r.tickets.assign(kK6SearchResultMaxTickets + 1, MakeSimpleTicket(9));
        std::vector<Byte> wire;
        CHECK(EncodeK6SearchResult(r, wire) == Kad6Status::TooLarge,
              "result encode ticket_count over cap TooLarge");
        CHECK(wire.empty(), "result encode ticket_count over cap clears out");
    }

    // ── Decode-side: canonical_tags_len disagrees with the actual tag blob ──
    // (over-declared: the real K6TagListV1 blob fully parses but consumes
    // fewer bytes than canonical_tags_len claims -- padding bytes fill the
    // rest of the declared region so the outer buffer is otherwise valid.)
    {
        K6TagList tags;
        tags.push_back(MakeNumericTag(0x02, kK6ValU8, {0x09}));
        std::vector<Byte> tagsWire;
        CHECK(EncodeK6TagList(tags, tagsWire) == Kad6Status::Ok, "helper: tagsWire encode ok");

        std::vector<Byte> raw;
        ByteWriter w(raw);
        w.bytes(kNonZeroHash16.data(), kNonZeroHash16.size());
        w.u8(0);                    // result_kind
        w.u8(kK6NetOriginKad2);     // network_origin
        w.u16le(static_cast<std::uint16_t>(tags.size())); // tag_count (correct)
        const std::size_t padding = 5;
        w.u32le(static_cast<std::uint32_t>(tagsWire.size() + padding)); // canonical_tags_len OVER-declared
        w.bytes(tagsWire.data(), tagsWire.size());
        for (std::size_t i = 0; i < padding; ++i) w.u8(0x00); // filler so the declared region exists
        w.u8(0); // ticket_count = 0

        K6SearchResult dec;
        CHECK(DecodeK6SearchResult(raw.data(), raw.size(), dec) == Kad6Status::Malformed,
              "result decode canonical_tags_len mismatch -> Malformed");
    }

    // ── Decode-side: tag_count disagrees with the decoded list size ─────────
    {
        K6TagList tags;
        tags.push_back(MakeNumericTag(0x03, kK6ValU8, {0x01}));
        tags.push_back(MakeNumericTag(0x04, kK6ValU8, {0x02}));
        std::vector<Byte> tagsWire;
        CHECK(EncodeK6TagList(tags, tagsWire) == Kad6Status::Ok, "helper: tagsWire2 encode ok");

        std::vector<Byte> raw;
        ByteWriter w(raw);
        w.bytes(kNonZeroHash16.data(), kNonZeroHash16.size());
        w.u8(0);
        w.u8(kK6NetOriginKad2);
        w.u16le(static_cast<std::uint16_t>(tags.size() + 1)); // WRONG tag_count (declares 3, actual 2)
        w.u32le(static_cast<std::uint32_t>(tagsWire.size()));  // canonical_tags_len correct
        w.bytes(tagsWire.data(), tagsWire.size());
        w.u8(0); // ticket_count = 0

        K6SearchResult dec;
        CHECK(DecodeK6SearchResult(raw.data(), raw.size(), dec) == Kad6Status::Malformed,
              "result decode tag_count mismatch -> Malformed");
    }

    // ── Decode-side: ticket_count over cap (checked before any ticket read) ──
    {
        K6TagList emptyTags;
        std::vector<Byte> tagsWire;
        CHECK(EncodeK6TagList(emptyTags, tagsWire) == Kad6Status::Ok, "helper: empty tagsWire encode ok");

        std::vector<Byte> raw;
        ByteWriter w(raw);
        w.bytes(kNonZeroHash16.data(), kNonZeroHash16.size());
        w.u8(0);
        w.u8(kK6NetOriginKad2);
        w.u16le(0); // tag_count = 0
        w.u32le(static_cast<std::uint32_t>(tagsWire.size()));
        w.bytes(tagsWire.data(), tagsWire.size());
        w.u8(static_cast<Byte>(kK6SearchResultMaxTickets + 1)); // ticket_count over cap, no ticket bytes follow

        K6SearchResult dec;
        CHECK(DecodeK6SearchResult(raw.data(), raw.size(), dec) == Kad6Status::TooLarge,
              "result decode ticket_count over cap TooLarge");
    }

    // Null buffer handling.
    {
        K6SearchResult dec;
        CHECK(DecodeK6SearchResult(nullptr, 0, dec) == Kad6Status::Truncated,
              "result decode null+len0 -> Truncated");
        CHECK(DecodeK6SearchResult(nullptr, 5, dec) == Kad6Status::NullArgument,
              "result decode null+len!=0 -> NullArgument");
    }
}

static void test_result_truncation_and_fuzz() {
    const std::vector<Byte> wire = ValidResultWire();
    CHECK(!wire.empty(), "result: valid wire non-empty (fixture sanity)");

    auto decode = [](const Byte* p, std::size_t n, K6SearchResult& out, std::size_t* c) {
        return DecodeK6SearchResult(p, n, out, c);
    };
    CheckNoPrefixOk<K6SearchResult>(wire, decode, "result: no proper prefix decodes Ok");
    FuzzNeverCrashNeverOverconsume<K6SearchResult>(decode, 0xDEADBEEFu,
        "result fuzz: consumed never exceeds input");
}

// ══════════════════════════════════════════════════════════════════════════
// K6M_SEARCH_END
// ══════════════════════════════════════════════════════════════════════════

static void test_end_roundtrip() {
    K6SearchEnd e;
    e.status = K6SearchEndStatus::Partial;
    e.result_count = 12;
    e.queried_nodes = 34;
    e.elapsed_ms = 56789;
    e.load_hint = 200;

    std::vector<Byte> wire;
    CHECK(EncodeK6SearchEnd(e, wire) == Kad6Status::Ok, "end encode ok");
    CHECK(wire.size() == kK6SearchEndBodySize, "end wire size == 13");

    K6SearchEnd dec;
    std::size_t consumed = 0;
    CHECK(DecodeK6SearchEnd(wire.data(), wire.size(), dec, &consumed) == Kad6Status::Ok,
          "end decode ok");
    CHECK(consumed == kK6SearchEndBodySize, "end consumed == 13");
    CHECK(dec.status == e.status, "end status round trip");
    CHECK(dec.result_count == e.result_count, "end result_count round trip");
    CHECK(dec.queried_nodes == e.queried_nodes, "end queried_nodes round trip");
    CHECK(dec.elapsed_ms == e.elapsed_ms, "end elapsed_ms round trip");
    CHECK(dec.load_hint == e.load_hint, "end load_hint round trip");

    // Every status enumerator round-trips.
    const K6SearchEndStatus all[] = {
        K6SearchEndStatus::Ok, K6SearchEndStatus::Partial, K6SearchEndStatus::Cancelled,
        K6SearchEndStatus::Timeout, K6SearchEndStatus::Overloaded, K6SearchEndStatus::NoRoute,
        K6SearchEndStatus::PolicyDenied,
    };
    for (K6SearchEndStatus st : all) {
        K6SearchEnd e2; e2.status = st;
        std::vector<Byte> w2;
        CHECK(EncodeK6SearchEnd(e2, w2) == Kad6Status::Ok, "end encode status variant ok");
        K6SearchEnd d2;
        CHECK(DecodeK6SearchEnd(w2.data(), w2.size(), d2) == Kad6Status::Ok, "end decode status variant ok");
        CHECK(d2.status == st, "end status variant round trip");
    }
}

static void test_end_rejects() {
    {
        K6SearchEnd e;
        e.status = static_cast<K6SearchEndStatus>(7);
        std::vector<Byte> wire;
        CHECK(EncodeK6SearchEnd(e, wire) == Kad6Status::BadValue,
              "end encode rejects unknown status");

        wire.assign(kK6SearchEndBodySize, 0);
        wire[0] = 7;
        K6SearchEnd dec;
        CHECK(DecodeK6SearchEnd(wire.data(), wire.size(), dec) == Kad6Status::Malformed,
              "end decode rejects unknown status");
    }
    // Reserved bytes must be 0; flip each of the 3 independently.
    {
        std::vector<Byte> raw;
        ByteWriter w(raw);
        w.u8(0); w.u16le(1); w.u16le(2); w.u32le(100); w.u8(50);
        w.u8(0x01); w.u8(0x00); w.u8(0x00); // reserved[0] != 0
        K6SearchEnd dec;
        CHECK(DecodeK6SearchEnd(raw.data(), raw.size(), dec) == Kad6Status::Malformed,
              "end decode reserved[0]!=0 -> Malformed");
    }
    {
        std::vector<Byte> raw;
        ByteWriter w(raw);
        w.u8(0); w.u16le(1); w.u16le(2); w.u32le(100); w.u8(50);
        w.u8(0x00); w.u8(0x02); w.u8(0x00); // reserved[1] != 0
        K6SearchEnd dec;
        CHECK(DecodeK6SearchEnd(raw.data(), raw.size(), dec) == Kad6Status::Malformed,
              "end decode reserved[1]!=0 -> Malformed");
    }
    {
        std::vector<Byte> raw;
        ByteWriter w(raw);
        w.u8(0); w.u16le(1); w.u16le(2); w.u32le(100); w.u8(50);
        w.u8(0x00); w.u8(0x00); w.u8(0x03); // reserved[2] != 0
        K6SearchEnd dec;
        CHECK(DecodeK6SearchEnd(raw.data(), raw.size(), dec) == Kad6Status::Malformed,
              "end decode reserved[2]!=0 -> Malformed");
    }
    // Null buffer handling.
    {
        K6SearchEnd dec;
        CHECK(DecodeK6SearchEnd(nullptr, 0, dec) == Kad6Status::Truncated,
              "end decode null+len0 -> Truncated");
        CHECK(DecodeK6SearchEnd(nullptr, 5, dec) == Kad6Status::NullArgument,
              "end decode null+len!=0 -> NullArgument");
    }
}

static void test_end_truncation_and_fuzz() {
    const std::vector<Byte> wire = ValidEndWire();
    CHECK(wire.size() == kK6SearchEndBodySize, "end: valid wire is exactly 13 bytes (fixture sanity)");

    auto decode = [](const Byte* p, std::size_t n, K6SearchEnd& out, std::size_t* c) {
        return DecodeK6SearchEnd(p, n, out, c);
    };
    CheckNoPrefixOk<K6SearchEnd>(wire, decode, "end: no proper prefix decodes Ok");
    FuzzNeverCrashNeverOverconsume<K6SearchEnd>(decode, 0x5EED1234u,
        "end fuzz: consumed never exceeds input");
}

int main() {
    test_start_roundtrip();
    test_start_rejects();
    test_start_truncation_and_fuzz();

    test_result_roundtrip();
    test_result_rejects();
    test_result_truncation_and_fuzz();

    test_end_roundtrip();
    test_end_rejects();
    test_end_truncation_and_fuzz();

    std::printf("test_kad6_search: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
