// SPDX-License-Identifier: MIT
//
// test_kad6_tags.cpp — K6TagListV1 codec tests (ticket K6-1.3): round trip,
// canonical-sort determinism, and every reject path in kad6_tags.h's spec
// comment (K6-TAG-001..005). Rejects are exercised twice where practical:
// once through EncodeK6TagList (in-memory K6Tag -> wire) and once through
// DecodeK6TagList against hand-built wire bytes (wire -> in-memory), since
// the two functions validate independently and the decoder is the one
// facing attacker-controlled input.
//
//   from libkad6/:  make.bat test_kad6_tags tests\test_kad6_tags.cpp src\kad6_tags.cpp
#include "kad6/kad6_tags.h"
#include "kad6/kad6_bytes.h"
#include "kad6/kad6_types.h"

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

// Hand-build a raw K6TagListV1 buffer holding exactly one tag, bypassing
// EncodeK6TagList's own validation entirely -- lets a test feed the decoder
// deliberately malformed wire bytes it still must reject. `totalLenDelta`
// perturbs the declared total_len away from the true serialized size.
std::vector<Byte> RawOneTag(Byte name_kind, const std::vector<Byte>& name,
                            Byte value_kind, std::uint32_t value_len_field,
                            const std::vector<Byte>& value_bytes,
                            int totalLenDelta = 0) {
    std::vector<Byte> body;
    {
        ByteWriter bw(body);
        bw.u8(name_kind);
        bw.u8(static_cast<Byte>(name.size()));
        bw.bytes(name.data(), name.size());
        bw.u8(value_kind);
        bw.u32le(value_len_field);
        bw.bytes(value_bytes.data(), value_bytes.size());
    }
    std::vector<Byte> out;
    ByteWriter w(out);
    w.u8(1);      // version
    w.u16le(1);   // count
    const std::int64_t total = static_cast<std::int64_t>(7 + body.size()) + totalLenDelta;
    w.u32le(static_cast<std::uint32_t>(total));
    w.bytes(body.data(), body.size());
    return out;
}

} // namespace

int main() {
    // ── Round trip: numeric-name U32, utf8-name UTF8, HASH16 ───────────────
    {
        K6TagList list;
        list.push_back(MakeNumericTag(0x10, kK6ValU32, {0x01, 0x02, 0x03, 0x04}));
        list.push_back(MakeUtf8Tag("greeting", kK6ValUtf8, {'h', 'i'}));
        K6Tag hashTag;
        hashTag.name_kind = kK6NameKindNumericU8;
        hashTag.name = {0x20};
        hashTag.value_kind = kK6ValHash16;
        hashTag.value.assign(16, 0xAB);
        list.push_back(hashTag);

        std::vector<Byte> wire;
        CHECK(EncodeK6TagList(list, wire) == Kad6Status::Ok, "encode round-trip ok");

        K6TagList decoded;
        std::size_t consumed = 0;
        const Kad6Status dst = DecodeK6TagList(wire.data(), wire.size(), decoded, &consumed);
        CHECK(dst == Kad6Status::Ok, "decode round-trip ok");
        CHECK(consumed == wire.size(), "consumed == wire size");
        CHECK(decoded.size() == 3, "decoded 3 tags");
        if (decoded.size() == 3) {
            CHECK(decoded[0].name_kind == kK6NameKindNumericU8 &&
                  decoded[0].name.size() == 1 && decoded[0].name[0] == 0x10, "tag0 name");
            CHECK(decoded[0].value_kind == kK6ValU32 && decoded[0].value.size() == 4,
                  "tag0 value shape");
            CHECK(decoded[0].value == std::vector<Byte>({0x01, 0x02, 0x03, 0x04}),
                  "tag0 value bytes");

            CHECK(decoded[1].name_kind == kK6NameKindUtf8, "tag1 name kind");
            CHECK(std::string(decoded[1].name.begin(), decoded[1].name.end()) == "greeting",
                  "tag1 name bytes");
            CHECK(decoded[1].value_kind == kK6ValUtf8 &&
                  std::string(decoded[1].value.begin(), decoded[1].value.end()) == "hi",
                  "tag1 value");

            CHECK(decoded[2].value_kind == kK6ValHash16 && decoded[2].value.size() == 16,
                  "tag2 hash16 shape");
        }
    }

    // ── Canonical sort: deterministic, documented order ────────────────────
    {
        K6TagList list;
        list.push_back(MakeUtf8Tag("zzz", kK6ValU8, {0x01}));
        list.push_back(MakeNumericTag(0x05, kK6ValU8, {0x02}));
        list.push_back(MakeNumericTag(0x02, kK6ValU16, {0x00, 0x01}));
        list.push_back(MakeNumericTag(0x02, kK6ValU8, {0x09}));
        list.push_back(MakeUtf8Tag("aaa", kK6ValU8, {0x03}));

        Kad6TagsCanonicalSort(list);

        // Documented order: (name_kind asc, name bytes lexicographic asc,
        // value_kind asc, value bytes lexicographic asc). numeric_u8(0) < utf8(1);
        // among numeric names, byte 0x02 < 0x05; among the two name==0x02 tags,
        // value_kind U8(0) < U16(1); among utf8 names, "aaa" < "zzz".
        CHECK(list.size() == 5, "sort size preserved");
        if (list.size() == 5) {
            CHECK(list[0].name_kind == kK6NameKindNumericU8 && list[0].name[0] == 0x02 &&
                  list[0].value_kind == kK6ValU8, "sort[0] = (numeric 0x02, U8)");
            CHECK(list[1].name_kind == kK6NameKindNumericU8 && list[1].name[0] == 0x02 &&
                  list[1].value_kind == kK6ValU16, "sort[1] = (numeric 0x02, U16)");
            CHECK(list[2].name_kind == kK6NameKindNumericU8 && list[2].name[0] == 0x05,
                  "sort[2] = (numeric 0x05)");
            CHECK(list[3].name_kind == kK6NameKindUtf8 &&
                  std::string(list[3].name.begin(), list[3].name.end()) == "aaa",
                  "sort[3] = (utf8 \"aaa\")");
            CHECK(list[4].name_kind == kK6NameKindUtf8 &&
                  std::string(list[4].name.begin(), list[4].name.end()) == "zzz",
                  "sort[4] = (utf8 \"zzz\")");
        }
    }

    // ── Reject: 129 tags -> TooLarge (encode) ──────────────────────────────
    {
        K6TagList list;
        for (int i = 0; i < 129; ++i)
            list.push_back(MakeNumericTag(static_cast<Byte>(i & 0xFF), kK6ValU8, {0x00}));
        std::vector<Byte> wire;
        CHECK(EncodeK6TagList(list, wire) == Kad6Status::TooLarge, "encode 129 tags TooLarge");
        CHECK(wire.empty(), "encode 129 tags clears out");
    }
    // ── Reject: count=129 -> TooLarge before the body is even parsed (decode) ──
    {
        std::vector<Byte> wire;
        ByteWriter w(wire);
        w.u8(1);
        w.u16le(129);
        w.u32le(7); // no tag bytes follow -- decoder must not need them
        K6TagList decoded;
        CHECK(DecodeK6TagList(wire.data(), wire.size(), decoded) == Kad6Status::TooLarge,
              "decode count=129 TooLarge (header-only check)");
    }

    // ── Reject: U16 tag with value_len=3 -> BadValue ───────────────────────
    {
        K6TagList list;
        list.push_back(MakeNumericTag(0x01, kK6ValU16, {0x00, 0x01, 0x02}));
        std::vector<Byte> wire;
        CHECK(EncodeK6TagList(list, wire) == Kad6Status::BadValue, "encode U16 len=3 BadValue");

        std::vector<Byte> raw = RawOneTag(kK6NameKindNumericU8, {0x01}, kK6ValU16, 3,
                                          {0x00, 0x01, 0x02});
        K6TagList decoded;
        CHECK(DecodeK6TagList(raw.data(), raw.size(), decoded) == Kad6Status::BadValue,
              "decode U16 len=3 BadValue");
    }

    // ── Reject: UTF8 value containing 0x00 -> Malformed ────────────────────
    {
        K6TagList list;
        list.push_back(MakeNumericTag(0x02, kK6ValUtf8, {'a', 0x00, 'b'}));
        std::vector<Byte> wire;
        CHECK(EncodeK6TagList(list, wire) == Kad6Status::Malformed,
              "encode utf8 value w/ NUL Malformed");

        std::vector<Byte> raw = RawOneTag(kK6NameKindNumericU8, {0x02}, kK6ValUtf8, 3,
                                          {'a', 0x00, 'b'});
        K6TagList decoded;
        CHECK(DecodeK6TagList(raw.data(), raw.size(), decoded) == Kad6Status::Malformed,
              "decode utf8 value w/ NUL Malformed");
    }

    // ── Reject: value of 17 KiB -> TooLarge ─────────────────────────────────
    {
        std::vector<Byte> big(17 * 1024, 0x41);

        K6TagList list;
        list.push_back(MakeNumericTag(0x03, kK6ValBytes, big));
        std::vector<Byte> wire;
        CHECK(EncodeK6TagList(list, wire) == Kad6Status::TooLarge, "encode 17KiB value TooLarge");

        std::vector<Byte> raw = RawOneTag(kK6NameKindNumericU8, {0x03}, kK6ValBytes,
                                          static_cast<std::uint32_t>(big.size()), big);
        K6TagList decoded;
        CHECK(DecodeK6TagList(raw.data(), raw.size(), decoded) == Kad6Status::TooLarge,
              "decode 17KiB value TooLarge");
    }

    // ── Reject: HASH32 with value_len=31 -> BadValue ────────────────────────
    {
        std::vector<Byte> v31(31, 0x22);

        K6TagList list;
        list.push_back(MakeNumericTag(0x04, kK6ValHash32, v31));
        std::vector<Byte> wire;
        CHECK(EncodeK6TagList(list, wire) == Kad6Status::BadValue, "encode HASH32 len=31 BadValue");

        std::vector<Byte> raw = RawOneTag(kK6NameKindNumericU8, {0x04}, kK6ValHash32, 31, v31);
        K6TagList decoded;
        CHECK(DecodeK6TagList(raw.data(), raw.size(), decoded) == Kad6Status::BadValue,
              "decode HASH32 len=31 BadValue");
    }

    // ── Reject: utf8 name_len=65 -> BadValue ────────────────────────────────
    {
        const std::string longName(65, 'x');

        K6Tag t;
        t.name_kind = kK6NameKindUtf8;
        t.name.assign(longName.begin(), longName.end());
        t.value_kind = kK6ValU8;
        t.value = {0x01};
        K6TagList list;
        list.push_back(t);
        std::vector<Byte> wire;
        CHECK(EncodeK6TagList(list, wire) == Kad6Status::BadValue,
              "encode utf8 name_len=65 BadValue");

        const std::vector<Byte> nameBytes(longName.begin(), longName.end());
        std::vector<Byte> raw = RawOneTag(kK6NameKindUtf8, nameBytes, kK6ValU8, 1, {0x01});
        K6TagList decoded;
        CHECK(DecodeK6TagList(raw.data(), raw.size(), decoded) == Kad6Status::BadValue,
              "decode utf8 name_len=65 BadValue");
    }

    // ── UTF-8 validator: direct checks ──────────────────────────────────────
    {
        const Byte ok1[] = {'h', 'e', 'l', 'l', 'o'};
        CHECK(Kad6IsValidUtf8NoNul(ok1, 5), "utf8 ascii valid");
        const Byte ok2[] = {0xC3, 0xA9}; // U+00E9
        CHECK(Kad6IsValidUtf8NoNul(ok2, 2), "utf8 2-byte valid");
        const Byte ok3[] = {0xE2, 0x82, 0xAC}; // U+20AC euro sign
        CHECK(Kad6IsValidUtf8NoNul(ok3, 3), "utf8 3-byte valid");
        const Byte badNul[] = {'a', 0x00};
        CHECK(!Kad6IsValidUtf8NoNul(badNul, 2), "utf8 nul rejected");
        const Byte badTrunc[] = {0xC3};
        CHECK(!Kad6IsValidUtf8NoNul(badTrunc, 1), "utf8 truncated sequence rejected");
        const Byte badCont[] = {0xC3, 0x28};
        CHECK(!Kad6IsValidUtf8NoNul(badCont, 2), "utf8 bad continuation byte rejected");
        const Byte overlong[] = {0xC0, 0x80}; // overlong encoding of NUL
        CHECK(!Kad6IsValidUtf8NoNul(overlong, 2), "utf8 overlong encoding rejected");
        const Byte surrogate[] = {0xED, 0xA0, 0x80}; // U+D800, unpaired surrogate
        CHECK(!Kad6IsValidUtf8NoNul(surrogate, 3), "utf8 surrogate half rejected");
        CHECK(Kad6IsValidUtf8NoNul(nullptr, 0), "utf8 empty buffer valid");
    }

    // ── Decode cross-check: declared total_len must match bytes consumed ───
    {
        std::vector<Byte> raw = RawOneTag(kK6NameKindNumericU8, {0x07}, kK6ValU8, 1, {0x42},
                                          /*totalLenDelta=*/-1);
        K6TagList decoded;
        CHECK(DecodeK6TagList(raw.data(), raw.size(), decoded) == Kad6Status::Malformed,
              "decode total_len mismatch -> Malformed");
        CHECK(decoded.empty(), "decode failure leaves out empty");
    }

    // ── Decode: null buffer handling ────────────────────────────────────────
    {
        K6TagList decoded;
        CHECK(DecodeK6TagList(nullptr, 0, decoded) == Kad6Status::Truncated,
              "decode null+len0 -> Truncated (empty input)");
        CHECK(DecodeK6TagList(nullptr, 5, decoded) == Kad6Status::NullArgument,
              "decode null+len!=0 -> NullArgument (caller bug)");
    }

    std::printf("test_kad6_tags: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
