// SPDX-License-Identifier: MIT
//
// libkad6 — kad6_tags.cpp: implementation of the K6TagListV1 codec
// (ticket K6-1.3). New code, MIT, no MFC / sockets / threads / embedded
// crypto — see kad6_tags.h for the wire layout and the invariants each
// check below enforces.
#include "kad6/kad6_tags.h"
#include "kad6/kad6_address.h"
#include "kad6/kad6_bytes.h"

#include <algorithm>

namespace kad6 {

namespace {

// K6TagListV1 header: version(1) + count(2) + total_len(4).
constexpr std::size_t kHeaderSize = 1 + 2 + 4;
// K6TagV1 fixed overhead: name_kind(1) + name_len(1) + value_kind(1) + value_len(4).
constexpr std::size_t kTagFixedOverhead = 1 + 1 + 1 + 4;

bool IsKnownValueKind(Byte k) noexcept {
    return k <= kK6ValCAddress; // 0..9, contiguous
}

bool IsFixedWidthValueKind(Byte k) noexcept {
    switch (k) {
        case kK6ValU8:
        case kK6ValU16:
        case kK6ValU32:
        case kK6ValU64:
        case kK6ValHash16:
        case kK6ValHash20:
        case kK6ValHash32:
            return true;
        default:
            return false;
    }
}

// Exact required length for a fixed-width value_kind. Caller must have
// already confirmed IsFixedWidthValueKind(k).
std::size_t FixedValueLen(Byte k) noexcept {
    switch (k) {
        case kK6ValU8:     return 1;
        case kK6ValU16:    return 2;
        case kK6ValU32:    return 4;
        case kK6ValU64:    return 8;
        case kK6ValHash16: return 16;
        case kK6ValHash20: return 20;
        case kK6ValHash32: return 32;
        default:           return 0;
    }
}

// Structural validation of one in-memory tag (name/value_kind rules, UTF-8
// validity). Does NOT check the kK6MaxTagValueBytes limit -- callers check
// that themselves so the "checked before allocating" ordering stays visible
// at the call site.
Kad6Status ValidateTagShape(const K6Tag& t) noexcept {
    if (t.name_kind == kK6NameKindNumericU8) {
        if (t.name.size() != 1)
            return Kad6Status::BadValue;
    } else if (t.name_kind == kK6NameKindUtf8) {
        if (t.name.empty() || t.name.size() > kK6MaxUtf8NameLen)
            return Kad6Status::BadValue;
        if (!Kad6IsValidUtf8NoNul(t.name.data(), t.name.size()))
            return Kad6Status::Malformed;
    } else {
        return Kad6Status::BadValue;
    }

    if (!IsKnownValueKind(t.value_kind))
        return Kad6Status::BadValue;
    if (IsFixedWidthValueKind(t.value_kind)) {
        if (t.value.size() != FixedValueLen(t.value_kind))
            return Kad6Status::BadValue;
    }
    if (t.value_kind == kK6ValUtf8) {
        if (!Kad6IsValidUtf8NoNul(t.value.data(), t.value.size()))
            return Kad6Status::Malformed;
    }
    if (t.value_kind == kK6ValCAddress) {
        Kad6Address address;
        std::size_t consumed = 0;
        const Kad6Status st = DecodeKad6Address(t.value.data(), t.value.size(),
                                                address, &consumed);
        if (st != Kad6Status::Ok || consumed != t.value.size())
            return Kad6Status::Malformed;
    }
    return Kad6Status::Ok;
}

std::size_t TagWireSize(const K6Tag& t) noexcept {
    return kTagFixedOverhead + t.name.size() + t.value.size();
}

bool TagLess(const K6Tag& a, const K6Tag& b) noexcept {
    if (a.name_kind != b.name_kind)
        return a.name_kind < b.name_kind;
    if (a.name != b.name)
        return a.name < b.name;
    if (a.value_kind != b.value_kind)
        return a.value_kind < b.value_kind;
    return a.value < b.value;
}

bool TagEqual(const K6Tag& a, const K6Tag& b) noexcept {
    return !TagLess(a, b) && !TagLess(b, a);
}

bool IsCanonicalUnique(const K6TagList& list) noexcept {
    for (std::size_t i = 1; i < list.size(); ++i) {
        if (!TagLess(list[i - 1], list[i]))
            return false; // descending or exact duplicate
    }
    return true;
}

} // namespace

bool Kad6IsValidUtf8NoNul(const Byte* p, std::size_t n) noexcept {
    if (p == nullptr)
        return n == 0;

    std::size_t i = 0;
    while (i < n) {
        const Byte b0 = p[i];
        if (b0 == 0x00)
            return false; // no NUL anywhere -- the buffer has no external terminator

        if (b0 < 0x80) {
            ++i;
            continue;
        }

        std::size_t extra;      // number of continuation bytes expected
        std::uint32_t cp;       // codepoint accumulator
        std::uint32_t minCp;    // smallest codepoint this length may legally encode
        if ((b0 & 0xE0) == 0xC0)      { extra = 1; cp = b0 & 0x1Fu; minCp = 0x80; }
        else if ((b0 & 0xF0) == 0xE0) { extra = 2; cp = b0 & 0x0Fu; minCp = 0x800; }
        else if ((b0 & 0xF8) == 0xF0) { extra = 3; cp = b0 & 0x07u; minCp = 0x10000; }
        else return false; // stray continuation byte or invalid lead (0xF8..0xFF)

        if (i + extra >= n)
            return false; // truncated sequence

        for (std::size_t k = 1; k <= extra; ++k) {
            const Byte b = p[i + k];
            if (b == 0x00)
                return false;
            if ((b & 0xC0) != 0x80)
                return false; // not a continuation byte
            cp = (cp << 6) | static_cast<std::uint32_t>(b & 0x3Fu);
        }

        if (cp < minCp)
            return false; // overlong encoding
        if (cp > 0x10FFFFu)
            return false; // outside Unicode range
        if (cp >= 0xD800u && cp <= 0xDFFFu)
            return false; // unpaired surrogate half

        i += 1 + extra;
    }
    return true;
}

Kad6Status EncodeK6TagList(const K6TagList& list, std::vector<Byte>& out) {
    out.clear();

    if (list.size() > kK6MaxTags)
        return Kad6Status::TooLarge;

    // Pass 1: validate every tag and size the whole list BEFORE allocating
    // the output buffer (Postel: producer strict, limits checked up front).
    std::size_t bodySize = 0;
    for (const K6Tag& t : list) {
        const Kad6Status shape = ValidateTagShape(t);
        if (shape != Kad6Status::Ok)
            return shape;
        if (t.value.size() > kK6MaxTagValueBytes)
            return Kad6Status::TooLarge;
        bodySize += TagWireSize(t);
    }

    const std::size_t total = kHeaderSize + bodySize;
    if (total > kK6MaxTagListBytes)
        return Kad6Status::TooLarge;

    K6TagList canonical = list;
    Kad6TagsCanonicalSort(canonical);
    for (std::size_t i = 1; i < canonical.size(); ++i) {
        if (TagEqual(canonical[i - 1], canonical[i]))
            return Kad6Status::BadValue;
    }

    // Pass 2: everything validated -- now it is safe to allocate and write.
    out.reserve(total);
    ByteWriter w(out);
    w.u8(kK6TagListVersion);
    w.u16le(static_cast<std::uint16_t>(canonical.size()));
    w.u32le(static_cast<std::uint32_t>(total));
    for (const K6Tag& t : canonical) {
        w.u8(t.name_kind);
        w.u8(static_cast<Byte>(t.name.size()));
        w.bytes(t.name.data(), t.name.size());
        w.u8(t.value_kind);
        w.u32le(static_cast<std::uint32_t>(t.value.size()));
        w.bytes(t.value.data(), t.value.size());
    }
    return Kad6Status::Ok;
}

Kad6Status DecodeK6TagList(const Byte* in, std::size_t len, K6TagList& out,
                           std::size_t* consumed) noexcept {
    if (consumed != nullptr)
        *consumed = 0;
    out.clear();

    ByteReader r(in, len);
    if (r.null_arg())
        return Kad6Status::NullArgument;

    if (!r.need(1))
        return Kad6Status::Truncated;
    const Byte version = r.u8();
    if (version != kK6TagListVersion)
        return Kad6Status::UnsupportedVersion;

    if (!r.need(2))
        return Kad6Status::Truncated;
    const std::uint16_t count = r.u16le();
    if (count > kK6MaxTags)
        return Kad6Status::TooLarge;

    if (!r.need(4))
        return Kad6Status::Truncated;
    const std::uint32_t total_len = r.u32le();
    if (total_len > kK6MaxTagListBytes)
        return Kad6Status::TooLarge;
    if (total_len > len)
        return Kad6Status::Truncated;

    // Parse into a local list; `out` stays empty until the whole structure
    // is verified, so a failure partway through never leaks a partial parse.
    K6TagList tmp;
    tmp.reserve(count);

    for (std::uint16_t i = 0; i < count; ++i) {
        if (!r.need(2))
            return Kad6Status::Truncated;
        const Byte name_kind = r.u8();
        const Byte name_len  = r.u8();

        if (name_kind == kK6NameKindNumericU8) {
            if (name_len != 1)
                return Kad6Status::BadValue;
        } else if (name_kind == kK6NameKindUtf8) {
            if (name_len < 1 || name_len > kK6MaxUtf8NameLen)
                return Kad6Status::BadValue;
        } else {
            return Kad6Status::BadValue;
        }

        const Byte* namePtr = r.take(name_len);
        if (namePtr == nullptr)
            return Kad6Status::Truncated;
        if (name_kind == kK6NameKindUtf8 && !Kad6IsValidUtf8NoNul(namePtr, name_len))
            return Kad6Status::Malformed;

        if (!r.need(1 + 4))
            return Kad6Status::Truncated;
        const Byte value_kind = r.u8();
        const std::uint32_t value_len = r.u32le();

        if (!IsKnownValueKind(value_kind))
            return Kad6Status::BadValue;
        if (IsFixedWidthValueKind(value_kind) && value_len != FixedValueLen(value_kind))
            return Kad6Status::BadValue;
        // Limit checked BEFORE the buffer below is taken/allocated.
        if (value_len > kK6MaxTagValueBytes)
            return Kad6Status::TooLarge;

        const Byte* valPtr = r.take(value_len);
        if (valPtr == nullptr)
            return Kad6Status::Truncated;
        if (value_kind == kK6ValUtf8 && !Kad6IsValidUtf8NoNul(valPtr, value_len))
            return Kad6Status::Malformed;

        if (value_kind == kK6ValCAddress) {
            Kad6Address address;
            std::size_t addressConsumed = 0;
            const Kad6Status addressStatus = DecodeKad6Address(
                valPtr, value_len, address, &addressConsumed);
            if (addressStatus != Kad6Status::Ok || addressConsumed != value_len)
                return Kad6Status::Malformed;
        }

        K6Tag tag;
        tag.name_kind = name_kind;
        tag.name.assign(namePtr, namePtr + name_len);
        tag.value_kind = value_kind;
        tag.value.assign(valPtr, valPtr + value_len);
        tmp.push_back(std::move(tag));
    }

    if (!r.ok())
        return Kad6Status::Truncated;
    if (r.pos() != total_len)
        return Kad6Status::Malformed; // producer's declared length disagrees with reality
    if (!IsCanonicalUnique(tmp))
        return Kad6Status::Malformed;

    out = std::move(tmp);
    if (consumed != nullptr)
        *consumed = r.pos();
    return Kad6Status::Ok;
}

void Kad6TagsCanonicalSort(K6TagList& list) {
    std::sort(list.begin(), list.end(), TagLess);
}

} // namespace kad6
