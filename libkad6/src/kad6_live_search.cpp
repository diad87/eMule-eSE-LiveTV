// SPDX-License-Identifier: MIT
#include "kad6/kad6_live_search.h"

#include "kad6/kad6_tags.h"

#include <algorithm>
#include <cstring>

namespace kad6 {
namespace {

constexpr const char* kSrcIp   = "SRCIP";
constexpr const char* kPort    = "PORT";
constexpr const char* kUdpPort = "UDPPORT";
constexpr const char* kBitrate = "BITRATE";
constexpr const char* kViewers = "VIEWERS";
constexpr const char* kStarted = "STARTED";
constexpr const char* kNs      = "NS";
constexpr const char* kTitle   = "TITLE";
constexpr const char* kCat     = "CAT";
constexpr const char* kLang    = "LANG";

bool IsAllZero(const std::array<Byte, kHash16Size>& v) noexcept {
    Byte any = 0;
    for (Byte b : v) any = static_cast<Byte>(any | b);
    return any == 0;
}

std::vector<Byte> U16(std::uint16_t v) {
    return {static_cast<Byte>(v), static_cast<Byte>(v >> 8)};
}

std::vector<Byte> U32(std::uint32_t v) {
    return {static_cast<Byte>(v), static_cast<Byte>(v >> 8),
            static_cast<Byte>(v >> 16), static_cast<Byte>(v >> 24)};
}

std::uint16_t ReadU16(const std::vector<Byte>& v) noexcept {
    return static_cast<std::uint16_t>(v[0]) |
           static_cast<std::uint16_t>(static_cast<std::uint16_t>(v[1]) << 8);
}

std::uint32_t ReadU32(const std::vector<Byte>& v) noexcept {
    return static_cast<std::uint32_t>(v[0]) |
           (static_cast<std::uint32_t>(v[1]) << 8) |
           (static_cast<std::uint32_t>(v[2]) << 16) |
           (static_cast<std::uint32_t>(v[3]) << 24);
}

K6Tag Tag(const char* name, Byte kind, std::vector<Byte> value) {
    K6Tag t;
    t.name_kind = kK6NameKindUtf8;
    t.name.assign(name, name + std::strlen(name));
    t.value_kind = kind;
    t.value = std::move(value);
    return t;
}

bool NameIs(const K6Tag& tag, const char* name) noexcept {
    const std::size_t n = std::strlen(name);
    return tag.name_kind == kK6NameKindUtf8 && tag.name.size() == n &&
           std::equal(tag.name.begin(), tag.name.end(), name);
}

bool ValidUtf8(const std::vector<Byte>& v) noexcept {
    return Kad6IsValidUtf8NoNul(v.data(), v.size());
}

} // namespace

Kad6Status BuildK6LiveSearchResult(const K6LiveSearchMetadata& live,
                                    K6SearchResult& out) {
    out = K6SearchResult{};
    if (IsAllZero(live.result_id) || live.discovery_namespace > 2 ||
        (live.network_origin != kK6NetOriginKad2 &&
         live.network_origin != kK6NetOriginKad6))
        return Kad6Status::BadValue;
    if (!ValidUtf8(live.title_utf8) || !ValidUtf8(live.category_utf8) ||
        !ValidUtf8(live.language_utf8))
        return Kad6Status::Malformed;

    K6SearchResult tmp;
    tmp.result_id = live.result_id;
    tmp.result_kind = kK6SearchKindLive;
    tmp.network_origin = live.network_origin;
    tmp.tags.push_back(Tag(kBitrate, kK6ValU16, U16(live.bitrate_kbps)));
    tmp.tags.push_back(Tag(kViewers, kK6ValU32, U32(live.viewer_count)));
    tmp.tags.push_back(Tag(kStarted, kK6ValU32, U32(live.started_at)));
    tmp.tags.push_back(Tag(kNs,      kK6ValU8, {live.discovery_namespace}));
    tmp.tags.push_back(Tag(kTitle,   kK6ValUtf8, live.title_utf8));
    tmp.tags.push_back(Tag(kCat,     kK6ValUtf8, live.category_utf8));
    tmp.tags.push_back(Tag(kLang,    kK6ValUtf8, live.language_utf8));
    Kad6TagsCanonicalSort(tmp.tags);

    // Exercise all nested shape/size checks now, not later at a network call.
    std::vector<Byte> wire;
    const Kad6Status st = EncodeK6SearchResult(tmp, wire);
    if (st != Kad6Status::Ok) return st;
    out = std::move(tmp);
    return Kad6Status::Ok;
}

Kad6Status ParseK6LiveSearchResult(const K6SearchResult& result,
                                    K6LiveSearchMetadata& out) noexcept {
    out = K6LiveSearchMetadata{};
    if (IsAllZero(result.result_id) || result.result_kind != kK6SearchKindLive ||
        !result.tickets.empty() ||
        (result.network_origin != kK6NetOriginKad2 &&
         result.network_origin != kK6NetOriginKad6))
        return Kad6Status::Malformed;

    K6LiveSearchMetadata tmp;
    tmp.result_id = result.result_id;
    tmp.network_origin = result.network_origin;
    unsigned seen = 0;
    constexpr unsigned kAll = (1u << 7) - 1u;

    for (const K6Tag& tag : result.tags) {
        unsigned bit = 0;
        if (NameIs(tag, kSrcIp) || NameIs(tag, kPort) || NameIs(tag, kUdpPort))
            return Kad6Status::Malformed;
        if (NameIs(tag, kBitrate)) bit = 1u << 0;
        else if (NameIs(tag, kViewers)) bit = 1u << 1;
        else if (NameIs(tag, kStarted)) bit = 1u << 2;
        else if (NameIs(tag, kNs)) bit = 1u << 3;
        else if (NameIs(tag, kTitle)) bit = 1u << 4;
        else if (NameIs(tag, kCat)) bit = 1u << 5;
        else if (NameIs(tag, kLang)) bit = 1u << 6;
        else continue; // additive future tag

        if ((seen & bit) != 0) return Kad6Status::Malformed;
        seen |= bit;

        if (bit == (1u << 0)) {
            if (tag.value_kind != kK6ValU16 || tag.value.size() != 2)
                return Kad6Status::Malformed;
            tmp.bitrate_kbps = ReadU16(tag.value);
        } else if (bit == (1u << 1) || bit == (1u << 2)) {
            if (tag.value_kind != kK6ValU32 || tag.value.size() != 4)
                return Kad6Status::Malformed;
            const std::uint32_t value = ReadU32(tag.value);
            if (bit == (1u << 1)) tmp.viewer_count = value;
            else tmp.started_at = value;
        } else if (bit == (1u << 3)) {
            if (tag.value_kind != kK6ValU8 || tag.value.size() != 1 || tag.value[0] > 2)
                return Kad6Status::Malformed;
            tmp.discovery_namespace = tag.value[0];
        } else {
            if (tag.value_kind != kK6ValUtf8 || !ValidUtf8(tag.value))
                return Kad6Status::Malformed;
            if (bit == (1u << 4)) tmp.title_utf8 = tag.value;
            else if (bit == (1u << 5)) tmp.category_utf8 = tag.value;
            else tmp.language_utf8 = tag.value;
        }
    }

    if (seen != kAll)
        return Kad6Status::Malformed;
    out = std::move(tmp);
    return Kad6Status::Ok;
}

} // namespace kad6
