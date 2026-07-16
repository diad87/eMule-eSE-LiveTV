// SPDX-License-Identifier: MIT
#include "kad6/kad6_live_search.h"

#include <cstdio>
#include <string>
#include <vector>

using namespace kad6;

static int g_pass = 0;
static int g_fail = 0;
#define CHECK(c, m) do { if (c) ++g_pass; else { ++g_fail; \
    std::printf("  FAIL: %s (%s:%d)\n", m, __FILE__, __LINE__); } } while (0)

static std::vector<Byte> Bytes(const char* s) {
    return std::vector<Byte>(s, s + std::char_traits<char>::length(s));
}

static K6LiveSearchMetadata Sample() {
    K6LiveSearchMetadata m;
    for (Byte i = 0; i < 16; ++i) m.result_id[i] = static_cast<Byte>(i + 1);
    m.ipv4 = {203, 0, 113, 9};
    m.tcp_port = 4662;
    m.udp_port = 4672;
    m.bitrate_kbps = 2500;
    m.viewer_count = 0x78563412u;
    m.started_at = 0x10203040u;
    m.discovery_namespace = 1;
    m.title_utf8 = Bytes("Canal \xC3\x91");
    m.category_utf8 = Bytes("news");
    m.language_utf8 = Bytes("es");
    return m;
}

int main() {
    const K6LiveSearchMetadata source = Sample();
    K6SearchResult result;
    CHECK(BuildK6LiveSearchResult(source, result) == Kad6Status::Ok, "build");
    CHECK(result.result_kind == kK6SearchKindLive, "live result kind");
    CHECK(result.network_origin == kK6NetOriginKad2, "Kad2 origin");
    CHECK(result.tags.size() == 10, "ten canonical tags");
    CHECK(result.tickets.empty(), "Option A emits no dial tickets");

    std::vector<Byte> wire;
    CHECK(EncodeK6SearchResult(result, wire) == Kad6Status::Ok, "encode result");
    K6SearchResult decoded;
    std::size_t consumed = 0;
    CHECK(DecodeK6SearchResult(wire.data(), wire.size(), decoded, &consumed) == Kad6Status::Ok,
          "decode result");
    CHECK(consumed == wire.size(), "exact result consumption");

    K6LiveSearchMetadata parsed;
    CHECK(ParseK6LiveSearchResult(decoded, parsed) == Kad6Status::Ok, "parse mapping");
    CHECK(parsed.result_id == source.result_id, "result id round trip");
    CHECK(parsed.ipv4 == source.ipv4, "IPv4 network-byte order round trip");
    CHECK(parsed.tcp_port == 4662 && parsed.udp_port == 4672, "ports round trip");
    CHECK(parsed.bitrate_kbps == 2500, "bitrate round trip");
    CHECK(parsed.viewer_count == 0x78563412u, "u32 LE viewers round trip");
    CHECK(parsed.started_at == 0x10203040u, "u32 LE started round trip");
    CHECK(parsed.discovery_namespace == 1, "namespace round trip");
    CHECK(parsed.title_utf8 == source.title_utf8, "UTF-8 title round trip");
    CHECK(parsed.category_utf8 == source.category_utf8, "category round trip");
    CHECK(parsed.language_utf8 == source.language_utf8, "language round trip");

    K6Tag future;
    future.name_kind = kK6NameKindUtf8;
    future.name = Bytes("FUTURE");
    future.value_kind = kK6ValU8;
    future.value = {7};
    decoded.tags.push_back(future);
    CHECK(ParseK6LiveSearchResult(decoded, parsed) == Kad6Status::Ok, "unknown additive tag ignored");

    K6SearchResult missing = result;
    missing.tags.pop_back();
    CHECK(ParseK6LiveSearchResult(missing, parsed) == Kad6Status::Malformed, "missing tag rejected");
    K6SearchResult duplicate = result;
    duplicate.tags.push_back(result.tags.front());
    CHECK(ParseK6LiveSearchResult(duplicate, parsed) == Kad6Status::Malformed, "semantic duplicate rejected");
    K6SearchResult wrong_kind = result;
    wrong_kind.result_kind = kK6SearchKindKeyword;
    CHECK(ParseK6LiveSearchResult(wrong_kind, parsed) == Kad6Status::Malformed, "wrong result kind rejected");

    K6LiveSearchMetadata bad = source;
    bad.ipv4 = {};
    CHECK(BuildK6LiveSearchResult(bad, result) == Kad6Status::BadValue, "zero IPv4 rejected");
    bad = source;
    bad.tcp_port = 0;
    CHECK(BuildK6LiveSearchResult(bad, result) == Kad6Status::BadValue, "zero TCP port rejected");
    bad = source;
    bad.title_utf8 = {0xC0, 0xAF};
    CHECK(BuildK6LiveSearchResult(bad, result) == Kad6Status::Malformed, "invalid UTF-8 rejected");

    std::printf("kad6 live-search mapping: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
