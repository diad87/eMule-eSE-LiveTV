#include "kad6/kad6_path.h"

#include <cstring>
#include <iostream>
#include <vector>

using namespace kad6;

static int checks = 0;
#define CHECK(x) do { ++checks; if (!(x)) { std::cerr << "FAIL line " << __LINE__ << ": " #x "\n"; return 1; } } while (0)

struct RandomStream { std::vector<std::uint64_t> values; std::size_t next = 0; };
static bool Random(void* context, Byte* out, std::size_t length)
{
    if (!context || length != 8) return false;
    RandomStream& stream = *static_cast<RandomStream*>(context);
    if (stream.next >= stream.values.size()) return false;
    const std::uint64_t value = stream.values[stream.next++];
    for (unsigned i = 0; i < 8; ++i) out[i] = static_cast<Byte>(value >> (i * 8));
    return true;
}

static K6PathCandidate Candidate(Byte id, Byte prefix, std::uint32_t asn,
                                 std::uint32_t op, bool exit = true)
{
    K6PathCandidate c;
    c.node_pub.fill(id); c.user_hash.fill(static_cast<Byte>(id + 64));
    c.address.family = Kad6Address::Family::IPv6;
    c.address.addr[0] = 0x20; c.address.addr[1] = 0x01;
    c.address.addr[2] = 0x0d; c.address.addr[3] = 0xb8;
    c.address.addr[4] = prefix; c.address.addr[5] = 0;
    c.address.addr[6] = id;
    c.asn = asn; c.operator_group = op; c.weight = id;
    c.authenticated = c.endpoint_verified = c.connected = true;
    c.supports_strict3 = c.supports_shaping = c.has_capacity = true;
    c.supports_exit = exit;
    return c;
}

int main()
{
    std::vector<K6PathCandidate> cands{
        Candidate(1, 1, 64501, 1), Candidate(2, 2, 64502, 2),
        Candidate(3, 3, 64503, 3), Candidate(4, 4, 64504, 4)};
    K6StrictPath path;
    RandomStream random{{0, 0, 0}};
    CHECK(SelectK6StrictPath(cands, nullptr, Random, &random, path) == K6PathStatus::Ok);
    CHECK(path.index[0] != path.index[1]);
    CHECK(path.index[0] != path.index[2]);
    CHECK(path.index[1] != path.index[2]);
    CHECK(!Kad6AddressInSameSubnet(cands[path.index[0]].address, cands[path.index[1]].address, 48));

    // A hard guard pin is honored even when weighted randomness would choose another.
    random = RandomStream{{999, 0, 0}};
    CHECK(SelectK6StrictPath(cands, cands[2].node_pub.data(), Random, &random, path) == K6PathStatus::Ok);
    CHECK(path.index[0] == 2);

    std::array<Byte, 32> absent{}; absent.fill(99);
    random = RandomStream{{0}};
    CHECK(SelectK6StrictPath(cands, absent.data(), Random, &random, path) == K6PathStatus::PinnedGuardUnavailable);

    // Same /48, ASN or known operator group each blocks a strict path.
    std::vector<K6PathCandidate> same48{
        Candidate(1, 7, 64501, 1), Candidate(2, 7, 64502, 2), Candidate(3, 7, 64503, 3)};
    random = RandomStream{{0, 0, 0}};
    CHECK(SelectK6StrictPath(same48, nullptr, Random, &random, path) == K6PathStatus::NotDiverse);
    std::vector<K6PathCandidate> sameAsn{
        Candidate(1, 1, 64501, 1), Candidate(2, 2, 64501, 2), Candidate(3, 3, 64501, 3)};
    random = RandomStream{{0, 0, 0}};
    CHECK(SelectK6StrictPath(sameAsn, nullptr, Random, &random, path) == K6PathStatus::NotDiverse);
    std::vector<K6PathCandidate> sameOp{
        Candidate(1, 1, 64501, 9), Candidate(2, 2, 64502, 9), Candidate(3, 3, 64503, 9)};
    random = RandomStream{{0, 0, 0}};
    CHECK(SelectK6StrictPath(sameOp, nullptr, Random, &random, path) == K6PathStatus::NotDiverse);

    // Co-seeders and candidates without verified metadata/capacity are excluded.
    cands[0].current_content_peer = true;
    cands[1].endpoint_verified = false;
    cands[2].has_capacity = false;
    random = RandomStream{{0}};
    CHECK(SelectK6StrictPath(cands, nullptr, Random, &random, path) == K6PathStatus::NotDiverse);

    // CSPRNG failure is explicit, never replaced by deterministic first-entry selection.
    std::vector<K6PathCandidate> valid{
        Candidate(1, 1, 64501, 1), Candidate(2, 2, 64502, 2), Candidate(3, 3, 64503, 3)};
    RandomStream empty;
    CHECK(SelectK6StrictPath(valid, nullptr, Random, &empty, path) == K6PathStatus::RandomFailed);

    // Class-5 shaping is part of STRICT, not an optional post-selection
    // downgrade. A hop lacking it is ineligible.
    valid[0].supports_shaping = false;
    random = RandomStream{{0, 0, 0}};
    CHECK(SelectK6StrictPath(valid, nullptr, Random, &random, path) == K6PathStatus::NotDiverse);
    valid[0].supports_shaping = true;

    // NodeIdentity and UserHash are both uniqueness boundaries.
    valid[1].node_pub = valid[0].node_pub;
    random = RandomStream{{0, 0, 0}};
    CHECK(SelectK6StrictPath(valid, nullptr, Random, &random, path) == K6PathStatus::NotDiverse);

    std::cout << "kad6 strict path tests: " << checks << " checks, PASS\n";
    return 0;
}
