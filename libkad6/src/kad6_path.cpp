// SPDX-License-Identifier: MIT
#include "kad6/kad6_path.h"

#include <cstring>
#include <limits>

namespace kad6 {
namespace {

bool NonZero(const Byte* value, std::size_t length) noexcept
{
    Byte aggregate = 0;
    for (std::size_t i = 0; i < length; ++i)
        aggregate = static_cast<Byte>(aggregate | value[i]);
    return aggregate != 0;
}

bool Eligible(const K6PathCandidate& c, bool exit_role) noexcept
{
    return c.authenticated && c.endpoint_verified && c.connected
        && c.supports_strict3 && c.supports_shaping && c.has_capacity
        && (!exit_role || c.supports_exit)
        && !c.current_content_peer && c.weight != 0 && c.asn != 0
        && c.address.family == Kad6Address::Family::IPv6
        && NonZero(c.address.addr.data(), c.address.addr.size())
        && NonZero(c.node_pub.data(), c.node_pub.size())
        && NonZero(c.user_hash.data(), c.user_hash.size());
}

bool SameIdentity(const K6PathCandidate& a, const K6PathCandidate& b) noexcept
{
    return Kad6CtEqual(a.node_pub.data(), b.node_pub.data(), a.node_pub.size())
        || Kad6CtEqual(a.user_hash.data(), b.user_hash.data(), a.user_hash.size());
}

bool Diverse(const K6PathCandidate& a, const K6PathCandidate& b) noexcept
{
    if (SameIdentity(a, b)
        || Kad6AddressInSameSubnet(a.address, b.address, 48)
        || a.asn == b.asn)
        return false;
    // Unknown operator groups are not asserted equal.  Known groups are a
    // hard anti-correlation boundary in addition to /48 and ASN.
    return a.operator_group == 0 || b.operator_group == 0
        || a.operator_group != b.operator_group;
}

bool ReadRandom64(K6PathRandom random, void* context, std::uint64_t& out) noexcept
{
    Byte bytes[8]{};
    if (!random || !random(context, bytes, sizeof bytes))
        return false;
    out = 0;
    for (unsigned i = 0; i < 8; ++i)
        out |= static_cast<std::uint64_t>(bytes[i]) << (i * 8);
    return true;
}

K6PathStatus PickWeighted(const std::vector<K6PathCandidate>& candidates,
                          const std::vector<std::size_t>& eligible,
                          K6PathRandom random, void* context,
                          std::size_t& selected) noexcept
{
    if (eligible.empty())
        return K6PathStatus::NotDiverse;
    std::uint64_t total = 0;
    for (std::size_t index : eligible) {
        const std::uint64_t weight = candidates[index].weight;
        if (total > std::numeric_limits<std::uint64_t>::max() - weight)
            return K6PathStatus::TooManyCandidates;
        total += weight;
    }
    if (total == 0)
        return K6PathStatus::NotDiverse;

    // Rejection sampling avoids modulo bias while retaining deterministic
    // host-injected test vectors.
    std::uint64_t value = 0;
    const std::uint64_t limit = std::numeric_limits<std::uint64_t>::max()
        - (std::numeric_limits<std::uint64_t>::max() % total);
    do {
        if (!ReadRandom64(random, context, value))
            return K6PathStatus::RandomFailed;
    } while (value >= limit);
    value %= total;
    for (std::size_t index : eligible) {
        if (value < candidates[index].weight) {
            selected = index;
            return K6PathStatus::Ok;
        }
        value -= candidates[index].weight;
    }
    return K6PathStatus::RandomFailed; // unreachable unless arithmetic drifts
}

} // namespace

K6PathStatus SelectK6StrictPath(const std::vector<K6PathCandidate>& candidates,
                                const Byte* pinned_guard,
                                K6PathRandom random,
                                void* random_context,
                                K6StrictPath& out) noexcept
{
    out = K6StrictPath{};
    if (!random)
        return K6PathStatus::NullArgument;
    if (candidates.size() > kK6PathMaxCandidates)
        return K6PathStatus::TooManyCandidates;

    std::vector<std::size_t> guards;
    for (std::size_t i = 0; i < candidates.size(); ++i) {
        if (!Eligible(candidates[i], false))
            continue;
        if (!pinned_guard
            || Kad6CtEqual(candidates[i].node_pub.data(), pinned_guard,
                           candidates[i].node_pub.size()))
            guards.push_back(i);
    }
    if (guards.empty())
        return pinned_guard ? K6PathStatus::PinnedGuardUnavailable
                            : K6PathStatus::NoEligibleGuard;
    K6PathStatus status = PickWeighted(candidates, guards, random,
                                       random_context, out.index[0]);
    if (status != K6PathStatus::Ok)
        return status;

    std::vector<std::size_t> middles;
    for (std::size_t i = 0; i < candidates.size(); ++i)
        if (Eligible(candidates[i], false)
            && Diverse(candidates[out.index[0]], candidates[i]))
            middles.push_back(i);
    status = PickWeighted(candidates, middles, random,
                          random_context, out.index[1]);
    if (status != K6PathStatus::Ok)
        return status == K6PathStatus::RandomFailed ? status
                                                    : K6PathStatus::NotDiverse;

    std::vector<std::size_t> exits;
    for (std::size_t i = 0; i < candidates.size(); ++i)
        if (Eligible(candidates[i], true)
            && Diverse(candidates[out.index[0]], candidates[i])
            && Diverse(candidates[out.index[1]], candidates[i]))
            exits.push_back(i);
    status = PickWeighted(candidates, exits, random,
                          random_context, out.index[2]);
    if (status != K6PathStatus::Ok)
        return status == K6PathStatus::RandomFailed ? status
                                                    : K6PathStatus::NotDiverse;
    return K6PathStatus::Ok;
}

const char* K6PathStatusName(K6PathStatus status) noexcept
{
    switch (status) {
        case K6PathStatus::Ok:                     return "Ok";
        case K6PathStatus::NullArgument:           return "NullArgument";
        case K6PathStatus::TooManyCandidates:      return "TooManyCandidates";
        case K6PathStatus::NoEligibleGuard:        return "NoEligibleGuard";
        case K6PathStatus::PinnedGuardUnavailable: return "PinnedGuardUnavailable";
        case K6PathStatus::NotDiverse:             return "NotDiverse";
        case K6PathStatus::RandomFailed:            return "RandomFailed";
    }
    return "?";
}

} // namespace kad6
