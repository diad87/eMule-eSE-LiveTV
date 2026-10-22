// SPDX-License-Identifier: MIT
#include "reach/direct_attempt.h"

#include <algorithm>
#include <tuple>
#include <utility>

namespace reach {
namespace {

unsigned KindRank(DirectKind kind) noexcept
{
    return static_cast<unsigned>(kind);
}

unsigned EvidenceRank(DirectEvidence evidence) noexcept
{
    switch (evidence) {
    case DirectEvidence::InboundVerified: return 4;
    case DirectEvidence::MappingVerified: return 3;
    case DirectEvidence::Reserved: return 2;
    case DirectEvidence::Observed: return 1;
    case DirectEvidence::Advertised: return 0;
    }
    return 0;
}

bool IsV4Mapped(const std::array<std::uint8_t, 16>& address) noexcept
{
    for (std::size_t i = 0; i != 10; ++i)
        if (address[i] != 0) return false;
    return address[10] == 0xff && address[11] == 0xff;
}

bool IsV4Global(const std::array<std::uint8_t, 16>& a) noexcept
{
    const auto x = a[0], y = a[1];
    if ((x | y | a[2] | a[3]) == 0) return false;
    if (x == 10 || x == 127 || x >= 224) return false;
    if (x == 169 && y == 254) return false;
    if (x == 172 && y >= 16 && y <= 31) return false;
    if (x == 192 && (y == 168 || (y == 0 && a[2] == 0))) return false;
    if (x == 100 && y >= 64 && y <= 127) return false;
    if (x == 198 && (y == 18 || y == 19)) return false;
    return true;
}

bool IsV6Zero(const std::array<std::uint8_t, 16>& a) noexcept
{
    for (auto b : a) if (b != 0) return false;
    return true;
}

bool IsV6Loopback(const std::array<std::uint8_t, 16>& a) noexcept
{
    for (std::size_t i = 0; i != 15; ++i) if (a[i] != 0) return false;
    return a[15] == 1;
}

bool IsV6Global(const std::array<std::uint8_t, 16>& a) noexcept
{
    if (IsV6Zero(a) || IsV6Loopback(a) || IsV4Mapped(a) || a[0] == 0xff)
        return false;
    if (a[0] == 0xfe && (a[1] & 0xc0) == 0x80) return false; // link-local
    if ((a[0] & 0xfe) == 0xfc) return false; // ULA
    if (a[0] == 0x20 && a[1] == 0x01 && a[2] == 0x0d && a[3] == 0xb8)
        return false; // documentation prefix
    return true;
}

bool PrefixMatches(const std::array<std::uint8_t, 16>& candidate,
                   const std::array<std::uint8_t, 16>& local,
                   std::uint8_t bits) noexcept
{
    const std::size_t whole = bits / 8;
    const std::uint8_t remaining = bits % 8;
    for (std::size_t i = 0; i != whole; ++i)
        if (candidate[i] != local[i]) return false;
    if (remaining) {
        const std::uint8_t mask = static_cast<std::uint8_t>(0xffu << (8 - remaining));
        if ((candidate[whole] & mask) != (local[whole] & mask)) return false;
    }
    return true;
}

bool SameLanPrefixMatches(const DirectCandidate& c, const DirectPolicy& p) noexcept
{
    const unsigned maximum = c.family == 4 ? 32u : 128u;
    return p.local_interface_family == c.family && p.local_prefix_length > 0 &&
           p.local_prefix_length <= maximum &&
           PrefixMatches(c.address, p.local_interface_address, p.local_prefix_length);
}

bool EvidenceFits(const DirectCandidate& c) noexcept
{
    switch (c.kind) {
    case DirectKind::DirectV6:
    case DirectKind::DirectV4:
        return c.evidence == DirectEvidence::InboundVerified ||
               c.evidence == DirectEvidence::Observed;
    case DirectKind::VerifiedMapping:
        return c.evidence == DirectEvidence::MappingVerified;
    case DirectKind::Callback:
        return c.evidence == DirectEvidence::InboundVerified ||
               c.evidence == DirectEvidence::Reserved;
    case DirectKind::Punch2:
    case DirectKind::Punch3:
    case DirectKind::Predicted:
    case DirectKind::Birthday:
        return c.evidence == DirectEvidence::Reserved;
    }
    return false;
}

bool AddressFits(const DirectCandidate& c, const DirectPolicy& p) noexcept
{
    const bool lan = c.scope == DirectScope::SameLan;
    if (lan && (!p.allow_same_lan || p.required_interface_id == 0 ||
                c.interface_id != p.required_interface_id || !SameLanPrefixMatches(c,p)))
        return false;
    if (c.family == 4) {
        if (!p.allow_ipv4) return false;
        for (std::size_t i = 4; i != 16; ++i) if (c.address[i] != 0) return false;
        if (lan && p.local_prefix_length < 31) {
            // Prefix validation above establishes a concrete local subnet.
            // Every host bit set addresses all hosts, not a remote peer.
            bool broadcast = true;
            for (unsigned bit = p.local_prefix_length; bit < 32; ++bit)
                if (!(c.address[bit / 8] & (0x80u >> (bit % 8)))) {
                    broadcast = false;
                    break;
                }
            if (broadcast) return false;
        }
        return lan ? (c.address[0] != 0 && c.address[0] != 127 &&
                        c.address[0] < 224 &&
                        !(c.address[0] == 255 && c.address[1] == 255 &&
                          c.address[2] == 255 && c.address[3] == 255))
                   : IsV4Global(c.address);
    }
    if (c.family != 6 || !p.allow_ipv6) return false;
    if (lan) return !IsV6Zero(c.address) && !IsV6Loopback(c.address) &&
                     c.address[0] != 0xff && !IsV4Mapped(c.address);
    return IsV6Global(c.address);
}

bool ShapeFits(const DirectCandidate& c) noexcept
{
    if (!c.id || !c.port || !c.transport_mask || (c.transport_mask & ~0x07u) ||
        !EvidenceFits(c) ||
        (c.scope != DirectScope::Global && c.scope != DirectScope::SameLan))
        return false;
    if (c.kind == DirectKind::DirectV4 && c.family != 4) return false;
    if (c.kind == DirectKind::DirectV6 && c.family != 6) return false;
    if (c.kind == DirectKind::VerifiedMapping &&
        c.evidence != DirectEvidence::MappingVerified) return false;
    return true;
}

bool EndpointTransportGenerationEqual(const DirectCandidate& a,
                                      const DirectCandidate& b) noexcept
{
    return a.family == b.family && a.address == b.address && a.port == b.port &&
           a.transport_mask == b.transport_mask &&
           a.topology_generation == b.topology_generation;
}

bool Better(const DirectCandidate& a, const DirectCandidate& b) noexcept
{
    if (KindRank(a.kind) != KindRank(b.kind)) return KindRank(a.kind) < KindRank(b.kind);
    if (EvidenceRank(a.evidence) != EvidenceRank(b.evidence))
        return EvidenceRank(a.evidence) > EvidenceRank(b.evidence);
    const auto ar = a.rtt_ms ? a.rtt_ms : UINT32_MAX;
    const auto br = b.rtt_ms ? b.rtt_ms : UINT32_MAX;
    if (ar != br) return ar < br;
    if (a.family != b.family) return a.family < b.family;
    if (a.address != b.address) return a.address < b.address;
    if (a.port != b.port) return a.port < b.port;
    return a.id < b.id;
}

} // namespace

DirectPlan BuildDirectPlan(const DirectPolicy& policy,
                           const std::vector<DirectCandidate>& candidates)
{
    DirectPlan plan;
    if (!policy.topology_generation ||
        (policy.allow_same_lan && (!policy.required_interface_id ||
         (policy.local_interface_family != 4 && policy.local_interface_family != 6) ||
         !policy.local_prefix_length ||
         policy.local_prefix_length > (policy.local_interface_family == 4 ? 32 : 128)))) {
        plan.status = DirectStatus::InvalidPolicy;
        return plan;
    }
    if (candidates.size() > kDirectMaxCandidateInputs) {
        plan.status = DirectStatus::TooManyCandidates;
        return plan;
    }

    std::vector<DirectCandidate> accepted;
    accepted.reserve(std::min(candidates.size(),kDirectMaxCandidates));
    for (const auto& c : candidates) {
        if (!ShapeFits(c) || !AddressFits(c, policy) ||
            (c.kind == DirectKind::Birthday && !policy.allow_birthday) ||
            c.topology_generation != policy.topology_generation ||
            c.expires_monotonic_ms <= policy.now_monotonic_ms)
            continue;
        auto duplicate = std::find_if(accepted.begin(), accepted.end(),
            [&](const DirectCandidate& old) { return EndpointTransportGenerationEqual(old, c); });
        if (duplicate == accepted.end()) {
            if (accepted.size() == kDirectMaxCandidates) {
                plan.status = DirectStatus::TooManyCandidates;
                return plan;
            }
            accepted.push_back(c);
        }
        else {
            // Combining evidence must never extend the lifetime of a route.
            const auto expiry = std::min(c.expires_monotonic_ms,
                                         duplicate->expires_monotonic_ms);
            if (Better(c, *duplicate)) *duplicate = c;
            duplicate->expires_monotonic_ms = expiry;
        }
    }

    std::stable_sort(accepted.begin(), accepted.end(), Better);
    if (accepted.size() > kDirectMaxRoutes) accepted.resize(kDirectMaxRoutes);
    plan.routes = std::move(accepted);
    return plan;
}

} // namespace reach
