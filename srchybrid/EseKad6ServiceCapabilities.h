#pragma once
#include <cstdint>
namespace ese { namespace discovery {
// Signed K6RouterRecord u64 only. Never copy these bits to an eD2K bitmap.
// Low 32 bits remain available to the existing router capability projection.
inline constexpr std::uint64_t K6_CAP_DIRECT_INDEX_V1 = 0x0000000100000000ULL;
inline constexpr std::uint64_t K6_CAP_PEER_RDV_V1 = 0x0000000200000000ULL;
struct Kad6ServiceReadiness {
    bool consent=false, persistentIdentity=false, publicContactVerified=false;
    bool indexReceiver=false, contactRefreshReceiver=false, rendezvousReceiver=false;
};
// Recompute, never inherit a previous advertisement after a service retires.
// This function grants no route, return proof, pin or transport authorization.
constexpr std::uint64_t ProjectKad6ServiceCapabilities(std::uint64_t base,
    const Kad6ServiceReadiness& ready) noexcept {
    const auto preserved=base & ~(K6_CAP_DIRECT_INDEX_V1 | K6_CAP_PEER_RDV_V1);
    if(!ready.consent || !ready.persistentIdentity || !ready.publicContactVerified) return preserved;
    return preserved | (ready.indexReceiver && ready.contactRefreshReceiver ? K6_CAP_DIRECT_INDEX_V1 : 0) |
        (ready.rendezvousReceiver ? K6_CAP_PEER_RDV_V1 : 0);
}
} }
