#pragma once

#include <cstdint>

namespace eSELive {

// Keep the baseline capability decision independent from MFC so the exact
// policy used by the HELLO path can be exercised by the standalone tests.
// The bit values are asserted against Opcodes.h at the integration site.
constexpr std::uint32_t kEseCapSealedRecords = 0x00000200u;
constexpr std::uint32_t kEseCapGossipProtocol = 0x00000400u;
constexpr std::uint32_t kEseCapLiveChunkFrag = 0x00002000u;

constexpr std::uint32_t BuildEseBaselineCapabilities(
    bool sealedRecordsEndToEnd,
    bool gossipEndToEnd,
    bool liveChunkFragmentationEndToEnd) noexcept
{
    return (sealedRecordsEndToEnd ? kEseCapSealedRecords : 0u)
        | (gossipEndToEnd ? kEseCapGossipProtocol : 0u)
        | (liveChunkFragmentationEndToEnd ? kEseCapLiveChunkFrag : 0u);
}

// Channel crypto codecs exist, but the peer-facing channel request/answer/
// revoke and gossip handlers are not wired.  A codec alone is not an
// end-to-end capability.
constexpr std::uint32_t EseOperationalBaselineCapabilities() noexcept
{
    return BuildEseBaselineCapabilities(false, false, true);
}

} // namespace eSELive
