#include "../EseCapabilityPolicy.h"

#include <cassert>
#include <cstdint>
#include <iostream>

int main()
{
    using namespace eSELive;

    const std::uint32_t baseline = EseOperationalBaselineCapabilities();
    assert((baseline & kEseCapSealedRecords) == 0);
    assert((baseline & kEseCapGossipProtocol) == 0);
    assert((baseline & kEseCapLiveChunkFrag) != 0);

    assert(BuildEseBaselineCapabilities(false, false, false) == 0);
    assert(BuildEseBaselineCapabilities(true, false, false) == kEseCapSealedRecords);
    assert(BuildEseBaselineCapabilities(false, true, false) == kEseCapGossipProtocol);
    assert(BuildEseBaselineCapabilities(true, true, true)
        == (kEseCapSealedRecords | kEseCapGossipProtocol | kEseCapLiveChunkFrag));

    std::cout << "eSE capability policy: PASS\n";
    return 0;
}
