#include "../LiveTunnelPeerState.h"

#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <vector>

using namespace eSELive;

namespace eSELive {
bool RunLiveTunnelKadBridgeCharacterizationSelfTest();
}

namespace {

int Fail(const char* message)
{
    std::cerr << "FAIL: " << message << '\n';
    return 1;
}

} // namespace

int main()
{
    if (!RunLiveTunnelPeerStateCharacterizationSelfTest())
        return Fail("peer-state characterization");
    if (!RunLiveTunnelKadBridgeCharacterizationSelfTest())
        return Fail("Kad-bridge characterization");

    LiveTunnelPeerState peers;
    LiveSourceEndpointKey endpoint;
    endpoint.address_family = 1;
    endpoint.address = {10, 20, 30, 40};
    endpoint.tcp_port = 4662;
    endpoint.network_origin = 1;
    peers.RecordSourceResult(endpoint, true, 1);
    peers.RecordSourceResult(endpoint, true, 2);
    peers.RecordSourceFailure(endpoint, 3);
    if (peers.ApplySourceScore(100, endpoint) != 130)
        return Fail("source score bonus and penalty");
    endpoint.network_origin = 2;
    if (peers.ApplySourceScore(100, endpoint) != 100)
        return Fail("network-separated source history");

    std::cout << "live tunnel peer/Kad tests: PASS\n";
    return 0;
}
