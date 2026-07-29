#include "../LiveTunnelKadBridge.h"
#include "../LiveTunnelPeerState.h"

#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <vector>

using namespace eSELive;

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
    kad6::K6Endpoint endpoint;
    endpoint.addr.family = kad6::Kad6Address::Family::IPv4;
    endpoint.addr.addr = {10, 20, 30, 40};
    endpoint.tcp_port = 4662;
    peers.RecordSourceResult(endpoint, 1, true, 1);
    peers.RecordSourceResult(endpoint, 1, true, 2);
    peers.RecordSourceFailure(endpoint, 1, 3);
    if (peers.ApplySourceScore(100, endpoint, 1) != 130)
        return Fail("source score bonus and penalty");
    if (peers.ApplySourceScore(100, endpoint, 2) != 100)
        return Fail("network-separated source history");

    std::vector<std::uint32_t> stopped;
    LiveTunnelKadPorts ports;
    ports.stop_search = [&stopped](std::uint32_t id) {
        if (id == 2)
            throw std::runtime_error("late Kad stop");
        stopped.push_back(id);
    };
    LiveTunnelKadBridge bridge(std::move(ports));
    bridge.StopSearches({1, 2, 3});
    if (stopped != std::vector<std::uint32_t>({1, 3}))
        return Fail("stop isolation");

    std::cout << "live tunnel peer/Kad tests: PASS\n";
    return 0;
}
