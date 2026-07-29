#include "../LiveTunnelMetrics.h"

#include <cstdint>
#include <iostream>
#include <thread>
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
    if (!RunLiveTunnelMetricsCharacterizationSelfTest())
        return Fail("metrics characterization");

    LiveTunnelMetrics metrics;
    constexpr std::size_t kThreads = 4;
    constexpr std::size_t kIterations = 10000;
    std::vector<std::thread> workers;
    for (std::size_t thread = 0; thread < kThreads; ++thread) {
        workers.emplace_back([&metrics, kIterations]() {
            for (std::size_t iteration = 0; iteration < kIterations; ++iteration) {
                metrics.RecordCellSent(512);
                metrics.RecordCellReceived(256);
            }
        });
    }
    for (std::thread& worker : workers)
        worker.join();

    const LiveTunnelTotalsSnapshot totals = metrics.Totals();
    const std::uint64_t expected = kThreads * kIterations;
    if (totals.cells_sent != expected || totals.cells_received != expected ||
        totals.bytes_sent != expected * 512 ||
        totals.bytes_received != expected * 256)
        return Fail("concurrent totals");

    LivePeerSnapshot peer;
    peer.ip = 0x01020304u;
    peer.port = 4662;
    peer.address = "1.2.3.4";
    peer.has_ipv4 = true;
    metrics.ReplacePeers(std::vector<LivePeerSnapshot>(1, peer), 1);
    std::vector<LivePeerSnapshot> first;
    std::size_t first_count = 0;
    metrics.GetPeers(first, first_count);
    first[0].address = "mutated";
    std::vector<LivePeerSnapshot> second;
    std::size_t second_count = 0;
    metrics.GetPeers(second, second_count);
    if (first_count != 1 || second_count != 1 || second.size() != 1 ||
        second[0].address != "1.2.3.4")
        return Fail("immutable peer copy");

    std::cout << "live tunnel metrics tests: PASS\n";
    return 0;
}
