#include "natmap/network_topology_tracker.h"
#include <cstdio>
#include <cstdlib>
#include <limits>
static unsigned checks=0;
static void Check(bool value) { ++checks; if(!value) std::exit(1); }
int main() {
    natmap::NetworkTopologyTracker tracker;
    Check(!tracker.Observe(17)); Check(!tracker.Observe(17));
    Check(tracker.Observe(18)); Check(!tracker.Observe(18));
    Check(tracker.Observe(0)); Check(!tracker.Observe(0));
    Check(tracker.Observe(18)); Check(!tracker.Observe(18));
    Check(tracker.SampleDue(100)); Check(!tracker.SampleDue(100));
    Check(!tracker.SampleDue(1099)); Check(tracker.SampleDue(1100));
    Check(tracker.SampleDue(50)); Check(!tracker.SampleDue(51));
    Check(tracker.SampleDue((std::numeric_limits<std::uint64_t>::max)()));
    Check(!tracker.SampleDue((std::numeric_limits<std::uint64_t>::max)()));
    Check(tracker.SampleDue(0)); Check(!tracker.SampleDue(999));
    Check(tracker.SampleDue(1000));
    natmap::NetworkTopologyTracker unavailable;
    Check(!unavailable.Observe(0)); Check(!unavailable.Observe(0)); Check(unavailable.Observe(1));
    std::printf("network topology tracker: %u checks PASS (change detector, not OS network acceptance)\n",checks);
}
