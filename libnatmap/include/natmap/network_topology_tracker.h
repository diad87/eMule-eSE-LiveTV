#pragma once
#include <cstdint>
namespace natmap {
// Process-local change detector, not endpoint/identity/proof authority.
// Zero means unavailable; entering/leaving that state also invalidates once.
class NetworkTopologyTracker {
public:
    bool Observe(std::uint64_t signature) {
        if(!initialized_) { initialized_=true; signature_=signature; return false; }
        if(signature==signature_) return false;
        signature_=signature; return true;
    }
    bool SampleDue(std::uint64_t now) {
        if(sampled_ && now>=lastSample_ && now-lastSample_<1000) return false;
        sampled_=true; lastSample_=now; return true;
    }
private:
    bool initialized_=false,sampled_=false;
    std::uint64_t signature_=0,lastSample_=0;
};
}
