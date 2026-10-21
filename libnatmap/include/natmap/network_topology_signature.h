#pragma once
#include <array>
#include <algorithm>
#include <cstdint>
#include <vector>
namespace natmap {
using NetworkTopologyRecord=std::array<std::uint8_t,64>;
inline void SetTopologyInteger(NetworkTopologyRecord& record,std::size_t offset,std::uint64_t value,std::size_t bytes) {
    if(offset>record.size() || bytes>8 || bytes>record.size()-offset) return;
    for(std::size_t i=0;i<bytes;++i) record[offset+i]=static_cast<std::uint8_t>(value>>(8*(bytes-1-i)));
}
class CanonicalNetworkTopology {
public:
    bool Add(const NetworkTopologyRecord& record) {
        if(records_.size()>=4096) { overflow_=true; return false; }
        records_.push_back(record); return true;
    }
    std::uint64_t Signature() {
        if(overflow_ || records_.empty()) return 0;
        std::sort(records_.begin(),records_.end());
        records_.erase(std::unique(records_.begin(),records_.end()),records_.end());
        std::uint64_t signature=1469598103934665603ULL;
        for(const auto& record:records_) for(const auto byte:record) { signature^=byte; signature*=1099511628211ULL; }
        return signature ? signature : 1;
    }
private:
    std::vector<NetworkTopologyRecord> records_;
    bool overflow_=false;
};
}
