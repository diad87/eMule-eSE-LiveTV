#pragma once
#include <array>
#include <cstdint>
#include <limits>
namespace ese { namespace discovery {
// Bounded per-file scheduling; failures consume their cooldown too. Neither
// topology changes nor file size changes reset the hash's retry budget.
class Kad6LookupCooldown {
public:
    bool Claim(const std::array<std::uint8_t,16>& file,std::uint64_t now) noexcept {
        if((haveTime_ && now<last_) || now>(std::numeric_limits<std::uint64_t>::max)()-60000) return false;
        last_=now; haveTime_=true;
        bool nonzero=false; for(auto byte:file) nonzero=nonzero || byte!=0;
        if(!nonzero) return false;
        Entry* available=nullptr;
        for(auto& entry:entries_) {
            if(entry.used && entry.file==file) {
                if(now<entry.until) return false;
                entry.until=now+60000; return true;
            }
            if(!available && (!entry.used || now>=entry.until)) available=&entry;
        }
        if(!available) return false;
        *available={file,now+60000,true}; return true;
    }
private:
    struct Entry { std::array<std::uint8_t,16> file{}; std::uint64_t until=0; bool used=false; };
    std::array<Entry,64> entries_{};
    std::uint64_t last_=0; bool haveTime_=false;
};
} }
