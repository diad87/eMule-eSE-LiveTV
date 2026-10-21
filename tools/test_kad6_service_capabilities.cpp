#include "../srchybrid/EseKad6ServiceCapabilities.h"
#include <cstdio>
using namespace ese::discovery;
static_assert((K6_CAP_DIRECT_INDEX_V1 & K6_CAP_PEER_RDV_V1)==0,"distinct services");
static_assert((K6_CAP_DIRECT_INDEX_V1 | K6_CAP_PEER_RDV_V1)>0xffffffffULL,"not eD2K caps");
int main() {
    unsigned checks=0;
    constexpr std::uint64_t unrelated=0x8000000081000003ULL;
    for(unsigned mask=0;mask<64;++mask) {
        Kad6ServiceReadiness readiness;
        readiness.consent=(mask&1)!=0; readiness.persistentIdentity=(mask&2)!=0;
        readiness.publicContactVerified=(mask&4)!=0; readiness.indexReceiver=(mask&8)!=0;
        readiness.contactRefreshReceiver=(mask&16)!=0; readiness.rendezvousReceiver=(mask&32)!=0;
        const auto actual=ProjectKad6ServiceCapabilities(unrelated | K6_CAP_DIRECT_INDEX_V1 | K6_CAP_PEER_RDV_V1,readiness);
        const bool permitted=(mask&7)==7;
        const auto expected=unrelated | (permitted && (mask&24)==24 ? K6_CAP_DIRECT_INDEX_V1 : 0) |
            (permitted && (mask&32) ? K6_CAP_PEER_RDV_V1 : 0);
        ++checks; if(actual!=expected) return 1;
        ++checks; if(ProjectKad6ServiceCapabilities(actual,{})!=unrelated) return 2;
    }
    std::printf("Kad6 service capabilities: %u checks PASS (receiver-first projection; no advertisement or route grant)\n",checks);
}
