#include "../srchybrid/EseMappingReadback.h"
#include <cstdio>
#include <initializer_list>
int main() {
    unsigned checks=0; ese::mapping::ReadbackSchedule schedule;
    const auto check=[&](bool value) { ++checks; if(!value) std::printf("FAIL %u\n",checks); return value; };
    if(!check(!schedule.Due(UINT64_MAX))) return 1;
    for(const auto lifetime : {0U,1U,19U,20U,40U,239U,240U,7200U,UINT32_MAX}) {
        const auto seconds=lifetime==0 ? 60U : lifetime/4<5 ? 5U : lifetime/4>60 ? 60U : lifetime/4;
        if(!check(schedule.Activate(lifetime,1000)) || !check(schedule.Interval()==seconds*1000ULL) ||
            !check(!schedule.Due(schedule.Next()-1)) || !check(schedule.Due(schedule.Next())) ||
            !check(!schedule.Mark(999)) || !check(schedule.Mark(schedule.Next())) ||
            !check(schedule.Next()==1000+2*seconds*1000ULL)) return 1;
    }
    if(!check(!schedule.Activate(0,UINT64_MAX)) || !check(!schedule.Due(UINT64_MAX))) return 1;
    schedule.Clear(); if(!check(schedule.Next()==0 && schedule.Interval()==0)) return 1;
    std::printf("Mapping readback cadence: %u checks PASS (no router or route authority)\n",checks);
}
