// SPDX-License-Identifier: MIT
// Rev3 LT4 deterministic local laboratory. This is a mechanism/oracle test;
// it does not substitute for independent issuer deployment evidence.
#include "kad6/kad6_economy.h"
#include "kad6/kad6_quota.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <map>
#include <vector>

using namespace kad6;

static Hash32 HashFrom(std::uint64_t value, Byte domain) {
    Hash32 out{};
    for (std::size_t i=0;i<out.size();++i) {
        value ^= value << 13; value ^= value >> 7; value ^= value << 17;
        out[i]=static_cast<Byte>((value >> ((i%8)*8)) ^ domain ^ i);
    }
    return out;
}

static K6QuotaHierarchyRequest Request(std::uint64_t principal,
        std::uint64_t prefix, std::uint64_t issuer, std::uint32_t asn,
        std::uint64_t now_ms) {
    K6QuotaHierarchyRequest out;
    out.principal=HashFrom(principal,0x11);out.issuer_key_id=HashFrom(issuer,0x55);
    for(std::size_t i=0;i<out.prefix48.size();++i)
        out.prefix48[i]=static_cast<Byte>(prefix>>(8*(out.prefix48.size()-1-i)));
    out.asn=asn;out.service=K6QuotaService::ExitEd2kFull;out.now_ms=now_ms;
    return out;
}

static double Jain(const std::array<std::uint64_t,8>& values) {
    long double sum=0,squares=0;
    for(std::uint64_t value:values){sum+=value;squares+=static_cast<long double>(value)*value;}
    return squares==0?0.0:static_cast<double>((sum*sum)/(values.size()*squares));
}

int main() {
    const auto started=std::chrono::steady_clock::now();
    K6QuotaHierarchyPolicy attackPolicy;
    attackPolicy.principal={16,16};attackPolicy.prefix48={64,64};
    attackPolicy.issuer={256,256};attackPolicy.asn={512,512};
    attackPolicy.service={1024,1024};attackPolicy.global={2048,2048};
    attackPolicy.max_principals=4096;attackPolicy.max_prefixes=64;
    attackPolicy.max_issuers=8;attackPolicy.max_asns=8;
    K6QuotaHierarchy attack(attackPolicy);
    std::uint64_t attackAdmitted=0,capacityDenied=0,rateDenied=0;
    for(std::uint64_t i=1;i<=1000000;++i){
        K6QuotaHierarchyRequest request=Request(i,0x20010db80001ull,1,64500,1000);
        const K6QuotaStatus status=attack.Reserve(request);
        if(status==K6QuotaStatus::Ok)++attackAdmitted;
        else if(status==K6QuotaStatus::Capacity)++capacityDenied;
        else if(status==K6QuotaStatus::RateLimited)++rateDenied;
    }
    std::uint64_t failoverAdmitted=0;
    for(std::uint64_t i=0;i<1024;++i){
        K6QuotaHierarchyRequest request=Request(2000000+i,0x20010db80001ull,
            2+(i%4),64500,1000);
        if(attack.Reserve(request)==K6QuotaStatus::Ok)++failoverAdmitted;
    }

    K6QuotaHierarchyPolicy honestPolicy;
    honestPolicy.principal={16,16};honestPolicy.prefix48={256,256};
    honestPolicy.issuer={3000,3000};honestPolicy.asn={1000,1000};
    honestPolicy.service={12000,12000};honestPolicy.global={12000,12000};
    honestPolicy.max_principals=2048;honestPolicy.max_prefixes=128;
    honestPolicy.max_issuers=8;honestPolicy.max_asns=32;
    K6QuotaHierarchy honest(honestPolicy);
    std::uint64_t honestAdmitted=0;
    for(std::uint64_t i=0;i<10000;++i){
        const std::uint64_t client=i%1000;
        K6QuotaHierarchyRequest request=Request(client+1,
            0x20010db81000ull+(client%64),1+(client%4),
            64512+static_cast<std::uint32_t>(client%16),1000+i*90);
        if(honest.Reserve(request)==K6QuotaStatus::Ok)++honestAdmitted;
    }

    K6QuotaHierarchyPolicy boundaryPolicy;
    boundaryPolicy.principal={2,2};boundaryPolicy.prefix48={2,2};
    boundaryPolicy.issuer={2,2};boundaryPolicy.asn={2,2};
    boundaryPolicy.service={2,2};boundaryPolicy.global={2,2};
    K6QuotaHierarchy boundary(boundaryPolicy);
    K6QuotaHierarchyRequest before=Request(1,1,1,64512,899999);before.units=2;
    const bool boundaryInitial=boundary.Reserve(before)==K6QuotaStatus::Ok;
    K6QuotaHierarchyRequest after=Request(1,1,1,64512,900001);
    const bool boundaryNoReset=boundary.Reserve(after)==K6QuotaStatus::RateLimited;

    K6FairScheduler scheduler;
    std::array<std::uint64_t,8> served{};bool fairSetup=true;
    for(std::size_t i=0;i<8;++i){
        const Hash32 issuer=HashFrom(i+1,0x70),target=HashFrom(i+1,0x30);
        fairSetup=fairSetup&&scheduler.RegisterAllocation(i+1,issuer,1024u*1024u,1024u*1024u)
            &&scheduler.RegisterStream(i+1,100+i,target,1024u*1024u,1024u*1024u)
            &&scheduler.Enqueue(100+i,1024u*1024u);
    }
    std::array<std::uint64_t,8> firstRound{};std::uint64_t round=0;
    while(scheduler.queued_bytes()!=0&&round<128){
        ++round;std::vector<K6FairGrant> grants;
        scheduler.Poll(8*kK6FairDefaultQuantum,8,grants);
        for(const K6FairGrant& grant:grants){const std::size_t index=grant.allocation_id-1;
            served[index]+=grant.bytes;if(firstRound[index]==0)firstRound[index]=round;}
    }
    const auto minmax=std::minmax_element(served.begin(),served.end());
    std::array<std::uint64_t,8> sortedWait=firstRound;std::sort(sortedWait.begin(),sortedWait.end());
    const double honestRatio=static_cast<double>(honestAdmitted)/10000.0;
    const double fairness=Jain(served);
    const std::uint64_t overshoot=attackAdmitted>attackPolicy.prefix48.capacity_units
        ?attackAdmitted-attackPolicy.prefix48.capacity_units:0;
    const bool pass=attackAdmitted<=attackPolicy.prefix48.capacity_units
        &&attack.principal_count()<=attackPolicy.max_principals&&failoverAdmitted==0
        &&honestRatio>=0.95&&boundaryInitial&&boundaryNoReset&&fairSetup
        &&scheduler.queued_bytes()==0&&(*minmax.second-*minmax.first)<=kK6FairDefaultQuantum
        &&fairness>=0.99&&sortedWait[7]<=1;
    const auto elapsed=std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now()-started).count();
    std::printf("LT4_KIND=deterministic-local-mechanism-lab\n");
    std::printf("LT4_ARRIVALS=1000000\nLT4_ATTACK_ADMITTED=%llu\n",
        static_cast<unsigned long long>(attackAdmitted));
    std::printf("LT4_ATTACK_RATE_DENIED=%llu\nLT4_ATTACK_CAPACITY_DENIED=%llu\n",
        static_cast<unsigned long long>(rateDenied),static_cast<unsigned long long>(capacityDenied));
    std::printf("LT4_PRINCIPAL_STATE=%zu\nLT4_FAILOVER_ADMITTED=%llu\n",
        attack.principal_count(),static_cast<unsigned long long>(failoverAdmitted));
    std::printf("LT4_BURST_OVERSHOOT=%llu\nLT4_HONEST_ADMISSION=%.6f\n",
        static_cast<unsigned long long>(overshoot),honestRatio);
    std::printf("LT4_BOUNDARY_NO_RESET=%u\nLT4_DRR_ROUNDS=%llu\n",
        boundaryNoReset?1:0,static_cast<unsigned long long>(round));
    std::printf("LT4_WAIT_P50_ROUNDS=%llu\nLT4_WAIT_P95_ROUNDS=%llu\nLT4_WAIT_P99_ROUNDS=%llu\n",
        static_cast<unsigned long long>(sortedWait[3]),
        static_cast<unsigned long long>(sortedWait[7]),
        static_cast<unsigned long long>(sortedWait[7]));
    std::printf("LT4_MAX_ISSUER_SHARE=%.6f\nLT4_JAIN_FAIRNESS=%.9f\n",
        static_cast<double>(*minmax.second)/(8.0*1024.0*1024.0),fairness);
    std::printf("LT4_RUNTIME_MS=%lld\nLT4_RESULT=%s\n",
        static_cast<long long>(elapsed),pass?"PASS":"FAIL");
    return pass?0:1;
}
