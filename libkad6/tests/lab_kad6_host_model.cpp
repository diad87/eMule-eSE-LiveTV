// SPDX-License-Identifier: MIT
// Portable concurrency model for the Rev3 CC lane. It deliberately wraps the
// same portable lease, quota and credit state used by the Windows host behind
// the host's pending-state ownership boundary.
#include "kad6/kad6_gateway.h"
#include "kad6/kad6_lease.h"
#include "kad6/kad6_quota.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace kad6;
namespace {
thread_local bool pending_held=false;

struct Model {
    std::mutex pending;
    K6SourceLeaseTable leases;
    K6QuotaHierarchy quota;
    std::map<std::uint64_t,std::uint64_t> publications;
    std::atomic<std::uint64_t> operations{0},callbacks{0},violations{0};
};

struct PendingGuard {
    explicit PendingGuard(std::mutex& mutex):lock(mutex){pending_held=true;}
    ~PendingGuard(){pending_held=false;}
    std::unique_lock<std::mutex> lock;
};

void Callback(Model& model,std::size_t count){
    if(pending_held)++model.violations;
    model.callbacks.fetch_add(count,std::memory_order_relaxed);
}

K6SourceBind Bind(std::uint64_t id){
    K6SourceBind bind;bind.file_hash[0]=1;bind.compat_user_hash[0]=2;
    bind.bind_nonce[0]=3;bind.bind_nonce[1]=static_cast<Byte>(id);
    bind.file_size=1024;bind.desired_family=4;
    bind.transport_mask=kK6TransportTcp|kK6TransportUdp;
    bind.flags=kK6SourceAllowInbound|kK6SourceFile;
    bind.requested_lifetime_s=3600;bind.max_upload_bps=65536;
    bind.source_epoch=id+1;bind.requested_mode=K6BindingMode::DedicatedVep;
    return bind;
}

K6SourceBound Bound(const K6SourceBind& bind,std::uint64_t id){
    K6SourceBound bound;bound.status=K6SourceBoundStatus::Ok;
    bound.transport_mask=bind.transport_mask;bound.flags=bind.flags;
    bound.binding_mode=K6BindingMode::DedicatedVep;
    bound.identity_mode=K6IdentityMode::OriginatorVep;bound.endpoint_slot=1;
    bound.source_lease_id=id+1;bound.lifetime_s=1800;bound.refresh_after_s=900;
    bound.bind_nonce=bind.bind_nonce;
    bound.virtual_endpoint.addr.family=Kad6Address::Family::IPv4;
    bound.virtual_endpoint.addr.addr={8,8,4,4};bound.virtual_endpoint.tcp_port=4662;
    bound.virtual_endpoint.udp_port=4672;
    bound.virtual_endpoint.transport_flags=kK6EpTcpEd2k|kK6EpEd2kGateway;
    bound.virtual_endpoint.valid_until=100000;bound.exit_apparent_ip=bound.virtual_endpoint.addr;
    bound.exit_node_pub[0]=1;return bound;
}

K6QuotaHierarchyRequest Quota(std::uint64_t id,std::uint64_t now){
    K6QuotaHierarchyRequest request;request.principal[0]=static_cast<Byte>(id);
    request.principal[1]=static_cast<Byte>(id>>8);request.prefix48[0]=0x20;
    request.prefix48[5]=static_cast<Byte>(id%32);request.issuer_key_id[0]=1;
    request.asn=64512+static_cast<std::uint32_t>(id%16);
    request.service=K6QuotaService::ExitEd2kFull;request.now_ms=now;return request;
}

void Worker(Model& model,std::uint64_t seed,std::uint64_t operations){
    for(std::uint64_t i=0;i<operations;++i){
        seed^=seed<<13;seed^=seed>>7;seed^=seed<<17;
        const std::uint64_t id=(seed&4095u)+1;std::vector<std::uint64_t> transitioned;
        switch(seed%7){
        case 0:{PendingGuard guard(model.pending);K6SourceBind bind=Bind(id);
            K6SourceBound bound=Bound(bind,id);
            (void)model.leases.AddBound(static_cast<std::uint32_t>(id),bind.file_hash,
                bind,bound,1000);break;}
        case 1:{PendingGuard guard(model.pending);
            model.leases.QueueCircuitTeardown(static_cast<std::uint32_t>(id));break;}
        case 2:{PendingGuard guard(model.pending);
            (void)model.leases.DrainQueuedCircuits(64,&transitioned);
            (void)model.leases.EraseClosedSome(64);break;}
        case 3:{PendingGuard guard(model.pending);
            (void)model.leases.ExpireSome(5000+(seed%4000),64,&transitioned);
            (void)model.leases.EraseClosedSome(64);break;}
        case 4:{PendingGuard guard(model.pending);model.publications[id]=seed;
            if(model.publications.size()>4096)model.publications.erase(model.publications.begin());break;}
        case 5:{PendingGuard guard(model.pending);(void)model.quota.Reserve(Quota(id,1000+i));break;}
        default:{PendingGuard guard(model.pending);model.publications.erase(id);
            model.leases.QueueCircuitTeardown(static_cast<std::uint32_t>(id));break;}
        }
        if(!transitioned.empty())Callback(model,transitioned.size());
        model.operations.fetch_add(1,std::memory_order_relaxed);
    }
}
}

int main(int argc,char** argv){
    // Default is the local smoke lane. The Rev3 full campaign is selected
    // explicitly with --schedules 100 --ops 1000000.
    std::uint64_t schedules=10,operationsPerSchedule=100000;unsigned threads=8;
    for(int i=1;i<argc;++i){
        if(i+1>=argc)return 2;
        if(std::string(argv[i])=="--schedules")schedules=std::strtoull(argv[++i],nullptr,10);
        else if(std::string(argv[i])=="--ops")operationsPerSchedule=std::strtoull(argv[++i],nullptr,10);
        else if(std::string(argv[i])=="--threads")threads=static_cast<unsigned>(std::strtoul(argv[++i],nullptr,10));
        else return 2;
    }
    if(!schedules||!operationsPerSchedule||threads<2||threads>32)return 2;
    const auto started=std::chrono::steady_clock::now();std::uint64_t totalCallbacks=0;
    for(std::uint64_t schedule=0;schedule<schedules;++schedule){
        Model model;std::vector<std::thread> workers;
        const std::uint64_t base=operationsPerSchedule/threads,remainder=operationsPerSchedule%threads;
        for(unsigned t=0;t<threads;++t)workers.emplace_back(Worker,std::ref(model),
            0x4b36434300000000ull^(schedule<<8)^t,base+(t<remainder));
        for(std::thread& worker:workers)worker.join();
        std::vector<std::uint64_t> transitioned;
        {
            PendingGuard guard(model.pending);
            for(std::uint32_t circuit:model.leases.TrackedCircuits())
                model.leases.QueueCircuitTeardown(circuit);
            while(model.leases.ActiveSize()!=0){
                const std::size_t changed=model.leases.DrainQueuedCircuits(256,&transitioned);
                (void)model.leases.EraseClosedSome(256);
                if(changed==0&&model.leases.ActiveSize()!=0){++model.violations;break;}
            }
            (void)model.leases.EraseClosed();model.publications.clear();
        }
        Callback(model,transitioned.size());
        if(model.operations.load()!=operationsPerSchedule||model.violations.load()!=0
            ||model.leases.Size()!=0||!model.publications.empty()){
            std::printf("CC_FAIL schedule=%llu ops=%llu violations=%llu leases=%zu\n",
                static_cast<unsigned long long>(schedule),
                static_cast<unsigned long long>(model.operations.load()),
                static_cast<unsigned long long>(model.violations.load()),model.leases.Size());return 1;
        }
        totalCallbacks+=model.callbacks.load();
    }
    const auto elapsed=std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now()-started).count();
    std::printf("CC_KIND=portable-host-model\nCC_SCHEDULES=%llu\nCC_OPS_PER_SCHEDULE=%llu\n",
        static_cast<unsigned long long>(schedules),static_cast<unsigned long long>(operationsPerSchedule));
    std::printf("CC_THREADS=%u\nCC_TOTAL_OPS=%llu\nCC_CALLBACKS=%llu\nCC_RUNTIME_MS=%lld\nCC_RESULT=PASS\n",
        threads,static_cast<unsigned long long>(schedules*operationsPerSchedule),
        static_cast<unsigned long long>(totalCallbacks),static_cast<long long>(elapsed));
    return 0;
}
