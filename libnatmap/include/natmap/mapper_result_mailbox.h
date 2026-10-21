#pragma once
#include "natmap/natmap_types.h"
#include <array>
#include <mutex>
#include <memory>

namespace natmap {
struct MapperOperation {
    std::uint64_t id=0,generation=0,started=0,deadline=0;
    MapperKind mapper=MapperKind::None;
    std::uint16_t tcp=0,udp=0;
    bool refresh=false;
};
struct MapperResult {
    std::uint32_t external_ipv4=0,lifetime=0,epoch=0;
    std::uint16_t external_tcp=0,external_udp=0;
    bool success=false;
};
struct OwnedMapperResult { MapperOperation operation; MapperResult result; };
// No pointer is posted across threads. Register before starting a worker;
// worker publishes using its captured id, UI consumes that exact id. Caller
// supplies current generation/time, not mutable mapper state. Bounded, single
// use, no eviction of active operations and no generation/ownership authority.
class MapperResultMailbox {
public:
    bool Begin(const MapperOperation& operation) {
        std::lock_guard<std::mutex> lock(mutex_);
        if(!operation.id || operation.id<=lastId_ || !operation.generation ||
            operation.mapper==MapperKind::None || !operation.tcp || operation.deadline<=operation.started) return false;
        for(auto& slot:slots_) if(!slot.used) {
            slot={}; slot.used=true; slot.value.operation=operation; lastId_=operation.id; return true;
        }
        return false;
    }
    bool Publish(std::uint64_t id,const MapperResult& result) {
        std::lock_guard<std::mutex> lock(mutex_);
        for(auto& slot:slots_) if(slot.used && slot.value.operation.id==id) {
            if(slot.published) return false;
            if(result.success && (!result.external_ipv4 || !result.external_tcp ||
                (slot.value.operation.udp && !result.external_udp))) return false;
            slot.value.result=result; slot.published=true; return true;
        }
        return false;
    }
    bool Take(std::uint64_t id,std::uint64_t generation,std::uint64_t now,OwnedMapperResult& out) {
        out={}; std::lock_guard<std::mutex> lock(mutex_);
        for(auto& slot:slots_) if(slot.used && slot.value.operation.id==id) {
            if(!slot.published) return false;
            const auto value=slot.value; slot={};
            if(value.operation.generation!=generation || now<value.operation.started || now>=value.operation.deadline) return false;
            out=value; return true;
        }
        return false;
    }
    void Discard(std::uint64_t id) {
        std::lock_guard<std::mutex> lock(mutex_);
        for(auto& slot:slots_) if(slot.used && slot.value.operation.id==id) slot={};
    }
    void Expire(std::uint64_t now) {
        std::lock_guard<std::mutex> lock(mutex_);
        for(auto& slot:slots_) if(slot.used && (now<slot.value.operation.started || now>=slot.value.operation.deadline)) slot={};
    }
    void DiscardAll() {
        std::lock_guard<std::mutex> lock(mutex_);
        for(auto& slot:slots_) slot={}; // keep lastId_: no operation-id reuse
    }
private:
    struct Slot { OwnedMapperResult value{}; bool used=false,published=false; };
    std::array<Slot,16> slots_{};
    std::mutex mutex_;
    std::uint64_t lastId_=0;
};
// Setup is the real platform notification installer; failed setup owns no
// pending registration. Keep this boundary testable with injected failures.
template<class Setup> bool ArmMapperNotification(std::shared_ptr<MapperResultMailbox> mailbox,
    std::uint64_t operation,Setup setup) {
    if(!mailbox || !operation) return false;
    try {
        if(setup()) return true;
    } catch(...) {
        mailbox->Discard(operation); throw;
    }
    mailbox->Discard(operation); return false;
}
// Captured when a worker starts. Its queue lifetime does not depend on the
// dialog/manager. Notify receives only an integer id, never a heap pointer.
class MapperResultPublisher {
public:
    MapperResultPublisher(std::shared_ptr<MapperResultMailbox> mailbox,std::uint64_t operation)
        : mailbox_(std::move(mailbox)),operation_(operation) {}
    void Cancel() { if(mailbox_ && operation_) mailbox_->Discard(operation_); }
    template<class Notify> bool Publish(const MapperResult& result,Notify notify) {
        if(!mailbox_ || !operation_ || !mailbox_->Publish(operation_,result)) return false;
        try {
            if(notify(operation_)) return true;
        } catch(...) {
            mailbox_->Discard(operation_); throw;
        }
        mailbox_->Discard(operation_); return false;
    }
private:
    std::shared_ptr<MapperResultMailbox> mailbox_;
    std::uint64_t operation_=0;
};
}
