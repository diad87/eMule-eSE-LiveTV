// SPDX-License-Identifier: MIT
#pragma once
#include "reach/direct_coordinator.h"

namespace reach {
// Main-thread scalar ownership only. Splitting never executes adapters or
// changes controller state. The host delivers terminal subscribers centrally,
// once, and releases the handle only after every transport owner drains.
struct DirectDispatchBatch {
    struct Step { std::size_t transport=0,action=0; };
    std::array<DirectCoordinatorBatch,3> transports; // TCP, uTP, QUIC
    // Execute through this order, not transport by transport: Close on one
    // adapter may precede Attach on another during winner replacement.
    std::vector<Step> order;
    std::vector<std::uint64_t> terminal_subscribers;
};
class DirectRouteDispatch {
public:
    bool Register(DirectHandle handle,std::uint32_t route,std::uint8_t transport) noexcept {
        if(handle.slot>=kDirectMaxAttempts || !handle.generation || !route || Index(transport)<0) return false;
        if(terminals_[handle.slot].generation) return false;
        std::size_t count=0; Entry* empty=nullptr;
        for(auto& entry:entries_) {
            if(!entry.route) { if(!empty) empty=&entry; continue; }
            if(entry.handle.slot!=handle.slot) continue;
            if(entry.handle.generation!=handle.generation) return false;
            if(entry.route==route) return entry.transport==transport && !entry.drained;
            ++count;
        }
        if(!empty || count>=kDirectMaxRoutes) return false;
        *empty={handle,route,transport,false}; return true;
    }
    // Host calls this only after validating the authoritative coordinator
    // terminal. False means stale or already delivered; never notify twice.
    bool MarkTerminal(DirectHandle handle) noexcept {
        if(handle.slot>=kDirectMaxAttempts || !handle.generation || terminals_[handle.slot].generation) return false;
        for(const auto& entry:entries_)
            if(entry.route && entry.handle.slot==handle.slot && !Same(entry.handle,handle)) return false;
        terminals_[handle.slot]=handle; return true;
    }
    // Adapter acknowledges only after contexts, callbacks and buffers drain.
    // An unstarted reservation must also be explicitly acknowledged.
    bool MarkDrained(DirectHandle handle,std::uint32_t route,std::uint8_t transport) noexcept {
        for(auto& entry:entries_) if(entry.route==route && route && Same(entry.handle,handle)) {
            if(entry.transport!=transport) return false;
            entry.drained=true; return true;
        }
        return false;
    }
    bool HasTerminal(DirectHandle handle) const noexcept {
        return handle.slot<kDirectMaxAttempts && handle.generation && Same(terminals_[handle.slot],handle);
    }
    bool DrainedTerminal(DirectHandle handle) const noexcept {
        if(!HasTerminal(handle)) return false;
        for(const auto& entry:entries_) if(entry.route && Same(entry.handle,handle) && !entry.drained) return false;
        return true; // host must additionally check pending events and coordinator.Release
    }
    bool CoversDrained(DirectHandle handle,const std::vector<DirectSessionRoute>& routes) const noexcept {
        if(!DrainedTerminal(handle)) return false;
        for(const auto& route:routes) {
            bool found=false;
            for(const auto& entry:entries_)
                if(entry.route==route.id && route.id && Same(entry.handle,handle) &&
                    entry.transport==route.transport && entry.drained) { found=true; break; }
            if(!found) return false;
        }
        return true;
    }
    void EraseReleased(DirectHandle handle) noexcept {
        for(auto& entry:entries_) if(Same(entry.handle,handle)) entry={};
        if(handle.slot<kDirectMaxAttempts && Same(terminals_[handle.slot],handle)) terminals_[handle.slot]={};
    }
    std::optional<DirectDispatchBatch> Split(const DirectCoordinatorBatch& batch) const {
        if(batch.handle.slot>=kDirectMaxAttempts || !batch.handle.generation) return std::nullopt;
        if(terminals_[batch.handle.slot].generation) return std::nullopt;
        if(batch.terminal_subscribers.size()>kDirectMaxSubscribers) return std::nullopt;
        for(std::size_t i=0;i<batch.terminal_subscribers.size();++i) {
            if(!batch.terminal_subscribers[i]) return std::nullopt;
            for(std::size_t j=0;j<i;++j)
                if(batch.terminal_subscribers[i]==batch.terminal_subscribers[j]) return std::nullopt;
        }
        DirectDispatchBatch result;
        std::array<bool,3> owners{};
        for(auto& output:result.transports) output.handle=batch.handle;
        for(const auto& entry:entries_) {
            if(!entry.route || entry.handle.slot!=batch.handle.slot) continue;
            if(entry.handle.generation!=batch.handle.generation) return std::nullopt;
            owners[Index(entry.transport)]=true;
        }
        bool terminal=false;
        for(const auto& action:batch.actions) {
            if(action.type==DirectActionType::Terminal) {
                if(terminal || action.route_id) return std::nullopt;
                terminal=true;
                for(std::size_t i=0;i<owners.size();++i) if(owners[i]) {
                    result.order.push_back({i,result.transports[i].actions.size()});
                    result.transports[i].actions.push_back(action);
                }
                continue;
            }
            if(terminal || (action.type!=DirectActionType::Start && action.type!=DirectActionType::Attach && action.type!=DirectActionType::Close)) return std::nullopt;
            const Entry* owner=nullptr;
            for(const auto& entry:entries_) if(entry.route==action.route_id && entry.route && Same(entry.handle,batch.handle)) { owner=&entry; break; }
            if(!owner) return std::nullopt; // fail whole batch; never partially execute
            const auto index=static_cast<std::size_t>(Index(owner->transport));
            result.order.push_back({index,result.transports[index].actions.size()});
            result.transports[index].actions.push_back(action);
        }
        if(!terminal && !batch.terminal_subscribers.empty()) return std::nullopt;
        if(terminal) result.terminal_subscribers=batch.terminal_subscribers;
        return result;
    }
private:
    struct Entry { DirectHandle handle{}; std::uint32_t route=0; std::uint8_t transport=0; bool drained=false; };
    static bool Same(DirectHandle a,DirectHandle b) noexcept { return a.slot==b.slot && a.generation==b.generation; }
    static int Index(std::uint8_t transport) noexcept { return transport==DirectTcp ? 0 : transport==DirectUtp ? 1 : transport==DirectQuic ? 2 : -1; }
    std::array<Entry,kDirectMaxAttempts*kDirectMaxRoutes> entries_{};
    std::array<DirectHandle,kDirectMaxAttempts> terminals_{};
};
}
