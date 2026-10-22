#pragma once
#include "reach/direct_session.h"
#include <array>
namespace ese {
// Main-thread-only. Route IDs cannot be reused within a DCO handle.
class QuicRouteOwners {
public:
    struct Binding { reach::DirectHandle handle; std::uint32_t route=0; std::uint64_t epoch=0,owner=0; bool occupied=false; };
    const Binding* Find(reach::DirectHandle h,std::uint32_t route) const noexcept {
        for(const auto& b:slots_) if(b.occupied && Same(b.handle,h) && b.route==route) return &b;
        return nullptr;
    }
    bool HasHandle(reach::DirectHandle h) const noexcept {
        for(const auto& b:slots_) if(b.occupied && Same(b.handle,h)) return true;
        return false;
    }
    bool Reserve(reach::DirectHandle h,std::uint32_t route,std::uint64_t epoch) noexcept {
        if(h.slot>=256 || !h.generation || !route || Find(h,route)) return false;
        for(auto& b:slots_) if(!b.occupied) { b={h,route,epoch,0,true}; return true; }
        return false;
    }
    bool Bind(reach::DirectHandle h,std::uint32_t route,std::uint64_t owner) noexcept {
        if(!owner) return false;
        for(const auto& b:slots_) if(b.occupied && b.owner==owner) return false;
        for(auto& b:slots_) if(b.occupied && Same(b.handle,h) && b.route==route && !b.owner) { b.owner=owner; return true; }
        return false;
    }
    void CancelReservation(reach::DirectHandle h,std::uint32_t route) noexcept {
        for(auto& b:slots_) if(b.occupied && Same(b.handle,h) && b.route==route && !b.owner) b={};
    }
    bool Adopt(std::uint64_t owner,std::uint64_t epoch) noexcept {
        for(auto& b:slots_) if(b.occupied && b.owner==owner && owner && epoch && b.epoch==epoch-1) { b.epoch=epoch; return true; }
        return false;
    }
    void Erase(std::uint64_t owner) noexcept {
        if(!owner) return;
        for(auto& b:slots_) if(b.occupied && b.owner==owner) b={};
    }
private:
    static bool Same(reach::DirectHandle a,reach::DirectHandle b) noexcept { return a.slot==b.slot && a.generation==b.generation; }
    std::array<Binding,256> slots_{};
};
}
