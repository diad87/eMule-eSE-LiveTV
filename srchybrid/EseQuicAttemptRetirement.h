#pragma once
#include "EseQuicRouteOwners.h"
#include "reach/direct_coordinator.h"
#include "reach/direct_event_queue.h"
namespace ese {
// Main-thread only, after consumer contexts/writers have been destroyed.
// Never retire mixed-transport attempts through a QUIC-only ownership registry.
inline bool ReleaseQuicAttempt(reach::DirectCoordinator& coordinator,
    const QuicRouteOwners& owners,const reach::DirectEventQueue& events,reach::DirectHandle handle) {
    if(owners.HasHandle(handle) || events.HasHandle(handle) ||
        !coordinator.UsesOnlyTransport(handle,reach::DirectQuic)) return false;
    return coordinator.Release(handle);
}
}
