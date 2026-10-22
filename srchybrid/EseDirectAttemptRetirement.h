#pragma once
#include "reach/direct_route_dispatch.h"
#include "reach/direct_event_queue.h"
namespace ese {
// Main-thread only, outside adapter callbacks. Drained acknowledgements mean
// no contexts, buffers or producers remain for that route, not just socket EOF.
inline bool ReleaseDirectAttempt(reach::DirectCoordinator& coordinator,
    reach::DirectRouteDispatch& dispatch,const reach::DirectEventQueue& events,
    reach::DirectHandle handle) {
    const auto routes=coordinator.RoutesSnapshot(handle);
    if(!routes || !dispatch.CoversDrained(handle,*routes) || events.HasHandle(handle)) return false;
    if(!coordinator.Release(handle)) return false;
    dispatch.EraseReleased(handle);
    return true;
}
}
