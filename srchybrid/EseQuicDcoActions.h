#pragma once
#include "EseQuicRouteOwners.h"
#include "EseQuicTransport.h"
#include "reach/direct_coordinator.h"
namespace ese {
// Main-thread action application, shared by host and isolated integration tests.
// Start/Terminal remain in the returned batches for the source/client consumer.
template<class Find,class Adopt>
void ApplyQuicDcoActions(reach::DirectCoordinator& coordinator,const QuicRouteOwners& owners,
    std::vector<reach::DirectCoordinatorBatch>& batches,Find find,Adopt adopt) {
    std::vector<reach::DirectHandle> failedAttach;
    for(const auto& batch:batches) for(const auto& action:batch.actions) {
        const auto* binding=owners.Find(batch.handle,action.route_id);
        if(!binding || !binding->owner) continue;
        if(action.type==reach::DirectActionType::Close && action.session_epoch>=binding->epoch) {
            if(auto* transport=find(binding->owner)) transport->Close(action.reason);
        } else if(action.type==reach::DirectActionType::Attach) {
            if(!adopt(binding->owner,batch.handle)) failedAttach.push_back(batch.handle);
        }
    }
    // Appending only after traversal preserves iterator validity and terminal
    // subscriber notifications; cancellation cannot leave a false READY winner.
    for(const auto handle:failedAttach) {
        auto failed=coordinator.Cancel(handle,reach::DirectReason::DirectUnreachable);
        for(const auto& action:failed.actions) if(action.type==reach::DirectActionType::Close) {
            const auto* binding=owners.Find(handle,action.route_id);
            if(binding && binding->owner) if(auto* transport=find(binding->owner)) transport->Close(action.reason);
        }
        if(!failed.actions.empty()) batches.push_back(std::move(failed));
    }
}
}
