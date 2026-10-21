// SPDX-License-Identifier: MIT
#include "reach/direct_coordinator.h"
#include <algorithm>
#include <limits>
#include <utility>

namespace reach {
namespace {
template<std::size_t N> bool Nonzero(const std::array<std::uint8_t,N>& bytes)
{
    return std::any_of(bytes.begin(),bytes.end(),[](auto b){return b!=0;});
}
bool ValidPeer(const DirectPeerKey& peer)
{
    switch (peer.domain) {
    case DirectPeerDomain::NodePublicKey:
        return Nonzero(peer.identity) && !peer.source_record_id && !peer.source_epoch;
    case DirectPeerDomain::UserHash:
        return std::any_of(peer.identity.begin(),peer.identity.begin()+16,[](auto b){return b!=0;}) &&
            std::all_of(peer.identity.begin()+16,peer.identity.end(),[](auto b){return b==0;}) &&
            !peer.source_record_id && !peer.source_epoch;
    case DirectPeerDomain::Provisional:
        return !Nonzero(peer.identity) && peer.source_record_id && peer.source_epoch;
    }
    return false;
}
bool SamePeer(const DirectPeerKey& a,const DirectPeerKey& b)
{
    return a.domain==b.domain && a.identity==b.identity &&
        a.source_record_id==b.source_record_id && a.source_epoch==b.source_epoch;
}
bool Terminal(const DirectSession& session)
{
    return session.State()==DirectSessionState::Failed || session.State()==DirectSessionState::Cancelled;
}
}

DirectCoordinator::Slot* DirectCoordinator::Resolve(DirectHandle handle) noexcept
{
    if (handle.slot>=slots_.size() || !handle.generation) return nullptr;
    auto& slot=slots_[handle.slot];
    return slot.session && slot.generation==handle.generation ? &slot : nullptr;
}
const DirectCoordinator::Slot* DirectCoordinator::Resolve(DirectHandle handle) const noexcept
{
    if (handle.slot>=slots_.size() || !handle.generation) return nullptr;
    const auto& slot=slots_[handle.slot];
    return slot.session && slot.generation==handle.generation ? &slot : nullptr;
}

DirectRequestResult DirectCoordinator::RequestSharedAttempt(const DirectPeerKey& peer,
    std::uint64_t subscriber,const DirectAttemptId& attempt_id,
    std::uint64_t topology_generation,std::uint64_t now_ms)
{
    if(peer.domain!=DirectPeerDomain::NodePublicKey) return {};
    for(const auto& slot:slots_)
        if(slot.session && SamePeer(peer,slot.peer) && slot.attempt_id!=attempt_id) return {};
    return Request(peer,subscriber,attempt_id,topology_generation,now_ms);
}

DirectRequestResult DirectCoordinator::Request(const DirectPeerKey& peer,
    std::uint64_t subscriber,const DirectAttemptId& attempt_id,
    std::uint64_t topology_generation,std::uint64_t now_ms)
{
    if (!ValidPeer(peer) || !subscriber || !Nonzero(attempt_id) || !topology_generation) return {};
    for (std::size_t i=0;i<slots_.size();++i) {
        auto& slot=slots_[i];
        if (!slot.session || !SamePeer(peer,slot.peer)) continue;
        const DirectHandle handle{static_cast<std::uint32_t>(i),slot.generation};
        if (Terminal(*slot.session)) return {DirectRequestStatus::AwaitingRelease,handle};
        if (slot.topology_generation!=topology_generation)
            return {DirectRequestStatus::StaleTopology,handle};
        if (std::find(slot.subscribers.begin(),slot.subscribers.end(),subscriber)==slot.subscribers.end()) {
            if (slot.subscribers.size()==kDirectMaxSubscribers)
                return {DirectRequestStatus::ResourceLimit,handle};
            slot.subscribers.push_back(subscriber);
        }
        return {DirectRequestStatus::Joined,handle};
    }
    // A CSPRNG collision is rejected rather than aliasing separate peers.
    for (const auto& slot:slots_)
        if (slot.session && slot.attempt_id==attempt_id) return {};
    for (std::size_t i=0;i<slots_.size();++i) {
        auto& slot=slots_[i];
        if (slot.session || slot.generation==std::numeric_limits<std::uint32_t>::max()) continue;
        ++slot.generation;
        const DirectHandle handle{static_cast<std::uint32_t>(i),slot.generation};
        slot.peer=peer; slot.attempt_id=attempt_id; slot.topology_generation=topology_generation;
        slot.subscribers={subscriber};
        slot.session.emplace(handle,topology_generation,now_ms);
        ++size_;
        return {DirectRequestStatus::Created,handle};
    }
    return {DirectRequestStatus::ResourceLimit,{}};
}

DirectCoordinatorBatch DirectCoordinator::Batch(DirectHandle handle,const Slot& slot,
    std::vector<DirectSessionAction> actions)
{
    DirectCoordinatorBatch batch;
    batch.handle=handle;
    if (std::any_of(actions.begin(),actions.end(),[](const auto& action){
        return action.type==DirectActionType::Terminal;
    })) batch.terminal_subscribers=slot.subscribers;
    batch.actions=std::move(actions);
    return batch;
}
DirectCoordinatorBatch DirectCoordinator::SetRoutes(DirectHandle handle,
    const std::vector<DirectSessionRoute>& routes,std::uint64_t now_ms)
{
    auto* slot=Resolve(handle);
    return slot ? Batch(handle,*slot,slot->session->SetRoutes(routes,now_ms)) : DirectCoordinatorBatch{handle,{},{}};
}
bool DirectCoordinator::AuthorizesStart(DirectHandle handle,const DirectSessionRoute& route,
    std::uint64_t epoch) const noexcept
{
    const auto* slot=Resolve(handle);
    return slot && slot->session->AuthorizesStart(route,epoch);
}
DirectCoordinatorBatch DirectCoordinator::Advance(DirectHandle handle,std::uint64_t now_ms,
    const std::vector<DirectSessionEvent>& events)
{
    auto* slot=Resolve(handle);
    return slot ? Batch(handle,*slot,slot->session->Advance(now_ms,events)) : DirectCoordinatorBatch{handle,{},{}};
}
DirectCoordinatorBatch DirectCoordinator::Cancel(DirectHandle handle,DirectReason reason)
{
    auto* slot=Resolve(handle);
    return slot ? Batch(handle,*slot,slot->session->Cancel(reason)) : DirectCoordinatorBatch{handle,{},{}};
}
DirectIdentityResult DirectCoordinator::ResolveAuthenticatedPeer(DirectHandle handle,
    std::uint32_t route,std::uint64_t epoch,const DirectPeerKey& authenticated)
{
    DirectIdentityResult result;
    auto* source=Resolve(handle);
    if (!source || !ValidPeer(authenticated) || authenticated.domain==DirectPeerDomain::Provisional ||
        !source->session->AwaitingAuthentication(route,epoch)) return result;
    result.destination=handle;
    if (source->peer.domain!=DirectPeerDomain::Provisional) {
        if (SamePeer(source->peer,authenticated)) result.status=DirectIdentityResolution::Unchanged;
        return result; // never rename a different expected/pinned identity
    }
    for (std::size_t i=0;i<slots_.size();++i) {
        auto& target=slots_[i];
        if (!target.session || &target==source || !SamePeer(target.peer,authenticated)) continue;
        if (Terminal(*target.session) || target.topology_generation!=source->topology_generation) return result;
        auto subscribers=target.subscribers;
        for (const auto token:source->subscribers)
            if (std::find(subscribers.begin(),subscribers.end(),token)==subscribers.end()) subscribers.push_back(token);
        if (subscribers.size()>kDirectMaxSubscribers) {
            result.status=DirectIdentityResolution::ResourceLimit; return result;
        }
        // Allocate all returned/merged storage before mutating either attempt.
        result.moved_subscribers=source->subscribers;
        result.retired.handle=handle;
        result.retired.actions=source->session->Cancel(DirectReason::PeerGone);
        source->subscribers.clear(); // transferred, not terminal notifications
        target.subscribers=std::move(subscribers);
        result.destination={static_cast<std::uint32_t>(i),target.generation};
        result.status=DirectIdentityResolution::Merged;
        return result;
    }
    source->peer=authenticated;
    result.status=DirectIdentityResolution::Promoted;
    return result;
}
std::vector<DirectCoordinatorBatch> DirectCoordinator::AdvanceAll(std::uint64_t now_ms,
    const std::vector<DirectSessionEvent>& events)
{
    std::vector<DirectCoordinatorBatch> batches;
    if (events.size()>4096) return batches;
    for (std::size_t i=0;i<slots_.size();++i) {
        auto& slot=slots_[i];
        if (!slot.session) continue;
        const DirectHandle handle{static_cast<std::uint32_t>(i),slot.generation};
        std::vector<DirectSessionEvent> matching;
        for (const auto& event:events)
            if (event.handle.slot==handle.slot && event.handle.generation==handle.generation)
                matching.push_back(event);
        auto batch=Batch(handle,slot,slot.session->Advance(now_ms,matching));
        if (!batch.actions.empty()) batches.push_back(std::move(batch));
    }
    return batches;
}
DirectCoordinatorBatch DirectCoordinator::Unsubscribe(DirectHandle handle,std::uint64_t subscriber)
{
    auto* slot=Resolve(handle);
    if (!slot) return {handle,{},{}};
    const auto it=std::find(slot->subscribers.begin(),slot->subscribers.end(),subscriber);
    if (it==slot->subscribers.end()) return {handle,{},{}};
    slot->subscribers.erase(it);
    if (slot->subscribers.empty()) return Cancel(handle,DirectReason::PeerGone);
    return {handle,{},{}};
}
std::vector<DirectCoordinatorBatch> DirectCoordinator::InvalidateTopology(std::uint64_t generation)
{
    std::vector<DirectCoordinatorBatch> batches;
    for (std::size_t i=0;i<slots_.size();++i) {
        auto& slot=slots_[i];
        if (!slot.session) continue;
        const DirectHandle handle{static_cast<std::uint32_t>(i),slot.generation};
        auto batch=Batch(handle,slot,slot.session->InvalidateTopology(generation));
        if (!batch.actions.empty()) batches.push_back(std::move(batch));
    }
    return batches;
}
bool DirectCoordinator::Release(DirectHandle handle)
{
    auto* slot=Resolve(handle);
    if (!slot || !Terminal(*slot->session)) return false;
    slot->session.reset(); slot->subscribers.clear(); slot->peer={}; slot->attempt_id={};
    slot->topology_generation=0;
    --size_;
    return true;
}
bool DirectCoordinator::UsesOnlyTransport(DirectHandle handle,std::uint8_t transport) const noexcept
{
    const auto* slot=Resolve(handle);
    return slot && slot->session->UsesOnlyTransport(transport);
}
std::optional<std::vector<DirectSessionRoute>> DirectCoordinator::RoutesSnapshot(DirectHandle handle) const
{
    const auto* slot=Resolve(handle);
    if(!slot) return std::nullopt;
    return slot->session->RoutesSnapshot();
}
std::vector<DirectHandle> DirectCoordinator::ActiveHandles() const
{
    std::vector<DirectHandle> result; result.reserve(size_);
    for(std::size_t i=0;i<slots_.size();++i) if(slots_[i].session)
        result.push_back({static_cast<std::uint32_t>(i),slots_[i].generation});
    return result;
}

std::optional<DirectCoordinatorSnapshot> DirectCoordinator::Snapshot(DirectHandle handle) const
{
    const auto* slot=Resolve(handle);
    if (!slot) return std::nullopt;
    const auto& s=*slot->session;
    return DirectCoordinatorSnapshot{handle,slot->attempt_id,slot->peer,s.State(),s.Reason(),
        s.Winner(),s.Epoch(),s.UsefulBytes(),s.TransferVerified(),slot->subscribers.size(),slot->topology_generation,s.HighestRouteId(),s.ReasonChain(),s.ReasonCount(),s.FallbackCount()};
}
} // namespace reach
