// this file is part of eMule eSE - LT4 publish and ticket state owner
#include "LiveTunnelSourcePublisher.h"

#include <algorithm>
#include <utility>

namespace eSELive {

M2AModuleHandle M2A_BIND_LT4_15F4A995EA(const M2AParentPort&);
LiveTunnelSourcePublisher::LiveTunnelSourcePublisher(
    const M2AParentPort&) noexcept
    :m_m2a_binding_15f4a995ea(M2AAssignmentPolicy::RetainExisting)
{
    m_m2a_binding_15f4a995ea=M2A_BIND_LT4_15F4A995EA(M2AParentPort{this});
}

bool LiveTunnelSourcePublisher::InitializeTicketSecret(
    const std::array<std::uint8_t, 32>& secret) noexcept
{
    std::uint8_t any = 0;
    for (std::uint8_t value : secret)
        any |= value;
    std::lock_guard<std::mutex> guard(m_mutex);
    m_k6TicketSecret.fill(0);
    m_k6TicketSecretReady = any != 0;
    if (m_k6TicketSecretReady)
        m_k6TicketSecret = secret;
    return m_k6TicketSecretReady;
}

bool LiveTunnelSourcePublisher::TicketSecretReady() const noexcept
{
    std::lock_guard<std::mutex> guard(m_mutex);
    return m_k6TicketSecretReady;
}

std::array<std::uint8_t, 32>
LiveTunnelSourcePublisher::TicketSecretSnapshot() const noexcept
{
    std::lock_guard<std::mutex> guard(m_mutex);
    return m_k6TicketSecretReady ? m_k6TicketSecret
                                 : std::array<std::uint8_t, 32>{};
}

void LiveTunnelSourcePublisher::AuthorizeTarget(
    const std::string& key,
    const LiveTunnelAuthorizedTarget& target)
{
    std::lock_guard<std::mutex> guard(m_mutex);
    m_k6AuthorizedTargets[key] = target;
}

bool LiveTunnelSourcePublisher::FindAuthorizedTarget(
    const std::string& key,
    std::uint64_t now,
    LiveTunnelAuthorizedTarget& target) const
{
    std::lock_guard<std::mutex> guard(m_mutex);
    const auto found = m_k6AuthorizedTargets.find(key);
    if (found == m_k6AuthorizedTargets.end() ||
        found->second.expires_at <= now)
        return false;
    target = found->second;
    return true;
}

bool LiveTunnelSourcePublisher::ConsumeTicket(
    const kad6::K6TargetTicket& ticket,
    std::uint64_t now) noexcept
{
    if (!LiveTunnelTicketPolicy::ValidateTicketEnvelope(ticket, now))
        return false;
    const std::string key = LiveTunnelTicketPolicy::ReplayKey(ticket);
    std::lock_guard<std::mutex> guard(m_mutex);
    if (!m_k6TicketSecretReady)
        return false;
    LiveTunnelUsedTicket& used = m_k6UsedTickets[key];
    if (used.used >= ticket.max_connections)
        return false; // TicketReplayRejected
    ++used.used;
    used.expires_at = ticket.expires_at;
    return true;
}

LiveTunnelPublishMutation LiveTunnelSourcePublisher::PreparePublish(
    const LiveTunnelPublishRuntime& runtime,
    const std::string& shadowKey)
{
    std::lock_guard<std::mutex> guard(m_mutex);
    for (const auto& pair : m_k6Publishes) {
        const LiveTunnelPublishRuntime& old = pair.second;
        if (old.source_lease_id == runtime.source_lease_id &&
            old.request.record_epoch == runtime.request.record_epoch &&
            old.request.network_mask == runtime.request.network_mask &&
            old.request.record == runtime.request.record &&
            old.refresh_enabled)
            return LiveTunnelPublishMutation::DuplicatePublish;
    }
    if (m_k6Publishes.size() >= 8192 ||
        runtime.publish_lease_id == 0 ||
        m_k6Publishes.find(runtime.publish_lease_id) != m_k6Publishes.end())
        return LiveTunnelPublishMutation::CapacityRejected;
    LiveTunnelPublishRuntime stored = runtime;
    if (!shadowKey.empty()) {
        const auto primary = m_k6ShadowPrimary.find(shadowKey);
        if (primary == m_k6ShadowPrimary.end())
            m_k6ShadowPrimary.emplace(shadowKey, runtime.publish_lease_id);
        else
            stored.primary_publish_lease_id = primary->second;
    }
    m_k6Publishes.emplace(runtime.publish_lease_id, std::move(stored));
    return LiveTunnelPublishMutation::Created; // SingleShadowPrimary
}

LiveTunnelPublishMutation LiveTunnelSourcePublisher::OpenPublish(
    LiveTunnelPublishRuntime& runtime,const std::string& shadowKey,
    LiveTunnelPublishRuntime& duplicate,bool& exteriorPublish)
{
    exteriorPublish=false; std::lock_guard<std::mutex> guard(m_mutex);
    for(const auto& pair:m_k6Publishes){const auto& old=pair.second;
        if(old.source_lease_id==runtime.source_lease_id&&old.request.record_epoch==runtime.request.record_epoch&&old.request.network_mask==runtime.request.network_mask&&old.request.record==runtime.request.record&&old.refresh_enabled){duplicate=old;return LiveTunnelPublishMutation::DuplicatePublish;}}
    if(m_k6Publishes.size()>=8192||!runtime.publish_lease_id||m_k6Publishes.find(runtime.publish_lease_id)!=m_k6Publishes.end())return LiveTunnelPublishMutation::CapacityRejected;
    if(!shadowKey.empty()){auto primary=m_k6ShadowPrimary.find(shadowKey);if(primary==m_k6ShadowPrimary.end()){m_k6ShadowPrimary.emplace(shadowKey,runtime.publish_lease_id);exteriorPublish=true;}else runtime.primary_publish_lease_id=primary->second;}
    m_k6Publishes.emplace(runtime.publish_lease_id,runtime);return LiveTunnelPublishMutation::Created;
}

LiveTunnelPublishMutation LiveTunnelSourcePublisher::CommitPublish(
    std::uint64_t publishLeaseId,
    kad6::K6PublishStatus status,
    std::uint8_t networks)
{
    std::lock_guard<std::mutex> guard(m_mutex);
    const auto found = m_k6Publishes.find(publishLeaseId);
    if (found == m_k6Publishes.end())
        return LiveTunnelPublishMutation::LateAckIgnored;
    found->second.status = status;
    found->second.published_networks |= networks;
    return LiveTunnelPublishMutation::Updated;
}

LiveTunnelPublishMutation LiveTunnelSourcePublisher::Unpublish(
    std::uint64_t publishLeaseId,
    std::vector<LiveTunnelPublishAction>& actions)
{
    actions.clear();
    std::lock_guard<std::mutex> guard(m_mutex);
    const auto found = m_k6Publishes.find(publishLeaseId);
    if (found == m_k6Publishes.end())
        return LiveTunnelPublishMutation::DuplicateUnpublish;
    actions.push_back({LiveTunnelPublishActionKind::RemoveCoalesced,
                       publishLeaseId, found->second.source_lease_id});
    actions.push_back({LiveTunnelPublishActionKind::StopServing,
                       publishLeaseId, found->second.source_lease_id});
    for (auto primary = m_k6ShadowPrimary.begin();
         primary != m_k6ShadowPrimary.end();) {
        if (primary->second == publishLeaseId)
            primary = m_k6ShadowPrimary.erase(primary);
        else
            ++primary;
    }
    m_k6Publishes.erase(found);
    return LiveTunnelPublishMutation::Updated;
}

LiveTunnelPublishMutation LiveTunnelSourcePublisher::RecordShadowAck(
    std::uint64_t publishLeaseId,
    std::uint16_t replicas,
    std::uint8_t load)
{
    std::lock_guard<std::mutex> guard(m_mutex);
    const auto found = m_k6Publishes.find(publishLeaseId);
    if (found == m_k6Publishes.end() || !found->second.refresh_enabled)
        return LiveTunnelPublishMutation::LateAckIgnored;
    found->second.replicas =
        (std::max)(found->second.replicas, replicas);
    found->second.max_load = (std::max)(found->second.max_load, load);
    found->second.status = kad6::K6PublishStatus::RemoteAck;
    return LiveTunnelPublishMutation::Updated;
}

LiveTunnelPublishMutation LiveTunnelSourcePublisher::RecordNativeAck(
    std::uint64_t publishLeaseId,
    kad6::K6PublishStatus status)
{
    return CommitPublish(
        publishLeaseId, status, kad6::kK6PublishNetKad6);
}

std::vector<LiveTunnelPublishAction>
LiveTunnelSourcePublisher::CollectRefreshes(std::uint64_t now) const
{
    std::vector<LiveTunnelPublishAction> actions;
    std::lock_guard<std::mutex> guard(m_mutex);
    for (const auto& pair : m_k6Publishes) {
        const LiveTunnelPublishRuntime& runtime = pair.second;
        if (!runtime.refresh_enabled || runtime.expires_at <= now)
            continue;
        if (runtime.next_refresh_at != 0 && runtime.next_refresh_at <= now)
            actions.push_back({LiveTunnelPublishActionKind::RefreshShadow,
                               pair.first, runtime.source_lease_id});
        if (runtime.next_native_refresh_at != 0 &&
            runtime.next_native_refresh_at <= now)
            actions.push_back({LiveTunnelPublishActionKind::RefreshNative,
                               pair.first, runtime.source_lease_id});
        if (runtime.visibility_probe_at != 0 &&
            runtime.visibility_probe_at <= now)
            actions.push_back({LiveTunnelPublishActionKind::ProbeVisibility,
                               pair.first, runtime.source_lease_id});
    }
    return actions;
}

std::vector<LiveTunnelPublishAction>
LiveTunnelSourcePublisher::Sweep(std::uint64_t now)
{
    std::vector<LiveTunnelPublishAction> actions;
    std::lock_guard<std::mutex> guard(m_mutex);
    for (auto publish = m_k6Publishes.begin();
         publish != m_k6Publishes.end();) {
        if (publish->second.expires_at > now) {
            ++publish;
            continue;
        }
        actions.push_back({LiveTunnelPublishActionKind::RemoveCoalesced,
                           publish->first,
                           publish->second.source_lease_id});
        const std::uint64_t expired = publish->first;
        publish = m_k6Publishes.erase(publish);
        for (auto primary = m_k6ShadowPrimary.begin();
             primary != m_k6ShadowPrimary.end();) {
            if (primary->second == expired)
                primary = m_k6ShadowPrimary.erase(primary);
            else
                ++primary;
        }
    }
    for (auto target = m_k6AuthorizedTargets.begin();
         target != m_k6AuthorizedTargets.end();) {
        if (target->second.expires_at <= now)
            target = m_k6AuthorizedTargets.erase(target);
        else
            ++target;
    }
    for (auto ticket = m_k6UsedTickets.begin();
         ticket != m_k6UsedTickets.end();) {
        if (ticket->second.expires_at <= now)
            ticket = m_k6UsedTickets.erase(ticket);
        else
            ++ticket;
    }
    return actions;
}

bool LiveTunnelSourcePublisher::DisablePublish(std::uint64_t id){std::lock_guard<std::mutex> g(m_mutex);auto it=m_k6Publishes.find(id);if(it==m_k6Publishes.end())return false;it->second.refresh_enabled=false;return true;}
std::vector<std::uint64_t> LiveTunnelSourcePublisher::DisableSource(std::uint64_t source){std::vector<std::uint64_t> ids;std::lock_guard<std::mutex> g(m_mutex);for(auto& pair:m_k6Publishes)if(pair.second.source_lease_id==source){pair.second.refresh_enabled=false;ids.push_back(pair.first);}return ids;}
std::vector<std::uint64_t> LiveTunnelSourcePublisher::DisableAll(bool clear){std::vector<std::uint64_t> ids;std::lock_guard<std::mutex> g(m_mutex);for(auto& pair:m_k6Publishes){pair.second.refresh_enabled=false;ids.push_back(pair.first);}if(clear){m_k6Publishes.clear();m_k6ShadowPrimary.clear();}return ids;}
bool LiveTunnelSourcePublisher::EnsureShadow(const std::string& key,std::uint64_t candidate,std::uint64_t& primary,bool& created){created=false;std::lock_guard<std::mutex> g(m_mutex);auto runtime=m_k6Publishes.find(candidate);if(runtime==m_k6Publishes.end())return false;auto it=m_k6ShadowPrimary.find(key);if(it==m_k6ShadowPrimary.end()){m_k6ShadowPrimary.emplace(key,candidate);primary=candidate;created=true;}else primary=it->second;runtime->second.primary_publish_lease_id=primary;return true;}
bool LiveTunnelSourcePublisher::ForgetShadow(const std::string& key){std::lock_guard<std::mutex> g(m_mutex);return m_k6ShadowPrimary.erase(key)!=0;}
bool LiveTunnelSourcePublisher::SetQueueState(std::uint64_t id,bool queued,std::uint64_t primary,std::uint64_t next){std::lock_guard<std::mutex> g(m_mutex);auto it=m_k6Publishes.find(id);if(it==m_k6Publishes.end())return false;it->second.kad2_queued=queued;if(primary)it->second.primary_publish_lease_id=primary;if(next)it->second.next_refresh_at=next;return true;}
bool LiveTunnelSourcePublisher::MarkNativeSent(std::uint64_t id,std::uint64_t now,std::uint64_t ttl,std::uint64_t& source){std::lock_guard<std::mutex> g(m_mutex);auto it=m_k6Publishes.find(id);if(it==m_k6Publishes.end()||!it->second.refresh_enabled)return false;auto& r=it->second;r.status=kad6::K6PublishStatus::Sent;r.published_networks|=kad6::kK6PublishNetKad6;if(r.auto_refresh)r.next_native_refresh_at=now+(std::max<std::uint64_t>)(kad6::kK6PublishMinTtlSeconds,ttl/2);source=r.source_lease_id;return true;}
std::vector<std::uint64_t> LiveTunnelSourcePublisher::MarkShadowSent(std::uint64_t id){std::vector<std::uint64_t> sources;std::lock_guard<std::mutex> g(m_mutex);auto p=m_k6Publishes.find(id);if(p==m_k6Publishes.end()||!p->second.refresh_enabled)return sources;for(auto& pair:m_k6Publishes)if(pair.second.refresh_enabled&&pair.second.primary_publish_lease_id==p->second.primary_publish_lease_id){if(pair.second.status==kad6::K6PublishStatus::Queued)pair.second.status=kad6::K6PublishStatus::Sent;pair.second.published_networks|=kad6::kK6PublishNetKad2;sources.push_back(pair.second.source_lease_id);}return sources;}
bool LiveTunnelSourcePublisher::MarkShadowAckFamily(std::uint64_t id,std::uint8_t load,std::uint64_t now){std::lock_guard<std::mutex> g(m_mutex);auto p=m_k6Publishes.find(id);if(p==m_k6Publishes.end()||!p->second.refresh_enabled)return false;for(auto& pair:m_k6Publishes)if(pair.second.refresh_enabled&&pair.second.primary_publish_lease_id==p->second.primary_publish_lease_id){auto& r=pair.second;if(r.status!=kad6::K6PublishStatus::VerifiedVisible)r.status=kad6::K6PublishStatus::RemoteAck;r.published_networks|=kad6::kK6PublishNetKad2;if(r.replicas!=0xffff)++r.replicas;r.max_load=(std::max)(r.max_load,load);if(!r.visibility_probe_at)r.visibility_probe_at=now+145;}return true;}
bool LiveTunnelSourcePublisher::MarkShadowVerifiedFamily(std::uint64_t id){std::lock_guard<std::mutex> g(m_mutex);auto p=m_k6Publishes.find(id);if(p==m_k6Publishes.end()||!p->second.refresh_enabled)return false;for(auto& pair:m_k6Publishes)if(pair.second.refresh_enabled&&pair.second.primary_publish_lease_id==p->second.primary_publish_lease_id){auto& r=pair.second;r.status=kad6::K6PublishStatus::VerifiedVisible;r.published_networks|=kad6::kK6PublishNetKad2;r.visibility_probe_started=false;r.visibility_probe_at=r.visibility_probe_deadline=0;}return true;}
bool LiveTunnelSourcePublisher::MarkNativeResult(std::uint64_t id,kad6::K6StoreStatus status,std::uint8_t load,std::uint64_t epoch,std::uint64_t now,bool& overload){overload=false;std::lock_guard<std::mutex> g(m_mutex);auto it=m_k6Publishes.find(id);if(it==m_k6Publishes.end()||!it->second.refresh_enabled)return false;auto& r=it->second;if(status==kad6::K6StoreStatus::Stored&&epoch>=r.request.record_epoch){if(r.status!=kad6::K6PublishStatus::VerifiedVisible)r.status=kad6::K6PublishStatus::RemoteAck;r.published_networks|=kad6::kK6PublishNetKad6;if(r.replicas!=0xffff)++r.replicas;r.max_load=(std::max)(r.max_load,load);}else if(status==kad6::K6StoreStatus::Overloaded){overload=true;if(r.auto_refresh){r.next_native_refresh_at=now+r.native_backoff_s;r.native_backoff_s=(std::min)(r.native_backoff_s*2u,15u*60u);}if(r.published_networks)r.status=kad6::K6PublishStatus::Partial;}return true;}
std::vector<LiveTunnelPublishRuntime> LiveTunnelSourcePublisher::TakeNativeRefreshes(std::uint64_t now){std::vector<LiveTunnelPublishRuntime> due;std::lock_guard<std::mutex> g(m_mutex);for(auto& pair:m_k6Publishes){auto& r=pair.second;if(r.refresh_enabled&&r.auto_refresh&&r.next_native_refresh_at&&r.next_native_refresh_at<=now&&r.expires_at>now+kad6::kK6PublishMinTtlSeconds&&r.request.record_kind==kad6::K6RecordKind::Kad6SourceDescriptor&&(r.request.network_mask&kad6::kK6PublishNetKad6)){r.next_native_refresh_at=now+r.native_backoff_s;due.push_back(r);}}return due;}
bool LiveTunnelSourcePublisher::CompleteNativeRefresh(std::uint64_t id,bool sent,std::uint64_t now){std::lock_guard<std::mutex> g(m_mutex);auto it=m_k6Publishes.find(id);if(it==m_k6Publishes.end()||!it->second.refresh_enabled)return false;auto& r=it->second;if(sent){const std::uint64_t left=r.expires_at>now?r.expires_at-now:0;r.next_native_refresh_at=now+(std::max<std::uint64_t>)(kad6::kK6PublishMinTtlSeconds,left/2);r.native_backoff_s=60;r.published_networks|=kad6::kK6PublishNetKad6;if(r.status==kad6::K6PublishStatus::Queued)r.status=kad6::K6PublishStatus::Sent;}else{r.next_native_refresh_at=now+r.native_backoff_s;r.native_backoff_s=(std::min)(r.native_backoff_s*2u,15u*60u);}return true;}
bool LiveTunnelSourcePublisher::TakeShadow(std::uint64_t id,LiveTunnelPublishRuntime& r){std::lock_guard<std::mutex> g(m_mutex);auto it=m_k6Publishes.find(id);if(it==m_k6Publishes.end())return false;it->second.kad2_queued=false;r=it->second;return true;}
bool LiveTunnelSourcePublisher::CompleteShadow(std::uint64_t id,bool started,std::uint64_t now){std::lock_guard<std::mutex> g(m_mutex);auto p=m_k6Publishes.find(id);if(p==m_k6Publishes.end()||!p->second.refresh_enabled)return false;const std::uint64_t left=p->second.expires_at>now?p->second.expires_at-now:0,delay=started?(std::max<std::uint64_t>)(kad6::kK6PublishMinTtlSeconds,left/2):(std::min<std::uint32_t>)(p->second.refresh_backoff_s,15u*60u);for(auto& pair:m_k6Publishes)if(pair.second.refresh_enabled&&pair.second.primary_publish_lease_id==id){auto& r=pair.second;r.kad2_search_active=started;r.next_refresh_at=now+delay;if(started)r.refresh_backoff_s=60;else{r.refresh_backoff_s=(std::min<std::uint32_t>)(static_cast<std::uint32_t>(delay)*2u,15u*60u);if(r.published_networks)r.status=kad6::K6PublishStatus::Partial;}}return true;}
std::vector<LiveTunnelPublishRuntime> LiveTunnelSourcePublisher::TakeVisibilityProbes(std::uint64_t now,bool& overload){overload=false;std::vector<LiveTunnelPublishRuntime> due;std::lock_guard<std::mutex> g(m_mutex);for(auto& pair:m_k6Publishes){auto& r=pair.second;if(r.primary_publish_lease_id!=r.publish_lease_id||!r.refresh_enabled||r.expires_at<=now||(r.published_networks&kad6::kK6PublishNetKad2)==0||r.status==kad6::K6PublishStatus::VerifiedVisible)continue;if(r.visibility_probe_started){if(r.visibility_probe_deadline>now)continue;r.visibility_probe_started=false;r.visibility_probe_at=now+60;overload=true;}if(r.visibility_probe_at&&r.visibility_probe_at<=now){r.visibility_probe_started=true;r.visibility_probe_deadline=now+50;due.push_back(r);}}return due;}
bool LiveTunnelSourcePublisher::CompleteVisibilityProbe(std::uint64_t id,bool started,std::uint64_t now){std::lock_guard<std::mutex> g(m_mutex);auto it=m_k6Publishes.find(id);if(it==m_k6Publishes.end()||!it->second.refresh_enabled)return false;auto& r=it->second;r.visibility_probe_started=started;r.visibility_probe_deadline=started?now+50:0;if(!started)r.visibility_probe_at=now+15;return true;}
void LiveTunnelSourcePublisher::ResetPublishes(){std::lock_guard<std::mutex> g(m_mutex);m_k6Publishes.clear();m_k6ShadowPrimary.clear();}

void LiveTunnelSourcePublisher::PruneTicketState(std::uint64_t now)
{
    std::lock_guard<std::mutex> guard(m_mutex);
    for (auto target = m_k6AuthorizedTargets.begin();
         target != m_k6AuthorizedTargets.end();) {
        if (target->second.expires_at <= now)
            target = m_k6AuthorizedTargets.erase(target);
        else
            ++target;
    }
    for (auto ticket = m_k6UsedTickets.begin();
         ticket != m_k6UsedTickets.end();) {
        if (ticket->second.expires_at <= now)
            ticket = m_k6UsedTickets.erase(ticket);
        else
            ++ticket;
    }
}

std::size_t LiveTunnelSourcePublisher::PublishCount() const noexcept
{
    std::lock_guard<std::mutex> guard(m_mutex);
    return m_k6Publishes.size();
}

std::map<std::uint64_t, LiveTunnelPublishRuntime>
LiveTunnelSourcePublisher::PublishSnapshot() const
{
    std::lock_guard<std::mutex> guard(m_mutex);
    return m_k6Publishes;
}

bool LiveTunnelSourcePublisher::FindPublish(
    std::uint64_t publishLeaseId,
    LiveTunnelPublishRuntime& runtime) const
{
    std::lock_guard<std::mutex> guard(m_mutex);
    const auto found = m_k6Publishes.find(publishLeaseId);
    if (found == m_k6Publishes.end())
        return false;
    runtime = found->second;
    return true;
}







std::map<std::string, std::uint64_t>
LiveTunnelSourcePublisher::ShadowSnapshot() const
{
    std::lock_guard<std::mutex> guard(m_mutex);
    return m_k6ShadowPrimary;
}


M2AModuleHandle M2A_BIND_LT4_6E698BD4A3(const M2AParentPort& parent){return MakeM2AModuleHandle(new LiveTunnelSourcePublisher(parent));}
LiveTunnelSourcePublisher* ResolveLiveTunnelSourcePublisher(M2AModuleHandle& h) noexcept{return static_cast<LiveTunnelSourcePublisher*>(h.Get());}
const LiveTunnelSourcePublisher* ResolveLiveTunnelSourcePublisher(const M2AModuleHandle& h) noexcept{return static_cast<const LiveTunnelSourcePublisher*>(h.Get());}
bool M2A_LT4_InitializeSecretBridge(M2AModuleHandle& h,const std::array<std::uint8_t,32>& v) noexcept{auto* o=ResolveLiveTunnelSourcePublisher(h);return o&&o->InitializeTicketSecret(v);}
bool M2A_LT4_TicketSecretReadyBridge(const M2AModuleHandle& h) noexcept{auto* o=ResolveLiveTunnelSourcePublisher(h);return o&&o->TicketSecretReady();}
std::array<std::uint8_t,32> M2A_LT4_TicketSecretBridge(const M2AModuleHandle& h) noexcept{auto* o=ResolveLiveTunnelSourcePublisher(h);return o?o->TicketSecretSnapshot():std::array<std::uint8_t,32>{};}
void M2A_LT4_AuthorizeTargetBridge(M2AModuleHandle& h,const std::string& k,const LiveTunnelAuthorizedTarget& v){auto* o=ResolveLiveTunnelSourcePublisher(h);if(o)o->AuthorizeTarget(k,v);}
bool M2A_LT4_FindAuthorizedTargetBridge(const M2AModuleHandle& h,const std::string& k,std::uint64_t n,LiveTunnelAuthorizedTarget& v){auto* o=ResolveLiveTunnelSourcePublisher(h);return o&&o->FindAuthorizedTarget(k,n,v);}
bool M2A_LT4_ConsumeTicketBridge(M2AModuleHandle& h,const kad6::K6TargetTicket& t,std::uint64_t n) noexcept{auto* o=ResolveLiveTunnelSourcePublisher(h);return o&&o->ConsumeTicket(t,n);}
std::map<std::uint64_t,LiveTunnelPublishRuntime> M2A_LT4_PublishSnapshotBridge(const M2AModuleHandle& h){auto* o=ResolveLiveTunnelSourcePublisher(h);return o?o->PublishSnapshot():std::map<std::uint64_t,LiveTunnelPublishRuntime>{};}
std::size_t M2A_LT4_PublishCountBridge(const M2AModuleHandle& h) noexcept{auto* o=ResolveLiveTunnelSourcePublisher(h);return o?o->PublishCount():0;}
bool M2A_LT4_FindPublishBridge(const M2AModuleHandle& h,std::uint64_t id,LiveTunnelPublishRuntime& v){auto* o=ResolveLiveTunnelSourcePublisher(h);return o&&o->FindPublish(id,v);}
std::map<std::string,std::uint64_t> M2A_LT4_ShadowSnapshotBridge(const M2AModuleHandle& h){auto* o=ResolveLiveTunnelSourcePublisher(h);return o?o->ShadowSnapshot():std::map<std::string,std::uint64_t>{};}
LiveTunnelPublishMutation M2A_LT4_OpenPublishBridge(M2AModuleHandle& h,LiveTunnelPublishRuntime& r,const std::string& k,LiveTunnelPublishRuntime& d,bool& e){auto* o=ResolveLiveTunnelSourcePublisher(h);return o?o->OpenPublish(r,k,d,e):LiveTunnelPublishMutation::CapacityRejected;} LiveTunnelPublishMutation M2A_LT4_RemovePublishBridge(M2AModuleHandle& h,std::uint64_t id,std::vector<LiveTunnelPublishAction>& a){auto* o=ResolveLiveTunnelSourcePublisher(h);return o?o->Unpublish(id,a):LiveTunnelPublishMutation::DuplicateUnpublish;}
bool M2A_LT4_DisablePublishBridge(M2AModuleHandle& h,std::uint64_t id){auto* o=ResolveLiveTunnelSourcePublisher(h);return o&&o->DisablePublish(id);} std::vector<std::uint64_t> M2A_LT4_DisableSourceBridge(M2AModuleHandle& h,std::uint64_t id){auto* o=ResolveLiveTunnelSourcePublisher(h);return o?o->DisableSource(id):std::vector<std::uint64_t>{};} std::vector<std::uint64_t> M2A_LT4_DisableAllBridge(M2AModuleHandle& h,bool c){auto* o=ResolveLiveTunnelSourcePublisher(h);return o?o->DisableAll(c):std::vector<std::uint64_t>{};}
bool M2A_LT4_EnsureShadowBridge(M2AModuleHandle& h,const std::string& k,std::uint64_t id,std::uint64_t& p,bool& c){auto* o=ResolveLiveTunnelSourcePublisher(h);return o&&o->EnsureShadow(k,id,p,c);} bool M2A_LT4_ForgetShadowBridge(M2AModuleHandle& h,const std::string& k){auto* o=ResolveLiveTunnelSourcePublisher(h);return o&&o->ForgetShadow(k);} bool M2A_LT4_SetQueueStateBridge(M2AModuleHandle& h,std::uint64_t id,bool q,std::uint64_t p,std::uint64_t n){auto* o=ResolveLiveTunnelSourcePublisher(h);return o&&o->SetQueueState(id,q,p,n);}
bool M2A_LT4_MarkNativeSentBridge(M2AModuleHandle& h,std::uint64_t id,std::uint64_t n,std::uint64_t t,std::uint64_t& s){auto* o=ResolveLiveTunnelSourcePublisher(h);return o&&o->MarkNativeSent(id,n,t,s);} std::vector<std::uint64_t> M2A_LT4_MarkShadowSentBridge(M2AModuleHandle& h,std::uint64_t id){auto* o=ResolveLiveTunnelSourcePublisher(h);return o?o->MarkShadowSent(id):std::vector<std::uint64_t>{};} bool M2A_LT4_MarkShadowAckBridge(M2AModuleHandle& h,std::uint64_t id,std::uint8_t l,std::uint64_t n){auto* o=ResolveLiveTunnelSourcePublisher(h);return o&&o->MarkShadowAckFamily(id,l,n);} bool M2A_LT4_MarkShadowVerifiedBridge(M2AModuleHandle& h,std::uint64_t id){auto* o=ResolveLiveTunnelSourcePublisher(h);return o&&o->MarkShadowVerifiedFamily(id);} bool M2A_LT4_MarkNativeResultBridge(M2AModuleHandle& h,std::uint64_t id,kad6::K6StoreStatus s,std::uint8_t l,std::uint64_t e,std::uint64_t n,bool& v){auto* o=ResolveLiveTunnelSourcePublisher(h);return o&&o->MarkNativeResult(id,s,l,e,n,v);}
std::vector<LiveTunnelPublishRuntime> M2A_LT4_TakeNativeRefreshesBridge(M2AModuleHandle& h,std::uint64_t n){auto* o=ResolveLiveTunnelSourcePublisher(h);return o?o->TakeNativeRefreshes(n):std::vector<LiveTunnelPublishRuntime>{};} bool M2A_LT4_CompleteNativeRefreshBridge(M2AModuleHandle& h,std::uint64_t id,bool s,std::uint64_t n){auto* o=ResolveLiveTunnelSourcePublisher(h);return o&&o->CompleteNativeRefresh(id,s,n);} bool M2A_LT4_TakeShadowBridge(M2AModuleHandle& h,std::uint64_t id,LiveTunnelPublishRuntime& r){auto* o=ResolveLiveTunnelSourcePublisher(h);return o&&o->TakeShadow(id,r);} bool M2A_LT4_CompleteShadowBridge(M2AModuleHandle& h,std::uint64_t id,bool s,std::uint64_t n){auto* o=ResolveLiveTunnelSourcePublisher(h);return o&&o->CompleteShadow(id,s,n);}
std::vector<LiveTunnelPublishRuntime> M2A_LT4_TakeVisibilityProbesBridge(M2AModuleHandle& h,std::uint64_t n,bool& v){auto* o=ResolveLiveTunnelSourcePublisher(h);return o?o->TakeVisibilityProbes(n,v):std::vector<LiveTunnelPublishRuntime>{};} bool M2A_LT4_CompleteVisibilityProbeBridge(M2AModuleHandle& h,std::uint64_t id,bool s,std::uint64_t n){auto* o=ResolveLiveTunnelSourcePublisher(h);return o&&o->CompleteVisibilityProbe(id,s,n);} std::vector<LiveTunnelPublishAction> M2A_LT4_SweepBridge(M2AModuleHandle& h,std::uint64_t n){auto* o=ResolveLiveTunnelSourcePublisher(h);return o?o->Sweep(n):std::vector<LiveTunnelPublishAction>{};} void M2A_LT4_ResetPublishesBridge(M2AModuleHandle& h){auto* o=ResolveLiveTunnelSourcePublisher(h);if(o)o->ResetPublishes();}
void M2A_LT4_PruneTicketStateBridge(M2AModuleHandle& h,std::uint64_t n){auto* o=ResolveLiveTunnelSourcePublisher(h);if(o)o->PruneTicketState(n);}

bool RunLiveTunnelSourcePublisherCharacterizationSelfTest()
{
    int parent = 0;
    LiveTunnelSourcePublisher publisher(M2AParentPort{&parent});
    std::array<std::uint8_t, 32> secret{};
    secret[0] = 1;
    if (!publisher.InitializeTicketSecret(secret) ||
        !publisher.TicketSecretReady())
        return false;

    LiveTunnelPublishRuntime runtime;
    runtime.publish_lease_id = 7;
    runtime.source_lease_id = 11;
    runtime.expires_at = 200;
    runtime.request.record_epoch = 1;
    runtime.request.network_mask = kad6::kK6PublishNetKad2;
    runtime.request.record.push_back(3);
    const bool SingleShadowPrimary =
        publisher.PreparePublish(runtime, "same") ==
        LiveTunnelPublishMutation::Created;
    LiveTunnelPublishRuntime duplicate = runtime;
    duplicate.publish_lease_id = 8;
    const bool DuplicatePublish =
        publisher.PreparePublish(duplicate, "same") ==
        LiveTunnelPublishMutation::DuplicatePublish;

    std::vector<LiveTunnelPublishAction> actions;
    const bool DuplicateUnpublish =
        publisher.Unpublish(7, actions) ==
            LiveTunnelPublishMutation::Updated &&
        publisher.Unpublish(7, actions) ==
            LiveTunnelPublishMutation::DuplicateUnpublish;
    const bool LateAckIgnored =
        publisher.RecordNativeAck(
            7, kad6::K6PublishStatus::RemoteAck) ==
        LiveTunnelPublishMutation::LateAckIgnored;

    LiveTunnelPublishRuntime flow; flow.publish_lease_id=20; flow.source_lease_id=21;
    flow.expires_at=1000; flow.primary_publish_lease_id=20; flow.auto_refresh=true;
    flow.next_native_refresh_at=100; flow.request.record_epoch=2;
    flow.request.record_kind=kad6::K6RecordKind::Kad6SourceDescriptor; flow.request.network_mask=kad6::kK6PublishNetKad2|kad6::kK6PublishNetKad6;
    flow.request.record.push_back(4);
    LiveTunnelPublishRuntime replay; bool exterior=false;
    const bool ProductiveOpen=publisher.OpenPublish(flow,"flow",replay,exterior)==LiveTunnelPublishMutation::Created&&exterior;
    LiveTunnelPublishRuntime retry=flow; retry.publish_lease_id=22; const bool ProductiveReplay=publisher.OpenPublish(
        retry,"flow",replay,exterior)==LiveTunnelPublishMutation::DuplicatePublish
        &&replay.publish_lease_id==20;
    std::uint64_t source=0; const bool ShadowNativeTransitions=
        publisher.MarkNativeSent(20,100,600,source)&&source==21
        &&publisher.MarkShadowSent(20).size()==1
        &&publisher.MarkShadowAckFamily(20,42,100);
    const bool RefreshReservedBeforeIo=
        publisher.TakeNativeRefreshes(400).size()==1
        &&publisher.TakeNativeRefreshes(400).empty()
        &&publisher.CompleteNativeRefresh(20,false,400);
    bool probeOverload=false; const bool ProbeReservedBeforeIo=
        publisher.TakeVisibilityProbes(245,probeOverload).size()==1
        &&publisher.TakeVisibilityProbes(245,probeOverload).empty()
        &&publisher.CompleteVisibilityProbe(20,false,245);
    bool nativeOverload=false; const bool LateCallbackAfterDisable=publisher.MarkShadowVerifiedFamily(20)
        &&publisher.DisablePublish(20)
        &&!publisher.MarkNativeResult(20,kad6::K6StoreStatus::Stored,0,2,300,nativeOverload)
        &&!publisher.MarkNativeSent(20,300,600,source);

    kad6::K6TargetTicket ticket;
    ticket.service =
        static_cast<kad6::Byte>(kad6::K6TicketService::Ed2kTcp);
    ticket.lease_id = 9;
    ticket.issued_at = 100;
    ticket.expires_at = 120;
    ticket.max_connections = 1;
    ticket.max_bytes = 1024;
    ticket.target_endpoint.tcp_port = 4662;
    ticket.nonce[0] = 4;
    kad6::K6Endpoint deniedTarget = ticket.target_endpoint;
    deniedTarget.tcp_port = 22;
    const bool TicketSensitivePortRejected =
        !LiveTunnelTicketPolicy::AllowTarget(
            ticket.service, deniedTarget, 4662, 4711) &&
        LiveTunnelTicketPolicy::AllowTarget(
            ticket.service, ticket.target_endpoint, 4661, 4711);
    const bool TicketReplayRejected =
        publisher.ConsumeTicket(ticket, 101) &&
        !publisher.ConsumeTicket(ticket, 101);
    return SingleShadowPrimary && DuplicatePublish &&
        DuplicateUnpublish && LateAckIgnored &&
        ProductiveOpen && ProductiveReplay && ShadowNativeTransitions &&
        RefreshReservedBeforeIo && ProbeReservedBeforeIo &&
        LateCallbackAfterDisable &&
        TicketSensitivePortRejected && TicketReplayRejected;
}

} // namespace eSELive
