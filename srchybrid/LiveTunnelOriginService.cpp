// this file is part of eMule eSE - LT6 origin state owner
#include "stdafx.h"
#include "LiveTunnelOriginService.h"
#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <limits>
#include <thread>
namespace eSELive { M2AModuleHandle M2A_BIND_LT6_6F855B99C0(const M2AParentPort&);bool M2A_LT6_SubmitWorkerBridge(M2AModuleHandle&,uint64_t,LiveTunnelOriginWorkerTask);void M2A_LT6_CancelWorkerBridge(M2AModuleHandle&)noexcept;void M2A_LT6_JoinWorkerBridge(M2AModuleHandle&)noexcept;
LiveTunnelOriginService::LiveTunnelOriginService(const M2AParentPort&)
    :m_m2a_binding_6f855b99c0(M2AAssignmentPolicy::RetainExisting){
    m_m2a_binding_6f855b99c0=M2A_BIND_LT6_6F855B99C0(M2AParentPort{this});}
LiveTunnelOriginService::~LiveTunnelOriginService()noexcept{Cancel();Join();}
bool LiveTunnelOriginService::AddSourceLookup(uint32_t id,const LiveTunnelOriginSourceLookup& v){
    if(!id)return false;std::lock_guard<std::mutex> l(m_mutex);return m_k6OriginSourceLookups.emplace(id,v).second;}
bool LiveTunnelOriginService::BindSourceLookup(uint32_t id,uint32_t circuit,LiveTunnelOriginSourceLookup& v){
    std::lock_guard<std::mutex> l(m_mutex);auto i=m_k6OriginSourceLookups.find(id);
    if(i==m_k6OriginSourceLookups.end()||(i->second.circuit_id&&i->second.circuit_id!=circuit))return false;
    i->second.circuit_id=circuit;v=i->second;return true;}
bool LiveTunnelOriginService::NoteSourceLookupResult(uint32_t id){
    std::lock_guard<std::mutex> l(m_mutex);auto i=m_k6OriginSourceLookups.find(id);
    if(i==m_k6OriginSourceLookups.end())return false;
    if(i->second.received!=(std::numeric_limits<uint16_t>::max)())++i->second.received;return true;}
bool LiveTunnelOriginService::TakeSourceLookup(uint32_t id,uint32_t circuit,LiveTunnelOriginSourceLookup& v){
    std::lock_guard<std::mutex> l(m_mutex);auto i=m_k6OriginSourceLookups.find(id);
    if(i==m_k6OriginSourceLookups.end()||(i->second.circuit_id&&i->second.circuit_id!=circuit))return false;
    v=i->second;m_k6OriginSourceLookups.erase(i);return true;}
bool LiveTunnelOriginService::AddDownloadActivation(uint32_t id,const LiveTunnelOriginDownloadActivation& v){
    if(!id||!v.client_token)return false;std::lock_guard<std::mutex> l(m_mutex);
    return m_k6DownloadActivations.emplace(id,v).second;}
bool LiveTunnelOriginService::TakeDownloadActivation(uint32_t id,uint32_t circuit,LiveTunnelOriginDownloadActivation& v){
    std::lock_guard<std::mutex> l(m_mutex);auto i=m_k6DownloadActivations.find(id);
    if(i==m_k6DownloadActivations.end()||i->second.circuit_id!=circuit)return false;
    v=i->second;m_k6DownloadActivations.erase(i);return true;}
bool LiveTunnelOriginService::RemoveDownloadActivation(uint32_t id,LiveTunnelOriginDownloadActivation* v){
    std::lock_guard<std::mutex> l(m_mutex);auto i=m_k6DownloadActivations.find(id);
    if(i==m_k6DownloadActivations.end())return false;if(v)*v=i->second;m_k6DownloadActivations.erase(i);return true;}
void LiveTunnelOriginService::RemoveDownloadActivationsByClient(uintptr_t client){
    std::lock_guard<std::mutex> l(m_mutex);
    for(auto i=m_k6DownloadActivations.begin();i!=m_k6DownloadActivations.end();)
        if(i->second.client_token==client)i=m_k6DownloadActivations.erase(i);else ++i;}
void LiveTunnelOriginService::AddSourceRoute(uint64_t lease,uint32_t circuit){
    std::lock_guard<std::mutex> l(m_mutex);m_k6OriginSourceLeaseRoutes[lease]=circuit;}
bool LiveTunnelOriginService::FindSourceRoute(uint64_t lease,uint32_t& circuit)const{
    std::lock_guard<std::mutex> l(m_mutex);auto i=m_k6OriginSourceLeaseRoutes.find(lease);
    if(i==m_k6OriginSourceLeaseRoutes.end())return false;circuit=i->second;return true;}
bool LiveTunnelOriginService::TakeSourceRoute(uint64_t lease,uint32_t& circuit){
    std::lock_guard<std::mutex> l(m_mutex);auto i=m_k6OriginSourceLeaseRoutes.find(lease);
    if(i==m_k6OriginSourceLeaseRoutes.end())return false;circuit=i->second;m_k6OriginSourceLeaseRoutes.erase(i);return true;}
void LiveTunnelOriginService::AddPublishRoute(uint64_t lease,uint32_t circuit){
    std::lock_guard<std::mutex> l(m_mutex);m_k6OriginPublishLeaseRoutes[lease]=circuit;}
bool LiveTunnelOriginService::TakePublishRoute(uint64_t lease,uint32_t& circuit){
    std::lock_guard<std::mutex> l(m_mutex);auto i=m_k6OriginPublishLeaseRoutes.find(lease);
    if(i==m_k6OriginPublishLeaseRoutes.end())return false;circuit=i->second;m_k6OriginPublishLeaseRoutes.erase(i);return true;}
LiveTunnelOriginAdvertiseReservation LiveTunnelOriginService::ReserveAdvertise(
    const std::string& key,uint64_t now,uint64_t minimumEpoch){
    LiveTunnelOriginAdvertiseReservation r;std::lock_guard<std::mutex> l(m_mutex);
    AdvertiseState& s=m_k6OriginAdvertisements[key];if(s.in_flight||s.next_attempt>now)return r;
    size_t workers=0;for(const auto& item:m_k6OriginAdvertisements)if(item.second.in_flight)++workers;
    if(workers>=2)return r;if(m_k6OriginSourceEpoch<minimumEpoch)m_k6OriginSourceEpoch=minimumEpoch;
    if(m_k6OriginSourceEpoch==(std::numeric_limits<uint64_t>::max)())return r;
    s.in_flight=true;if(++s.generation==0)++s.generation;r.accepted=true;r.generation=s.generation;r.epoch=++m_k6OriginSourceEpoch;
    r.previous_source_lease_id=s.source_lease_id;r.previous_publish_lease_id=s.publish_lease_id;return r;}
bool LiveTunnelOriginService::FinishAdvertise(const std::string& key,uint64_t generation,bool success,
    uint64_t sourceLease,uint64_t publishLease,uint32_t refresh,uint64_t now){
    std::lock_guard<std::mutex> l(m_mutex);auto i=m_k6OriginAdvertisements.find(key);
    if(i==m_k6OriginAdvertisements.end()||!i->second.in_flight||i->second.generation!=generation)return false;
    AdvertiseState& s=i->second;s.in_flight=false;
    if(success){s.source_lease_id=sourceLease;s.publish_lease_id=publishLease;s.next_attempt=now+std::max<uint32_t>(refresh,60);}
    else s.next_attempt=now+60;return true;}
bool LiveTunnelOriginService::SubmitAdvertise(uint64_t generation,LiveTunnelOriginWorkerTask task){
    return M2A_LT6_SubmitWorkerBridge(m_m2a_binding_6f855b99c0,generation,std::move(task));}
void LiveTunnelOriginService::AddTargetRoute(const std::string& key,const LiveTunnelOriginTargetRoute& v){
    std::lock_guard<std::mutex> l(m_mutex);m_k6OriginTargetRoutes[key]=v;}
bool LiveTunnelOriginService::FindTargetRoute(const std::string& key,uint64_t now,LiveTunnelOriginTargetRoute& v)const{
    std::lock_guard<std::mutex> l(m_mutex);auto i=m_k6OriginTargetRoutes.find(key);
    if(i==m_k6OriginTargetRoutes.end()||i->second.expires_at<=now)return false;v=i->second;return true;}
void LiveTunnelOriginService::AddLiveRoute(const std::string& key,const LiveTunnelOriginTargetRoute& v){
    std::lock_guard<std::mutex> l(m_mutex);m_k6OriginLiveRoutes[key]=v;}
bool LiveTunnelOriginService::FindLiveRoute(const std::string& key,uint64_t now,LiveTunnelOriginTargetRoute& v)const{
    std::lock_guard<std::mutex> l(m_mutex);auto i=m_k6OriginLiveRoutes.find(key);
    if(i==m_k6OriginLiveRoutes.end()||i->second.expires_at<=now)return false;v=i->second;return true;}
LiveTunnelOriginSweepResult LiveTunnelOriginService::Sweep(
    uint64_t now,uint32_t tick,const std::set<uint32_t>& active){
    LiveTunnelOriginSweepResult r;std::lock_guard<std::mutex> l(m_mutex);
    if(m_lastSweepSecond==now){r.timer_coalesced=true;return r;} // TimerCoalesced
    m_lastSweepSecond=now;const auto expired=[&](const LiveTunnelOriginTargetRoute& v){
        return v.expires_at<=now||active.find(v.circuit_id)==active.end();};
    for(auto i=m_k6OriginTargetRoutes.begin();i!=m_k6OriginTargetRoutes.end();)
        if(expired(i->second))i=m_k6OriginTargetRoutes.erase(i);else ++i;
    for(auto i=m_k6OriginLiveRoutes.begin();i!=m_k6OriginLiveRoutes.end();)
        if(expired(i->second))i=m_k6OriginLiveRoutes.erase(i);else ++i;
    std::set<uint64_t> lost;
    for(auto i=m_k6OriginSourceLeaseRoutes.begin();i!=m_k6OriginSourceLeaseRoutes.end();)
        if(active.find(i->second)==active.end()){lost.insert(i->first);
            r.actions.push_back({LiveTunnelOriginActionKind::LeaseRouteRemoved,0,0,i->first}); // LeaseRouteRemoved
            i=m_k6OriginSourceLeaseRoutes.erase(i);}else ++i;
    for(auto i=m_k6OriginPublishLeaseRoutes.begin();i!=m_k6OriginPublishLeaseRoutes.end();)
        if(active.find(i->second)==active.end())i=m_k6OriginPublishLeaseRoutes.erase(i);else ++i;
    for(auto& item:m_k6OriginAdvertisements)if(lost.find(item.second.source_lease_id)!=lost.end()){
        item.second.source_lease_id=0;item.second.publish_lease_id=0;item.second.next_attempt=0;
        r.actions.push_back({LiveTunnelOriginActionKind::AdvertiseRollback,0,0,0});} // AdvertiseRollback
    for(auto i=m_k6OriginSourceLookups.begin();i!=m_k6OriginSourceLookups.end();){
        const bool timeout=static_cast<int32_t>(tick-i->second.deadline_tick)>=0;
        const bool lostCircuit=i->second.circuit_id&&active.find(i->second.circuit_id)==active.end();
        if(!timeout&&!lostCircuit){++i;continue;}r.actions.push_back(
            {LiveTunnelOriginActionKind::SourceLookupExpired,i->first,0,0});i=m_k6OriginSourceLookups.erase(i);}
    for(auto i=m_k6DownloadActivations.begin();i!=m_k6DownloadActivations.end();){
        const bool timeout=static_cast<int32_t>(tick-i->second.deadline_tick)>=0;
        const bool lostCircuit=active.find(i->second.circuit_id)==active.end();
        if(!timeout&&!lostCircuit){++i;continue;}r.actions.push_back(
            {LiveTunnelOriginActionKind::DownloadActivationExpired,i->first,i->second.client_token,0});
        i=m_k6DownloadActivations.erase(i);}return r;}
void LiveTunnelOriginService::Cancel()noexcept{
    M2A_LT6_CancelWorkerBridge(m_m2a_binding_6f855b99c0);} // WorkerCanceled
void LiveTunnelOriginService::Join()noexcept{
    M2A_LT6_JoinWorkerBridge(m_m2a_binding_6f855b99c0);}
M2AModuleHandle M2A_BIND_LT6_8E07B736A1(const M2AParentPort& parent){
    return MakeM2AModuleHandle(new LiveTunnelOriginService(parent));}
LiveTunnelOriginService* ResolveLiveTunnelOriginService(M2AModuleHandle& h)noexcept{
    return static_cast<LiveTunnelOriginService*>(h.Get());}
const LiveTunnelOriginService* ResolveLiveTunnelOriginService(const M2AModuleHandle& h)noexcept{
    return static_cast<const LiveTunnelOriginService*>(h.Get());}
bool M2A_LT6_OperateBridge(const M2AModuleHandle& h,LiveTunnelOriginOperation op,
    void* a,void* b,void* c,void* d,void*,void*){
    auto* o=const_cast<LiveTunnelOriginService*>(ResolveLiveTunnelOriginService(h));if(!o)return false;
    switch(op){
    case LiveTunnelOriginOperation::AddSourceLookup:return o->AddSourceLookup(*static_cast<uint32_t*>(a),*static_cast<LiveTunnelOriginSourceLookup*>(b));
    case LiveTunnelOriginOperation::BindSourceLookup:return o->BindSourceLookup(*static_cast<uint32_t*>(a),*static_cast<uint32_t*>(b),*static_cast<LiveTunnelOriginSourceLookup*>(c));
    case LiveTunnelOriginOperation::NoteSourceLookupResult:return o->NoteSourceLookupResult(*static_cast<uint32_t*>(a));
    case LiveTunnelOriginOperation::TakeSourceLookup:return o->TakeSourceLookup(*static_cast<uint32_t*>(a),*static_cast<uint32_t*>(b),*static_cast<LiveTunnelOriginSourceLookup*>(c));
    case LiveTunnelOriginOperation::AddDownloadActivation:return o->AddDownloadActivation(*static_cast<uint32_t*>(a),*static_cast<LiveTunnelOriginDownloadActivation*>(b));
    case LiveTunnelOriginOperation::TakeDownloadActivation:return o->TakeDownloadActivation(*static_cast<uint32_t*>(a),*static_cast<uint32_t*>(b),*static_cast<LiveTunnelOriginDownloadActivation*>(c));
    case LiveTunnelOriginOperation::RemoveDownloadActivation:return o->RemoveDownloadActivation(*static_cast<uint32_t*>(a),static_cast<LiveTunnelOriginDownloadActivation*>(b));
    case LiveTunnelOriginOperation::RemoveDownloadActivationsByClient:o->RemoveDownloadActivationsByClient(*static_cast<uintptr_t*>(a));return true;
    case LiveTunnelOriginOperation::AddSourceRoute:o->AddSourceRoute(*static_cast<uint64_t*>(a),*static_cast<uint32_t*>(b));return true;
    case LiveTunnelOriginOperation::FindSourceRoute:return o->FindSourceRoute(*static_cast<uint64_t*>(a),*static_cast<uint32_t*>(b));
    case LiveTunnelOriginOperation::TakeSourceRoute:return o->TakeSourceRoute(*static_cast<uint64_t*>(a),*static_cast<uint32_t*>(b));
    case LiveTunnelOriginOperation::AddPublishRoute:o->AddPublishRoute(*static_cast<uint64_t*>(a),*static_cast<uint32_t*>(b));return true;
    case LiveTunnelOriginOperation::TakePublishRoute:return o->TakePublishRoute(*static_cast<uint64_t*>(a),*static_cast<uint32_t*>(b));
    case LiveTunnelOriginOperation::ReserveAdvertise:*static_cast<LiveTunnelOriginAdvertiseReservation*>(d)=o->ReserveAdvertise(*static_cast<std::string*>(a),*static_cast<uint64_t*>(b),*static_cast<uint64_t*>(c));return true;
    case LiveTunnelOriginOperation::FinishAdvertise:{const auto& v=*static_cast<LiveTunnelOriginAdvertiseCompletion*>(c);return o->FinishAdvertise(*static_cast<std::string*>(a),*static_cast<uint64_t*>(b),v.success,v.source_lease_id,v.publish_lease_id,v.refresh_after,v.now);}
    case LiveTunnelOriginOperation::SubmitAdvertise:return o->SubmitAdvertise(*static_cast<uint64_t*>(a),std::move(*static_cast<LiveTunnelOriginWorkerTask*>(b)));
    case LiveTunnelOriginOperation::AddTargetRoute:o->AddTargetRoute(*static_cast<std::string*>(a),*static_cast<LiveTunnelOriginTargetRoute*>(b));return true;
    case LiveTunnelOriginOperation::FindTargetRoute:return o->FindTargetRoute(*static_cast<std::string*>(a),*static_cast<uint64_t*>(b),*static_cast<LiveTunnelOriginTargetRoute*>(c));
    case LiveTunnelOriginOperation::AddLiveRoute:o->AddLiveRoute(*static_cast<std::string*>(a),*static_cast<LiveTunnelOriginTargetRoute*>(b));return true;
    case LiveTunnelOriginOperation::FindLiveRoute:return o->FindLiveRoute(*static_cast<std::string*>(a),*static_cast<uint64_t*>(b),*static_cast<LiveTunnelOriginTargetRoute*>(c));
    case LiveTunnelOriginOperation::Sweep:*static_cast<LiveTunnelOriginSweepResult*>(d)=o->Sweep(*static_cast<uint64_t*>(a),*static_cast<uint32_t*>(b),*static_cast<std::set<uint32_t>*>(c));return true;
    case LiveTunnelOriginOperation::Cancel:o->Cancel();return true;case LiveTunnelOriginOperation::Join:o->Join();return true;}
    return false;}
bool RunLiveTunnelOriginServiceCharacterizationSelfTest(){
    int p=0;LiveTunnelOriginService s(M2AParentPort{&p});const std::set<uint32_t> active{7};
    LiveTunnelOriginSourceLookup lookup;lookup.circuit_id=7;lookup.deadline_tick=200;
    if(!s.AddSourceLookup(11,lookup))return false;const auto first=s.Sweep(1,100,active),again=s.Sweep(1,300,active);
    if(!first.actions.empty()||!again.timer_coalesced)return false; // TimerCoalesced
    LiveTunnelOriginSourceLookup taken;if(!s.TakeSourceLookup(11,7,taken))return false;
    const auto r=s.ReserveAdvertise("a",10,10);
    if(!r.accepted||s.FinishAdvertise("a",r.generation+1,false,0,0,0,10))return false; // StaleResultIgnored
    s.AddSourceRoute(99,8);const auto swept=s.Sweep(2,300,active);bool removed=false;
    for(const auto& action:swept.actions)removed|=action.kind==LiveTunnelOriginActionKind::LeaseRouteRemoved;
    std::mutex gate;std::condition_variable changed;unsigned running=0,completed=0;
    bool release=false,queuedRan=false,joinStarted=false,joined=false;
    const auto task=[&]{std::unique_lock<std::mutex> l(gate);++running;changed.notify_all();
        changed.wait(l,[&]{return release;});++completed;};
    if(!s.SubmitAdvertise(1,task)||!s.SubmitAdvertise(2,task)){s.Cancel();s.Join();return false;}
    {std::unique_lock<std::mutex> l(gate);if(!changed.wait_for(l,std::chrono::seconds(2),[&]{return running==2;})){
        release=true;l.unlock();changed.notify_all();s.Cancel();s.Join();return false;}}
    if(!s.SubmitAdvertise(3,[&]{std::lock_guard<std::mutex> l(gate);queuedRan=true;})){
        {std::lock_guard<std::mutex> l(gate);release=true;}changed.notify_all();s.Cancel();s.Join();return false;}
    s.Cancel();std::thread joiner([&]{{std::lock_guard<std::mutex> l(gate);joinStarted=true;}changed.notify_all();
        s.Join();{std::lock_guard<std::mutex> l(gate);joined=true;}changed.notify_all();});
    bool joinedBeforeRelease=false;{std::unique_lock<std::mutex> l(gate);
        changed.wait(l,[&]{return joinStarted;});joinedBeforeRelease=joined;release=true;}
    changed.notify_all();joiner.join();{std::lock_guard<std::mutex> l(gate);
        return removed&&!joinedBeforeRelease&&joined&&!queuedRan&&completed==2;}}
    // WorkerCanceled, LeaseRouteRemoved, AdvertiseRollback
} // namespace eSELive
