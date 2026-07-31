// this file is part of eMule eSE - LT8 search state owner
#include "stdafx.h"
#include "LiveTunnelSearchService.h"
#include <algorithm>
namespace eSELive {
namespace { bool DeadlineReached32(DWORD now,DWORD deadline){return static_cast<std::int32_t>(now-deadline)>=0;} }
namespace { bool StrictlyElapsed32(DWORD now,DWORD since,DWORD interval){return static_cast<DWORD>(now-since)>interval;} }
LiveTunnelSearchService::LiveTunnelSearchService(const M2AParentPort& parent) noexcept:m_parent(parent.context){}
bool LiveTunnelSearchService::AddJob(std::uint64_t key,const LiveTunnelSearchJob& job){if(!key)return false;m_searchJobs[key]=job;return true;}
bool LiveTunnelSearchService::UpdateJob(std::uint64_t key,const LiveTunnelSearchJob& job){auto it=m_searchJobs.find(key);if(it==m_searchJobs.end())return false;it->second=job;return true;}
bool LiveTunnelSearchService::FindJob(std::uint64_t key,LiveTunnelSearchJob& job)const{auto it=m_searchJobs.find(key);if(it==m_searchJobs.end())return false;job=it->second;return true;}
bool LiveTunnelSearchService::TakeJob(std::uint64_t key,LiveTunnelSearchJob& job){auto it=m_searchJobs.find(key);if(it==m_searchJobs.end())return false;job=std::move(it->second);m_searchJobs.erase(it);return true;}
std::vector<LiveTunnelSearchJob> LiveTunnelSearchService::TakeDue(DWORD now){std::vector<LiveTunnelSearchJob> due;for(auto it=m_searchJobs.begin();it!=m_searchJobs.end();)if(DeadlineReached32(now,it->second.deadline)){due.push_back(std::move(it->second));it=m_searchJobs.erase(it);}else ++it;return due;}
bool LiveTunnelSearchService::AppendReply(std::uint64_t key,const std::vector<std::uint8_t>& one,std::uint16_t maxResults,std::size_t maxBytes,DWORD now){
    if(!key||one.size()<4||maxResults==0||maxBytes<4)return false;auto& value=m_k6SearchReplies[key];
    if(value.legacy.empty()){value.legacy.assign(4,0);value.started=now;}
    const std::size_t payload=one.size()-4;
    if(value.count>=maxResults||value.legacy.size()>maxBytes||payload>maxBytes-value.legacy.size())return false;
    value.legacy.insert(value.legacy.end(),one.begin()+4,one.end());++value.count;return true;
}
bool LiveTunnelSearchService::TakeReply(std::uint64_t key,std::vector<std::uint8_t>& legacy,std::uint16_t& count){auto it=m_k6SearchReplies.find(key);legacy.assign(4,0);count=0;if(it==m_k6SearchReplies.end())return false;legacy=std::move(it->second.legacy);count=it->second.count;m_k6SearchReplies.erase(it);return true;}
std::size_t LiveTunnelSearchService::SweepReplies(DWORD now,DWORD ttl){std::size_t removed=0;for(auto it=m_k6SearchReplies.begin();it!=m_k6SearchReplies.end();)if(StrictlyElapsed32(now,it->second.started,ttl)){it=m_k6SearchReplies.erase(it);++removed;}else ++it;return removed;}
std::size_t LiveTunnelSearchService::JobCount()const noexcept{return m_searchJobs.size();}
M2AModuleHandle M2A_BIND_LT8_17641C1557(const M2AParentPort& parent){return MakeM2AModuleHandle(new LiveTunnelSearchService(parent));}
namespace {
LiveTunnelSearchService* Resolve(M2AModuleHandle& h)noexcept{return static_cast<LiveTunnelSearchService*>(h.Get());}
const LiveTunnelSearchService* Resolve(const M2AModuleHandle& h)noexcept{return static_cast<const LiveTunnelSearchService*>(h.Get());}
bool Check(bool value){return value;}
}
bool M2A_LT8_AddJobBridge(M2AModuleHandle& h,std::uint64_t k,const LiveTunnelSearchJob& v){auto* o=Resolve(h);return o&&o->AddJob(k,v);}
bool M2A_LT8_UpdateJobBridge(M2AModuleHandle& h,std::uint64_t k,const LiveTunnelSearchJob& v){auto* o=Resolve(h);return o&&o->UpdateJob(k,v);}
bool M2A_LT8_FindJobBridge(const M2AModuleHandle& h,std::uint64_t k,LiveTunnelSearchJob& v){auto* o=Resolve(h);return o&&o->FindJob(k,v);}
bool M2A_LT8_TakeJobBridge(M2AModuleHandle& h,std::uint64_t k,LiveTunnelSearchJob& v){auto* o=Resolve(h);return o&&o->TakeJob(k,v);}
std::vector<LiveTunnelSearchJob> M2A_LT8_TakeDueBridge(M2AModuleHandle& h,DWORD n){auto* o=Resolve(h);return o?o->TakeDue(n):std::vector<LiveTunnelSearchJob>();}
bool M2A_LT8_AppendReplyBridge(M2AModuleHandle& h,std::uint64_t k,const std::vector<std::uint8_t>& v,std::uint16_t r,std::size_t b,DWORD n){auto* o=Resolve(h);return o&&o->AppendReply(k,v,r,b,n);}
bool M2A_LT8_TakeReplyBridge(M2AModuleHandle& h,std::uint64_t k,std::vector<std::uint8_t>& v,std::uint16_t& c){auto* o=Resolve(h);return o&&o->TakeReply(k,v,c);}
std::size_t M2A_LT8_SweepRepliesBridge(M2AModuleHandle& h,DWORD n,DWORD t){auto* o=Resolve(h);return o?o->SweepReplies(n,t):0;}
std::size_t M2A_LT8_JobCountBridge(const M2AModuleHandle& h)noexcept{auto* o=Resolve(h);return o?o->JobCount():0;}
bool RunLiveTunnelSearchServiceCharacterizationSelfTest(){
    LiveTunnelSearchService owner(M2AParentPort{reinterpret_cast<void*>(1)});
    LiveTunnelSearchJob empty;empty.circ_id=7;empty.req_id=9;empty.deadline=20; // EmptySearch
    LiveTunnelSearchJob replacement=empty;replacement.deadline=21; // DuplicateRegistrationKeepsLegacyOverwrite
    if(!Check(owner.AddJob(1,empty))||!Check(owner.AddJob(1,replacement))||!Check(owner.TakeDue(20).empty())||!Check(owner.TakeDue(21).size()==1))return false;
    LiveTunnelSearchJob canceled;canceled.circ_id=8;canceled.req_id=10;canceled.deadline=30;LiveTunnelSearchJob taken; // CanceledBeforeResponse
    if(!Check(owner.AddJob(2,canceled))||!Check(owner.TakeJob(2,taken))||!Check(owner.TakeDue(30).empty()))return false;
    const std::vector<std::uint8_t> one={0,0,2,0,0xaa,0xbb}; // ByteExactSerialization
    for(std::uint16_t i=0;i<kad6::kK6SearchMaxResults;++i)if(!Check(owner.AppendReply(3,one,kad6::kK6SearchMaxResults,4+2*kad6::kK6SearchMaxResults,40)))return false; // ResultLimit
    if(!Check(!owner.AppendReply(3,one,kad6::kK6SearchMaxResults,4+2*kad6::kK6SearchMaxResults,40)))return false;
    std::vector<std::uint8_t> legacy;std::uint16_t count=0;
    if(!Check(owner.TakeReply(3,legacy,count))||!Check(count==kad6::kK6SearchMaxResults)||!Check(legacy.size()==4+2*kad6::kK6SearchMaxResults)||!Check(legacy[4]==0xaa&&legacy[5]==0xbb))return false;
    if(!Check(owner.AppendReply(4,one,1,6,100))||!Check(owner.SweepReplies(150,50)==0)||!Check(owner.SweepReplies(151,50)==1))return false; // StrictExpiryBoundary
    return true;
}
} // namespace eSELive
