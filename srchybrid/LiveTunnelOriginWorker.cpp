// this file is part of eMule eSE - LT6 cancelable origin worker
#include "stdafx.h"
#include "LiveTunnelOriginWorker.h"
namespace eSELive{
LiveTunnelOriginWorker::LiveTunnelOriginWorker(const M2AParentPort&){
    for(auto& thread:m_threads)thread=std::thread(&LiveTunnelOriginWorker::Run,this);}

LiveTunnelOriginWorker::~LiveTunnelOriginWorker()noexcept{Cancel();Join();}
bool LiveTunnelOriginWorker::Submit(std::uint64_t generation,LiveTunnelOriginWorkerTask task){
    if(!task)return false;{std::lock_guard<std::mutex> lock(m_mutex);
    if(m_cancelled){++m_stale;return false;}m_work.push_back(Work{generation,m_generation,std::move(task)});}
    m_ready.notify_one();return true;}
void LiveTunnelOriginWorker::Cancel()noexcept{
    {std::lock_guard<std::mutex> lock(m_mutex);if(m_cancelled)return;m_cancelled=true;
    ++m_generation;m_stale+=m_work.size();m_work.clear();}m_ready.notify_all();}
void LiveTunnelOriginWorker::Join()noexcept{for(auto& thread:m_threads)if(thread.joinable())thread.join();}
std::uint64_t LiveTunnelOriginWorker::generation()const noexcept{
    std::lock_guard<std::mutex> lock(m_mutex);return m_generation;}
std::uint64_t LiveTunnelOriginWorker::stale()const noexcept{
    std::lock_guard<std::mutex> lock(m_mutex);return m_stale;}
void LiveTunnelOriginWorker::Run()noexcept{for(;;){Work work;{
    std::unique_lock<std::mutex> lock(m_mutex);m_ready.wait(lock,[this]{return m_cancelled||!m_work.empty();});
    if(m_cancelled)return;work=std::move(m_work.front());m_work.pop_front();
    if(work.cancel_generation!=m_generation){++m_stale;continue;}}
    try{work.task();}catch(...){/* Exceptions cannot escape or bypass deterministic shutdown. */}}}
M2AModuleHandle M2A_BIND_LT6_6F855B99C0(const M2AParentPort& parent){
    return MakeM2AModuleHandle(new LiveTunnelOriginWorker(parent));}
LiveTunnelOriginWorker* ResolveLiveTunnelOriginWorker(M2AModuleHandle& h)noexcept{
    return static_cast<LiveTunnelOriginWorker*>(h.Get());}
bool M2A_LT6_SubmitWorkerBridge(M2AModuleHandle& h,std::uint64_t g,LiveTunnelOriginWorkerTask task){
    auto* w=ResolveLiveTunnelOriginWorker(h);return w&&w->Submit(g,std::move(task));}
void M2A_LT6_CancelWorkerBridge(M2AModuleHandle& h)noexcept{auto* w=ResolveLiveTunnelOriginWorker(h);if(w)w->Cancel();}
void M2A_LT6_JoinWorkerBridge(M2AModuleHandle& h)noexcept{auto* w=ResolveLiveTunnelOriginWorker(h);if(w)w->Join();}
} // namespace eSELive
