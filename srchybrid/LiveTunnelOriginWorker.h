// this file is part of eMule eSE - LT6 cancelable origin worker
#pragma once
#include "LiveTunnelOriginPort.h"
#include "M2ABindingPort.h"
#include <array>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <mutex>
#include <thread>
namespace eSELive{
class LiveTunnelOriginWorker final {
public:
    explicit LiveTunnelOriginWorker(const M2AParentPort&);~LiveTunnelOriginWorker() noexcept;
    LiveTunnelOriginWorker(const LiveTunnelOriginWorker&)=delete;LiveTunnelOriginWorker& operator=(const LiveTunnelOriginWorker&)=delete;
    bool Submit(std::uint64_t,LiveTunnelOriginWorkerTask);
    void Cancel() noexcept; void Join() noexcept;
    std::uint64_t generation() const noexcept; std::uint64_t stale() const noexcept;
private:
    struct Work{std::uint64_t generation=0,cancel_generation=0;LiveTunnelOriginWorkerTask task;};
    void Run() noexcept;
    mutable std::mutex m_mutex;
    std::condition_variable m_ready;std::deque<Work> m_work;std::array<std::thread,2> m_threads;
    std::uint64_t m_generation=1,m_stale=0;
    bool m_cancelled=false;
};
M2AModuleHandle M2A_BIND_LT6_6F855B99C0(const M2AParentPort&);
LiveTunnelOriginWorker* ResolveLiveTunnelOriginWorker(M2AModuleHandle&) noexcept;
} // namespace eSELive
