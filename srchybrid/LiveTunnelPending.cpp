#include "LiveTunnelPending.h"

#include <chrono>
#include <condition_variable>
#include <map>
#include <mutex>
#include <utility>

namespace eSELive {

struct LiveTunnelPending::Entry
{
    std::condition_variable changed;
    bool terminal = false;
    bool failed = false;
    std::uint32_t result = 0;
    std::vector<std::uint8_t> reply;

    std::uint32_t circuit_id = 0;
    std::uint8_t sub_cmd = 0;
    std::uint32_t required_exit_caps = 0;
    int retries_left = 0;
    std::vector<std::uint8_t> request_message;
};

struct LiveTunnelPending::Impl
{
    mutable std::mutex mutex;
    std::map<std::uint32_t, std::shared_ptr<Entry>> requests;
};

LiveTunnelPending::Handle::Handle(
    std::uint32_t request_id,
    std::shared_ptr<Entry> entry)
    : m_requestId(request_id)
    , m_entry(std::move(entry))
{
}

LiveTunnelPending::Handle::operator bool() const noexcept
{
    return m_requestId != 0 && static_cast<bool>(m_entry);
}

std::uint32_t LiveTunnelPending::Handle::request_id() const noexcept
{
    return m_requestId;
}

LiveTunnelPending::LiveTunnelPending()
    : m_impl(std::make_unique<Impl>())
{
}

LiveTunnelPending::~LiveTunnelPending() = default;
bool LiveTunnelPending::IsLive(std::uint32_t request_id) const { std::lock_guard<std::mutex> guard(m_impl->mutex); const auto found=m_impl->requests.find(request_id); return found!=m_impl->requests.end() && !found->second->terminal; }

LiveTunnelPending::Handle LiveTunnelPending::Register(
    const RequestIdGenerator& generator)
{
    if (!generator)
        return {};

    for (;;) {
        // The generator is coordinator-owned and may eventually be replaced by
        // an injected entropy source. Keep it outside the pending mutex.
        const std::uint32_t request_id = generator();
        if (request_id == 0)
            continue;

        std::lock_guard<std::mutex> guard(m_impl->mutex);
        if (m_impl->requests.find(request_id) != m_impl->requests.end())
            continue;

        auto entry = std::make_shared<Entry>();
        m_impl->requests.emplace(request_id, entry);
        return Handle(request_id, std::move(entry));
    }
}

bool LiveTunnelPending::Configure(
    const Handle& handle,
    std::uint8_t sub_cmd,
    std::uint32_t required_exit_caps,
    int retries,
    const std::uint8_t* message,
    std::size_t message_size)
{
    if (!handle)
        return false;
    if (message_size != 0 && message == nullptr)
        return false;

    std::lock_guard<std::mutex> guard(m_impl->mutex);
    const auto it = m_impl->requests.find(handle.m_requestId);
    if (it == m_impl->requests.end()
        || it->second != handle.m_entry
        || it->second->terminal) {
        return false;
    }

    Entry& entry = *it->second;
    entry.sub_cmd = sub_cmd;
    entry.required_exit_caps = required_exit_caps;
    entry.retries_left = retries;
    if (message_size == 0)
        entry.request_message.clear();
    else
        entry.request_message.assign(message, message + message_size);
    return true;
}

bool LiveTunnelPending::SetCircuit(
    std::uint32_t request_id,
    std::uint32_t circuit_id)
{
    std::lock_guard<std::mutex> guard(m_impl->mutex);
    const auto it = m_impl->requests.find(request_id);
    if (it == m_impl->requests.end())
        return false;

    it->second->circuit_id = circuit_id;
    return true;
}

bool LiveTunnelPending::Complete(
    std::uint32_t request_id,
    const std::uint8_t* reply,
    std::size_t reply_size,
    std::uint32_t result)
{
    if (reply_size != 0 && reply == nullptr)
        return false;

    std::shared_ptr<Entry> completed;
    {
        std::lock_guard<std::mutex> guard(m_impl->mutex);
        const auto it = m_impl->requests.find(request_id);
        if (it == m_impl->requests.end() || it->second->terminal)
            return false;

        completed = it->second;
        if (reply_size == 0)
            completed->reply.clear();
        else
            completed->reply.assign(reply, reply + reply_size);
        completed->result = result;
        completed->failed = false;
        completed->terminal = true;
    }

    completed->changed.notify_all();
    return true;
}

bool LiveTunnelPending::Wait(
    Handle handle,
    std::uint32_t timeout_ms,
    Outcome& outcome)
{
    if (!handle)
        return false;

    std::unique_lock<std::mutex> lock(m_impl->mutex);
    const auto initial = m_impl->requests.find(handle.m_requestId);
    if (initial == m_impl->requests.end() || initial->second != handle.m_entry)
        return false;

    const std::shared_ptr<Entry> entry = initial->second;
    const bool terminal = entry->changed.wait_for(
        lock,
        std::chrono::milliseconds(timeout_ms),
        [&entry] { return entry->terminal; });

    // Completion cannot change after terminal is true. Timeout owns removal
    // under the same mutex, so any later reply observes an absent request.
    const auto current = m_impl->requests.find(handle.m_requestId);
    if (current != m_impl->requests.end() && current->second == entry)
        m_impl->requests.erase(current);
    if (!terminal || entry->failed)
        return false;

    outcome.reply = std::move(entry->reply);
    outcome.result = entry->result;
    outcome.circuit_id = entry->circuit_id;
    return true;
}

std::vector<LiveTunnelPending::RetryAction>
LiveTunnelPending::CollectRetries(
    const std::set<std::uint32_t>& active_circuit_ids)
{
    std::vector<RetryAction> retries;
    std::vector<std::shared_ptr<Entry>> failed;

    {
        std::lock_guard<std::mutex> guard(m_impl->mutex);
        for (const auto& request : m_impl->requests) {
            Entry& entry = *request.second;
            if (entry.terminal || entry.circuit_id == 0)
                continue;
            if (active_circuit_ids.find(entry.circuit_id)
                != active_circuit_ids.end()) {
                continue;
            }

            if (entry.retries_left > 0) {
                --entry.retries_left;
                entry.circuit_id = 0;

                RetryAction action;
                action.request_id = request.first;
                action.sub_cmd = entry.sub_cmd;
                action.required_exit_caps = entry.required_exit_caps;
                action.message = entry.request_message;
                retries.push_back(std::move(action));
            } else {
                // Failure is a terminal completion just like a reply. Commit it
                // once under the mutex, then wake the waiter after unlock.
                entry.failed = true;
                entry.terminal = true;
                failed.push_back(request.second);
            }
        }
    }

    for (const auto& entry : failed)
        entry->changed.notify_all();
    return retries;
}

std::size_t LiveTunnelPending::CancelAll()
{
    std::vector<std::shared_ptr<Entry>> cancelled;
    {
        std::lock_guard<std::mutex> guard(m_impl->mutex);
        cancelled.reserve(m_impl->requests.size());
        for (const auto& request : m_impl->requests) {
            Entry& entry = *request.second;
            if (!entry.terminal) {
                entry.failed = true;
                entry.terminal = true;
            }
            cancelled.push_back(request.second);
        }
        m_impl->requests.clear();
    }
    for (const auto& entry : cancelled)
        entry->changed.notify_all();
    return cancelled.size();
}

std::size_t LiveTunnelPending::size() const
{
    std::lock_guard<std::mutex> guard(m_impl->mutex);
    return m_impl->requests.size();
}

}  // namespace eSELive
