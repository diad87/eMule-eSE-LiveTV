#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <set>
#include <vector>

namespace eSELive {

// Owns the lifecycle of synchronous requests sent through live tunnels.
//
// The coordinator deliberately sees only handles and immutable retry snapshots.
// Request records, their wait primitive, and their terminal state stay private so
// that reply, timeout, and retry-failure races have one serialization point.
class LiveTunnelPending
{
    struct Entry;

public:
    using RequestIdGenerator = std::function<std::uint32_t()>;

    class Handle
    {
        friend class LiveTunnelPending;

    public:
        Handle() = default;
        Handle(const Handle&) = delete;
        Handle& operator=(const Handle&) = delete;
        Handle(Handle&&) noexcept = default;
        Handle& operator=(Handle&&) noexcept = default;

        explicit operator bool() const noexcept;
        std::uint32_t request_id() const noexcept;

    private:
        Handle(std::uint32_t request_id, std::shared_ptr<Entry> entry);

        std::uint32_t m_requestId = 0;
        std::shared_ptr<Entry> m_entry;
    };

    struct Outcome
    {
        std::vector<std::uint8_t> reply;
        std::uint32_t result = 0;
        std::uint32_t circuit_id = 0;
    };

    struct RetryAction
    {
        std::uint32_t request_id = 0;
        std::uint8_t sub_cmd = 0;
        std::uint32_t required_exit_caps = 0;
        std::vector<std::uint8_t> message;
    };

    LiveTunnelPending();
    ~LiveTunnelPending();

    LiveTunnelPending(const LiveTunnelPending&) = delete;
    LiveTunnelPending& operator=(const LiveTunnelPending&) = delete;
    LiveTunnelPending(LiveTunnelPending&&) = delete;
    LiveTunnelPending& operator=(LiveTunnelPending&&) = delete;

    // Registers an empty request. Zero and identifiers already in use are
    // rejected without exposing the pending-domain lock to the generator.
    Handle Register(const RequestIdGenerator& generator);

    // Adds the retry recipe while the request is still live.
    bool Configure(
        const Handle& handle,
        std::uint8_t sub_cmd,
        std::uint32_t required_exit_caps,
        int retries,
        const std::uint8_t* message,
        std::size_t message_size);

    // Associates the current circuit while the request is still registered.
    // This remains valid after a fast completion but before Wait removes the
    // record, preserving the coordinator's reply-versus-send bookkeeping race.
    bool SetCircuit(std::uint32_t request_id, std::uint32_t circuit_id);

    // Commits the first reply. Duplicate, timed-out, and failed completions are
    // harmless no-ops. Waiter notification occurs after state is committed and
    // after the pending-domain lock has been released.
    bool Complete(
        std::uint32_t request_id,
        const std::uint8_t* reply,
        std::size_t reply_size,
        std::uint32_t result);

    // Consumes the sole waiter handle and waits with the same mutex that
    // protects terminal state. The request is unregistered before return,
    // whether it completed or timed out.
    bool Wait(Handle handle, std::uint32_t timeout_ms, Outcome& outcome);

    // Examines a caller-owned registry snapshot. No callback into the
    // coordinator is made while the pending-domain lock is held.
    std::vector<RetryAction> CollectRetries(
        const std::set<std::uint32_t>& active_circuit_ids);

    // Fails every generation currently registered and wakes all waiters.
    // Records are detached atomically; notification happens after unlock.
    std::size_t CancelAll();

    std::size_t size() const;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

}  // namespace eSELive
