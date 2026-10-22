// SPDX-License-Identifier: MIT
#pragma once
#include "reach/direct_session.h"
#include <deque>
#include <mutex>

namespace reach {
inline constexpr std::size_t kDirectSessionBufferLimit = 4u * 1024u * 1024u;
inline constexpr std::size_t kDirectGlobalBufferLimit = 128u * 1024u * 1024u;
inline constexpr std::size_t kDirectBufferChunkLimit = 1024;
struct DirectByteView { const std::uint8_t* data = nullptr; std::size_t size = 0; };
enum class DirectIoStatus : std::uint8_t { Accepted, WouldBlock, Closed, Invalid, ResourceLimit };
struct DirectSendResult { DirectIoStatus status = DirectIoStatus::Invalid; std::size_t accepted = 0; };
struct DirectTransportSnapshot {
    bool started = false;
    bool closed = false;
    std::size_t tx_buffered = 0;
    std::size_t rx_buffered = 0;
    std::uint64_t accepted_offset = 0;
    std::uint64_t acknowledged_offset = 0;
};

class IDirectTransport {
public:
    virtual ~IDirectTransport() = default;
    virtual bool Start(DirectHandle handle, const DirectSessionRoute& route) = 0;
    virtual DirectSendResult Send(DirectByteView bytes) = 0;
    virtual void SetReceiveBudget(std::size_t bytes) = 0;
    virtual void Close(DirectReason reason) = 0;
    virtual DirectTransportSnapshot Snapshot() const = 0;
};

// Shared by every transport in a process. Lifetime must exceed its buffers.
class DirectBufferPool {
public:
    explicit DirectBufferPool(std::size_t limit = kDirectGlobalBufferLimit);
    DirectBufferPool(DirectBufferPool& parent,std::size_t limit);
    std::size_t ReserveUpTo(std::size_t requested);
    bool ReserveExact(std::size_t requested);
    void Release(std::size_t bytes);
    std::size_t Used() const;
private:
    mutable std::mutex mutex_;
    const std::size_t limit_;
    DirectBufferPool* parent_=nullptr; // parent must outlive all reservations
    std::size_t used_ = 0;
};

// Adapter-owned buffers, used on its owning thread. Accepted payload is copied
// into owned storage and retained until cumulative ACK/consumer delivery/close.
// Views are borrowed until the next mutating call; no copied transmit buffer
// is created outside the process accounting. Chunk count also bounds metadata.
class DirectTransportBuffers {
public:
    explicit DirectTransportBuffers(DirectBufferPool& pool,
        std::size_t tx_limit = kDirectSessionBufferLimit,
        std::size_t rx_limit = kDirectSessionBufferLimit);
    DirectTransportBuffers(DirectBufferPool& tx_pool,DirectBufferPool& rx_pool);
    ~DirectTransportBuffers();
    DirectTransportBuffers(const DirectTransportBuffers&) = delete;
    DirectTransportBuffers& operator=(const DirectTransportBuffers&) = delete;
    DirectSendResult Send(DirectByteView bytes);
    DirectSendResult Receive(DirectByteView bytes);
    DirectSendResult ReceiveAtomic(DirectByteView bytes);
    DirectByteView TransmitFront() const;
    // Absolute stream offset, including partial ACKs. Chunk storage stays at
    // the same address across Send; it is freed only after whole-chunk ACK/Close.
    DirectByteView TransmitAt(std::uint64_t offset) const;
    DirectByteView ReceiveFront() const;
    bool AcknowledgeThrough(std::uint64_t offset);
    bool ConsumeReceived(std::size_t bytes);
    void SetReceiveBudget(std::size_t bytes);
    void Close();
    DirectTransportSnapshot Snapshot() const;
private:
    struct Chunk { std::vector<std::uint8_t> bytes; std::size_t consumed = 0; };
    DirectSendResult Append(std::deque<Chunk>& queue, std::size_t& buffered, std::size_t& reserved,
        std::size_t limit, DirectByteView bytes, DirectBufferPool&, bool exact = false);
    void Consume(std::deque<Chunk>& queue, std::size_t& buffered, std::size_t& reserved, std::size_t bytes,DirectBufferPool&);
    static DirectByteView Front(const std::deque<Chunk>& queue);
    DirectBufferPool& pool_;
    DirectBufferPool& rx_pool_;
    const std::size_t tx_limit_;
    std::size_t rx_limit_;
    std::deque<Chunk> tx_, rx_;
    std::size_t tx_buffered_ = 0, rx_buffered_ = 0;
    std::size_t tx_reserved_ = 0, rx_reserved_ = 0;
    std::uint64_t accepted_offset_ = 0, acknowledged_offset_ = 0;
    bool closed_ = false;
};
// A single stream writer. ngtcp2 reports ordered contiguous ACK ranges; validate
// this contract before retiring storage. Not a QUIC engine or retransmitter.
class DirectStreamWriter {
public:
    explicit DirectStreamWriter(DirectTransportBuffers& buffers);
    DirectStreamWriter(const DirectStreamWriter&) = delete;
    DirectStreamWriter& operator=(const DirectStreamWriter&) = delete;
    DirectByteView Pending() const;
    bool Submitted(std::size_t bytes);
    bool Acknowledged(std::uint64_t offset,std::uint64_t bytes);
    std::uint64_t SubmittedOffset() const { return submitted_; }
private:
    DirectTransportBuffers& buffers_;
    std::uint64_t submitted_ = 0;
};
} // namespace reach
