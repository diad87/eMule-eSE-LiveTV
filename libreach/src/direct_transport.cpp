// SPDX-License-Identifier: MIT
#include "reach/direct_transport.h"
#include <algorithm>
#include <cassert>
#include <limits>
#include <new>
#include <utility>

namespace reach {
DirectBufferPool::DirectBufferPool(std::size_t limit)
    : limit_(std::min(limit,kDirectGlobalBufferLimit)) {}
DirectBufferPool::DirectBufferPool(DirectBufferPool& parent,std::size_t limit)
    : limit_(std::min(limit,kDirectGlobalBufferLimit)),parent_(&parent) {}
std::size_t DirectBufferPool::ReserveUpTo(std::size_t requested)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto reserved=std::min(requested,limit_-used_);
    if(parent_) reserved=parent_->ReserveUpTo(reserved);
    used_+=reserved;
    return reserved;
}
void DirectBufferPool::Release(std::size_t bytes)
{
    std::lock_guard<std::mutex> lock(mutex_);
    assert(bytes<=used_);
    if(bytes<=used_) { used_-=bytes; if(parent_) parent_->Release(bytes); }
}
bool DirectBufferPool::ReserveExact(std::size_t bytes) {
    std::lock_guard<std::mutex> lock(mutex_);
    if(bytes>limit_-used_) return false;
    if(parent_ && !parent_->ReserveExact(bytes)) return false;
    used_+=bytes; return true;
}
std::size_t DirectBufferPool::Used() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return used_;
}
DirectTransportBuffers::DirectTransportBuffers(DirectBufferPool& pool,std::size_t tx_limit,
    std::size_t rx_limit)
    : pool_(pool),rx_pool_(pool),tx_limit_(std::min(tx_limit,kDirectSessionBufferLimit)),
      rx_limit_(std::min(rx_limit,kDirectSessionBufferLimit)) {}
DirectTransportBuffers::DirectTransportBuffers(DirectBufferPool& tx,DirectBufferPool& rx)
    : pool_(tx),rx_pool_(rx),tx_limit_(kDirectSessionBufferLimit),rx_limit_(kDirectSessionBufferLimit) {}
DirectTransportBuffers::~DirectTransportBuffers() { Close(); }

DirectSendResult DirectTransportBuffers::Append(std::deque<Chunk>& queue,std::size_t& buffered,
    std::size_t& reserved,
    std::size_t limit,DirectByteView bytes,DirectBufferPool& pool,bool exact)
{
    if(closed_) return {DirectIoStatus::Closed,0};
    if(bytes.size && !bytes.data) return {DirectIoStatus::Invalid,0};
    if(!bytes.size) return {DirectIoStatus::Accepted,0};
    if(queue.size()>=kDirectBufferChunkLimit || reserved>=limit)
        return {DirectIoStatus::WouldBlock,0};
    if(exact && bytes.size>limit-reserved) return {DirectIoStatus::WouldBlock,0};
    const auto accepted=exact ? (pool.ReserveExact(bytes.size) ? bytes.size : 0) :
        pool.ReserveUpTo(std::min(bytes.size,limit-reserved));
    if(!accepted) return {DirectIoStatus::WouldBlock,0};
    try {
        Chunk chunk;
        chunk.bytes.assign(bytes.data,bytes.data+accepted);
        queue.push_back(std::move(chunk));
    } catch(const std::bad_alloc&) {
        pool.Release(accepted);
        return {DirectIoStatus::ResourceLimit,0};
    }
    buffered+=accepted;
    reserved+=accepted;
    return {DirectIoStatus::Accepted,accepted};
}
DirectSendResult DirectTransportBuffers::Send(DirectByteView bytes)
{
    if(bytes.size>std::numeric_limits<std::uint64_t>::max()-accepted_offset_)
        return {DirectIoStatus::Invalid,0};
    const auto result=Append(tx_,tx_buffered_,tx_reserved_,tx_limit_,bytes,pool_);
    accepted_offset_+=result.accepted;
    return result;
}
DirectSendResult DirectTransportBuffers::Receive(DirectByteView bytes)
{
    return Append(rx_,rx_buffered_,rx_reserved_,rx_limit_,bytes,rx_pool_);
}
DirectSendResult DirectTransportBuffers::ReceiveAtomic(DirectByteView bytes) {
    return Append(rx_,rx_buffered_,rx_reserved_,rx_limit_,bytes,rx_pool_,true);
}
DirectByteView DirectTransportBuffers::Front(const std::deque<Chunk>& queue)
{
    if(queue.empty()) return {};
    const auto& chunk=queue.front();
    return {chunk.bytes.data()+chunk.consumed,chunk.bytes.size()-chunk.consumed};
}
DirectByteView DirectTransportBuffers::TransmitFront() const { return Front(tx_); }
DirectByteView DirectTransportBuffers::TransmitAt(std::uint64_t offset) const {
    if(closed_ || offset<acknowledged_offset_ || offset>=accepted_offset_) return {};
    auto skip=offset-acknowledged_offset_;
    for(const auto& chunk:tx_) {
        const auto available=chunk.bytes.size()-chunk.consumed;
        if(skip<available) {
            const auto index=chunk.consumed+static_cast<std::size_t>(skip);
            return {chunk.bytes.data()+index,chunk.bytes.size()-index};
        }
        skip-=available;
    }
    return {};
}
DirectByteView DirectTransportBuffers::ReceiveFront() const { return Front(rx_); }
void DirectTransportBuffers::Consume(std::deque<Chunk>& queue,std::size_t& buffered,
    std::size_t& reserved,std::size_t bytes,DirectBufferPool& pool)
{
    const auto consumed=bytes;
    std::size_t released=0;
    while(bytes) {
        auto& chunk=queue.front();
        const auto count=std::min(bytes,chunk.bytes.size()-chunk.consumed);
        chunk.consumed+=count; bytes-=count;
        if(chunk.consumed==chunk.bytes.size()) {
            released+=chunk.bytes.size();
            queue.pop_front();
        }
    }
    buffered-=consumed;
    reserved-=released;
    pool.Release(released);
}
bool DirectTransportBuffers::AcknowledgeThrough(std::uint64_t offset)
{
    if(closed_ || offset<acknowledged_offset_ || offset>accepted_offset_) return false;
    const auto bytes=static_cast<std::size_t>(offset-acknowledged_offset_);
    if(bytes>tx_buffered_) return false;
    Consume(tx_,tx_buffered_,tx_reserved_,bytes,pool_);
    acknowledged_offset_=offset;
    return true;
}
bool DirectTransportBuffers::ConsumeReceived(std::size_t bytes)
{
    if(closed_ || bytes>rx_buffered_) return false;
    Consume(rx_,rx_buffered_,rx_reserved_,bytes,rx_pool_);
    return true;
}
void DirectTransportBuffers::SetReceiveBudget(std::size_t bytes)
{
    rx_limit_=std::min(bytes,kDirectSessionBufferLimit);
}
void DirectTransportBuffers::Close()
{
    if(closed_) return;
    closed_=true;
    tx_.clear(); rx_.clear();
    pool_.Release(tx_reserved_); rx_pool_.Release(rx_reserved_);
    tx_buffered_=rx_buffered_=0;
    tx_reserved_=rx_reserved_=0;
}
DirectTransportSnapshot DirectTransportBuffers::Snapshot() const
{
    return {false,closed_,tx_buffered_,rx_buffered_,accepted_offset_,acknowledged_offset_};
}
DirectStreamWriter::DirectStreamWriter(DirectTransportBuffers& buffers)
    : buffers_(buffers),submitted_(buffers.Snapshot().acknowledged_offset) {}
DirectByteView DirectStreamWriter::Pending() const { return buffers_.TransmitAt(submitted_); }
bool DirectStreamWriter::Submitted(std::size_t bytes) {
    if(buffers_.Snapshot().closed || bytes>Pending().size) return false;
    submitted_+=bytes; return true;
}
bool DirectStreamWriter::Acknowledged(std::uint64_t offset,std::uint64_t bytes) {
    const auto state=buffers_.Snapshot();
    if(state.closed || offset!=state.acknowledged_offset || offset>submitted_ || bytes>submitted_-offset)
        return false;
    return buffers_.AcknowledgeThrough(offset+bytes);
}
} // namespace reach
