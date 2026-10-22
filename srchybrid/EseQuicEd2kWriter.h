#pragma once
#include "EseQuicTransport.h"
#include <cstring>
#include <mutex>
#include <thread>
namespace ese {
// One owned segment of the existing eD2K byte stream (including split packets).
// Queue/Remaining/Stop may run on the producer worker; Flush is owner-thread
// only and is the sole method touching QUIC. Stop, quiesce/join producers,
// then destroy before retiring the TX pool. No wire encoding is added.
class QuicEd2kWriter {
public:
    explicit QuicEd2kWriter(reach::DirectBufferPool& pool) : owner_(std::this_thread::get_id()),pool_(pool) {}
    ~QuicEd2kWriter() { Stop(); }
    QuicEd2kWriter(const QuicEd2kWriter&)=delete;
    QuicEd2kWriter& operator=(const QuicEd2kWriter&)=delete;
    reach::DirectBufferPool& Pool() const { return pool_; }
    std::size_t Remaining() const { std::lock_guard<std::mutex> lock(mutex_); return size_-offset_; }
    reach::DirectSendResult Queue(reach::DirectByteView bytes) {
        std::lock_guard<std::mutex> lock(mutex_);
        if(stopped_) return {reach::DirectIoStatus::Closed,0};
        if(size_!=offset_) return {reach::DirectIoStatus::WouldBlock,0};
        if((bytes.size && !bytes.data) || bytes.size>2000006) return {reach::DirectIoStatus::Invalid,0};
        if(!bytes.size) return {reach::DirectIoStatus::Accepted,0};
        if(!pool_.ReserveExact(bytes.size)) return {reach::DirectIoStatus::WouldBlock,0};
        try { bytes_=std::make_unique<std::uint8_t[]>(bytes.size); }
        catch(...) { pool_.Release(bytes.size); return {reach::DirectIoStatus::ResourceLimit,0}; }
        std::memcpy(bytes_.get(),bytes.data,bytes.size); size_=bytes.size; offset_=0;
        return {reach::DirectIoStatus::Accepted,bytes.size};
    }
    reach::DirectSendResult Flush(QuicTransport& transport,reach::DirectHandle handle,
        std::uint32_t route,std::uint64_t epoch,std::size_t budget=64*1024) {
        if(std::this_thread::get_id()!=owner_) return {reach::DirectIoStatus::Invalid,0};
        std::lock_guard<std::mutex> lock(mutex_);
        if(stopped_) return {reach::DirectIoStatus::Closed,0};
        if(&transport.TxPool()!=&pool_ || !transport.AllowsDelivery(handle,route,epoch))
            return {reach::DirectIoStatus::Invalid,0};
        if(size_==offset_) return {reach::DirectIoStatus::Accepted,0};
        if(!budget) return {reach::DirectIoStatus::WouldBlock,0};
        const auto result=transport.Send({bytes_.get()+offset_,(std::min)(budget,size_-offset_)});
        offset_+=result.accepted;
        if(offset_==size_) AbortLocked(); // facade owns accepted bytes through ACK
        return result;
    }
    void Abort() noexcept {
        std::lock_guard<std::mutex> lock(mutex_); AbortLocked();
    }
    void Stop() noexcept {
        std::lock_guard<std::mutex> lock(mutex_); stopped_=true; AbortLocked();
    }
private:
    void AbortLocked() noexcept {
        bytes_.reset(); if(size_) pool_.Release(size_); size_=offset_=0;
    }
    mutable std::mutex mutex_;
    const std::thread::id owner_;
    bool stopped_=false;
    reach::DirectBufferPool& pool_;
    std::unique_ptr<std::uint8_t[]> bytes_;
    std::size_t size_=0,offset_=0;
};
}
