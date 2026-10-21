#pragma once
#include "reach/direct_transport.h"
#include <algorithm>
#include <array>
#include <cstring>
#include <memory>
namespace ese {
enum class Ed2kFrameStatus { NeedMore, Frame, Invalid, ResourceLimit };
// Exact legacy framing: protocol:u8, length:u32le (opcode+payload), opcode:u8.
// Holds one frame, counted in the shared pool. No new wire envelope/opcode.
class Ed2kFramer {
public:
    explicit Ed2kFramer(reach::DirectBufferPool& pool) : pool_(pool) {}
    ~Ed2kFramer() { Release(); }
    Ed2kFramer(const Ed2kFramer&)=delete;
    Ed2kFramer& operator=(const Ed2kFramer&)=delete;
    Ed2kFrameStatus Feed(reach::DirectByteView bytes,std::size_t& consumed) {
        consumed=0;
        if(status_!=Ed2kFrameStatus::NeedMore) return status_;
        if(bytes.size && !bytes.data) return status_=Ed2kFrameStatus::Invalid;
        if(headerUsed_<header_.size()) {
            const auto n=(std::min)(bytes.size,header_.size()-headerUsed_);
            if(n) std::memcpy(header_.data()+headerUsed_,bytes.data,n);
            headerUsed_+=n; consumed+=n;
            if(headerUsed_!=header_.size()) return status_;
            const auto length=std::uint32_t(header_[1]) | (std::uint32_t(header_[2])<<8) |
                (std::uint32_t(header_[3])<<16) | (std::uint32_t(header_[4])<<24);
            if((header_[0]!=0xe3 && header_[0]!=0xc5 && header_[0]!=0xd4) ||
                !length || length-1>2000000) return status_=Ed2kFrameStatus::Invalid;
            payloadSize_=length-1;
            const auto reserve=payloadSize_+1;
            if(!pool_.ReserveExact(reserve)) return status_=Ed2kFrameStatus::ResourceLimit;
            reserved_=reserve;
            try { payload_=std::make_unique<std::uint8_t[]>(reserve); }
            catch(...) { Release(); return status_=Ed2kFrameStatus::ResourceLimit; }
        }
        const auto n=(std::min)(bytes.size-consumed,payloadSize_-payloadUsed_);
        if(n) std::memcpy(payload_.get()+payloadUsed_,bytes.data+consumed,n);
        payloadUsed_+=n; consumed+=n;
        if(payloadUsed_==payloadSize_) status_=Ed2kFrameStatus::Frame;
        return status_;
    }
    bool Ready() const noexcept { return status_==Ed2kFrameStatus::Frame; }
    const std::array<std::uint8_t,6>& Header() const noexcept { return header_; }
    reach::DirectByteView Payload() const noexcept { return Ready() ? reach::DirectByteView{payload_.get(),payloadSize_} : reach::DirectByteView{}; }
    reach::DirectBufferPool& Pool() const noexcept { return pool_; }
    void Abort() noexcept { Release(); status_=Ed2kFrameStatus::Invalid; }
    bool Next() noexcept {
        if(!Ready()) return false;
        Release(); headerUsed_=payloadSize_=payloadUsed_=0;
        status_=Ed2kFrameStatus::NeedMore; return true;
    }
private:
    void Release() noexcept { payload_.reset(); if(reserved_) { pool_.Release(reserved_); reserved_=0; } }
    reach::DirectBufferPool& pool_;
    std::array<std::uint8_t,6> header_{};
    std::unique_ptr<std::uint8_t[]> payload_;
    std::size_t headerUsed_=0,payloadSize_=0,payloadUsed_=0,reserved_=0;
    Ed2kFrameStatus status_=Ed2kFrameStatus::NeedMore;
};
}
