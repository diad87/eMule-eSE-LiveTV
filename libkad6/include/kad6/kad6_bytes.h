// SPDX-License-Identifier: MIT
//
// libkad6 — kad6_bytes.h: bounded little-endian cursor reader/writer shared by
// every Kad6 codec. Centralising bounds checks here removes the class of
// out-of-bounds read that the fuzz targets (ticket K6-0.8) guard against: a
// ByteReader never advances past its buffer and latches an error flag on the
// first short read, so a codec can read a whole struct and check ok() once.
#pragma once

#include "kad6/kad6_types.h"

#include <cstring>
#include <vector>

namespace kad6 {

// Read-only bounded cursor. All reads are checked; on any short read the reader
// latches ok()==false and subsequent reads return zero / nullptr without ever
// touching memory past the buffer. Postel-friendly: a partial parse is an error.
class ByteReader {
public:
    ByteReader(const Byte* p, std::size_t len) noexcept
        : p_(p), len_(p ? len : 0), null_(p == nullptr && len != 0) {}

    bool ok() const noexcept { return ok_ && !null_; }
    bool null_arg() const noexcept { return null_; }
    std::size_t pos() const noexcept { return pos_; }
    std::size_t remaining() const noexcept { return (ok_ && !null_) ? (len_ - pos_) : 0; }

    // True iff at least n more bytes are available; latches failure otherwise.
    bool need(std::size_t n) noexcept {
        if (!ok_ || null_ || (len_ - pos_) < n) { ok_ = false; return false; }
        return true;
    }

    Byte u8() noexcept {
        if (!need(1)) return 0;
        return p_[pos_++];
    }
    std::uint16_t u16le() noexcept {
        if (!need(2)) return 0;
        std::uint32_t v = static_cast<std::uint32_t>(p_[pos_])
                        | (static_cast<std::uint32_t>(p_[pos_ + 1]) << 8);
        pos_ += 2;
        return static_cast<std::uint16_t>(v);
    }
    std::uint32_t u32le() noexcept {
        if (!need(4)) return 0;
        std::uint32_t v = 0;
        for (std::size_t i = 0; i < 4; ++i)
            v |= static_cast<std::uint32_t>(p_[pos_ + i]) << (8 * i);
        pos_ += 4;
        return v;
    }
    std::uint64_t u64le() noexcept {
        if (!need(8)) return 0;
        std::uint64_t v = 0;
        for (std::size_t i = 0; i < 8; ++i)
            v |= static_cast<std::uint64_t>(p_[pos_ + i]) << (8 * i);
        pos_ += 8;
        return v;
    }
    // Copy n bytes into out. Returns false (copying nothing) on short read.
    bool bytes(Byte* out, std::size_t n) noexcept {
        if (!need(n)) return false;
        if (n) std::memcpy(out, p_ + pos_, n);
        pos_ += n;
        return true;
    }
    // Borrow a pointer to n bytes without copying. Returns nullptr on short read.
    const Byte* take(std::size_t n) noexcept {
        if (!need(n)) return nullptr;
        const Byte* r = p_ + pos_;
        pos_ += n;
        return r;
    }

private:
    const Byte* p_;
    std::size_t len_;
    std::size_t pos_ = 0;
    bool ok_ = true;
    bool null_ = false;
};

// Append-only little-endian writer over a caller-owned vector.
class ByteWriter {
public:
    explicit ByteWriter(std::vector<Byte>& out) noexcept : out_(out) {}

    void u8(Byte v) { out_.push_back(v); }
    void u16le(std::uint16_t v) {
        out_.push_back(static_cast<Byte>(v & 0xFF));
        out_.push_back(static_cast<Byte>((v >> 8) & 0xFF));
    }
    void u32le(std::uint32_t v) {
        for (std::size_t i = 0; i < 4; ++i)
            out_.push_back(static_cast<Byte>((v >> (8 * i)) & 0xFF));
    }
    void u64le(std::uint64_t v) {
        for (std::size_t i = 0; i < 8; ++i)
            out_.push_back(static_cast<Byte>((v >> (8 * i)) & 0xFF));
    }
    void bytes(const Byte* p, std::size_t n) { if (n) out_.insert(out_.end(), p, p + n); }

    std::size_t size() const noexcept { return out_.size(); }

private:
    std::vector<Byte>& out_;
};

} // namespace kad6
