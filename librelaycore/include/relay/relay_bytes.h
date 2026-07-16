// SPDX-License-Identifier: MIT
// Bounded byte cursor and canonical unsigned LEB128 varints for Relay/KRP.
#pragma once

#include "relay/relay_core.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace relay {

class RelayByteReader {
public:
    RelayByteReader(const Byte* data, std::size_t size) noexcept
        : data_(data), size_(data == nullptr ? 0 : size),
          status_(data == nullptr && size != 0 ? RelayStatus::InvalidArgument
                                               : RelayStatus::Ok) {}

    RelayStatus status() const noexcept { return status_; }
    bool ok() const noexcept { return status_ == RelayStatus::Ok; }
    std::size_t position() const noexcept { return position_; }
    std::size_t remaining() const noexcept {
        return ok() ? size_ - position_ : 0;
    }

    RelayStatus ReadByte(Byte& out) noexcept {
        if (!Require(1))
            return status_;
        out = data_[position_++];
        return RelayStatus::Ok;
    }

    // Canonical unsigned LEB128.  It rejects truncated, overlong and >64-bit
    // encodings, and only writes `out` after the complete value is valid.
    RelayStatus ReadVarint(std::uint64_t& out) noexcept {
        if (!ok())
            return status_;

        std::uint64_t value = 0;
        for (unsigned index = 0; index < 10; ++index) {
            Byte byte = 0;
            if (ReadByte(byte) != RelayStatus::Ok)
                return status_;

            const Byte payload = static_cast<Byte>(byte & 0x7Fu);
            if (index == 9 && (payload & 0xFEu) != 0)
                return Fail(RelayStatus::Malformed);

            value |= static_cast<std::uint64_t>(payload) << (index * 7u);
            if ((byte & 0x80u) == 0) {
                if (index != 0 && payload == 0)
                    return Fail(RelayStatus::Malformed); // overlong
                out = value;
                return RelayStatus::Ok;
            }
        }
        return Fail(RelayStatus::Malformed);
    }

    const Byte* Take(std::size_t count) noexcept {
        if (!Require(count))
            return nullptr;
        if (count == 0 && data_ == nullptr)
            return nullptr;
        const Byte* result = data_ + position_;
        position_ += count;
        return result;
    }

private:
    bool Require(std::size_t count) noexcept {
        if (!ok())
            return false;
        if (count > size_ - position_) {
            status_ = RelayStatus::Truncated;
            return false;
        }
        return true;
    }

    RelayStatus Fail(RelayStatus status) noexcept {
        status_ = status;
        return status_;
    }

    const Byte* data_ = nullptr;
    std::size_t size_ = 0;
    std::size_t position_ = 0;
    RelayStatus status_ = RelayStatus::Ok;
};

class RelayByteWriter {
public:
    explicit RelayByteWriter(std::vector<Byte>& output) noexcept : output_(output) {}

    void WriteByte(Byte value) { output_.push_back(value); }

    void WriteVarint(std::uint64_t value) {
        do {
            Byte byte = static_cast<Byte>(value & 0x7Fu);
            value >>= 7u;
            if (value != 0)
                byte = static_cast<Byte>(byte | 0x80u);
            output_.push_back(byte);
        } while (value != 0);
    }

    RelayStatus WriteBytes(const Byte* data, std::size_t size) {
        if (data == nullptr && size != 0)
            return RelayStatus::InvalidArgument;
        if (size != 0)
            output_.insert(output_.end(), data, data + size);
        return RelayStatus::Ok;
    }

private:
    std::vector<Byte>& output_;
};

} // namespace relay
