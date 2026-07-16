// SPDX-License-Identifier: MIT
// Native Kad6 signed-source STORE RPC (K6-3).
#pragma once

#include "kad6/kad6_routing.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace kad6 {

constexpr std::size_t kK6StoreMaxPayloadSize = 1200;
constexpr Byte kK6FindSourceMaxRecords = 8;

enum class K6StoreStatus : Byte {
    Rejected = 0,
    Stored = 1,
    Stale = 2,
    Overloaded = 3
};

// wire: K6RouteHeaderV2 || target_hash[16] || record_len:u16 LE ||
//       K6SourceRecord[record_len]
struct K6StoreSourceRequest {
    K6RouteHeader header;
    Hash16 target_hash{};
    K6SourceRecord record;
};

// wire: K6RouteHeaderV2 || target_hash[16] || status:u8 || load:u8 ||
//       reserved:u16=0 || accepted_epoch:u64 LE
struct K6StoreSourceResponse {
    K6RouteHeader header;
    Hash16 target_hash{};
    K6StoreStatus status = K6StoreStatus::Rejected;
    Byte load = 0;
    std::uint16_t reserved = 0;
    std::uint64_t accepted_epoch = 0;
};

// wire: K6RouteHeaderV2 || target_hash[16] || max_records:u8 || reserved[3]=0
struct K6FindSourceRequest {
    K6RouteHeader header;
    Hash16 target_hash{};
    Byte max_records = 1;
};

// wire: K6RouteHeaderV2 || target_hash[16] || count:u8 || reserved[3]=0 ||
//       repeated(record_len:u16 LE || K6SourceRecord[record_len])
struct K6FindSourceResponse {
    K6RouteHeader header;
    Hash16 target_hash{};
    std::vector<K6SourceRecord> records;
};

Kad6Status EncodeK6StoreSourceRequest(const K6StoreSourceRequest& message,
                                      std::vector<Byte>& out);
Kad6Status DecodeK6StoreSourceRequest(const Byte* in, std::size_t len,
                                      K6StoreSourceRequest& message) noexcept;
Kad6Status EncodeK6StoreSourceResponse(const K6StoreSourceResponse& message,
                                       std::vector<Byte>& out);
Kad6Status DecodeK6StoreSourceResponse(const Byte* in, std::size_t len,
                                       K6StoreSourceResponse& message) noexcept;
Kad6Status EncodeK6FindSourceRequest(const K6FindSourceRequest& message,
                                     std::vector<Byte>& out);
Kad6Status DecodeK6FindSourceRequest(const Byte* in, std::size_t len,
                                     K6FindSourceRequest& message) noexcept;
Kad6Status EncodeK6FindSourceResponse(const K6FindSourceResponse& message,
                                      std::vector<Byte>& out);
Kad6Status DecodeK6FindSourceResponse(const Byte* in, std::size_t len,
                                      K6FindSourceResponse& message) noexcept;

} // namespace kad6
