// SPDX-License-Identifier: MIT
// Signed virtual identity endpoint used by legacy SecureIdent through an exit.
#pragma once

#include "kad6/kad6_address.h"
#include "kad6/kad6_crypto.h"

#include <cstdint>
#include <vector>

namespace kad6 {

constexpr std::uint64_t kK6VepMaxTtlSeconds = 30u * 60u;

struct K6VirtualIdentityEndpoint {
    Kad6Address apparent_source_ip;
    std::uint16_t apparent_tcp_port = 0;
    std::uint16_t apparent_udp_port = 0;
    Hash32 exit_node_pub{};
    std::uint64_t source_lease_id = 0; // outgoing DIAL uses stream_id
    std::uint64_t valid_until = 0;
    std::array<Byte,kEd25519SigSize> signature{};
};

Kad6Status K6VepSerializeSigned(const K6VirtualIdentityEndpoint&,std::vector<Byte>&);
Kad6Status SignK6Vep(const Kad6CryptoHooks&,K6VirtualIdentityEndpoint&,std::vector<Byte>&);
Kad6Status EncodeK6Vep(const K6VirtualIdentityEndpoint&,std::vector<Byte>&);
Kad6Status DecodeK6Vep(const Byte*,std::size_t,K6VirtualIdentityEndpoint&,
                        std::size_t* consumed=nullptr)noexcept;
Kad6Status VerifyK6Vep(const Kad6CryptoHooks&,const K6VirtualIdentityEndpoint&,
                        std::uint64_t nowUnix)noexcept;

} // namespace kad6
