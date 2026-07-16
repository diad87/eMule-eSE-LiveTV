// SPDX-License-Identifier: MIT
//
// libkad6 — kad6_endpoint.h: K6EndpointV1 (spec §7.2). A Kad6 address plus its
// transport ports, capability flags, priority, observed flag and validity. It
// is the reachable-contact building block embedded inside router records,
// source records and target tickets.
//
// Wire layout (little-endian; the leading address is itself variable-length):
//   field            size
//   caddress         2 / 6 / 18   (kad6_address wire object)
//   udp_port         u16 LE
//   tcp_port         u16 LE
//   transport_flags  u16 LE
//   priority         u8
//   observed         u8
//   valid_until      u64 LE (Unix seconds)
#pragma once

#include "kad6/kad6_address.h"
#include "kad6/kad6_bytes.h"
#include "kad6/kad6_types.h"

#include <cstdint>
#include <vector>

namespace kad6 {

// transport_flags bits (spec §7.2 table). Bits 8..15 are reserved.
constexpr std::uint16_t kK6EpUdpKad6         = 0x0001; // bit 0: accepts Kad6 UDP RPC
constexpr std::uint16_t kK6EpTcpEd2k         = 0x0002; // bit 1: accepts eD2K TCP
constexpr std::uint16_t kK6EpTunnelRelay     = 0x0004; // bit 2: can be an onion hop
constexpr std::uint16_t kK6EpKad2Gateway     = 0x0008; // bit 3: can emit Kad2 IPv4
constexpr std::uint16_t kK6EpEd2kGateway     = 0x0010; // bit 4: accepts/opens legacy sessions
constexpr std::uint16_t kK6EpInboundVerified = 0x0020; // bit 5: endpoint probed by a third party
constexpr std::uint16_t kK6EpTemporaryAddr   = 0x0040; // bit 6: IPv6 privacy address, short-lived
constexpr std::uint16_t kK6EpMetered         = 0x0080; // bit 7: limited / costly capacity
constexpr std::uint16_t kK6EpReservedMask    = 0xFF00; // bits 8..15 reserved

// Fixed tail after the variable-length address: udp+tcp+flags(6) + prio+obs(2) + valid(8).
constexpr std::size_t kK6EndpointTailSize = 16;
constexpr std::size_t kK6EndpointMinEncodedSize = 2 + kK6EndpointTailSize;
constexpr std::size_t kK6EndpointMaxEncodedSize = 18 + kK6EndpointTailSize;

struct K6Endpoint {
    Kad6Address   addr;
    std::uint16_t udp_port = 0;
    std::uint16_t tcp_port = 0;
    std::uint16_t transport_flags = 0;
    Byte          priority = 0;
    Byte          observed = 0;
    std::uint64_t valid_until = 0; // Unix seconds
};

// Serialized length (address size + 16). Does not validate; pair with Encode.
std::size_t K6EndpointEncodedSize(const K6Endpoint& e) noexcept;

// Serialize into a fresh buffer (cleared first, and on failure). Validates the
// address family via the address encoder; an invalid family => Malformed.
Kad6Status EncodeK6Endpoint(const K6Endpoint& e, std::vector<Byte>& out);

// Parse from [in, in+len). Uses the address decoder then a ByteReader for the
// fixed tail, so a short or malformed buffer never reads out of bounds.
//   - address decode failure propagates (Malformed / Truncated / NullArgument)
//   - fewer than 16 tail bytes after the address => Truncated
//   - observed outside the canonical boolean range 0..1 => Malformed
// Reserved transport bits are preserved on decode for forward compatibility.
// `consumed`, if non-null, receives addressSize + 16 on success, 0 otherwise.
Kad6Status DecodeK6Endpoint(const Byte* in, std::size_t len, K6Endpoint& out,
                            std::size_t* consumed = nullptr) noexcept;

} // namespace kad6
