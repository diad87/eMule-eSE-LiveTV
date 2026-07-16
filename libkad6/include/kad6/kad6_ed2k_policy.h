// SPDX-License-Identifier: MIT
// eD2K framing and endpoint-bearing control inventory for the K6-4 gateway.
#pragma once

#include "kad6/kad6_address.h"

#include <cstdint>
#include <vector>

namespace kad6 {

constexpr Byte kEd2kProtocolBase   = 0xE3;
constexpr Byte kEd2kProtocolPacked = 0xD4;
constexpr Byte kEd2kProtocolEmule  = 0xC5;
constexpr std::size_t kK6Ed2kHeaderSize = 6;
constexpr std::size_t kK6Ed2kMaxPayload = 16u * 1024u * 1024u;

enum class K6Ed2kDirection : Byte { OriginToRemote = 0, RemoteToOrigin = 1 };
enum class K6Ed2kFrameClass : Byte {
    Hello, PublicIpRequest, PublicIpAnswer, SourceExchange, Callback,
    BuddyControl, EndpointControl, ContentData, SafeControl, Packed,
    UnknownControl, UnknownProtocol
};
enum class K6Ed2kDisposition : Byte { Pass, RewriteEndpoint, ConvertToHints, Drop, Reject };

struct K6Ed2kFrameView {
    Byte protocol = 0;
    Byte opcode = 0;
    const Byte* payload = nullptr;
    std::uint32_t payload_size = 0;
};

Kad6Status DecodeK6Ed2kFrame(const Byte*,std::size_t,K6Ed2kFrameView&)noexcept;
Kad6Status EncodeK6Ed2kFrame(Byte protocol,Byte opcode,const Byte* payload,
                              std::size_t payloadLen,std::vector<Byte>& out);
K6Ed2kFrameClass ClassifyK6Ed2kFrame(Byte protocol,Byte opcode)noexcept;
K6Ed2kDisposition K6Ed2kPolicy(K6Ed2kDirection,K6Ed2kFrameClass)noexcept;

// Rewrites only OP_PUBLICIP_ANSWER/_V6. The caller supplies the exit address;
// an address-family mismatch is denied rather than exposing/fabricating A.
Kad6Status RewriteK6Ed2kPublicIpAnswer(const K6Ed2kFrameView&,
                                        const Kad6Address& apparent,
                                        std::vector<Byte>& out);

} // namespace kad6
