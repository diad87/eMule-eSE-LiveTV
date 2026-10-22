#pragma once
#include "EseWireProtocol.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
namespace ese { namespace control {
inline constexpr std::size_t HeaderSize=40,MaxDatagram=1200;
// Recognition only: reserved magic cannot be reinterpreted as legacy traffic,
// including malformed length/version/type. Does not authorize a control owner.
inline bool Recognize(const std::uint8_t* bytes,std::size_t size) noexcept {
    return bytes && size>=8 && !std::memcmp(bytes,wire::kEseWireControlMagic,8);
}
struct Header {
    std::uint8_t type=0;
    std::array<std::uint8_t,16> attempt{};
    std::uint64_t generation=0;
    std::uint32_t sequence=0;
};
// Untrusted borrowed bytes. Parsing confers NO identity, freshness, capability,
// endpoint validation, replay authorization or permission to open a route.
struct Envelope {
    Header header;
    const std::uint8_t* payload=nullptr;
    std::size_t payloadSize=0;
};
inline bool KnownType(std::uint8_t type) noexcept { return type>=wire::kEseWireUdpProbe && type<=wire::kEseWireUdpK6ContactResult; }
inline bool ParseUntrusted(const std::uint8_t* bytes,std::size_t size,Envelope& out) noexcept {
    out={};
    if(!bytes || size<HeaderSize || size>MaxDatagram ||
        std::memcmp(bytes,wire::kEseWireControlMagic,8) || bytes[8]!=wire::kEseWireUdpVersion || !KnownType(bytes[9])) return false;
    const auto length=(static_cast<std::size_t>(bytes[10])<<8)|bytes[11];
    if(length!=size-HeaderSize) return false;
    out.header.type=bytes[9];
    std::memcpy(out.header.attempt.data(),bytes+12,16);
    for(unsigned i=28;i<36;++i) out.header.generation=(out.header.generation<<8)|bytes[i];
    for(unsigned i=36;i<40;++i) out.header.sequence=(out.header.sequence<<8)|bytes[i];
    out.payload=bytes+HeaderSize; out.payloadSize=length;
    return true;
}
struct Datagram {
    std::array<std::uint8_t,MaxDatagram> bytes{};
    std::size_t size=0;
};
// Only serializes the envelope. Caller must supply the type-specific body,
// signature and fresh correlation; this is not a signed-message builder.
inline bool Encode(const Header& header,const std::uint8_t* payload,std::size_t size,Datagram& out) noexcept {
    out.size=0;
    if(!KnownType(header.type) || size>MaxDatagram-HeaderSize || (size && !payload)) return false;
    // memmove permits re-encoding a payload borrowed from this same datagram.
    if(size) std::memmove(out.bytes.data()+HeaderSize,payload,size);
    std::memcpy(out.bytes.data(),wire::kEseWireControlMagic,8);
    out.bytes[8]=wire::kEseWireUdpVersion; out.bytes[9]=header.type;
    out.bytes[10]=static_cast<std::uint8_t>(size>>8); out.bytes[11]=static_cast<std::uint8_t>(size);
    std::memcpy(out.bytes.data()+12,header.attempt.data(),16);
    for(unsigned i=0;i<8;++i) out.bytes[28+i]=static_cast<std::uint8_t>(header.generation>>(56-8*i));
    for(unsigned i=0;i<4;++i) out.bytes[36+i]=static_cast<std::uint8_t>(header.sequence>>(24-8*i));
    out.size=HeaderSize+size; return true;
}
struct SignatureInput {
    std::array<std::uint8_t,MaxDatagram+sizeof(wire::kEseWireUdpAuthDomain)-64> bytes{};
    std::size_t size=0;
};
// Excludes unsigned PROBE/CHALLENGE and standalone ticket/receipt/Birthday
// domains. Merely prepares bytes; signature verification grants no freshness.
inline bool EnvelopeSignedType(std::uint8_t type) noexcept {
    switch(type) {
    case wire::kEseWireUdpProve: case wire::kEseWireUdpAck:
    case wire::kEseWireUdpRdvReserve: case wire::kEseWireUdpRdvIntro:
    case wire::kEseWireUdpRdvForward: case wire::kEseWireUdpRdvAccept:
    case wire::kEseWireUdpWitnessRequest: case wire::kEseWireUdpCancel:
    case wire::kEseWireUdpDescriptorPut: case wire::kEseWireUdpDescriptorGet:
    case wire::kEseWireUdpDescriptorResult: case wire::kEseWireUdpK6DirectPut:
    case wire::kEseWireUdpK6DirectPutResult: case wire::kEseWireUdpK6DirectFind:
    case wire::kEseWireUdpK6DirectFindResult: case wire::kEseWireUdpK6ContactGet:
    case wire::kEseWireUdpK6ContactResult: return true;
    default: return false;
    }
}
inline bool BuildSignatureInput(const std::uint8_t* packet,std::size_t size,SignatureInput& out) noexcept {
    out.size=0; Envelope envelope;
    if(!ParseUntrusted(packet,size,envelope) || !EnvelopeSignedType(envelope.header.type) || envelope.payloadSize<64) return false;
    constexpr auto domainSize=sizeof(wire::kEseWireUdpAuthDomain); // includes NUL
    std::memcpy(out.bytes.data(),wire::kEseWireUdpAuthDomain,domainSize);
    std::memcpy(out.bytes.data()+domainSize,packet,size-64);
    out.size=domainSize+size-64;
    return true;
}
} }
