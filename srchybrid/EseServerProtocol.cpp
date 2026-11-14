#include "EseServerProtocol.h"

#include <algorithm>
#include <cstring>
#include <new>

namespace ese::server {
namespace {
bool NonzeroRequest(const RequestId& request) noexcept
{
    return std::any_of(request.begin(),request.end(),[](std::uint8_t byte) { return byte!=0; });
}

bool ValidHeader(const FrameHeader& header) noexcept
{
    if(header.flags & ~(kEseWireServerResponse | kEseWireServerFinal)) return false;
    if((header.flags & kEseWireServerResponse) && !NonzeroRequest(header.request)) return false;
    if(header.type==kEseWireServerError)
        return (header.flags & kEseWireServerFinal)!=0;
    return !(header.flags & kEseWireServerFinal) || (header.flags & kEseWireServerResponse);
}

std::uint16_t Read16(const std::uint8_t* bytes) noexcept
{
    return static_cast<std::uint16_t>((bytes[0]<<8) | bytes[1]);
}

std::uint32_t Read32(const std::uint8_t* bytes) noexcept
{
    return (std::uint32_t{bytes[0]}<<24) | (std::uint32_t{bytes[1]}<<16) |
        (std::uint32_t{bytes[2]}<<8) | bytes[3];
}

void Write16(std::uint8_t* bytes,std::uint16_t value) noexcept
{
    bytes[0]=static_cast<std::uint8_t>(value>>8);
    bytes[1]=static_cast<std::uint8_t>(value);
}

void Write32(std::uint8_t* bytes,std::uint32_t value) noexcept
{
    for(unsigned i=0;i<4;++i)
        bytes[i]=static_cast<std::uint8_t>(value>>(24-i*8));
}
}

bool AcceptsAlpn(std::string_view selected) noexcept
{
    return selected==kEseWireServerAlpn;
}

bool EncodeFrame(const FrameView& frame,std::vector<std::uint8_t>& output)
{
    if(!ValidHeader(frame.header) || frame.payload.size>MaxPayloadSize ||
        (!frame.payload.data && frame.payload.size)) return false;
    try {
        std::vector<std::uint8_t> encoded(HeaderSize+frame.payload.size);
        std::memcpy(encoded.data(),kEseWireServerMagic,4);
        Write32(encoded.data()+4,static_cast<std::uint32_t>(frame.payload.size));
        Write16(encoded.data()+8,frame.header.type);
        Write16(encoded.data()+10,frame.header.flags);
        std::copy(frame.header.request.begin(),frame.header.request.end(),encoded.begin()+12);
        if(frame.payload.size)
            std::memcpy(encoded.data()+HeaderSize,frame.payload.data,frame.payload.size);
        output.swap(encoded);
        return true;
    } catch(const std::bad_alloc&) {
        return false;
    }
}

FeedResult FrameDecoder::Feed(ByteView input)
{
    if(state_!=DecodeState::Reading || !input.size) return {0,state_};
    if(!input.data) {
        state_=DecodeState::Malformed;
        return {0,state_};
    }
    std::size_t consumed=0;
    if(headerUsed_<HeaderSize) {
        const auto count=(std::min)(input.size,HeaderSize-headerUsed_);
        std::memcpy(headerBytes_.data()+headerUsed_,input.data,count);
        consumed=count;
        headerUsed_+=count;
        if(headerUsed_<HeaderSize) return {consumed,state_};
        const auto* bytes=headerBytes_.data();
        const auto length=Read32(bytes+4);
        header_.type=Read16(bytes+8);
        header_.flags=Read16(bytes+10);
        std::copy_n(bytes+12,header_.request.size(),header_.request.begin());
        if(std::memcmp(bytes,kEseWireServerMagic,4)!=0 || length>MaxPayloadSize || !ValidHeader(header_)) {
            state_=DecodeState::Malformed;
            return {consumed,state_};
        }
        try { payload_.resize(length); }
        catch(const std::bad_alloc&) {
            state_=DecodeState::ResourceLimit;
            return {consumed,state_};
        }
    }
    const auto count=(std::min)(input.size-consumed,payload_.size()-payloadUsed_);
    if(count) std::memcpy(payload_.data()+payloadUsed_,input.data+consumed,count);
    payloadUsed_+=count;
    if(payloadUsed_==payload_.size()) state_=DecodeState::Ready;
    return {consumed+count,state_};
}

std::optional<FrameView> FrameDecoder::Get() const noexcept
{
    if(state_!=DecodeState::Ready) return std::nullopt;
    return FrameView{header_,{payload_.data(),payload_.size()}};
}

bool FrameDecoder::Consume() noexcept
{
    if(state_!=DecodeState::Ready) return false;
    headerUsed_=payloadUsed_=0;
    // Release old storage so an invalid next header has no frame allocation.
    std::vector<std::uint8_t>().swap(payload_);
    state_=DecodeState::Reading;
    return true;
}

Disposition ClassifyFrame(const FrameHeader& header,Direction direction,Phase phase) noexcept
{
    if(!ValidHeader(header)) return Disposition::Invalid;
    const bool fromClient=direction==Direction::ClientToServer;
    const bool correlated=NonzeroRequest(header.request);
    const bool request=correlated && !header.flags;
    const bool response=correlated && (header.flags & kEseWireServerResponse);
    const bool finalResponse=response && (header.flags & kEseWireServerFinal);
    const bool notification=!correlated && !header.flags;
    auto valid=[](bool matches) { return matches ? Disposition::Message : Disposition::Invalid; };
    if(phase==Phase::Authentication) {
        switch(header.type) {
        case kEseWireServerClientHello:
        case kEseWireServerClientProof:
            return valid(fromClient && notification);
        case kEseWireServerServerHello:
        case kEseWireServerServerProof:
        case kEseWireServerAuthOk:
            return valid(!fromClient && notification);
        case kEseWireServerError:
            // Pre-authentication failure is terminal and has no request ID.
            return valid(!fromClient && !correlated && header.flags==kEseWireServerFinal);
        default:
            return Disposition::Invalid;
        }
    }
    switch(header.type) {
    case kEseWireServerClientHello:
    case kEseWireServerServerHello:
    case kEseWireServerServerProof:
    case kEseWireServerClientProof:
    case kEseWireServerAuthOk:
        return Disposition::Invalid;
    case kEseWireServerEd2kCommand:
    case kEseWireServerSourceHintsGet:
    case kEseWireServerPubBegin:
    case kEseWireServerPubChunk:
    case kEseWireServerPubCommit:
    case kEseWireServerPubStateGet:
    case kEseWireServerVoucherGet:
    case kEseWireServerPairRequest:
    case kEseWireServerConsentReply:
    case kEseWireServerProbeRequest:
    case kEseWireServerProbeArm:
    case kEseWireServerPing:
        return valid(fromClient && request);
    case kEseWireServerSessionRenew:
        return valid(fromClient ? request : finalResponse);
    case kEseWireServerEd2kEvent:
        return valid(!fromClient && (response || notification));
    case kEseWireServerAck:
    case kEseWireServerSourceHints:
    case kEseWireServerPubState:
    case kEseWireServerVoucher:
    case kEseWireServerProbeResult:
    case kEseWireServerProbeReady:
    case kEseWireServerPong:
    case kEseWireServerError:
        return valid(!fromClient && finalResponse);
    case kEseWireServerConsentQuery:
    case kEseWireServerRegStatus:
        return valid(!fromClient && notification);
    case kEseWireServerPairResult:
        return valid(!fromClient && (finalResponse || notification));
    default:
        return fromClient && request ? Disposition::UnsupportedRequest : Disposition::Invalid;
    }
}

std::optional<std::uint32_t> SelectCapabilities(std::uint32_t client,std::uint32_t server) noexcept
{
    constexpr auto known=kEseWireServerCapEd2kEnvelope | kEseWireServerCapIpv6EnodeV1 |
        kEseWireServerCapRdv2 | kEseWireServerCapCrossCallback |
        kEseWireServerCapAtomicPublish | kEseWireServerCapIpv6Connectback;
    constexpr auto required=kEseWireServerCapEd2kEnvelope | kEseWireServerCapAtomicPublish;
    auto selected=client & server & known;
    if((selected & required)!=required) return std::nullopt;
    if(!(selected & kEseWireServerCapRdv2)) selected&=~kEseWireServerCapCrossCallback;
    if(!(selected & kEseWireServerCapIpv6EnodeV1)) selected&=~kEseWireServerCapIpv6Connectback;
    return selected;
}
}
