#include "ServerSession.h"

#include <algorithm>
#include <cstring>
#include <limits>

namespace ese::server {
namespace {
constexpr std::uint8_t Ed2k=0xe3;
constexpr std::uint8_t Login=0x01,GetServerList=0x14,OfferFiles=0x15,Disconnect=0x18,
    ServerList=0x32,IdChange=0x40,ServerIdent=0x41;
constexpr std::uint64_t CacheMilliseconds=120000;
constexpr std::uint64_t LeaseMilliseconds=600000;
constexpr std::size_t CacheEntries=256;

std::uint64_t AddTime(std::uint64_t now,std::uint64_t duration) noexcept
{
    const auto maximum=(std::numeric_limits<std::uint64_t>::max)();
    return now>maximum-duration ? maximum : now+duration;
}

unsigned ReadLe(const std::uint8_t* data,unsigned size) noexcept
{
    unsigned value=0;
    for(unsigned i=0;i<size;++i) value|=unsigned{data[i]}<<(i*8);
    return value;
}

void AppendLittle(EncodedFrame& output,std::uint32_t value,unsigned size)
{
    for(unsigned i=0;i<size;++i) output.push_back(static_cast<std::uint8_t>(value>>(i*8)));
}

void AppendBig32(EncodedFrame& output,std::uint32_t value)
{
    for(unsigned i=0;i<4;++i) output.push_back(static_cast<std::uint8_t>(value>>((3-i)*8)));
}

bool Reply(const RequestId& request,std::uint16_t type,ByteView payload,Responses& output,bool last=true)
{
    EncodedFrame response;
    const auto flags=static_cast<std::uint16_t>(kEseWireServerResponse | (last ? kEseWireServerFinal : 0));
    if(!EncodeFrame({{type,flags,request},payload},response)) return false;
    output.push_back(std::move(response));
    return true;
}

bool Error(const RequestId& request,std::uint16_t code,Responses& output)
{
    const std::uint8_t bytes[]={static_cast<std::uint8_t>(code>>8),static_cast<std::uint8_t>(code),0,0,0,0};
    return Reply(request,kEseWireServerError,{bytes,sizeof bytes},output);
}

bool Event(const RequestId& request,std::uint8_t opcode,const EncodedFrame& payload,Responses& output,bool last)
{
    EncodedFrame wrapped={Ed2k,opcode};
    AppendBig32(wrapped,static_cast<std::uint32_t>(payload.size()));
    wrapped.insert(wrapped.end(),payload.begin(),payload.end());
    return Reply(request,kEseWireServerEd2kEvent,{wrapped.data(),wrapped.size()},output,last);
}

bool ValidateLogin(ByteView input,const Bytes16& expected) noexcept
{
    if(input.size<26 || !std::equal(expected.begin(),expected.end(),input.data) ||
        !ReadLe(input.data+20,2)) return false;
    const unsigned tags=ReadLe(input.data+22,4);
    if(tags>32) return false;
    std::size_t offset=26;
    std::array<bool,256> seen{};
    for(unsigned i=0;i<tags;++i) {
        // The product login serializer uses legacy u16 name length and a
        // one-byte tag ID. The required scalar payloads stay little-endian.
        if(input.size-offset<4 || ReadLe(input.data+offset+1,2)!=1) return false;
        const auto type=input.data[offset], name=input.data[offset+3];
        if(seen[name]) return false;
        seen[name]=true;
        offset+=4;
        std::size_t length=0;
        if(type==0x02) {
            if(input.size-offset<2) return false;
            length=ReadLe(input.data+offset,2);
            offset+=2;
            if(!length || length>255 || name!=0x01) return false;
        } else if(type==0x03) {
            if(name!=0x11 && name!=0x20 && name!=0xfb && name!=0xf0) return false;
            length=4;
        } else return false;
        if(length>input.size-offset) return false;
        if(type==0x02 && std::memchr(input.data+offset,0,length)) return false;
        offset+=length;
    }
    return offset==input.size && seen[0x01] && seen[0x11] && seen[0x20] && seen[0xfb];
}
}

ServerSession::ServerSession(const ClientHello& authenticatedClient,ServerEndpoint endpoint,ServerIndex& index,
    std::uint64_t generation,std::uint64_t now)
    : client_(authenticatedClient),endpoint_(endpoint),lease_(AddTime(now,LeaseMilliseconds)),
      index_(index),generation_(generation)
{
    completed_.reserve(CacheEntries);
}

ServerSession::~ServerSession()
{
    if(loggedIn_ && client_.mode==SessionMode::Primary) index_.Deactivate(client_.node,generation_);
}

bool ServerSession::Handle(const FrameView& frame,AuthCrypto& crypto,std::uint64_t now,Responses& output)
{
    if(closed_ || (frame.payload.size && !frame.payload.data) || frame.payload.size>MaxPayloadSize) return false;
    const auto route=ClassifyFrame(frame.header,Direction::ClientToServer,Phase::Authenticated);
    if(route==Disposition::Invalid) return false;
    Responses pending;
    if(now>=lease_) {
        if(!Error(frame.header.request,kEseWireServerExpired,pending)) return false;
        output.swap(pending);
        closed_=true;
        return true;
    }
    if(loggedIn_ && client_.mode==SessionMode::Primary && !index_.CurrentPrimary(client_.node,generation_,now)) {
        if(!Error(frame.header.request,kEseWireServerWrongState,pending)) return false;
        output.swap(pending);
        closed_=true;
        return true;
    }
    EncodedFrame request={static_cast<std::uint8_t>(frame.header.type>>8),static_cast<std::uint8_t>(frame.header.type)};
    if(frame.payload.size) request.insert(request.end(),frame.payload.data,frame.payload.data+frame.payload.size);
    Bytes32 digest{};
    if(!crypto.Hash({request.data(),request.size()},digest)) return false;
    completed_.erase(std::remove_if(completed_.begin(),completed_.end(),
        [now](const Completed& prior) { return now>=prior.until; }),completed_.end());
    const auto found=std::find_if(completed_.begin(),completed_.end(),
        [&frame](const Completed& prior) { return frame.header.request==prior.request; });
    if(found!=completed_.end()) {
        if(found->digest!=digest) {
            if(!Error(frame.header.request,kEseWireServerConflict,pending)) return false;
        } else pending=found->responses;
        output.swap(pending);
        return true;
    }
    if(completed_.size()==CacheEntries) {
        if(!Error(frame.header.request,kEseWireServerResourceLimit,pending)) return false;
        output.swap(pending);
        return true;
    }
    auto loggedIn=loggedIn_;
    auto closed=closed_;
    auto lease=lease_;
    if(route==Disposition::UnsupportedRequest) {
        if(!Error(frame.header.request,kEseWireServerUnsupported,pending)) return false;
    } else if(!Dispatch(frame,crypto,now,pending,loggedIn,closed,lease)) return false;
    completed_.push_back({frame.header.request,digest,AddTime(now,CacheMilliseconds),pending});
    if(loggedIn && !loggedIn_ && client_.mode==SessionMode::Primary) {
        const auto status=index_.ActivatePrimary(client_,generation_,lease);
        if(status) {
            pending.clear();
            if(!Error(frame.header.request,status,pending)) return false;
            completed_.back().responses=pending;
            loggedIn=false;
        }
    }
    if(loggedIn && client_.mode==SessionMode::Primary) {
        if(closed) index_.Deactivate(client_.node,generation_);
        else if(lease!=lease_) index_.Renew(client_.node,generation_,lease);
    }
    loggedIn_=loggedIn;
    closed_=closed;
    lease_=lease;
    output.swap(pending);
    return true;
}

bool ServerSession::Dispatch(const FrameView& frame,AuthCrypto& crypto,std::uint64_t now,Responses& output,bool& loggedIn,bool& closed,
    std::uint64_t& lease)
{
    const auto& request=frame.header.request;
    if(!loggedIn && frame.header.type!=kEseWireServerEd2kCommand)
        return Error(request,kEseWireServerWrongState,output);
    if(frame.header.type==kEseWireServerPing) {
        return frame.payload.size==16 ? Reply(request,kEseWireServerPong,frame.payload,output) :
            Error(request,kEseWireServerMalformed,output);
    }
    if(frame.header.type==kEseWireServerSessionRenew) {
        if(frame.payload.size) return Error(request,kEseWireServerMalformed,output);
        EncodedFrame payload;
        AppendBig32(payload,SessionLeaseSeconds);
        lease=AddTime(now,LeaseMilliseconds);
        return Reply(request,kEseWireServerSessionRenew,{payload.data(),payload.size()},output);
    }
    if(frame.header.type==kEseWireServerSourceHintsGet) {
        std::array<std::uint8_t,24> key{};
        if(frame.payload.size!=key.size()) return Error(request,kEseWireServerMalformed,output);
        std::copy_n(frame.payload.data,key.size(),key.begin());
        const auto hints=index_.Hints(client_.node,client_.mode==SessionMode::Primary ? generation_ : 0, key,now);
        if(!hints) return Error(request,kEseWireServerWrongState,output);
        return Reply(request,kEseWireServerSourceHints,{hints->data(),hints->size()},output);
    }
    if(frame.header.type>=kEseWireServerPubBegin && frame.header.type<=kEseWireServerPubStateGet) {
        if(client_.mode==SessionMode::Auxiliary) return Error(request,kEseWireServerWrongState,output);
        if(frame.header.type==kEseWireServerPubStateGet) {
            PublishState visible;
            const auto status=index_.Publish(client_.node,generation_,frame.header.type,frame.payload,crypto,now,visible);
            if(status) return Error(request,status,output);
            const auto bytes=EncodePublishState(visible);
            return Reply(request,kEseWireServerPubState,{bytes.data(),bytes.size()},output);
        }
        // Prepare the success response before mutating staging or the visible
        // publication, so an allocation failure cannot acknowledge lost work.
        const std::uint8_t ack[2]={};
        if(!Reply(request,kEseWireServerAck,{ack,sizeof ack},output)) return false;
        PublishState ignored;
        const auto status=index_.Publish(client_.node,generation_,frame.header.type,frame.payload,crypto,now,ignored);
        if(!status) return true;
        output.clear();
        return Error(request,status,output);
    }
    if(frame.header.type!=kEseWireServerEd2kCommand)
        return Error(request,kEseWireServerUnsupported,output);
    const auto* bytes=frame.payload.data;
    const auto size=frame.payload.size;
    if(size<6 || bytes[0]!=Ed2k) return Error(request,kEseWireServerMalformed,output);
    std::uint32_t declared=0;
    for(unsigned i=2;i<6;++i) declared=(declared<<8)|bytes[i];
    if(declared!=size-6) return Error(request,kEseWireServerMalformed,output);
    const auto opcode=bytes[1];
    if(!loggedIn && opcode!=Login) return Error(request,kEseWireServerWrongState,output);
    if(opcode==Login) {
        if(loggedIn) return Error(request,kEseWireServerWrongState,output);
        if(!ValidateLogin({bytes+6,declared},client_.userHash)) return Error(request,kEseWireServerMalformed,output);
        EncodedFrame id;
        AppendLittle(id,endpoint_.lowId,4); // Never claim HighID without an inbound probe.
        EncodedFrame identity(endpoint_.identity.begin(),endpoint_.identity.end());
        identity.insert(identity.end(),endpoint_.ipv4.begin(),endpoint_.ipv4.end());
        AppendLittle(identity,endpoint_.port,2);
        AppendLittle(identity,0,4);
        loggedIn=true;
        return Event(request,IdChange,id,output,false) && Event(request,ServerIdent,identity,output,true);
    }
    if(opcode==OfferFiles) // OFFERFILES belongs to the separate classic listener.
        return Error(request,kEseWireServerUnsupported,output);
    if(opcode==GetServerList && !declared)
        return Event(request,ServerList,EncodedFrame{0},output,true);
    if(opcode==Disconnect && !declared) {
        const std::uint8_t status[2]={};
        closed=true;
        return Reply(request,kEseWireServerAck,{status,sizeof status},output);
    }
    if(opcode==GetServerList || opcode==Disconnect) return Error(request,kEseWireServerMalformed,output);
    return Error(request,kEseWireServerUnsupported,output);
}
}
