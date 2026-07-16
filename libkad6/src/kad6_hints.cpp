// SPDX-License-Identifier: MIT
#include "kad6/kad6_hints.h"

#include <algorithm>
#include <cstring>

namespace kad6 {
namespace {

bool AllZero(const Byte* p, std::size_t n) noexcept {
    Byte v=0; for(std::size_t i=0;i<n;++i)v=static_cast<Byte>(v|p[i]); return v==0;
}

bool SameEndpoint(const K6Endpoint& a,const K6Endpoint& b) noexcept {
    return a.addr==b.addr&&a.udp_port==b.udp_port&&a.tcp_port==b.tcp_port;
}

std::uint32_t ByteSwap32(std::uint32_t v) noexcept {
    return ((v & 0x000000ffu) << 24) | ((v & 0x0000ff00u) << 8) |
           ((v & 0x00ff0000u) >> 8) | ((v & 0xff000000u) >> 24);
}

bool IsLegacyLowId(std::uint32_t wireId) noexcept {
    // Every SX version writes LowID as the small numeric HybridID. HighID byte
    // order changes at v3, but LowID classification is always on the raw ID.
    return wireId < 0x01000000u;
}

Kad6Status Exact(ByteReader& r, std::size_t len) noexcept {
    if(!r.ok())return Kad6Status::Truncated;
    return r.pos()==len?Kad6Status::Ok:Kad6Status::Malformed;
}

} // namespace

Kad6Status DecodeEd2kSourceExchange(Byte opcode,const Byte*payload,std::size_t len,
                                     K6ParsedPex&out)noexcept{
    out=K6ParsedPex{};if(!payload&&len)return Kad6Status::NullArgument;
    if(opcode!=kEd2kOpAnswerSources&&opcode!=kEd2kOpAnswerSources2)return Kad6Status::BadValue;
    ByteReader r(payload,len);Byte explicitVersion=0;
    if(opcode==kEd2kOpAnswerSources2)explicitVersion=r.u8();
    r.bytes(out.object_hash.data(),16);const std::uint16_t count=r.u16le();
    if(!r.ok())return Kad6Status::Truncated;if(count>kK6PexMaxWireSources)return Kad6Status::TooLarge;
    const std::size_t remaining=r.remaining();std::size_t width=0;
    if(opcode==kEd2kOpAnswerSources2){
        if(explicitVersion<1||explicitVersion>4)return Kad6Status::UnsupportedVersion;
        width=explicitVersion==1?12u:(explicitVersion<4?28u:29u);out.version=explicitVersion;
    }else{
        if(count==0){if(remaining!=0)return Kad6Status::Malformed;out.version=1;return Kad6Status::Ok;}
        if(remaining==static_cast<std::size_t>(count)*12u){out.version=1;width=12;}
        else if(remaining==static_cast<std::size_t>(count)*28u){out.version=2;width=28;}
        else if(remaining==static_cast<std::size_t>(count)*29u){out.version=4;width=29;}
        else return Kad6Status::Malformed;
    }
    if(remaining!=static_cast<std::size_t>(count)*width)return Kad6Status::Malformed;
    out.sources.reserve((std::min<std::size_t>)(count,kK6SourceHintsMaxSources));
    for(std::uint16_t i=0;i<count;++i){
        const std::uint32_t rawId=r.u32le();const std::uint16_t port=r.u16le();
        const std::uint32_t serverIp=r.u32le();const std::uint16_t serverPort=r.u16le();
        Hash16 user{};if(out.version>=2)r.bytes(user.data(),16);const Byte crypt=out.version>=4?r.u8():0;
        if(!r.ok())return Kad6Status::Truncated;
        if(out.sources.size()>=kK6SourceHintsMaxSources){++out.omitted;continue;}
        // v1/v2 IDs are old byte order; v3/v4 are HybridID. Normalize to the
        // same network-order DWORD used by the host IPFilter.
        const std::uint32_t networkId=out.version<3?rawId:ByteSwap32(rawId);
        K6ParsedPexSource s;s.legacy_id=networkId;s.server_ip=serverIp;s.server_port=serverPort;
        s.user_hash=user;s.crypt_options=crypt;s.low_id=IsLegacyLowId(rawId);
        if(!s.low_id){
            s.endpoint.addr.family=Kad6Address::Family::IPv4;
            for(unsigned j=0;j<4;++j)s.endpoint.addr.addr[j]=static_cast<Byte>(networkId>>(8*j));
            s.endpoint.tcp_port=port;
            s.endpoint.transport_flags=kK6EpTcpEd2k;
        }
        out.sources.push_back(s);
    }
    return Exact(r,len);
}

Kad6Status EncodeK6SourceHints(const K6SourceHints&v,std::vector<Byte>&out){
    out.clear();if(v.source_session_id==0||v.source_stream_id==0||v.pex_version<1||v.pex_version>4||
       (v.flags&0xfcu)!=0||v.sources.size()>kK6SourceHintsMaxSources||AllZero(v.exterior_message_hash.data(),32))
        return Kad6Status::BadValue;
    ByteWriter w(out);w.u64le(v.source_session_id);w.u64le(v.source_stream_id);w.u64le(v.source_message_seq);
    w.u8(v.pex_version);w.u8(v.flags);w.u16le(static_cast<std::uint16_t>(v.sources.size()));
    w.bytes(v.object_hash.data(),16);w.bytes(v.exterior_message_hash.data(),32);
    for(const auto&s:v.sources){
        if(s.ticket.empty()||s.ticket.size()>0xffffu||(s.crypt_options&0xf0u)!=0){out.clear();return Kad6Status::BadValue;}
        std::vector<Byte> ep;if(EncodeK6Endpoint(s.endpoint,ep)!=Kad6Status::Ok){out.clear();return Kad6Status::BadValue;}
        K6TargetTicket t;std::size_t used=0;if(DecodeK6TargetTicket(s.ticket.data(),s.ticket.size(),t,&used)!=Kad6Status::Ok||used!=s.ticket.size()||
          t.provenance_kind!=static_cast<Byte>(K6Provenance::Pex)||t.provenance_session!=v.source_session_id||
          t.provenance_stream!=v.source_stream_id||t.provenance_seq!=v.source_message_seq||t.object_hash!=v.object_hash||
          t.service!=static_cast<Byte>(K6TicketService::Ed2kTcp)||!SameEndpoint(t.target_endpoint,s.endpoint)||
          t.provenance_digest!=v.exterior_message_hash){out.clear();return Kad6Status::BadValue;}
        w.bytes(ep.data(),ep.size());w.bytes(s.user_hash.data(),16);w.u8(s.crypt_options);
        w.u16le(static_cast<std::uint16_t>(s.ticket.size()));w.bytes(s.ticket.data(),s.ticket.size());
    }return Kad6Status::Ok;
}

Kad6Status DecodeK6SourceHints(const Byte*in,std::size_t len,K6SourceHints&out,std::size_t*consumed)noexcept{
    out=K6SourceHints{};if(consumed)*consumed=0;if(!in&&len)return Kad6Status::NullArgument;ByteReader r(in,len);
    out.source_session_id=r.u64le();out.source_stream_id=r.u64le();out.source_message_seq=r.u64le();out.pex_version=r.u8();out.flags=r.u8();
    const std::uint16_t count=r.u16le();r.bytes(out.object_hash.data(),16);r.bytes(out.exterior_message_hash.data(),32);
    if(!r.ok())return Kad6Status::Truncated;if(count>kK6SourceHintsMaxSources)return Kad6Status::TooLarge;
    if(!out.source_session_id||!out.source_stream_id||out.pex_version<1||out.pex_version>4||(out.flags&0xfcu)||AllZero(out.exterior_message_hash.data(),32))return Kad6Status::Malformed;
    out.sources.reserve(count);
    for(std::uint16_t i=0;i<count;++i){K6SourceHint s;std::size_t n=0;Kad6Status st=DecodeK6Endpoint(in+r.pos(),r.remaining(),s.endpoint,&n);if(st!=Kad6Status::Ok){out={};return st;}r.take(n);r.bytes(s.user_hash.data(),16);s.crypt_options=r.u8();const std::uint16_t tn=r.u16le();const Byte*tp=r.take(tn);if(!r.ok()){out={};return Kad6Status::Truncated;}s.ticket.assign(tp,tp+tn);K6TargetTicket t;std::size_t used=0;if(tn==0||(s.crypt_options&0xf0u)||DecodeK6TargetTicket(tp,tn,t,&used)!=Kad6Status::Ok||used!=tn||t.provenance_kind!=static_cast<Byte>(K6Provenance::Pex)||t.provenance_session!=out.source_session_id||t.provenance_stream!=out.source_stream_id||t.provenance_seq!=out.source_message_seq||t.object_hash!=out.object_hash||t.provenance_digest!=out.exterior_message_hash||t.service!=static_cast<Byte>(K6TicketService::Ed2kTcp)||!SameEndpoint(t.target_endpoint,s.endpoint)){out={};return Kad6Status::Malformed;}out.sources.push_back(std::move(s));}
    Kad6Status st=Exact(r,len);if(st!=Kad6Status::Ok){out={};return st;}if(consumed)*consumed=len;return Kad6Status::Ok;
}

} // namespace kad6
