#include "EseQuicHeaderProbe.h"
#include <ngtcp2/ngtcp2.h>
#include <algorithm>
namespace ese { namespace udp {
bool DecodeQuicHeader(const std::uint8_t* p,std::size_t n,std::size_t shortSize,Header& out) noexcept {
    if(!p || !n || shortSize>20) return false;
    ngtcp2_pkt_hd header{};
    const bool longForm=(p[0]&0x80)!=0;
    const auto decoded=longForm ? ngtcp2_pkt_decode_hd_long(&header,p,n) :
        ngtcp2_pkt_decode_hd_short(&header,p,n,shortSize);
    if(decoded<0 || !header.dcid.datalen || header.dcid.datalen>20) return false;
    // Fixed bit is necessary for QUIC v1, but never sufficient for routing.
    if(header.version!=0 && header.version!=NGTCP2_PROTO_VER_V1) return false;
    if(header.version!=0 && !(p[0]&0x40)) return false;
    if(!longForm && !(p[0]&0x40)) return false;
    Header h; h.destination.size=static_cast<std::uint8_t>(header.dcid.datalen);
    std::copy_n(header.dcid.data,header.dcid.datalen,h.destination.bytes.begin());
    h.initial=longForm && header.version==NGTCP2_PROTO_VER_V1 && header.type==NGTCP2_PKT_INITIAL;
    out=h; return true;
}
bool AcceptQuicInitial(const std::uint8_t* p,std::size_t n) noexcept {
    if(!p || n<1200) return false;
    ngtcp2_pkt_hd header{};
    return ngtcp2_accept(&header,p,n)==0 && header.version==NGTCP2_PROTO_VER_V1 && header.type==NGTCP2_PKT_INITIAL;
}
} }
