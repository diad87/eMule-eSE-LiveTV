// SPDX-License-Identifier: MIT
#include "kad6/kad6_ed2k_policy.h"
#include "kad6/kad6_bytes.h"

namespace kad6 {

Kad6Status DecodeK6Ed2kFrame(const Byte*in,std::size_t len,K6Ed2kFrameView&out)noexcept{
    out={};if(!in&&len)return Kad6Status::NullArgument;if(len<kK6Ed2kHeaderSize)return Kad6Status::Truncated;
    ByteReader r(in,len);out.protocol=r.u8();const std::uint32_t packetLen=r.u32le();out.opcode=r.u8();
    if(!r.ok())return Kad6Status::Truncated;if(packetLen==0)return Kad6Status::Malformed;
    const std::uint64_t payloadLen=static_cast<std::uint64_t>(packetLen)-1u;if(payloadLen>kK6Ed2kMaxPayload)return Kad6Status::TooLarge;
    if(payloadLen!=r.remaining())return payloadLen>r.remaining()?Kad6Status::Truncated:Kad6Status::Malformed;
    out.payload_size=static_cast<std::uint32_t>(payloadLen);out.payload=r.take(out.payload_size);return r.ok()?Kad6Status::Ok:Kad6Status::Truncated;
}

Kad6Status EncodeK6Ed2kFrame(Byte protocol,Byte opcode,const Byte*payload,std::size_t n,std::vector<Byte>&out){out.clear();if(!payload&&n)return Kad6Status::NullArgument;if(n>kK6Ed2kMaxPayload)return Kad6Status::TooLarge;if(protocol!=kEd2kProtocolBase&&protocol!=kEd2kProtocolEmule&&protocol!=kEd2kProtocolPacked)return Kad6Status::BadValue;ByteWriter w(out);w.u8(protocol);w.u32le(static_cast<std::uint32_t>(n+1));w.u8(opcode);w.bytes(payload,n);return Kad6Status::Ok;}

K6Ed2kFrameClass ClassifyK6Ed2kFrame(Byte p,Byte op)noexcept{
    if(p==kEd2kProtocolPacked)return K6Ed2kFrameClass::Packed;
    if(p!=kEd2kProtocolBase&&p!=kEd2kProtocolEmule)return K6Ed2kFrameClass::UnknownProtocol;
    if((p==kEd2kProtocolBase&&op==0x01)||(p==kEd2kProtocolBase&&op==0x4c))return K6Ed2kFrameClass::Hello;
    if(p==kEd2kProtocolEmule&&op==0x97)return K6Ed2kFrameClass::PublicIpRequest;
    if(p==kEd2kProtocolEmule&&(op==0x98||op==0xb3))return K6Ed2kFrameClass::PublicIpAnswer;
    if(p==kEd2kProtocolEmule&&(op==0x82||op==0x84))return K6Ed2kFrameClass::SourceExchange;
    if((p==kEd2kProtocolBase&&(op==0x1c||op==0x35||op==0x36))||
       (p==kEd2kProtocolEmule&&(op==0x94||op==0x95||op==0x96||op==0x99||op==0x9a||op==0xa7||op==0xa8||op==0xe1||op==0xe2)))return K6Ed2kFrameClass::Callback;
    if(p==kEd2kProtocolEmule&&(op==0x9f||op==0xa0))return K6Ed2kFrameClass::BuddyControl;
    if((p==kEd2kProtocolBase&&(op==0x4b||op==0x4d||op==0x60||op==0xfe)))
        return K6Ed2kFrameClass::EndpointControl;
    if((p==kEd2kProtocolBase&&op==0x46)||(p==kEd2kProtocolEmule&&(op==0x40||op==0xa1||op==0xa2)))return K6Ed2kFrameClass::ContentData;
    if(p==kEd2kProtocolBase){
        switch(op){
        case 0x47:case 0x48:case 0x49:case 0x4e:case 0x4f:case 0x50:
        case 0x51:case 0x52:case 0x54:case 0x55:case 0x56:case 0x57:
        case 0x58:case 0x59:case 0x5b:case 0x5c:return K6Ed2kFrameClass::SafeControl;
        default:return K6Ed2kFrameClass::UnknownControl;
        }
    }
    switch(op){
    case 0x01:case 0x02:case 0x60:case 0x61:case 0x81:case 0x83:
    case 0x85:case 0x86:case 0x87:case 0x90:case 0x91:case 0x92:
    case 0x93:case 0x9b:case 0x9c:case 0x9d:case 0x9e:case 0xa3:
    case 0xa4:case 0xa5:case 0xa6:case 0xa9:case 0xb0:case 0xb1:
    case 0xb2:return K6Ed2kFrameClass::SafeControl;
    default:return K6Ed2kFrameClass::UnknownControl;
    }
}

K6Ed2kDisposition K6Ed2kPolicy(K6Ed2kDirection d,K6Ed2kFrameClass c)noexcept{
    switch(c){
    case K6Ed2kFrameClass::Hello:return d==K6Ed2kDirection::OriginToRemote?K6Ed2kDisposition::RewriteEndpoint:K6Ed2kDisposition::Pass;
    case K6Ed2kFrameClass::PublicIpAnswer:return d==K6Ed2kDirection::OriginToRemote?K6Ed2kDisposition::RewriteEndpoint:K6Ed2kDisposition::Pass;
    case K6Ed2kFrameClass::SourceExchange:return d==K6Ed2kDirection::RemoteToOrigin?K6Ed2kDisposition::ConvertToHints:K6Ed2kDisposition::Drop;
    case K6Ed2kFrameClass::Callback:
    case K6Ed2kFrameClass::BuddyControl:
    case K6Ed2kFrameClass::EndpointControl:return K6Ed2kDisposition::Drop;
    case K6Ed2kFrameClass::Packed:
    case K6Ed2kFrameClass::UnknownControl:
    case K6Ed2kFrameClass::UnknownProtocol:return K6Ed2kDisposition::Reject;
    default:return K6Ed2kDisposition::Pass;
    }
}

Kad6Status RewriteK6Ed2kPublicIpAnswer(const K6Ed2kFrameView&f,const Kad6Address&a,std::vector<Byte>&out){
    if(f.protocol!=kEd2kProtocolEmule||(f.opcode!=0x98&&f.opcode!=0xb3))return Kad6Status::BadValue;
    if(f.opcode==0x98){if(a.family!=Kad6Address::Family::IPv4)return Kad6Status::TargetForbidden;return EncodeK6Ed2kFrame(f.protocol,f.opcode,a.addr.data(),4,out);}
    if(a.family!=Kad6Address::Family::IPv6)return Kad6Status::TargetForbidden;return EncodeK6Ed2kFrame(f.protocol,f.opcode,a.addr.data(),16,out);
}

} // namespace kad6
