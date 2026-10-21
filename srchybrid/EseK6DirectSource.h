#pragma once
#include "EseReachDescriptor.h"
namespace ese { namespace discovery {
struct DirectSource {
    std::array<std::uint8_t,16> file{};
    std::uint64_t fileSize=0,generation=0,serial=0;
    std::array<std::uint8_t,32> node{},digest{};
    std::uint32_t ttl=0;
    std::array<std::uint8_t,64> signature{};
};
// maxFileSize is the actual host engine bound, not a separate wire constant.
inline bool DecodeSource(const std::uint8_t* p,std::size_t size,std::uint64_t maxFileSize,DirectSource& out) noexcept {
    out={}; if(!p || size!=173 || p[0]!=wire::kEseWireK6DirectSourceVersion) return false;
    const auto fileSize=ReadBe(p+17,8),generation=ReadBe(p+89,8),serial=ReadBe(p+97,8);
    const auto ttl=static_cast<std::uint32_t>(ReadBe(p+105,4));
    unsigned node=0; for(unsigned i=25;i<57;++i) node|=p[i];
    if(!fileSize || fileSize>maxFileSize || !generation || !serial || !ttl || ttl>120 || !node) return false;
    std::memcpy(out.file.data(),p+1,16); out.fileSize=fileSize;
    std::memcpy(out.node.data(),p+25,32); std::memcpy(out.digest.data(),p+57,32);
    out.generation=generation; out.serial=serial; out.ttl=ttl;
    std::memcpy(out.signature.data(),p+109,64); return true;
}
inline bool EncodeSource(const DirectSource& source,std::uint64_t maxFileSize,std::array<std::uint8_t,173>& out) noexcept {
    out={}; std::array<std::uint8_t,173> bytes{}; bytes[0]=wire::kEseWireK6DirectSourceVersion;
    std::memcpy(bytes.data()+1,source.file.data(),16); std::memcpy(bytes.data()+25,source.node.data(),32);
    std::memcpy(bytes.data()+57,source.digest.data(),32); std::memcpy(bytes.data()+109,source.signature.data(),64);
    for(unsigned i=0;i<8;++i) {
        bytes[17+i]=static_cast<std::uint8_t>(source.fileSize>>(56-8*i));
        bytes[89+i]=static_cast<std::uint8_t>(source.generation>>(56-8*i));
        bytes[97+i]=static_cast<std::uint8_t>(source.serial>>(56-8*i));
    }
    for(unsigned i=0;i<4;++i) bytes[105+i]=static_cast<std::uint8_t>(source.ttl>>(24-8*i));
    DirectSource checked; if(!DecodeSource(bytes.data(),bytes.size(),maxFileSize,checked)) return false;
    out=bytes; return true;
}
struct SourceSignatureInput {
    std::array<std::uint8_t,109+sizeof(wire::kEseWireK6DirectSourceDomain)> bytes{};
};
struct FindEntryView {
    const std::uint8_t* bytes=nullptr;
    std::size_t size=0;
    std::uint32_t remainingTtl=0;
};
struct FindResultView {
    std::uint8_t kind=0,count=0;
    std::array<std::uint8_t,16> file{};
    std::uint64_t fileSize=0;
    std::array<std::uint8_t,32> requester{},requestDigest{};
    std::array<FindEntryView,4> entries{};
    const std::uint8_t* signature=nullptr;
};
// Borrowed outer structure only. SOURCES additionally checks source layouts;
// CLOSER router records remain opaque: actual libkad6 codec/crypto/freshness,
// direct-index capability and distinct W identities are mandatory afterwards.
inline bool DecodeFindResult(const std::uint8_t* p,std::size_t size,std::uint64_t maxFileSize,FindResultView& out) noexcept {
    out={}; if(!p || size<154 || size>control::MaxDatagram-control::HeaderSize || p[0]>2) return false;
    FindResultView result; result.kind=p[0]; result.count=p[89];
    result.fileSize=ReadBe(p+17,8); unsigned key=0; for(unsigned i=25;i<57;++i) key|=p[i];
    if(!result.fileSize || result.fileSize>maxFileSize || !key) return false;
    std::memcpy(result.file.data(),p+1,16); std::memcpy(result.requester.data(),p+25,32);
    std::memcpy(result.requestDigest.data(),p+57,32);
    const auto end=size-64; std::size_t offset=90;
    if(result.kind==0) {
        if(!result.count || result.count>4 || size!=154+177*static_cast<std::size_t>(result.count)) return false;
        for(unsigned i=0;i<result.count;++i) {
            DirectSource source; if(!DecodeSource(p+offset,173,maxFileSize,source) || source.file!=result.file || source.fileSize!=result.fileSize) return false;
            const auto ttl=static_cast<std::uint32_t>(ReadBe(p+offset+173,4));
            if(!ttl || ttl>source.ttl) return false;
            for(unsigned j=0;j<i;++j) if(!std::memcmp(result.entries[j].bytes+25,source.node.data(),32)) return false;
            result.entries[i]={p+offset,173,ttl}; offset+=177;
        }
    } else if(result.kind==1) {
        if(!result.count || result.count>2) return false;
        for(unsigned i=0;i<result.count;++i) {
            if(offset>end || end-offset<2) return false;
            const auto length=static_cast<std::size_t>(ReadBe(p+offset,2)); offset+=2;
            if(!length || length>end-offset) return false;
            result.entries[i]={p+offset,length,0}; offset+=length;
        }
    } else if(result.count) return false;
    if(offset!=end) return false;
    result.signature=p+end; out=result; return true;
}
struct DirectFind {
    std::array<std::uint8_t,32> requester{};
    std::array<std::uint8_t,16> file{};
    std::uint64_t fileSize=0;
    std::uint8_t maximum=0;
    std::array<std::uint8_t,64> signature{};
};
inline bool DecodeFind(const std::uint8_t* p,std::size_t size,std::uint64_t maxFileSize,DirectFind& out) noexcept {
    out={}; if(!p || size!=121) return false;
    const auto fileSize=ReadBe(p+48,8); unsigned key=0; for(unsigned i=0;i<32;++i) key|=p[i];
    if(!key || !fileSize || fileSize>maxFileSize || !p[56] || p[56]>4) return false;
    std::memcpy(out.requester.data(),p,32); std::memcpy(out.file.data(),p+32,16);
    out.fileSize=fileSize; out.maximum=p[56]; std::memcpy(out.signature.data(),p+57,64); return true;
}
inline bool EncodeFind(const DirectFind& query,std::uint64_t maxFileSize,std::array<std::uint8_t,121>& out) noexcept {
    out={}; std::array<std::uint8_t,121> bytes{};
    std::memcpy(bytes.data(),query.requester.data(),32); std::memcpy(bytes.data()+32,query.file.data(),16);
    for(unsigned i=0;i<8;++i) bytes[48+i]=static_cast<std::uint8_t>(query.fileSize>>(56-8*i));
    bytes[56]=query.maximum; std::memcpy(bytes.data()+57,query.signature.data(),64);
    DirectFind checked; if(!DecodeFind(bytes.data(),bytes.size(),maxFileSize,checked)) return false;
    out=bytes; return true;
}
inline bool BuildSourceSignatureInput(const std::uint8_t* p,std::size_t size,std::uint64_t maxFileSize,SourceSignatureInput& out) noexcept {
    out={}; DirectSource source; if(!DecodeSource(p,size,maxFileSize,source)) return false;
    constexpr auto domain=sizeof(wire::kEseWireK6DirectSourceDomain);
    std::memcpy(out.bytes.data(),wire::kEseWireK6DirectSourceDomain,domain);
    std::memcpy(out.bytes.data()+domain,p,109); return true;
}
} }
