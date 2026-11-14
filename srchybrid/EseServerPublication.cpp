#include "EseServerPublication.h"
#include "kad6/kad6_tags.h"
#include <algorithm>
#include <cstring>

namespace ese::server {
namespace {
constexpr std::size_t RecordKeySize=24;

template<class Integer>
Integer Read(const std::uint8_t* bytes) noexcept
{
    Integer value=0;
    for(std::size_t i=0;i<sizeof(value);++i)
        value=static_cast<Integer>((value<<8)|bytes[i]);
    return value;
}

template<class Integer>
void Write(std::uint8_t* bytes,Integer value) noexcept
{
    for(std::size_t i=sizeof(value);i>0;--i) {
        bytes[i-1]=static_cast<std::uint8_t>(value);
        value>>=8;
    }
}

bool ValidName(const std::uint8_t* name,std::size_t length) noexcept
{
    return length && length<=255 && kad6::Kad6IsValidUtf8NoNul(name,length) &&
        std::none_of(name,name+length,[](std::uint8_t c) { return c=='/' || c=='\\' || c==':'; });
}
}

bool DecodePublishState(ByteView input,PublishState& output) noexcept
{
    if(!input.data || input.size!=44) return false;
    PublishState value;
    value.revision=Read<std::uint64_t>(input.data);
    value.records=Read<std::uint32_t>(input.data+8);
    std::copy_n(input.data+12,value.digest.size(),value.digest.begin());
    if(value.records>MaxPublicationRecords || (!value.revision && value.records)) return false;
    output=value;
    return true;
}

std::array<std::uint8_t,44> EncodePublishState(const PublishState& state) noexcept
{
    std::array<std::uint8_t,44> bytes{};
    Write(bytes.data(),state.revision);
    Write(bytes.data()+8,state.records);
    std::copy(state.digest.begin(),state.digest.end(),bytes.begin()+12);
    return bytes;
}

bool DecodePublishChunk(ByteView input,PublishChunk& output) noexcept
{
    constexpr std::size_t chunkHeader=14;
    constexpr std::size_t recordHeader=26;
    constexpr std::size_t minimumRecord=recordHeader+2;
    if(!input.data || input.size<chunkHeader || input.size>MaxPayloadSize) return false;
    PublishChunk value;
    value.revision=Read<std::uint64_t>(input.data);
    value.index=Read<std::uint32_t>(input.data+8);
    value.records=Read<std::uint16_t>(input.data+12);
    if(!value.revision || !value.records || value.records>MaxPublicationChunkRecords || value.index>=MaxPublicationRecords)
        return false;
    std::size_t offset=chunkHeader;
    for(unsigned i=0;i<value.records;++i) {
        if(input.size-offset<minimumRecord) return false;
        const auto* record=input.data+offset;
        const auto nameSize=Read<std::uint16_t>(record+RecordKeySize);
        if(nameSize>input.size-offset-recordHeader-1 || !ValidName(record+recordHeader,nameSize) ||
            record[recordHeader+nameSize]>8) return false;
        if(value.lastKey.data && std::memcmp(value.lastKey.data,record,RecordKeySize)>=0) return false;
        value.lastKey={record,RecordKeySize};
        if(!value.firstKey.data) value.firstKey=value.lastKey;
        offset+=recordHeader+nameSize+1;
    }
    if(offset!=input.size) return false;
    value.canonicalRecords={input.data+chunkHeader,input.size-chunkHeader};
    output=value;
    return true;
}

bool DecodePublishCommit(ByteView input,std::uint64_t& revision,Bytes32& digest) noexcept
{
    if(!input.data || input.size!=40) return false;
    const auto value=Read<std::uint64_t>(input.data);
    if(!value) return false;
    revision=value;
    std::copy_n(input.data+8,digest.size(),digest.begin());
    return true;
}
}
