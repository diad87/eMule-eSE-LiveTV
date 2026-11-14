#include "EseRendezvousV2.h"
#include <algorithm>
#include <cstring>
#include <limits>

namespace ese::server::rdv {
namespace {
constexpr std::size_t MacOffset=108;
constexpr std::uint64_t BucketMilliseconds=10000;
constexpr std::uint64_t LeaseMilliseconds=60000;
constexpr std::uint64_t ChallengesPerSecond=4;

template<std::size_t Size>
bool Nonzero(const std::array<std::uint8_t,Size>& bytes) noexcept
{
    return std::any_of(bytes.begin(),bytes.end(),[](std::uint8_t value) { return value!=0; });
}

std::uint64_t Read64(const std::uint8_t* bytes) noexcept
{
    std::uint64_t value=0;
    for(unsigned i=0;i<8;++i) value=(value<<8)|bytes[i];
    return value;
}

void Write64(std::uint8_t* bytes,std::uint64_t value) noexcept
{
    for(unsigned i=0;i<8;++i) bytes[i]=static_cast<std::uint8_t>(value>>(56-i*8));
}

bool ValidFamily(std::uint8_t family) noexcept { return family==4 || family==6; }

bool Initiates(std::uint8_t type) noexcept
{
    return type==kEseWireRdv2Register || type==kEseWireRdv2Keepalive;
}

void Clear(Bytes32& secret) noexcept
{
    volatile std::uint8_t* byte=secret.data();
    for(std::size_t i=0;i<secret.size();++i) byte[i]=0;
}

bool SameContext(const SessionContext& a,const SessionContext& b) noexcept
{
    return a.epoch==b.epoch && a.session==b.session && a.generation==b.generation;
}

bool Valid(const Message& value) noexcept
{
    if(!ValidFamily(value.family) || !Nonzero(value.context.epoch) || !Nonzero(value.context.session) ||
        !value.context.generation || !value.sequence || !Nonzero(value.nonce)) return false;
    if(Initiates(value.type)) return !Nonzero(value.cookie);
    return (value.type==kEseWireRdv2Challenge || value.type==kEseWireRdv2Echo) && Nonzero(value.cookie);
}

bool ValidEndpoint(const Endpoint& endpoint) noexcept
{
    if(!ValidFamily(endpoint.family) || !endpoint.port || !Nonzero(endpoint.address)) return false;
    if(endpoint.family==4) {
        return endpoint.address[0]!=0 && endpoint.address[0]<224 &&
            std::none_of(endpoint.address.begin()+4,endpoint.address.end(),[](std::uint8_t byte) { return byte!=0; });
    }
    constexpr std::array<std::uint8_t,12> mapped{0,0,0,0,0,0,0,0,0,0,0xff,0xff};
    return endpoint.address[0]!=0xff && !std::equal(mapped.begin(),mapped.end(),endpoint.address.begin());
}

std::uint64_t AddTime(std::uint64_t now,std::uint64_t duration) noexcept
{
    const auto limit=(std::numeric_limits<std::uint64_t>::max)();
    return now>limit-duration ? limit : now+duration;
}
}

bool SameEndpoint(const Endpoint& a,const Endpoint& b) noexcept
{
    return a.family==b.family && a.port==b.port && a.address==b.address;
}

CookieSecrets::~CookieSecrets()
{
    Clear(current_);
    Clear(previous_);
}

bool CookieSecrets::Rotate(const Bytes32& newlyGenerated,std::uint64_t now) noexcept
{
    constexpr std::uint64_t rotation=600000,window=20000;
    if(!Nonzero(newlyGenerated) || newlyGenerated==current_ ||
        (Nonzero(current_) && (now<issued_ || now-issued_<rotation))) return false;
    const auto scheduled=AddTime(issued_,rotation);
    if(Nonzero(current_) && now<AddTime(scheduled,window)) {
        previous_=current_;
        previousUntil_=AddTime(scheduled,window);
    } else {
        Clear(previous_);
        previousUntil_=0;
    }
    current_=newlyGenerated;
    issued_=now;
    return true;
}

const Bytes32* CookieSecrets::Current(std::uint64_t now) const noexcept
{
    return Nonzero(current_) && now>=issued_ && now-issued_<600000 ? &current_ : nullptr;
}

const Bytes32* CookieSecrets::Previous(std::uint64_t now) const noexcept
{
    return now>=issued_ && now<previousUntil_ ? &previous_ : nullptr;
}

bool ReadContext(ByteView input,SessionContext& context) noexcept
{
    if(!input.data || input.size!=DatagramSize || std::memcmp(input.data,kEseWireRdv2Magic,8)!=0 ||
        !ValidFamily(input.data[9]) || input.data[10] || input.data[11]) return false;
    SessionContext parsed;
    std::copy_n(input.data+12,16,parsed.epoch.begin());
    std::copy_n(input.data+28,16,parsed.session.begin());
    parsed.generation=Read64(input.data+44);
    if(!parsed.generation || !Nonzero(parsed.epoch) || !Nonzero(parsed.session)) return false;
    context=parsed;
    return true;
}

bool Encode(const Message& value,const Bytes32& key,Crypto& crypto,Datagram& output) noexcept
{
    if(!Valid(value) || !Nonzero(key)) return false;
    Datagram bytes{};
    std::memcpy(bytes.data(),kEseWireRdv2Magic,8);
    bytes[8]=value.type;
    bytes[9]=value.family;
    std::copy(value.context.epoch.begin(),value.context.epoch.end(),bytes.begin()+12);
    std::copy(value.context.session.begin(),value.context.session.end(),bytes.begin()+28);
    Write64(bytes.data()+44,value.context.generation);
    Write64(bytes.data()+52,value.sequence);
    std::copy(value.nonce.begin(),value.nonce.end(),bytes.begin()+60);
    std::copy(value.cookie.begin(),value.cookie.end(),bytes.begin()+76);
    Bytes32 mac{};
    if(!crypto.Hmac(key,{bytes.data(),MacOffset},mac)) return false;
    std::copy(mac.begin(),mac.end(),bytes.begin()+MacOffset);
    output=bytes;
    return true;
}

bool Decode(ByteView input,Direction direction,const Bytes32& key,Crypto& crypto,Message& output) noexcept
{
    Message value;
    if(!ReadContext(input,value.context) || !Nonzero(key)) return false;
    value.type=input.data[8];
    if((value.type==kEseWireRdv2Challenge)!=(direction==Direction::ServerToClient)) return false;
    value.family=input.data[9];
    value.sequence=Read64(input.data+52);
    std::copy_n(input.data+60,value.nonce.size(),value.nonce.begin());
    std::copy_n(input.data+76,value.cookie.size(),value.cookie.begin());
    if(!Valid(value)) return false;
    Bytes32 mac{},expected{};
    std::copy_n(input.data+MacOffset,mac.size(),mac.begin());
    if(!crypto.Hmac(key,{input.data,MacOffset},expected) || !crypto.Equal(mac,expected)) return false;
    output=value;
    return true;
}

bool BuildCookie(const Message& message,const Endpoint& endpoint,std::uint64_t timeBucket,
    const Bytes32& secret,Crypto& crypto,Bytes32& cookie) noexcept
{
    if(!ValidEndpoint(endpoint) || endpoint.family!=message.family || !Nonzero(secret)) return false;
    constexpr auto domainSize=sizeof(kEseWireRdv2CookieDomain);
    std::array<std::uint8_t,domainSize+16+16+8+1+16+2+16+8> bytes{};
    std::memcpy(bytes.data(),kEseWireRdv2CookieDomain,domainSize);
    auto offset=domainSize;
    std::copy(message.context.epoch.begin(),message.context.epoch.end(),bytes.begin()+offset);
    offset+=16;
    std::copy(message.context.session.begin(),message.context.session.end(),bytes.begin()+offset);
    offset+=16;
    Write64(bytes.data()+offset,message.context.generation);
    offset+=8;
    bytes[offset++]=endpoint.family;
    const std::size_t count=endpoint.family==4 ? 4 : 16;
    std::copy_n(endpoint.address.begin(),count,bytes.begin()+offset);
    offset+=count;
    bytes[offset++]=static_cast<std::uint8_t>(endpoint.port>>8);
    bytes[offset++]=static_cast<std::uint8_t>(endpoint.port);
    std::copy(message.nonce.begin(),message.nonce.end(),bytes.begin()+offset);
    offset+=16;
    Write64(bytes.data()+offset,timeBucket);
    offset+=8;
    return crypto.Hmac(secret,{bytes.data(),offset},cookie);
}

ReceiveResult Session::Receive(ByteView datagram,const Endpoint& observed,const Bytes32& udpKey,
    const CookieSecrets& secrets,Crypto& crypto,std::uint64_t now) noexcept
{
    const auto* cookieSecret=secrets.Current(now);
    if(!cookieSecret) return {};
    Message message;
    if(!ValidEndpoint(observed) || !Decode(datagram,Direction::ClientToServer,udpKey,crypto,message) ||
        !SameContext(message.context,context_) || message.family!=observed.family) return {};
    auto& family=families_[message.family==4 ? 0 : 1];
    if(message.sequence<family.highWater || (!family.highWater && message.sequence!=1)) return {};
    if(message.sequence==family.highWater) {
        if(!SameEndpoint(observed,family.endpoint) ||
            !std::equal(family.lastDatagram.begin(),family.lastDatagram.end(),datagram.data)) return {};
        if(message.type==kEseWireRdv2Echo)
            return {{},Current(message.family,now),false};
        if(!family.challenge || now>=family.challengeUntil) return {};
    }
    if(Initiates(message.type)) {
        if(message.sequence==(std::numeric_limits<std::uint64_t>::max)()) return {};
        if(message.type==kEseWireRdv2Keepalive && !Current(message.family,now)) return {};
        const auto second=now/1000;
        if(second!=family.budgetBucket) { family.budgetBucket=second; family.issued=0; }
        if(family.issued>=ChallengesPerSecond) return {};
        if(message.sequence==family.highWater) {
            ++family.issued;
            return {family.challenge,{},false};
        }
        Message answer=message;
        answer.type=kEseWireRdv2Challenge;
        const auto bucket=now/BucketMilliseconds;
        Datagram encoded{};
        if(!BuildCookie(answer,observed,bucket,*cookieSecret,crypto,answer.cookie) ||
            !Encode(answer,udpKey,crypto,encoded)) return {};
        ++family.issued;
        family.endpoint=observed;
        family.request=answer;
        family.highWater=message.sequence;
        family.challenge=encoded;
        family.challengeUntil=AddTime(now,2*BucketMilliseconds);
        std::copy_n(datagram.data,DatagramSize,family.lastDatagram.begin());
        return {encoded,{},false};
    }
    if(!family.challenge || now>=family.challengeUntil || family.highWater+1!=message.sequence ||
        !SameEndpoint(observed,family.endpoint) || family.request.nonce!=message.nonce ||
        !crypto.Equal(family.request.cookie,message.cookie)) return {};
    const auto bucket=now/BucketMilliseconds;
    auto verify=[&](const Bytes32& secret,std::uint64_t issuedBucket) {
        Bytes32 expected{};
        return BuildCookie(message,observed,issuedBucket,secret,crypto,expected) && crypto.Equal(message.cookie,expected);
    };
    const auto* previousSecret=secrets.Previous(now);
    if(!verify(*cookieSecret,bucket) && !(bucket && verify(*cookieSecret,bucket-1)) &&
        !(previousSecret && (verify(*previousSecret,bucket) || (bucket && verify(*previousSecret,bucket-1))))) return {};
    const bool replaced=family.registration && !SameEndpoint(family.registration->endpoint,observed);
    family.highWater=message.sequence;
    family.challenge.reset();
    family.registration=Registration{observed,AddTime(now,LeaseMilliseconds)};
    std::copy_n(datagram.data,DatagramSize,family.lastDatagram.begin());
    return {{},family.registration,replaced};
}

std::optional<Registration> Session::Current(std::uint8_t family,std::uint64_t now) const noexcept
{
    if(!ValidFamily(family)) return std::nullopt;
    const auto& value=families_[family==4 ? 0 : 1].registration;
    return value && now<value->until ? value : std::nullopt;
}
}
