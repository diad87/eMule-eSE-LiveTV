#include "EseChannelBinding.h"
#include <algorithm>
#include <cstring>

namespace ese { namespace binding {
namespace {
template<std::size_t N> bool Nonzero(const std::array<std::uint8_t,N>& a) noexcept {
    return std::any_of(a.begin(),a.end(),[](std::uint8_t b){ return b!=0; });
}
bool Valid(const Hello& h) noexcept {
    return h.role<=1 && Nonzero(h.node) && Nonzero(h.attempt) && Nonzero(h.nonce);
}
}
bool EncodeHello(const Hello& h, std::array<std::uint8_t,HelloSize>& out) noexcept {
    if(!Valid(h) || (h.caps & ~KnownCaps)) return false;
    std::array<std::uint8_t,HelloSize> b{};
    b[0]=1; b[1]=h.role;
    std::copy(h.node.begin(),h.node.end(),b.begin()+2);
    std::copy(h.userHash.begin(),h.userHash.end(),b.begin()+34);
    std::copy(h.attempt.begin(),h.attempt.end(),b.begin()+50);
    for(unsigned i=0;i<8;++i) b[66+i]=static_cast<std::uint8_t>(h.topologyGeneration >> (56-8*i));
    std::copy(h.nonce.begin(),h.nonce.end(),b.begin()+74);
    for(unsigned i=0;i<4;++i) b[106+i]=static_cast<std::uint8_t>(h.caps >> (24-8*i));
    out=b; return true;
}
bool DecodeHello(const std::uint8_t* b, std::size_t n, Hello& out) noexcept {
    if(!b || n!=HelloSize || b[0]!=1 || b[1]>1) return false;
    Hello h; h.role=b[1];
    std::copy_n(b+2,32,h.node.begin()); std::copy_n(b+34,16,h.userHash.begin());
    std::copy_n(b+50,16,h.attempt.begin()); std::copy_n(b+74,32,h.nonce.begin());
    for(unsigned i=0;i<8;++i) h.topologyGeneration=(h.topologyGeneration<<8)|b[66+i];
    for(unsigned i=0;i<4;++i) h.caps=(h.caps<<8)|b[106+i];
    if(!Valid(h)) return false;
    // Preserve unknown bits in the transcript; never negotiate them.
    out=h; return true;
}
std::array<std::uint8_t,81> AuthMessage(const std::array<std::uint8_t,32>& exporter,
    const std::array<std::uint8_t,32>& context, std::uint8_t role) noexcept {
    const auto& domain=wire::kEseWirePeerAuthDomain;
    static_assert(sizeof(domain)==16,"signature domain includes NUL");
    std::array<std::uint8_t,81> b{};
    std::memcpy(b.data(),domain,sizeof(domain));
    std::copy(exporter.begin(),exporter.end(),b.begin()+16);
    std::copy(context.begin(),context.end(),b.begin()+48); b[80]=role;
    return b;
}
ReadResult ControlReader::Feed(const std::uint8_t* p,std::size_t n,std::size_t& consumed) noexcept {
    consumed=0;
    if(invalid_) return ReadResult::Invalid;
    if(n && !p) { invalid_=true; return ReadResult::Invalid; }
    if(ready_) { ready_=false; used_=length_=0; }
    while(consumed<n) {
        const std::size_t target=used_<4 ? 4 : length_+4;
        const std::size_t take=(std::min)(target-used_,n-consumed);
        std::copy_n(p+consumed,take,bytes_.begin()+used_); consumed+=take; used_+=take;
        if(used_==4 && !length_) {
            for(unsigned i=0;i<4;++i) length_=(length_<<8)|bytes_[i];
            if(!length_ || length_>MaxControlLength) { invalid_=true; return ReadResult::Invalid; }
        }
        if(length_ && used_==length_+4) {
            if(bytes_[4]<wire::kEseWireControlHello || bytes_[4]>wire::kEseWireControlDvlDisable) { invalid_=true; return ReadResult::Invalid; }
            ready_=true; return ReadResult::Frame;
        }
    }
    return ReadResult::NeedMore;
}
Session::Session(const Hello& h,const std::array<std::uint8_t,32>& expected,
    const std::array<std::uint8_t,32>* pin,bool persistent,bool tlsComplete,std::uint64_t started) noexcept
    : local_(h),expected_(expected),started_(started),hasPin_(pin!=nullptr) {
    if(pin) pin_=*pin;
    if(!persistent || !tlsComplete || !Nonzero(expected_) || !EncodeHello(h,localWire_) ||
        !(h.caps & wire::kEseWireCapQuicStream) || (pin && !Nonzero(*pin))) Fail(Failure::InvalidConfig);
}
bool Session::Fail(Failure f) noexcept {
    if(failure_==Failure::None) failure_=f;
    return false;
}
bool Session::LocalHello(std::array<std::uint8_t,HelloSize>& out) noexcept {
    if(failure_!=Failure::None) return false;
    if(sentHello_) return Fail(Failure::WrongState);
    out=localWire_; sentHello_=true; return true;
}
bool Session::RemoteHello(const std::uint8_t* p,std::size_t n) noexcept {
    if(failure_!=Failure::None) return false;
    if(gotHello_) return Fail(Failure::WrongState);
    Hello h;
    if(!DecodeHello(p,n,h)) return Fail(Failure::Malformed);
    if(hasPin_ && h.node!=pin_) return Fail(Failure::PinChanged);
    if(h.node!=expected_ || h.role==local_.role || h.attempt!=local_.attempt || !(h.caps&wire::kEseWireCapQuicStream))
        return Fail(Failure::IdentityMismatch);
    remote_=h; std::copy_n(p,n,remoteWire_.begin()); gotHello_=true; return true;
}
bool Session::Message(Crypto& crypto,std::uint8_t role,std::array<std::uint8_t,81>& out) noexcept {
    std::array<std::uint8_t,HelloSize*2> transcript{};
    const auto& first=local_.role==0 ? localWire_ : remoteWire_;
    const auto& second=local_.role==0 ? remoteWire_ : localWire_;
    std::copy(first.begin(),first.end(),transcript.begin());
    std::copy(second.begin(),second.end(),transcript.begin()+HelloSize);
    std::array<std::uint8_t,32> context{},exporter{};
    if(!crypto.Hash(transcript.data(),transcript.size(),context) || !crypto.Export(context,exporter))
        return Fail(Failure::CryptoFailed);
    out=AuthMessage(exporter,context,role); return true;
}
bool Session::LocalAuth(Crypto& crypto,std::array<std::uint8_t,AuthSize>& out) noexcept {
    if(failure_!=Failure::None) return false;
    if(!sentHello_ || !gotHello_ || madeAuth_) return Fail(Failure::WrongState);
    std::array<std::uint8_t,81> message{}; std::array<std::uint8_t,64> signature{};
    if(!Message(crypto,local_.role,message)) return false;
    if(!crypto.Sign(message.data(),message.size(),signature)) return Fail(Failure::CryptoFailed);
    out[0]=local_.role; std::copy(signature.begin(),signature.end(),out.begin()+1);
    madeAuth_=true; return true;
}
bool Session::AuthSent() noexcept {
    if(failure_!=Failure::None) return false;
    if(!madeAuth_ || sentAuth_) return Fail(Failure::WrongState);
    sentAuth_=true; return true;
}
bool Session::RemoteAuth(Crypto& crypto,const std::uint8_t* p,std::size_t n) noexcept {
    if(failure_!=Failure::None) return false;
    if(!sentHello_ || !gotHello_ || verified_) return Fail(Failure::WrongState);
    if(!p || n!=AuthSize || p[0]!=remote_.role) return Fail(Failure::Malformed);
    std::array<std::uint8_t,81> message{};
    if(!Message(crypto,remote_.role,message)) return false;
    if(!crypto.Verify(remote_.node,message.data(),message.size(),p+1)) return Fail(Failure::IdentityMismatch);
    verified_=true; return true;
}
void Session::Tick(std::uint64_t now) noexcept {
    if(!Ready() && failure_==Failure::None && now>=started_ && now-started_>=5000)
        Fail(Failure::AuthTimeout);
}
ControlExchange::ControlExchange(const Hello& h,const std::array<std::uint8_t,32>& expected,
    const std::array<std::uint8_t,32>* pin,bool persistent,bool tls,std::uint64_t started) noexcept
    : session_(h,expected,pin,persistent,tls,started) {
    std::array<std::uint8_t,HelloSize> hello{};
    if(session_.LocalHello(hello)) Append(wire::kEseWireControlHello,hello.data(),hello.size());
}
void ControlExchange::Append(std::uint8_t type,const std::uint8_t* p,std::size_t n) noexcept {
    const auto length=static_cast<std::uint32_t>(n+1);
    for(unsigned i=0;i<4;++i) output_[size_++]=static_cast<std::uint8_t>(length>>(24-8*i));
    output_[size_++]=type; std::copy_n(p,n,output_.begin()+size_); size_+=n;
}
bool ControlExchange::Fail(Failure f) noexcept {
    if(error_==Failure::None) error_=f;
    return false;
}
ControlBytes ControlExchange::Pending() const noexcept {
    if(Error()!=Failure::None || submitted_==size_) return {};
    return {output_.data()+submitted_,size_-submitted_};
}
bool ControlExchange::QueueClose(std::uint16_t reason) noexcept {
    if(!Ready() || reason<wire::kEseWireCloseNoCandidate ||
        reason>wire::kEseWireCloseLegacyCallbackUnavailable) return false;
    if(closeReason_) return closeReason_==reason;
    const std::uint8_t payload[]={static_cast<std::uint8_t>(reason>>8),static_cast<std::uint8_t>(reason)};
    Append(wire::kEseWireControlClose,payload,sizeof(payload));
    closeReason_=reason;
    return true;
}
bool ControlExchange::SubmittedThrough(std::size_t offset) noexcept {
    if(Error()!=Failure::None) return false;
    if(offset<submitted_ || offset>size_) return Fail(Failure::WrongState);
    submitted_=offset;
    if(authQueued_ && !authSent_ && submitted_==size_) {
        if(!session_.AuthSent()) return false;
        authSent_=true;
    }
    return true;
}
bool ControlExchange::Receive(Crypto& crypto,const std::uint8_t* p,std::size_t n,ControlSink* sink) noexcept {
    if(Error()!=Failure::None) return false;
    if(n && !p) return Fail(Failure::Malformed);
    std::size_t offset=0;
    while(offset<n) {
        std::size_t consumed=0;
        const auto result=reader_.Feed(p+offset,n-offset,consumed); offset+=consumed;
        if(result==ReadResult::Invalid) return Fail(Failure::Malformed);
        if(result==ReadResult::NeedMore) break;
        const auto type=reader_.Type(); const auto* payload=reader_.Payload(); const auto length=reader_.PayloadSize();
        if(type==wire::kEseWireControlHello) {
            if(!session_.RemoteHello(payload,length)) return false;
            std::array<std::uint8_t,AuthSize> auth{};
            if(!session_.LocalAuth(crypto,auth)) return false;
            Append(wire::kEseWireControlAuth,auth.data(),auth.size()); authQueued_=true;
        } else if(type==wire::kEseWireControlAuth) {
            if(!session_.RemoteAuth(crypto,payload,length)) return false;
        } else {
            if(!Ready() || ((type==wire::kEseWireControlCreditRequest || type==wire::kEseWireControlCreditReport) &&
                !(SelectedCaps()&wire::kEseWireCapRemoteCredit)) ||
                (type>=wire::kEseWireControlDvlEnable && !(SelectedCaps()&wire::kEseWireCapDvlProfile))) return Fail(Failure::WrongState);
            if(!sink || !sink->Frame(type,payload,length)) return Fail(Failure::Malformed);
        }
    }
    return true;
}
} }
