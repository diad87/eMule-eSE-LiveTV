#include "EseServerDescriptor.h"

#include <algorithm>
#include <charconv>

namespace ese::server {
namespace {
enum class Field { ServerId,Node,Host,TlsPort,QuicPort,RdvPort,Trust,Pin,Fallback,Count };
constexpr std::array<std::string_view,static_cast<std::size_t>(Field::Count)> Names{
    "server_id","server_node_pub","host","tls_port","quic_port","rdv_udp_port",
    "trust_mode","tls_spki_sha256","allow_plaintext_fallback"};

bool Nonzero(const Bytes32& bytes) noexcept
{
    return std::any_of(bytes.begin(),bytes.end(),[](std::uint8_t byte) { return byte!=0; });
}

bool DecodeHex(std::string_view value,Bytes32& bytes) noexcept
{
    if(value.size()!=bytes.size()*2) return false;
    for(std::size_t i=0;i<bytes.size();++i) {
        unsigned byte=0;
        const auto* begin=value.data()+i*2;
        const auto parsed=std::from_chars(begin,begin+2,byte,16);
        if(parsed.ec!=std::errc{} || parsed.ptr!=begin+2) return false;
        bytes[i]=static_cast<std::uint8_t>(byte);
    }
    return Nonzero(bytes);
}

bool ParsePort(std::string_view value,std::uint16_t& port) noexcept
{
    unsigned number=0;
    const auto parsed=std::from_chars(value.data(),value.data()+value.size(),number);
    if(parsed.ec!=std::errc{} || parsed.ptr!=value.data()+value.size() || !number || number>65535) return false;
    port=static_cast<std::uint16_t>(number);
    return true;
}

bool ValidHostname(std::string_view value) noexcept
{
    if(value.empty() || value.size()>253 || value.back()=='.') return false;
    while(!value.empty()) {
        const auto end=value.find('.');
        const auto label=value.substr(0,end);
        if(label.empty() || label.size()>63 || label.front()=='-' || label.back()=='-') return false;
        for(const auto byte:label)
            if(!((byte>='a' && byte<='z') || (byte>='A' && byte<='Z') || (byte>='0' && byte<='9') || byte=='-'))
                return false;
        if(end==std::string_view::npos) return true;
        value.remove_prefix(end+1);
    }
    return false;
}

bool ParseField(Field field,std::string_view value,ServerDescriptor& descriptor)
{
    switch(field) {
    case Field::ServerId: return DecodeHex(value,descriptor.serverId);
    case Field::Node: return DecodeHex(value,descriptor.node);
    case Field::Host:
        if(!ValidHostname(value)) return false;
        descriptor.host=value;
        return true;
    case Field::TlsPort: return ParsePort(value,descriptor.tlsPort);
    case Field::QuicPort: return ParsePort(value,descriptor.quicPort);
    case Field::RdvPort: return ParsePort(value,descriptor.rdvUdpPort);
    case Field::Trust:
        if(value=="PIN") descriptor.trust=DescriptorTrust::Pin;
        else if(value=="PKIX") descriptor.trust=DescriptorTrust::Pkix;
        else if(value=="TOFU") descriptor.trust=DescriptorTrust::Tofu;
        else return false;
        return true;
    case Field::Pin: return DecodeHex(value,descriptor.spkiSha256);
    case Field::Fallback:
        if(value=="true") descriptor.allowPlaintextFallback=true;
        else if(value=="false") descriptor.allowPlaintextFallback=false;
        else return false;
        return true;
    case Field::Count: return false;
    }
    return false;
}
}

bool ParseServerDescriptor(std::string_view input,AuthCrypto& crypto,ServerDescriptor& output)
{
    if(input.empty() || input.size()>2048 || input.find('\0')!=std::string_view::npos) return false;
    ServerDescriptor descriptor;
    std::array<bool,Names.size()> seen{};
    while(!input.empty()) {
        const auto newline=input.find('\n');
        auto line=input.substr(0,newline);
        if(!line.empty() && line.back()=='\r') line.remove_suffix(1);
        const auto separator=line.find('=');
        if(separator==std::string_view::npos) return false;
        const auto name=line.substr(0,separator),value=line.substr(separator+1);
        const auto known=std::find(Names.begin(),Names.end(),name);
        if(known==Names.end() || value.empty()) return false;
        const auto index=static_cast<std::size_t>(known-Names.begin());
        if(seen[index] || !ParseField(static_cast<Field>(index),value,descriptor)) return false;
        seen[index]=true;
        if(newline==std::string_view::npos) break;
        input.remove_prefix(newline+1);
    }
    for(const auto field:{Field::ServerId,Field::Node,Field::Host,Field::Trust})
        if(!seen[static_cast<std::size_t>(field)]) return false;
    if((!descriptor.tlsPort && !descriptor.quicPort) ||
        (descriptor.trust==DescriptorTrust::Pin && !Nonzero(descriptor.spkiSha256)) ||
        (descriptor.trust==DescriptorTrust::Pkix && Nonzero(descriptor.spkiSha256)))
        return false;
    Bytes32 computed{};
    if(!crypto.Hash({descriptor.node.data(),descriptor.node.size()},computed) || computed!=descriptor.serverId)
        return false;
    output=std::move(descriptor);
    return true;
}

TransportPlan::TransportPlan(const ServerDescriptor& descriptor,const TransportOptions& options) noexcept
{
    // A first-use workflow requires explicit UI and atomic durable storage.
    // When it is unavailable, even an opted-in classic fallback stays closed.
    if(descriptor.trust==DescriptorTrust::Tofu) return;
    if(options.quic && descriptor.quicPort) choices_[count_++]={Transport::Quic,descriptor.quicPort};
    if(options.tls && descriptor.tlsPort) choices_[count_++]={Transport::Tls,descriptor.tlsPort};
    if(descriptor.allowPlaintextFallback && options.explicitlyConfiguredClassicPort)
        choices_[count_++]={Transport::Classic,options.explicitlyConfiguredClassicPort};
}

std::optional<TransportChoice> TransportPlan::Current() const noexcept
{
    return current_<count_ ? std::optional<TransportChoice>(choices_[current_]) : std::nullopt;
}

void TransportPlan::Advance(DialOutcome failure) noexcept
{
    if(current_>=count_) return;
    if(failure==DialOutcome::NetworkUnavailable || failure==DialOutcome::Timeout || failure==DialOutcome::AppStalled)
        ++current_;
    else current_=count_;
}
}
