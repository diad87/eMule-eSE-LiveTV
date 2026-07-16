// SPDX-License-Identifier: MIT
#include "kad6/kad6_exit_notice.h"

#include "kad6/kad6_tags.h"

#include <algorithm>
#include <cstring>

namespace kad6 {
namespace {

bool Any(const Byte* value, std::size_t size) noexcept {
    Byte any = 0;
    for (std::size_t i = 0; i < size; ++i) any = static_cast<Byte>(any | value[i]);
    return any != 0;
}

std::string Base64Url(const Byte* input, std::size_t size) {
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string output;
    output.reserve((size * 4 + 2) / 3);
    for (std::size_t i = 0; i < size; i += 3) {
        const std::uint32_t a = input[i];
        const std::uint32_t b = i + 1 < size ? input[i + 1] : 0;
        const std::uint32_t c = i + 2 < size ? input[i + 2] : 0;
        const std::uint32_t word = (a << 16) | (b << 8) | c;
        output.push_back(alphabet[(word >> 18) & 63]);
        output.push_back(alphabet[(word >> 12) & 63]);
        if (i + 1 < size) output.push_back(alphabet[(word >> 6) & 63]);
        if (i + 2 < size) output.push_back(alphabet[word & 63]);
    }
    return output;
}

bool ValidText(const std::string& value, std::size_t max_size) noexcept {
    return value.size() <= max_size &&
        Kad6IsValidUtf8NoNul(reinterpret_cast<const Byte*>(value.data()), value.size());
}

void JsonString(const std::string& value, std::string& output) {
    static const char hex[] = "0123456789abcdef";
    output.push_back('"');
    for (unsigned char byte : value) {
        switch (byte) {
        case '"': output += "\\\""; break;
        case '\\': output += "\\\\"; break;
        case '\b': output += "\\b"; break;
        case '\f': output += "\\f"; break;
        case '\n': output += "\\n"; break;
        case '\r': output += "\\r"; break;
        case '\t': output += "\\t"; break;
        default:
            if (byte < 0x20) {
                output += "\\u00";
                output.push_back(hex[byte >> 4]);
                output.push_back(hex[byte & 15]);
            } else output.push_back(static_cast<char>(byte));
        }
    }
    output.push_back('"');
}

std::string Decimal(std::uint64_t value) {
    return std::to_string(value);
}

std::string AddressText(const Kad6Address& original) {
    Kad6Address address = original;
    Kad6AddressNormalize(address);
    if (address.family == Kad6Address::Family::IPv4) {
        return Decimal(address.addr[0]) + "." + Decimal(address.addr[1]) + "." +
            Decimal(address.addr[2]) + "." + Decimal(address.addr[3]);
    }
    if (address.family != Kad6Address::Family::IPv6) return std::string();
    std::uint16_t groups[8]{};
    for (std::size_t i = 0; i < 8; ++i)
        groups[i] = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(address.addr[i * 2]) << 8) |
             address.addr[i * 2 + 1]);
    std::size_t best_start = 8, best_length = 0;
    for (std::size_t i = 0; i < 8;) {
        if (groups[i] != 0) { ++i; continue; }
        std::size_t end = i;
        while (end < 8 && groups[end] == 0) ++end;
        if (end - i >= 2 && end - i > best_length) {
            best_start = i;
            best_length = end - i;
        }
        i = end;
    }
    static const char hex[] = "0123456789abcdef";
    std::string output;
    for (std::size_t i = 0; i < 8;) {
        if (i == best_start) {
            output += "::";
            i += best_length;
            continue;
        }
        if (!output.empty() && output.back() != ':') output.push_back(':');
        const std::uint16_t group = groups[i++];
        bool started = false;
        for (int shift = 12; shift >= 0; shift -= 4) {
            const Byte digit = static_cast<Byte>((group >> shift) & 15);
            if (digit != 0 || started || shift == 0) {
                output.push_back(hex[digit]);
                started = true;
            }
        }
    }
    return output;
}

bool EndpointLess(const K6ExitNoticeEndpoint& a,
                  const K6ExitNoticeEndpoint& b) {
    const int af = static_cast<int>(a.address.family);
    const int bf = static_cast<int>(b.address.family);
    if (af != bf) return af < bf;
    if (a.address.addr != b.address.addr) return a.address.addr < b.address.addr;
    return a.port < b.port;
}

Kad6Status Validate(const K6ExitNotice& value, bool require_signature) noexcept {
    if (value.version != 1 || !Any(value.node_pub.data(), value.node_pub.size()) ||
        !Any(value.key_id.data(), value.key_id.size()) ||
        value.endpoints.empty() || value.endpoints.size() > kK6ExitNoticeMaxEndpoints ||
        value.service_classes.empty() || value.service_classes.size() > 4 ||
        value.configured_limits.max_kbps == 0 ||
        value.configured_limits.max_sessions == 0 || value.valid_from == 0 ||
        value.valid_until <= value.valid_from ||
        value.valid_until - value.valid_from > kK6ExitNoticeMaxValiditySeconds ||
        !ValidText(value.software, 64) || value.software.empty() ||
        !ValidText(value.abuse_contact, 256) || !ValidText(value.policy_url, 256) ||
        value.notice != kK6ExitNoticeText ||
        (require_signature && !Any(value.signature.data(), value.signature.size())))
        return Kad6Status::BadValue;
    if (!value.policy_url.empty() && value.policy_url.compare(0, 8, "https://") != 0)
        return Kad6Status::BadValue;
    for (const K6ExitNoticeEndpoint& endpoint : value.endpoints)
        if ((endpoint.address.family != Kad6Address::Family::IPv4 &&
             endpoint.address.family != Kad6Address::Family::IPv6) ||
            endpoint.port == 0 || AddressText(endpoint.address).empty())
            return Kad6Status::BadValue;
    std::array<bool, 4> seen{};
    for (K6ExitNoticeService service : value.service_classes) {
        const std::size_t index = static_cast<std::size_t>(service);
        if (index >= seen.size() || seen[index]) return Kad6Status::BadValue;
        seen[index] = true;
    }
    if (static_cast<unsigned>(value.logging_policy) >
        static_cast<unsigned>(K6ExitLoggingPolicy::MinimumLegal))
        return Kad6Status::BadValue;
    return Kad6Status::Ok;
}

} // namespace

const char* K6ExitNoticeServiceName(K6ExitNoticeService value) noexcept {
    switch (value) {
    case K6ExitNoticeService::Control: return "EXIT_CONTROL";
    case K6ExitNoticeService::ExitKad: return "EXIT_KAD";
    case K6ExitNoticeService::ExitEd2kDial: return "EXIT_ED2K_DIAL";
    case K6ExitNoticeService::ExitEd2kFull: return "EXIT_ED2K_FULL";
    }
    return nullptr;
}

const char* K6ExitLoggingPolicyName(K6ExitLoggingPolicy value) noexcept {
    switch (value) {
    case K6ExitLoggingPolicy::OperatorDeclared: return "operator_declared";
    case K6ExitLoggingPolicy::AggregateOnly: return "aggregate_only";
    case K6ExitLoggingPolicy::SystemMetadataPossible: return "system_metadata_possible";
    case K6ExitLoggingPolicy::MinimumLegal: return "minimum_legal";
    }
    return nullptr;
}

Kad6Status K6ExitNoticeCanonicalJson(const K6ExitNotice& value,
                                     bool include_signature,
                                     std::string& output) {
    output.clear();
    const Kad6Status valid = Validate(value, include_signature);
    if (valid != Kad6Status::Ok) return valid;
    std::vector<K6ExitNoticeEndpoint> endpoints = value.endpoints;
    for (K6ExitNoticeEndpoint& endpoint : endpoints)
        Kad6AddressNormalize(endpoint.address);
    std::sort(endpoints.begin(), endpoints.end(), EndpointLess);
    std::vector<K6ExitNoticeService> services = value.service_classes;
    std::sort(services.begin(), services.end(), [](K6ExitNoticeService a,
                                                   K6ExitNoticeService b) {
        return static_cast<unsigned>(a) < static_cast<unsigned>(b);
    });
    output = "{\"abuse_contact\":";
    JsonString(value.abuse_contact, output);
    output += ",\"configured_limits\":{\"max_kbps\":" +
        Decimal(value.configured_limits.max_kbps) + ",\"max_sessions\":" +
        Decimal(value.configured_limits.max_sessions) + "},\"endpoints\":[";
    for (std::size_t i = 0; i < endpoints.size(); ++i) {
        if (i) output.push_back(',');
        output += "{\"address\":";
        JsonString(AddressText(endpoints[i].address), output);
        output += ",\"family\":" +
            Decimal(static_cast<unsigned>(endpoints[i].address.family)) +
            ",\"port\":" + Decimal(endpoints[i].port) + "}";
    }
    output += "],\"key_id\":";
    JsonString(Base64Url(value.key_id.data(), value.key_id.size()), output);
    output += ",\"logging_policy\":";
    JsonString(K6ExitLoggingPolicyName(value.logging_policy), output);
    output += ",\"node_pub\":";
    JsonString(Base64Url(value.node_pub.data(), value.node_pub.size()), output);
    output += ",\"notice\":";
    JsonString(value.notice, output);
    output += ",\"policy_url\":";
    JsonString(value.policy_url, output);
    output += ",\"service_classes\":[";
    for (std::size_t i = 0; i < services.size(); ++i) {
        if (i) output.push_back(',');
        JsonString(K6ExitNoticeServiceName(services[i]), output);
    }
    output += "]";
    if (include_signature) {
        output += ",\"signature\":";
        JsonString(Base64Url(value.signature.data(), value.signature.size()), output);
    }
    output += ",\"software\":";
    JsonString(value.software, output);
    output += ",\"valid_from\":";
    JsonString(Decimal(value.valid_from), output);
    output += ",\"valid_until\":";
    JsonString(Decimal(value.valid_until), output);
    output += ",\"version\":1}";
    if (output.size() > kK6ExitNoticeMaxJsonBytes) {
        output.clear();
        return Kad6Status::TooLarge;
    }
    return Kad6Status::Ok;
}

Kad6Status SignK6ExitNotice(const Kad6CryptoHooks& crypto,
                            K6ExitNotice& value, std::string& signed_json) {
    signed_json.clear();
    if (!crypto.sha256 || !crypto.ed25519_sign ||
        !crypto.sha256(value.node_pub.data(), value.node_pub.size(), value.key_id.data()))
        return Kad6Status::AuthFailed;
    std::string canonical;
    const Kad6Status status = K6ExitNoticeCanonicalJson(value, false, canonical);
    if (status != Kad6Status::Ok) return status;
    std::vector<Byte> message(kK6ExitNoticeDomain,
        kK6ExitNoticeDomain + sizeof(kK6ExitNoticeDomain) - 1);
    message.insert(message.end(), canonical.begin(), canonical.end());
    if (!crypto.ed25519_sign(nullptr, 0, message.data(), message.size(),
                             value.signature.data()))
        return Kad6Status::AuthFailed;
    return K6ExitNoticeCanonicalJson(value, true, signed_json);
}

Kad6Status VerifyK6ExitNotice(const Kad6CryptoHooks& crypto,
                              const K6ExitNotice& value) {
    if (!crypto.sha256 || !crypto.ed25519_verify) return Kad6Status::AuthFailed;
    Hash32 expected{};
    if (!crypto.sha256(value.node_pub.data(), value.node_pub.size(), expected.data()) ||
        !Kad6CtEqual(expected.data(), value.key_id.data(), expected.size()))
        return Kad6Status::AuthFailed;
    std::string canonical;
    const Kad6Status status = K6ExitNoticeCanonicalJson(value, false, canonical);
    if (status != Kad6Status::Ok) return status;
    std::vector<Byte> message(kK6ExitNoticeDomain,
        kK6ExitNoticeDomain + sizeof(kK6ExitNoticeDomain) - 1);
    message.insert(message.end(), canonical.begin(), canonical.end());
    return crypto.ed25519_verify(value.node_pub.data(), message.data(), message.size(),
        value.signature.data()) ? Kad6Status::Ok : Kad6Status::AuthFailed;
}

} // namespace kad6
