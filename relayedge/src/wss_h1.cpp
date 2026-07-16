// SPDX-License-Identifier: MIT
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>

#include "edge/wss_h1.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <limits>
#include <string>

namespace relayedge {

namespace {

constexpr char kWebSocketGuid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

char Lower(char value) noexcept {
    return static_cast<char>(std::tolower(static_cast<unsigned char>(value)));
}

std::string LowerString(const std::string& value) {
    std::string lowered = value;
    std::transform(lowered.begin(), lowered.end(), lowered.begin(), Lower);
    return lowered;
}

std::string TrimAscii(const std::string& value) {
    const std::size_t first = value.find_first_not_of(" \t");
    if (first == std::string::npos)
        return {};
    const std::size_t last = value.find_last_not_of(" \t");
    return value.substr(first, last - first + 1);
}

bool IsTokenChar(char value) noexcept {
    const unsigned char byte = static_cast<unsigned char>(value);
    if (std::isalnum(byte) != 0)
        return true;
    constexpr char extra[] = "!#$%&'*+-.^_`|~";
    return std::strchr(extra, value) != nullptr;
}

bool ContainsToken(const std::string& value, const char* wanted) {
    std::size_t position = 0;
    const std::string expected = LowerString(wanted);
    while (position <= value.size()) {
        const std::size_t comma = value.find(',', position);
        const std::size_t end = comma == std::string::npos ? value.size() : comma;
        if (LowerString(TrimAscii(value.substr(position, end - position))) == expected)
            return true;
        if (comma == std::string::npos)
            break;
        position = comma + 1;
    }
    return false;
}

int Base64Value(char value) noexcept {
    if (value >= 'A' && value <= 'Z') return value - 'A';
    if (value >= 'a' && value <= 'z') return value - 'a' + 26;
    if (value >= '0' && value <= '9') return value - '0' + 52;
    if (value == '+') return 62;
    if (value == '/') return 63;
    return -1;
}

bool DecodeWebSocketKey(const std::string& value,
                        std::array<relay::Byte, 16>& decoded) noexcept {
    if (value.size() != 24 || value[22] != '=' || value[23] != '=')
        return false;
    std::size_t output = 0;
    for (std::size_t index = 0; index < value.size(); index += 4) {
        const int a = Base64Value(value[index]);
        const int b = Base64Value(value[index + 1]);
        const int c = value[index + 2] == '=' ? 0 : Base64Value(value[index + 2]);
        const int d = value[index + 3] == '=' ? 0 : Base64Value(value[index + 3]);
        if (a < 0 || b < 0 || c < 0 || d < 0)
            return false;
        const std::uint32_t word = (static_cast<std::uint32_t>(a) << 18) |
            (static_cast<std::uint32_t>(b) << 12) |
            (static_cast<std::uint32_t>(c) << 6) | static_cast<std::uint32_t>(d);
        if (output < decoded.size()) decoded[output++] = static_cast<relay::Byte>(word >> 16);
        if (value[index + 2] != '=' && output < decoded.size())
            decoded[output++] = static_cast<relay::Byte>(word >> 8);
        if (value[index + 3] != '=' && output < decoded.size())
            decoded[output++] = static_cast<relay::Byte>(word);
    }
    return output == decoded.size();
}

std::string Base64Encode(const relay::Byte* data, std::size_t size) {
    constexpr char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string output;
    output.reserve(((size + 2) / 3) * 4);
    for (std::size_t index = 0; index < size; index += 3) {
        const std::size_t remaining = size - index;
        const std::uint32_t word = (static_cast<std::uint32_t>(data[index]) << 16) |
            (remaining > 1 ? static_cast<std::uint32_t>(data[index + 1]) << 8 : 0) |
            (remaining > 2 ? static_cast<std::uint32_t>(data[index + 2]) : 0);
        output.push_back(alphabet[(word >> 18) & 63]);
        output.push_back(alphabet[(word >> 12) & 63]);
        output.push_back(remaining > 1 ? alphabet[(word >> 6) & 63] : '=');
        output.push_back(remaining > 2 ? alphabet[word & 63] : '=');
    }
    return output;
}

bool Sha1(const relay::Byte* data,
          std::size_t size,
          std::array<relay::Byte, 20>& digest) noexcept {
    if (size > static_cast<std::size_t>((std::numeric_limits<ULONG>::max)()))
        return false;
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD object_size = 0;
    DWORD result_size = 0;
    std::vector<relay::Byte> object;
    bool ok = false;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(
            &algorithm, BCRYPT_SHA1_ALGORITHM, nullptr, 0)))
        goto cleanup;
    if (!BCRYPT_SUCCESS(BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size),
            &result_size, 0)) || object_size > 4096)
        goto cleanup;
    try {
        object.resize(object_size);
    } catch (...) {
        goto cleanup;
    }
    if (!BCRYPT_SUCCESS(BCryptCreateHash(algorithm, &hash, object.data(),
            object_size, nullptr, 0, 0)))
        goto cleanup;
    if (!BCRYPT_SUCCESS(BCryptHashData(hash, const_cast<PUCHAR>(data),
            static_cast<ULONG>(size), 0)))
        goto cleanup;
    if (!BCRYPT_SUCCESS(BCryptFinishHash(hash, digest.data(),
            static_cast<ULONG>(digest.size()), 0)))
        goto cleanup;
    ok = true;
cleanup:
    if (hash != nullptr) BCryptDestroyHash(hash);
    if (algorithm != nullptr) BCryptCloseAlgorithmProvider(algorithm, 0);
    return ok;
}

bool IsKnownOpcode(std::uint8_t opcode) noexcept {
    return opcode == static_cast<std::uint8_t>(WssOpcode::Binary) ||
           opcode == static_cast<std::uint8_t>(WssOpcode::Close) ||
           opcode == static_cast<std::uint8_t>(WssOpcode::Ping) ||
           opcode == static_cast<std::uint8_t>(WssOpcode::Pong);
}

bool IsControlOpcode(std::uint8_t opcode) noexcept {
    return (opcode & 0x08u) != 0;
}

bool ValidUtf8(const relay::Byte* data, std::size_t size) noexcept {
    std::size_t index = 0;
    while (index < size) {
        const relay::Byte first = data[index++];
        if (first <= 0x7Fu)
            continue;
        std::size_t continuation = 0;
        relay::Byte second_min = 0x80u;
        relay::Byte second_max = 0xBFu;
        if (first >= 0xC2u && first <= 0xDFu) {
            continuation = 1;
        } else if (first >= 0xE0u && first <= 0xEFu) {
            continuation = 2;
            if (first == 0xE0u) second_min = 0xA0u;
            if (first == 0xEDu) second_max = 0x9Fu;
        } else if (first >= 0xF0u && first <= 0xF4u) {
            continuation = 3;
            if (first == 0xF0u) second_min = 0x90u;
            if (first == 0xF4u) second_max = 0x8Fu;
        } else {
            return false;
        }
        if (continuation > size - index || data[index] < second_min ||
            data[index] > second_max)
            return false;
        ++index;
        for (std::size_t offset = 1; offset < continuation; ++offset, ++index) {
            if (data[index] < 0x80u || data[index] > 0xBFu)
                return false;
        }
    }
    return true;
}

bool ValidClosePayload(const relay::Byte* payload, std::size_t size) noexcept {
    if (size == 0)
        return true;
    if (payload == nullptr || size == 1)
        return false;
    const std::uint16_t code = (static_cast<std::uint16_t>(payload[0]) << 8) |
        payload[1];
    const bool valid_code =
        (code >= 1000 && code <= 1014 && code != 1004 && code != 1005 &&
         code != 1006) || (code >= 3000 && code <= 4999);
    return valid_code && ValidUtf8(payload + 2, size - 2);
}

} // namespace

relay::RelayStatus ParseWssUpgradeRequest(const relay::Byte* data,
                                          std::size_t size,
                                          WssUpgradeRequest& request) {
    request = {};
    if (data == nullptr && size != 0)
        return relay::RelayStatus::InvalidArgument;
    if (size > kMaxWssHandshakeBytes)
        return relay::RelayStatus::TooLarge;
    const std::string text(reinterpret_cast<const char*>(data), size);
    const std::size_t terminator = text.find("\r\n\r\n");
    if (terminator == std::string::npos)
        return relay::RelayStatus::Truncated;
    const std::size_t consumed = terminator + 4;
    std::size_t position = 0;
    std::size_t line_end = text.find("\r\n", position);
    if (line_end == std::string::npos || line_end > kMaxWssHeaderLineBytes)
        return relay::RelayStatus::Malformed;
    if (text.substr(0, line_end) != "GET /krp/v1 HTTP/1.1")
        return relay::RelayStatus::UnsupportedOption;
    position = line_end + 2;

    std::string host, upgrade, connection, version, key, protocol;
    bool has_extensions = false;
    bool has_transfer_encoding = false;
    bool nonzero_content_length = false;
    std::size_t header_count = 0;
    while (position < terminator) {
        line_end = text.find("\r\n", position);
        if (line_end == std::string::npos || line_end > terminator ||
            line_end - position > kMaxWssHeaderLineBytes || ++header_count > kMaxWssHeaders)
            return relay::RelayStatus::TooLarge;
        const std::string line = text.substr(position, line_end - position);
        if (line.empty() || line[0] == ' ' || line[0] == '\t')
            return relay::RelayStatus::Malformed;
        const std::size_t colon = line.find(':');
        if (colon == std::string::npos || colon == 0)
            return relay::RelayStatus::Malformed;
        const std::string name = line.substr(0, colon);
        if (!std::all_of(name.begin(), name.end(), IsTokenChar))
            return relay::RelayStatus::Malformed;
        const std::string lowered = LowerString(name);
        const std::string value = TrimAscii(line.substr(colon + 1));
        auto set_once = [&value](std::string& field) {
            if (!field.empty()) return false;
            field = value;
            return true;
        };
        if (lowered == "host") { if (!set_once(host)) return relay::RelayStatus::Malformed; }
        else if (lowered == "upgrade") { if (!set_once(upgrade)) return relay::RelayStatus::Malformed; }
        else if (lowered == "connection") { if (!set_once(connection)) return relay::RelayStatus::Malformed; }
        else if (lowered == "sec-websocket-version") { if (!set_once(version)) return relay::RelayStatus::Malformed; }
        else if (lowered == "sec-websocket-key") { if (!set_once(key)) return relay::RelayStatus::Malformed; }
        else if (lowered == "sec-websocket-protocol") { if (!set_once(protocol)) return relay::RelayStatus::Malformed; }
        else if (lowered == "sec-websocket-extensions") has_extensions = true;
        else if (lowered == "transfer-encoding") has_transfer_encoding = true;
        else if (lowered == "content-length" && value != "0") nonzero_content_length = true;
        position = line_end + 2;
    }
    std::array<relay::Byte, 16> decoded_key{};
    if (host.empty() || LowerString(upgrade) != "websocket" ||
        !ContainsToken(connection, "upgrade") || version != "13" ||
        !DecodeWebSocketKey(key, decoded_key) ||
        !ContainsToken(protocol, "krp.v1") || has_extensions ||
        has_transfer_encoding || nonzero_content_length)
        return relay::RelayStatus::UnsupportedOption;
    request.websocket_key = key;
    request.consumed = consumed;
    return relay::RelayStatus::Ok;
}

relay::RelayStatus BuildWssUpgradeResponse(const WssUpgradeRequest& request,
                                           std::vector<relay::Byte>& response) {
    std::array<relay::Byte, 16> decoded{};
    if (!DecodeWebSocketKey(request.websocket_key, decoded))
        return relay::RelayStatus::InvalidArgument;
    const std::string material = request.websocket_key + kWebSocketGuid;
    std::array<relay::Byte, 20> digest{};
    if (!Sha1(reinterpret_cast<const relay::Byte*>(material.data()), material.size(), digest))
        return relay::RelayStatus::InvalidState;
    const std::string accept = Base64Encode(digest.data(), digest.size());
    const std::string text = "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Accept: " + accept + "\r\n"
        "Sec-WebSocket-Protocol: krp.v1\r\n\r\n";
    response.assign(text.begin(), text.end());
    return relay::RelayStatus::Ok;
}

relay::RelayStatus BuildWssClientUpgradeRequest(
    const char* host,
    const char* path,
    std::vector<relay::Byte>& request,
    std::string& websocket_key) noexcept {
    request.clear();
    websocket_key.clear();
    if (host == nullptr || *host == '\0' || path == nullptr ||
        std::strcmp(path, "/krp/v1") != 0 || std::strpbrk(host, "\r\n") != nullptr)
        return relay::RelayStatus::InvalidArgument;
    std::array<relay::Byte, 16> nonce{};
    if (!BCRYPT_SUCCESS(BCryptGenRandom(nullptr, nonce.data(),
            static_cast<ULONG>(nonce.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
        return relay::RelayStatus::InvalidState;
    try {
        websocket_key = Base64Encode(nonce.data(), nonce.size());
        const std::string text = std::string("GET ") + path + " HTTP/1.1\r\n" +
            "Host: " + host + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
            "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: " + websocket_key +
            "\r\nSec-WebSocket-Protocol: krp.v1\r\n\r\n";
        if (text.size() > kMaxWssHandshakeBytes)
            return relay::RelayStatus::TooLarge;
        request.assign(text.begin(), text.end());
    } catch (...) {
        request.clear();
        websocket_key.clear();
        return relay::RelayStatus::TooLarge;
    }
    return relay::RelayStatus::Ok;
}

relay::RelayStatus ParseWssUpgradeResponse(
    const relay::Byte* data,
    std::size_t size,
    const std::string& websocket_key,
    std::size_t& consumed) {
    consumed = 0;
    std::array<relay::Byte, 16> decoded_key{};
    if ((data == nullptr && size != 0) || !DecodeWebSocketKey(websocket_key, decoded_key))
        return relay::RelayStatus::InvalidArgument;
    if (size > kMaxWssHandshakeBytes)
        return relay::RelayStatus::TooLarge;
    const std::string text(reinterpret_cast<const char*>(data), size);
    const std::size_t terminator = text.find("\r\n\r\n");
    if (terminator == std::string::npos)
        return relay::RelayStatus::Truncated;
    const std::size_t total = terminator + 4;
    const std::size_t first_end = text.find("\r\n");
    if (first_end == std::string::npos || first_end > kMaxWssHeaderLineBytes ||
        text.substr(0, first_end) != "HTTP/1.1 101 Switching Protocols")
        return relay::RelayStatus::Malformed;

    std::string upgrade, connection, accept, protocol;
    bool has_extensions = false;
    bool has_transfer_encoding = false;
    bool nonzero_content_length = false;
    std::size_t header_count = 0;
    std::size_t position = first_end + 2;
    while (position < terminator) {
        const std::size_t line_end = text.find("\r\n", position);
        if (line_end == std::string::npos || line_end > terminator ||
            line_end - position > kMaxWssHeaderLineBytes || ++header_count > kMaxWssHeaders)
            return relay::RelayStatus::TooLarge;
        const std::string line = text.substr(position, line_end - position);
        if (line.empty() || line[0] == ' ' || line[0] == '\t')
            return relay::RelayStatus::Malformed;
        const std::size_t colon = line.find(':');
        if (colon == std::string::npos || colon == 0)
            return relay::RelayStatus::Malformed;
        const std::string name = line.substr(0, colon);
        if (!std::all_of(name.begin(), name.end(), IsTokenChar))
            return relay::RelayStatus::Malformed;
        const std::string lowered = LowerString(name);
        const std::string value = TrimAscii(line.substr(colon + 1));
        auto set_once = [&value](std::string& field) {
            if (!field.empty()) return false;
            field = value;
            return true;
        };
        if (lowered == "upgrade") { if (!set_once(upgrade)) return relay::RelayStatus::Malformed; }
        else if (lowered == "connection") { if (!set_once(connection)) return relay::RelayStatus::Malformed; }
        else if (lowered == "sec-websocket-accept") { if (!set_once(accept)) return relay::RelayStatus::Malformed; }
        else if (lowered == "sec-websocket-protocol") { if (!set_once(protocol)) return relay::RelayStatus::Malformed; }
        else if (lowered == "sec-websocket-extensions") has_extensions = true;
        else if (lowered == "transfer-encoding") has_transfer_encoding = true;
        else if (lowered == "content-length" && value != "0") nonzero_content_length = true;
        position = line_end + 2;
    }

    const std::string material = websocket_key + kWebSocketGuid;
    std::array<relay::Byte, 20> digest{};
    if (!Sha1(reinterpret_cast<const relay::Byte*>(material.data()), material.size(), digest))
        return relay::RelayStatus::InvalidState;
    const std::string expected_accept = Base64Encode(digest.data(), digest.size());
    if (LowerString(upgrade) != "websocket" || !ContainsToken(connection, "upgrade") ||
        accept != expected_accept || protocol != "krp.v1" || has_extensions ||
        has_transfer_encoding || nonzero_content_length)
        return relay::RelayStatus::UnsupportedOption;
    consumed = total;
    return relay::RelayStatus::Ok;
}

relay::RelayStatus EncodeWssFrame(WssOpcode opcode,
                                  const relay::Byte* payload,
                                  std::size_t payload_size,
                                  bool mask,
                                  const std::array<relay::Byte, 4>& mask_key,
                                  std::vector<relay::Byte>& encoded) {
    const std::uint8_t opcode_value = static_cast<std::uint8_t>(opcode);
    if (!IsKnownOpcode(opcode_value) || (payload == nullptr && payload_size != 0) ||
        payload_size > kMaxWssPayloadBytes ||
        (IsControlOpcode(opcode_value) && payload_size > 125) ||
        (opcode == WssOpcode::Close && !ValidClosePayload(payload, payload_size)))
        return relay::RelayStatus::InvalidArgument;
    std::size_t header_size = 2 + (mask ? 4 : 0);
    if (payload_size >= 126 && payload_size <= 65535) header_size += 2;
    else if (payload_size > 65535) header_size += 8;
    try {
        encoded.assign(header_size + payload_size, 0);
    } catch (...) {
        return relay::RelayStatus::TooLarge;
    }
    encoded[0] = static_cast<relay::Byte>(0x80u | opcode_value);
    std::size_t position = 2;
    if (payload_size < 126) {
        encoded[1] = static_cast<relay::Byte>(payload_size);
    } else if (payload_size <= 65535) {
        encoded[1] = 126;
        encoded[position++] = static_cast<relay::Byte>(payload_size >> 8);
        encoded[position++] = static_cast<relay::Byte>(payload_size);
    } else {
        encoded[1] = 127;
        const std::uint64_t length = payload_size;
        for (int shift = 56; shift >= 0; shift -= 8)
            encoded[position++] = static_cast<relay::Byte>(length >> shift);
    }
    if (mask) {
        encoded[1] |= 0x80u;
        std::copy(mask_key.begin(), mask_key.end(), encoded.begin() + position);
        position += mask_key.size();
    }
    for (std::size_t index = 0; index < payload_size; ++index)
        encoded[position + index] = mask ? payload[index] ^ mask_key[index % 4] : payload[index];
    return relay::RelayStatus::Ok;
}

relay::RelayStatus WssFrameParser::AddBytes(const relay::Byte* data, std::size_t size) {
    if (data == nullptr && size != 0)
        return relay::RelayStatus::InvalidArgument;
    if (size == 0)
        return relay::RelayStatus::Ok;
    if (size > kMaxWssBufferedBytes - buffer_.size()) {
        buffer_.clear();
        return relay::RelayStatus::TooLarge;
    }
    try {
        buffer_.insert(buffer_.end(), data, data + size);
    } catch (...) {
        buffer_.clear();
        return relay::RelayStatus::TooLarge;
    }
    return relay::RelayStatus::Ok;
}

relay::RelayStatus WssFrameParser::Pop(WssFrame& frame) {
    frame = {};
    if (buffer_.size() < 2)
        return relay::RelayStatus::Truncated;
    const relay::Byte first = buffer_[0], second = buffer_[1];
    const bool fin = (first & 0x80u) != 0;
    const std::uint8_t opcode = first & 0x0Fu;
    const bool masked = (second & 0x80u) != 0;
    if (!fin || (first & 0x70u) != 0 || !IsKnownOpcode(opcode) ||
        masked != require_mask_)
        return relay::RelayStatus::Malformed;
    std::uint64_t payload_size = second & 0x7Fu;
    std::size_t position = 2;
    if (payload_size == 126) {
        if (buffer_.size() < position + 2)
            return relay::RelayStatus::Truncated;
        payload_size = (static_cast<std::uint64_t>(buffer_[position]) << 8) |
            buffer_[position + 1];
        position += 2;
        if (payload_size < 126)
            return relay::RelayStatus::Malformed;
    } else if (payload_size == 127) {
        if (buffer_.size() < position + 8)
            return relay::RelayStatus::Truncated;
        if ((buffer_[position] & 0x80u) != 0)
            return relay::RelayStatus::Malformed;
        payload_size = 0;
        for (std::size_t index = 0; index < 8; ++index)
            payload_size = (payload_size << 8) | buffer_[position + index];
        position += 8;
        if (payload_size <= 65535)
            return relay::RelayStatus::Malformed;
    }
    if (payload_size > kMaxWssPayloadBytes ||
        (IsControlOpcode(opcode) && payload_size > 125))
        return relay::RelayStatus::TooLarge;
    std::array<relay::Byte, 4> mask_key{};
    if (masked) {
        if (buffer_.size() < position + mask_key.size())
            return relay::RelayStatus::Truncated;
        std::copy(buffer_.begin() + position,
                  buffer_.begin() + position + mask_key.size(), mask_key.begin());
        position += mask_key.size();
    }
    if (payload_size > buffer_.size() - position)
        return relay::RelayStatus::Truncated;
    try {
        frame.payload.resize(static_cast<std::size_t>(payload_size));
    } catch (...) {
        return relay::RelayStatus::TooLarge;
    }
    for (std::size_t index = 0; index < frame.payload.size(); ++index)
        frame.payload[index] = masked
            ? buffer_[position + index] ^ mask_key[index % 4]
            : buffer_[position + index];
    if (opcode == static_cast<std::uint8_t>(WssOpcode::Close) &&
        !ValidClosePayload(frame.payload.data(), frame.payload.size()))
        return relay::RelayStatus::Malformed;
    frame.opcode = static_cast<WssOpcode>(opcode);
    buffer_.erase(buffer_.begin(), buffer_.begin() + position + frame.payload.size());
    return relay::RelayStatus::Ok;
}

} // namespace relayedge
