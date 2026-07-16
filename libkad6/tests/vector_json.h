// SPDX-License-Identifier: MIT
// Tiny read-only helper for the deliberately flat K6-0 vector schema. It is
// not a general JSON parser; malformed/missing fields fail closed in tests.
#pragma once

#include "kad6/kad6_types.h"

#include <cctype>
#include <cstddef>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace kad6_vectors {

inline std::string LoadText(const char* path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return {};
    std::ostringstream out;
    out << file.rdbuf();
    return out.str();
}

inline std::string ObjectById(const std::string& json, const char* id) {
    const std::string needle = std::string("\"id\": \"") + id + "\"";
    const std::size_t idPos = json.find(needle);
    if (idPos == std::string::npos) return {};
    const std::size_t begin = json.rfind('{', idPos);
    const std::size_t end = json.find('}', idPos);
    if (begin == std::string::npos || end == std::string::npos || end < begin) return {};
    return json.substr(begin, end - begin + 1);
}

inline std::string StringField(const std::string& object, const char* key) {
    const std::string needle = std::string("\"") + key + "\"";
    std::size_t pos = object.find(needle);
    if (pos == std::string::npos) return {};
    pos = object.find(':', pos + needle.size());
    if (pos == std::string::npos) return {};
    pos = object.find('"', pos + 1);
    if (pos == std::string::npos) return {};
    const std::size_t end = object.find('"', pos + 1);
    if (end == std::string::npos) return {};
    return object.substr(pos + 1, end - pos - 1);
}

inline int HexNibble(char c) noexcept {
    if (c >= '0' && c <= '9') return c - '0';
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    return -1;
}

inline bool HexToBytes(const std::string& hex, std::vector<kad6::Byte>& out) {
    out.clear();
    if ((hex.size() & 1u) != 0) return false;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        const int hi = HexNibble(hex[i]);
        const int lo = HexNibble(hex[i + 1]);
        if (hi < 0 || lo < 0) { out.clear(); return false; }
        out.push_back(static_cast<kad6::Byte>((hi << 4) | lo));
    }
    return true;
}

inline std::string BytesToHex(const kad6::Byte* data, std::size_t len) {
    static const char digits[] = "0123456789abcdef";
    std::string out(len * 2, '0');
    for (std::size_t i = 0; i < len; ++i) {
        out[2 * i] = digits[data[i] >> 4];
        out[2 * i + 1] = digits[data[i] & 15];
    }
    return out;
}

inline std::string BytesToHex(const std::vector<kad6::Byte>& bytes) {
    return BytesToHex(bytes.data(), bytes.size());
}

} // namespace kad6_vectors
