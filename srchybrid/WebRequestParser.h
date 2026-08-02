#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace ese {
namespace web {

constexpr std::size_t kMaxHeaderBytes = 32u * 1024u;
constexpr std::size_t kMaxTargetBytes = 8u * 1024u;
constexpr std::size_t kMaxBodyBytes = 1024u * 1024u;
constexpr std::size_t kMaxRequestBytes = kMaxHeaderBytes + kMaxBodyBytes;
constexpr std::size_t kMaxHeaderFields = 128u;
constexpr std::size_t kMaxQueryFields = 128u;
constexpr std::size_t kMaxQueryValueBytes = 64u * 1024u;
constexpr std::size_t kMaxCookieHeaderBytes = 8u * 1024u;
constexpr std::size_t kMaxCookieFields = 64u;
constexpr std::size_t kMaxCookieValueBytes = 4u * 1024u;

enum class Method {
    Get,
    Post,
    Options
};

enum class ParseStatus {
    NeedMore,
    Ready,
    BadRequest,
    HeaderTooLarge,
    TargetTooLarge,
    BodyTooLarge
};

struct HeaderField {
    std::string name;
    std::string value;
};

struct ParsedRequest {
    Method method = Method::Get;
    std::string target;
    std::vector<HeaderField> headers;
    std::size_t header_bytes = 0;
    std::size_t content_length = 0;
};

enum class QueryStatus {
    Ok,
    NotFound,
    AmbiguousField,
    TooManyFields,
    ValueTooLarge
};

enum class CookieStatus {
    Ok,
    NotFound,
    BadCookie,
    HeaderTooLarge,
    TooManyFields,
    ValueTooLarge
};

ParseStatus InspectRequest(
    const char* bytes,
    std::size_t byte_count,
    ParsedRequest& request);

QueryStatus GetQueryValue(
    const std::string& target,
    const std::string& field_name,
    std::string& value);

QueryStatus GetQueryValues(
    const std::string& target,
    const std::string& field_name,
    std::vector<std::string>& values);

CookieStatus GetCookieValue(
    const std::string& cookie_header,
    const std::string& cookie_name,
    std::string& value);

bool RunCharacterizationSelfTest(std::string& failure);

} // namespace web
} // namespace ese
