#include "WebRequestParser.h"

#include <string_view>

namespace ese {
namespace web {
namespace {

bool IsTokenCharacter(char value)
{
    const unsigned char ch = static_cast<unsigned char>(value);
    if ((ch >= '0' && ch <= '9') ||
        (ch >= 'A' && ch <= 'Z') ||
        (ch >= 'a' && ch <= 'z')) {
        return true;
    }
    switch (ch) {
        case '!':
        case '#':
        case '$':
        case '%':
        case '&':
        case '\'':
        case '*':
        case '+':
        case '-':
        case '.':
        case '^':
        case '_':
        case '`':
        case '|':
        case '~':
            return true;
        default:
            return false;
    }
}

char AsciiLower(char value)
{
    if (value >= 'A' && value <= 'Z')
        return static_cast<char>(value + ('a' - 'A'));
    return value;
}

bool EqualsAsciiCaseInsensitive(std::string_view left, std::string_view right)
{
    if (left.size() != right.size())
        return false;
    for (std::size_t index = 0; index < left.size(); ++index) {
        if (AsciiLower(left[index]) != AsciiLower(right[index]))
            return false;
    }
    return true;
}

std::string_view TrimOptionalWhitespace(std::string_view value)
{
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t'))
        value.remove_prefix(1);
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t'))
        value.remove_suffix(1);
    return value;
}

std::string AsciiLowerCopy(std::string_view value)
{
    std::string result;
    result.reserve(value.size());
    for (char character : value)
        result.push_back(AsciiLower(character));
    return result;
}

std::size_t FindHeaderEnd(const char* bytes, std::size_t byte_count)
{
    for (std::size_t index = 0; index < byte_count; ++index) {
        if (bytes[index] != '\n')
            continue;
        if (index >= 1u && bytes[index - 1u] == '\n')
            return index + 1u;
        if (index >= 3u &&
            bytes[index - 3u] == '\r' &&
            bytes[index - 2u] == '\n' &&
            bytes[index - 1u] == '\r') {
            return index + 1u;
        }
    }
    return 0;
}

bool ParseUnsignedDecimal(
    std::string_view text,
    std::size_t& value,
    bool& exceeds_limit)
{
    value = 0;
    exceeds_limit = false;
    if (text.empty())
        return false;

    for (char character : text) {
        if (character < '0' || character > '9')
            return false;
        const std::size_t digit =
            static_cast<std::size_t>(character - '0');
        if (value > (kMaxBodyBytes - digit) / 10u) {
            exceeds_limit = true;
            return false;
        }
        value = value * 10u + digit;
    }
    return true;
}

bool ParseRequestLine(std::string_view line, ParsedRequest& request)
{
    const std::size_t first_space = line.find(' ');
    if (first_space == std::string_view::npos || first_space == 0u)
        return false;
    const std::size_t second_space = line.find(' ', first_space + 1u);
    if (second_space == std::string_view::npos ||
        second_space == first_space + 1u ||
        line.find(' ', second_space + 1u) != std::string_view::npos) {
        return false;
    }

    const std::string_view method_token = line.substr(0, first_space);
    if (method_token == "GET")
        request.method = Method::Get;
    else if (method_token == "POST")
        request.method = Method::Post;
    else if (method_token == "OPTIONS")
        request.method = Method::Options;
    else
        return false;

    const std::string_view target =
        line.substr(first_space + 1u, second_space - first_space - 1u);
    if (target.empty() || target.front() != '/')
        return false;
    if (target.size() > kMaxTargetBytes)
        return true;
    for (char character : target) {
        const unsigned char ch = static_cast<unsigned char>(character);
        if (ch <= 0x20u || ch == 0x7fu)
            return false;
    }

    const std::string_view version = line.substr(second_space + 1u);
    if (version != "HTTP/1.0" && version != "HTTP/1.1")
        return false;

    request.target.assign(target.data(), target.size());
    return true;
}

int HexValue(char value)
{
    if (value >= '0' && value <= '9')
        return value - '0';
    if (value >= 'a' && value <= 'f')
        return value - 'a' + 10;
    if (value >= 'A' && value <= 'F')
        return value - 'A' + 10;
    return -1;
}

std::string NormalizeFormValue(std::string_view raw)
{
    std::string normalized;
    normalized.reserve(raw.size());
    for (std::size_t index = 0; index < raw.size(); ++index) {
        if (raw[index] == '+') {
            normalized.push_back(' ');
            continue;
        }
        if (raw[index] == '%' && index + 2u < raw.size()) {
            const int high = HexValue(raw[index + 1u]);
            const int low = HexValue(raw[index + 2u]);
            if (high >= 0 && low >= 0) {
                const char decoded = static_cast<char>((high << 4) | low);
                const unsigned char byte =
                    static_cast<unsigned char>(decoded);
                if (byte > 0x1fu || byte == 0x0au)
                    normalized.push_back(decoded);
                index += 2u;
                continue;
            }
        }
        normalized.push_back(raw[index]);
    }
    return normalized;
}

QueryStatus CollectQueryValues(
    std::string_view target,
    std::string_view field_name,
    std::vector<std::string>& values)
{
    values.clear();
    const std::size_t question = target.find('?');
    if (question == std::string_view::npos)
        return QueryStatus::NotFound;

    std::string_view query = target.substr(question + 1u);
    const std::size_t fragment = query.find('#');
    if (fragment != std::string_view::npos)
        query = query.substr(0, fragment);

    std::size_t fields = 0;
    std::size_t position = 0;
    while (position <= query.size()) {
        const std::size_t separator = query.find('&', position);
        const std::size_t end =
            separator == std::string_view::npos ? query.size() : separator;
        const std::string_view field = query.substr(position, end - position);
        ++fields;
        if (fields > kMaxQueryFields)
            return QueryStatus::TooManyFields;

        const std::size_t equals = field.find('=');
        const std::string_view name =
            equals == std::string_view::npos ? field : field.substr(0, equals);
        const std::string_view raw_value =
            equals == std::string_view::npos
                ? std::string_view()
                : field.substr(equals + 1u);
        if (name == field_name) {
            if (raw_value.size() > kMaxQueryValueBytes)
                return QueryStatus::ValueTooLarge;
            values.push_back(NormalizeFormValue(raw_value));
        }

        if (separator == std::string_view::npos)
            break;
        position = separator + 1u;
    }

    return values.empty() ? QueryStatus::NotFound : QueryStatus::Ok;
}

} // namespace

ParseStatus InspectRequest(
    const char* bytes,
    std::size_t byte_count,
    ParsedRequest& request)
{
    request = ParsedRequest();
    if (bytes == nullptr && byte_count != 0u)
        return ParseStatus::BadRequest;
    if (byte_count > kMaxRequestBytes)
        return ParseStatus::BodyTooLarge;

    const std::size_t header_bytes = FindHeaderEnd(bytes, byte_count);
    if (header_bytes == 0u) {
        return byte_count > kMaxHeaderBytes
            ? ParseStatus::HeaderTooLarge
            : ParseStatus::NeedMore;
    }
    if (header_bytes > kMaxHeaderBytes)
        return ParseStatus::HeaderTooLarge;

    const std::string_view header(bytes, header_bytes);
    if (header.find('\0') != std::string_view::npos)
        return ParseStatus::BadRequest;

    std::size_t position = 0;
    const std::size_t first_newline = header.find('\n');
    if (first_newline == std::string_view::npos)
        return ParseStatus::BadRequest;
    std::string_view request_line = header.substr(0, first_newline);
    if (!request_line.empty() && request_line.back() == '\r')
        request_line.remove_suffix(1);
    if (!ParseRequestLine(request_line, request))
        return ParseStatus::BadRequest;
    if (request.target.empty())
        return ParseStatus::TargetTooLarge;

    bool has_content_length = false;
    bool duplicate_content_length = false;
    std::size_t content_length = 0;
    std::size_t header_fields = 0;
    position = first_newline + 1u;
    while (position < header.size()) {
        const std::size_t newline = header.find('\n', position);
        if (newline == std::string_view::npos)
            return ParseStatus::BadRequest;
        std::string_view line = header.substr(position, newline - position);
        if (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);
        position = newline + 1u;
        if (line.empty())
            break;
        if (line.front() == ' ' || line.front() == '\t')
            return ParseStatus::BadRequest;
        ++header_fields;
        if (header_fields > kMaxHeaderFields)
            return ParseStatus::BadRequest;

        const std::size_t colon = line.find(':');
        if (colon == std::string_view::npos || colon == 0u)
            return ParseStatus::BadRequest;
        const std::string_view name = line.substr(0, colon);
        for (char character : name) {
            if (!IsTokenCharacter(character))
                return ParseStatus::BadRequest;
        }
        const std::string_view value =
            TrimOptionalWhitespace(line.substr(colon + 1u));
        for (char character : value) {
            const unsigned char byte =
                static_cast<unsigned char>(character);
            if ((byte < 0x20u && byte != 0x09u) || byte == 0x7fu)
                return ParseStatus::BadRequest;
        }
        HeaderField normalized_header;
        normalized_header.name = AsciiLowerCopy(name);
        normalized_header.value.assign(value.data(), value.size());
        request.headers.push_back(normalized_header);

        if (EqualsAsciiCaseInsensitive(name, "content-length")) {
            duplicate_content_length = has_content_length;
            if (duplicate_content_length)
                return ParseStatus::BadRequest;
            bool exceeds_limit = false;
            if (!ParseUnsignedDecimal(
                    value, content_length, exceeds_limit)) {
                return exceeds_limit
                    ? ParseStatus::BodyTooLarge
                    : ParseStatus::BadRequest;
            }
            has_content_length = true;
        } else if (EqualsAsciiCaseInsensitive(name, "transfer-encoding")) {
            return ParseStatus::BadRequest;
        }
    }

    request.header_bytes = header_bytes;
    request.content_length = content_length;
    if (content_length > kMaxBodyBytes)
        return ParseStatus::BodyTooLarge;
    if (byte_count - header_bytes < content_length)
        return ParseStatus::NeedMore;
    return ParseStatus::Ready;
}

QueryStatus GetQueryValue(
    const std::string& target,
    const std::string& field_name,
    std::string& value)
{
    value.clear();
    std::vector<std::string> values;
    const QueryStatus status =
        CollectQueryValues(target, field_name, values);
    if (status == QueryStatus::Ok)
        value = values.front();
    return status;
}

QueryStatus GetQueryValues(
    const std::string& target,
    const std::string& field_name,
    std::vector<std::string>& values)
{
    return CollectQueryValues(target, field_name, values);
}

CookieStatus GetCookieValue(
    const std::string& cookie_header,
    const std::string& cookie_name,
    std::string& value)
{
    value.clear();
    if (cookie_header.size() > kMaxCookieHeaderBytes)
        return CookieStatus::HeaderTooLarge;
    if (cookie_name.empty())
        return CookieStatus::BadCookie;
    for (char character : cookie_name) {
        if (!IsTokenCharacter(character))
            return CookieStatus::BadCookie;
    }

    bool found = false;
    std::size_t fields = 0;
    std::size_t position = 0;
    const std::string_view header(cookie_header);
    while (position <= header.size()) {
        const std::size_t separator = header.find(';', position);
        const std::size_t end =
            separator == std::string_view::npos ? header.size() : separator;
        const std::string_view field =
            TrimOptionalWhitespace(header.substr(position, end - position));
        ++fields;
        if (fields > kMaxCookieFields)
            return CookieStatus::TooManyFields;
        if (field.empty())
            return CookieStatus::BadCookie;

        const std::size_t equals = field.find('=');
        if (equals == std::string_view::npos || equals == 0u)
            return CookieStatus::BadCookie;
        const std::string_view name =
            TrimOptionalWhitespace(field.substr(0, equals));
        const std::string_view raw_value =
            TrimOptionalWhitespace(field.substr(equals + 1u));
        for (char character : name) {
            if (!IsTokenCharacter(character))
                return CookieStatus::BadCookie;
        }
        for (char character : raw_value) {
            const unsigned char byte =
                static_cast<unsigned char>(character);
            if (byte <= 0x20u || byte == 0x7fu)
                return CookieStatus::BadCookie;
        }
        if (name == cookie_name) {
            if (found)
                return CookieStatus::BadCookie;
            if (raw_value.size() > kMaxCookieValueBytes)
                return CookieStatus::ValueTooLarge;
            value.assign(raw_value.data(), raw_value.size());
            found = true;
        }

        if (separator == std::string_view::npos)
            break;
        position = separator + 1u;
    }
    return found ? CookieStatus::Ok : CookieStatus::NotFound;
}

bool RunCharacterizationSelfTest(std::string& failure)
{
    failure.clear();
    std::string value;
    if (GetQueryValue("/?a=one&b=two", "b", value) != QueryStatus::Ok ||
        value != "two" ||
        GetQueryValue("/?ab=wrong&b=right", "b", value) != QueryStatus::Ok ||
        value != "right") {
        failure = "web parser failed exact deterministic query";
        return false;
    }

    std::vector<std::string> values;
    if (GetQueryValues(
            "/?downloads=ABC&downloads=Def", "downloads", values)
            != QueryStatus::Ok ||
        values.size() != 2u ||
        values[0] != "ABC" ||
        values[1] != "Def") {
        failure = "web parser failed repeated query";
        return false;
    }

    const std::string request_wire =
        "POST /ignored HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Cookie: session=abc123\r\n"
        "Content-Length: 3\r\n\r\nx=1";
    ParsedRequest parsed_request;
    if (InspectRequest(
            request_wire.data(), request_wire.size(), parsed_request)
            != ParseStatus::Ready ||
        parsed_request.method != Method::Post ||
        parsed_request.content_length != 3u) {
        failure = "web request parser failed runtime request";
        return false;
    }

    if (GetCookieValue(
            "session=abc123; theme=dark", "session", value)
            != CookieStatus::Ok ||
        value != "abc123") {
        failure = "web request parser failed runtime cookie";
        return false;
    }

    const std::string hostile_request =
        "POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n";
    if (InspectRequest(
            hostile_request.data(), hostile_request.size(), parsed_request)
            != ParseStatus::BadRequest) {
        failure = "web request parser accepted hostile length";
        return false;
    }
    return true;
}

} // namespace web
} // namespace ese
