#include "../WebRequestParser.h"

#include <cstdio>
#include <string>
#include <vector>

namespace {

int failures = 0;

void Expect(bool condition, const char* diagnostic)
{
    if (!condition) {
        std::fprintf(stderr, "FAIL: %s\n", diagnostic);
        ++failures;
    }
}

void ExpectStatus(
    const std::string& request,
    ese::web::ParseStatus expected,
    const char* diagnostic)
{
    ese::web::ParsedRequest parsed;
    const ese::web::ParseStatus actual =
        ese::web::InspectRequest(request.data(), request.size(), parsed);
    Expect(actual == expected, diagnostic);
}

} // namespace

int main()
{
    using ese::web::Method;
    using ese::web::ParseStatus;
    using ese::web::QueryStatus;
    using ese::web::CookieStatus;

    {
        const std::string wire =
            "GET /?a=one&b=two HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
        ese::web::ParsedRequest parsed;
        Expect(
            ese::web::InspectRequest(wire.data(), wire.size(), parsed) ==
                ParseStatus::Ready,
            "complete CRLF GET is ready");
        Expect(parsed.method == Method::Get, "GET method is exact");
        Expect(parsed.target == "/?a=one&b=two", "request target is preserved");
        Expect(parsed.content_length == 0u, "GET has an empty body");
        Expect(parsed.header_bytes == wire.size(), "header byte count is exact");
        Expect(
            parsed.headers.size() == 1u &&
                parsed.headers[0].name == "host" &&
                parsed.headers[0].value == "127.0.0.1",
            "headers are normalized without changing values");
    }

    {
        const std::string wire = "GET / HTTP/1.0\nHost: localhost\n\n";
        ese::web::ParsedRequest parsed;
        Expect(
            ese::web::InspectRequest(wire.data(), wire.size(), parsed) ==
                ParseStatus::Ready,
            "legacy LF request remains accepted");
        Expect(parsed.method == Method::Get, "LF request method is parsed");
        Expect(parsed.target == "/", "LF request target is parsed");
    }

    {
        const std::string head =
            "POST /ignored HTTP/1.1\r\nContent-Length: 7\r\n\r\n";
        ese::web::ParsedRequest parsed;
        Expect(
            ese::web::InspectRequest(head.data(), head.size(), parsed) ==
                ParseStatus::NeedMore,
            "partial POST waits for the declared body");
        const std::string wire = head + "a=b+cde";
        Expect(
            ese::web::InspectRequest(wire.data(), wire.size(), parsed) ==
                ParseStatus::Ready,
            "complete POST body is ready");
        Expect(parsed.method == Method::Post, "POST method is exact");
        Expect(parsed.content_length == 7u, "POST body size is exact");
    }

    {
        const std::string wire =
            "OPTIONS /api/live HTTP/1.1\r\nContent-Length: 0\r\n\r\n";
        ese::web::ParsedRequest parsed;
        Expect(
            ese::web::InspectRequest(wire.data(), wire.size(), parsed) ==
                ParseStatus::Ready,
            "OPTIONS remains supported");
        Expect(parsed.method == Method::Options, "OPTIONS method is exact");
    }

    ExpectStatus(
        "GETTING / HTTP/1.1\r\n\r\n",
        ParseStatus::BadRequest,
        "method prefix is rejected");
    ExpectStatus(
        "PUT / HTTP/1.1\r\n\r\n",
        ParseStatus::BadRequest,
        "unsupported method is rejected");
    ExpectStatus(
        "GET  HTTP/1.1\r\n\r\n",
        ParseStatus::BadRequest,
        "empty target is rejected");
    ExpectStatus(
        "GET / FTP/1.0\r\n\r\n",
        ParseStatus::BadRequest,
        "non-HTTP version is rejected");
    ExpectStatus(
        "GET / HTTP/1.1\r\nBroken\r\n\r\n",
        ParseStatus::BadRequest,
        "header without a colon is rejected");
    ExpectStatus(
        "GET / HTTP/1.1\r\n folded: value\r\n\r\n",
        ParseStatus::BadRequest,
        "obsolete folded header is rejected");
    ExpectStatus(
        "POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n",
        ParseStatus::BadRequest,
        "negative content length is rejected");
    ExpectStatus(
        "POST / HTTP/1.1\r\nContent-Length: 1x\r\n\r\n",
        ParseStatus::BadRequest,
        "content length with junk is rejected");
    ExpectStatus(
        "POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx",
        ParseStatus::BadRequest,
        "duplicate content length is rejected");
    ExpectStatus(
        "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
        ParseStatus::BadRequest,
        "unsupported transfer encoding is rejected");
    ExpectStatus(
        "POST / HTTP/1.1\r\nContent-Length: 42949672960\r\n\r\n",
        ParseStatus::BodyTooLarge,
        "overflow-sized content length is rejected");

    {
        const std::string too_long_target =
            "GET /" + std::string(ese::web::kMaxTargetBytes, 'x') +
            " HTTP/1.1\r\n\r\n";
        ExpectStatus(
            too_long_target,
            ParseStatus::TargetTooLarge,
            "target above the byte cap is rejected");
    }
    {
        const std::string too_large_header(
            ese::web::kMaxHeaderBytes + 1u, 'x');
        ExpectStatus(
            too_large_header,
            ParseStatus::HeaderTooLarge,
            "unterminated header above the byte cap is rejected");
    }
    {
        const std::string maximum_body =
            "POST / HTTP/1.1\r\nContent-Length: " +
            std::to_string(ese::web::kMaxBodyBytes) + "\r\n\r\n";
        ExpectStatus(
            maximum_body,
            ParseStatus::NeedMore,
            "body exactly at the byte cap remains admissible");
        const std::string excessive_body =
            "POST / HTTP/1.1\r\nContent-Length: " +
            std::to_string(ese::web::kMaxBodyBytes + 1u) + "\r\n\r\n";
        ExpectStatus(
            excessive_body,
            ParseStatus::BodyTooLarge,
            "body above the byte cap is rejected before allocation");
    }

    {
        std::string many_headers = "GET / HTTP/1.1\r\n";
        for (std::size_t i = 0; i <= ese::web::kMaxHeaderFields; ++i)
            many_headers += "X-" + std::to_string(i) + ": y\r\n";
        many_headers += "\r\n";
        ExpectStatus(
            many_headers,
            ParseStatus::BadRequest,
            "header field count is bounded");
    }

    {
        std::string value;
        Expect(
            ese::web::GetQueryValue("/?a=one&b=two", "b", value) ==
                QueryStatus::Ok &&
                value == "two",
            "legacy query value is preserved");
        Expect(
            ese::web::GetQueryValue("/?ab=wrong&b=right", "b", value) ==
                QueryStatus::Ok &&
                value == "right",
            "query names require exact boundaries");
        Expect(
            ese::web::GetQueryValue("/?B=upper&b=lower", "b", value) ==
                QueryStatus::Ok &&
                value == "lower",
            "query names remain case-sensitive");
        Expect(
            ese::web::GetQueryValue(
                "/?text=Hello+World%21%0A%0D%zz", "text", value) ==
                QueryStatus::Ok &&
                value == "Hello World!\n%zz",
            "form normalization preserves legacy decoding and control filtering");
        Expect(
            ese::web::GetQueryValue("/?empty=&other=x", "empty", value) ==
                QueryStatus::Ok &&
                value.empty(),
            "present empty query value is distinguishable");
        Expect(
            ese::web::GetQueryValue("/?a=one#fragment", "missing", value) ==
                QueryStatus::NotFound,
            "missing query value is reported");
    }

    {
        std::vector<std::string> values;
        Expect(
            ese::web::GetQueryValues(
                "/?downloads=ABC&downloads=Def", "downloads", values) ==
                QueryStatus::Ok,
            "repeated query values are accepted");
        Expect(
            values.size() == 2u && values[0] == "ABC" && values[1] == "Def",
            "repeated query values preserve order and case");
    }

    {
        std::string target = "/?";
        for (std::size_t i = 0; i <= ese::web::kMaxQueryFields; ++i) {
            if (i != 0u)
                target.push_back('&');
            target += "x" + std::to_string(i) + "=1";
        }
        std::string value;
        Expect(
            ese::web::GetQueryValue(target, "x0", value) ==
                QueryStatus::TooManyFields,
            "query field count is bounded");
    }

    {
        const std::string target =
            "/?x=" + std::string(ese::web::kMaxQueryValueBytes + 1u, 'v');
        std::string value;
        Expect(
            ese::web::GetQueryValue(target, "x", value) ==
                QueryStatus::ValueTooLarge,
            "individual query value size is bounded");
    }

    {
        std::string value;
        Expect(
            ese::web::GetCookieValue(
                "session=abc123; theme=dark", "session", value) ==
                CookieStatus::Ok &&
                value == "abc123",
            "cookie value is parsed by exact name");
        Expect(
            ese::web::GetCookieValue(
                "xsession=wrong; session=right", "session", value) ==
                CookieStatus::Ok &&
                value == "right",
            "cookie name boundaries are exact");
        Expect(
            ese::web::GetCookieValue(
                "Session=upper; session=lower", "session", value) ==
                CookieStatus::Ok &&
                value == "lower",
            "cookie names remain case-sensitive");
        Expect(
            ese::web::GetCookieValue("other=value", "session", value) ==
                CookieStatus::NotFound,
            "missing cookie is reported");
        Expect(
            ese::web::GetCookieValue(
                "session=one; session=two", "session", value) ==
                CookieStatus::BadCookie,
            "duplicate security cookie is rejected");
        Expect(
            ese::web::GetCookieValue("broken", "session", value) ==
                CookieStatus::BadCookie,
            "malformed cookie is rejected");
    }

    {
        std::string header;
        for (std::size_t i = 0; i <= ese::web::kMaxCookieFields; ++i) {
            if (i != 0u)
                header += ";";
            header += "c" + std::to_string(i) + "=v";
        }
        std::string value;
        Expect(
            ese::web::GetCookieValue(header, "c0", value) ==
                CookieStatus::TooManyFields,
            "cookie field count is bounded");
        const std::string large_cookie =
            "session=" +
            std::string(ese::web::kMaxCookieValueBytes + 1u, 'v');
        Expect(
            ese::web::GetCookieValue(
                large_cookie, "session", value) ==
                CookieStatus::ValueTooLarge,
            "cookie value size is bounded");
    }

    if (failures != 0) {
        std::fprintf(stderr, "%d WebRequestParser test(s) failed.\n", failures);
        return 1;
    }
    std::puts("WebRequestParser tests passed.");
    return 0;
}
