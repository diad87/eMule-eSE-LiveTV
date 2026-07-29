#include "../WebApiSerializer.h"

#include <cstdio>
#include <string>

namespace {

int failures = 0;

void Check(bool condition, const char* message)
{
	if (!condition) {
		std::fprintf(stderr, "FAIL: %s\n", message);
		++failures;
	}
}

void TestJson()
{
	std::string controls;
	for (unsigned value = 0; value < 0x20; ++value)
		controls += static_cast<char>(value);
	const std::string escaped = ese::web::EscapeJson(controls);
	for (unsigned value = 0; value < 0x20; ++value) {
		char marker[7] = {};
		std::snprintf(marker, sizeof(marker), "\\u%04x", value);
		const bool hasShortEscape =
			(value == '\b' && escaped.find("\\b") != std::string::npos) ||
			(value == '\f' && escaped.find("\\f") != std::string::npos) ||
			(value == '\n' && escaped.find("\\n") != std::string::npos) ||
			(value == '\r' && escaped.find("\\r") != std::string::npos) ||
			(value == '\t' && escaped.find("\\t") != std::string::npos);
		Check(
			hasShortEscape || escaped.find(marker) != std::string::npos,
			"every JSON control byte must be escaped");
	}
	Check(
		ese::web::EscapeJson("\"\\/\x7f") == "\\\"\\\\/\x7f",
		"JSON quote/backslash escaping must preserve slash and DEL");
	std::string highBytes;
	for (unsigned value = 0x80; value <= 0xff; ++value)
		highBytes += static_cast<char>(value);
	Check(
		ese::web::EscapeJson(highBytes) == highBytes,
		"JSON escaping must preserve caller-owned text encoding");
}

void TestMarkup()
{
	Check(
		ese::web::EscapeHtml(L"<&>\"'\n\r", true) ==
			L"&lt;&amp;&gt;&quot;&#8217;\\n\r",
		"quoted HTML mode must match the legacy contract");
	Check(
		ese::web::EscapeHtml(L"<&>\"'\n\r", false) ==
			L"&lt;&amp;&gt;&quot;'\n\r",
		"HTML text mode must preserve apostrophe/newline");
	Check(
		ese::web::EscapeHtml(L"&lt;&#39;", true) ==
			L"&amp;lt;&amp;#39;",
		"pre-escaped entities must not bypass escaping");
	Check(
		ese::web::EscapeXml(L"<tag a=\"x\">&'\n") ==
			L"&lt;tag a=&quot;x&quot;&gt;&amp;'\n",
		"XML text escaping must match the characterized four replacements");
	const std::wstring embedded(L"\0\u20ac", 2);
	Check(
		ese::web::EscapeHtml(embedded, true) == embedded,
		"markup escaping must preserve embedded NUL and non-ASCII code units");
}

void CheckResponse(
	const ese::web::SerializedWebResponse& response,
	unsigned status,
	const char* reason,
	const char* contentType,
	const char* body,
	const char* message)
{
	Check(
		response.status_code == status &&
			response.reason_phrase == reason &&
			response.content_type == contentType &&
			response.body == body,
		message);
}

void TestResponseModels()
{
	CheckResponse(
		ese::web::Serialize(
			ese::web::WebJoinResponseModel{true, "key\"\\\n"}),
		200,
		"OK",
		"application/json",
		"{\"success\":true,\"streamKey\":\"key\\\"\\\\\\n\"}",
		"join response must own exact status, headers, schema and escaping");
	CheckResponse(
		ese::web::Serialize(
			ese::web::WebJoinResponseModel{false, "bad"}),
		400,
		"Bad Request",
		"application/json",
		"{\"success\":false,\"streamKey\":\"bad\"}",
		"failed join response must retain its exact HTTP metadata");

	CheckResponse(
		ese::web::Serialize(ese::web::WebDirectJoinResponseModel{
			false,
			true,
			false,
			"bad\"\n",
			"key\\x",
			"::1\"\t",
			0,
			"rejected",
			"why\r"}),
		400,
		"Bad Request",
		"application/json",
		"{\"success\":false,\"joined\":true,\"dialed\":false,"
		"\"error\":\"bad\\\"\\n\",\"streamKey\":\"key\\\\x\","
		"\"ip\":\"::1\\\"\\t\",\"port\":0,\"mode\":\"rejected\","
		"\"hint\":\"why\\r\"}",
		"direct-join response must serialize every caller-owned field");
	CheckResponse(
		ese::web::Serialize(ese::web::WebDirectJoinResponseModel{
			true,
			true,
			false,
			"",
			"key",
			"",
			0,
			"kad-search",
			u8"Anonymous link \u2014 searching Kad for the broadcaster (5-30 s)"}),
		200,
		"OK",
		"application/json",
		u8"{\"success\":true,\"joined\":true,\"dialed\":false,\"error\":\"\","
		u8"\"streamKey\":\"key\",\"ip\":\"\",\"port\":0,"
		u8"\"mode\":\"kad-search\",\"hint\":\"Anonymous link \u2014 searching "
		u8"Kad for the broadcaster (5-30 s)\"}",
		"direct-join response must preserve the legacy UTF-8 em dash bytes");

	CheckResponse(
		ese::web::Serialize(ese::web::WebTunnelPingResponseModel{
			true, "sent\n", "reply\"", "unused"}),
		200,
		"OK",
		"application/json",
		"{\"ok\":true,\"sent\":\"sent\\n\",\"received\":\"reply\\\"\"}",
		"successful tunnel-ping response must retain its exact schema");
	CheckResponse(
		ese::web::Serialize(ese::web::WebTunnelPingResponseModel{
			false, "unused", "unused", "timeout\t"}),
		200,
		"OK",
		"application/json",
		"{\"ok\":false,\"reason\":\"timeout\\t\"}",
		"failed tunnel-ping response must escape its reason");

	CheckResponse(
		ese::web::Serialize(ese::web::WebStringArrayResponseModel{
			"it\"ems", {"a\n", "b\\", std::string("\0x", 2)}}),
		200,
		"OK",
		"application/json; charset=utf-8",
		"{\"it\\\"ems\":[\"a\\n\",\"b\\\\\",\"\\u0000x\"]}",
		"string-array response must escape field names, values and NUL");

	Check(
		ese::web::Serialize(ese::web::WebRemoteLinkXmlResponseModel{
			true, L"added & <ready>", L"\"file\" & name"}) ==
			L"<status result=\"OK\"><description>added &amp; &lt;ready&gt;"
			L"</description><filename>&quot;file&quot; &amp; name</filename>"
			L"</status>",
		"successful remote-link XML must own its exact schema and escaping");
	Check(
		ese::web::Serialize(ese::web::WebRemoteLinkXmlResponseModel{
			false, L"wrong <password> & retry", L"ignored"}) ==
			L"<status result=\"FAILED\" reason=\"WRONG_PASSWORD\">"
			L"<description>wrong &lt;password&gt; &amp; retry</description>"
			L"</status>",
		"failed remote-link XML must omit filename and escape its description");
}

} // namespace

int main()
{
	TestJson();
	TestMarkup();
	TestResponseModels();
	std::string selfTestFailure;
	Check(
		ese::web::RunWebApiSerializerSelfTest(selfTestFailure),
		"production WebApiSerializer self-test must pass");
	if (failures != 0) {
		std::fprintf(stderr, "%d WebApiSerializer test(s) failed.\n", failures);
		return 1;
	}
	std::puts("WebApiSerializer tests passed.");
	return 0;
}
