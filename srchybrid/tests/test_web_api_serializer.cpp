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

} // namespace

int main()
{
	TestJson();
	TestMarkup();
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
