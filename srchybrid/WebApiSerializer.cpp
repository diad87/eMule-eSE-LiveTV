#include "WebApiSerializer.h"

namespace ese {
namespace web {
namespace {

void AppendHexEscape(std::string& output, unsigned char value)
{
	static const char kHex[] = "0123456789abcdef";
	output += "\\u00";
	output += kHex[(value >> 4) & 0x0f];
	output += kHex[value & 0x0f];
}

} // namespace

std::string EscapeJson(const std::string& input)
{
	std::string output;
	output.reserve(input.size());
	for (const unsigned char value : input) {
		switch (value) {
		case '"':
			output += "\\\"";
			break;
		case '\\':
			output += "\\\\";
			break;
		case '\b':
			output += "\\b";
			break;
		case '\f':
			output += "\\f";
			break;
		case '\n':
			output += "\\n";
			break;
		case '\r':
			output += "\\r";
			break;
		case '\t':
			output += "\\t";
			break;
		default:
			if (value < 0x20)
				AppendHexEscape(output, value);
			else
				output += static_cast<char>(value);
			break;
		}
	}
	return output;
}

std::wstring EscapeHtml(
	const std::wstring& input,
	bool escapeApostropheAndNewline)
{
	std::wstring output;
	output.reserve(input.size());
	for (const wchar_t value : input) {
		switch (value) {
		case L'&':
			output += L"&amp;";
			break;
		case L'<':
			output += L"&lt;";
			break;
		case L'>':
			output += L"&gt;";
			break;
		case L'"':
			output += L"&quot;";
			break;
		case L'\'':
			if (escapeApostropheAndNewline)
				output += L"&#8217;";
			else
				output += value;
			break;
		case L'\n':
			if (escapeApostropheAndNewline)
				output += L"\\n";
			else
				output += value;
			break;
		default:
			output += value;
			break;
		}
	}
	return output;
}

std::wstring EscapeXml(const std::wstring& input)
{
	return EscapeHtml(input, false);
}

bool RunWebApiSerializerSelfTest(std::string& failure)
{
	failure.clear();
	std::string json;
	json += '"';
	json += '\\';
	json += '\b';
	json += '\f';
	json += '\n';
	json += '\r';
	json += '\t';
	json += '\x01';
	json += static_cast<char>(0x80);
	std::string expectedJson = "\\\"\\\\\\b\\f\\n\\r\\t\\u0001";
	expectedJson += static_cast<char>(0x80);
	if (EscapeJson(json) != expectedJson) {
		failure = "web API serializer changed JSON escaping";
		return false;
	}
	const std::wstring markup = L"<&>\"'\n\r\u20ac";
	if (EscapeHtml(markup, true) !=
		L"&lt;&amp;&gt;&quot;&#8217;\\n\r\u20ac") {
		failure = "web API serializer changed quoted HTML escaping";
		return false;
	}
	if (EscapeHtml(markup, false) !=
		L"&lt;&amp;&gt;&quot;'\n\r\u20ac") {
		failure = "web API serializer changed HTML text escaping";
		return false;
	}
	if (EscapeXml(L"<&>\"'\n") != L"&lt;&amp;&gt;&quot;'\n") {
		failure = "web API serializer changed XML escaping";
		return false;
	}
	return true;
}

} // namespace web
} // namespace ese
