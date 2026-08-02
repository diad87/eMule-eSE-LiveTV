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

SerializedWebResponse Serialize(const WebJoinResponseModel& model)
{
	SerializedWebResponse response;
	response.status_code = model.success ? 200u : 400u;
	response.reason_phrase = model.success ? "OK" : "Bad Request";
	response.content_type = "application/json";
	response.body = "{\"success\":";
	response.body += model.success ? "true" : "false";
	response.body += ",\"streamKey\":\"";
	response.body += EscapeJson(model.stream_key);
	response.body += "\"}";
	return response;
}

SerializedWebResponse Serialize(const WebDirectJoinResponseModel& model)
{
	SerializedWebResponse response;
	response.status_code = model.success ? 200u : 400u;
	response.reason_phrase = model.success ? "OK" : "Bad Request";
	response.content_type = "application/json";
	response.body = "{\"success\":";
	response.body += model.success ? "true" : "false";
	response.body += ",\"joined\":";
	response.body += model.joined ? "true" : "false";
	response.body += ",\"dialed\":";
	response.body += model.dialed ? "true" : "false";
	response.body += ",\"error\":\"";
	response.body += EscapeJson(model.error);
	response.body += "\",\"streamKey\":\"";
	response.body += EscapeJson(model.stream_key);
	response.body += "\",\"ip\":\"";
	response.body += EscapeJson(model.ip);
	response.body += "\",\"port\":";
	response.body += std::to_string(model.port);
	response.body += ",\"mode\":\"";
	response.body += EscapeJson(model.mode);
	response.body += "\",\"hint\":\"";
	response.body += EscapeJson(model.hint);
	response.body += "\"}";
	return response;
}

SerializedWebResponse Serialize(const WebTunnelPingResponseModel& model)
{
	SerializedWebResponse response;
	response.status_code = 200;
	response.reason_phrase = "OK";
	response.content_type = "application/json";
	if (!model.success) {
		response.body = "{\"ok\":false,\"reason\":\"";
		response.body += EscapeJson(model.failure_reason);
		response.body += "\"}";
		return response;
	}
	response.body = "{\"ok\":true,\"sent\":\"";
	response.body += EscapeJson(model.sent);
	response.body += "\",\"received\":\"";
	response.body += EscapeJson(model.received);
	response.body += "\"}";
	return response;
}

SerializedWebResponse Serialize(const WebStringArrayResponseModel& model)
{
	SerializedWebResponse response;
	response.status_code = 200;
	response.reason_phrase = "OK";
	response.content_type = "application/json; charset=utf-8";
	response.body = "{\"";
	response.body += EscapeJson(model.field_name);
	response.body += "\":[";
	for (std::size_t index = 0; index < model.values.size(); ++index) {
		if (index != 0)
			response.body += ',';
		response.body += '"';
		response.body += EscapeJson(model.values[index]);
		response.body += '"';
	}
	response.body += "]}";
	return response;
}

std::wstring Serialize(const WebRemoteLinkXmlResponseModel& model)
{
	std::wstring body = L"<status result=\"";
	body += model.success ? L"OK\">" :
		L"FAILED\" reason=\"WRONG_PASSWORD\">";
	body += L"<description>";
	body += EscapeXml(model.description);
	body += L"</description>";
	if (model.success) {
		body += L"<filename>";
		body += EscapeXml(model.filename);
		body += L"</filename>";
	}
	body += L"</status>";
	return body;
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
	const SerializedWebResponse join = Serialize(
		WebJoinResponseModel{false, "bad\"key\n"});
	if (join.status_code != 400 || join.reason_phrase != "Bad Request" ||
		join.content_type != "application/json" ||
		join.body !=
			"{\"success\":false,\"streamKey\":\"bad\\\"key\\n\"}") {
		failure = "web API serializer changed join response model";
		return false;
	}
	const std::wstring remote = Serialize(WebRemoteLinkXmlResponseModel{
		true, L"added & ready", L"<unsafe>\""});
	if (remote !=
		L"<status result=\"OK\"><description>added &amp; ready</description>"
		L"<filename>&lt;unsafe&gt;&quot;</filename></status>") {
		failure = "web API serializer changed remote-link response model";
		return false;
	}
	return true;
}

} // namespace web
} // namespace ese
