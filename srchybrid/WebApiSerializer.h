#pragma once

#include <string>
#include <vector>

namespace ese {
namespace web {

struct SerializedWebResponse {
	unsigned status_code = 200;
	std::string reason_phrase;
	std::string content_type;
	std::string body;
};

struct WebJoinResponseModel {
	bool success = false;
	std::string stream_key;
};

struct WebDirectJoinResponseModel {
	bool success = false;
	bool joined = false;
	bool dialed = false;
	std::string error;
	std::string stream_key;
	std::string ip;
	unsigned port = 0;
	std::string mode;
	std::string hint;
};

struct WebTunnelPingResponseModel {
	bool success = false;
	std::string sent;
	std::string received;
	std::string failure_reason;
};

struct WebStringArrayResponseModel {
	std::string field_name;
	std::vector<std::string> values;
};

struct WebRemoteLinkXmlResponseModel {
	bool success = false;
	std::wstring description;
	std::wstring filename;
};

// JSON escaping is byte-preserving for bytes >= 0x20. The caller owns text
// encoding; this function only applies the JSON string grammar.
std::string EscapeJson(const std::string& input);

// Preserves the classic WebServer contract. The optional mode additionally
// escapes apostrophes for quoted/script contexts and renders LF as "\\n".
std::wstring EscapeHtml(
	const std::wstring& input,
	bool escapeApostropheAndNewline);

// XML text uses the same four-character escaping as the legacy HTML text mode.
std::wstring EscapeXml(const std::wstring& input);

SerializedWebResponse Serialize(const WebJoinResponseModel& model);
SerializedWebResponse Serialize(const WebDirectJoinResponseModel& model);
SerializedWebResponse Serialize(const WebTunnelPingResponseModel& model);
SerializedWebResponse Serialize(const WebStringArrayResponseModel& model);
std::wstring Serialize(const WebRemoteLinkXmlResponseModel& model);

bool RunWebApiSerializerSelfTest(std::string& failure);

} // namespace web
} // namespace ese
