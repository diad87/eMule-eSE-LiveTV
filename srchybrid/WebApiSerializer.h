#pragma once

#include <string>

namespace ese {
namespace web {

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

bool RunWebApiSerializerSelfTest(std::string& failure);

} // namespace web
} // namespace ese
