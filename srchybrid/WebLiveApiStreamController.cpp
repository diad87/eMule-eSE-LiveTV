#include "WebLiveApiStreamController.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace {
bool EqualNoCase(const std::string& left, const char* right)
{
	if (left.size() != std::strlen(right)) return false;
	for (std::size_t i = 0; i < left.size(); ++i)
		if (std::tolower(static_cast<unsigned char>(left[i])) !=
			std::tolower(static_cast<unsigned char>(right[i]))) return false;
	return true;
}
std::uint16_t LegacyUInt16(const std::string& text)
{
	char* end = 0; const long value = std::strtol(text.c_str(), &end, 10);
	return static_cast<std::uint16_t>(value);
}
std::string Bool(bool value) { return value ? "true" : "false"; }
void Fail(W8LiveStreamResponse& out)
{
	out.status = 400; out.reason = "Bad Request";
}
std::string HttpEscapeTitle(const std::string& input)
{
	static const char hex[] = "0123456789ABCDEF"; std::string out;
	for (unsigned char c : input) {
		if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) out += static_cast<char>(c);
		else if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v') out += '+';
		else { out += '%'; out += hex[c >> 4]; out += hex[c & 15]; }
	}
	return out;
}
bool ParseLink(const std::string& link, std::string& key, std::string& ip,
	std::string& port, std::string& title)
{
	if (link.empty() || !key.empty()) return false;
	std::string parts[6]; std::size_t begin = 0; unsigned count = 0;
	while (count < 6) { const std::size_t end = link.find('|', begin);
		parts[count++] = link.substr(begin, end == std::string::npos ? end : end - begin);
		if (end == std::string::npos) break; begin = end + 1; }
	if (count < 5 || !EqualNoCase(parts[1], "live")) return false;
	key = parts[2]; const std::string& endpoint = parts[3];
	if (!endpoint.empty() && endpoint[0] == '[') {
		const std::size_t close = endpoint.find(']');
		if (close > 1 && close + 1 < endpoint.size() && endpoint[close + 1] == ':') {
			ip = endpoint.substr(1, close - 1); port = endpoint.substr(close + 2); }
	} else { const std::size_t colon = endpoint.rfind(':');
		if (colon != std::string::npos && colon > 0) { ip = endpoint.substr(0, colon); port = endpoint.substr(colon + 1); } }
	if (title.empty()) title = parts[4]; return true;
}
W8LiveStreamAddress ParseAddress(const std::string& ip, const std::string& port,
	W8LiveStreamPort& service)
{
	W8LiveStreamAddress out; if (ip.empty() || port.empty()) return out;
	out.port = LegacyUInt16(port); const bool ipv6 = ip.find(':') != std::string::npos;
	if (out.port && service.IsUsableAddress(ip, ipv6)) {
		out.family = ipv6 ? W8LiveStreamAddress::Family::IPv6 : W8LiveStreamAddress::Family::IPv4;
		out.text = ip;
	} else out.port = 0; return out;
}
void DirectReply(W8LiveStreamResponse& out, bool success, bool joined, bool dialed,
	const char* error, const std::string& key, const std::string& ip, unsigned port,
	const char* mode, const char* hint)
{
	if (!success) Fail(out);
	out.body = "{\"success\":" + Bool(success) + ",\"joined\":" + Bool(joined) +
		",\"dialed\":" + Bool(dialed) + ",\"error\":\"" + W8EscapeJson(error) +
		"\",\"streamKey\":\"" + W8EscapeJson(key) + "\",\"ip\":\"" +
		W8EscapeJson(ip) + "\",\"port\":" + std::to_string(port) +
		",\"mode\":\"" + mode + "\",\"hint\":\"" + W8EscapeJson(hint) + "\"}";
}
} // namespace

std::string W8EscapeJson(const std::string& input)
{
	static const char hex[] = "0123456789abcdef"; std::string out;
	for (unsigned char c : input) {
		if (c == '"') out += "\\\""; else if (c == '\\') out += "\\\\";
		else if (c == '\b') out += "\\b"; else if (c == '\f') out += "\\f";
		else if (c == '\n') out += "\\n"; else if (c == '\r') out += "\\r";
		else if (c == '\t') out += "\\t"; else if (c < 0x20) {
			out += "\\u00"; out += hex[c >> 4]; out += hex[c & 15];
		} else out += static_cast<char>(c);
	} return out;
}
std::string W8EncodeKey16(const std::array<unsigned char, 16>& key)
{
	static const char hex[] = "0123456789abcdef"; std::string out(32, '0');
	for (unsigned i = 0; i < key.size(); ++i) { out[i * 2] = hex[key[i] >> 4]; out[i * 2 + 1] = hex[key[i] & 15]; }
	return out;
}
bool W8DecodeKey16(const std::string& input, std::array<unsigned char, 16>& key)
{
	if (input.size() != 32) return false;
	auto nibble = [](unsigned char c) -> int { if (c >= '0' && c <= '9') return c - '0'; c = static_cast<unsigned char>(std::tolower(c)); return c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1; };
	for (unsigned i = 0; i < key.size(); ++i) { const int high = nibble(input[i * 2]), low = nibble(input[i * 2 + 1]); if (high < 0 || low < 0) return false; key[i] = static_cast<unsigned char>((high << 4) | low); }
	return true;
}
std::string W8BuildLiveStreamHeader(const W8LiveStreamResponse& response)
{
	std::string header = "HTTP/1.1 " + std::to_string(response.status) + " " + response.reason + "\r\nContent-Type: " + response.content_type + "\r\n";
	if (response.cors) header += "Access-Control-Allow-Origin: http://127.0.0.1\r\n";
	if (response.nosniff) header += "X-Content-Type-Options: nosniff\r\n";
	return header + "Content-Length: " + std::to_string(response.body.size()) + "\r\n\r\n";
}
bool RunW8LiveStreamApi(const W8LiveStreamRequest& in, W8LiveStreamPort& service, W8LiveStreamResponse& out)
{
	out = W8LiveStreamResponse(); std::array<unsigned char, 16> key{};
	if (in.operation == W8LiveStreamOperation::Join) {
		const bool valid = service.IsAvailable() && W8DecodeKey16(in.key, key); bool joined = false, dialed = false;
		const std::string& title = !in.ui_title.empty() ? in.ui_title : in.title;
		if (valid) service.Join(key, title.empty() ? "Live" : title, W8LiveStreamAddress(), joined, dialed);
		if (!joined) Fail(out); out.body = "{\"success\":" + Bool(joined) + ",\"streamKey\":\"" + W8EscapeJson(in.key) + "\"}"; return true;
	}
	if (in.operation == W8LiveStreamOperation::Leave) {
		const bool has = !in.key.empty() && W8DecodeKey16(in.key, key); const bool was = service.IsAvailable() && service.Leave(key, has);
		out.body = "{\"success\":true,\"wasViewing\":" + Bool(was) + "}"; return true;
	}
	if (in.operation == W8LiveStreamOperation::PlayerAlive) {
		if (service.IsAvailable()) { bool matches = in.key.empty(); std::array<unsigned char, 16> current{};
			if (!in.key.empty()) matches = W8DecodeKey16(in.key, key) && service.CopyViewerKey(current) && key == current;
			if (matches) service.NotePlayerFetch(); }
		out.cors = false; out.nosniff = false; out.body = "{\"success\":true}"; return true;
	}
	if (in.operation == W8LiveStreamOperation::BroadcastStop) {
		const bool was = service.IsAvailable() && service.StopBroadcast(); out.nosniff = false;
		out.body = "{\"success\":true,\"was_broadcasting\":" + Bool(was) + "}"; return true;
	}
	if (in.operation == W8LiveStreamOperation::BroadcastStart) {
		const std::string wireSource = in.source.empty() ? "testpattern" : in.source;
		W8LiveBroadcastRequest request{!in.ui_source.empty() ? in.ui_source : wireSource, !in.ui_title.empty() ? in.ui_title : (in.title.empty() ? "eSE Live" : in.title), !in.ui_category.empty() ? in.ui_category : (in.category.empty() ? "General" : in.category), !in.ui_language.empty() ? in.ui_language : (in.language.empty() ? "Spanish" : in.language), !in.ui_file.empty() ? in.ui_file : in.file, LegacyUInt16(in.bitrate)};
		if (!request.bitrate) request.bitrate = 1500; bool ok = service.IsAvailable() && service.StartBroadcast(request), ready = false, waiting = false; int chunks = 0;
		if (ok) { const bool rtmp = EqualNoCase(wireSource, "rtmp"); const std::uint32_t start = service.NowMs(), limit = rtmp ? 1500u : 14000u;
			for (;;) { bool alive = false; service.BroadcastLiveness(alive, chunks); if (!alive) { service.StopBroadcast(); ok = false; break; } if (chunks >= 3) { ready = true; break; }
				if (static_cast<std::uint32_t>(service.NowMs() - start) >= limit) { if (rtmp) waiting = true; else { service.StopBroadcast(); ok = false; } break; } service.PauseMs(100); }
		}
		std::string link, anonymous, direct; if (ok && service.CopyBroadcastKey(key)) { const std::string hex = W8EncodeKey16(key), title = in.title_encoded_wire.empty() ? HttpEscapeTitle(request.title) : in.title_encoded_wire, ip = service.PublicIPv4Text(); anonymous = "ed2k://|live|" + hex + "||" + title + "|/"; const std::uint16_t port = service.AdvertisedPort(); if (!ip.empty() && port) direct = "ed2k://|live|" + hex + "|" + ip + ':' + std::to_string(port) + '|' + title + "|/"; link = ((in.direct == "1" || EqualNoCase(in.direct, "true")) && !direct.empty()) ? direct : anonymous; }
		if (!ok) Fail(out); const char* state = ready ? "ready" : (waiting ? "waiting_input" : "failed");
		out.body = "{\"success\":" + Bool(ok) + ",\"ready\":" + Bool(ready) + ",\"state\":\"" + state + "\",\"chunks\":" + std::to_string(chunks) + ",\"source\":\"" + W8EscapeJson(wireSource) + "\",\"bitrate\":" + std::to_string(request.bitrate) + ",\"link\":\"" + W8EscapeJson(link) + "\"";
		if (ok && !anonymous.empty()) out.body += ",\"link_anonymous\":\"" + W8EscapeJson(anonymous) + "\",\"link_direct\":\"" + W8EscapeJson(direct.empty() ? anonymous : direct) + "\""; out.body += '}'; return true;
	}
	if (in.operation == W8LiveStreamOperation::DirectJoin) {
		std::string supplied = in.key, ip = in.ip, port = in.port, wireTitle = in.title; const bool explicitKey = !supplied.empty(); ParseLink(in.link, supplied, ip, port, wireTitle);
		std::string title = !in.ui_title.empty() ? in.ui_title : wireTitle;
		if (!explicitKey && in.ui_title.empty() && !in.ui_link.empty()) { std::string ignoredKey, ignoredIp, ignoredPort, uiTitle; ParseLink(in.ui_link, ignoredKey, ignoredIp, ignoredPort, uiTitle); if (!uiTitle.empty()) title = uiTitle; }
		if (title.empty()) title = "Live";
		const bool valid = service.IsAvailable() && W8DecodeKey16(supplied, key); W8LiveStreamAddress address = valid ? ParseAddress(ip, port, service) : W8LiveStreamAddress(); const bool socks4 = address.family == W8LiveStreamAddress::Family::IPv6 && service.IsUnsupportedIPv6Socks4(); bool joined = false, dialed = false;
		if (valid && !socks4) service.Join(key, title, address, joined, dialed); const bool success = valid && joined && !socks4; const bool direct = address.family != W8LiveStreamAddress::Family::None && address.port;
		DirectReply(out, success, joined, dialed, socks4 ? "ipv6_not_supported_by_socks4" : (!valid ? "invalid_stream_key" : (!joined ? "join_rejected" : "")), supplied, ip, address.port, socks4 ? "rejected" : (direct ? "direct" : "kad-search"), socks4 ? "SOCKS4/SOCKS4A cannot represent an IPv6 destination; use SOCKS5 or HTTP CONNECT" : (success ? (direct ? "Dialing broadcaster directly" : "Anonymous link \xE2\x80\x94 searching Kad for the broadcaster (5-30 s)") : (valid ? "JoinStream rejected" : "Bad streamKey or eMule not ready"))); return true;
	}
	if (in.operation == W8LiveStreamOperation::StreamFile) {
		std::string resource = in.stream_resource; const std::size_t query = resource.find('?'); if (query != std::string::npos) resource.resize(query);
		if (service.IsAvailable() && W8DecodeKey16(in.stream_hash, key)) { std::array<unsigned char, 16> current{}; if (service.CopyViewerKey(current) && current == key) service.NotePlayerFetch(); }
		out.forward_stream_file = true; out.stream_hash = in.stream_hash; out.stream_resource = resource; out.content_type.clear(); out.body.clear(); return true;
	}
	return false;
}
namespace {
class SelfPort final : public W8LiveStreamPort {
public:
	bool available = true, allowJoin = true, alive = true, broadcasting = false, socks4 = false, lastHas = false, copyBroadcast = true;
	int joins = 0, leaves = 0, notes = 0, starts = 0, stops = 0, step = 0; std::uint32_t now = 0;
	std::vector<int> sequence; std::array<unsigned char, 16> viewer{}, broadcast{}, lastJoinKey{}; std::string publicIp = "1.2.3.4", lastJoinTitle; W8LiveStreamAddress lastJoinAddress; W8LiveBroadcastRequest lastBroadcastRequest;
	bool IsAvailable() const override { return available; }
	bool Join(const std::array<unsigned char, 16>& key, const std::string& title, const W8LiveStreamAddress& address, bool& joined, bool& dialed) override { ++joins; lastJoinKey = key; lastJoinTitle = title; lastJoinAddress = address; joined = allowJoin; dialed = allowJoin && address.family != W8LiveStreamAddress::Family::None && address.port != 0; return allowJoin; }
	bool Leave(const std::array<unsigned char, 16>&, bool has) override { ++leaves; lastHas = has; return has; }
	bool CopyViewerKey(std::array<unsigned char, 16>& out) const override { out = viewer; return true; }
	void NotePlayerFetch() override { ++notes; }
	bool StartBroadcast(const W8LiveBroadcastRequest& request) override { ++starts; lastBroadcastRequest = request; return broadcasting = true; }
	void BroadcastLiveness(bool& outAlive, int& chunks) const override { outAlive = alive; chunks = sequence.empty() ? 0 : sequence[static_cast<std::size_t>((std::min)(step, static_cast<int>(sequence.size() - 1)))]; ++const_cast<SelfPort*>(this)->step; }
	bool StopBroadcast() override { ++stops; const bool was = broadcasting; broadcasting = false; return was; }
	bool CopyBroadcastKey(std::array<unsigned char, 16>& out) const override { out = broadcast; return copyBroadcast; }
	std::string PublicIPv4Text() const override { return publicIp; }
	std::uint16_t AdvertisedPort() const override { return 4662; }
	std::uint32_t NowMs() const override { return now; }
	void PauseMs(unsigned milliseconds) override { now += milliseconds; }
	bool IsUnsupportedIPv6Socks4() const override { return socks4; }
	bool IsUsableAddress(const std::string& text, bool ipv6) const override { return ipv6 ? text == "::1" : text == "1.2.3.4"; }
};
bool SelfRun(W8LiveStreamRequest request, SelfPort& port, W8LiveStreamResponse& response) { return RunW8LiveStreamApi(request, port, response); }
bool Golden(const W8LiveStreamResponse& r, unsigned status, const char* reason, const std::string& body,
	bool cors = true, bool nosniff = true, bool forward = false)
{
	const std::string type = forward ? "" : "application/json", header = "HTTP/1.1 " + std::to_string(status) + " " + reason + "\r\nContent-Type: " + type + "\r\n" + (cors ? "Access-Control-Allow-Origin: http://127.0.0.1\r\n" : "") + (nosniff ? "X-Content-Type-Options: nosniff\r\n" : "") + "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n";
	return r.status == status && r.reason == reason && r.body == body && r.cors == cors &&
		r.nosniff == nosniff && r.forward_stream_file == forward &&
		r.content_type == type && W8BuildLiveStreamHeader(r) == header;
}
} // namespace

bool RunW8LiveStreamCharacterizationSelfTest(std::string& failure)
{
	const std::string hex = "ab000000000000000000000000000010"; std::array<unsigned char, 16> key{}; key[0] = 0xab; key[15] = 0x10;
	if (W8EncodeKey16(key) != hex || !W8DecodeKey16(hex, key) || W8DecodeKey16("bad", key) || W8EscapeJson("\"\\\n\x01") != "\\\"\\\\\\n\\u0001") { failure = "codec"; return false; }
	SelfPort port; port.viewer = key; port.broadcast = key; W8LiveStreamRequest request; W8LiveStreamResponse response;
	const std::string join = "{\"success\":true,\"streamKey\":\"" + hex + "\"}";
	request.operation = W8LiveStreamOperation::Join; request.key = hex; if (!SelfRun(request, port, response) || port.joins != 1 || !Golden(response, 200, "OK", join) || port.lastJoinKey != key || port.lastJoinTitle != "Live" || port.lastJoinAddress.family != W8LiveStreamAddress::Family::None || !port.lastJoinAddress.text.empty() || port.lastJoinAddress.port) { failure = "join"; return false; }
	request.ui_title = "\xD0\x96"; SelfRun(request, port, response); if (port.joins != 2 || !Golden(response, 200, "OK", join) || port.lastJoinTitle != request.ui_title) { failure = "join-ui-title"; return false; } request.ui_title.clear();
	request.key = "bad"; if (!SelfRun(request, port, response) || port.joins != 2 || !Golden(response, 400, "Bad Request", "{\"success\":false,\"streamKey\":\"bad\"}")) { failure = "join-invalid"; return false; }
	request.operation = W8LiveStreamOperation::Leave; request.key = hex; SelfRun(request, port, response); if (port.leaves != 1 || !port.lastHas || !Golden(response, 200, "OK", "{\"success\":true,\"wasViewing\":true}")) { failure = "leave-valid"; return false; }
	request.key.clear(); SelfRun(request, port, response); if (port.leaves != 2 || port.lastHas || !Golden(response, 200, "OK", "{\"success\":true,\"wasViewing\":false}")) { failure = "leave-absent"; return false; }
	request.key = "bad"; SelfRun(request, port, response); if (port.leaves != 3 || port.lastHas || !Golden(response, 200, "OK", "{\"success\":true,\"wasViewing\":false}")) { failure = "leave-invalid"; return false; }
	request.operation = W8LiveStreamOperation::PlayerAlive; request.key.clear(); SelfRun(request, port, response); request.key = hex; SelfRun(request, port, response); request.key = "cd000000000000000000000000000010"; SelfRun(request, port, response); if (port.notes != 2 || !Golden(response, 200, "OK", "{\"success\":true}", false, false)) { failure = "alive"; return false; }
	request = W8LiveStreamRequest(); request.operation = W8LiveStreamOperation::BroadcastStart; request.source = "testpattern"; request.title = "wire-title"; request.category = "wire-category"; request.language = "wire-language"; request.file = "wire-file"; request.bitrate = "0"; request.ui_source = "gui-source"; request.ui_title = "\xD0\x96 \xC3\xB1"; request.ui_category = "gui-category"; request.ui_language = "gui-language"; request.ui_file = "gui-file"; port.sequence = {0, 1, 3}; port.step = port.stops = 0; port.now = 0;
	const std::string encodedTitle = "%D0%96+%C3%B1", anon = "ed2k://|live|" + hex + "||" + encodedTitle + "|/", direct = "ed2k://|live|" + hex + "|1.2.3.4:4662|" + encodedTitle + "|/";
	const std::string ready = "{\"success\":true,\"ready\":true,\"state\":\"ready\",\"chunks\":3,\"source\":\"testpattern\",\"bitrate\":1500,\"link\":\"" + anon + "\",\"link_anonymous\":\"" + anon + "\",\"link_direct\":\"" + direct + "\"}";
	SelfRun(request, port, response); if (port.starts != 1 || !Golden(response, 200, "OK", ready) || port.lastBroadcastRequest.source != request.ui_source || port.lastBroadcastRequest.title != request.ui_title || port.lastBroadcastRequest.category != request.ui_category || port.lastBroadcastRequest.language != request.ui_language || port.lastBroadcastRequest.file != request.ui_file || port.lastBroadcastRequest.bitrate != 1500) { failure = "start-ready"; return false; }
	request.source = "rtmp"; request.title_encoded_wire = "wire-title"; port.sequence = {0}; port.step = port.stops = 0; port.now = 0; const std::string wireAnon = "ed2k://|live|" + hex + "||wire-title|/", wireDirect = "ed2k://|live|" + hex + "|1.2.3.4:4662|wire-title|/", waiting = "{\"success\":true,\"ready\":false,\"state\":\"waiting_input\",\"chunks\":0,\"source\":\"rtmp\",\"bitrate\":1500,\"link\":\"" + wireAnon + "\",\"link_anonymous\":\"" + wireAnon + "\",\"link_direct\":\"" + wireDirect + "\"}"; SelfRun(request, port, response); if (port.starts != 2 || !Golden(response, 200, "OK", waiting) || port.stops != 0) { failure = "start-rtmp"; return false; }
	request.source = "screen"; port.alive = false; port.stops = 0; SelfRun(request, port, response); if (port.starts != 3 || !Golden(response, 400, "Bad Request", "{\"success\":false,\"ready\":false,\"state\":\"failed\",\"chunks\":0,\"source\":\"screen\",\"bitrate\":1500,\"link\":\"\"}") || port.stops != 1) { failure = "start-dead"; return false; }
	port.alive = true; port.sequence = {0}; port.step = port.stops = 0; port.now = 0; request.bitrate = "65537"; SelfRun(request, port, response); if (port.starts != 4 || !Golden(response, 400, "Bad Request", "{\"success\":false,\"ready\":false,\"state\":\"failed\",\"chunks\":0,\"source\":\"screen\",\"bitrate\":1,\"link\":\"\"}") || port.stops != 1) { failure = "start-timeout-wrap"; return false; }
	request.operation = W8LiveStreamOperation::BroadcastStop; port.broadcasting = true; SelfRun(request, port, response); if (!Golden(response, 200, "OK", "{\"success\":true,\"was_broadcasting\":true}", true, false)) { failure = "stop-active"; return false; } SelfRun(request, port, response); if (!Golden(response, 200, "OK", "{\"success\":true,\"was_broadcasting\":false}", true, false)) { failure = "stop-idle"; return false; }
	request = W8LiveStreamRequest(); request.operation = W8LiveStreamOperation::DirectJoin; request.key = hex; request.ip = "1.2.3.4"; request.port = "4662"; request.ui_title = "v4-ui";
	const std::string directJoin = "{\"success\":true,\"joined\":true,\"dialed\":true,\"error\":\"\",\"streamKey\":\"" + hex + "\",\"ip\":\"1.2.3.4\",\"port\":4662,\"mode\":\"direct\",\"hint\":\"Dialing broadcaster directly\"}";
	SelfRun(request, port, response); if (port.joins != 3 || !Golden(response, 200, "OK", directJoin) || port.lastJoinKey != key || port.lastJoinTitle != request.ui_title || port.lastJoinAddress.family != W8LiveStreamAddress::Family::IPv4 || port.lastJoinAddress.text != request.ip || port.lastJoinAddress.port != 4662) { failure = "direct-v4"; return false; }
	request = W8LiveStreamRequest(); request.operation = W8LiveStreamOperation::DirectJoin; request.link = "ed2k://|live|" + hex + "|[::1]:4662|TitleFromLink|/"; request.ui_link = "ed2k://|live|ignored||TitleFromLink|/"; request.ui_title = "Explicit"; const std::string ipv6 = "{\"success\":true,\"joined\":true,\"dialed\":true,\"error\":\"\",\"streamKey\":\"" + hex + "\",\"ip\":\"::1\",\"port\":4662,\"mode\":\"direct\",\"hint\":\"Dialing broadcaster directly\"}"; SelfRun(request, port, response); if (port.joins != 4 || !Golden(response, 200, "OK", ipv6) || port.lastJoinKey != key || port.lastJoinTitle != "Explicit" || port.lastJoinAddress.family != W8LiveStreamAddress::Family::IPv6 || port.lastJoinAddress.text != "::1" || port.lastJoinAddress.port != 4662) { failure = "direct-ipv6-link"; return false; }
	request = W8LiveStreamRequest(); request.operation = W8LiveStreamOperation::DirectJoin; request.link = "ed2k://|live|" + hex + "||wire-anon|/"; request.ui_link = "ed2k://|live|ignored||ui-anon|/"; const std::string kadHint = "Anonymous link \xE2\x80\x94 searching Kad for the broadcaster (5-30 s)", anonymous = "{\"success\":true,\"joined\":true,\"dialed\":false,\"error\":\"\",\"streamKey\":\"" + hex + "\",\"ip\":\"\",\"port\":0,\"mode\":\"kad-search\",\"hint\":\"" + kadHint + "\"}"; SelfRun(request, port, response); if (port.joins != 5 || !Golden(response, 200, "OK", anonymous) || port.lastJoinKey != key || port.lastJoinTitle != "ui-anon" || port.lastJoinAddress.family != W8LiveStreamAddress::Family::None || !port.lastJoinAddress.text.empty() || port.lastJoinAddress.port) { failure = "direct-anon"; return false; }
	request.key = hex; request.link.clear(); request.ip = "::1"; request.port = "4662"; port.socks4 = true; const std::string socks = "{\"success\":false,\"joined\":false,\"dialed\":false,\"error\":\"ipv6_not_supported_by_socks4\",\"streamKey\":\"" + hex + "\",\"ip\":\"::1\",\"port\":4662,\"mode\":\"rejected\",\"hint\":\"SOCKS4/SOCKS4A cannot represent an IPv6 destination; use SOCKS5 or HTTP CONNECT\"}"; SelfRun(request, port, response); if (port.joins != 5 || !Golden(response, 400, "Bad Request", socks)) { failure = "direct-socks4"; return false; }
	port.socks4 = false; request.ip = "nope"; const std::string invalidEndpoint = "{\"success\":true,\"joined\":true,\"dialed\":false,\"error\":\"\",\"streamKey\":\"" + hex + "\",\"ip\":\"nope\",\"port\":0,\"mode\":\"kad-search\",\"hint\":\"" + kadHint + "\"}"; SelfRun(request, port, response); if (port.joins != 6 || !Golden(response, 200, "OK", invalidEndpoint) || port.lastJoinTitle != "Live") { failure = "direct-invalid-endpoint"; return false; }
	port.available = false; request.key = "bad"; const std::string absent = "{\"success\":false,\"joined\":false,\"dialed\":false,\"error\":\"invalid_stream_key\",\"streamKey\":\"bad\",\"ip\":\"nope\",\"port\":0,\"mode\":\"kad-search\",\"hint\":\"Bad streamKey or eMule not ready\"}"; SelfRun(request, port, response); if (port.joins != 6 || !Golden(response, 400, "Bad Request", absent)) { failure = "direct-absent"; return false; }
	port.available = true; request = W8LiveStreamRequest(); request.operation = W8LiveStreamOperation::BroadcastStart; port.sequence = {3}; port.step = 0; port.copyBroadcast = false; SelfRun(request, port, response); if (port.starts != 5 || !Golden(response, 200, "OK", "{\"success\":true,\"ready\":true,\"state\":\"ready\",\"chunks\":3,\"source\":\"testpattern\",\"bitrate\":1500,\"link\":\"\"}")) { failure = "start-no-key"; return false; }
	port.copyBroadcast = true; port.publicIp.clear(); port.sequence = {3}; port.step = 0; request.direct = "1"; const std::string defaultAnon = "ed2k://|live|" + hex + "||eSE+Live|/", noIp = "{\"success\":true,\"ready\":true,\"state\":\"ready\",\"chunks\":3,\"source\":\"testpattern\",\"bitrate\":1500,\"link\":\"" + defaultAnon + "\",\"link_anonymous\":\"" + defaultAnon + "\",\"link_direct\":\"" + defaultAnon + "\"}"; SelfRun(request, port, response); if (port.starts != 6 || !Golden(response, 200, "OK", noIp)) { failure = "start-no-ip"; return false; }
	port.available=false; SelfRun(request,port,response); if(port.starts!=6 || !Golden(response,400,"Bad Request","{\"success\":false,\"ready\":false,\"state\":\"failed\",\"chunks\":0,\"source\":\"testpattern\",\"bitrate\":1500,\"link\":\"\"}")){failure="start-unavailable";return false;}
	port.publicIp = "1.2.3.4"; port.available = true; request = W8LiveStreamRequest(); request.operation = W8LiveStreamOperation::StreamFile; request.stream_hash = hex; request.stream_resource = "stream.m3u8?x=1"; const int before = port.notes;
	SelfRun(request, port, response); if (!Golden(response, 200, "OK", "", true, true, true) || response.stream_hash != hex || response.stream_resource != "stream.m3u8" || port.notes != before + 1) { failure = "hls-match"; return false; }
	request.stream_hash = "cd000000000000000000000000000010"; SelfRun(request, port, response); if (!Golden(response, 200, "OK", "", true, true, true) || response.stream_hash != request.stream_hash || response.stream_resource != "stream.m3u8" || port.notes != before + 1) { failure = "hls-mismatch"; return false; }
	failure.clear(); return true;
}

namespace eSELive {
WebLiveApiStreamController::WebLiveApiStreamController(const M2AParentPort& parent) noexcept : m_parent(parent) {}
M2AModuleHandle M2A_BIND_W8_4974C0F316(const M2AParentPort& parent) { return parent ? MakeM2AModuleHandle(new WebLiveApiStreamController(parent)) : M2AModuleHandle(); }
void M2A_UNBIND_W8_4974C0F316(const M2AParentPort&) {}
} // namespace eSELive
