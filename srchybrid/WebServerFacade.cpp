#include "WebServerFacade.h"

#include <algorithm>
#include <cctype>
#include <limits>

namespace eSELive {

WebServerFacade::WebServerFacade(const M2AParentPort& parent) noexcept
	: m_parent(parent)
{
}

M2AModuleHandle M2A_BIND_W12_B26D83D73F(const M2AParentPort& parent)
{
	// This facade deliberately owns no process or socket state.  The handle is
	// a construction/liveness probe; response policy remains pure and stateless.
	return parent
		? MakeM2AModuleHandle(new WebServerFacade(parent))
		: M2AModuleHandle();
}

void M2A_UNBIND_W12_B26D83D73F(const M2AParentPort&)
{
	// Stateless and therefore idempotent.  StopServer and the destructor both
	// call this boundary so every lifecycle path remains symmetric.
}

} // namespace eSELive

namespace ese { namespace web { namespace {

std::string LowerAscii(const std::string& value)
{
	std::string lowered(value);
	std::transform(lowered.begin(), lowered.end(), lowered.begin(),
		[](unsigned char c) { return static_cast<char>(std::tolower(c)); });
	return lowered;
}

void SetHeader(std::string& header, const char* name, const char* value)
{
	const std::size_t boundary = header.find("\r\n\r\n");
	const std::size_t headerEnd = boundary == std::string::npos ? header.size() : boundary;
	const std::string lowered = LowerAscii(header.substr(0, headerEnd));
	const std::string marker = "\r\n" + LowerAscii(name) + ":";
	const std::size_t markerAt = lowered.find(marker);
	const std::string replacement = std::string(name) + ": " + value;
	if (markerAt != std::string::npos) {
		const std::size_t lineAt = markerAt + 2;
		std::size_t lineEnd = header.find("\r\n", lineAt);
		if (lineEnd == std::string::npos)
			lineEnd = header.size();
		header.replace(lineAt, lineEnd - lineAt, replacement);
		return;
	}
	if (boundary != std::string::npos) {
		header.insert(boundary, "\r\n" + replacement);
		return;
	}
	if (!header.empty() && header.compare(header.size() - 2, 2, "\r\n") != 0)
		header += "\r\n";
	header += replacement + "\r\n\r\n";
}

bool IsLowerHex(const std::string& value, std::size_t expected)
{
	if (value.size() != expected)
		return false;
	return std::all_of(value.begin(), value.end(), [](char character) {
		return (character >= '0' && character <= '9') ||
			(character >= 'a' && character <= 'f');
	});
}

bool ReplaceOnce(
	std::string& value,
	const std::string& before,
	const std::string& after)
{
	const std::size_t at = value.find(before);
	if (at == std::string::npos ||
		value.find(before, at + before.size()) != std::string::npos)
		return false;
	value.replace(at, before.size(), after);
	return true;
}

void SetContentLength(std::string& header, std::size_t length)
{
	const std::string value = std::to_string(length);
	SetHeader(header, "Content-Length", value.c_str());
}

} // namespace

std::string HardenLiveResponseHeaders(const std::string& header, bool noStore)
{
	std::string hardened(header);
	SetHeader(hardened, "Referrer-Policy", "no-referrer");
	if (noStore)
		SetHeader(hardened, "Cache-Control", "no-store");
	return hardened;
}

std::string BuildRejectedLiveSessionLog(std::uint32_t ipv4NetworkOrder)
{
	return "Rejected /s/ request with invalid or expired token from "
		+ std::to_string(ipv4NetworkOrder & 0xffu) + "."
		+ std::to_string((ipv4NetworkOrder >> 8) & 0xffu) + "."
		+ std::to_string((ipv4NetworkOrder >> 16) & 0xffu) + "."
		+ std::to_string((ipv4NetworkOrder >> 24) & 0xffu);
}

std::string BuildRejectedHlsCapabilityLog(std::uint32_t ipv4NetworkOrder)
{
	return "Rejected protected media request from "
		+ std::to_string(ipv4NetworkOrder & 0xffu) + "."
		+ std::to_string((ipv4NetworkOrder >> 8) & 0xffu) + "."
		+ std::to_string((ipv4NetworkOrder >> 16) & 0xffu) + "."
		+ std::to_string((ipv4NetworkOrder >> 24) & 0xffu);
}

std::string BuildHlsCapabilityPlaylistPath(
	const std::string& token,
	std::uint64_t generation,
	const std::string& streamKey)
{
	if (!IsLowerHex(token, 64) || generation == 0 ||
		!IsLowerHex(streamKey, 32))
		return std::string();
	return "/h/" + token + "/" + std::to_string(generation) + "/" +
		streamKey + "/stream.m3u8";
}

bool RewriteLiveIndexForCookieSession(
	std::string& header,
	std::string& body)
{
	if (!ReplaceOnce(
		body,
		"const B=location.pathname.replace(/\\/live\\/?$/,'');",
		"const B='';"))
		return false;
	SetContentLength(header, body.size());
	return true;
}

bool RewriteLivePlayerForHlsCapability(
	std::string& header,
	std::string& body,
	const std::string& streamKey,
	const std::string& capabilityPlaylistPath)
{
	if (!IsLowerHex(streamKey, 32) ||
		capabilityPlaylistPath.compare(0, 3, "/h/") != 0)
		return false;
	std::string rewritten(body);
	if (!ReplaceOnce(
		rewritten,
		"const B=location.pathname.split('/live/')[0];",
		"const B='';") ||
		!ReplaceOnce(
			rewritten,
			"const src=B+'/api/live/" + streamKey + "/stream.m3u8';",
			"const src='" + capabilityPlaylistPath + "';"))
		return false;
	body.swap(rewritten);
	SetContentLength(header, body.size());
	return true;
}

bool RunWebServerFacadeCharacterizationSelfTest(std::string& failure)
{
	const std::string original =
		"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n";
	const std::string hardened = HardenLiveResponseHeaders(original, true);
	if (hardened.find("Referrer-Policy: no-referrer\r\n") == std::string::npos ||
		hardened.find("Cache-Control: no-store\r\n") == std::string::npos) {
		failure = "live response policy";
		return false;
	}
	if (HardenLiveResponseHeaders(hardened, true) != hardened) {
		failure = "live response policy idempotence";
		return false;
	}
	const std::string productiveHtml =
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: text/html; charset=utf-8\r\n"
		"Content-Length: 4\r\n"
		"Cache-Control: no-cache\r\n\r\n";
	const std::string expectedHtml =
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: text/html; charset=utf-8\r\n"
		"Content-Length: 4\r\n"
		"Cache-Control: no-store\r\n"
		"Referrer-Policy: no-referrer\r\n\r\n";
	if (HardenLiveResponseHeaders(productiveHtml, true) != expectedHtml) {
		failure = "productive HTML response policy";
		return false;
	}
	const std::string replaced = HardenLiveResponseHeaders(
		"HTTP/1.1 200 OK\r\nreferrer-policy: origin\r\nCache-Control: no-cache\r\n\r\n", true);
	if (replaced.find("Referrer-Policy: no-referrer") == std::string::npos ||
		replaced.find("Cache-Control: no-store") == std::string::npos ||
		replaced.find("origin") != std::string::npos ||
		replaced.find("no-cache") != std::string::npos) {
		failure = "live response policy replacement";
		return false;
	}
	const std::string credentialCanary = "W12-SEC-02-CANARY-TOKEN";
	const std::string invalidSessionUrl = "/s/" + credentialCanary + "/live";
	const std::string rejected = BuildRejectedLiveSessionLog(0x04030201u);
	if (rejected != "Rejected /s/ request with invalid or expired token from 1.2.3.4" ||
		rejected.find(credentialCanary) != std::string::npos ||
		rejected.find(invalidSessionUrl) != std::string::npos ||
		rejected.find("/s/123") != std::string::npos) {
		failure = "session rejection redaction";
		return false;
	}
	const std::string capabilityToken(64, 'c');
	const std::string streamKey = "0123456789abcdef0123456789abcdef";
	const std::string capabilityPath = BuildHlsCapabilityPlaylistPath(
		capabilityToken, 7, streamKey);
	if (capabilityPath != "/h/" + capabilityToken + "/7/" + streamKey +
			"/stream.m3u8" ||
		!BuildHlsCapabilityPlaylistPath(capabilityToken, 0, streamKey).empty()) {
		failure = "HLS capability path";
		return false;
	}
	std::string playerBody =
		"const B=location.pathname.split('/live/')[0];"
		"const src=B+'/api/live/" + streamKey + "/stream.m3u8';";
	std::string playerHeader =
		"HTTP/1.1 200 OK\r\nContent-Length: " +
		std::to_string(playerBody.size()) + "\r\n\r\n";
	if (!RewriteLivePlayerForHlsCapability(
			playerHeader, playerBody, streamKey, capabilityPath) ||
		playerBody != "const B='';const src='" + capabilityPath + "';" ||
		playerBody.find("/s/") != std::string::npos ||
		playerHeader.find(
			"Content-Length: " + std::to_string(playerBody.size()) + "\r\n") ==
			std::string::npos) {
		failure = "HLS capability player rewrite";
		return false;
	}
	std::string indexBody =
		"const B=location.pathname.replace(/\\/live\\/?$/,'');";
	std::string indexHeader = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
	if (!RewriteLiveIndexForCookieSession(indexHeader, indexBody) ||
		indexBody != "const B='';") {
		failure = "cookie session clean live URLs";
		return false;
	}
	const std::string rejectedCapability =
		BuildRejectedHlsCapabilityLog(0x04030201u);
	if (rejectedCapability != "Rejected protected media request from 1.2.3.4" ||
		rejectedCapability.find(capabilityToken) != std::string::npos ||
		rejectedCapability.find(capabilityPath) != std::string::npos) {
		failure = "HLS capability rejection redaction";
		return false;
	}
	failure.clear();
	return true;
}

} } // namespace ese::web
