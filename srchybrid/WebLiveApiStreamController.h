#pragma once

#include "M2ABindingPort.h"

#include <array>
#include <cstdint>
#include <string>

// Deliberately standard-library-only boundary.  The application adapter owns
// platform strings, endpoints, sockets, GUI messages and the filesystem.
enum class W8LiveStreamOperation {
	Join, Leave, PlayerAlive, BroadcastStart, BroadcastStop, DirectJoin, StreamFile
};

struct W8LiveStreamRequest {
	W8LiveStreamOperation operation = W8LiveStreamOperation::Join;
	std::string key, title, source, category, language, bitrate, file, direct;
	std::string link, ip, port, stream_hash, stream_resource;
	// Legacy fields above are wire bytes.  These fields retain UI UTF-8 until
	// the application adapter invokes GUI-facing ports.
	std::string ui_title, ui_source, ui_category, ui_language, ui_file, ui_link;
	std::string title_encoded_wire;
};

struct W8LiveStreamAddress {
	enum class Family { None, IPv4, IPv6 } family = Family::None;
	std::string text;
	std::uint16_t port = 0;
};

struct W8LiveStreamResponse {
	unsigned status = 200;
	std::string reason = "OK";
	std::string content_type = "application/json";
	std::string body;
	bool cors = true;
	bool nosniff = true;
	bool forward_stream_file = false;
	std::string stream_hash, stream_resource;
};

struct W8LiveBroadcastRequest {
	std::string source, title, category, language, file;
	std::uint16_t bitrate = 0;
};

// Implemented by the thin application adapter.  Calls that mutate state are
// already marshalled by that adapter; this module only decides the contract.
class W8LiveStreamPort {
public:
	virtual ~W8LiveStreamPort() = default;
	virtual bool IsAvailable() const = 0;
	virtual bool Join(const std::array<unsigned char, 16>& key, const std::string& title,
		const W8LiveStreamAddress& address, bool& joined, bool& dialed) = 0;
	virtual bool Leave(const std::array<unsigned char, 16>& key, bool has_key) = 0;
	virtual bool CopyViewerKey(std::array<unsigned char, 16>& key) const = 0;
	virtual void NotePlayerFetch() = 0;
	virtual bool StartBroadcast(const W8LiveBroadcastRequest& request) = 0;
	virtual void BroadcastLiveness(bool& alive, int& chunks) const = 0;
	virtual bool StopBroadcast() = 0;
	virtual bool CopyBroadcastKey(std::array<unsigned char, 16>& key) const = 0;
	// The adapter preserves the legacy textual byte order for the public IPv4.
	virtual std::string PublicIPv4Text() const = 0;
	virtual std::uint16_t AdvertisedPort() const = 0;
	virtual std::uint32_t NowMs() const = 0;
	virtual void PauseMs(unsigned milliseconds) = 0;
	virtual bool IsUnsupportedIPv6Socks4() const = 0;
	virtual bool IsUsableAddress(const std::string& text, bool ipv6) const = 0;
};

std::string W8EscapeJson(const std::string& input);
std::string W8EncodeKey16(const std::array<unsigned char, 16>& key);
bool W8DecodeKey16(const std::string& input, std::array<unsigned char, 16>& key);
std::string W8BuildLiveStreamHeader(const W8LiveStreamResponse& response);
bool RunW8LiveStreamApi(const W8LiveStreamRequest& request, W8LiveStreamPort& port,
	W8LiveStreamResponse& response);
bool RunW8LiveStreamCharacterizationSelfTest(std::string& failure);

namespace eSELive {
class WebLiveApiStreamController final {
public:
	explicit WebLiveApiStreamController(const M2AParentPort& parent) noexcept;
private:
	M2AParentPort m_parent;
};
M2AModuleHandle M2A_BIND_W8_4974C0F316(const M2AParentPort& parent);
void M2A_UNBIND_W8_4974C0F316(const M2AParentPort& parent);
} // namespace eSELive
