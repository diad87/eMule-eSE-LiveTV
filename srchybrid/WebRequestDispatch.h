// this file is part of eMule eSE - W1 classic web request dispatcher
#pragma once

#include "M2ABindingPort.h"
#include <afxstr.h>
#include <cstdint>

namespace eSELive {

enum class WebClassicView : std::uint8_t {
	Unknown = 0, Login, RemoteLinkAdded, RemoteLinkFailed,
	CommentList, Header, Footer, Server, Shared, Transfer,
	Search, Graphs, Log, ServerInfo, DebugLog, MyInfo,
	Stats, Kad, Options
};

enum class WebAdminAction : std::uint8_t { Close, Shutdown, Reboot };

struct WebClassicInput {
	const void* legacy = nullptr;
	CString url;
	CString ip_text;
	CStringA csrf_token;
	CStringA fetch_site;
	CStringA browser_session_token;
	CString admin_password_hash;
	CString guest_password_hash;
	CString access_denied_text;
	std::uint32_t ip = 0;
	int default_category = 0;
	bool loopback = false;
	bool app_running = false;
	bool use_gzip = false;
	bool guest_enabled = false;
	bool allow_high_level = false;
	bool secure_transport = false;
};

struct WebClassicPort {
	void* context = nullptr;
	CString (*parse_url)(const CString&, const CString&) = nullptr;
	bool (*validate_challenge)(const void*, const CString&, const CString&, bool&) = nullptr;
	bool (*login_blocked)(void*, std::uint32_t, std::uint64_t) = nullptr;
	bool (*add_session)(void*, std::uint32_t, bool, int, std::uint64_t, const CStringA&, const CStringA&) = nullptr;
	bool (*resolve_browser_session)(void*, const CStringA&, std::uint64_t, std::uint64_t, std::uint32_t&) = nullptr;
	bool (*validate_csrf)(void*, std::uint32_t, const CStringA&, const CStringA&) = nullptr;
	void (*record_login_failure)(void*, std::uint32_t, std::uint64_t) = nullptr;
	void (*record_login_success)(void*, std::uint32_t) = nullptr;
	bool (*remove_session)(const void*, long) = nullptr;
	bool (*is_logged_in)(const void*, long) = nullptr;
	bool (*is_admin)(const void*, const CString&) = nullptr;
	void (*send_content)(const void*, const CStringA&, const CString&) = nullptr;
	void (*send_binary)(const void*, const CStringA&, const void*, unsigned long) = nullptr;
	void (*send_reply)(const void*, const char*) = nullptr;
	void (*notify_login)(bool, const CString&) = nullptr;
	void (*notify_bad_login)(const CString&) = nullptr;
	void (*perform_admin_action)(WebAdminAction) = nullptr;
	bool (*send_requested_file)(const void*, const CString&) = nullptr;
	CString (*render)(WebClassicView, const void*, long) = nullptr;

	bool Complete() const noexcept;
};

class WebRequestDispatch {
public:
	explicit WebRequestDispatch(const M2AParentPort& parent) noexcept;
	void Process(const WebClassicInput& input, const WebClassicPort& port) const;

private:
	const void* m_parent = nullptr;
};

M2AModuleHandle M2A_BIND_W1_EC6846B80E(const M2AParentPort&);
void M2A_UNBIND_W1_EC6846B80E(const M2AParentPort&);
void RunWebClassicRequest(const M2AParentPort&, const WebClassicInput&, const WebClassicPort&);
WebClassicView ResolveWebClassicView(const CString& page) noexcept;
std::uint64_t WebRequestAuthNowMs() noexcept;
std::uint64_t WebRequestSessionTimeoutMs() noexcept;
CStringA GenerateWebRequestHexToken();
CStringA DigestWebRequestToken(const CStringA& token);
std::uint32_t GenerateWebRequestWord32();
bool ValidateWebChallengeDigest(const CStringA& nonce, const CStringA& response,
	const CString& adminHash, bool guestEnabled, const CString& guestHash,
	bool& outIsAdmin);
int CompressWebGzip(unsigned char* destination, unsigned long* destinationLength,
	const unsigned char* source, unsigned long sourceLength, int level);
bool RunWebClassicRequestCharacterizationSelfTest();

} // namespace eSELive
