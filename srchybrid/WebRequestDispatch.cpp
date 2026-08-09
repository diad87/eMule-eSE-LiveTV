// this file is part of eMule eSE - W1 classic web request dispatcher
#include "stdafx.h"
#include "WebRequestDispatch.h"

#include "../cryptopp/osrng.h"
#include "../cryptopp/sha.h"
#include "MD5Sum.h"
#include "OtherFunctions.h"
#include "Preferences.h"
#include "StringConversion.h"
#include "zlib/zlib.h"

#include <memory>
#include <mutex>

namespace eSELive {
namespace {

#define HTTPInit \
	"Server: eMule\r\n" \
	"Connection: close\r\n" \
	"Content-Type: text/html\r\n" \
	"X-Content-Type-Options: nosniff\r\n" \
	"X-Frame-Options: SAMEORIGIN\r\n" \
	"Cache-Control: no-store\r\n" \
	"Referrer-Policy: no-referrer\r\n" \
	"Access-Control-Allow-Origin: http://localhost:3000\r\n" \
	"Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n" \
	"Access-Control-Allow-Headers: Authorization, X-CSRF-Token, Content-Type\r\n" \
	"Access-Control-Expose-Headers: X-CSRF-Token\r\n"
#define HTTPInitGZ HTTPInit "Content-Encoding: gzip\r\n"

struct ClassicRoute {
	LPCTSTR page;
	WebClassicView view;
};

const ClassicRoute kClassicRoutes[] = {
	{_T("server"), WebClassicView::Server},
	{_T("shared"), WebClassicView::Shared},
	{_T("transfer"), WebClassicView::Transfer},
	{_T("search"), WebClassicView::Search},
	{_T("graphs"), WebClassicView::Graphs},
	{_T("log"), WebClassicView::Log},
	{_T("sinfo"), WebClassicView::ServerInfo},
	{_T("debuglog"), WebClassicView::DebugLog},
	{_T("myinfo"), WebClassicView::MyInfo},
	{_T("stats"), WebClassicView::Stats},
	{_T("kad"), WebClassicView::Kad},
	{_T("options"), WebClassicView::Options},
};

struct RequestState {
	bool use_gzip = false;
	bool just_add_link = false;
	bool login = false;
	bool response_committed = false;
	std::uint32_t ip = 0;
	std::uint64_t now_ms = 0;
	long session = 0;
	CString session_text;
	CStringA issued_csrf;
	CStringA issued_browser_token;
	bool clear_browser_cookie = false;
	CString output;
};

class ComScope {
public:
	ComScope() noexcept { (void)CoInitialize(NULL); }
	~ComScope() { CoUninitialize(); }
};

CryptoPP::AutoSeededRandomPool requestRng;
std::mutex requestRngMutex;
std::mutex dispatchBindingMutex; std::shared_ptr<WebRequestDispatch> dispatchBinding; const void* dispatchParent = nullptr;

CStringA GenerateHexTokenInternal()
{
	BYTE bytes[32];
	{
		std::lock_guard<std::mutex> lock(requestRngMutex);
		requestRng.GenerateBlock(bytes, sizeof(bytes));
	}
	CStringA token;
	for (const BYTE value : bytes)
		token.AppendFormat("%02x", value);
	return token;
}

std::uint32_t GenerateWord32Internal()
{
	std::lock_guard<std::mutex> lock(requestRngMutex);
	return requestRng.GenerateWord32();
}

bool ConstantTimeEqual(const std::string& lhs, const std::string& rhs)
{
	const std::size_t maximum = lhs.size() > rhs.size() ? lhs.size() : rhs.size();
	std::size_t difference = lhs.size() ^ rhs.size();
	for (std::size_t index = 0; index < maximum; ++index) {
		const unsigned char left = index < lhs.size() ? static_cast<unsigned char>(lhs[index]) : 0;
		const unsigned char right = index < rhs.size() ? static_cast<unsigned char>(rhs[index]) : 0;
		difference |= static_cast<std::size_t>(left ^ right);
	}
	return difference == 0;
}

bool Authenticate(
	const WebClassicInput& input,
	const WebClassicPort& port,
	RequestState& state)
{
	state.use_gzip = input.use_gzip;
	state.ip = input.ip;
	state.now_ms = WebRequestAuthNowMs();
	if (port.login_blocked(port.context, state.ip, state.now_ms)) {
		state.response_committed = true;
		port.send_content(input.legacy, HTTPInit, input.access_denied_text);
		return false;
	}

	const CString requestedPage(port.parse_url(input.url, _T("w")));
	const CString requestedSessionText(port.parse_url(input.url, _T("ses")));
	const long requestedSession = _tstol(requestedSessionText);
	state.session = input.loopback ? requestedSession : 0;
	if (!input.browser_session_token.IsEmpty()) {
		std::uint32_t resolved = 0;
		if (port.resolve_browser_session(
			port.context, input.browser_session_token, state.now_ms,
			WebRequestSessionTimeoutMs(), resolved)) {
			state.session = static_cast<long>(resolved);
		} else if (!input.loopback && requestedPage != _T("password")) {
			state.response_committed = true;
			port.send_reply(input.legacy,
				"HTTP/1.1 403 Forbidden\r\n"
				"Cache-Control: no-store\r\n"
				"Referrer-Policy: no-referrer\r\n"
				"Content-Length: 0\r\n\r\n");
			return false;
		}
	}
	if (!input.loopback && requestedSession > 0) {
		if (state.session == 0 && requestedPage != _T("password")) {
			state.response_committed = true;
			port.send_reply(input.legacy,
				"HTTP/1.1 403 Forbidden\r\n"
				"Cache-Control: no-store\r\n"
				"Referrer-Policy: no-referrer\r\n"
				"Content-Length: 0\r\n\r\n");
			return false;
		}
		if (state.session != 0 && state.session != requestedSession) {
			state.response_committed = true;
			port.send_reply(input.legacy,
				"HTTP/1.1 403 Forbidden\r\n"
				"Cache-Control: no-store\r\n"
				"Referrer-Policy: no-referrer\r\n"
				"Content-Length: 0\r\n\r\n");
			return false;
		}
	}
	if (requestedPage == _T("password")) {
		const CString& ip = input.ip_text;
		state.just_add_link =
			!port.parse_url(input.url, _T("c")).IsEmpty();
		const CString response(port.parse_url(input.url, _T("r")));
		const CString nonce(port.parse_url(input.url, _T("n")));
		bool isAdmin = false;
		bool authOk = false;
		if (!response.IsEmpty() && !nonce.IsEmpty()) {
			authOk = port.validate_challenge(
				input.legacy, nonce, response, isAdmin);
		} else {
			const CString plain(port.parse_url(input.url, _T("p")));
			if (input.loopback && !plain.IsEmpty()) {
				if (MD5Sum(plain).GetHashString() == input.admin_password_hash) {
					isAdmin = true;
					authOk = true;
				} else if (input.guest_enabled
					&& !input.guest_password_hash.IsEmpty()
					&& MD5Sum(plain).GetHashString()
						== input.guest_password_hash) {
					authOk = true;
				}
			}
		}
		if (authOk && !state.just_add_link) {
			state.issued_csrf = GenerateWebRequestHexToken();
			bool added = false;
			for (unsigned attempt = 0; attempt < 16 && !added; ++attempt) {
				state.issued_browser_token = GenerateWebRequestHexToken();
				state.session = static_cast<long>(
					GenerateWebRequestWord32() & 0x7FFFFFFFu);
				added = port.add_session(
					port.context,
					static_cast<std::uint32_t>(state.session),
					isAdmin, input.default_category, state.now_ms,
					state.issued_csrf, state.issued_browser_token);
			}
			if (!added) {
				authOk = false;
				state.issued_csrf.Empty();
				state.issued_browser_token.Empty();
			}
		}
		if (authOk) {
			port.notify_login(isAdmin, ip);
			state.login = true;
		}
		const CString plain(port.parse_url(input.url, _T("p")));
		if (!authOk && (!response.IsEmpty() || !plain.IsEmpty())) {
			port.notify_bad_login(ip);
			port.record_login_failure(
				port.context, state.ip, state.now_ms);
			if (port.login_blocked(
				port.context, state.ip, state.now_ms)) {
				state.response_committed = true;
				port.send_content(input.legacy, HTTPInit, input.access_denied_text);
				return false;
			}
		}
		state.use_gzip = false;
		if (state.login)
			port.record_login_success(port.context, state.ip);
	}

	state.session_text.Format(_T("%ld"), state.session);
	if (state.issued_csrf.IsEmpty() && state.session > 0
		&& !port.validate_csrf(
			port.context,
			static_cast<std::uint32_t>(state.session),
			input.csrf_token, input.fetch_site)) {
		state.response_committed = true;
		port.send_reply(input.legacy,
			"HTTP/1.1 403 Forbidden\r\n"
			"Cache-Control: no-store\r\n"
			"Referrer-Policy: no-referrer\r\n"
			"Content-Length: 0\r\n\r\n");
		return false;
	}
	if (requestedPage == _T("logout")) {
		port.remove_session(input.legacy, state.session);
		state.clear_browser_cookie = true;
	}
	return true;
}

bool SendAdministrativeAction(
	const WebClassicInput& input,
	const WebClassicPort& port,
	RequestState& state,
	const CString& page,
	bool admin)
{
	WebAdminAction action;
	if (page == _T("close") && admin
		&& input.allow_high_level) {
		action = WebAdminAction::Close;
	} else if (page == _T("shutdown") && admin) {
		action = WebAdminAction::Shutdown;
	} else if (page == _T("reboot") && admin) {
		action = WebAdminAction::Reboot;
	} else {
		return false;
	}
	port.remove_session(input.legacy, state.session);
	state.clear_browser_cookie = true;
	state.response_committed = true;
	CStringA headers(HTTPInit);
	headers.AppendFormat(
		"Set-Cookie: eSEWebSession=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict%s\r\n",
		input.secure_transport ? "; Secure" : "");
	port.send_content(input.legacy, headers,
		port.render(WebClassicView::Login, input.legacy, state.session));
	port.perform_admin_action(action);
	return true;
}

bool SendCommentOrFile(
	const WebClassicInput& input,
	const WebClassicPort& port,
	RequestState& state,
	const CString& page,
	bool admin)
{
	if (page == _T("commentlist")) {
		const CString result(
			port.render(
				WebClassicView::CommentList, input.legacy, state.session));
		if (!result.IsEmpty()) {
			state.response_committed = true;
			port.send_content(input.legacy, HTTPInit, result);
			return true;
		}
	} else if (page == _T("getfile") && admin) {
		const CString fileHash(port.parse_url(input.url, _T("filehash")));
		state.response_committed = true;
		const bool sent = port.send_requested_file(input.legacy, fileHash);
		state.response_committed = sent;
		return sent;
	}
	return false;
}

void ComposePage(
	const WebClassicInput& input,
	const WebClassicPort& port,
	RequestState& state)
{
	if (port.is_logged_in(input.legacy, state.session)) {
		const bool admin = port.is_admin(input.legacy, state.session_text);
		const CString page(port.parse_url(input.url, _T("w")));
		if (SendAdministrativeAction(
			input, port, state, page, admin)
			|| SendCommentOrFile(input, port, state, page, admin))
			return;
		state.output += port.render(
			WebClassicView::Header, input.legacy, state.session);
		const WebClassicView view = ResolveWebClassicView(page);
		if (view != WebClassicView::Unknown)
			state.output += port.render(view, input.legacy, state.session);
		if (view == WebClassicView::Options || page.IsEmpty())
			state.use_gzip = false;
		state.output += port.render(
			WebClassicView::Footer, input.legacy, state.session);
	} else if (state.just_add_link && state.login) {
		state.output += port.render(
			WebClassicView::RemoteLinkAdded, input.legacy, state.session);
	} else {
		state.use_gzip = false;
		state.output += port.render(
			state.just_add_link
				? WebClassicView::RemoteLinkFailed
				: WebClassicView::Login,
			input.legacy, state.session);
	}
}

void SendResponse(
	const WebClassicInput& input,
	const WebClassicPort& port,
	RequestState& state)
{
	if (state.response_committed)
		return;
	TCHAR* gzipOut = NULL;
	DWORD gzipLen = 0;
	if (state.use_gzip) {
		bool compressed = false;
		try {
			const CStringA utf8(wc2utf8(state.output));
			uLongf length = utf8.GetLength() + 1024;
			gzipOut = new TCHAR[length];
			if (CompressWebGzip(
				reinterpret_cast<unsigned char*>(gzipOut),
				&length,
				reinterpret_cast<const unsigned char*>((LPCSTR)utf8),
				utf8.GetLength(), Z_DEFAULT_COMPRESSION) == Z_OK) {
				compressed = true;
				gzipLen = length;
			}
		} catch (...) {
			ASSERT(0);
		}
		if (!compressed) {
			state.use_gzip = false;
			delete[] gzipOut;
			gzipOut = NULL;
		}
	}
	CStringA headers(state.use_gzip ? HTTPInitGZ : HTTPInit);
	if (!state.issued_csrf.IsEmpty())
		headers.AppendFormat(
			"X-CSRF-Token: %s\r\n", (LPCSTR)state.issued_csrf);
	if (!state.issued_browser_token.IsEmpty())
		headers.AppendFormat(
			"Set-Cookie: eSEWebSession=%s; Path=/; HttpOnly; SameSite=Strict%s\r\n",
			(LPCSTR)state.issued_browser_token,
			input.secure_transport ? "; Secure" : "");
	else if (state.clear_browser_cookie)
		headers.AppendFormat(
			"Set-Cookie: eSEWebSession=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict%s\r\n",
			input.secure_transport ? "; Secure" : "");
	state.response_committed = true;
	if (state.use_gzip)
		port.send_binary(input.legacy, headers, gzipOut, gzipLen);
	else
		port.send_content(input.legacy, headers, state.output);
	delete[] gzipOut;
}

} // namespace

std::uint64_t WebRequestAuthNowMs() noexcept
{
	// This project still advertises a Windows XP SDK baseline, where the
	// GetTickCount64 declaration is hidden. Resolve the real 64-bit monotonic
	// clock on supported systems and retain a locked wrap-extension fallback.
	typedef ULONGLONG (WINAPI *GetTickCount64Fn)();
	static GetTickCount64Fn getTickCount64 =
		reinterpret_cast<GetTickCount64Fn>(GetProcAddress(
			GetModuleHandleW(L"kernel32.dll"), "GetTickCount64"));
	if (getTickCount64 != NULL)
		return static_cast<std::uint64_t>(getTickCount64());
	static CCriticalSection legacyClockLock;
	static DWORD previous = 0;
	static std::uint64_t epoch = 0;
	CSingleLock lock(&legacyClockLock, TRUE);
	const DWORD current = ::GetTickCount();
	if (current < previous)
		epoch += (1ull << 32);
	previous = current;
	return epoch + current;
}

std::uint64_t WebRequestSessionTimeoutMs() noexcept
{
	const int timeoutMinutes = thePrefs.GetWebTimeoutMins();
	return timeoutMinutes > 0
		? static_cast<std::uint64_t>(timeoutMinutes) * 60u * 1000u
		: 0;
}

CStringA GenerateWebRequestHexToken()
{
	return GenerateHexTokenInternal();
}

CStringA DigestWebRequestToken(const CStringA& token)
{
	CryptoPP::byte digest[CryptoPP::SHA256::DIGESTSIZE];
	CryptoPP::SHA256().CalculateDigest(
		digest,
		reinterpret_cast<const CryptoPP::byte*>((LPCSTR)token),
		token.GetLength());
	CStringA encoded;
	for (int index = 0; index < CryptoPP::SHA256::DIGESTSIZE; ++index)
		encoded.AppendFormat("%02x", digest[index]);
	return encoded;
}

std::uint32_t GenerateWebRequestWord32()
{
	return GenerateWord32Internal();
}

bool ValidateWebChallengeDigest(
	const CStringA& nonce,
	const CStringA& response,
	const CString& adminHash,
	bool guestEnabled,
	const CString& guestHash,
	bool& outIsAdmin)
{
	auto matches = [&](const CString& storedHash) {
		const CT2A converted(storedHash);
		CStringA normalizedHash(static_cast<LPCSTR>(converted));
		normalizedHash.MakeLower();
		const CStringA input = nonce + normalizedHash;
		CryptoPP::byte digest[CryptoPP::SHA256::DIGESTSIZE];
		CryptoPP::SHA256().CalculateDigest(
			digest,
			reinterpret_cast<const CryptoPP::byte*>((LPCSTR)input),
			input.GetLength());
		CStringA expected;
		for (int index = 0; index < CryptoPP::SHA256::DIGESTSIZE; ++index)
			expected.AppendFormat("%02x", digest[index]);
		return ConstantTimeEqual(
			std::string((LPCSTR)expected, expected.GetLength()),
			std::string((LPCSTR)response, response.GetLength()));
	};
	outIsAdmin = false;
	if (!adminHash.IsEmpty() && matches(adminHash)) {
		outIsAdmin = true;
		return true;
	}
	return guestEnabled && !guestHash.IsEmpty() && matches(guestHash);
}

int CompressWebGzip(
	unsigned char* destination,
	unsigned long* destinationLength,
	const unsigned char* source,
	unsigned long sourceLength,
	int level)
{
	z_stream stream = {};
	stream.zalloc = (alloc_func)NULL;
	stream.zfree = (free_func)NULL;
	stream.opaque = (voidpf)NULL;
	uLong crc = crc32(0, Z_NULL, 0);
	int error = deflateInit2(
		&stream, level, Z_DEFLATED, -MAX_WBITS,
		MAX_MEM_LEVEL, Z_DEFAULT_STRATEGY);
	if (error != Z_OK)
		return error;
	if (*destinationLength < 18) {
		deflateEnd(&stream);
		return Z_BUF_ERROR;
	}
	const BYTE header[10] =
		{0x1f, 0x8b, Z_DEFLATED, 0, 0, 0, 0, 0, 0, 255};
	memcpy(destination, header, sizeof(header));
	stream.next_in = const_cast<Bytef*>(source);
	stream.avail_in = static_cast<uInt>(sourceLength);
	stream.next_out = &destination[sizeof(header)];
	stream.avail_out = *destinationLength - 18;
	error = deflate(&stream, Z_FINISH);
	if (error != Z_STREAM_END) {
		deflateEnd(&stream);
		return error;
	}
	error = deflateEnd(&stream);
	crc = crc32(crc, source, static_cast<uInt>(sourceLength));
	const std::size_t trailer = sizeof(header) + stream.total_out;
	if (trailer + 8 > *destinationLength)
		return Z_BUF_ERROR;
	memcpy(&destination[trailer], &crc, sizeof(uLong));
	memcpy(
		&destination[trailer + sizeof(uLong)],
		&sourceLength, sizeof(uLong));
	*destinationLength = sizeof(header) + stream.total_out + 8;
	return error;
}

bool WebClassicPort::Complete() const noexcept
{
	return context != nullptr
		&& parse_url != nullptr
		&& validate_challenge != nullptr
		&& login_blocked != nullptr
		&& add_session != nullptr
		&& resolve_browser_session != nullptr
		&& validate_csrf != nullptr
		&& record_login_failure != nullptr
		&& record_login_success != nullptr
		&& remove_session != nullptr
		&& is_logged_in != nullptr
		&& is_admin != nullptr
		&& send_content != nullptr
		&& send_binary != nullptr
		&& send_reply != nullptr
		&& notify_login != nullptr
		&& notify_bad_login != nullptr
		&& perform_admin_action != nullptr
		&& send_requested_file != nullptr
		&& render != nullptr;
}

WebClassicView ResolveWebClassicView(const CString& page) noexcept
{
	for (const ClassicRoute& route : kClassicRoutes) {
		if (page == route.page)
			return route.view;
	}
	return WebClassicView::Unknown;
}

WebRequestDispatch::WebRequestDispatch(
	const M2AParentPort& parent) noexcept
	: m_parent(parent.context)
{
}

void WebRequestDispatch::Process(
	const WebClassicInput& input,
	const WebClassicPort& port) const
{
	if (m_parent == nullptr || !port.Complete()
		|| !input.app_running || input.legacy == nullptr)
		return;
	InitThreadLocale();
	ComScope com;
	RequestState state;
#ifndef _DEBUG
	try {
#endif
		if (!Authenticate(input, port, state))
			return;
		ComposePage(input, port, state);
		SendResponse(input, port, state);
#ifndef _DEBUG
	} catch (...) {
		ASSERT(0);
		if (!state.response_committed) {
			state.response_committed = true;
			port.send_reply(input.legacy,
				"HTTP/1.1 500 Internal Server Error\r\n"
				"Connection: close\r\n"
				"Cache-Control: no-store\r\n"
				"Referrer-Policy: no-referrer\r\n"
				"Content-Length: 0\r\n\r\n");
		}
	}
#endif
}

void RunWebClassicRequest(
	const M2AParentPort& parent,
	const WebClassicInput& input,
	const WebClassicPort& port)
{
	std::shared_ptr<WebRequestDispatch> dispatch; { std::lock_guard<std::mutex> lock(dispatchBindingMutex); if (parent.context != dispatchParent) return; dispatch = dispatchBinding; }
	if (dispatch != nullptr) dispatch->Process(input, port);
}

M2AModuleHandle M2A_BIND_W1_EC6846B80E(
	const M2AParentPort& parent)
{
	if (!parent) return M2AModuleHandle();
	std::lock_guard<std::mutex> lock(dispatchBindingMutex); const auto owner = std::make_shared<M2AModuleHandle>(MakeM2AModuleHandle(new WebRequestDispatch(parent))); dispatchBinding = std::shared_ptr<WebRequestDispatch>(owner, static_cast<WebRequestDispatch*>(owner->Get())); dispatchParent = parent.context;
	return M2AModuleHandle(dispatchBinding.get(), nullptr);
}

void M2A_UNBIND_W1_EC6846B80E(const M2AParentPort& parent) { std::lock_guard<std::mutex> lock(dispatchBindingMutex); if (parent.context == dispatchParent) { dispatchParent = nullptr; dispatchBinding.reset(); } }

namespace {

struct DispatchProbe { bool logged = true, admin = false, csrf = true, challenge = true, bearer = true, file_result = false, file_throw = false, parse_throw = false; int contents = 0, binaries = 0, replies = 0, actions = 0, files = 0, sessions = 0, removals = 0; CStringA headers, issued_bearer; };
thread_local DispatchProbe* activeProbe = nullptr;
CString ProbeParse(const CString& url, const CString& field) { if (activeProbe != nullptr && activeProbe->parse_throw && field == _T("filehash")) throw 1; const CString key(field + _T("=")); int begin = url.Find(key); if (begin < 0) return CString(); begin += key.GetLength(); const int end = url.Find(_T('&'), begin); return end < 0 ? url.Mid(begin) : url.Mid(begin, end - begin); }
bool ProbeChallenge(const void* raw, const CString&, const CString&, bool& admin) { const DispatchProbe& p = *static_cast<const DispatchProbe*>(raw); admin = p.admin; return p.challenge; } bool ProbeBlocked(void*, std::uint32_t, std::uint64_t) { return false; } bool ProbeAdd(void* raw, std::uint32_t, bool, int, std::uint64_t, const CStringA&, const CStringA& bearer) { DispatchProbe& p = *static_cast<DispatchProbe*>(raw); ++p.sessions; p.logged = true; p.issued_bearer = bearer; return true; }
bool ProbeBearer(void* raw, const CStringA&, std::uint64_t, std::uint64_t, std::uint32_t& id) { DispatchProbe& p = *static_cast<DispatchProbe*>(raw); id = 1; return p.bearer; }
bool ProbeCsrf(void* raw, std::uint32_t, const CStringA&, const CStringA&) { return static_cast<DispatchProbe*>(raw)->csrf; } void ProbeFailure(void*, std::uint32_t, std::uint64_t) {} void ProbeSuccess(void*, std::uint32_t) {} bool ProbeRemove(const void* raw, long) { ++static_cast<DispatchProbe*>(const_cast<void*>(raw))->removals; return true; } bool ProbeLogged(const void* raw, long) { return static_cast<const DispatchProbe*>(raw)->logged; } bool ProbeAdmin(const void* raw, const CString&) { return static_cast<const DispatchProbe*>(raw)->admin; }
void ProbeContent(const void* raw, const CStringA& headers, const CString&) { DispatchProbe& p=*static_cast<DispatchProbe*>(const_cast<void*>(raw));++p.contents;p.headers=headers; } void ProbeBinary(const void* raw, const CStringA& headers, const void*, unsigned long) { DispatchProbe& p=*static_cast<DispatchProbe*>(const_cast<void*>(raw));++p.binaries;p.headers=headers; } void ProbeReply(const void* raw, const char* headers) { DispatchProbe& p=*static_cast<DispatchProbe*>(const_cast<void*>(raw));++p.replies;p.headers=headers; } void ProbeNotify(bool, const CString&) {} void ProbeBad(const CString&) {}
void ProbeAction(WebAdminAction) { if (activeProbe != nullptr) ++activeProbe->actions; } bool ProbeFile(const void* raw, const CString&) { DispatchProbe& p = *static_cast<DispatchProbe*>(const_cast<void*>(raw)); ++p.files; if (p.file_throw) throw 1; return p.file_result; } CString ProbeRender(WebClassicView view, const void*, long) { return view == WebClassicView::Header ? _T("H") : view == WebClassicView::Footer ? _T("F") : _T("V"); }
bool ProbeHardened(const CStringA& headers) { return headers.Find("Cache-Control: no-store\r\n") >= 0 && headers.Find("Referrer-Policy: no-referrer\r\n") >= 0; }
bool RunProbe(
	DispatchProbe& probe,
	const CString& url,
	bool gzip = false,
	bool highLevel = false,
	bool secure = false,
	bool loopback = true,
	const CStringA& browserToken = CStringA(),
	const CStringA& csrfToken = CStringA(),
	const CStringA& fetchSite = CStringA())
{
	WebClassicPort port{&probe, ProbeParse, ProbeChallenge, ProbeBlocked, ProbeAdd, ProbeBearer, ProbeCsrf, ProbeFailure, ProbeSuccess, ProbeRemove, ProbeLogged, ProbeAdmin, ProbeContent, ProbeBinary, ProbeReply, ProbeNotify, ProbeBad, ProbeAction, ProbeFile, ProbeRender};
	WebClassicInput input; input.legacy = &probe; input.url = url; input.ip_text = loopback ? _T("127.0.0.1") : _T("198.51.100.7"); input.ip = loopback ? INADDR_LOOPBACK : 0x076433c6u; input.loopback = loopback; input.app_running = true; input.use_gzip = gzip; input.allow_high_level = highLevel; input.secure_transport = secure; input.browser_session_token = browserToken;
	input.csrf_token = csrfToken; input.fetch_site = fetchSite;
	const M2AParentPort parent{&probe}; M2AModuleHandle binding = M2A_BIND_W1_EC6846B80E(parent); if (!binding) return false; activeProbe = &probe; try { RunWebClassicRequest(parent, input, port); } catch (...) { activeProbe = nullptr; M2A_UNBIND_W1_EC6846B80E(parent); return probe.file_throw || probe.parse_throw; } activeProbe = nullptr; M2A_UNBIND_W1_EC6846B80E(parent); return true;
}

} // namespace

bool RunWebClassicRequestCharacterizationSelfTest()
{
	if (!(ResolveWebClassicView(_T("server")) == WebClassicView::Server && ResolveWebClassicView(_T("options")) == WebClassicView::Options && ResolveWebClassicView(_T("SERVER")) == WebClassicView::Unknown && ResolveWebClassicView(_T("missing")) == WebClassicView::Unknown && ResolveWebClassicView(CString()) == WebClassicView::Unknown)) return false;
	if (DigestWebRequestToken(CStringA("abc")) !=
		"ba7816bf8f01cfea414140de5dae2223"
		"b00361a396177a9cb410ff61f20015ad") return false;
	DispatchProbe auth; auth.logged = false; if (!RunProbe(auth, _T("?ses=1&w=password&r=ok&n=n")) || auth.sessions != 1 || auth.issued_bearer.GetLength() != 64 || auth.contents != 1 || !ProbeHardened(auth.headers) || auth.headers.Find("Set-Cookie: eSEWebSession=") < 0 || auth.headers.Find("HttpOnly; SameSite=Strict") < 0 || auth.headers.Find("; Secure") >= 0) return false;
	DispatchProbe secureAuth; secureAuth.logged = false; if (!RunProbe(secureAuth, _T("?w=password&r=ok&n=n"), false, false, true) || !ProbeHardened(secureAuth.headers) || secureAuth.headers.Find("HttpOnly; SameSite=Strict; Secure") < 0) return false;
	DispatchProbe remoteNoCookie; if (!RunProbe(remoteNoCookie, _T("?ses=1&w=server"), false, false, false, false) || remoteNoCookie.replies != 1 || remoteNoCookie.contents != 0 || !ProbeHardened(remoteNoCookie.headers)) return false;
	DispatchProbe remoteCookie; if (!RunProbe(remoteCookie, _T("?ses=1&w=server"), false, false, false, false, CStringA("bearer")) || remoteCookie.contents != 1 || remoteCookie.replies != 0) return false;
	DispatchProbe remoteMismatch; if (!RunProbe(remoteMismatch, _T("?ses=2&w=server"), false, false, false, false, CStringA("bearer")) || remoteMismatch.replies != 1 || remoteMismatch.contents != 0 || !ProbeHardened(remoteMismatch.headers)) return false;
	DispatchProbe remoteClean; if (!RunProbe(remoteClean, _T("?w=server"), false, false, false, false, CStringA("bearer")) || remoteClean.contents != 1 || remoteClean.replies != 0) return false;
	DispatchProbe logout; if (!RunProbe(logout, _T("?w=logout"), false, false, true, false, CStringA("bearer")) || logout.removals != 1 || logout.headers.Find("eSEWebSession=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict; Secure") < 0) return false;
	DispatchProbe csrf; csrf.csrf = false; if (!RunProbe(csrf, _T("?ses=1&w=server")) || csrf.replies != 1 || csrf.contents != 0 || !ProbeHardened(csrf.headers)) return false;
	DispatchProbe admin; admin.admin = true; if (!RunProbe(admin, _T("?ses=1&w=close"), false, true) || admin.actions != 1 || admin.contents != 1) return false; DispatchProbe missing; missing.admin = true; if (!RunProbe(missing, _T("?ses=1&w=getfile&filehash=x")) || missing.files != 1 || missing.contents != 1) return false;
	DispatchProbe authenticatedClose; authenticatedClose.logged = false; authenticatedClose.admin = true;
	if (!RunProbe(authenticatedClose, _T("?w=password&r=ok&n=n"))
		|| authenticatedClose.sessions != 1
		|| authenticatedClose.issued_bearer.GetLength() != 64) return false;
	const int csrfBegin = authenticatedClose.headers.Find("X-CSRF-Token: ");
	if (csrfBegin < 0) return false;
	const CStringA issuedCsrf = authenticatedClose.headers.Mid(
		csrfBegin + 14, 64);
	if (issuedCsrf.GetLength() != 64) return false;
	if (!RunProbe(authenticatedClose, _T("?w=close"), false, true,
		false, false, authenticatedClose.issued_bearer, issuedCsrf,
		CStringA("same-origin"))
		|| authenticatedClose.actions != 1
		|| authenticatedClose.removals != 1
		|| authenticatedClose.headers.Find(
			"Set-Cookie: eSEWebSession=; Path=/; Max-Age=0;") < 0) return false;
	DispatchProbe fileThrow; fileThrow.admin = true; fileThrow.file_throw = true; if (!RunProbe(fileThrow, _T("?ses=1&w=getfile&filehash=x")) || fileThrow.files != 1 || fileThrow.replies != 0 || fileThrow.contents != 0) return false; DispatchProbe parseThrow; parseThrow.admin = true; parseThrow.parse_throw = true; if (!RunProbe(parseThrow, _T("?ses=1&w=getfile&filehash=x")) || parseThrow.files != 0 || parseThrow.replies != 1 || !ProbeHardened(parseThrow.headers)) return false; DispatchProbe gzip;
	return RunProbe(gzip, _T("?ses=1&w=server"), true) && gzip.binaries == 1 && gzip.contents == 0 && ProbeHardened(gzip.headers);
}

} // namespace eSELive
