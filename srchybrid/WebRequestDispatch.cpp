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

	state.session_text = port.parse_url(input.url, _T("ses"));
	state.session = _tstol(state.session_text);
	if (port.parse_url(input.url, _T("w")) == _T("password")) {
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
				state.session = static_cast<long>(
					GenerateWebRequestWord32() & 0x7FFFFFFFu);
				added = port.add_session(
					port.context,
					static_cast<std::uint32_t>(state.session),
					isAdmin, input.default_category, state.now_ms,
					state.issued_csrf);
			}
			if (!added) {
				authOk = false;
				state.issued_csrf.Empty();
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
			"Content-Length: 0\r\n\r\n");
		return false;
	}
	if (port.parse_url(input.url, _T("w")) == _T("logout"))
		port.remove_session(input.legacy, state.session);
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
	state.response_committed = true;
	port.send_content(input.legacy, HTTPInit,
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
	return static_cast<std::uint64_t>(::GetTickCount());
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

struct DispatchProbe { bool logged = true, admin = false, csrf = true, challenge = true, file_result = false, file_throw = false, parse_throw = false; int contents = 0, binaries = 0, replies = 0, actions = 0, files = 0, sessions = 0; };
thread_local DispatchProbe* activeProbe = nullptr;
CString ProbeParse(const CString& url, const CString& field) { if (activeProbe != nullptr && activeProbe->parse_throw && field == _T("filehash")) throw 1; const CString key(field + _T("=")); int begin = url.Find(key); if (begin < 0) return CString(); begin += key.GetLength(); const int end = url.Find(_T('&'), begin); return end < 0 ? url.Mid(begin) : url.Mid(begin, end - begin); }
bool ProbeChallenge(const void* raw, const CString&, const CString&, bool& admin) { const DispatchProbe& p = *static_cast<const DispatchProbe*>(raw); admin = p.admin; return p.challenge; } bool ProbeBlocked(void*, std::uint32_t, std::uint64_t) { return false; } bool ProbeAdd(void* raw, std::uint32_t, bool, int, std::uint64_t, const CStringA&) { DispatchProbe& p = *static_cast<DispatchProbe*>(raw); ++p.sessions; p.logged = true; return true; }
bool ProbeCsrf(void* raw, std::uint32_t, const CStringA&, const CStringA&) { return static_cast<DispatchProbe*>(raw)->csrf; } void ProbeFailure(void*, std::uint32_t, std::uint64_t) {} void ProbeSuccess(void*, std::uint32_t) {} bool ProbeRemove(const void*, long) { return true; } bool ProbeLogged(const void* raw, long) { return static_cast<const DispatchProbe*>(raw)->logged; } bool ProbeAdmin(const void* raw, const CString&) { return static_cast<const DispatchProbe*>(raw)->admin; }
void ProbeContent(const void* raw, const CStringA&, const CString&) { ++static_cast<DispatchProbe*>(const_cast<void*>(raw))->contents; } void ProbeBinary(const void* raw, const CStringA&, const void*, unsigned long) { ++static_cast<DispatchProbe*>(const_cast<void*>(raw))->binaries; } void ProbeReply(const void* raw, const char*) { ++static_cast<DispatchProbe*>(const_cast<void*>(raw))->replies; } void ProbeNotify(bool, const CString&) {} void ProbeBad(const CString&) {}
void ProbeAction(WebAdminAction) { if (activeProbe != nullptr) ++activeProbe->actions; } bool ProbeFile(const void* raw, const CString&) { DispatchProbe& p = *static_cast<DispatchProbe*>(const_cast<void*>(raw)); ++p.files; if (p.file_throw) throw 1; return p.file_result; } CString ProbeRender(WebClassicView view, const void*, long) { return view == WebClassicView::Header ? _T("H") : view == WebClassicView::Footer ? _T("F") : _T("V"); }
bool RunProbe(DispatchProbe& probe, const CString& url, bool gzip = false, bool highLevel = false)
{
	WebClassicPort port{&probe, ProbeParse, ProbeChallenge, ProbeBlocked, ProbeAdd, ProbeCsrf, ProbeFailure, ProbeSuccess, ProbeRemove, ProbeLogged, ProbeAdmin, ProbeContent, ProbeBinary, ProbeReply, ProbeNotify, ProbeBad, ProbeAction, ProbeFile, ProbeRender};
	WebClassicInput input; input.legacy = &probe; input.url = url; input.ip_text = _T("127.0.0.1"); input.ip = INADDR_LOOPBACK; input.loopback = true; input.app_running = true; input.use_gzip = gzip; input.allow_high_level = highLevel;
	const M2AParentPort parent{&probe}; M2AModuleHandle binding = M2A_BIND_W1_EC6846B80E(parent); if (!binding) return false; activeProbe = &probe; try { RunWebClassicRequest(parent, input, port); } catch (...) { activeProbe = nullptr; M2A_UNBIND_W1_EC6846B80E(parent); return probe.file_throw || probe.parse_throw; } activeProbe = nullptr; M2A_UNBIND_W1_EC6846B80E(parent); return true;
}

} // namespace

bool RunWebClassicRequestCharacterizationSelfTest()
{
	if (!(ResolveWebClassicView(_T("server")) == WebClassicView::Server && ResolveWebClassicView(_T("options")) == WebClassicView::Options && ResolveWebClassicView(_T("SERVER")) == WebClassicView::Unknown && ResolveWebClassicView(_T("missing")) == WebClassicView::Unknown && ResolveWebClassicView(CString()) == WebClassicView::Unknown)) return false;
	DispatchProbe auth; auth.logged = false; if (!RunProbe(auth, _T("?ses=1&w=password&r=ok&n=n")) || auth.sessions != 1 || auth.contents != 1) return false; DispatchProbe csrf; csrf.csrf = false; if (!RunProbe(csrf, _T("?ses=1&w=server")) || csrf.replies != 1 || csrf.contents != 0) return false;
	DispatchProbe admin; admin.admin = true; if (!RunProbe(admin, _T("?ses=1&w=close"), false, true) || admin.actions != 1 || admin.contents != 1) return false; DispatchProbe missing; missing.admin = true; if (!RunProbe(missing, _T("?ses=1&w=getfile&filehash=x")) || missing.files != 1 || missing.contents != 1) return false;
	DispatchProbe fileThrow; fileThrow.admin = true; fileThrow.file_throw = true; if (!RunProbe(fileThrow, _T("?ses=1&w=getfile&filehash=x")) || fileThrow.files != 1 || fileThrow.replies != 0 || fileThrow.contents != 0) return false; DispatchProbe parseThrow; parseThrow.admin = true; parseThrow.parse_throw = true; if (!RunProbe(parseThrow, _T("?ses=1&w=getfile&filehash=x")) || parseThrow.files != 0 || parseThrow.replies != 1) return false; DispatchProbe gzip;
	return RunProbe(gzip, _T("?ses=1&w=server"), true) && gzip.binaries == 1 && gzip.contents == 0;
}

} // namespace eSELive
