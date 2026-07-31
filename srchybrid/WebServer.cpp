#include "stdafx.h"
#ifdef K
#undef K
#endif
#include <locale.h>
#include <algorithm>
#include <cmath>
#include <vector>
#include "emule.h"
#include "StringConversion.h"
#include "OtherFunctions.h"
#include "WebApiSerializer.h"
#include "WebDiagnostics.h"
#include "M2ABindingPort.h"
#include "WebRequestParser.h"
#include "WebRouteTable.h"
#include "WebSearchController.h"
#include "WebSharedController.h"
#include "WebStaticAssets.h"
#include "WebTransferController.h"
#include "WebServer.h"
#include "ClientCredits.h"
#include "ClientList.h"
#include "DownloadQueue.h"
#include "ED2KLink.h"
#include "emuledlg.h"
#include "FriendList.h"
#include "ini2.h"
#include "Kademlia/Kademlia/Kademlia.h"
#include "Kademlia/Kademlia/UDPFirewallTester.h"
#include "Kademlia/net/KademliaUDPListener.h"
#include "Kademlia/Kademlia/KadV2Defines.h"     // F5: privacy endpoint
#include "Kademlia/Kademlia/KadV2ModeSelector.h"
// v0.71 P1.1 — runtime visibility headers for /api/live/privacy. We expose
// what the privacy stack is ACTUALLY doing so the user (and any external
// monitoring) can verify the modules are alive vs. dormant.
#include "Kademlia/Kademlia/KadV2TunnelPool.h"
#include "LiveTunnel.h"
#include "LiveSubscriptionStore.h"
#include "FirewallProberV6.h"
#include "ClientUDPSocket.h"
#include "eMuleAI/UtpSocket.h"
#include "Opcodes.h"   // g_uEseCapsRuntime extern
#include "KademliaWnd.h"
#include "KadSearchListCtrl.h"
#include "kademlia/kademlia/Entry.h"
#include "KnownFileList.h"
#include "ListenSocket.h"
#include "LiveStreamManager.h"
#include "LiveDebugLog.h"
#include "RTMPIngest.h"
#include <deque>
#include "Log.h"
#include "MenuCmds.h"
#include "Preferences.h"
#include "Server.h"
#include "ServerList.h"
#include "ServerWnd.h"
#include "SearchList.h"
#include "SearchDlg.h"
#include "SearchParams.h"
#include "SharedFileList.h"
#include "ServerConnect.h"
#include "StatisticsDlg.h"
#include "Opcodes.h"
#include "Statistics.h"
#include "KadKeepalive.h"      // R.2: keepalive control + stats for /api/keepalive and /api/status
#include "LiveBuddyRelay.h"    // R.3: relay accept/egress/viewer-connect for /api/relay/*
#include "RelayClient.h"       // P3: read-only KRP state cache; no worker-thread eMule access
#include "QArray.h"
#include "TransferDlg.h"
#include "UploadQueue.h"
#include "UpDownClient.h"
#include "UPnPImpl.h"
#include "UPnPImplWrapper.h"
#include "UserMsgs.h"

using namespace eSELive;

namespace eSELive {
enum class WebClassicView : std::uint8_t { Unknown = 0, Login, RemoteLinkAdded, RemoteLinkFailed, CommentList, Header, Footer, Server, Shared, Transfer, Search, Graphs, Log, ServerInfo, DebugLog, MyInfo, Stats, Kad, Options };
enum class WebAdminAction : std::uint8_t { Close, Shutdown, Reboot };
struct WebClassicInput {
	const void* legacy = nullptr; CString url; CString ip_text; CStringA csrf_token; CStringA fetch_site; CString admin_password_hash; CString guest_password_hash; CString access_denied_text;
	std::uint32_t ip = 0; int default_category = 0; bool loopback = false; bool app_running = false; bool use_gzip = false; bool guest_enabled = false; bool allow_high_level = false;
};
struct WebClassicPort {
	void* context = nullptr; CString (*parse_url)(const CString&, const CString&) = nullptr; bool (*validate_challenge)(const void*, const CString&, const CString&, bool&) = nullptr;
	bool (*login_blocked)(void*, std::uint32_t, std::uint64_t) = nullptr; bool (*add_session)(void*, std::uint32_t, bool, int, std::uint64_t, const CStringA&) = nullptr; bool (*validate_csrf)(void*, std::uint32_t, const CStringA&, const CStringA&) = nullptr;
	void (*record_login_failure)(void*, std::uint32_t, std::uint64_t) = nullptr; void (*record_login_success)(void*, std::uint32_t) = nullptr; bool (*remove_session)(const void*, long) = nullptr; bool (*is_logged_in)(const void*, long) = nullptr; bool (*is_admin)(const void*, const CString&) = nullptr;
	void (*send_content)(const void*, const CStringA&, const CString&) = nullptr; void (*send_binary)(const void*, const CStringA&, const void*, unsigned long) = nullptr; void (*send_reply)(const void*, const char*) = nullptr;
	void (*notify_login)(bool, const CString&) = nullptr; void (*notify_bad_login)(const CString&) = nullptr; void (*perform_admin_action)(WebAdminAction) = nullptr; bool (*send_requested_file)(const void*, const CString&) = nullptr; CString (*render)(WebClassicView, const void*, long) = nullptr;
	bool Complete() const noexcept;
};
M2AModuleHandle M2A_BIND_W1_EC6846B80E(const M2AParentPort&); void M2A_UNBIND_W1_EC6846B80E(const M2AParentPort&);
void RunWebClassicRequest(const M2AParentPort&, const WebClassicInput&, const WebClassicPort&); bool RunWebClassicRequestCharacterizationSelfTest(); std::uint64_t WebRequestAuthNowMs() noexcept; std::uint64_t WebRequestSessionTimeoutMs() noexcept; CStringA GenerateWebRequestHexToken(); std::uint32_t GenerateWebRequestWord32(); bool ValidateWebChallengeDigest(const CStringA&, const CStringA&, const CString&, bool, const CString&, bool&); int CompressWebGzip(unsigned char*, unsigned long*, const unsigned char*, unsigned long, int); enum class WebTemplateId : std::uint8_t { Header, HeaderStylesheet, Footer, ServerList, ServerLine, TransferImages, TransferList, TransferDownHeader, TransferDownFooter, TransferDownLine, TransferUpHeader, TransferUpFooter, TransferUpLine, TransferUpQueueShow, TransferUpQueueHide, TransferUpQueueLine, TransferUpQueueBannedShow, TransferUpQueueBannedHide, TransferUpQueueBannedLine, TransferUpQueueFriendShow, TransferUpQueueFriendHide, TransferUpQueueFriendLine, SharedList, SharedLine, Graphs, Log, ServerInfo, DebugLog, Stats, Preferences, Login, AddServerBox, Search, ProgressbarWidth, SearchHeader, SearchResultLine, ProgressbarImgs, ProgressbarImgsPercent, CatArrow, DownArrow, UpArrow, DownDoubleArrow, UpDoubleArrow, Kad, BootstrapLine, MyInfoLog, CommentList, CommentListLine, Count }; enum class WebTemplateLogView : std::uint8_t { Log, ServerInfo, DebugLog }; struct WebHeaderRuntime { CString version, serverName; std::uint32_t serverUsers = 0, serverMaxUsers = 0, serverFiles = 0; std::uint32_t allUsers = 0, allFiles = 0, openSockets = 0; double downloadRate = 0.0, uploadRate = 0.0; bool serverConnecting = false, serverConnected = false, highId = false; bool kad2Connected = false, kadFirewalled = false; bool kad6Connected = false, kadRunning = false; }; struct WebCommentRow { CString user, file, text, rating; }; struct WebCommentListInput { bool found = false; CString fileName; std::vector<WebCommentRow> rows; }; M2AModuleHandle M2A_BIND_W2_071B3D442B(const M2AParentPort&); void M2A_UNBIND_W2_071B3D442B(const M2AParentPort&); M2AModuleHandle M2A_BIND_W2_9330EBAD15(const M2AParentPort&); void M2A_UNBIND_W2_9330EBAD15(const M2AParentPort&); bool ReloadWebTemplates(const M2AParentPort&, const CString&, bool, bool, bool&); CString GetWebTemplate(const M2AParentPort&, WebTemplateId); CString GetWebTemplateLastModified(const M2AParentPort&); CString GetWebTemplateETag(const M2AParentPort&); M2AModuleHandle CaptureWebTemplateSnapshot(const M2AParentPort&); CString EscapeWebTemplateText(const CString&, bool); CString GetWebPlainResource(UINT, bool); bool RunWebTemplateCharacterizationSelfTest(); CString RenderWebHeader(const M2AParentPort&, const CString&, const CString&, const CString&, long, bool, std::uint32_t, const CString&, const CString&, const CString&, const WebHeaderRuntime&); CString RenderWebFooter(const M2AParentPort&, const CString&); CString RenderWebLogin(const M2AParentPort&, const CString&, const CStringA&, bool, const CString&); CString RenderWebLogView(WebTemplateLogView, const CString&, const CString&, const CString&); CString RenderWebMyInfo(const CString&, const CString&); CString RenderWebStats(const CString&, const CString&); CString RenderWebCommentList(const WebCommentListInput&, const CString&, const CString&); void InsertWebCategoryBox(CString&, int, LPCTSTR, bool, bool, const CString&, const CString&, int, bool); bool RunWebPageChromeCharacterizationSelfTest();
enum class WebServerAction : std::uint8_t { Connect, Disconnect, Remove, AddStatic, RemoveStatic, PriorityLow, PriorityNormal, PriorityHigh }; struct WebServerRow { CString description, fullIp, ip, name, priorityText, state, version; std::uint32_t files = 0, hardLimit = 0, maxUsers = 0, ping = 0; std::uint32_t softLimit = 0, users = 0; int failed = 0, port = 0; std::uint8_t priority = 0; bool isStatic = false; }; struct WebServerPageInput { CString url, pageTemplate, rowTemplate, addTemplate, upArrow, downArrow; bool admin = false; unsigned sort = 0; bool reverse = false; std::array<bool, 10> hidden{}; }; struct WebServerPageResult { CString html; unsigned sort = 0; bool reverse = false; std::array<bool, 10> hidden{}; }; struct WebServerGuiPort { void* context = nullptr; CString (*parse)(void*, const CString&, const CString&) = nullptr; CString (*plain)(void*, unsigned) = nullptr; void (*action)(void*, WebServerAction, const CString&, int) = nullptr; bool (*addServer)(void*, const CString&, int, const CString&, const CString&, bool, bool, CString&) = nullptr; void (*updateServerMet)(void*, const CString&, CString&) = nullptr; void (*saveHidden)(void*, const std::array<bool, 10>&) = nullptr; void (*snapshot)(void*, std::vector<WebServerRow>&) = nullptr; bool Complete() const noexcept; }; M2AModuleHandle M2A_BIND_W3_F05B56128F(const M2AParentPort&); void M2A_UNBIND_W3_F05B56128F(const M2AParentPort&); WebServerPageResult RunWebServerPage(const M2AParentPort&, const WebServerPageInput&, const WebServerGuiPort&); bool RunWebServerPageCharacterizationSelfTest();
enum class WebTransferTemplate : std::uint8_t { Images, List, DownHeader, DownFooter, DownLine, UpHeader, UpFooter, UpLine, QueueShow, QueueHide, QueueLine, QueueBannedShow, QueueBannedHide, QueueBannedLine, QueueFriendShow, QueueFriendHide, QueueFriendLine, ProgressbarWidth, CatArrow, DownArrow, UpArrow };
struct WebTransferProjectionInput { CString url, session, categorySuffix, selectedFile; int category = 0; bool admin = false; unsigned downloadSort = 0, uploadSort = 0, queueSort = 0; bool downloadReverse = false, uploadReverse = false, queueReverse = false; bool showQueue = false, showBanned = false, showFriend = false; unsigned maxWebUploadFileSizeMB = 0; std::array<bool, 8> downloadHidden{}; std::array<bool, 5> uploadHidden{}; std::array<bool, 4> queueHidden{}; };
struct WebTransferSnapshot { CArray<DownloadFiles> downloads; CArray<UploadUsers> uploads; CArray<QueueUsers> queue; int queueCount = 0, bannedCount = 0, friendCount = 0; int queueSecure = 0, bannedSecure = 0, friendSecure = 0; };
struct WebTransferProjectionPort { void* context = nullptr; CString (*templateText)(void*, WebTransferTemplate) = nullptr; CString (*plain)(void*, unsigned) = nullptr; CString (*special)(void*, const CString&, bool) = nullptr; void (*insertCategory)(void*, CString&, int, LPCTSTR, bool, bool, const CString&, const CString&, int) = nullptr; void (*snapshot)(void*, int, unsigned, bool, unsigned, bool, unsigned, bool, bool, bool, bool, WebTransferSnapshot&) = nullptr; bool Complete() const noexcept; };
M2AModuleHandle M2A_BIND_W4_AD763A5EE0(const M2AParentPort&); void M2A_UNBIND_W4_AD763A5EE0(const M2AParentPort&); CString RunWebTransferProjection(const M2AParentPort&, const WebTransferProjectionInput&, const WebTransferProjectionPort&); bool RunWebTransferProjectionCharacterizationSelfTest();
}

static M2AParentPort WebTemplateParent(const void* parent) { return M2AParentPort{const_cast<void*>(parent)}; }
static std::uint64_t WebAuthNowMs()
{
	return eSELive::WebRequestAuthNowMs();
}
static std::uint64_t WebSessionTimeoutMs()
{
	return eSELive::WebRequestSessionTimeoutMs();
}

static void SendWebForbidden(CWebSocket* socket, const char* hint)
{
	CStringA body;
	body.Format("{\"error\":\"forbidden\",\"hint\":\"%s\"}", hint);
	CStringA header;
	header.Format(
		"HTTP/1.1 403 Forbidden\r\n"
		"Content-Type: application/json\r\n"
		"Cache-Control: no-store\r\n"
		"Content-Length: %d\r\n\r\n",
		body.GetLength());
	socket->SendData(header, header.GetLength());
	socket->SendData(body, body.GetLength());
}

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

#ifdef UNICODE
#define _tcreate_locale  _wcreate_locale
#else
#define _tcreate_locale  _create_locale
#endif // !UNICODE

// eSE: Cabeceras HTTP de seguridad reforzadas (Fase 1 - CORS/CSRF)
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
#define HTTPENCODING _T("utf-8")

//SyruS CQArray-Sorting operators
bool operator > (QueueUsers &first, QueueUsers &second)
{
	return (first.sIndex.CompareNoCase(second.sIndex) > 0);
}
bool operator < (QueueUsers &first, QueueUsers &second)
{
	return (first.sIndex.CompareNoCase(second.sIndex) < 0);
}

bool operator > (SearchFileStruct &first, SearchFileStruct &second)
{
	return (first.m_strIndex.CompareNoCase(second.m_strIndex) > 0);
}
bool operator < (SearchFileStruct &first, SearchFileStruct &second)
{
	return (first.m_strIndex.CompareNoCase(second.m_strIndex) < 0);
}

static BOOL	WSdownloadColumnHidden[8];
static BOOL	WSuploadColumnHidden[5];
static BOOL	WSqueueColumnHidden[4];
static BOOL	WSsharedColumnHidden[7];
static BOOL	WSserverColumnHidden[10];
static BOOL	WSsearchColumnHidden[4];

CWebServer::CWebServer()
	: m_uCurIP()
	, m_iSearchSortby(3)
	, m_nIntruderDetect()
	, m_bServerWorking()
	, m_bSearchAsc()
	, m_bIsTempDisabled()
{
	M2AModuleHandle serverListBinding = M2A_BIND_W3_F05B56128F(M2AParentPort{this}); if (!serverListBinding) return; CIni ini(thePrefs.GetConfigFile(), _T("WebServer"));
	ini.SerGet(true, WSdownloadColumnHidden, _countof(WSdownloadColumnHidden), _T("downloadColumnHidden"));
	ini.SerGet(true, WSuploadColumnHidden, _countof(WSuploadColumnHidden), _T("uploadColumnHidden"));
	ini.SerGet(true, WSqueueColumnHidden, _countof(WSqueueColumnHidden), _T("queueColumnHidden"));
	ini.SerGet(true, WSsearchColumnHidden, _countof(WSsearchColumnHidden), _T("searchColumnHidden"));
	ini.SerGet(true, WSsharedColumnHidden, _countof(WSsharedColumnHidden), _T("sharedColumnHidden"));
	ini.SerGet(true, WSserverColumnHidden, _countof(WSserverColumnHidden), _T("serverColumnHidden"));
	m_Params.bShowUploadQueue = ini.GetBool(_T("ShowUploadQueue"), false);
	m_Params.bShowUploadQueueBanned = ini.GetBool(_T("ShowUploadQueueBanned"), false);
	m_Params.bShowUploadQueueFriend = ini.GetBool(_T("ShowUploadQueueFriend"), false);
	m_Params.bDownloadSortReverse = ini.GetBool(_T("DownloadSortReverse"), true);
	m_Params.bUploadSortReverse = ini.GetBool(_T("UploadSortReverse"), true);
	m_Params.bQueueSortReverse = ini.GetBool(_T("QueueSortReverse"), true);
	m_Params.bServerSortReverse = ini.GetBool(_T("ServerSortReverse"), true);
	m_Params.bSharedSortReverse = ini.GetBool(_T("SharedSortReverse"), true);
	m_Params.DownloadSort = (DownloadSort)ini.GetInt(_T("DownloadSort"), DOWN_SORT_NAME);
	m_Params.UploadSort = (UploadSort)ini.GetInt(_T("UploadSort"), UP_SORT_FILENAME);
	m_Params.QueueSort = (QueueSort)ini.GetInt(_T("QueueSort"), QU_SORT_FILENAME);
	m_Params.ServerSort = (ServerSort)ini.GetInt(_T("ServerSort"), SERVER_SORT_NAME);
	m_Params.SharedSort = (SharedSort)ini.GetInt(_T("SharedSort"), SHARED_SORT_NAME);
}

CWebServer::~CWebServer()
{
	// save layout settings
	CIni ini(thePrefs.GetConfigFile(), _T("WebServer"));
	ini.WriteBool(_T("ShowUploadQueue"), m_Params.bShowUploadQueue);
	ini.WriteBool(_T("ShowUploadQueueBanned"), m_Params.bShowUploadQueueBanned);
	ini.WriteBool(_T("ShowUploadQueueFriend"), m_Params.bShowUploadQueueFriend);
	ini.WriteBool(_T("DownloadSortReverse"), m_Params.bDownloadSortReverse);
	ini.WriteBool(_T("UploadSortReverse"), m_Params.bUploadSortReverse);
	ini.WriteBool(_T("QueueSortReverse"), m_Params.bQueueSortReverse);
	ini.WriteBool(_T("ServerSortReverse"), m_Params.bServerSortReverse);
	ini.WriteBool(_T("SharedSortReverse"), m_Params.bSharedSortReverse);
	ini.WriteInt(_T("DownloadSort"), m_Params.DownloadSort);
	ini.WriteInt(_T("UploadSort"), m_Params.UploadSort);
	ini.WriteInt(_T("QueueSort"), m_Params.QueueSort);
	ini.WriteInt(_T("ServerSort"), m_Params.ServerSort);
	ini.WriteInt(_T("SharedSort"), m_Params.SharedSort);
	if (m_bServerWorking)
		StopSockets();
	M2A_UNBIND_W1_EC6846B80E(M2AParentPort{this}); M2A_UNBIND_W2_9330EBAD15(M2AParentPort{this}); M2A_UNBIND_W2_071B3D442B(M2AParentPort{this}); M2A_UNBIND_W3_F05B56128F(M2AParentPort{this}); M2A_UNBIND_W4_AD763A5EE0(M2AParentPort{this});
}

void CWebServer::_SaveWIConfigArray(BOOL *array, int size, LPCTSTR key)
{
	CIni ini(thePrefs.GetConfigFile(), _T("WebServer"));
	ini.SerGet(false, array, size, key);
}

bool CWebServer::ReloadTemplates()
{
	M2AModuleHandle binding = M2A_BIND_W2_071B3D442B(M2AParentPort{this}); if (!binding) return false; bool stopServer = false; const bool loaded = ReloadWebTemplates(M2AParentPort{this}, thePrefs.GetTemplate(), thePrefs.GetWSIsEnabled(), m_bServerWorking, stopServer); if (stopServer) StopServer(); return loaded;
}
//Cax2 - restarts the server with the new port settings
void CWebServer::RestartSockets()
{
	M2AModuleHandle headerBinding = M2A_BIND_W2_9330EBAD15(M2AParentPort{this}); if (!headerBinding) return; StopSockets();
	if (m_bServerWorking)
		StartSockets(this);
}

void CWebServer::StartServer()
{
	M2AModuleHandle requestDispatchBinding = M2A_BIND_W1_EC6846B80E(M2AParentPort{this}); if (!requestDispatchBinding) return; M2AModuleHandle templateBinding = M2A_BIND_W2_071B3D442B(M2AParentPort{this}); M2AModuleHandle headerBinding = M2A_BIND_W2_9330EBAD15(M2AParentPort{this}); if (!templateBinding || !headerBinding) return;
	bool wsPrefEnabled = thePrefs.GetWSIsEnabled();
	LIVE_LOG("WS", "StartServer entry: pref.Enabled=%d  pref.Port=%u  serverWorking=%d  template=\"%S\"",
		(int)wsPrefEnabled, (unsigned)thePrefs.GetWSPort(),
		(int)m_bServerWorking, (LPCWSTR)thePrefs.GetTemplate());
	if (m_bServerWorking == wsPrefEnabled) {
		LIVE_LOG("WS", "StartServer SKIP: already in target state (%d)", (int)wsPrefEnabled);
		return;
	}
	m_bServerWorking = wsPrefEnabled;
	if (m_bServerWorking) {
		LIVE_LOG("WS", "StartServer: calling ReloadTemplates()");
		ReloadTemplates();
		LIVE_LOG("WS", "StartServer: ReloadTemplates returned, serverWorking=%d", (int)m_bServerWorking);
		if (m_bServerWorking) {
			LIVE_LOG("WS", "StartServer: calling StartSockets()");
			StartSockets(this);
			m_nIntruderDetect = 0;
			m_bIsTempDisabled = false;
			LIVE_LOG("WS", "StartServer: StartSockets returned (no bind feedback yet — see WSL events)");
		} else {
			LIVE_LOG("WS", "StartServer ABORT: ReloadTemplates disabled the server");
		}
	} else {
		LIVE_LOG("WS", "StartServer: stopping (pref disabled)");
		StopSockets();
	}
	UINT uid = (thePrefs.GetWSIsEnabled() && m_bServerWorking) ? IDS_ENABLED : IDS_DISABLED;
	AddLogLine(false, _T("%s: %s%s")
		, (LPCTSTR)_GetPlainResString(IDS_PW_WS)
		, (LPCTSTR)_GetPlainResString(uid).MakeLower()
		, (uid == IDS_ENABLED && thePrefs.GetWebUseHttps()) ? _T(" (HTTPS)") : _T(""));
	LIVE_LOG("WS", "StartServer EXIT: bServerWorking=%d  pref.Enabled=%d",
		(int)m_bServerWorking, (int)thePrefs.GetWSIsEnabled());
}

void CWebServer::StopServer()
{
	if (m_bServerWorking) {
		StopSockets();
		m_bServerWorking = false;
	}
	thePrefs.SetWSIsEnabled(false);
}

void CWebServer::AddStatsLine(const UpDown &line)
{
	m_Params.PointsForWeb.Add(line);
	if (m_Params.PointsForWeb.GetCount() > WEB_GRAPH_WIDTH)
		m_Params.PointsForWeb.RemoveAt(0);
}

CString CWebServer::_SpecialChars(const CString &cstr, bool noquote /*=false*/)
{
	return EscapeWebTemplateText(cstr, noquote);
}

bool CWebServer::RunCharacterizationSelfTest(CString& outFailure)
{
	outFailure.Empty();
	if (_ParseURL(_T("/?a=one&b=two"), _T("b")) != _T("two")) {
		outFailure = _T("web parser failed deterministic query");
		return false;
	}
	std::string parserFailure;
	if (!ese::web::RunCharacterizationSelfTest(parserFailure)) {
		outFailure = OptUtf8ToStr(
			parserFailure.data(), static_cast<int>(parserFailure.size()));
		return false;
	}
	std::string authFailure;
	if (!ese::web::RunWebAuthPolicySelfTest(authFailure)) {
		outFailure = OptUtf8ToStr(
			authFailure.data(), static_cast<int>(authFailure.size()));
		return false;
	}
	std::string routeFailure;
	if (!ese::web::RunWebRouteTableSelfTest(routeFailure)) {
		outFailure = OptUtf8ToStr(routeFailure.data(), static_cast<int>(routeFailure.size()));
		return false;
	}
	if (!RunWebClassicRequestCharacterizationSelfTest()) { outFailure = _T("web request dispatch route table changed"); return false; } if (!RunWebTemplateCharacterizationSelfTest() || !RunWebPageChromeCharacterizationSelfTest()) { outFailure = _T("web template/header rendering changed"); return false; } if (!RunWebServerPageCharacterizationSelfTest()) { outFailure = _T("web server-list rendering changed"); return false; } if (!RunWebTransferProjectionCharacterizationSelfTest()) { outFailure = _T("web transfer projection changed"); return false; }
	std::string serializerFailure;
	if (!ese::web::RunWebApiSerializerSelfTest(serializerFailure)) {
		outFailure = OptUtf8ToStr(
			serializerFailure.data(),
			static_cast<int>(serializerFailure.size()));
		return false;
	}
	std::string diagnosticsFailure;
	if (!ese::web::RunWebDiagnosticsSelfTest(diagnosticsFailure)) {
		outFailure = OptUtf8ToStr(
			diagnosticsFailure.data(),
			static_cast<int>(diagnosticsFailure.size()));
		return false;
	}
	std::string staticFailure;
	if (!ese::web::RunWebStaticAssetsSelfTest(staticFailure)) {
		outFailure = OptUtf8ToStr(
			staticFailure.data(), static_cast<int>(staticFailure.size()));
		return false;
	}
	std::string responseFailure;
	if (!ese::web::RunWebSocketResponseSelfTest(responseFailure)) {
		outFailure = OptUtf8ToStr(
			responseFailure.data(),
			static_cast<int>(responseFailure.size()));
		return false;
	}
	if (_SpecialChars(_T("<&\"'\n"), true) != _T("&lt;&amp;&quot;&#8217;\\n")) {
		outFailure = _T("web serialization escaping changed");
		return false;
	}
	const Bytef input[] = "mod02";
	Bytef compressed[64] = {};
	uLongf compressedLength = sizeof(compressed);
	if (CompressWebGzip(compressed, &compressedLength, input, sizeof(input) - 1, Z_BEST_SPEED) != 0
		|| compressedLength < 18
		|| compressed[0] != 0x1f || compressed[1] != 0x8b) {
		outFailure = _T("web gzip serialization failed");
		return false;
	}
	const uLong expectedCrc = crc32(0, input, sizeof(input) - 1);
	const size_t trailer = static_cast<size_t>(compressedLength) - 8;
	const uint32 trailerCrc = static_cast<uint32>(compressed[trailer])
		| (static_cast<uint32>(compressed[trailer + 1]) << 8)
		| (static_cast<uint32>(compressed[trailer + 2]) << 16)
		| (static_cast<uint32>(compressed[trailer + 3]) << 24);
	const uint32 trailerSize = static_cast<uint32>(compressed[trailer + 4])
		| (static_cast<uint32>(compressed[trailer + 5]) << 8)
		| (static_cast<uint32>(compressed[trailer + 6]) << 16)
		| (static_cast<uint32>(compressed[trailer + 7]) << 24);
	if (trailerCrc != static_cast<uint32>(expectedCrc)
		|| trailerSize != sizeof(input) - 1) {
		outFailure = _T("web gzip trailer changed");
		return false;
	}
	Bytef inflated[sizeof(input) - 1] = {};
	z_stream inflater = {};
	inflater.next_in = compressed;
	inflater.avail_in = static_cast<uInt>(compressedLength);
	inflater.next_out = inflated;
	inflater.avail_out = sizeof(inflated);
	if (inflateInit2(&inflater, MAX_WBITS + 16) != Z_OK) {
		outFailure = _T("web gzip inflate init failed");
		return false;
	}
	const int inflateResult = inflate(&inflater, Z_FINISH);
	inflateEnd(&inflater);
	if (inflateResult != Z_STREAM_END || inflater.total_out != sizeof(inflated)
		|| memcmp(inflated, input, sizeof(inflated)) != 0) {
		outFailure = _T("web gzip round-trip changed");
		return false;
	}
	return true;
}

void CWebServer::_ProcessURL(const ThreadData &Data)
{
	CWebServer* owner = reinterpret_cast<CWebServer*>(Data.pThis); if (owner == NULL) return;
	WebClassicPort port; port.context = owner;
	port.parse_url = [](const CString& url, const CString& field) { return _ParseURL(url, field); };
	port.validate_challenge = [](const void* raw, const CString& nonce, const CString& response, bool& admin) { return _ValidateChallengeResponse(*static_cast<const ThreadData*>(raw), nonce, response, admin); };
	port.login_blocked = [](void* raw, std::uint32_t ip, std::uint64_t now) { return static_cast<CWebServer*>(raw)->m_authPolicy.IsLoginBlocked(ip, now); };
	port.add_session = [](void* raw, std::uint32_t id, bool admin, int category, std::uint64_t now, const CStringA& csrf) {
		return static_cast<CWebServer*>(raw)->m_authPolicy.AddSession(id, admin ? ese::web::WebRole::Admin : ese::web::WebRole::Guest, category, now, std::string((LPCSTR)csrf, csrf.GetLength())); };
	port.validate_csrf = [](void* raw, std::uint32_t id, const CStringA& token, const CStringA& fetchSite) {
		ese::web::WebSessionSnapshot session; CWebServer* server = static_cast<CWebServer*>(raw); if (!server->m_authPolicy.GetSession(id, session)) return true;
		return ese::web::WebAuthPolicy::ValidateCsrfRequest(session, std::string((LPCSTR)token, token.GetLength()), std::string((LPCSTR)fetchSite, fetchSite.GetLength())); };
	port.record_login_failure = [](void* raw, std::uint32_t ip, std::uint64_t now) { static_cast<CWebServer*>(raw)->m_authPolicy.RecordLoginFailure(ip, now); };
	port.record_login_success = [](void* raw, std::uint32_t ip) { static_cast<CWebServer*>(raw)->m_authPolicy.RecordLoginSuccess(ip); };
	port.remove_session = [](const void* raw, long session) { return _RemoveSession(*static_cast<const ThreadData*>(raw), session); };
	port.is_logged_in = [](const void* raw, long session) { return _IsLoggedIn(*static_cast<const ThreadData*>(raw), session); };
	port.is_admin = [](const void* raw, const CString& session) { return _IsSessionAdmin(*static_cast<const ThreadData*>(raw), session); };
	port.send_content = [](const void* raw, const CStringA& header, const CString& body) { static_cast<const ThreadData*>(raw)->pSocket->SendContent(header, body); };
	port.send_binary = [](const void* raw, const CStringA& header, const void* body, unsigned long size) { static_cast<const ThreadData*>(raw)->pSocket->SendContent(header, body, size); };
	port.send_reply = [](const void* raw, const char* reply) { static_cast<const ThreadData*>(raw)->pSocket->SendReply(reply); };
	port.notify_login = [](bool admin, const CString& ip) { SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_UPDATEMYINFO, 0); AddLogLine(true, GetResString(admin ? IDS_WEB_ADMINLOGIN : IDS_WEB_GUESTLOGIN) + _T(" (%s)"), (LPCTSTR)ip); };
	port.notify_bad_login = [](const CString& ip) { LogWarning(LOG_STATUSBAR, GetResString(IDS_WEB_BADLOGINATTEMPT) + _T(" (%s)"), (LPCTSTR)ip); };
	port.perform_admin_action = [](WebAdminAction action) { if (action == WebAdminAction::Close) { theApp.m_app_state = APP_STATE_SHUTTINGDOWN; SendMessage(theApp.emuledlg->m_hWnd, WM_CLOSE, 0, 0); } else SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_WINFUNC, action == WebAdminAction::Shutdown ? 1 : 2); };
	port.send_requested_file = [](const void* raw, const CString& fileHash) {
		const ThreadData& data = *static_cast<const ThreadData*>(raw); uchar hash[MDX_DIGEST_SIZE]; if (!strmd4(fileHash, hash)) return false;
		CKnownFile* file = theApp.sharedfiles->GetFileByID(hash); if (file == NULL) return false; const UINT maxMb = thePrefs.GetMaxWebUploadFileSizeMB();
		if (maxMb != 0 && file->GetFileSize() > static_cast<uint64>(maxMb) * 1024 * 1024) { data.pSocket->SendReply("HTTP/1.1 403 Forbidden\r\n"); return true; }
		const CStringA name(wc2utf8(file->GetFileName())); ese::web::WebFileResponseOptions options; options.cacheControl = "no-store";
		options.attachmentUtf8.assign((LPCSTR)name, name.GetLength()); data.pSocket->SendFileResponse(file->GetFilePath(), "download.bin", data.sRange, options, static_cast<ULONGLONG>(maxMb) * 1024ull * 1024ull, false, true); return true; };
	port.render = [](WebClassicView view, const void* raw, long session) {
		const ThreadData& data = *static_cast<const ThreadData*>(raw); switch (view) {
		case WebClassicView::Login: return _GetLoginScreen(data); case WebClassicView::RemoteLinkAdded: return _GetRemoteLinkAddedOk(data); case WebClassicView::RemoteLinkFailed: return _GetRemoteLinkAddedFailed(data); case WebClassicView::CommentList: return _GetCommentlist(data);
		case WebClassicView::Header: return _GetHeader(data, session); case WebClassicView::Footer: return _GetFooter(data); case WebClassicView::Server: return _GetServerList(data); case WebClassicView::Shared: return _GetSharedFilesList(data); case WebClassicView::Transfer: return _GetTransferList(data);
		case WebClassicView::Search: return _GetSearch(data); case WebClassicView::Graphs: return _GetGraphs(data); case WebClassicView::Log: return _GetLog(data);
		case WebClassicView::ServerInfo: return _GetServerInfo(data); case WebClassicView::DebugLog: return _GetDebugLog(data); case WebClassicView::MyInfo: return _GetMyInfo(data); case WebClassicView::Stats: return _GetStats(data); case WebClassicView::Kad: return _GetKadDlg(data); case WebClassicView::Options: return _GetPreferences(data);
		default: return CString();
		}
	};
	WebClassicInput input; input.legacy = &Data; input.url = Data.sURL; input.ip_text = ipstr(Data.inadr); input.csrf_token = Data.sCsrfToken; input.fetch_site = Data.sFetchSite;
	input.admin_password_hash = thePrefs.GetWSPass(); input.guest_password_hash = thePrefs.GetWSLowPass(); input.access_denied_text = _GetPlainResString(IDS_ACCESSDENIED); input.ip = inet_addr(ipstrA(Data.inadr));
	input.default_category = -thePrefs.GetCatFilter(0); input.loopback = Data.inadr.S_un.S_addr == htonl(INADDR_LOOPBACK); input.app_running = theApp.IsRunning(); input.use_gzip = thePrefs.GetWebUseGzip(); input.guest_enabled = thePrefs.GetWSIsLowUserEnabled(); input.allow_high_level = thePrefs.GetWebAdminAllowedHiLevFunc();
	M2AModuleHandle templateSnapshot = CaptureWebTemplateSnapshot(WebTemplateParent(owner)); RunWebClassicRequest(M2AParentPort{owner}, input, port);
}

CString CWebServer::_ParseURLArray(CString URL, CString fieldname)
{
	const CStringA urlA(URL);
	const CStringA fieldA(fieldname);
	const std::string url(urlA.GetString(), urlA.GetLength());
	const std::string field(fieldA.GetString(), fieldA.GetLength());
	std::vector<std::string> values;
	if (ese::web::GetQueryValues(url, field, values) != ese::web::QueryStatus::Ok)
		return CString();
	CString res;
	for (const std::string &value : values) {
		const CString decoded(OptUtf8ToStr(
			value.data(), static_cast<int>(value.size())));
		if (decoded.IsEmpty())
			break;
		res.AppendFormat(_T("%s|"), (LPCTSTR)decoded);
	}
	return res;
}

CString CWebServer::_ParseURL(const CString &URL, const CString &fieldname)
{
	const CStringA urlA(URL);
	const CStringA fieldA(fieldname);
	const std::string url(urlA.GetString(), urlA.GetLength());
	const std::string field(fieldA.GetString(), fieldA.GetLength());
	std::string value;
	if (ese::web::GetQueryValue(url, field, value) != ese::web::QueryStatus::Ok)
		return CString();
	return OptUtf8ToStr(value.data(), static_cast<int>(value.size()));
}

CString CWebServer::_GetHeader(const ThreadData &Data, long lSession)
{
	CWebServer* owner = reinterpret_cast<CWebServer*>(Data.pThis); if (owner == NULL) return CString();
	WebHeaderRuntime runtime; runtime.version = theApp.m_strCurVersionLong; runtime.serverConnecting = theApp.serverconnect->IsConnecting(); runtime.serverConnected = theApp.serverconnect->IsConnected(); runtime.highId = theApp.HasVerifiedEd2kHighId(); if (runtime.serverConnected) { CServer* current = theApp.serverconnect->GetCurrentServer(); CServer* server = current == NULL ? NULL : theApp.serverlist->GetServerByAddress(current->GetAddress(), current->GetPort()); if (server != NULL) { runtime.serverName = server->GetListName(); runtime.serverUsers = server->GetUsers(); runtime.serverMaxUsers = server->GetMaxUsers(); runtime.serverFiles = server->GetFiles(); } } for (INT_PTR index = theApp.serverlist->GetServerCount(); --index >= 0;) { const CServer* server = theApp.serverlist->GetServerAt(index); runtime.allUsers += server->GetUsers(); runtime.allFiles += server->GetFiles(); } runtime.kad2Connected = Kademlia::CKademlia::IsKad2Connected(); runtime.kadFirewalled = Kademlia::CKademlia::IsFirewalled(); runtime.kad6Connected = Kademlia::CKademlia::IsKad6Connected(); runtime.kadRunning = Kademlia::CKademlia::IsRunning(); runtime.downloadRate = theApp.downloadqueue->GetDatarate(); runtime.uploadRate = theApp.uploadqueue->GetDatarate(); runtime.openSockets = theApp.listensocket->GetOpenSockets();
	return RenderWebHeader(WebTemplateParent(owner), _ParseURL(Data.sURL, _T("w")), _ParseURL(Data.sURL, _T("cat")), _ParseURL(Data.sURL, _T("c")), lSession, _IsSessionAdmin(Data, lSession), GenerateWebRequestWord32(), GetWebTemplate(WebTemplateParent(owner), WebTemplateId::Header), GetWebTemplate(WebTemplateParent(owner), WebTemplateId::HeaderStylesheet), GetWebTemplate(WebTemplateParent(owner), WebTemplateId::CatArrow), runtime);
}
const CString CWebServer::_GetFooter(const ThreadData &Data)
{
	const CWebServer* owner = reinterpret_cast<CWebServer*>(Data.pThis); return owner == NULL ? CString() : RenderWebFooter(WebTemplateParent(owner), GetWebTemplate(WebTemplateParent(owner), WebTemplateId::Footer));
}
CString CWebServer::_GetServerList(const ThreadData &Data)
{
	M2AModuleHandle binding = M2A_BIND_W3_F05B56128F(M2AParentPort{Data.pThis}); if (!binding) return CString();
	CWebServer* owner = static_cast<CWebServer*>(Data.pThis); if (owner == nullptr) return CString();
	WebServerPageInput input; input.url = Data.sURL; input.admin = _IsSessionAdmin(Data, _ParseURL(Data.sURL, _T("ses"))); input.sort = owner->m_Params.ServerSort; input.reverse = owner->m_Params.bServerSortReverse;
	input.pageTemplate = GetWebTemplate(WebTemplateParent(owner), WebTemplateId::ServerList); input.rowTemplate = GetWebTemplate(WebTemplateParent(owner), WebTemplateId::ServerLine); input.addTemplate = GetWebTemplate(WebTemplateParent(owner), WebTemplateId::AddServerBox); input.upArrow = GetWebTemplate(WebTemplateParent(owner), WebTemplateId::UpArrow); input.downArrow = GetWebTemplate(WebTemplateParent(owner), WebTemplateId::DownArrow);
	for (std::size_t index = 0; index < input.hidden.size(); ++index) input.hidden[index] = WSserverColumnHidden[index] != FALSE;
	WebServerGuiPort port; port.context = owner;
	port.parse = [](void*, const CString& url, const CString& field) { return _ParseURL(url, field); };
	port.plain = [](void*, unsigned id) { return _GetPlainResString(id); };
	port.action = [](void*, WebServerAction action, const CString& ip, int serverPort) { if (action == WebServerAction::Disconnect) { const bool connecting = theApp.serverconnect->IsConnecting(); SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, connecting ? WEBGUIIA_STOPCONNECTING : WEBGUIIA_DISCONNECT, connecting ? 0 : 1); return; } if (action == WebServerAction::Connect && ip.IsEmpty()) { SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_CONNECTTOSERVER, 0); return; } CServer* server = theApp.serverlist->GetServerByAddress(ip, static_cast<uint16>(serverPort)); if (server == nullptr) return; switch (action) { case WebServerAction::Connect: SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_CONNECTTOSERVER, reinterpret_cast<LPARAM>(server)); break; case WebServerAction::Remove: SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_SERVER_REMOVE, reinterpret_cast<LPARAM>(server)); break; case WebServerAction::AddStatic: SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_ADD_TO_STATIC, reinterpret_cast<LPARAM>(server)); break; case WebServerAction::RemoveStatic: SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_REMOVE_FROM_STATIC, reinterpret_cast<LPARAM>(server)); break; case WebServerAction::PriorityLow: server->SetPreference(SRV_PR_LOW); SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_UPDATESERVER, reinterpret_cast<LPARAM>(server)); break; case WebServerAction::PriorityNormal: server->SetPreference(SRV_PR_NORMAL); SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_UPDATESERVER, reinterpret_cast<LPARAM>(server)); break; case WebServerAction::PriorityHigh: server->SetPreference(SRV_PR_HIGH); SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_UPDATESERVER, reinterpret_cast<LPARAM>(server)); break; default: break; } };
	port.addServer = [](void*, const CString& address, int serverPort, const CString& name, const CString& priority, bool makeStatic, bool connectNow, CString& message) { message = EscapeWebTemplateText(theApp.emuledlg->GetLastLogEntry(), true); CServer* server = new CServer(static_cast<uint16>(serverPort), address); server->SetListName(name); if (!theApp.emuledlg->serverwnd->serverlistctrl.AddServer(server, true)) { delete server; return false; } if (priority == _T("low")) server->SetPreference(PR_LOW); else if (priority == _T("normal")) server->SetPreference(PR_NORMAL); else if (priority == _T("high")) server->SetPreference(PR_HIGH); SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_UPDATESERVER, reinterpret_cast<LPARAM>(server)); if (makeStatic) { SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_ADD_TO_STATIC, reinterpret_cast<LPARAM>(server)); message.AppendFormat(_T("<br>%s"), (LPCTSTR)EscapeWebTemplateText(theApp.emuledlg->GetLastLogEntry(), true)); } if (connectNow) SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_CONNECTTOSERVER, reinterpret_cast<LPARAM>(server)); return true; };
	port.updateServerMet = [](void*, const CString& url, CString& message) { SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_UPDATESERVERMETFROMURL, reinterpret_cast<LPARAM>((LPCTSTR)url)); message = EscapeWebTemplateText(theApp.emuledlg->GetLastLogEntry(), true); };
	port.saveHidden = [](void*, const std::array<bool, 10>& hidden) { for (std::size_t index = 0; index < hidden.size(); ++index) WSserverColumnHidden[index] = hidden[index]; _SaveWIConfigArray(WSserverColumnHidden, _countof(WSserverColumnHidden), _T("serverColumnHidden")); };
	port.snapshot = [](void*, std::vector<WebServerRow>& rows) { rows.reserve(static_cast<std::size_t>(theApp.serverlist->GetServerCount())); for (INT_PTR index = theApp.serverlist->GetServerCount(); --index >= 0;) { const CServer& server = *theApp.serverlist->GetServerAt(index); WebServerRow row; row.name = EscapeWebTemplateText(server.GetListName(), true); row.ip = server.GetAddress(); row.port = server.GetPort(); row.description = EscapeWebTemplateText(server.GetDescription(), true); row.ping = server.GetPing(); row.users = server.GetUsers(); row.maxUsers = server.GetMaxUsers(); row.files = server.GetFiles(); row.isStatic = server.IsStaticMember(); unsigned priorityId = 0; switch (server.GetPreference()) { case SRV_PR_HIGH: priorityId = IDS_PRIOHIGH; row.priority = 2; break; case SRV_PR_NORMAL: priorityId = IDS_PRIONORMAL; row.priority = 1; break; case SRV_PR_LOW: priorityId = IDS_PRIOLOW; row.priority = 0; break; default: break; } if (priorityId != 0) row.priorityText = _GetPlainResString(priorityId); row.failed = server.GetFailedCount(); row.softLimit = server.GetSoftFiles(); row.hardLimit = server.GetHardFiles(); row.version = server.GetVersion(); if (inet_addr(CStringA(row.ip)) != INADDR_NONE) { for (int part = 0, position = 0; part < 4 && position >= 0; ++part) { const CString token(row.ip.Tokenize(_T("."), position)); row.fullIp.AppendFormat(&_T("000%s")[min(token.GetLength(), 3)], (LPCTSTR)token); } } else row.fullIp = row.ip; row.state = server.GetFailedCount() ? _T("failed") : _T("disconnected"); if (theApp.serverconnect->IsConnecting()) row.state = _T("connecting"); else if (theApp.serverconnect->IsConnected() && theApp.serverconnect->GetCurrentServer() != nullptr && theApp.serverconnect->GetCurrentServer()->GetFullIP() == server.GetFullIP()) row.state = theApp.HasVerifiedEd2kHighId() ? _T("high") : _T("low"); rows.push_back(row); } };
	if (!port.Complete()) return CString();
	const WebServerPageResult result(RunWebServerPage(WebTemplateParent(owner), input, port)); owner->m_Params.ServerSort = static_cast<ServerSort>(result.sort); owner->m_Params.bServerSortReverse = result.reverse;
	for (std::size_t index = 0; index < result.hidden.size(); ++index) WSserverColumnHidden[index] = result.hidden[index];
	return result.html;
}
void CWebServer::_MakeTransferList(CString &, CWebServer *pThis, const ThreadData &Data, void *, void *, bool bAdmin)
{
	const CString session(_ParseURL(Data.sURL, _T("ses"))); const long sessionId = _tstol(session); int cat; const CString category(_ParseURL(Data.sURL, _T("cat"))); if (category.IsEmpty()) cat = _GetLastUserCat(Data, sessionId); else cat = _tstoi(category);
	const CString &sClear(_ParseURL(Data.sURL, _T("clearcompleted"))); const ese::web::WebTransferClearAction clearAction = ese::web::WebTransferController::PlanClearCompleted( bAdmin, std::string(CT2A(sClear))); if (clearAction.allowed) { if (clearAction.all) theApp.emuledlg->SendMessage(WEB_CLEAR_COMPLETED, (WPARAM)0, (LPARAM)cat); else { uchar FileHash[MDX_DIGEST_SIZE]; if (strmd4(sClear, FileHash)) { uchar *pFileHash = new uchar[MDX_DIGEST_SIZE]; md4cpy(pFileHash, FileHash); theApp.emuledlg->SendMessage(WEB_CLEAR_COMPLETED, (WPARAM)1, reinterpret_cast<LPARAM>(pFileHash)); } } } CString HTTPTemp(_ParseURL(Data.sURL, _T("ed2k"))); const ese::web::WebTransferAddAction addAction = ese::web::WebTransferController::PlanAddDownload( bAdmin, std::string(CT2A(HTTPTemp))); if (addAction.allowed) theApp.emuledlg->SendMessage(WEB_ADDDOWNLOADS, (WPARAM)(LPCTSTR)HTTPTemp, cat); HTTPTemp = _ParseURL(Data.sURL, _T("c")); const CString menuIndex = _ParseURL(Data.sURL, _T("m")); const CString menuValue = _ParseURL(Data.sURL, _T("v")); const ese::web::WebTransferColumnChange columnChange = ese::web::WebTransferController::PlanColumnChange( bAdmin, std::string(CT2A(HTTPTemp)), std::string(CT2A(menuIndex)), std::string(CT2A(menuValue))); if (columnChange.allowed) { BOOL* columns = columnChange.group == ese::web::WebTransferColumnGroup::Download ? WSdownloadColumnHidden : (columnChange.group == ese::web::WebTransferColumnGroup::Upload ? WSuploadColumnHidden : WSqueueColumnHidden); columns[columnChange.index] = columnChange.hidden; LPCTSTR key = columnChange.group == ese::web::WebTransferColumnGroup::Download ? _T("downloadColumnHidden") : (columnChange.group == ese::web::WebTransferColumnGroup::Upload ? _T("uploadColumnHidden") : _T("queueColumnHidden")); const int count = columnChange.group == ese::web::WebTransferColumnGroup::Download ? 8 : (columnChange.group == ese::web::WebTransferColumnGroup::Upload ? 5 : 4); _SaveWIConfigArray(columns, count, key); } else if (HTTPTemp == _T("menuprio") && bAdmin) { const CString &sPrio(_ParseURL(Data.sURL, _T("p"))); const ese::web::WebTransferPriorityDecision priority = ese::web::WebTransferController::PlanCategoryPriority( bAdmin, std::string(CT2A(sPrio))); if (priority.allowed) { const int prio = priority.priority == ese::web::WebTransferCategoryPriority::Low ? PR_LOW : (priority.priority == ese::web::WebTransferCategoryPriority::High ? PR_HIGH : (priority.priority == ese::web::WebTransferCategoryPriority::Normal ? PR_NORMAL : PR_AUTO)); SendMessage(theApp.emuledlg->m_hWnd, WEB_CATPRIO, (WPARAM)cat, (LPARAM)prio); } } const CString sOp = _ParseURL(Data.sURL, _T("op")); const CString sFile = _ParseURL(Data.sURL, _T("file")); if (!sOp.IsEmpty() && sFile.IsEmpty()) { const CString sUser = _ParseURL(Data.sURL, _T("userhash")); const ese::web::WebTransferFriendAction action = ese::web::WebTransferController::PlanFriendAction( bAdmin, std::string(CT2A(sOp)), std::string(CT2A(sUser))); uchar userHash[MDX_DIGEST_SIZE]; if (action.allowed && strmd4(sUser, userHash)) { CUpDownClient* client = theApp.clientlist->FindClientByUserHash(userHash); if (action.operation == ese::web::WebTransferFriendOperation::Add && client) { SendMessage(theApp.emuledlg->m_hWnd, WEB_ADDREMOVEFRIEND, (WPARAM)client, (LPARAM)1); } else if (action.operation == ese::web::WebTransferFriendOperation::Remove && client) { const CFriend* friendEntry = theApp.friendlist->SearchFriend(userHash, 0, 0); if (friendEntry) SendMessage(theApp.emuledlg->m_hWnd, WEB_ADDREMOVEFRIEND, (WPARAM)friendEntry, (LPARAM)0); } } } else if (!sOp.IsEmpty()) { const CString actionText = sOp == _T("rename") ? _ParseURL(Data.sURL, _T("name")) : CString(); const CString numericValue = sOp == _T("setcat") ? _ParseURL(Data.sURL, _T("filecat")) : (sOp == _T("streamseek") ? _ParseURL(Data.sURL, _T("part")) : CString()); const ese::web::WebTransferFileAction action = ese::web::WebTransferController::PlanFileAction( bAdmin, std::string(CT2A(sOp)), std::string(CT2A(sFile)), std::string(CT2A(actionText)), std::string(CT2A(numericValue))); uchar fileHash[MDX_DIGEST_SIZE]; if (action.allowed && strmd4(sFile, fileHash)) { WebFileOperationRequest* request = new WebFileOperationRequest; memcpy(request->fileHash, fileHash, sizeof request->fileHash); switch (action.operation) { case ese::web::WebTransferFileOperation::Stop: request->operation = WEBFILEOP_STOP; break; case ese::web::WebTransferFileOperation::Pause: request->operation = WEBFILEOP_PAUSE; break; case ese::web::WebTransferFileOperation::Resume: request->operation = WEBFILEOP_RESUME; break; case ese::web::WebTransferFileOperation::Cancel: request->operation = WEBFILEOP_CANCEL; break; case ese::web::WebTransferFileOperation::GetFileLink: request->operation = WEBFILEOP_GETFLC; break; case ese::web::WebTransferFileOperation::Rename: request->operation = WEBFILEOP_RENAME; request->text = actionText; break; case ese::web::WebTransferFileOperation::PriorityLow: request->operation = WEBFILEOP_PRIOLOW; break; case ese::web::WebTransferFileOperation::PriorityNormal: request->operation = WEBFILEOP_PRIONORMAL; break; case ese::web::WebTransferFileOperation::PriorityHigh: request->operation = WEBFILEOP_PRIOHIGH; break; case ese::web::WebTransferFileOperation::PriorityAuto: request->operation = WEBFILEOP_PRIOAUTO; break; case ese::web::WebTransferFileOperation::SetCategory: request->operation = WEBFILEOP_SETCAT; request->value = action.value; break; case ese::web::WebTransferFileOperation::StreamSeek: request->operation = WEBFILEOP_STREAMSEEK; request->value = action.value; break; default: delete request; request = NULL; } if (request) SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_FILE_OPERATION, (LPARAM)request); } } HTTPTemp = _ParseURL(Data.sURL, _T("sortreverse")); const CString &sSort(_ParseURL(Data.sURL, _T("sort"))); const ese::web::WebTransferSortDecision sortDecision = ese::web::WebTransferController::PlanSort( bAdmin, std::string(CT2A(sSort)), std::string(CT2A(HTTPTemp))); if (sortDecision.allowed) { if (sortDecision.domain == ese::web::WebTransferSortDomain::Download) { pThis->m_Params.DownloadSort = static_cast<DownloadSort>(sortDecision.target_index); pThis->m_Params.bDownloadSortReverse = sortDecision.reverse; } else if (sortDecision.domain == ese::web::WebTransferSortDomain::Upload) { pThis->m_Params.UploadSort = static_cast<UploadSort>(sortDecision.target_index); pThis->m_Params.bUploadSortReverse = sortDecision.reverse; } else { pThis->m_Params.QueueSort = static_cast<QueueSort>(sortDecision.target_index); pThis->m_Params.bQueueSortReverse = sortDecision.reverse; } } auto applyBoolean = [&](bool& current, LPCTSTR field) { const CString input = _ParseURL(Data.sURL, field); bool output = current; if (ese::web::WebTransferController::TryApplyBoolean( bAdmin, current, std::string(CT2A(input)), output)) current = output; };
	applyBoolean(pThis->m_Params.bShowUploadQueue, _T("showuploadqueue")); applyBoolean(pThis->m_Params.bShowUploadQueueBanned, _T("showuploadqueuebanned")); applyBoolean(pThis->m_Params.bShowUploadQueueFriend, _T("showuploadqueuefriend"));
}

CString CWebServer::_GetTransferList(const ThreadData &Data)
{
	CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis); if (pThis == NULL) return CString(); const CString sSession(_ParseURL(Data.sURL, _T("ses"))); const long lSession = _tstol(sSession); const bool bAdmin = _IsSessionAdmin(Data, lSession); int cat; const CString catp(_ParseURL(Data.sURL, _T("cat"))); if (catp.IsEmpty()) cat = _GetLastUserCat(Data, lSession); else { cat = _tstoi(catp); _SetLastUserCat(Data, lSession, cat); } CString sCat; if (cat != 0) sCat.Format(_T("&amp;cat=%i"), cat); CString ignored; _MakeTransferList(ignored, pThis, Data, nullptr, nullptr, bAdmin); const CString sFile(_ParseURL(Data.sURL, _T("file")));
	M2AModuleHandle projectionBinding = M2A_BIND_W4_AD763A5EE0(M2AParentPort{pThis}); if (!projectionBinding) return CString();
	WebTransferProjectionInput projection; projection.url = Data.sURL; projection.session = sSession; projection.categorySuffix = sCat; projection.selectedFile = sFile; projection.category = cat; projection.admin = bAdmin; projection.downloadSort = pThis->m_Params.DownloadSort; projection.uploadSort = pThis->m_Params.UploadSort; projection.queueSort = pThis->m_Params.QueueSort; projection.downloadReverse = pThis->m_Params.bDownloadSortReverse; projection.uploadReverse = pThis->m_Params.bUploadSortReverse; projection.queueReverse = pThis->m_Params.bQueueSortReverse; projection.showQueue = pThis->m_Params.bShowUploadQueue; projection.showBanned = pThis->m_Params.bShowUploadQueueBanned; projection.showFriend = pThis->m_Params.bShowUploadQueueFriend; projection.maxWebUploadFileSizeMB = thePrefs.GetMaxWebUploadFileSizeMB();
	for (unsigned i = 0; i < projection.downloadHidden.size(); ++i) projection.downloadHidden[i] = WSdownloadColumnHidden[i] != FALSE; for (unsigned i = 0; i < projection.uploadHidden.size(); ++i) projection.uploadHidden[i] = WSuploadColumnHidden[i] != FALSE; for (unsigned i = 0; i < projection.queueHidden.size(); ++i) projection.queueHidden[i] = WSqueueColumnHidden[i] != FALSE;
	struct ProjectionContext { CWebServer* owner; const ThreadData* data; } context{pThis, &Data}; WebTransferProjectionPort port; port.context = &context;
	port.templateText = [](void* raw, WebTransferTemplate id) { static const WebTemplateId ids[] = { WebTemplateId::TransferImages, WebTemplateId::TransferList, WebTemplateId::TransferDownHeader, WebTemplateId::TransferDownFooter, WebTemplateId::TransferDownLine, WebTemplateId::TransferUpHeader, WebTemplateId::TransferUpFooter, WebTemplateId::TransferUpLine, WebTemplateId::TransferUpQueueShow, WebTemplateId::TransferUpQueueHide, WebTemplateId::TransferUpQueueLine, WebTemplateId::TransferUpQueueBannedShow, WebTemplateId::TransferUpQueueBannedHide, WebTemplateId::TransferUpQueueBannedLine, WebTemplateId::TransferUpQueueFriendShow, WebTemplateId::TransferUpQueueFriendHide, WebTemplateId::TransferUpQueueFriendLine, WebTemplateId::ProgressbarWidth, WebTemplateId::CatArrow, WebTemplateId::DownArrow, WebTemplateId::UpArrow }; ProjectionContext* c = static_cast<ProjectionContext*>(raw); return GetWebTemplate(WebTemplateParent(c->owner), ids[static_cast<unsigned>(id)]); };
	port.plain = [](void*, unsigned id) { return _GetPlainResString(id); }; port.special = [](void*, const CString& text, bool noquote) { return _SpecialChars(text, noquote); }; port.insertCategory = [](void*, CString& out, int selected, LPCTSTR label, bool jump, bool extra, const CString& session, const CString& hash, int fileCategory) { InsertWebCategoryBox(out, selected, label, jump, extra, session, hash, fileCategory, false); };
	port.snapshot = [](void* rawContext, int selectedCategory, unsigned, bool, unsigned, bool, unsigned queueSort, bool queueReverse, bool showQueue, bool showBanned, bool showFriend, WebTransferSnapshot& snapshot) {
		struct Capture { int category; unsigned queueSort; bool queueReverse, showQueue, showBanned, showFriend; const ThreadData* data; WebTransferSnapshot* output; } capture{selectedCategory, queueSort, queueReverse, showQueue, showBanned, showFriend, static_cast<ProjectionContext*>(rawContext)->data, &snapshot}; WebTransferSnapshotRequest request; request.context = &capture; request.capture = [](void* raw) { Capture& parameters = *static_cast<Capture*>(raw); const int selectedCategory = parameters.category; const unsigned queueSort = parameters.queueSort; const bool queueReverse = parameters.queueReverse, showQueue = parameters.showQueue, showBanned = parameters.showBanned, showFriend = parameters.showFriend; WebTransferSnapshot& snapshot = *parameters.output;
		CArray<CPartFile*, CPartFile*> parts; theApp.emuledlg->transferwnd->GetDownloadList()->GetDisplayedFiles(&parts);
		for (INT_PTR i = 0; i < parts.GetCount(); ++i) { CPartFile* part = parts[i]; if (!part) continue; bool include = true; if (selectedCategory < 0) { switch (selectedCategory) { case -1: include = part->GetCategory() == 0; break; case -2: include = part->IsPartFile(); break; case -3: include = !part->IsPartFile(); break; case -4: include = (part->GetStatus() == PS_READY || part->GetStatus() == PS_EMPTY) && part->GetTransferringSrcCount() == 0; break; case -5: include = (part->GetStatus() == PS_READY || part->GetStatus() == PS_EMPTY) && part->GetTransferringSrcCount() > 0; break; case -6: include = part->GetStatus() == PS_ERROR; break; case -7: include = part->GetStatus() == PS_PAUSED || part->IsStopped(); break; case -8: include = part->lastseencomplete != 0; break; case -9: include = part->IsMovie(); break; case -10: include = ED2KFT_AUDIO == GetED2KFileTypeID(part->GetFileName()); break; case -11: include = part->IsArchive(); break; case -12: include = ED2KFT_CDIMAGE == GetED2KFileTypeID(part->GetFileName()); break; case -13: include = ED2KFT_DOCUMENT == GetED2KFileTypeID(part->GetFileName()); break; case -14: include = ED2KFT_IMAGE == GetED2KFileTypeID(part->GetFileName()); break; case -15: include = ED2KFT_PROGRAM == GetED2KFileTypeID(part->GetFileName()); break; case -16: include = ED2KFT_EMULECOLLECTION == GetED2KFileTypeID(part->GetFileName()); break; } } else if (selectedCategory > 0) include = part->GetCategory() == static_cast<UINT>(selectedCategory); if (!include) continue;
			DownloadFiles item{}; item.sFileName = _SpecialChars(part->GetFileName()); item.sFileType = _GetWebImageNameForFileType(item.sFileName); item.sFileNameJS = _SpecialChars(part->GetFileName()); item.m_qwFileSize = part->GetFileSize(); item.m_qwFileTransferred = part->GetCompletedSize(); item.m_dblCompleted = part->GetPercentCompleted(); item.lFileSpeed = part->GetDatarate(); item.iComment = part->HasComment() || part->HasRating() ? (part->HasBadRating() ? 2 : 1) : 0; item.iFileState = part->getPartfileStatusRank();
			switch (part->GetStatus()) { case PS_HASHING: item.sFileState = _T("hashing"); break; case PS_WAITINGFORHASH: item.sFileState = _T("waitinghash"); break; case PS_ERROR: item.sFileState = _T("error"); break; case PS_COMPLETING: item.sFileState = _T("completing"); break; case PS_COMPLETE: item.sFileState = _T("complete"); break; case PS_PAUSED: item.sFileState = part->IsStopped() ? _T("stopped") : _T("paused"); break; default: item.sFileState = part->GetDatarate() > 0 ? _T("downloading") : _T("waiting"); }
			item.bFileAutoPrio = part->IsAutoDownPriority(); item.nFilePrio = part->GetDownPriority(); item.nCategory = part->GetCategory(); item.sCategory = thePrefs.GetCategory(item.nCategory)->strTitle; item.sCategory.Replace(_T("'"), _T("\\'")); item.sFileHash = md4str(part->GetFileHash()); item.sDownloadGraph = _GetDownloadGraph(*parameters.data, item.sFileHash); item.lSourceCount = part->GetSourceCount(); item.lNotCurrentSourceCount = part->GetNotCurrentSourcesCount(); item.lTransferringSourceCount = part->GetTransferringSrcCount(); item.bIsComplete = !part->IsPartFile(); item.bIsPreview = part->IsReadyForPreview(); item.bIsGetFLC = part->GetPreviewPrio(); item.sED2kLink = theApp.GetPublicIP() != 0 && !theApp.IsFirewalled() ? part->GetED2kLink(false, false, false, true, theApp.GetPublicIP()) : part->GetED2kLink(); item.sFileInfo = _SpecialChars(part->GetInfoSummary(true), false); snapshot.downloads.Add(item); }
		for (POSITION pos = theApp.uploadqueue->GetFirstFromUploadList(); pos != NULL;) { const CUpDownClient& client(*theApp.uploadqueue->GetNextFromUploadList(pos)); UploadUsers item{}; item.sUserHash = md4str(client.GetUserHash()); item.sActive = client.GetUploadDatarate() > 0 ? _T("downloading") : _T("waiting"); item.sClientState = client.GetUploadDatarate() > 0 ? _T("uploading") : _T("connecting"); item.sFileInfo = _SpecialChars(_GetClientSummary(client), false); item.sFileInfo.Replace(_T("\\"), _T("\\\\")); item.sFileInfo.Replace(_T("\n"), _T("<br>")); item.sFileInfo.Replace(_T("'"), _T("&#8217;")); _GetClientversionImage(client, item.sClientSoft); item.sClientExtra = client.IsBanned() ? _T("banned") : (client.IsFriend() ? _T("friend") : (client.Credits()->GetScoreRatio(client.GetIP()) > 1 ? _T("credit") : _T("none"))); CString name(client.GetUserName()); if (name.GetLength() > SHORT_LENGTH_MIN) { name.Truncate(SHORT_LENGTH_MIN - 3); name += _T("..."); } item.sUserName = _SpecialChars(name); CKnownFile* known = theApp.sharedfiles->GetFileByID(client.GetUploadFileID()); item.sFileName = known ? _SpecialChars(known->GetFileName()) : _GetPlainResString(IDS_REQ_UNKNOWNFILE); item.nTransferredDown = client.GetTransferredDown(); item.nTransferredUp = client.GetTransferredUp(); const UINT rate = client.GetUploadDatarate(); item.nDataRate = rate == UNLIMITED ? 0 : rate; item.sClientNameVersion = client.GetClientSoftVer(); snapshot.uploads.Add(item); }
		CQArray<QueueUsers, QueueUsers> queue; for (POSITION pos = theApp.uploadqueue->waitinglist.GetHeadPosition(); pos != NULL;) { const CUpDownClient& client(*theApp.uploadqueue->waitinglist.GetNext(pos)); QueueUsers item{}; const int secure = client.Credits()->GetCurrentIdentState(client.GetIP()) == IS_IDENTIFIED; if (client.IsBanned()) { item.sClientExtra = _T("banned"); ++snapshot.bannedCount; snapshot.bannedSecure += secure; } else if (client.IsFriend()) { item.sClientExtra = _T("friend"); ++snapshot.friendCount; snapshot.friendSecure += secure; } else { item.sClientExtra = _T("none"); ++snapshot.queueCount; snapshot.queueSecure += secure; } CString name(client.GetUserName()); if (name.GetLength() > SHORT_LENGTH_MIN) { name.Truncate(SHORT_LENGTH_MIN - 3); name += _T("..."); } item.sUserName = _SpecialChars(name); item.sClientNameVersion = client.GetClientSoftVer(); CKnownFile* known = theApp.sharedfiles->GetFileByID(client.GetUploadFileID()); item.sFileName = known ? _SpecialChars(known->GetFileName()) : _GetPlainResString(IDS_REQ_UNKNOWNFILE); item.sClientState = item.sClientExtra; item.sClientStateSpecial = _T("connecting"); item.nScore = client.GetScore(false); _GetClientversionImage(client, item.sClientSoft); item.sUserHash = md4str(client.GetUserHash()); switch (queueSort) { case QU_SORT_CLIENT: item.sIndex = item.sClientSoft; break; case QU_SORT_USER: item.sIndex = item.sUserName; break; case QU_SORT_VERSION: item.sIndex = item.sClientNameVersion; break; case QU_SORT_FILENAME: item.sIndex = item.sFileName; break; case QU_SORT_SCORE: item.sIndex.Format(_T("%09u"), item.nScore); } queue.Add(item); }
		INT_PTR next = 0; uint32 score = 0; for (INT_PTR i = queue.GetCount(); --i >= 0;) if (queue[i].nScore > score) { next = i; score = queue[i].nScore; } if (queue.GetCount() != 0) { queue[next].sClientState = _T("next"); queue[next].sClientStateSpecial = queue[next].sClientState; } if ((snapshot.queueCount > 0 && showQueue) || (snapshot.bannedCount > 0 && showBanned) || (snapshot.friendCount > 0 && showFriend)) queue.QuickSort(queueReverse); for (INT_PTR i = 0; i < queue.GetCount(); ++i) snapshot.queue.Add(queue[i]);
		}; SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_TRANSFER_SNAPSHOT, reinterpret_cast<LPARAM>(&request));
	};
	if (!port.Complete()) return CString(); return RunWebTransferProjection(M2AParentPort{pThis}, projection, port);
}
CString CWebServer::_GetSharedFilesList(const ThreadData &Data)
{
	CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	if (pThis == NULL)
		return CString();

	const CString &sSession(_ParseURL(Data.sURL, _T("ses")));
	bool bAdmin = _IsSessionAdmin(Data, sSession);
	const CString &strSort(_ParseURL(Data.sURL, _T("sort")));

	CString strTmp(_ParseURL(Data.sURL, _T("sortreverse")));

	const ese::web::WebSharedSortDecision sharedSort =
		ese::web::WebSharedController::PlanSort(
			bAdmin, std::string(CT2A(strSort)),
			std::string(CT2A(strTmp)));
	if (sharedSort.allowed) {
		if (sharedSort.update_sort)
			pThis->m_Params.SharedSort =
				static_cast<SharedSort>(sharedSort.target_index);
		if (sharedSort.update_reverse)
			pThis->m_Params.bSharedSortReverse = sharedSort.reverse;
	}

	const CString priorityHash = _ParseURL(Data.sURL, _T("hash"));
	const CString sPrio = _ParseURL(Data.sURL, _T("prio"));
	const ese::web::WebSharedPriorityDecision priority =
		ese::web::WebSharedController::PlanPriority(
			bAdmin, std::string(CT2A(priorityHash)),
			std::string(CT2A(sPrio)));
	uchar priorityFileId[MDX_DIGEST_SIZE];
	if (priority.allowed &&
		DecodeBase16(priorityHash, priorityHash.GetLength(), priorityFileId,
			_countof(priorityFileId))) {
		CKnownFile* file = theApp.sharedfiles->GetFileByID(priorityFileId);
		if (file != NULL) {
			if (priority.priority == ese::web::WebSharedPriority::Auto) {
				file->SetAutoUpPriority(true);
				file->UpdateAutoUpPriority();
			} else {
				const uint8 uploadPriority =
					priority.priority == ese::web::WebSharedPriority::VeryLow
					? PR_VERYLOW
					: (priority.priority == ese::web::WebSharedPriority::Low
						? PR_LOW
						: (priority.priority ==
							ese::web::WebSharedPriority::Normal
							? PR_NORMAL
							: (priority.priority ==
								ese::web::WebSharedPriority::High
								? PR_HIGH : PR_VERYHIGH)));
				file->SetAutoUpPriority(false);
				file->SetUpPriority(uploadPriority);
			}
			SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION,
				WEBGUIIA_UPD_SFUPDATE, (LPARAM)file);
		}
	}

	if (_ParseURL(Data.sURL, _T("c")) == _T("menu")) {
		const CString index = _ParseURL(Data.sURL, _T("m"));
		const CString hidden = _ParseURL(Data.sURL, _T("v"));
		const ese::web::WebSharedColumnChange change =
			ese::web::WebSharedController::PlanColumnChange(
				bAdmin, std::string(CT2A(index)),
				std::string(CT2A(hidden)));
		if (change.allowed) {
			WSsharedColumnHidden[change.index] = change.hidden;
			_SaveWIConfigArray(WSsharedColumnHidden,
				_countof(WSsharedColumnHidden), _T("sharedColumnHidden"));
		}
	}
	const CString reload = _ParseURL(Data.sURL, _T("reload"));
	if (ese::web::WebSharedController::PlanReload(
		bAdmin, std::string(CT2A(reload))))
		SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_SHARED_FILES_RELOAD, 0);

	strTmp = (pThis->m_Params.bSharedSortReverse) ? _T("false") : _T("true");

	CString Out(GetWebTemplate(WebTemplateParent(pThis), WebTemplateId::SharedList));
	//State sorting link
	if (pThis->m_Params.SharedSort == SHARED_SORT_STATE)
		Out.Replace(_T("[SortState]"), _T("sort=state&amp;sortreverse=") + strTmp);
	else
		Out.Replace(_T("[SortState]"), _T("sort=state"));
	//Type sorting link
	if (pThis->m_Params.SharedSort == SHARED_SORT_TYPE)
		Out.Replace(_T("[SortType]"), _T("sort=type&amp;sortreverse=") + strTmp);
	else
		Out.Replace(_T("[SortType]"), _T("sort=type"));
	//Name sorting link
	if (pThis->m_Params.SharedSort == SHARED_SORT_NAME)
		Out.Replace(_T("[SortName]"), _T("sort=name&amp;sortreverse=") + strTmp);
	else
		Out.Replace(_T("[SortName]"), _T("sort=name"));
	//Size sorting Link
	if (pThis->m_Params.SharedSort == SHARED_SORT_SIZE)
		Out.Replace(_T("[SortSize]"), _T("sort=size&amp;sortreverse=") + strTmp);
	else
		Out.Replace(_T("[SortSize]"), _T("sort=size"));
	//Complete Sources sorting Link
	if (pThis->m_Params.SharedSort == SHARED_SORT_COMPLETES)
		Out.Replace(_T("[SortCompletes]"), _T("sort=completes&amp;sortreverse=") + strTmp);
	else
		Out.Replace(_T("[SortCompletes]"), _T("sort=completes"));
	//Priority sorting Link
	if (pThis->m_Params.SharedSort == SHARED_SORT_PRIORITY)
		Out.Replace(_T("[SortPriority]"), _T("sort=priority&amp;sortreverse=") + strTmp);
	else
		Out.Replace(_T("[SortPriority]"), _T("sort=priority"));
	//Transferred sorting link
	if (pThis->m_Params.SharedSort == SHARED_SORT_TRANSFERRED) {
		if (pThis->m_Params.bSharedSortReverse)
			Out.Replace(_T("[SortTransferred]"), _T("sort=alltimetransferred&amp;sortreverse=") + strTmp);
		else
			Out.Replace(_T("[SortTransferred]"), _T("sort=transferred&amp;sortreverse=") + strTmp);
	} else if (pThis->m_Params.SharedSort == SHARED_SORT_ALL_TIME_TRANSFERRED) {
		if (pThis->m_Params.bSharedSortReverse)
			Out.Replace(_T("[SortTransferred]"), _T("sort=transferred&amp;sortreverse=") + strTmp);
		else
			Out.Replace(_T("[SortTransferred]"), _T("sort=alltimetransferred&amp;sortreverse=") + strTmp);
	} else
		Out.Replace(_T("[SortTransferred]"), _T("&amp;sort=transferred&amp;sortreverse=false"));
	//Request sorting link
	if (pThis->m_Params.SharedSort == SHARED_SORT_REQUESTS) {
		if (pThis->m_Params.bSharedSortReverse)
			Out.Replace(_T("[SortRequests]"), _T("sort=alltimerequests&amp;sortreverse=") + strTmp);
		else
			Out.Replace(_T("[SortRequests]"), _T("sort=requests&amp;sortreverse=") + strTmp);
	} else if (pThis->m_Params.SharedSort == SHARED_SORT_ALL_TIME_REQUESTS) {
		if (pThis->m_Params.bSharedSortReverse)
			Out.Replace(_T("[SortRequests]"), _T("sort=requests&amp;sortreverse=") + strTmp);
		else
			Out.Replace(_T("[SortRequests]"), _T("sort=alltimerequests&amp;sortreverse=") + strTmp);
	} else
		Out.Replace(_T("[SortRequests]"), _T("&amp;sort=requests&amp;sortreverse=false"));
	//Accepts sorting link
	if (pThis->m_Params.SharedSort == SHARED_SORT_ACCEPTS) {
		if (pThis->m_Params.bSharedSortReverse)
			Out.Replace(_T("[SortAccepts]"), _T("sort=alltimeaccepts&amp;sortreverse=") + strTmp);
		else
			Out.Replace(_T("[SortAccepts]"), _T("sort=accepts&amp;sortreverse=") + strTmp);
	} else if (pThis->m_Params.SharedSort == SHARED_SORT_ALL_TIME_ACCEPTS) {
		if (pThis->m_Params.bSharedSortReverse)
			Out.Replace(_T("[SortAccepts]"), _T("sort=accepts&amp;sortreverse=") + strTmp);
		else
			Out.Replace(_T("[SortAccepts]"), _T("sort=alltimeaccepts&amp;sortreverse=") + strTmp);
	} else
		Out.Replace(_T("[SortAccepts]"), _T("&amp;sort=accepts&amp;sortreverse=false"));

	if (_ParseURL(Data.sURL, _T("reload")) == _T("true")) {
		//Pick-up last line of the log
		CString strResultLog(_SpecialChars(theApp.emuledlg->GetLastLogEntry().TrimRight(_T('\n'))));
		int iStringIndex = strResultLog.ReverseFind(_T('\n'));
		if (iStringIndex > 0)
			strResultLog.Delete(0, iStringIndex);
		Out.Replace(_T("[Message]"), strResultLog);
	} else
		Out.Replace(_T("[Message]"), _T(""));

	CString pcSortIcon((pThis->m_Params.bSharedSortReverse) ? GetWebTemplate(WebTemplateParent(pThis), WebTemplateId::UpArrow) : GetWebTemplate(WebTemplateParent(pThis), WebTemplateId::DownArrow));

	_GetPlainResString(strTmp, IDS_DL_FILENAME);
	if (WSsharedColumnHidden[0]) {
		Out.Replace(_T("[FilenameI]"), _T(""));
		Out.Replace(_T("[Filename]"), _T(""));
	} else {
		Out.Replace(_T("[FilenameI]"), (pThis->m_Params.SharedSort == SHARED_SORT_NAME) ? pcSortIcon : _T(""));
		Out.Replace(_T("[Filename]"), strTmp);
	}
	Out.Replace(_T("[FilenameM]"), strTmp);

	_GetPlainResString(strTmp, IDS_SF_TRANSFERRED);
	if (WSsharedColumnHidden[1]) {
		Out.Replace(_T("[FileTransferredI]"), _T(""));
		Out.Replace(_T("[FileTransferred]"), _T(""));
	} else {
		CString pcIconTmp = (pThis->m_Params.SharedSort == SHARED_SORT_TRANSFERRED) ? pcSortIcon : _T("");
		if (pThis->m_Params.SharedSort == SHARED_SORT_ALL_TIME_TRANSFERRED)
			pcIconTmp = (pThis->m_Params.bSharedSortReverse) ? GetWebTemplate(WebTemplateParent(pThis), WebTemplateId::UpDoubleArrow) : GetWebTemplate(WebTemplateParent(pThis), WebTemplateId::DownDoubleArrow);
		Out.Replace(_T("[FileTransferredI]"), pcIconTmp);
		Out.Replace(_T("[FileTransferred]"), strTmp);
	}
	Out.Replace(_T("[FileTransferredM]"), strTmp);

	_GetPlainResString(strTmp, IDS_SF_REQUESTS);
	if (WSsharedColumnHidden[2]) {
		Out.Replace(_T("[FileRequestsI]"), _T(""));
		Out.Replace(_T("[FileRequests]"), _T(""));
	} else {
		CString pcIconTmp = (pThis->m_Params.SharedSort == SHARED_SORT_REQUESTS) ? pcSortIcon : _T("");
		if (pThis->m_Params.SharedSort == SHARED_SORT_ALL_TIME_REQUESTS)
			pcIconTmp = (pThis->m_Params.bSharedSortReverse) ? GetWebTemplate(WebTemplateParent(pThis), WebTemplateId::UpDoubleArrow) : GetWebTemplate(WebTemplateParent(pThis), WebTemplateId::DownDoubleArrow);
		Out.Replace(_T("[FileRequestsI]"), pcIconTmp);
		Out.Replace(_T("[FileRequests]"), strTmp);
	}
	Out.Replace(_T("[FileRequestsM]"), strTmp);

	_GetPlainResString(strTmp, IDS_SF_ACCEPTS);
	if (WSsharedColumnHidden[3]) {
		Out.Replace(_T("[FileAcceptsI]"), _T(""));
		Out.Replace(_T("[FileAccepts]"), _T(""));
	} else {
		CString pcIconTmp = (pThis->m_Params.SharedSort == SHARED_SORT_ACCEPTS) ? pcSortIcon : _T("");
		if (pThis->m_Params.SharedSort == SHARED_SORT_ALL_TIME_ACCEPTS)
			pcIconTmp = (pThis->m_Params.bSharedSortReverse) ? GetWebTemplate(WebTemplateParent(pThis), WebTemplateId::UpDoubleArrow) : GetWebTemplate(WebTemplateParent(pThis), WebTemplateId::DownDoubleArrow);
		Out.Replace(_T("[FileAcceptsI]"), pcIconTmp);
		Out.Replace(_T("[FileAccepts]"), strTmp);
	}
	Out.Replace(_T("[FileAcceptsM]"), strTmp);

	_GetPlainResString(strTmp, IDS_DL_SIZE);
	if (WSsharedColumnHidden[4]) {
		Out.Replace(_T("[SizeI]"), _T(""));
		Out.Replace(_T("[Size]"), _T(""));
	} else {
		Out.Replace(_T("[SizeI]"), (pThis->m_Params.SharedSort == SHARED_SORT_SIZE) ? pcSortIcon : _T(""));
		Out.Replace(_T("[Size]"), strTmp);
	}
	Out.Replace(_T("[SizeM]"), strTmp);

	_GetPlainResString(strTmp, IDS_COMPLSOURCES);
	if (WSsharedColumnHidden[5]) {
		Out.Replace(_T("[CompletesI]"), _T(""));
		Out.Replace(_T("[Completes]"), _T(""));
	} else {
		Out.Replace(_T("[CompletesI]"), (pThis->m_Params.SharedSort == SHARED_SORT_COMPLETES) ? pcSortIcon : _T(""));
		Out.Replace(_T("[Completes]"), strTmp);
	}
	Out.Replace(_T("[CompletesM]"), strTmp);

	_GetPlainResString(strTmp, IDS_PRIORITY);
	if (WSsharedColumnHidden[6]) {
		Out.Replace(_T("[PriorityI]"), _T(""));
		Out.Replace(_T("[Priority]"), _T(""));
	} else {
		Out.Replace(_T("[PriorityI]"), (pThis->m_Params.SharedSort == SHARED_SORT_PRIORITY) ? pcSortIcon : _T(""));
		Out.Replace(_T("[Priority]"), strTmp);
	}
	Out.Replace(_T("[PriorityM]"), strTmp);

	Out.Replace(_T("[Actions]"), _GetPlainResString(IDS_WEB_ACTIONS));
	Out.Replace(_T("[Reload]"), _GetPlainResString(IDS_SF_RELOAD));
	Out.Replace(_T("[Session]"), sSession);
	Out.Replace(_T("[SharedList]"), _GetPlainResString(IDS_SHAREDFILES));

	CString OutE(GetWebTemplate(WebTemplateParent(pThis), WebTemplateId::SharedLine));

	CArray<SharedFiles> SharedArray;

	// Populating array
	for (POSITION pos = BEFORE_START_POSITION; pos != NULL;) {
		CKnownFile *pFile = theApp.sharedfiles->GetFileNext(pos);
		if (pFile != NULL) {
			bool bPartFile = pFile->IsPartFile();

			SharedFiles dFile;
			//dFile.sFileName = _SpecialChars(cur_file->GetFileName());
			dFile.bIsPartFile = bPartFile;
			dFile.sFileName = pFile->GetFileName();
			dFile.sFileState = bPartFile ? _T("filedown") : _T("file");
			dFile.sFileType = _GetWebImageNameForFileType(dFile.sFileName);
			dFile.m_qwFileSize = pFile->GetFileSize();

			if (theApp.GetPublicIP() && !theApp.IsFirewalled())
				dFile.sED2kLink = pFile->GetED2kLink(false, false, false, true, theApp.GetPublicIP());
			else
				dFile.sED2kLink = pFile->GetED2kLink();

			dFile.nFileTransferred = pFile->statistic.GetTransferred();
			dFile.nFileAllTimeTransferred = pFile->statistic.GetAllTimeTransferred();
			dFile.nFileRequests = pFile->statistic.GetRequests();
			dFile.nFileAllTimeRequests = pFile->statistic.GetAllTimeRequests();
			dFile.nFileAccepts = pFile->statistic.GetAccepts();
			dFile.nFileAllTimeAccepts = pFile->statistic.GetAllTimeAccepts();
			dFile.sFileHash = md4str(pFile->GetFileHash());

			const ese::web::WebSharedRowProjection completion =
				ese::web::WebSharedController::ProjectRow(
					false, ese::web::WebSharedPriority::None, bPartFile,
					dFile.m_qwFileSize, 0,
					pFile->m_nCompleteSourcesCountLo,
					pFile->m_nCompleteSourcesCountHi);
			dFile.sFileCompletes =
				CString(CA2T(completion.complete_sources.c_str()));

			UINT uid;
			if (pFile->IsAutoUpPriority()) {
				switch (pFile->GetUpPriority()) {
				case PR_LOW:
					uid = IDS_PRIOAUTOLOW;
					break;
				case PR_HIGH:
					uid = IDS_PRIOAUTOHIGH;
					break;
				case PR_VERYHIGH:
					uid = IDS_PRIOAUTORELEASE;
					break;
				//case PR_NORMAL:
				default:
					uid = IDS_PRIOAUTONORMAL;
				}
			} else {
				switch (pFile->GetUpPriority()) {
				case PR_VERYLOW:
					uid = IDS_PRIOVERYLOW;
					break;
				case PR_LOW:
					uid = IDS_PRIOLOW;
					break;
				case PR_HIGH:
					uid = IDS_PRIOHIGH;
					break;
				case PR_VERYHIGH:
					uid = IDS_PRIORELEASE;
					break;
				case PR_NORMAL:
				default:
					uid = IDS_PRIONORMAL;
				}
			}
			dFile.sFilePriority = GetResString(uid);

			dFile.nFilePriority = pFile->GetUpPriority();
			dFile.bFileAutoPriority = pFile->IsAutoUpPriority();
			SharedArray.Add(dFile);
		}
	} //for

	SortParams prm{ (int)pThis->m_Params.SharedSort, pThis->m_Params.bSharedSortReverse };
	qsort_s(SharedArray.GetData(), SharedArray.GetCount(), sizeof(SharedFiles), &_SharedCmp, &prm);

	// Displaying
	CString sSharedList;
	for (INT_PTR i = 0; i < SharedArray.GetCount(); ++i) {
		CString HTTPProcessData(OutE);

		bool b = (SharedArray[i].sFileHash == _ParseURL(Data.sURL, _T("hash")));
		HTTPProcessData.Replace(_T("[LastChangedDataset]"), b ? _T("checked") : _T("checked_no"));

		ese::web::WebSharedPriority rowPriority =
			ese::web::WebSharedPriority::None;
		switch (SharedArray[i].nFilePriority) {
		case PR_VERYLOW: rowPriority = ese::web::WebSharedPriority::VeryLow; break;
		case PR_LOW: rowPriority = ese::web::WebSharedPriority::Low; break;
		case PR_NORMAL: rowPriority = ese::web::WebSharedPriority::Normal; break;
		case PR_HIGH: rowPriority = ese::web::WebSharedPriority::High; break;
		case PR_VERYHIGH: rowPriority = ese::web::WebSharedPriority::Release; break;
		default: break;
		}
		const ese::web::WebSharedRowProjection priorityProjection =
			ese::web::WebSharedController::ProjectRow(
				SharedArray[i].bFileAutoPriority, rowPriority,
				true, SharedArray[i].m_qwFileSize,
				thePrefs.GetMaxWebUploadFileSizeMB(), 0, 0);
		const CString sharedpriority =
			CString(CA2T(priorityProjection.priority_token));

		CString ed2k(SharedArray[i].sED2kLink);		//ed2klink
		ed2k.Replace(_T("'"), _T("&#8217;"));
		const CString &hash(SharedArray[i].sFileHash);	//hash
		CString fname(SharedArray[i].sFileName);	//filename
		fname.Replace(_T("'"), _T("&#8217;"));

		bool downloadable = false;
		uchar fileid[MDX_DIGEST_SIZE];
		if (hash.GetLength() == 32 && DecodeBase16(hash, hash.GetLength(), fileid, _countof(fileid))) {
			HTTPProcessData.Replace(_T("[hash]"), hash);
			const CKnownFile *cur_file = theApp.sharedfiles->GetFileByID(fileid);
			if (cur_file != NULL) {
				HTTPProcessData.Replace(_T("[FileIsPriority]")
					, (cur_file->GetUpPriority() == PR_VERYHIGH) ? _T("release") : _T("none"));
				downloadable =
					ese::web::WebSharedController::ProjectRow(
						SharedArray[i].bFileAutoPriority, rowPriority,
						cur_file->IsPartFile(), SharedArray[i].m_qwFileSize,
						thePrefs.GetMaxWebUploadFileSizeMB(), 0, 0)
						.downloadable;
			}
		}

		HTTPProcessData.Replace(_T("[admin]"), bAdmin ? _T("admin") : _T(""));
		HTTPProcessData.Replace(_T("[ed2k]"), _SpecialChars(ed2k));
		HTTPProcessData.Replace(_T("[fname]"), _SpecialChars(fname));
		HTTPProcessData.Replace(_T("[session]"), sSession);
		HTTPProcessData.Replace(_T("[shared-priority]"), sharedpriority); //DonGato: priority change

		HTTPProcessData.Replace(_T("[FileName]"), _SpecialChars(SharedArray[i].sFileName));
		HTTPProcessData.Replace(_T("[FileType]"), SharedArray[i].sFileType);
		HTTPProcessData.Replace(_T("[FileState]"), SharedArray[i].sFileState);

		HTTPProcessData.Replace(_T("[Downloadable]"), downloadable ? _T("yes") : _T("no"));

		HTTPProcessData.Replace(_T("[IFDOWNLOADABLE]"), downloadable ? _T("") : _T("<!--"));
		HTTPProcessData.Replace(_T("[/IFDOWNLOADABLE]"), downloadable ? _T("") : _T("-->"));

		TCHAR HTTPTempC[100];
		//0
		if (WSsharedColumnHidden[0])
			HTTPProcessData.Replace(_T("[ShortFileName]"), _T(""));
		else if (SharedArray[i].sFileName.GetLength() > (SHORT_LENGTH))
			HTTPProcessData.Replace(_T("[ShortFileName]"), _SpecialChars(SharedArray[i].sFileName.Left(SHORT_LENGTH - 3)) + _T("..."));
		else
			HTTPProcessData.Replace(_T("[ShortFileName]"), _SpecialChars(SharedArray[i].sFileName));
		//1
		HTTPProcessData.Replace(_T("[FileTransferred]"), WSsharedColumnHidden[1] ? _T("") : (LPCTSTR)CastItoXBytes(SharedArray[i].nFileTransferred));
		if (WSsharedColumnHidden[1])
			*HTTPTempC = _T('\0');
		else
			_stprintf(HTTPTempC, _T(" (%s)"), (LPCTSTR)CastItoXBytes(SharedArray[i].nFileAllTimeTransferred));
		HTTPProcessData.Replace(_T("[FileAllTimeTransferred]"), HTTPTempC);
		//2
		if (WSsharedColumnHidden[2])
			*HTTPTempC = _T('\0');
		else
			_stprintf(HTTPTempC, _T("%i"), SharedArray[i].nFileRequests);
		HTTPProcessData.Replace(_T("[FileRequests]"), HTTPTempC);
		if (!WSsharedColumnHidden[2])
			_stprintf(HTTPTempC, _T(" (%i)"), SharedArray[i].nFileAllTimeRequests);
		HTTPProcessData.Replace(_T("[FileAllTimeRequests]"), HTTPTempC);
		//3
		if (WSsharedColumnHidden[3])
			*HTTPTempC = _T('\0');
		else
			_stprintf(HTTPTempC, _T("%i"), SharedArray[i].nFileAccepts);
		HTTPProcessData.Replace(_T("[FileAccepts]"), HTTPTempC);
		if (!WSsharedColumnHidden[3])
			_stprintf(HTTPTempC, _T(" (%i)"), SharedArray[i].nFileAllTimeAccepts);
		HTTPProcessData.Replace(_T("[FileAllTimeAccepts]"), HTTPTempC);
		//4..6
		if (WSsharedColumnHidden[4])
			HTTPProcessData.Replace(_T("[FileSize]"), _T(""));
		else
			HTTPProcessData.Replace(_T("[FileSize]"), CastItoXBytes(SharedArray[i].m_qwFileSize));
		if (WSsharedColumnHidden[5])
			HTTPProcessData.Replace(_T("[Completes]"), _T(""));
		else
			HTTPProcessData.Replace(_T("[Completes]"), SharedArray[i].sFileCompletes);
		if (WSsharedColumnHidden[6])
			HTTPProcessData.Replace(_T("[Priority]"), _T(""));
		else
			HTTPProcessData.Replace(_T("[Priority]"), SharedArray[i].sFilePriority);
		HTTPProcessData.Replace(_T("[FileHash]"), SharedArray[i].sFileHash);

		sSharedList += HTTPProcessData;
	}

	Out.Replace(_T("[SharedFilesList]"), sSharedList);
	Out.Replace(_T("[Session]"), sSession);
	return Out;
}

CString CWebServer::_GetGraphs(const ThreadData &Data)
{
	const CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	if (pThis == NULL)
		return CString();

	CString Out(GetWebTemplate(WebTemplateParent(pThis), WebTemplateId::Graphs));

	CString strGraphDownload, strGraphUpload, strGraphCons;
	LPCTSTR pszFmt = _T("%u");
	INT_PTR cnt = min(WEB_GRAPH_WIDTH, pThis->m_Params.PointsForWeb.GetCount());
	for (INT_PTR i = 0; i < cnt; ++i) {
		const UpDown &pt = pThis->m_Params.PointsForWeb[i];
		// download
		strGraphDownload.AppendFormat(pszFmt, (uint32)(pt.download * 1024));
		// upload
		strGraphUpload.AppendFormat(pszFmt, (uint32)(pt.upload * 1024));
		// connections
		strGraphCons.AppendFormat(pszFmt, (uint32)(pt.connections));
		pszFmt = _T(",%u");
	}

	Out.Replace(_T("[GraphDownload]"), strGraphDownload);
	Out.Replace(_T("[GraphUpload]"), strGraphUpload);
	Out.Replace(_T("[GraphConnections]"), strGraphCons);

	Out.Replace(_T("[TxtDownload]"), _GetPlainResString(IDS_TW_DOWNLOADS));
	Out.Replace(_T("[TxtUpload]"), _GetPlainResString(IDS_TW_UPLOADS));
	Out.Replace(_T("[TxtTime]"), _GetPlainResString(IDS_TIME));
	Out.Replace(_T("[KByteSec]"), _GetPlainResString(IDS_KBYTESPERSEC));
	Out.Replace(_T("[TxtConnections]"), _GetPlainResString(IDS_SP_ACTCON));

	Out.Replace(_T("[ScaleTime]"), (LPCTSTR)CastSecondsToHM(((time_t)thePrefs.GetTrafficOMeterInterval()) * WEB_GRAPH_WIDTH));

	CString s1;
	s1.Format(_T("%u"), thePrefs.GetMaxGraphDownloadRate() + 4);
	Out.Replace(_T("[MaxDownload]"), s1);
	s1.Format(_T("%u"), thePrefs.GetMaxGraphUploadRate(true) + 4);
	Out.Replace(_T("[MaxUpload]"), s1);
	s1.Format(_T("%u"), thePrefs.GetMaxConnections() + 20);
	Out.Replace(_T("[MaxConnections]"), s1);

	return Out;
}
CString CWebServer::_GetLog(const ThreadData &Data)
{
	const CWebServer* owner = reinterpret_cast<CWebServer*>(Data.pThis); if (owner == NULL) return CString(); const CString session(_ParseURL(Data.sURL, _T("ses"))); if (_ParseURL(Data.sURL, _T("clear")) == _T("yes") && _IsSessionAdmin(Data, session)) theApp.emuledlg->ResetLog(); return RenderWebLogView(WebTemplateLogView::Log, GetWebTemplate(WebTemplateParent(owner), WebTemplateId::Log), session, theApp.emuledlg->GetAllLogEntries());
}
CString CWebServer::_GetServerInfo(const ThreadData &Data)
{
	const CWebServer* owner = reinterpret_cast<CWebServer*>(Data.pThis); if (owner == NULL) return CString(); const CString session(_ParseURL(Data.sURL, _T("ses"))); if (_ParseURL(Data.sURL, _T("clear")) == _T("yes") && _IsSessionAdmin(Data, session)) theApp.emuledlg->ResetServerInfo(); return RenderWebLogView(WebTemplateLogView::ServerInfo, GetWebTemplate(WebTemplateParent(owner), WebTemplateId::ServerInfo), session, theApp.emuledlg->GetServerInfoText());
}
CString CWebServer::_GetDebugLog(const ThreadData &Data)
{
	const CWebServer* owner = reinterpret_cast<CWebServer*>(Data.pThis); if (owner == NULL) return CString(); const CString session(_ParseURL(Data.sURL, _T("ses"))); if (_ParseURL(Data.sURL, _T("clear")) == _T("yes") && _IsSessionAdmin(Data, session)) theApp.emuledlg->ResetDebugLog(); return RenderWebLogView(WebTemplateLogView::DebugLog, GetWebTemplate(WebTemplateParent(owner), WebTemplateId::DebugLog), session, theApp.emuledlg->GetAllDebugLogEntries());
}
CString CWebServer::_GetMyInfo(const ThreadData &Data)
{
	const CWebServer* owner = reinterpret_cast<CWebServer*>(Data.pThis); return owner == NULL ? CString() : RenderWebMyInfo(GetWebTemplate(WebTemplateParent(owner), WebTemplateId::MyInfoLog), theApp.emuledlg->serverwnd->GetMyInfoString());
}
CString CWebServer::_GetKadDlg(const ThreadData &Data)
{
	const CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	if (pThis == NULL)
		return CString();

	/*if (!thePrefs.GetNetworkKademlia()) {
		CString buffer;
		buffer.Format(_T("<br><center>[KADDEACTIVATED]</center>")  );
		return buffer;
	}*/

	const CString &sSession(_ParseURL(Data.sURL, _T("ses")));
	CString Out(GetWebTemplate(WebTemplateParent(pThis), WebTemplateId::Kad));

	if (_IsSessionAdmin(Data, sSession)) {
		if (!_ParseURL(Data.sURL, _T("bootstrap")).IsEmpty()) {
			CString dest(_ParseURL(Data.sURL, _T("ip")));
			dest.AppendFormat(_T(":%s"), (LPCTSTR)_ParseURL(Data.sURL, _T("port")));
			SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_KAD_BOOTSTRAP, (LPARAM)(LPCTSTR)dest);
		}

		const CString &sAction(_ParseURL(Data.sURL, _T("c")));
		if (sAction == _T("connect"))
			SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_KAD_START, 0);
		else if (sAction == _T("disconnect"))
			SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_KAD_STOP, 0);
		else if (sAction == _T("rcfirewall"))
			SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_KAD_RCFW, 0);
	}
	// check the condition if bootstrap is possible
	Out.Replace(_T("[BOOTSTRAPLINE]"),
		(!thePrefs.IsKad2Enabled() || Kademlia::CKademlia::IsKad2Connected())
			? _T("") : (LPCTSTR)GetWebTemplate(WebTemplateParent(pThis), WebTemplateId::BootstrapLine));

	// Infos
	CString buffer;
	CString kad2State = GetResString(Kademlia::CKademlia::IsKad2Connected()
		? (Kademlia::CKademlia::IsFirewalled() ? IDS_FIREWALLED : IDS_CONNECTED)
		: (Kademlia::CKademlia::IsKad2Running() ? IDS_CONNECTING : IDS_DISCONNECTED));
	CString kad6State = GetResString(Kademlia::CKademlia::IsKad6Connected()
		? IDS_CONNECTED
		: (Kademlia::CKademlia::IsKad6Running() ? IDS_CONNECTING : IDS_DISCONNECTED));
	CString kadState;
	kadState.Format(_T("Kad2: %s | Kad6: %s"), (LPCTSTR)kad2State,
		(LPCTSTR)kad6State);
	Out.Replace(_T("[KADSTATUS]"), kadState);
	if (Kademlia::CKademlia::IsRunning()) {
		if (Kademlia::CKademlia::IsKad2Connected()
			&& Kademlia::CKademlia::IsFirewalled())
			buffer.Format(_T("<a href=\"?ses=%s&amp;w=kad&amp;c=rcfirewall\">%s</a><br>"),
				(LPCTSTR)sSession, (LPCTSTR)GetResString(IDS_KAD_RECHECKFW));
		else
			buffer.Empty();
		buffer.AppendFormat(_T("<a href=\"?ses=%s&amp;w=kad&amp;c=disconnect\">%s</a>"),
			(LPCTSTR)sSession, (LPCTSTR)GetResString(IDS_IRC_DISCONNECT));
	} else {
		buffer.Format(_T("<a href=\"?ses=%s&amp;w=kad&amp;c=connect\">%s</a>"),
			(LPCTSTR)sSession, (LPCTSTR)GetResString(IDS_IRC_CONNECT));
	}

		Out.Replace(_T("[KADACTION]"), buffer);

		// kadstats
		// labels
		buffer.Format(_T("Kad2 %s<br>Kad6 %s<br>%s"),
			(LPCTSTR)GetResString(IDS_KADCONTACTLAB),
			(LPCTSTR)GetResString(IDS_KADCONTACTLAB),
			(LPCTSTR)GetResString(IDS_KADSEARCHLAB));
		Out.Replace(_T("[KADSTATSLABELS]"), buffer);

		// numbers
		buffer.Format(_T("%u<br>%u<br>%i"),
			theApp.emuledlg->kademliawnd->GetContactCount(),
			Kademlia::CKademlia::GetKad6VerifiedContacts(),
			theApp.emuledlg->kademliawnd->searchList->GetItemCount());
		Out.Replace(_T("[KADSTATSDATA]"), buffer);

		Out.Replace(_T("[BS_IP]"), GetResString(IDS_IP));
		Out.Replace(_T("[BS_PORT]"), GetResString(IDS_PORT));
		Out.Replace(_T("[BOOTSTRAP]"), GetResString(IDS_BOOTSTRAP));
		Out.Replace(_T("[KADSTAT]"), GetResString(IDS_STATSSETUPINFO));
		Out.Replace(_T("[STATUS]"), GetResString(IDS_STATUS));
		Out.Replace(_T("[KAD]"), GetResString(IDS_KADEMLIA));
		Out.Replace(_T("[Session]"), sSession);

		return Out;
}

CString CWebServer::_GetStats(const ThreadData &Data)
{
	const CWebServer* owner = reinterpret_cast<CWebServer*>(Data.pThis); if (owner == NULL) return CString(); SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_SHOWSTATISTICS, 1); return RenderWebStats(GetWebTemplate(WebTemplateParent(owner), WebTemplateId::Stats), theApp.emuledlg->statisticswnd->m_stattree.GetHTMLForExport());
}
CString CWebServer::_GetPreferences(const ThreadData &Data)
{
	const CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	if (pThis == NULL)
		return CString();

	const CString &sSession(_ParseURL(Data.sURL, _T("ses")));

	CString Out(GetWebTemplate(WebTemplateParent(pThis), WebTemplateId::Preferences));
	Out.Replace(_T("[Session]"), sSession);

	if ((_ParseURL(Data.sURL, _T("saveprefs")) == _T("true")) && _IsSessionAdmin(Data, sSession)) {
		CString strTmp(_ParseURL(Data.sURL, _T("gzip")));
		if (strTmp == _T("true") || strTmp == _T("on"))
			thePrefs.SetWebUseGzip(true);
		else if (strTmp == _T("false") || strTmp.IsEmpty())
			thePrefs.SetWebUseGzip(false);

		if (!_ParseURL(Data.sURL, _T("refresh")).IsEmpty())
			thePrefs.SetWebPageRefresh(_tstoi(_ParseURL(Data.sURL, _T("refresh"))));

		strTmp = _ParseURL(Data.sURL, _T("maxcapdown"));
		if (!strTmp.IsEmpty())
			thePrefs.SetMaxGraphDownloadRate(_tstoi(strTmp));
		strTmp = _ParseURL(Data.sURL, _T("maxcapup"));
		if (!strTmp.IsEmpty())
			thePrefs.SetMaxGraphUploadRate(_tstoi(strTmp));

		strTmp = _ParseURL(Data.sURL, _T("maxdown"));
		if (!strTmp.IsEmpty()) {
			uint32 dwSpeed = _tstoi(strTmp);
			thePrefs.SetMaxDownload(dwSpeed > 0 ? dwSpeed : UNLIMITED);
		}
		strTmp = _ParseURL(Data.sURL, _T("maxup"));
		if (!strTmp.IsEmpty()) {
			uint32 dwSpeed = _tstoi(strTmp);
			thePrefs.SetMaxUpload(dwSpeed > 0 ? dwSpeed : UNLIMITED);
		}

		if (!_ParseURL(Data.sURL, _T("maxsources")).IsEmpty())
			thePrefs.SetMaxSourcesPerFile(_tstoi(_ParseURL(Data.sURL, _T("maxsources"))));
		if (!_ParseURL(Data.sURL, _T("maxconnections")).IsEmpty())
			thePrefs.SetMaxConnections(_tstoi(_ParseURL(Data.sURL, _T("maxconnections"))));
		if (!_ParseURL(Data.sURL, _T("maxconnectionsperfive")).IsEmpty())
			thePrefs.SetMaxConsPerFive(_tstoi(_ParseURL(Data.sURL, _T("maxconnectionsperfive"))));
	}

	// Fill form
	Out.Replace(_T("[UseGzipVal]"), thePrefs.GetWebUseGzip() ? _T("checked") : _T(""));

	CString sRefresh;
	sRefresh.Format(_T("%d"), thePrefs.GetWebPageRefresh());
	Out.Replace(_T("[RefreshVal]"), sRefresh);

	sRefresh.Format(_T("%u"), thePrefs.GetMaxSourcePerFileDefault());
	Out.Replace(_T("[MaxSourcesVal]"), sRefresh);

	sRefresh.Format(_T("%u"), thePrefs.GetMaxConnections());
	Out.Replace(_T("[MaxConnectionsVal]"), sRefresh);

	sRefresh.Format(_T("%u"), thePrefs.GetMaxConperFive());
	Out.Replace(_T("[MaxConnectionsPer5Val]"), sRefresh);

	Out.Replace(_T("[KBS]"), _GetPlainResString(IDS_KBYTESPERSEC) + _T(':'));
	Out.Replace(_T("[LimitForm]"), _GetPlainResString(IDS_WEB_CONLIMITS) + _T(':'));
	Out.Replace(_T("[MaxSources]"), _GetPlainResString(IDS_PW_MAXSOURCES) + _T(':'));
	Out.Replace(_T("[MaxConnections]"), _GetPlainResString(IDS_PW_MAXC) + _T(':'));
	Out.Replace(_T("[MaxConnectionsPer5]"), _GetPlainResString(IDS_MAXCON5SECLABEL) + _T(':'));
	Out.Replace(_T("[UseGzipForm]"), _GetPlainResString(IDS_WEB_GZIP_COMPRESSION));
	Out.Replace(_T("[UseGzipComment]"), _GetPlainResString(IDS_WEB_GZIP_COMMENT));

	Out.Replace(_T("[RefreshTimeForm]"), _GetPlainResString(IDS_WEB_REFRESH_TIME));
	Out.Replace(_T("[RefreshTimeComment]"), _GetPlainResString(IDS_WEB_REFRESH_COMMENT));
	Out.Replace(_T("[SpeedForm]"), _GetPlainResString(IDS_SPEED_LIMITS));
	Out.Replace(_T("[SpeedCapForm]"), _GetPlainResString(IDS_CAPACITY_LIMITS));

	Out.Replace(_T("[MaxCapDown]"), _GetPlainResString(IDS_PW_CON_DOWNLBL));
	Out.Replace(_T("[MaxCapUp]"), _GetPlainResString(IDS_PW_CON_UPLBL));
	Out.Replace(_T("[MaxDown]"), _GetPlainResString(IDS_PW_CON_DOWNLBL));
	Out.Replace(_T("[MaxUp]"), _GetPlainResString(IDS_PW_CON_UPLBL));
	Out.Replace(_T("[WebControl]"), _GetPlainResString(IDS_WEB_CONTROL));
	Out.Replace(_T("[eMuleAppName]"), _T("eMule"));
	Out.Replace(_T("[Apply]"), _GetPlainResString(IDS_PW_APPLY));

	CString m_sTestURL;
	m_sTestURL.Format(PORTTESTURL, theApp.GetAdvertisedTcpPort(),
		theApp.GetAdvertisedUdpPort(), thePrefs.GetLanguageID());

	// the portcheck will need to do an obfuscated callback too if obfuscation is requested, so we have to provide our userhash so it can create the key
	if (thePrefs.IsCryptLayerPreferred())
		m_sTestURL.AppendFormat(_T("&obfuscated_test=%s"), (LPCTSTR)md4str(thePrefs.GetUserHash()));

	Out.Replace(_T("[CONNECTIONTESTLINK]"), _SpecialChars(m_sTestURL));
	Out.Replace(_T("[CONNECTIONTESTLABEL]"), GetResString(IDS_CONNECTIONTEST));


	CString sT;
	sT.Format(_T("%u"), thePrefs.GetMaxDownload() == UNLIMITED ? 0u : thePrefs.GetMaxDownload());
	Out.Replace(_T("[MaxDownVal]"), sT);

	sT.Format(_T("%u"), thePrefs.GetMaxUpload() == UNLIMITED ? 0u : thePrefs.GetMaxUpload());
	Out.Replace(_T("[MaxUpVal]"), sT);

	sT.Format(_T("%u"), thePrefs.GetMaxGraphDownloadRate());
	Out.Replace(_T("[MaxCapDownVal]"), sT);

	sT.Format(_T("%u"), thePrefs.GetMaxGraphUploadRate(true));
	Out.Replace(_T("[MaxCapUpVal]"), sT);

	return Out;
}

CString CWebServer::_GetLoginScreen(const ThreadData &Data)
{
	CWebServer* owner = reinterpret_cast<CWebServer*>(Data.pThis); return owner == NULL ? CString() : RenderWebLogin(WebTemplateParent(owner), GetWebTemplate(WebTemplateParent(owner), WebTemplateId::Login), _GenerateNonce(Data), owner->m_nIntruderDetect >= 1, theApp.m_strCurVersionLong);
}
// eSE 8.14: Generate a CSPRNG nonce for challenge-response login
CStringA CWebServer::_GenerateNonce(const ThreadData &Data)
{
	CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	if (pThis == NULL)
		return CStringA();

	const CStringA nonce = GenerateWebRequestHexToken();
	const std::uint32_t clientIp = inet_addr(ipstrA(Data.inadr));
	const std::string value((LPCSTR)nonce, nonce.GetLength());
	if (!pThis->m_authPolicy.AddChallenge(value, clientIp, WebAuthNowMs()))
		return CStringA();
	return nonce;
}

// eSE 8.14: Validate SHA256(nonce + storedHash) == clientResponse
bool CWebServer::_ValidateChallengeResponse(const ThreadData &Data,
	const CString &sNonce, const CString &sResponse, bool &outIsAdmin)
{
	CWebServer* owner = reinterpret_cast<CWebServer*>(Data.pThis);
	if (owner == NULL)
		return false;
	CStringA nonce = CT2A(sNonce), response = CT2A(sResponse);
	nonce.MakeLower(); response.MakeLower();
	const std::uint32_t clientIp = inet_addr(ipstrA(Data.inadr));
	if (!owner->m_authPolicy.ConsumeChallenge(
		std::string((LPCSTR)nonce, nonce.GetLength()),
		clientIp, WebAuthNowMs()))
		return false;
	return ValidateWebChallengeDigest(
		nonce, response, thePrefs.GetWSPass(),
		thePrefs.GetWSIsLowUserEnabled(), thePrefs.GetWSLowPass(), outIsAdmin);
}


bool CWebServer::_IsLoggedIn(const ThreadData &Data, long lSession)
{
	CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	if (pThis == NULL)
		return false;
	return lSession > 0 && pThis->m_authPolicy.TouchSession(
		static_cast<std::uint32_t>(lSession),
		WebAuthNowMs(),
		WebSessionTimeoutMs());
}

void CWebServer::_RemoveTimeOuts(const ThreadData &Data)
{
	// remove expired sessions
	CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	if (pThis != NULL)
		pThis->UpdateSessionCount();
}

bool CWebServer::_RemoveSession(const ThreadData &Data, long lSession)
{
	CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	if (pThis == NULL || lSession == 0)
		return false;

	if (!pThis->m_authPolicy.RemoveSession(static_cast<std::uint32_t>(lSession)))
		return false;
	AddLogLine(true, (LPCTSTR)GetResString(IDS_WEB_SESSIONEND), (LPCTSTR)ipstr(pThis->m_uCurIP));
	SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_UPDATEMYINFO, 0);
	return true;
}

bool CWebServer::_IsSessionAdmin(const ThreadData &Data, long sessionID)
{
	CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	if (pThis == NULL || sessionID <= 0)
		return false;
	ese::web::WebSessionSnapshot session;
	return pThis->m_authPolicy.GetSession(
		static_cast<std::uint32_t>(sessionID), session) &&
		ese::web::WebAuthPolicy::HasPermission(
			session.role, ese::web::WebRole::Admin);
}

bool CWebServer::_IsSessionAdmin(const ThreadData &Data, const CString &strSsessionID)
{
	return _IsSessionAdmin(Data, _tstol(strSsessionID));
}

CString CWebServer::_GetPlainResString(UINT nID, bool noquote)
{
	return GetWebPlainResource(nID, noquote);
}

void CWebServer::_GetPlainResString(CString &rstrOut, UINT nID, bool noquote)
{
	rstrOut = GetWebPlainResource(nID, noquote);
}
// Ornis: creating the progressbar. colored if resources are given/available
CString CWebServer::_GetDownloadGraph(const ThreadData &Data, const CString &filehash)
{
	const CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	if (pThis == NULL)
		return CString();

	uchar fileid[MDX_DIGEST_SIZE];
	if (filehash.GetLength() != MDX_DIGEST_SIZE * 2 || !DecodeBase16(filehash, MDX_DIGEST_SIZE * 2, fileid, _countof(fileid)))
		return CString();

	//	Color style (paused files)
	static LPCTSTR const styles_paused[12] =
	{
		_T("p_green.gif"), _T("p_black.gif"), _T("p_yellow.gif"), _T("p_red.gif"),
		_T("p_blue1.gif"), _T("p_blue2.gif"), _T("p_blue3.gif"), _T("p_blue4.gif"),
		_T("p_blue5.gif"), _T("p_blue6.gif"), _T("p_greenpercent.gif"), _T("transparent.gif")
	};
	//	Color style (active files)
	static LPCTSTR const styles_active[12] =
	{
		_T("green.gif"), _T("black.gif"), _T("yellow.gif"), _T("red.gif"),
		_T("blue1.gif"), _T("blue2.gif"), _T("blue3.gif"), _T("blue4.gif"),
		_T("blue5.gif"), _T("blue6.gif"), _T("greenpercent.gif"), _T("transparent.gif")
	};

	// v7.4.0 — snapshot under DownloadQueue lock so the rendering loop below
	// never reads CPartFile state mid-mutation. Holding a CPartFile* across
	// the rendering loop is the use-after-free we keep almost hitting.
	struct PartFileRenderSnapshot {
		bool             found = false;
		bool             isPartFile = false;
		EPartFileStatus  status = PS_EMPTY;
		UINT             percentCompleted = 0;
		CStringA         chunkBar;
		uint16           barWidth = 0;
	};
	PartFileRenderSnapshot snap;
	snap.barWidth = (uint16)_tstoi(GetWebTemplate(WebTemplateParent(pThis), WebTemplateId::ProgressbarWidth));
	theApp.downloadqueue->WithFileByID(fileid, [&](CPartFile *f) {
		snap.found            = true;
		snap.isPartFile       = f->IsPartFile();
		snap.status           = f->GetStatus();
		snap.percentCompleted = f->GetPercentCompleted();
		snap.chunkBar         = f->GetProgressString(snap.barWidth);
	});
	const LPCTSTR *barcolours = (snap.found && snap.status == PS_PAUSED) ? styles_paused : styles_active;

	CString Out;
	if (!snap.found || !snap.isPartFile) {
		Out.Format(GetWebTemplate(WebTemplateParent(pThis), WebTemplateId::ProgressbarImgsPercent), barcolours[10], snap.barWidth);
		Out += _T("<br>");
		Out.AppendFormat(GetWebTemplate(WebTemplateParent(pThis), WebTemplateId::ProgressbarImgs), barcolours[0], snap.barWidth);
	} else {
		const CStringA &s_ChunkBar = snap.chunkBar;
		// and now make a graph out of the array - need to be in a progressive way

		int compl = static_cast<int>((snap.barWidth / 100.0) * snap.percentCompleted);
		Out.Format(GetWebTemplate(WebTemplateParent(pThis), WebTemplateId::ProgressbarImgsPercent), barcolours[compl > 0 ? 10 : 11], (compl > 0 ? compl : 5));
		Out += _T("<br>");

		BYTE lastcolor = 1;
		uint16 lastindex = 0;
		const uint16 uBarWidth = snap.barWidth;
		for (uint16 i = 0; i < uBarWidth; ++i) {
			BYTE c = (BYTE)(s_ChunkBar[i] - '0');
			if (c >= _countof(styles_active)) c = 0;          // defence-in-depth clamp
			if (lastcolor != c) {
				if (i > lastindex && lastcolor < _countof(styles_active))
					Out.AppendFormat(GetWebTemplate(WebTemplateParent(pThis), WebTemplateId::ProgressbarImgs), barcolours[lastcolor], i - lastindex);
				lastcolor = c;
				lastindex = i;
			}
		}
		if (lastcolor >= _countof(styles_active)) lastcolor = 0;   // hard clamp
		Out.AppendFormat(GetWebTemplate(WebTemplateParent(pThis), WebTemplateId::ProgressbarImgs), barcolours[lastcolor], uBarWidth - lastindex);
	}
	return Out;
}

CString CWebServer::_GetSearch(const ThreadData &Data)
{
	CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	if (pThis == NULL)
		return CString();

	CString sCat;
	int cat = _tstoi(_ParseURL(Data.sURL, _T("cat")));
	if (cat != 0)
		sCat.Format(_T("%i"), cat);

	const CString &sSession(_ParseURL(Data.sURL, _T("ses")));
	bool bSessionAdmin = _IsSessionAdmin(Data, sSession);
	CString Out(GetWebTemplate(WebTemplateParent(pThis), WebTemplateId::Search));

	if (!_ParseURL(Data.sURL, _T("downloads")).IsEmpty() && bSessionAdmin) {
		const CString &downloads(_ParseURLArray(Data.sURL, _T("downloads")));
		const std::vector<std::string> hashes =
			ese::web::WebSearchController::PlanDownloads(
				bSessionAdmin, std::string(CT2A(downloads)));
		for (const std::string& hash : hashes) {
			const CString hashText(CA2T(hash.c_str()));
			SendMessage(theApp.emuledlg->m_hWnd, WEB_ADDDOWNLOADS,
				(LPARAM)(LPCTSTR)hashText, cat);
		}
	}

	if (_ParseURL(Data.sURL, _T("c")) == _T("menu")) {
		const CString index = _ParseURL(Data.sURL, _T("m"));
		const CString hidden = _ParseURL(Data.sURL, _T("v"));
		const ese::web::WebSearchColumnChange change =
			ese::web::WebSearchController::PlanColumnChange(
				bSessionAdmin, std::string(CT2A(index)),
				std::string(CT2A(hidden)));
		if (change.allowed) {
			WSsearchColumnHidden[change.index] = change.hidden;
			_SaveWIConfigArray(WSsearchColumnHidden,
				_countof(WSsearchColumnHidden), _T("searchColumnHidden"));
		}
	}

	if (!_ParseURL(Data.sURL, _T("tosearch")).IsEmpty() && bSessionAdmin) {
		const CString expression = _ParseURL(Data.sURL, _T("tosearch"));
		const CString fileType = _ParseURL(Data.sURL, _T("type"));
		const CString minimum = _ParseURL(Data.sURL, _T("min"));
		const CString maximum = _ParseURL(Data.sURL, _T("max"));
		const CString availability = _ParseURL(Data.sURL, _T("avail"));
		const CString extension = _ParseURL(Data.sURL, _T("ext"));
		const CString method = _ParseURL(Data.sURL, _T("method"));
		const ese::web::WebSearchRequest request =
			ese::web::WebSearchController::PlanSearch(
				bSessionAdmin,
				std::string(CT2A(expression)),
				std::string(CT2A(fileType)),
				std::string(CT2A(minimum)),
				std::string(CT2A(maximum)),
				std::string(CT2A(availability)),
				std::string(CT2A(extension)),
				std::string(CT2A(method)));
		CString strResponse = request.allowed
			? _GetPlainResString(IDS_SW_SEARCHINGINFO)
			: _GetPlainResString(IDS_ERROR);
		SSearchParams* pParams = NULL;
		if (request.allowed) {
			SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION,
				WEBGUIIA_DELETEALLSEARCHES, 0);
			pParams = new SSearchParams;
			pParams->strExpression = expression;
			pParams->strFileType = fileType;
			pParams->ullMinSize = request.minimum_bytes;
			pParams->ullMaxSize = request.maximum_bytes;
			pParams->uAvailability = request.availability;
			pParams->strExtension = extension;
			pParams->eType = request.method == ese::web::WebSearchMethod::Kademlia
				? SearchTypeKademlia
				: (request.method == ese::web::WebSearchMethod::Global
					? SearchTypeEd2kGlobal : SearchTypeEd2kServer);
			try {
				if (pParams->eType != SearchTypeKademlia) {
					if (!theApp.emuledlg->searchwnd->DoNewEd2kSearch(pParams)) {
						delete pParams;
						pParams = NULL;
						strResponse =
							_GetPlainResString(IDS_ERR_NOTCONNECTED);
					}
					// Search results arrive asynchronously; the UI refreshes.
				} else if (!theApp.emuledlg->searchwnd->DoNewKadSearch(
					pParams)) {
					delete pParams;
					pParams = NULL;
					strResponse =
						_GetPlainResString(IDS_ERR_NOTCONNECTEDKAD);
				}
			} catch (...) {
				AddDebugLogLine(DLP_VERYHIGH, false,
					_T("*** Exception in CWebServer::_GetSearch search dispatch"));
				strResponse = _GetPlainResString(IDS_ERROR);
				ASSERT(0);
				delete pParams;
				pParams = NULL;
			}
		}
		Out.Replace(_T("[Message]"), strResponse);

	}
	else if (!_ParseURL(Data.sURL, _T("tosearch")).IsEmpty() && !_IsSessionAdmin(Data, sSession)) {
		Out.Replace(_T("[Message]"), _GetPlainResString(IDS_ACCESSDENIED));
	}
	else
		Out.Replace(_T("[Message]"), _GetPlainResString(IDS_SW_REFETCHRES));

	CString sSort = _ParseURL(Data.sURL, _T("sort"));
	const CString sortAscending = _ParseURL(Data.sURL, _T("sortAsc"));
	const ese::web::WebSearchSortDecision searchSort =
		ese::web::WebSearchController::PlanSort(
			bSessionAdmin, std::string(CT2A(sSort)),
			std::string(CT2A(sortAscending)),
			static_cast<unsigned>(pThis->m_iSearchSortby),
			pThis->m_bSearchAsc);
	if (searchSort.allowed) {
		pThis->m_iSearchSortby = static_cast<int>(searchSort.column);
		pThis->m_bSearchAsc = searchSort.ascending;
	}

	CString result(GetWebTemplate(WebTemplateParent(pThis), WebTemplateId::SearchHeader));
	CQArray<SearchFileStruct, SearchFileStruct> SearchFileArray;
	theApp.searchlist->GetWebList(&SearchFileArray, pThis->m_iSearchSortby);
	SearchFileArray.QuickSort(pThis->m_bSearchAsc);

	uchar aFileHash[16];
	CKnownFile *sameFile;
	CString strOverlayImage;
	CString strSourcesImage;
	CString strColorPrefix;
	CString strColorSuffix = _T("</font>");
	CString strSources;
	CString strFilename;
	CString strTemp, strTemp2;
	SearchFileStruct structFile;

	for (uint16 i = 0; i < SearchFileArray.GetCount(); ++i) {
		structFile = SearchFileArray.GetAt(i);
		DecodeBase16(structFile.m_strFileHash, 32, aFileHash, _countof(aFileHash));
		strOverlayImage = _T("none");
		const bool downloading =
			theApp.downloadqueue->HasFileByID(aFileHash) != NULL;
		bool known = false;
		if (!downloading) {
			sameFile = theApp.sharedfiles->GetFileByID(aFileHash);
			if (sameFile == NULL)
				sameFile = theApp.knownfiles->FindKnownFileByID(aFileHash);
			known = sameFile != NULL;
		}
		const ese::web::WebSearchResultProjection projection =
			ese::web::WebSearchController::ProjectResult(
				downloading, known, structFile.m_uSourceCount);
		strColorPrefix.Format(_T("<font color=#%02x%02x%02x>"),
			projection.red, projection.green, projection.blue);
		strSourcesImage = CString(projection.source_bucket);

		strSources.Format(_T("%u(%u)"), structFile.m_uSourceCount, structFile.m_dwCompleteSourceCount);
		strFilename = structFile.m_strFileName;
		strFilename.Replace(_T("'"), _T("\\'"));

		strTemp2.Format(_T("ed2k://|file|%s|%I64u|%s|/"),
			(LPCTSTR)strFilename, structFile.m_uFileSize, (LPCTSTR)structFile.m_strFileHash);

		strTemp.Format(GetWebTemplate(WebTemplateParent(pThis), WebTemplateId::SearchResultLine),
			(LPCTSTR)strSourcesImage, (LPCTSTR)strTemp2, (LPCTSTR)strOverlayImage,
			(LPCTSTR)_GetWebImageNameForFileType(structFile.m_strFileName),
			(!WSsearchColumnHidden[0]) ? (LPCTSTR)(strColorPrefix + StringLimit(structFile.m_strFileName, 70) + strColorSuffix) : _T(""),
			(!WSsearchColumnHidden[1]) ? (LPCTSTR)(strColorPrefix + CastItoXBytes(structFile.m_uFileSize) + strColorSuffix) : _T(""),
			(!WSsearchColumnHidden[2]) ? (LPCTSTR)(strColorPrefix + structFile.m_strFileHash + strColorSuffix) : _T(""),
			(!WSsearchColumnHidden[3]) ? (LPCTSTR)(strColorPrefix + strSources + strColorSuffix) : _T(""),
			(LPCTSTR)structFile.m_strFileHash);
		result.Append(strTemp);
	}

	if (thePrefs.GetCatCount() > 1)
		_InsertCatBox(Out, 0, GetWebTemplate(WebTemplateParent(pThis), WebTemplateId::CatArrow), false, false, sSession, _T(""));
	else
		Out.Replace(_T("[CATBOX]"), _T(""));

	Out.Replace(_T("[SEARCHINFOMSG]"), _T(""));
	Out.Replace(_T("[RESULTLIST]"), result);
	Out.Replace(_T("[Result]"), GetResString(IDS_SW_RESULT));
	Out.Replace(_T("[Session]"), sSession);
	Out.Replace(_T("[Name]"), _GetPlainResString(IDS_SW_NAME));
	Out.Replace(_T("[Type]"), _GetPlainResString(IDS_TYPE));
	Out.Replace(_T("[Any]"), _GetPlainResString(IDS_SEARCH_ANY));
	Out.Replace(_T("[Audio]"), _GetPlainResString(IDS_SEARCH_AUDIO));
	Out.Replace(_T("[Image]"), _GetPlainResString(IDS_SEARCH_PICS));
	Out.Replace(_T("[Video]"), _GetPlainResString(IDS_SEARCH_VIDEO));
	Out.Replace(_T("[Document]"), _GetPlainResString(IDS_SEARCH_DOC));
	Out.Replace(_T("[CDImage]"), _GetPlainResString(IDS_SEARCH_CDIMG));
	Out.Replace(_T("[Program]"), _GetPlainResString(IDS_SEARCH_PRG));
	Out.Replace(_T("[Archive]"), _GetPlainResString(IDS_SEARCH_ARC));
	Out.Replace(_T("[Search]"), _GetPlainResString(IDS_EM_SEARCH));
	Out.Replace(_T("[Unicode]"), _GetPlainResString(IDS_SEARCH_UNICODE));
	Out.Replace(_T("[Size]"), _GetPlainResString(IDS_DL_SIZE));
	Out.Replace(_T("[Start]"), _GetPlainResString(IDS_SW_START));
	Out.Replace(_T("[USESSERVER]"), _GetPlainResString(IDS_SERVER));
	Out.Replace(_T("[USEKADEMLIA]"), _GetPlainResString(IDS_KADEMLIA));
	Out.Replace(_T("[METHOD]"), _GetPlainResString(IDS_METHOD));
	Out.Replace(_T("[SizeMin]"), _GetPlainResString(IDS_SEARCHMINSIZE));
	Out.Replace(_T("[SizeMax]"), _GetPlainResString(IDS_SEARCHMAXSIZE));
	Out.Replace(_T("[Availabl]"), _GetPlainResString(IDS_SEARCHAVAIL));
	Out.Replace(_T("[Extention]"), _GetPlainResString(IDS_SEARCHEXTENTION));
	Out.Replace(_T("[Global]"), _GetPlainResString(IDS_SW_GLOBAL));
	Out.Replace(_T("[MB]"), _GetPlainResString(IDS_MBYTES));
	Out.Replace(_T("[Apply]"), _GetPlainResString(IDS_PW_APPLY));
	Out.Replace(_T("[CatSel]"), sCat);
	Out.Replace(_T("[Ed2klink]"), _GetPlainResString(IDS_SW_LINK));

	CString pcSortIcon((pThis->m_bSearchAsc) ? GetWebTemplate(WebTemplateParent(pThis), WebTemplateId::UpArrow) : GetWebTemplate(WebTemplateParent(pThis), WebTemplateId::DownArrow));

	CString strTmp;
	_GetPlainResString(strTmp, IDS_DL_FILENAME);
	if (!WSsearchColumnHidden[0]) {
		Out.Replace(_T("[FilenameI]"), (pThis->m_iSearchSortby == 0) ? pcSortIcon : _T(""));
		Out.Replace(_T("[FilenameH]"), strTmp);
	} else {
		Out.Replace(_T("[FilenameI]"), _T(""));
		Out.Replace(_T("[FilenameH]"), _T(""));
	}
	Out.Replace(_T("[FilenameM]"), strTmp);

	_GetPlainResString(strTmp, IDS_DL_SIZE);
	if (!WSsearchColumnHidden[1]) {
		Out.Replace(_T("[FilesizeI]"), (pThis->m_iSearchSortby == 1) ? pcSortIcon : _T(""));
		Out.Replace(_T("[FilesizeH]"), strTmp);
	} else {
		Out.Replace(_T("[FilesizeI]"), _T(""));
		Out.Replace(_T("[FilesizeH]"), _T(""));
	}
	Out.Replace(_T("[FilesizeM]"), strTmp);

	_GetPlainResString(strTmp, IDS_FILEHASH);
	if (!WSsearchColumnHidden[2]) {
		Out.Replace(_T("[FilehashI]"), (pThis->m_iSearchSortby == 2) ? pcSortIcon : _T(""));
		Out.Replace(_T("[FilehashH]"), strTmp);
	} else {
		Out.Replace(_T("[FilehashI]"), _T(""));
		Out.Replace(_T("[FilehashH]"), _T(""));
	}
	Out.Replace(_T("[FilehashM]"), strTmp);

	_GetPlainResString(strTmp, IDS_DL_SOURCES);
	if (!WSsearchColumnHidden[3]) {
		Out.Replace(_T("[SourcesI]"), (pThis->m_iSearchSortby == 3) ? pcSortIcon : _T(""));
		Out.Replace(_T("[SourcesH]"), strTmp);
	} else {
		Out.Replace(_T("[SourcesI]"), _T(""));
		Out.Replace(_T("[SourcesH]"), _T(""));
	}
	Out.Replace(_T("[SourcesM]"), strTmp);

	Out.Replace(_T("[Download]"), _GetPlainResString(IDS_DOWNLOAD));

	strTmp.Format(_T("%i"), (pThis->m_iSearchSortby != 0 || (pThis->m_iSearchSortby == 0 && pThis->m_bSearchAsc == 0)) ? 1 : 0);
	Out.Replace(_T("[SORTASCVALUE0]"), strTmp);
	strTmp.Format(_T("%i"), (pThis->m_iSearchSortby != 1 || (pThis->m_iSearchSortby == 1 && pThis->m_bSearchAsc == 0)) ? 1 : 0);
	Out.Replace(_T("[SORTASCVALUE1]"), strTmp);
	strTmp.Format(_T("%i"), (pThis->m_iSearchSortby != 2 || (pThis->m_iSearchSortby == 2 && pThis->m_bSearchAsc == 0)) ? 1 : 0);
	Out.Replace(_T("[SORTASCVALUE2]"), strTmp);
	strTmp.Format(_T("%i"), (pThis->m_iSearchSortby != 3 || (pThis->m_iSearchSortby == 3 && pThis->m_bSearchAsc == 0)) ? 1 : 0);
	Out.Replace(_T("[SORTASCVALUE3]"), strTmp);
	strTmp.Format(_T("%i"), (pThis->m_iSearchSortby != 4 || (pThis->m_iSearchSortby == 4 && pThis->m_bSearchAsc == 0)) ? 1 : 0);
	Out.Replace(_T("[SORTASCVALUE4]"), strTmp);
	strTmp.Format(_T("%i"), (pThis->m_iSearchSortby != 5 || (pThis->m_iSearchSortby == 5 && pThis->m_bSearchAsc == 0)) ? 1 : 0);
	Out.Replace(_T("[SORTASCVALUE5]"), strTmp);

	return Out;
}

INT_PTR CWebServer::UpdateSessionCount()
{
	M2AModuleHandle transferProjectionBinding = M2A_BIND_W4_AD763A5EE0(M2AParentPort{this}); if (!transferProjectionBinding) return 0; const std::size_t removed = m_authPolicy.PurgeExpiredSessions(
		WebAuthNowMs(), WebSessionTimeoutMs());
	if (removed != 0)
		SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_UPDATEMYINFO, 0);

	return static_cast<INT_PTR>(m_authPolicy.SessionCount());
}

void CWebServer::_InsertCatBox(CString &Out, int preselect, LPCTSTR boxlabel, bool jump, bool extraCats, const CString &sSession, const CString &sFileHash, bool ed2kbox)
{
	int fileCategory = preselect; uchar hash[MDX_DIGEST_SIZE]; if (!sFileHash.IsEmpty() && strmd4(sFileHash, hash)) theApp.downloadqueue->WithFileByID(hash, [&](CPartFile* file) { fileCategory = file->GetCategory(); });
	InsertWebCategoryBox(Out, preselect, boxlabel, jump, extraCats, sSession, sFileHash, fileCategory, ed2kbox);
}
CString CWebServer::_GetRemoteLinkAddedOk(const ThreadData &Data)
{
	CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	if (pThis == NULL)
		return CString();

	int cat = _tstoi(_ParseURL(Data.sURL, _T("cat")));
	CString HTTPTemp = _ParseURL(Data.sURL, _T("c"));

	const TCHAR *buf = HTTPTemp;
	theApp.emuledlg->SendMessage(WEB_ADDDOWNLOADS, (WPARAM)buf, cat);

	const CString description = GetResString(IDS_WEB_REMOTE_LINK_ADDED);
	const std::wstring body = ese::web::Serialize(
		ese::web::WebRemoteLinkXmlResponseModel{
			true,
			std::wstring(
				static_cast<LPCTSTR>(description),
				static_cast<std::size_t>(description.GetLength())),
			std::wstring(
				static_cast<LPCTSTR>(HTTPTemp),
				static_cast<std::size_t>(HTTPTemp.GetLength()))});
	return CString(body.data(), static_cast<int>(body.size()));
}

CString CWebServer::_GetRemoteLinkAddedFailed(const ThreadData &Data)
{
	CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	if (pThis == NULL)
		return CString();

	const CString description = GetResString(IDS_WEB_REMOTE_LINK_NOT_ADDED);
	const std::wstring body = ese::web::Serialize(
		ese::web::WebRemoteLinkXmlResponseModel{
			false,
			std::wstring(
				static_cast<LPCTSTR>(description),
				static_cast<std::size_t>(description.GetLength())),
			std::wstring()});
	return CString(body.data(), static_cast<int>(body.size()));
}

void CWebServer::_SetLastUserCat(const ThreadData &Data, long lSession, int cat)
{
	CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	if (pThis == NULL)
		return;

	if (lSession > 0)
		pThis->m_authPolicy.SetLastCategory(
			static_cast<std::uint32_t>(lSession),
			cat,
			WebAuthNowMs(),
			WebSessionTimeoutMs());
}

int CWebServer::_GetLastUserCat(const ThreadData &Data, long lSession)
{
	CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	if (pThis == NULL)
		return 0;

	int category = 0;
	return lSession > 0 && pThis->m_authPolicy.GetLastCategory(
		static_cast<std::uint32_t>(lSession),
		category,
		WebAuthNowMs(),
		WebSessionTimeoutMs())
		? category
		: 0;
}



static CStringA EseJsonEscapeA(const CStringA& input)
{
	const std::string value(
		static_cast<LPCSTR>(input),
		static_cast<std::size_t>(input.GetLength()));
	const std::string escaped = ese::web::EscapeJson(value);
	return CStringA(escaped.data(), static_cast<int>(escaped.size()));
}

static CStringA EseHexKey16A(const uchar* key)
{
	CStringA hashHex;
	if (key != NULL) {
		for (int h = 0; h < 16; h++)
			hashHex.AppendFormat("%02x", key[h]);
	}
	return hashHex;
}

static int EseHexNibbleA(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return 10 + c - 'a';
	if (c >= 'A' && c <= 'F')
		return 10 + c - 'A';
	return -1;
}

static bool EseHexToKey16A(const CStringA& hex, uchar* outKey)
{
	if (hex.GetLength() != 32 || outKey == NULL)
		return false;
	for (int i = 0; i < 16; ++i) {
		int hi = EseHexNibbleA(hex[i * 2]);
		int lo = EseHexNibbleA(hex[i * 2 + 1]);
		if (hi < 0 || lo < 0)
			return false;
		outKey[i] = (uchar)((hi << 4) | lo);
	}
	return true;
}

// eSE Live Streaming & Network Status API
void CWebServer::_ProcessLiveAPI(const ThreadData &Data)
{
	CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	if (pThis == NULL)
		return;
	CStringA sURL(CT2A(Data.sURL));

	// --- M1 (mobile track): token-prefixed remote access ---------------------
	// Remote HLS players (Media3/VLC/Safari) resolve segment URIs relative to
	// the playlist URL and drop query strings, so the session token travels as
	// a path prefix instead: /s/{ses}/api/live/{hash}/stream.m3u8. The token is
	// a live webserver session id obtained through the password-gated login in
	// _ProcessURL; _IsLoggedIn() both validates it and renews its expiry, so an
	// actively playing stream keeps its own session alive. Bad or expired
	// tokens get a 403 but are NOT added to badlogins: a player left paused
	// past the session timeout would otherwise ban its own IP.
	bool bTokenAuth = false;
	bool bTokenAdmin = false;
	ese::web::WebSessionSnapshot tokenSession;
	if (sURL.GetLength() > 3 && strncmp(sURL, "/s/", 3) == 0) {
		const int iSlash = sURL.Find('/', 3);
		const long lToken = (iSlash > 3) ? atol((LPCSTR)sURL + 3) : 0;
		if (lToken != 0 && _IsLoggedIn(Data, lToken) &&
			pThis->m_authPolicy.GetSession(
				static_cast<std::uint32_t>(lToken), tokenSession)) {
			bTokenAuth = true;
			bTokenAdmin = tokenSession.role == ese::web::WebRole::Admin;
			sURL.Delete(0, iSlash); // strip prefix; routing below sees the bare path
		} else {
			SendWebForbidden(Data.pSocket, "invalid or expired token");
			const uint32 clientIP = Data.inadr.S_un.S_addr; // network order
			LIVE_LOG("SEC", "Rejected /s/ request with bad token from %lu.%lu.%lu.%lu  url=%s",
				(unsigned long)(clientIP & 0xFF),
				(unsigned long)((clientIP >> 8) & 0xFF),
				(unsigned long)((clientIP >> 16) & 0xFF),
				(unsigned long)((clientIP >> 24) & 0xFF),
				(LPCSTR)sURL);
			return;
		}
	}

	const std::string livePath((LPCSTR)sURL, sURL.GetLength());
	const ese::web::WebSessionSnapshot* mutationSession =
		bTokenAuth ? &tokenSession : nullptr;
	if (!ese::web::WebAuthPolicy::AuthorizeLiveRequest(
		livePath,
		Data.inadr.S_un.S_addr == htonl(INADDR_LOOPBACK),
		mutationSession,
		std::string((LPCSTR)Data.sCsrfToken, Data.sCsrfToken.GetLength()),
		std::string((LPCSTR)Data.sFetchSite, Data.sFetchSite.GetLength()),
		std::string((LPCSTR)Data.sHost, Data.sHost.GetLength()),
		std::string((LPCSTR)Data.sOrigin, Data.sOrigin.GetLength()))) {
		SendWebForbidden(
			Data.pSocket, "trusted origin or session CSRF required");
		return;
	}

	// Guest (low-user) tokens are viewers only. WebAuthPolicy owns the complete
	// permission matrix so newly extracted operator families cannot silently
	// bypass this boundary. Loopback keeps today's full-trust behavior.
	const ese::web::WebRole tokenRole = bTokenAdmin
		? ese::web::WebRole::Admin
		: ese::web::WebRole::Guest;
	const ese::web::WebRole requiredRole =
		ese::web::WebAuthPolicy::RequiredRoleForLivePath(
			std::string((LPCSTR)sURL, sURL.GetLength()));
	if (bTokenAuth && !ese::web::WebAuthPolicy::HasPermission(
		tokenRole, requiredRole)) {
		SendWebForbidden(Data.pSocket, "admin session required");
		return;
	}

	// --- /api/network/connect?ed2k=1&kad=1 ---
	// Local diagnostic control for headless/minimized multi-PC validation. The
	// endpoint is covered by the localhost/session gate above and guest sessions
	// are explicitly denied. SendMessage marshals both requests onto the GUI
	// thread, matching the authenticated classic WebServer controls.
	if (Data.webRoute == ese::web::WebRouteId::ApiNetworkConnect) {
		const CString ed2kArg(_ParseURL(Data.sURL, _T("ed2k")));
		const CString kadArg(_ParseURL(Data.sURL, _T("kad")));
		const bool requestEd2k = ed2kArg.IsEmpty() || ed2kArg != _T("0");
		const bool requestKad = kadArg.IsEmpty() || kadArg != _T("0");

		const ese::web::WebRateDecision connectRate =
			pThis->m_authPolicy.CheckRateLimit(
				ese::web::WebAction::NetworkConnect, WebAuthNowMs(), 2000);
		if (!connectRate.allowed) {
			CStringA json = "{\"success\":false,\"error\":\"rate_limited\",\"retry_after_ms\":";
			CStringA retry;
			retry.Format("%I64u}", connectRate.retry_after_ms);
			json += retry;
			CStringA hdr;
			hdr.Format(
				"HTTP/1.1 429 Too Many Requests\r\n"
				"Content-Type: application/json\r\n"
				"Cache-Control: no-store\r\n"
				"Content-Length: %d\r\n\r\n",
				json.GetLength());
			Data.pSocket->SendData(hdr, hdr.GetLength());
			Data.pSocket->SendData(json, json.GetLength());
			return;
		}

		bool ed2kRequested = false;
		bool kadRequested = false;
		if (requestEd2k && theApp.serverconnect != NULL
			&& !theApp.serverconnect->IsConnected()
			&& !theApp.serverconnect->IsConnecting()) {
			SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_CONNECTTOSERVER, 0);
			ed2kRequested = true;
		}
		if (requestKad && !Kademlia::CKademlia::IsRunning()) {
			SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_KAD_START, 0);
			kadRequested = true;
		}

		CStringA json;
		json.Format(
			"{\"success\":true,\"requested\":{\"ed2k\":%s,\"kad\":%s},"
			"\"state\":{\"ed2k_connected\":%s,\"ed2k_connecting\":%s,"
			"\"kad_running\":%s,\"kad_connected\":%s,"
			"\"kad_configured_mask\":%u,\"kad_running_mask\":%u,"
			"\"kad2_running\":%s,\"kad2_connected\":%s,"
			"\"kad6_running\":%s,\"kad6_connected\":%s,"
			"\"kad6_verified_contacts\":%u}}",
			ed2kRequested ? "true" : "false",
			kadRequested ? "true" : "false",
			(theApp.serverconnect != NULL && theApp.serverconnect->IsConnected()) ? "true" : "false",
			(theApp.serverconnect != NULL && theApp.serverconnect->IsConnecting()) ? "true" : "false",
			Kademlia::CKademlia::IsRunning() ? "true" : "false",
			Kademlia::CKademlia::IsAnyConnected() ? "true" : "false",
			static_cast<unsigned>(thePrefs.GetKadNetworkMask()),
			static_cast<unsigned>(Kademlia::CKademlia::GetRunningNetworkMask()),
			Kademlia::CKademlia::IsKad2Running() ? "true" : "false",
			Kademlia::CKademlia::IsKad2Connected() ? "true" : "false",
			Kademlia::CKademlia::IsKad6Running() ? "true" : "false",
			Kademlia::CKademlia::IsKad6Connected() ? "true" : "false",
			Kademlia::CKademlia::GetKad6VerifiedContacts());
		CStringA hdr;
		hdr.Format(
			"HTTP/1.1 200 OK\r\n"
			"Content-Type: application/json\r\n"
			"Cache-Control: no-store\r\n"
			"Access-Control-Allow-Origin: http://127.0.0.1\r\n"
			"X-Content-Type-Options: nosniff\r\n"
			"Content-Length: %d\r\n\r\n",
			json.GetLength());
		Data.pSocket->SendData(hdr, hdr.GetLength());
		Data.pSocket->SendData(json, json.GetLength());
		return;
	}

	// --- /api/debug/source-resolutions?after={sequence} --------------------
	// Local-only, bounded and privacy-preserving evidence for the D01
	// dual-stack hostname-source gate. It exposes hashes and outcomes, never a
	// hostname or address. A baseline sequence lets the harness attribute one
	// injection without clearing process state.
	if (Data.webRoute == ese::web::WebRouteId::ApiDebugSourceResolutions) {
		const uint32 clientIP = Data.inadr.S_un.S_addr;
		if (clientIP != htonl(INADDR_LOOPBACK)) {
			CStringA json =
				"{\"error\":\"forbidden\",\"hint\":\"this diagnostic is localhost-only\"}";
			CStringA header;
			header.Format(
				"HTTP/1.1 403 Forbidden\r\n"
				"Content-Type: application/json\r\n"
				"Cache-Control: no-store\r\n"
				"Content-Length: %d\r\n\r\n",
				json.GetLength());
			Data.pSocket->SendData(header, header.GetLength());
			Data.pSocket->SendData(json, json.GetLength());
			return;
		}

		uint64 afterSequence = 0;
		const CString afterArg(_ParseURL(Data.sURL, _T("after")));
		if (!afterArg.IsEmpty())
			afterSequence = _tcstoui64(afterArg, NULL, 10);

		uint64 currentSequence = 0;
		std::vector<SSourceResolutionEvent> events;
		if (theApp.downloadqueue != NULL) {
			theApp.downloadqueue->GetSourceResolutionEvents(
				afterSequence, currentSequence, events);
		}

		CStringA json;
		json.Format(
			"{\"schema\":\"ese.debug.source-resolutions/v1\","
			"\"sequence\":%I64u,\"events\":[",
			static_cast<unsigned __int64>(currentSequence));
		for (size_t eventIndex = 0; eventIndex < events.size(); ++eventIndex) {
			const SSourceResolutionEvent& event = events[eventIndex];
			if (eventIndex != 0)
				json += ',';
			CStringA eventJson;
			eventJson.Format(
				"{\"sequence\":%I64u,"
				"\"hostname_sha256\":\"%s\","
				"\"file_ed2k_hash\":\"%s\","
				"\"port\":%u,"
				"\"resolver_result\":\"%s\","
				"\"resolved\":{\"ipv4_count\":%u,\"ipv6_count\":%u,"
				"\"endpoint_set_sha256\":\"%s\"},"
				"\"materialized\":{\"ipv4_count\":%u,\"ipv6_count\":%u,"
				"\"endpoint_set_sha256\":\"%s\","
				"\"simultaneously_retained\":%s},"
				"\"candidates\":[",
				static_cast<unsigned __int64>(event.sequence),
				(LPCSTR)EseJsonEscapeA(event.hostnameSha256),
				(LPCSTR)EseJsonEscapeA(event.fileEd2kHash),
				static_cast<unsigned>(event.port),
				(LPCSTR)EseJsonEscapeA(event.resolverResult),
				static_cast<unsigned>(event.resolvedIPv4Count),
				static_cast<unsigned>(event.resolvedIPv6Count),
				(LPCSTR)EseJsonEscapeA(event.resolvedEndpointSetSha256),
				static_cast<unsigned>(event.materializedIPv4Count),
				static_cast<unsigned>(event.materializedIPv6Count),
				(LPCSTR)EseJsonEscapeA(event.materializedEndpointSetSha256),
				event.simultaneouslyRetained ? "true" : "false");
			json += eventJson;
			for (size_t candidateIndex = 0;
				candidateIndex < event.candidates.size(); ++candidateIndex)
			{
				const SSourceResolutionCandidateEvent& candidate =
					event.candidates[candidateIndex];
				if (candidateIndex != 0)
					json += ',';
				CStringA candidateJson;
				candidateJson.Format(
					"{\"family\":\"%s\",\"endpoint_sha256\":\"%s\","
					"\"outcome\":\"%s\",\"source_origin\":\"%s\"}",
					(LPCSTR)EseJsonEscapeA(candidate.family),
					(LPCSTR)EseJsonEscapeA(candidate.endpointSha256),
					(LPCSTR)EseJsonEscapeA(candidate.outcome),
					(LPCSTR)EseJsonEscapeA(candidate.sourceOrigin));
				json += candidateJson;
			}
			json += "]}";
		}
		json += "]}";

		CStringA header;
		header.Format(
			"HTTP/1.1 200 OK\r\n"
			"Content-Type: application/json\r\n"
			"Cache-Control: no-store\r\n"
			"Access-Control-Allow-Origin: http://127.0.0.1\r\n"
			"X-Content-Type-Options: nosniff\r\n"
			"Content-Length: %d\r\n\r\n",
			json.GetLength());
		Data.pSocket->SendData(header, header.GetLength());
		Data.pSocket->SendData(json, json.GetLength());
		return;
	}

	// --- /api/status --- eSE Network health for React alerts (Fase 2)
	if (Data.webRoute == ese::web::WebRouteId::ApiStatus) {
		// Determine UPnP port forwarding state: "true", "false", "unknown"
		const char* szUpnpFwd = "unknown";
		if (theApp.m_pUPnPFinder && theApp.m_pUPnPFinder->GetImplementation()) {
			TRISTATE ts = theApp.m_pUPnPFinder->GetImplementation()->ArePortsForwarded();
			szUpnpFwd = (ts == TRIS_TRUE) ? "true" : (ts == TRIS_FALSE) ? "false" : "unknown";
		}
		// I03/I04 need stable identity and connecting-list evidence, but those
		// diagnostics must never make the persistent eD2K identity observable
		// to a remote dashboard session (including an authenticated guest).
		// Keep the schema stable and expose values only to a loopback caller.
		ese::web::WebNetworkStatusDiagnostics status;
		status.local.exposed =
			Data.inadr.S_un.S_addr == htonl(INADDR_LOOPBACK);
		if (status.local.exposed) {
			const CStringA userHashA = CT2A(md4str(thePrefs.GetUserHash()));
			status.local.user_hash.assign(
				static_cast<LPCSTR>(userHashA),
				static_cast<std::size_t>(userHashA.GetLength()));
			status.local.connecting_client_count = theApp.clientlist
				? theApp.clientlist->GetConnectingClientCount() : 0;
			status.local.connecting_client_adds = theApp.clientlist
				? theApp.clientlist->GetConnectingClientAdds() : 0;
			status.local.connecting_client_high_water = theApp.clientlist
				? theApp.clientlist->GetConnectingClientHighWater() : 0;
			status.local.connecting_client_duplicate_adds = theApp.clientlist
				? theApp.clientlist->GetConnectingClientDuplicateAdds() : 0;
		}
		CKadKeepalive::Stats ksKeepalive = CKadKeepalive::Instance().GetStats();  // R.2 telemetry snapshot
		status.upnp_critical_error = thePrefs.GetUPnPCriticalError();
		status.utp_hole_punch_enabled = thePrefs.GetUtpHolePunchEnabled();
		status.web_upnp_active = thePrefs.GetWSUseUPnP();
		status.upnp_ports_forwarded = szUpnpFwd;
		status.kad_connected = Kademlia::CKademlia::IsAnyConnected();
		status.kad_configured_mask = thePrefs.GetKadNetworkMask();
		status.kad_running_mask = Kademlia::CKademlia::GetRunningNetworkMask();
		status.kad2_running = Kademlia::CKademlia::IsKad2Running();
		status.kad2_connected = Kademlia::CKademlia::IsKad2Connected();
		status.kad6_running = Kademlia::CKademlia::IsKad6Running();
		status.kad6_connected = Kademlia::CKademlia::IsKad6Connected();
		status.kad6_verified_contacts =
			Kademlia::CKademlia::GetKad6VerifiedContacts();
		status.ed2k_connected =
			theApp.serverconnect && theApp.serverconnect->IsConnected();
		status.hole_punch_attempts = CStatistics::m_dwHolePunchAttempts;
		status.hole_punch_success = CStatistics::m_dwHolePunchSuccess;
		status.hole_punch_sym_nat_fail = CStatistics::m_dwHolePunchSymNATFail;
		status.hole_punch_encrypted = CStatistics::m_dwHolePunchEncrypted;
		status.hole_punch_plaintext = CStatistics::m_dwHolePunchPlaintext;
		status.hole_punch_req_recv = CStatistics::m_dwHolePunchReqRecv;
		status.hole_punch_challenge_sent =
			CStatistics::m_dwHolePunchChallengeSent;
		status.kad3_rdv_req_sent = CStatistics::m_dwKad3RdvReqSent;
		status.kad3_rdv_req_recv = CStatistics::m_dwKad3RdvReqRecv;
		status.kad3_rdv_challenge_sent =
			CStatistics::m_dwKad3RdvChallengeSent;
		status.kad3_rdv_fwd = CStatistics::m_dwKad3RdvFwd;
		status.kad3_rdv_success = CStatistics::m_dwKad3RdvSuccess;
		status.keepalive_running = CKadKeepalive::Instance().IsRunning();
		status.keepalive_pings_sent = ksKeepalive.pingsSent;
		status.keepalive_pongs_recv = ksKeepalive.pongsReceived;
		status.keepalive_supernodes = ksKeepalive.supernodesActive;
		status.netlab_consent =
			thePrefs.GetEseNetLabConsent() == CPreferences::EseNetLabAccepted
				? "accepted"
				: thePrefs.GetEseNetLabConsent() ==
						CPreferences::EseNetLabDeclined
					? "declined" : "undecided";
		status.netlab_advanced_consent =
			thePrefs.GetEseNetLabAdvancedConsent() ==
				CPreferences::EseNetLabAccepted
				? "accepted"
				: thePrefs.GetEseNetLabAdvancedConsent() ==
						CPreferences::EseNetLabDeclined
					? "declined" : "undecided";
		status.netlab_contribution_consent =
			thePrefs.GetEseNetLabContributionConsent() ==
				CPreferences::EseNetLabAccepted
				? "accepted"
				: thePrefs.GetEseNetLabContributionConsent() ==
						CPreferences::EseNetLabDeclined
					? "declined" : "undecided";
		status.netlab_enabled = thePrefs.IsEseNetLabActive();
		const std::string body =
			ese::web::WebDiagnostics::Serialize(status);
		const CStringA json(body.data(), static_cast<int>(body.size()));
		CStringA header;
		header.Format(
			"HTTP/1.1 200 OK\r\n"
			HTTPInit
			"Content-Type: application/json\r\n"
			"Content-Length: %d\r\n\r\n",
			json.GetLength());
		Data.pSocket->SendData(header, header.GetLength());
		Data.pSocket->SendData(json, json.GetLength());
		return;
	}

	// --- /api/live/join?key={32hex}&title=... --- Start P2P viewing for a stream
	if (Data.webRoute == ese::web::WebRouteId::ApiLiveJoin) {
		CString keyT(_ParseURL(Data.sURL, _T("key")));
		CString title(_ParseURL(Data.sURL, _T("title")));
		if (title.IsEmpty())
			title = _T("Live");

		CStringA keyA = CT2A(keyT);
		uchar streamKey[16];
		bool ok = (theApp.liveStreamManager != NULL) && EseHexToKey16A(keyA, streamKey);
		if (ok) {
			// JoinStream mutates Live state and drives Kad — marshal it to the
			// main thread. This worker holds no Live lock here, so the blocking
			// SendMessage cannot deadlock.
			LiveWebJoinReq req;
			req.streamKey = streamKey;
			req.title     = title;
			req.address   = CAddress();
			req.port      = 0;
			req.joined    = false;
			req.dialed    = false;
			if (theApp.emuledlg != NULL)
				theApp.emuledlg->SendMessage(UM_LIVE_WEB_JOIN, 0, (LPARAM)&req);
			ok = req.joined;
		}

		const ese::web::SerializedWebResponse response =
			ese::web::Serialize(ese::web::WebJoinResponseModel{
				ok,
				std::string(
					static_cast<LPCSTR>(keyA),
					static_cast<std::size_t>(keyA.GetLength()))});
		const CStringA json(
			response.body.data(),
			static_cast<int>(response.body.size()));
		CStringA header;
		header.Format(
			"HTTP/1.1 %u %s\r\n"
			"Content-Type: %s\r\n"
			"Access-Control-Allow-Origin: http://127.0.0.1\r\n"
			"X-Content-Type-Options: nosniff\r\n"
			"Content-Length: %d\r\n\r\n",
			response.status_code,
			response.reason_phrase.c_str(),
			response.content_type.c_str(),
			json.GetLength());
		Data.pSocket->SendData(header, header.GetLength());
		Data.pSocket->SendData(json, json.GetLength());
		return;
	}

	// --- /api/live/leave --- Stop P2P viewing (ghost-viewer fix 2026-06).
	// Hit by the player pages' pagehide beacon (relayed by ese-server for
	// the :8080 pages). Marshaled: LeaveStream sends OP_LIVE_UNSUBSCRIBE
	// over eD2K sockets — main-thread only. Idempotent when not viewing.
	if (Data.webRoute == ese::web::WebRouteId::ApiLiveLeave) {
		LiveWebLeaveReq req;
		memset(req.streamKey, 0, sizeof req.streamKey);
		req.hasStreamKey = false;
		req.wasViewing = false;
		CString keyT(_ParseURL(Data.sURL, _T("key")));
		if (!keyT.IsEmpty()) {
			CStringA keyA = CT2A(keyT);
			req.hasStreamKey = EseHexToKey16A(keyA, req.streamKey);
		}
		if (theApp.emuledlg != NULL && theApp.liveStreamManager != NULL)
			theApp.emuledlg->SendMessage(UM_LIVE_WEB_LEAVE, 0, (LPARAM)&req);
		CStringA json;
		json.Format("{\"success\":true,\"wasViewing\":%s}", req.wasViewing ? "true" : "false");
		CStringA header;
		header.Format(
			"HTTP/1.1 200 OK\r\n"
			"Content-Type: application/json\r\n"
			"Access-Control-Allow-Origin: http://127.0.0.1\r\n"
			"X-Content-Type-Options: nosniff\r\n"
			"Content-Length: %d\r\n\r\n",
			json.GetLength());
		Data.pSocket->SendData(header, header.GetLength());
		Data.pSocket->SendData(json, json.GetLength());
		return;
	}

	// --- /api/live/player-alive --- heartbeat for the ghost-viewer watchdog.
	// ese-server pings this (throttled) while a browser keeps fetching HLS
	// from its /hls-local handler, which eMule otherwise never sees. Atomic
	// tick write only — safe on this worker thread (same class as the OBS-1
	// Interlocked counters; no Live lock, no marshaling needed).
	if (Data.webRoute == ese::web::WebRouteId::ApiLivePlayerAlive) {
		if (theApp.liveStreamManager != NULL) {
			CString keyT(_ParseURL(Data.sURL, _T("key")));
			bool matchesCurrent = keyT.IsEmpty();
			if (!keyT.IsEmpty()) {
				uchar requestedKey[16], viewerKey[16];
				CStringA keyA = CT2A(keyT);
				matchesCurrent = EseHexToKey16A(keyA, requestedKey)
					&& theApp.liveStreamManager->CopyViewerStreamKey(viewerKey)
					&& memcmp(requestedKey, viewerKey, 16) == 0;
			}
			if (matchesCurrent)
				theApp.liveStreamManager->NotePlayerFetch();
		}
		static const char kAliveResp[] =
			"HTTP/1.1 200 OK\r\n"
			"Content-Type: application/json\r\n"
			"Content-Length: 16\r\n\r\n"
			"{\"success\":true}";
		Data.pSocket->SendData(kAliveResp, (int)strlen(kAliveResp));
		return;
	}

	// --- /api/live/broadcast/start --- Tier 2.2: web-driven broadcast launch.
	// Lets the user start a stream from the browser without ever opening the
	// MFC "Live" tab. Source: testpattern (default), screen, file, rtmp.
	// Example: GET /api/live/broadcast/start?source=testpattern&title=Mi+Canal&bitrate=1500
	// (Use Left() match so query string doesn't break the route.)
	if (Data.webRoute == ese::web::WebRouteId::ApiLiveBroadcastStart) {
		CString sourceT(_ParseURL(Data.sURL, _T("source")));
		CString titleT (_ParseURL(Data.sURL, _T("title")));
		CString catT   (_ParseURL(Data.sURL, _T("category")));
		CString langT  (_ParseURL(Data.sURL, _T("language")));
		CString brT    (_ParseURL(Data.sURL, _T("bitrate")));
		CString fileT  (_ParseURL(Data.sURL, _T("file")));

		if (sourceT.IsEmpty()) sourceT = _T("testpattern");
		if (titleT.IsEmpty())  titleT  = _T("eSE Live");
		if (catT.IsEmpty())    catT    = _T("General");
		if (langT.IsEmpty())   langT   = _T("Spanish");
		uint16 bitrate = (uint16)_ttoi(brT);
		if (bitrate == 0) bitrate = 1500;

		// The launch (FFmpeg + Kad publish) is main-thread only — marshal it.
		// The ~14 s prebuffer wait then runs HERE on this worker thread; it
		// polls a lock-correct liveness status, so the main thread never blocks.
		bool ok = false;
		bool ready = false;
		bool waitingInput = false;
		int finalChunks = 0;
		if (theApp.liveStreamManager != NULL && theApp.emuledlg != NULL) {
			LiveWebBroadcastReq req;
			req.action        = LIVE_WEB_BC_LAUNCH;
			req.sourceType    = sourceT;
			req.title         = titleT;
			req.category      = catT;
			req.language      = langT;
			req.mediaFilePath = fileT;
			req.bitrate       = bitrate;
			req.ok            = false;
			theApp.emuledlg->SendMessage(UM_LIVE_WEB_BROADCAST, 0, (LPARAM)&req);
			ok = req.ok;
			if (ok) {
				const bool isRtmpInput = sourceT.CompareNoCase(_T("rtmp")) == 0;
				const DWORD maxWaitMs = isRtmpInput ? 1500 : 14000;
				DWORD t0 = GetTickCount();
				for (;;) {
					bool alive = false;
					int  chunks = 0;
					theApp.liveStreamManager->GetBroadcastLivenessStatus(alive, chunks);
					finalChunks = chunks;
					if (!alive) {
						// FFmpeg died early — abort; marshal the stop.
						LiveWebBroadcastReq stopReq;
						stopReq.action        = LIVE_WEB_BC_STOP;
						stopReq.sourceType    = _T("");
						stopReq.title         = _T("");
						stopReq.category      = _T("");
						stopReq.language      = _T("");
						stopReq.mediaFilePath = _T("");
						stopReq.bitrate       = 0;
						stopReq.ok            = false;
						theApp.emuledlg->SendMessage(UM_LIVE_WEB_BROADCAST, 0, (LPARAM)&stopReq);
						ok = false;
						break;
					}
					if (chunks >= 3) {
						ready = true;
						break;
					}
					if (GetTickCount() - t0 >= maxWaitMs) {
						if (isRtmpInput) {
							waitingInput = true;
						} else {
							// FFmpeg stayed alive but never produced a playable
							// prebuffer. Roll the armed broadcast back instead of
							// returning a false success to the dashboard.
							LiveWebBroadcastReq stopReq;
							stopReq.action        = LIVE_WEB_BC_STOP;
							stopReq.sourceType    = _T("");
							stopReq.title         = _T("");
							stopReq.category      = _T("");
							stopReq.language      = _T("");
							stopReq.mediaFilePath = _T("");
							stopReq.bitrate       = 0;
							stopReq.ok            = false;
							theApp.emuledlg->SendMessage(UM_LIVE_WEB_BROADCAST, 0, (LPARAM)&stopReq);
							ok = false;
						}
						break;
					}
					Sleep(100);
				}
			}
		}

		// Build the share link if broadcast started + we know our IP.
		CStringA linkA;
		if (ok) {
			uchar key[16];
			uint32 pubIP = theApp.GetPublicIP();
			uint16 port  = theApp.GetAdvertisedTcpPort();
			if (theApp.liveStreamManager->CopyBroadcastStreamKey(key)) {
				CStringA hex = EseHexKey16A(key);
				CString titleEnc = EncodeURLQueryParam(titleT);

				// 17 May 2026 — anonymous is now the DEFAULT for share links.
				// Both variants are still emitted in the JSON so any caller can
				// pick. The `link` field returns:
				//   - link_anonymous by default (privacy first; viewer does a
				//     Kad lookup to resolve broadcaster IP at click time)
				//   - link_direct only if ?direct=1 was passed (LAN-only, no
				//     Kad, faster but leaks IP into the URL string)
				// ?anon=1 still honored for backward compat (no-op since it's
				// now the default).
				CStringA linkAnon, linkDirect;
				linkAnon.Format("ed2k://|live|%s||%s|/",
					(LPCSTR)hex, (LPCSTR)CT2A(titleEnc));
				if (pubIP != 0 && port != 0) {
					linkDirect.Format("ed2k://|live|%s|%s:%u|%s|/",
						(LPCSTR)hex, (LPCSTR)CT2A(ipstr(pubIP)), port,
						(LPCSTR)CT2A(titleEnc));
				}
				CString directT(_ParseURL(Data.sURL, _T("direct")));
				bool wantDirect = (directT == _T("1") || directT.CompareNoCase(_T("true")) == 0);
				linkA = (wantDirect && !linkDirect.IsEmpty()) ? linkDirect : linkAnon;
				CStringA sourceJson = EseJsonEscapeA(CStringA(CT2A(sourceT)));
				CStringA linkJson = EseJsonEscapeA(linkA);
				CStringA linkAnonJson = EseJsonEscapeA(linkAnon);
				CStringA linkDirectJson = EseJsonEscapeA(linkDirect.IsEmpty() ? linkAnon : linkDirect);
				const char* state = ready ? "ready" : (waitingInput ? "waiting_input" : "failed");

				// Both variants get exposed in the JSON so a smart caller
				// can show a "switch to anonymous" toggle to its user.
				CStringA jsonLinks;
				jsonLinks.Format(
					"{\"success\":%s,\"ready\":%s,\"state\":\"%s\",\"chunks\":%d,"
					"\"source\":\"%s\",\"bitrate\":%u,"
					"\"link\":\"%s\",\"link_anonymous\":\"%s\",\"link_direct\":\"%s\"}",
					ok ? "true" : "false",
					ready ? "true" : "false", state, finalChunks,
					(LPCSTR)sourceJson, (unsigned)bitrate,
					(LPCSTR)linkJson, (LPCSTR)linkAnonJson,
					(LPCSTR)linkDirectJson);

				CStringA header;
				header.Format(
					"HTTP/1.1 %s\r\n"
					"Content-Type: application/json\r\n"
					"Access-Control-Allow-Origin: http://127.0.0.1\r\n"
					"X-Content-Type-Options: nosniff\r\n"
					"Content-Length: %d\r\n\r\n",
					ok ? "200 OK" : "400 Bad Request",
					jsonLinks.GetLength());
				Data.pSocket->SendData(header, header.GetLength());
				Data.pSocket->SendData(jsonLinks, jsonLinks.GetLength());
				return;
			}
		}

		CStringA json;
		CStringA sourceJson = EseJsonEscapeA(CStringA(CT2A(sourceT)));
		CStringA linkJson = EseJsonEscapeA(linkA);
		const char* state = ready ? "ready" : (waitingInput ? "waiting_input" : "failed");
		json.Format(
			"{\"success\":%s,\"ready\":%s,\"state\":\"%s\",\"chunks\":%d,"
			"\"source\":\"%s\",\"bitrate\":%u,\"link\":\"%s\"}",
			ok ? "true" : "false",
			ready ? "true" : "false", state, finalChunks,
			(LPCSTR)sourceJson, (unsigned)bitrate,
			(LPCSTR)linkJson);
		CStringA header;
		header.Format(
			"HTTP/1.1 %s\r\n"
			"Content-Type: application/json\r\n"
			"Access-Control-Allow-Origin: http://127.0.0.1\r\n"
			"X-Content-Type-Options: nosniff\r\n"
			"Content-Length: %d\r\n\r\n",
			ok ? "200 OK" : "400 Bad Request",
			json.GetLength());
		Data.pSocket->SendData(header, header.GetLength());
		Data.pSocket->SendData(json, json.GetLength());
		return;
	}

	// --- /api/live/broadcast/stop --- Tier 2.2: stop FFmpeg + Kad publish.
	if (Data.webRoute == ese::web::WebRouteId::ApiLiveBroadcastStop) {
		// Stop touches FFmpeg + sends OP_LIVE_END to peers over eD2K sockets —
		// main-thread only. Marshal it.
		bool wasBroadcasting = false;
		if (theApp.liveStreamManager != NULL && theApp.emuledlg != NULL) {
			LiveWebBroadcastReq req;
			req.action        = LIVE_WEB_BC_STOP;
			req.sourceType    = _T("");
			req.title         = _T("");
			req.category      = _T("");
			req.language      = _T("");
			req.mediaFilePath = _T("");
			req.bitrate       = 0;
			req.ok            = false;
			theApp.emuledlg->SendMessage(UM_LIVE_WEB_BROADCAST, 0, (LPARAM)&req);
			wasBroadcasting = req.ok;
		}

		CStringA json;
		json.Format("{\"success\":true,\"was_broadcasting\":%s}",
			wasBroadcasting ? "true" : "false");
		CStringA header;
		header.Format(
			"HTTP/1.1 200 OK\r\n"
			"Content-Type: application/json\r\n"
			"Access-Control-Allow-Origin: http://127.0.0.1\r\n"
			"Content-Length: %d\r\n\r\n",
			json.GetLength());
		Data.pSocket->SendData(header, header.GetLength());
		Data.pSocket->SendData(json, json.GetLength());
		return;
	}

	// --- /hls/<file> --- Sprint 5: serve HLS files directly from C++ WebServer.
	// Mirrors what Node.js channel_api.js does at port 8080. Lets the dashboard
	// (and any HLS player like VLC) work even when ese-server.exe is absent.
	if (Data.webRoute == ese::web::WebRouteId::LegacyHls) {
		CStringA req = sURL.Mid(5);
		// Strip query string
		int q = req.Find('?'); if (q >= 0) req = req.Left(q);
		// WebRouteTable has already validated the safe leaf and extension.
		// Ghost-viewer watchdog: any whitelisted HLS fetch proves a player is
		// alive — including 404 polls while the playlist isn't written yet.
		TCHAR tmp[MAX_PATH]; GetTempPath(MAX_PATH, tmp);
		CString fp;
		fp.Format(_T("%seMule_RTMP\\%hs"), tmp, (LPCSTR)req);
		// Viewers reconstruct HLS into a per-stream subdirectory so concurrent
		// streams cannot collide. Keep the legacy /hls/<file> URL working by
		// falling back to the active stream namespace when the root file is not
		// present. Broadcasters still take the root fast path above.
		if (!PathFileExists(fp) && theApp.liveStreamManager != NULL) {
			uchar key[16];
			if (theApp.liveStreamManager->CopyViewerStreamKey(key)) {
				CStringA keyHex = EseHexKey16A(key);
				fp.Format(_T("%seMule_RTMP\\%hs\\%hs"), tmp,
					(LPCSTR)keyHex, (LPCSTR)req);
				// A validated viewer-namespace poll proves that the remote
				// player is alive, even while its first playlist is a 404.
				theApp.liveStreamManager->NotePlayerFetch();
			}
		}
		ese::web::WebFileResponseOptions hlsOptions;
		hlsOptions.corsOrigin = "*";
		Data.pSocket->SendFileResponse(
			fp,
			req,
			Data.sRange,
			hlsOptions,
			20ull * 1024ull * 1024ull,
			true,
			false);
		return;
	}

	// --- /dashboard --- Sprint 5: minimal embedded dashboard (no Node.js needed).
	// Self-contained HTML page that talks to the C++ WebServer endpoints we
	// already expose. Lets the user broadcast + diagnose without ese-server.exe.
	// For the full polished experience, the Node.js dashboard at :8080 is still
	// preferred — but this guarantees emule.exe alone is functional.
	// Only catches /dashboard explicitly — leaves "/" and other paths to the
	// classic eMule WebServer pages so we don't shadow the legacy UI.
	if (Data.webRoute == ese::web::WebRouteId::Dashboard) {
		const char* dashHtml =
"<!DOCTYPE html><html lang=es><head><meta charset=utf-8><title>eSE Live (mini)</title>"
"<style>body{background:#0a0a0e;color:#e2e8f0;font-family:system-ui;margin:0;padding:20px;max-width:900px;margin:auto}"
"h1{color:#fff}.box{background:#13141a;border:1px solid #2a2a2e;border-radius:8px;padding:16px;margin:14px 0}"
"button{background:#4f46e5;color:#fff;border:0;padding:8px 16px;border-radius:6px;cursor:pointer;font-weight:700;font-size:13px}"
"button.stop{background:#dc2626}button.warn{background:#f59e0b}"
"input{background:#0e0e10;border:1px solid #2a2a2e;color:#ddd;padding:8px;border-radius:5px;font-family:monospace;font-size:12px}"
"input.wide{width:100%}.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:8px 0}"
".pf{display:flex;gap:14px;flex-wrap:wrap;font-size:13px}.pf>div{padding:4px 0}"
".ok{color:#10b981}.err{color:#ef4444}.warn-c{color:#f59e0b}"
"a{color:#818cf8}code{background:#0e0e10;padding:2px 6px;border-radius:3px;font-size:90%}"
"#log{font-family:monospace;font-size:11px;color:#94a3b8;background:#0e0e10;padding:8px;border-radius:5px;max-height:140px;overflow-y:auto;white-space:pre-wrap}"
"</style></head><body>"
"<h1>🎬 eSE Live <span style=font-size:13px;color:#6b7280>mini dashboard (sin Node.js)</span></h1>"
"<p style=font-size:13px;color:#9ca3af>Esta es la versión embebida en <code>emule.exe</code>. Para la experiencia completa abre <a href=http://localhost:8080/live>http://localhost:8080/live</a> (requiere ese-server.exe).</p>"
"<div class=box><h3 style=margin-top:0>🔍 Pre-flight</h3><div class=pf id=pf>cargando...</div></div>"
"<div class=box><h3 style=margin-top:0>NetLab beta</h3><div id=nl-state style=font-size:12px;color:#94a3b8>cargando...</div>"
"<div class=row><button id=nl-toggle class=warn>Desactivar todo</button><button id=nl-copy>Copiar informe saneado</button></div></div>"
"<div class=box><h3 style=margin-top:0>🎬 Emisión</h3>"
"<div class=row><label>Título: <input id=br-title placeholder='Mi Stream' value='eSE Demo'></label>"
"<select id=br-source style=padding:8px;background:#0e0e10;color:#ddd;border:1px solid #2a2a2e;border-radius:5px>"
"<option value=testpattern>Test Pattern</option><option value=screen>Screen Capture</option><option value=rtmp>OBS (RTMP)</option></select>"
"<select id=br-bitrate style=padding:8px;background:#0e0e10;color:#ddd;border:1px solid #2a2a2e;border-radius:5px>"
"<option>1500</option><option selected>3000</option><option>5000</option></select>"
"<button id=br-start>▶ START</button><button id=br-stop class=stop>■ STOP</button></div>"
"<div id=br-status style=font-size:12px;color:#94a3b8;margin-top:8px>Inactivo.</div>"
"<div id=br-link style=margin-top:8px;display:none><b>Link:</b> <input id=br-link-input class=wide readonly></div>"
"</div>"
"<div class=box><h3 style=margin-top:0>👁 Ver stream</h3>"
"<div class=row><input id=join-link class=wide placeholder='ed2k://|live|HEX|IP:PUERTO|TITULO|/'><button id=join-btn>Conectar</button></div>"
"<div id=join-msg style=font-size:12px;color:#94a3b8;margin-top:8px></div>"
"<div class=row><a href=/hls/stream.m3u8 style=font-size:12px>📺 Abrir HLS directo (VLC)</a></div>"
"</div>"
"<div class=box><h3 style=margin-top:0>📊 Estado en vivo</h3><div id=mon style=font-size:12px;font-family:monospace>—</div></div>"
"<div class=box><h3 style=margin-top:0>📜 Log</h3><div id=log></div></div>"
"<p style=text-align:center;margin-top:24px;font-size:11px;color:#6b7280>"
"<a href=/api/status>/api/status</a> · <a href=/api/live/debug>/api/live/debug</a> · <a href=/api/live/preflight>/api/live/preflight</a>"
"</p>"
"<script>"
"function L(t){var l=document.getElementById('log');l.textContent+=new Date().toLocaleTimeString()+' '+t+'\\n';l.scrollTop=l.scrollHeight;}"
"function PF(){fetch('/api/live/preflight').then(function(r){return r.json();}).then(function(d){var p=document.getElementById('pf');var f=function(ok,t){var c=ok===true?'ok':(ok==='checking'?'warn-c':'err');var i=ok===true?'✅':(ok==='checking'?'⏳':'❌');return '<div class='+c+'>'+i+' '+t+'</div>';};p.innerHTML=f(d.kad_connected,'Kad')+f(d.high_id?true:(d.firewall_checking?'checking':false),d.high_id?'HighID':(d.firewall_checking?'NAT…':'LowID'))+f(d.ffmpeg_found,'FFmpeg')+f(!!d.public_ip,'IP '+(d.public_ip||'?')+':'+d.port);}).catch(function(){});}"
"function MON(){fetch('/api/live/debug').then(function(r){return r.json();}).then(function(d){var m=document.getElementById('mon');if(!d){m.textContent='-';return;}m.innerHTML='broadcasting='+d.broadcasting+' viewing='+d.viewing+'<br>buffer='+(d.chunks?d.chunks.count+' segs ['+d.chunks.oldestSeq+'..'+d.chunks.newestSeq+']':'')+'<br>peers: view='+(d.peers?d.peers.viewPeers:0)+' broadcast='+(d.peers?d.peers.broadcastPeers:0)+' mesh='+(d.peers?d.peers.meshPeers:0)+'<br>kad: '+(d.discovery?'connected='+d.discovery.kadConnected+' streams='+d.discovery.knownStreams:'?');}).catch(function(){});}"
"function NL(){fetch('/api/ese/v9').then(function(r){return r.json();}).then(function(d){var n=d.netlab||{};var i=n.independent||{};var s=document.getElementById('nl-state');s.dataset.on=n.enabled?'1':'0';s.textContent='Laboratorio: '+(n.enabled?'ACTIVO':'OFF')+' | base '+(n.consent||'?')+' | avanzado '+(n.advanced_consent||'?')+' | contribucion '+(n.contribution_consent||'?')+' | Punch3 '+((n.staged||{}).ed2k_punch3?'ON':'OFF')+' | KRP '+(i.krp?'ON':'OFF')+' | Kad6 Beta Exit '+(i.kad6_beta_exit?'ON':'OFF');var b=document.getElementById('nl-toggle');b.disabled=n.consent!=='accepted';b.textContent=n.enabled?'Desactivar todo':'Reactivar niveles aceptados';b.className=n.enabled?'stop':'warn';}).catch(function(){});}"
"PF();MON();NL();setInterval(PF,8000);setInterval(MON,2000);setInterval(NL,5000);"
"document.getElementById('nl-toggle').onclick=function(){var on=document.getElementById('nl-state').dataset.on==='1'?'0':'1';fetch('/api/ese/v9?on='+on).then(function(){NL();});};"
"document.getElementById('nl-copy').onclick=function(){fetch('/api/ese/netlab/report').then(function(r){return r.text();}).then(function(t){if(navigator.clipboard&&navigator.clipboard.writeText){return navigator.clipboard.writeText(t);}var x=document.createElement('textarea');x.value=t;document.body.appendChild(x);x.select();document.execCommand('copy');x.remove();}).then(function(){L('Informe NetLab saneado copiado');}).catch(function(){L('No se pudo copiar el informe');});};"
"document.getElementById('br-start').onclick=function(){var t=encodeURIComponent(document.getElementById('br-title').value||'eSE');var s=document.getElementById('br-source').value;var b=document.getElementById('br-bitrate').value;L('Iniciando broadcast '+s+' '+b+'k…');fetch('/api/live/broadcast/start?source='+s+'&title='+t+'&bitrate='+b).then(function(r){return r.json();}).then(function(d){if(d.success){document.getElementById('br-status').textContent='✅ Emitiendo: '+d.source+' @ '+d.bitrate+' kbps';if(d.link){document.getElementById('br-link').style.display='';document.getElementById('br-link-input').value=d.link;}L('OK link='+d.link);}else{document.getElementById('br-status').textContent='❌ '+(d.error||'fallo');L('FAIL '+d.error);}});};"
"document.getElementById('br-stop').onclick=function(){fetch('/api/live/broadcast/stop').then(function(r){return r.json();}).then(function(d){document.getElementById('br-status').textContent='Detenido';document.getElementById('br-link').style.display='none';L('Stopped');});};"
"document.getElementById('join-btn').onclick=function(){var l=document.getElementById('join-link').value.trim();if(!l){return;}L('Joining '+l);fetch('/api/live/direct_join?link='+encodeURIComponent(l)).then(function(r){return r.json();}).then(function(d){var m=document.getElementById('join-msg');if(d.success){m.innerHTML='✅ Conectado a '+d.ip+':'+d.port+'. <a href=/hls/stream.m3u8>Abre el HLS</a>';m.className='ok';L('Joined');}else{m.textContent='❌ '+(d.error||'fallo');m.className='err';}});};"
"</script></body></html>";
		size_t bodyLen = strlen(dashHtml);
		CStringA hdr;
		hdr.Format(
			"HTTP/1.1 200 OK\r\n"
			"Content-Type: text/html; charset=utf-8\r\n"
			"Content-Length: %zu\r\n"
			"Cache-Control: no-cache\r\n\r\n",
			bodyLen);
		Data.pSocket->SendData(hdr, hdr.GetLength());
		Data.pSocket->SendData(dashHtml, (int)bodyLen);
		return;
	}

	// --- /api/holepunch/test --- Manual hole-punch trigger for diagnostics.
	// Lets the user fire a HOLEPUNCH_REQ at a known LowID peer's Kad endpoint
	// to verify the uTP NAT traversal works between two specific networks
	// (e.g. office ↔ home). Returns immediately with the attempt counters;
	// success is observed indirectly by polling /api/status afterward.
	//
	// Usage: GET /api/holepunch/test?ip=1.2.3.4&udp_port=4672
	//
	// SAFETY: rate-limited to 1 manual fire per 5 s to avoid being mistaken
	// for a Sybil attack on the target.
	// --- /api/holepunch/rdv_test --- Manual R.1 (3-way rendezvous) trigger.
	// A fires a HOLEPUNCH_REQ(0x68) at rendezvous R asking it to relay toward B.
	// Usage: GET /api/holepunch/rdv_test?target_ip=B&target_udp_port=4672&rdv_ip=R&rdv_udp_port=4672
	// Observe kad3_rdv_* in /api/status on A, R and B. Rate-limited 1 fire / 5 s.
	if (Data.webRoute == ese::web::WebRouteId::ApiHolePunchRendezvousTest) {
		const ese::web::WebRateDecision rendezvousRate =
			pThis->m_authPolicy.CheckRateLimit(
				ese::web::WebAction::ManualRendezvous, WebAuthNowMs(), 5000);
		if (!rendezvousRate.allowed) {
			CStringA json = "{\"success\":false,\"error\":\"rate_limited\",\"retry_after_ms\":";
			CStringA n; n.Format("%I64u}", rendezvousRate.retry_after_ms);
			json += n;
			CStringA hdr;
			hdr.Format("HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n", json.GetLength());
			Data.pSocket->SendData(hdr, hdr.GetLength());
			Data.pSocket->SendData(json, json.GetLength());
			return;
		}

		CStringA tIpA = CT2A(_ParseURL(Data.sURL, _T("target_ip")));
		CStringA rIpA = CT2A(_ParseURL(Data.sURL, _T("rdv_ip")));
		uint32 tIpNet = (uint32)inet_addr((LPCSTR)tIpA);
		uint16 tPort  = (uint16)_ttoi(_ParseURL(Data.sURL, _T("target_udp_port")));
		uint32 rIpNet = (uint32)inet_addr((LPCSTR)rIpA);
		uint16 rPort  = (uint16)_ttoi(_ParseURL(Data.sURL, _T("rdv_udp_port")));

		bool ok = false;
		const char* errCode = "ok";
		if (tIpNet == INADDR_NONE || tIpNet == 0 || tPort == 0 || rIpNet == INADDR_NONE || rIpNet == 0 || rPort == 0) {
			errCode = "invalid_ip_port";
		} else if (!Kademlia::CKademlia::IsConnected() || Kademlia::CKademlia::GetUDPListener() == NULL) {
			errCode = "kad_not_ready";
		} else if (!thePrefs.GetUtpHolePunchEnabled()) {
			errCode = "holepunch_disabled";
		} else if (!thePrefs.GetEseKad3Rendezvous()) {
			errCode = "rendezvous_disabled";
		} else {
			// InitiateKad3Rendezvous wants host-order IP/port (Kad convention).
			Kademlia::CKademlia::GetUDPListener()->InitiateKad3Rendezvous(ntohl(rIpNet), rPort, ntohl(tIpNet), tPort);
			ok = true;
		}

		CStringA json;
		json.Format(
			"{\"success\":%s,\"error\":\"%s\","
			"\"kad3_rdv\":{\"req_sent\":%u,\"req_recv\":%u,\"challenge_sent\":%u,\"fwd\":%u,\"rdv_success\":%u}}",
			ok ? "true" : "false", errCode,
			(unsigned)CStatistics::m_dwKad3RdvReqSent,
			(unsigned)CStatistics::m_dwKad3RdvReqRecv,
			(unsigned)CStatistics::m_dwKad3RdvChallengeSent,
			(unsigned)CStatistics::m_dwKad3RdvFwd,
			(unsigned)CStatistics::m_dwKad3RdvSuccess);
		CStringA hdr;
		hdr.Format(
			"HTTP/1.1 %s\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: http://127.0.0.1\r\nX-Content-Type-Options: nosniff\r\nContent-Length: %d\r\n\r\n",
			ok ? "200 OK" : "400 Bad Request", json.GetLength());
		Data.pSocket->SendData(hdr, hdr.GetLength());
		Data.pSocket->SendData(json, json.GetLength());
		return;
	}

	// --- /api/keepalive/{start|stop} --- Manual R.2 (Kad keepalive / pinhole) control.
	// start: RequestStart() flips a cross-thread flag; the Kad thread then self-populates
	// the supernode pool from the routing table and pings each every 25 s (PING_REQ 0x66),
	// each answered with a PONG (0x67) that refreshes the pinhole. Observe keepalive_* in
	// /api/status afterward. RequestStart/Stop are atomic (InterlockedExchange), so they
	// are safe to call from this webserver worker thread (no Kad/Live state touched here).
	if (Data.webRoute == ese::web::WebRouteId::ApiKeepaliveStart ||
		Data.webRoute == ese::web::WebRouteId::ApiKeepaliveStop) {
		const bool bStart =
			Data.webRoute == ese::web::WebRouteId::ApiKeepaliveStart;
		const bool bStop =
			Data.webRoute == ese::web::WebRouteId::ApiKeepaliveStop;
		// Throttle state-toggles: a rapid start/stop loop spams the Kad log and re-scans
		// the routing table. 2 s is invisible to manual testing but kills a toggle flood.
		const ese::web::WebRateDecision keepaliveRate =
			(bStart || bStop)
			? pThis->m_authPolicy.CheckRateLimit(
				ese::web::WebAction::KeepaliveToggle, WebAuthNowMs(), 2000)
			: ese::web::WebRateDecision{true, 0};
		if (!keepaliveRate.allowed) {
			CStringA json = "{\"success\":false,\"error\":\"rate_limited\",\"retry_after_ms\":";
			CStringA n; n.Format("%I64u}", keepaliveRate.retry_after_ms);
			json += n;
			CStringA hdr;
			hdr.Format("HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n", json.GetLength());
			Data.pSocket->SendData(hdr, hdr.GetLength());
			Data.pSocket->SendData(json, json.GetLength());
			return;
		}
		const char* errCode = "ok";
		bool ok = true;
		if (bStart && !thePrefs.IsEseNetLabActive()) {
			ok = false;
			errCode = "netlab_consent_required";
		}
		else if (bStart) { CKadKeepalive::Instance().RequestStart(); }
		else if (bStop)  { CKadKeepalive::Instance().RequestStop(); }
		else { ok = false; errCode = "unknown_action"; }

		CKadKeepalive::Stats ks = CKadKeepalive::Instance().GetStats();
		CStringA json;
		json.Format(
			"{\"success\":%s,\"error\":\"%s\",\"requested\":\"%s\","
			"\"keepalive\":{\"running\":%s,\"pings_sent\":%u,\"pongs_recv\":%u,\"supernodes\":%u}}",
			ok ? "true" : "false", errCode,
			bStart ? "start" : (bStop ? "stop" : "none"),
			CKadKeepalive::Instance().IsRunning() ? "true" : "false",
			(unsigned)ks.pingsSent, (unsigned)ks.pongsReceived, (unsigned)ks.supernodesActive);
		CStringA hdr;
		hdr.Format(
			"HTTP/1.1 %s\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: http://127.0.0.1\r\nX-Content-Type-Options: nosniff\r\nContent-Length: %d\r\n\r\n",
			ok ? "200 OK" : "400 Bad Request", json.GetLength());
		Data.pSocket->SendData(hdr, hdr.GetLength());
		Data.pSocket->SendData(json, json.GetLength());
		return;
	}

	// --- /api/ese/v9[?on=0|1] --- NetLab status + immediate cohort kill switch.
	// A GET without "on" is read-only. Enabling restores only levels already
	// accepted in the native notices. "on=0" atomically closes every lab level.
	if (Data.webRoute == ese::web::WebRouteId::ApiEseV9) {
		const CString onArg = _ParseURL(Data.sURL, _T("on"));
		bool ok = true;
		bool changed = false;
		const char* error = "";
		if (!onArg.IsEmpty()) {
			changed = true;
			if (onArg == _T("0")) {
				thePrefs.ApplyEseNetLabPreferenceState(false);
				RefreshEseV9PreviewCaps();
				CKadKeepalive::Instance().RequestStop();
				// The stable Kad6 public-exit gate is an independent operator
				// choice, not a NetLab level. Revocation closes beta exit via
				// ApplyEseNetLabPreferenceState(false) and leaves stable Kad6
				// untouched.
			} else if (onArg == _T("1")) {
				if (thePrefs.GetEseNetLabConsent() != CPreferences::EseNetLabAccepted) {
					ok = false;
					error = "explicit_consent_required";
				} else {
					thePrefs.ApplyEseNetLabPreferenceState(true);
					RefreshEseV9PreviewCaps();
					CKadKeepalive::Instance().RequestStart();
				}
			} else {
				ok = false;
				error = "invalid_on_value";
			}
			// A cohort kill switch must survive a crash or forced restart, not
			// merely the next graceful OnClose. Persist the single master gate
			// before replying. Startup normalizes every derived NetLab flag from
			// this value, so a crash after this write still restarts fail-closed.
			// Avoid the full Save() path on revocation: it serializes unrelated
			// preferences and statistics and can make an emergency stop miss its
			// bounded response time. Reactivation still persists the complete
			// accepted state.
			if (ok && onArg == _T("0")) {
				CIni ini(CPreferences::GetConfigFile(), _T("eMule"));
				ini.WriteBool(_T("EseNetLabEnabled"), false, _T("eSE"));
				if (ini.GetBool(_T("EseNetLabEnabled"), true, _T("eSE"))) {
					ok = false;
					error = "persist_failed";
				}
			} else if (ok && CPreferences::Save()) {
				ok = false;
				error = "persist_failed";
			}
			if (theApp.emuledlg != NULL
				&& ::IsWindow(theApp.emuledlg->GetSafeHwnd()))
				::PostMessage(theApp.emuledlg->GetSafeHwnd(),
					UM_KRP_CLIENT_EVENT, 0, 0);
		}
		const char* consent =
			thePrefs.GetEseNetLabConsent() == CPreferences::EseNetLabAccepted ? "accepted" :
			thePrefs.GetEseNetLabConsent() == CPreferences::EseNetLabDeclined ? "declined" : "undecided";
		const char* advancedConsent =
			thePrefs.GetEseNetLabAdvancedConsent() == CPreferences::EseNetLabAccepted ? "accepted" :
			thePrefs.GetEseNetLabAdvancedConsent() == CPreferences::EseNetLabDeclined ? "declined" : "undecided";
		const char* contributionConsent =
			thePrefs.GetEseNetLabContributionConsent() == CPreferences::EseNetLabAccepted ? "accepted" :
			thePrefs.GetEseNetLabContributionConsent() == CPreferences::EseNetLabDeclined ? "declined" : "undecided";
		CStringA json;
		json.Format("{\"success\":%s,\"changed\":%s,\"error\":\"%s\","
			"\"netlab\":{\"consent\":\"%s\",\"advanced_consent\":\"%s\","
			"\"contribution_consent\":\"%s\",\"enabled\":%s,\"capability_advertised\":%s,"
			"\"base\":{\"ipv6_auto\":%s,\"mappings\":true,\"hole_punch\":%s,\"auto_keepalive\":%s},"
			"\"staged\":{\"selector\":%s,\"port_predict\":%s,\"ed2k_punch3\":%s,\"kad3_rendezvous\":%s},"
			"\"independent\":{\"relay_accept\":%s,\"relay_egress\":%s,\"krp\":%s,"
			"\"kad6_beta_exit\":%s,\"kad6_stable_public_exit\":%s},"
			"\"keepalive_running\":%s},"
			"\"v9\":{\"experimental\":%s,"
			"\"port_predict\":%s,\"ed2k_punch3\":%s,\"kad3_rendezvous\":%s,"
			"\"keepalive_running\":%s,\"hole_punch_master\":%s},"
			"\"reach_connects\":{\"direct\":%u,\"punch2\":%u,\"punch3\":%u,\"relay\":%u}}",
			ok ? "true" : "false",
			changed ? "true" : "false",
			error,
			consent,
			advancedConsent,
			contributionConsent,
			thePrefs.IsEseNetLabActive() ? "true" : "false",
			(g_uEseCapsRuntime & ESE_CAP_NETLAB_V1) != 0 ? "true" : "false",
			thePrefs.IsIPv6Enabled() ? "true" : "false",
			thePrefs.GetUtpHolePunchEnabled() ? "true" : "false",
			thePrefs.GetEseAutoKeepalive() ? "true" : "false",
			thePrefs.GetEseReachSelector() ? "true" : "false",
			thePrefs.GetEseHolePunchPortPredict() ? "true" : "false",
			thePrefs.GetEseEd2kPunch3() ? "true" : "false",
			thePrefs.GetEseKad3Rendezvous() ? "true" : "false",
			thePrefs.GetEseRelayAccept() ? "true" : "false",
			thePrefs.GetEseRelayEgress() ? "true" : "false",
			thePrefs.GetKrpRelayEnabled() ? "true" : "false",
			thePrefs.GetKad6BetaExitOptIn() ? "true" : "false",
			thePrefs.GetKad6PublicExitOptIn() ? "true" : "false",
			CKadKeepalive::Instance().IsRunning() ? "true" : "false",
			thePrefs.GetEseV9Experimental() ? "true" : "false",
			thePrefs.GetEseHolePunchPortPredict() ? "true" : "false",
			thePrefs.GetEseEd2kPunch3() ? "true" : "false",
			thePrefs.GetEseKad3Rendezvous() ? "true" : "false",
			CKadKeepalive::Instance().IsRunning() ? "true" : "false",
			thePrefs.GetUtpHolePunchEnabled() ? "true" : "false",
			(unsigned)CStatistics::m_dwReachConnDirect, (unsigned)CStatistics::m_dwReachConnPunch2,
			(unsigned)CStatistics::m_dwReachConnPunch3, (unsigned)CStatistics::m_dwReachConnRelay);
		CStringA hdr;
		hdr.Format("HTTP/1.1 %s\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nAccess-Control-Allow-Origin: http://127.0.0.1\r\nX-Content-Type-Options: nosniff\r\nContent-Length: %d\r\n\r\n",
			ok ? "200 OK" : "409 Conflict", json.GetLength());
		Data.pSocket->SendData(hdr, hdr.GetLength());
		Data.pSocket->SendData(json, json.GetLength());
		return;
	}

	// Local, sanitized cohort report. It deliberately contains no address,
	// node ID, peer identifier, filename, stream key or central upload hook.
	if (Data.webRoute == ese::web::WebRouteId::ApiEseNetlabReport) {
		const CAddress v6 = CFirewallProberV6::Instance().GetDetectedV6IP();
		const bool hasV4 = theApp.GetPublicIP() != 0;
		const bool hasV6 = v6.GetType() == CAddress::IPv6 && v6.IsPublicIP();
		const char* natEstimate = !theApp.IsFirewalled() ? "open_or_mapped" :
			CStatistics::m_dwHolePunchSymNATFail != 0 ? "symmetric_or_cgnat_suspected" :
			"lowid_or_double_nat";
		const CKadKeepalive::Stats ka = CKadKeepalive::Instance().GetStats();
		const size_t utpConnected = CUtpSocket::GetConnectedSocketCount();
		const char* layer = CStatistics::m_dwKad3RdvReqSent != 0 ? "punch3" :
			CStatistics::m_dwHolePunchAttempts != 0 ? "punch2" :
			ka.pingsSent != 0 ? "keepalive" : hasV6 ? "ipv6" : "direct";
		const char* fallback = CStatistics::m_dwHolePunchSuccess != 0 ? "none" :
			CStatistics::m_dwHolePunchSymNATFail != 0 ? "punch_timeout_or_nat_mapping_changed" :
			!Kademlia::CKademlia::IsConnected() ? "kad_disconnected" : "not_observed";
		const CStringA version =
			EseJsonEscapeA(CStringA(CT2A(theApp.m_strCurVersionLong)));
		CStringA json;
		json.Format(
			"{\"schema\":\"ESE_NETLAB_REPORT_V1\",\"version\":\"%s\","
			"\"cohort\":{\"consent\":\"%s\",\"enabled\":%s},"
			"\"network\":{\"ipv4\":%s,\"ipv6\":%s,\"nat_estimated\":\"%s\"},"
			"\"last_layer_attempted\":\"%s\",\"fallback_reason\":\"%s\","
			"\"punch2\":{\"attempts\":%u,\"pinhole_confirmed\":%u,\"nat_failures\":%u,\"spray_extra_packets\":%u},"
			"\"punch3\":{\"requests\":%u,\"forwarded\":%u,\"signaling_success\":%u},"
			"\"keepalive\":{\"running\":%s,\"pings\":%u,\"pongs\":%u,\"peers\":%u},"
			"\"utp_connected\":%s,\"utp_connected_sockets\":%u,"
			"\"bytes\":{\"session_received\":%I64u,\"session_sent\":%I64u,\"relay_forwarded_kb\":%u},"
			"\"privacy\":{\"full_ip_stored\":false,\"central_telemetry\":false}}",
			(LPCSTR)version,
			thePrefs.GetEseNetLabConsent() == CPreferences::EseNetLabAccepted ? "accepted" :
				thePrefs.GetEseNetLabConsent() == CPreferences::EseNetLabDeclined ? "declined" : "undecided",
			thePrefs.IsEseNetLabActive() ? "true" : "false",
			hasV4 ? "true" : "false", hasV6 ? "true" : "false", natEstimate,
			layer, fallback,
			(unsigned)CStatistics::m_dwHolePunchAttempts,
			(unsigned)CStatistics::m_dwHolePunchSuccess,
			(unsigned)CStatistics::m_dwHolePunchSymNATFail,
			(unsigned)CStatistics::m_dwHolePunchSprayReqs,
			(unsigned)CStatistics::m_dwKad3RdvReqSent,
			(unsigned)CStatistics::m_dwKad3RdvFwd,
			(unsigned)CStatistics::m_dwKad3RdvSuccess,
			CKadKeepalive::Instance().IsRunning() ? "true" : "false",
			(unsigned)ka.pingsSent, (unsigned)ka.pongsReceived, (unsigned)ka.supernodesActive,
			utpConnected != 0 ? "true" : "false",
			(unsigned)utpConnected,
			(unsigned __int64)theStats.sessionReceivedBytes,
			(unsigned __int64)theStats.sessionSentBytes,
			(unsigned)CStatistics::m_dwRelayBytesFwdKB);
		CStringA hdr;
		hdr.Format("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nContent-Length: %d\r\n\r\n",
			json.GetLength());
		Data.pSocket->SendData(hdr, hdr.GetLength());
		Data.pSocket->SendData(json, json.GetLength());
		return;
	}

	// P3 KRP status is deliberately read-only and separate from /api/relay/*,
	// which belongs to the older Live/Buddy relay. The JSON is a mutex-protected
	// main-thread snapshot and contains no endpoint, certificate, identity or payload.
	if (Data.webRoute == ese::web::WebRouteId::ApiKrpStatus) {
		CStringA json;
		if (theApp.relayclient != NULL)
			theApp.relayclient->GetStatusJson(json);
		else
			json = "{\"enabled\":false,\"kill_switch\":false,\"display\":\"Low ID\",\"carrier\":\"Disabled\"}";
		CStringA hdr;
		hdr.Format(
			"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
			"Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n"
			"Content-Length: %d\r\n\r\n", json.GetLength());
		Data.pSocket->SendData(hdr, hdr.GetLength());
		Data.pSocket->SendData(json, json.GetLength());
		return;
	}

	// --- /api/relay/{accept|egress|selector|connect} --- R.3 relay floor + selector test/activation.
	//   accept?on=1   (relay buddy X): flip EseRelayAccept  — accept 0xCF SETUP + serve 0xCE viewers.
	//   egress?on=1   (broadcaster B): flip EseRelayEgress  — push my stream to a connected HighID buddy.
	//   selector?on=1 (viewer V):      flip EseReachSelector— Direct->punch2->punch3->relay escalation.
	//   connect?stream=<32hex>&buddy_ip=<X>&buddy_port=<P> (viewer V): subscribe to relay X via 0xCE.
	// Same prefs are loadable from emule.ini [eSE]; these flip them at runtime (no restart). on=0 turns off.
	if (Data.webRoute == ese::web::WebRouteId::ApiRelayAccept ||
		Data.webRoute == ese::web::WebRouteId::ApiRelayEgress ||
		Data.webRoute == ese::web::WebRouteId::ApiRelaySelector ||
		Data.webRoute == ese::web::WebRouteId::ApiRelayConnect) {
		const bool bOn = (_ParseURL(Data.sURL, _T("on")) != _T("0"));   // default ON unless on=0
		const char* action = "unknown";
		bool ok = true;
		if (Data.webRoute == ese::web::WebRouteId::ApiRelayAccept) {
			thePrefs.SetEseRelayAccept(bOn);
			volatile LONG* caps = reinterpret_cast<volatile LONG*>(&g_uEseCapsRuntime);
			if (bOn) ::InterlockedOr(caps, (LONG)ESE_CAP_LIVE_RELAY);
			else     ::InterlockedAnd(caps, ~(LONG)ESE_CAP_LIVE_RELAY);
			action = "accept";
		}
		else if (Data.webRoute == ese::web::WebRouteId::ApiRelayEgress)   { thePrefs.SetEseRelayEgress(bOn);   action = "egress"; }
		else if (Data.webRoute == ese::web::WebRouteId::ApiRelaySelector) { thePrefs.SetEseReachSelector(bOn); action = "selector"; }
		else if (Data.webRoute == ese::web::WebRouteId::ApiRelayConnect) {
			CStringA keyA = CT2A(_ParseURL(Data.sURL, _T("stream")));
			CStringA ipA  = CT2A(_ParseURL(Data.sURL, _T("buddy_ip")));
			uint16 port   = (uint16)_ttoi(_ParseURL(Data.sURL, _T("buddy_port")));
			uchar streamKey[16];
			uint32 ipNet = (uint32)inet_addr((LPCSTR)ipA);
			if (EseHexToKey16A(keyA, streamKey) && ipNet != INADDR_NONE && ipNet != 0 && port != 0) {
				CLiveBuddyRelay::Instance().RequestViewerConnect(streamKey, ipNet, port);
				action = "connect";
			} else { ok = false; action = "connect_bad_args"; }
		}
		else { ok = false; }
		CStringA json;
		json.Format("{\"success\":%s,\"action\":\"%s\",\"on\":%s,"
			"\"relay\":{\"accept\":%s,\"egress\":%s,\"selector\":%s,"
			"\"req_recv\":%u,\"accepted\":%u,\"active\":%u,\"bytes_fwd_kb\":%u,"
			"\"budget_drops\":%u,\"max_kbps\":%u},"
			"\"reach_connects\":{\"direct\":%u,\"punch2\":%u,\"punch3\":%u,\"relay\":%u}}",
			ok ? "true" : "false", action, bOn ? "true" : "false",
			thePrefs.GetEseRelayAccept() ? "true" : "false",
			thePrefs.GetEseRelayEgress() ? "true" : "false",
			thePrefs.GetEseReachSelector() ? "true" : "false",
			(unsigned)CStatistics::m_dwRelayReqRecv, (unsigned)CStatistics::m_dwRelayAccepted,
			(unsigned)CStatistics::m_dwRelayActive, (unsigned)CStatistics::m_dwRelayBytesFwdKB,
			(unsigned)CStatistics::m_dwRelayBudgetDrops, (unsigned)thePrefs.GetEseRelayMaxKBps(),
			(unsigned)CStatistics::m_dwReachConnDirect, (unsigned)CStatistics::m_dwReachConnPunch2,
			(unsigned)CStatistics::m_dwReachConnPunch3, (unsigned)CStatistics::m_dwReachConnRelay);
		CStringA hdr;
		hdr.Format("HTTP/1.1 %s\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: http://127.0.0.1\r\nX-Content-Type-Options: nosniff\r\nContent-Length: %d\r\n\r\n",
			ok ? "200 OK" : "400 Bad Request", json.GetLength());
		Data.pSocket->SendData(hdr, hdr.GetLength());
		Data.pSocket->SendData(json, json.GetLength());
		return;
	}

	if (Data.webRoute == ese::web::WebRouteId::ApiHolePunchTest) {
		const ese::web::WebRateDecision holePunchRate =
			pThis->m_authPolicy.CheckRateLimit(
				ese::web::WebAction::ManualHolePunch, WebAuthNowMs(), 5000);
		if (!holePunchRate.allowed) {
			CStringA json = "{\"success\":false,\"error\":\"rate_limited\",\"retry_after_ms\":";
			CStringA n;
			n.Format("%I64u}", holePunchRate.retry_after_ms);
			json += n;
			CStringA hdr;
			hdr.Format(
				"HTTP/1.1 429 Too Many Requests\r\n"
				"Content-Type: application/json\r\n"
				"Content-Length: %d\r\n\r\n",
				json.GetLength());
			Data.pSocket->SendData(hdr, hdr.GetLength());
			Data.pSocket->SendData(json, json.GetLength());
			return;
		}

		CString ipT  (_ParseURL(Data.sURL, _T("ip")));
		CString portT(_ParseURL(Data.sURL, _T("udp_port")));
		CStringA ipA = CT2A(ipT);
		const CStringA ipJson = EseJsonEscapeA(ipA);
		uint32 ipNet = (uint32)inet_addr((LPCSTR)ipA);
		uint16 udpPort = (uint16)_ttoi(portT);

		bool ok = false;
		const char* errCode = "ok";
		DWORD attemptsBefore = CStatistics::m_dwHolePunchAttempts;
		uint16 hpSpread = 0;   // [eSE v9] port-predict spread actually used (0 = single-shot); reported in JSON
		CUpDownClient* targetPeer = theApp.clientlist != NULL
			? theApp.clientlist->FindClientByIP_KadPort(ipNet, udpPort) : NULL;
		if (targetPeer == NULL && theApp.clientlist != NULL)
			targetPeer = theApp.clientlist->FindClientByIP(ipNet);

		if (ipNet == INADDR_NONE || ipNet == 0 || udpPort == 0) {
			errCode = "invalid_ip_port";
		} else if (!thePrefs.IsEseNetLabActive()) {
			errCode = "netlab_consent_required";
		} else if (targetPeer == NULL || !targetPeer->SupportsEseNetLabV1Target()) {
			errCode = "netlab_target_required";
		} else if (!Kademlia::CKademlia::IsConnected() || Kademlia::CKademlia::GetUDPListener() == NULL) {
			errCode = "kad_not_ready";
		} else if (!thePrefs.GetUtpHolePunchEnabled()) {
			errCode = "holepunch_disabled";
		} else if (theApp.clientudp == NULL || !theApp.clientudp->IsUtpReady()) {
			errCode = "utp_not_ready";
		} else {
			// SendEseHolePunchReq expects host-order IP, host-order port.
			// [eSE v9] optional ?spread=N (0-8) exercises anti-CGNAT port prediction straight
			// from the test endpoint without flipping the pref; empty/0 falls back to the
			// EseHolePunchPortPredict pref so normal test runs are unchanged.
			int spreadReq = _ttoi(_ParseURL(Data.sURL, _T("spread")));
			hpSpread = (spreadReq > 0)
				? (uint16)(spreadReq > 8 ? 8 : spreadReq)
				: (thePrefs.GetEseHolePunchPortPredict() ? (uint16)thePrefs.GetEseHolePunchPortSpread() : 0);
			Kademlia::CKademlia::GetUDPListener()->SendEseHolePunchReqSpray(
				ntohl(ipNet), udpPort, hpSpread, true, targetPeer);
			ok = true;
		}

		CStringA json;
		json.Format(
			"{\"success\":%s,\"error\":\"%s\","
			"\"target_ip\":\"%s\",\"target_udp_port\":%u,"
			"\"attempts_before\":%u,\"attempts_after\":%u,"
			"\"counters\":{"
			"\"attempts\":%u,\"success\":%u,\"sym_nat_fail\":%u,"
			"\"encrypted\":%u,\"plaintext\":%u,\"spray_reqs\":%u,"
			"\"req_recv\":%u,\"challenge_sent\":%u},"
			"\"port_predict\":{\"on\":%s,\"spread\":%u,\"used\":%u}}",
			ok ? "true" : "false",
			errCode,
			(LPCSTR)ipJson, (unsigned)udpPort,
			(unsigned)attemptsBefore, (unsigned)CStatistics::m_dwHolePunchAttempts,
			(unsigned)CStatistics::m_dwHolePunchAttempts,
			(unsigned)CStatistics::m_dwHolePunchSuccess,
			(unsigned)CStatistics::m_dwHolePunchSymNATFail,
			(unsigned)CStatistics::m_dwHolePunchEncrypted,
			(unsigned)CStatistics::m_dwHolePunchPlaintext,
			(unsigned)CStatistics::m_dwHolePunchSprayReqs,
			(unsigned)CStatistics::m_dwHolePunchReqRecv,
			(unsigned)CStatistics::m_dwHolePunchChallengeSent,
			thePrefs.GetEseHolePunchPortPredict() ? "true" : "false",
			(unsigned)thePrefs.GetEseHolePunchPortSpread(),
			(unsigned)hpSpread);
		CStringA hdr;
		hdr.Format(
			"HTTP/1.1 %s\r\n"
			"Content-Type: application/json\r\n"
			"Access-Control-Allow-Origin: http://127.0.0.1\r\n"
			"X-Content-Type-Options: nosniff\r\n"
			"Content-Length: %d\r\n\r\n",
			ok ? "200 OK" : "400 Bad Request",
			json.GetLength());
		Data.pSocket->SendData(hdr, hdr.GetLength());
		Data.pSocket->SendData(json, json.GetLength());
		return;
	}

	// --- /api/live/preflight --- Read-only health check before broadcasting.
	// Returns the four conditions that determine whether broadcasting will work:
	//   1. kad_connected   — your stream metadata can reach the DHT
	//   2. high_id         — viewers can open a TCP socket to your port
	//   3. upload_ok       — your max upload exceeds bitrate × 1.5 (per viewer)
	//   4. ffmpeg_found    — RTMPIngest can launch the encoder
	// The web UI uses this to gate the START button and explain failures.
	if (Data.webRoute == ese::web::WebRouteId::ApiLivePreflight) {
		bool kadConn = Kademlia::CKademlia::IsConnected();
		// Tier 1.5: differentiate between "firewall test completed and we ARE
		// firewalled" vs "test still running, don't know yet". This avoids
		// the pre-flight panel flashing a red ❌ during the first 30-90 s of
		// Kad's startup when the tester hasn't reported yet.
		bool fwVerified = Kademlia::CUDPFirewallTester::IsVerified();
		bool kadFw   = theApp.IsFirewalled();
		bool ed2kFw  = !theApp.HasVerifiedEd2kHighId();
		bool highId  = !ed2kFw;
		bool fwChecking = !fwVerified && kadConn && ed2kFw;  // still measuring
		uint32 maxUpKBs = thePrefs.GetMaxUpload();   // KB/s, 0 = unlimited
		uint16 port = theApp.GetAdvertisedTcpPort();
		uint32 pubIP = theApp.GetPublicIP();
		CString ffPath = CRTMPIngest::FindFFmpeg();
		bool ffmpegFound = (GetFileAttributes(ffPath) != INVALID_FILE_ATTRIBUTES);

		CStringA pubIpA;
		if (pubIP != 0)
			pubIpA = (LPCSTR)CT2A(ipstr(pubIP));
		else
			pubIpA = "";

		// v0.71 IPv6 — surface the in-band detected public v6 address
		// (OP_PUBLICIP_ANSWER_V6 / CFirewallProberV6) so the eSE web UI can show
		// and link it WITHOUT querying any third-party echo service. Empty until
		// a peer has observed and reported our v6 address.
		CStringA pubIp6A = "";
		try {
			CAddress v6 = CFirewallProberV6::Instance().GetDetectedV6IP();
			if (!v6.IsNull())
				pubIp6A = CStringA(v6.ToStringC());
		} catch (...) { /* a health endpoint must never throw */ }

		CStringA ffPathA = (LPCSTR)CT2A(ffPath);
		ffPathA = EseJsonEscapeA(ffPathA);

		CStringA json;
		json.Format(
			"{\"kad_connected\":%s,"
			"\"high_id\":%s,"
			"\"kad_firewalled\":%s,"
			"\"ed2k_lowid\":%s,"
			"\"firewall_checking\":%s,"
			"\"max_upload_kbs\":%u,"
			"\"port\":%u,"
			"\"public_ip\":\"%s\","
			"\"public_ip_v6\":\"%s\","
			"\"ffmpeg_found\":%s,"
			"\"ffmpeg_path\":\"%s\","
			"\"ready\":%s}",
			kadConn ? "true" : "false",
			highId ? "true" : "false",
			kadFw ? "true" : "false",
			ed2kFw ? "true" : "false",
			fwChecking ? "true" : "false",
			(unsigned)maxUpKBs, (unsigned)port,
			(LPCSTR)pubIpA,
			(LPCSTR)pubIp6A,
			ffmpegFound ? "true" : "false",
			(LPCSTR)ffPathA,
			(kadConn && highId && ffmpegFound) ? "true" : "false");

		CStringA header;
		header.Format(
			"HTTP/1.1 200 OK\r\n"
			HTTPInit
			"Content-Type: application/json\r\n"
			"Content-Length: %d\r\n\r\n",
			json.GetLength());
		Data.pSocket->SendData(header, header.GetLength());
		Data.pSocket->SendData(json, json.GetLength());
		return;
	}

	// --- /api/live/privacy/tunnel_ping?text=... --- v0.71 C — data plane demo.
	// Sends a TUN_OP_PING through any active circuit (1-hop or 2-hop).
	// The exit relay echoes back as TUN_OP_PING_REPLY with "echo:<text>".
	// This is the FIRST end-to-end demonstration of the data plane working
	// through the onion tunnel. If circuits exist but the reply doesn't
	// arrive within timeoutMs, returns ok:false with reason.
	// --- /api/live/privacy/subscriptions --- v0.71 P2.A — REST CRUD
	// over the DPAPI-encrypted subscriptions store. The full MFC dialog
	// is deferred; REST gives users (or external UI clients) immediate
	// access via curl to add/list/remove subscriptions.
	//   GET                       -> list current entries
	//   GET ?add=<32 hex>&name=N  -> add channel
	//   GET ?remove=<32 hex>      -> remove channel
	if (Data.webRoute == ese::web::WebRouteId::ApiLivePrivacySubscriptions) {
		const CString addArg = _ParseURL(Data.sURL, _T("add"));
		const CString rmArg  = _ParseURL(Data.sURL, _T("remove"));
		const CString nmArg  = _ParseURL(Data.sURL, _T("name"));
		auto hexToBytes = [](const CString& hex, uint8_t out[32]) -> bool {
			if (hex.GetLength() != 64) return false;
			for (int i = 0; i < 32; ++i) {
				int hi = -1, lo = -1;
				TCHAR a = hex[i*2], b = hex[i*2+1];
				if (a >= '0' && a <= '9') hi = a - '0';
				else if (a >= 'a' && a <= 'f') hi = a - 'a' + 10;
				else if (a >= 'A' && a <= 'F') hi = a - 'A' + 10;
				if (b >= '0' && b <= '9') lo = b - '0';
				else if (b >= 'a' && b <= 'f') lo = b - 'a' + 10;
				else if (b >= 'A' && b <= 'F') lo = b - 'A' + 10;
				if (hi < 0 || lo < 0) return false;
				out[i] = (uint8_t)((hi << 4) | lo);
			}
			return true;
		};

		bool ok = true;
		CStringA msg = "ok";
		try {
			auto& store = eSELive::CLiveSubscriptionStore::Get();
			if (!addArg.IsEmpty()) {
				uint8_t pk[32];
				if (!hexToBytes(addArg, pk)) { ok = false; msg = "invalid pubkey hex (need 64 chars)"; }
				else {
					eSELive::SubscriptionEntry e = {};
					memcpy(e.channel_pubkey, pk, 32);
					e.name = CStringA(nmArg);
					e.added_unix_ts = (uint64_t)time(NULL);
					e.notifications = true;
					if (!store.Add(e)) { ok = false; msg = "add failed (already subscribed?)"; }
					else store.Save();
				}
			}
			if (!rmArg.IsEmpty()) {
				uint8_t pk[32];
				if (!hexToBytes(rmArg, pk)) { ok = false; msg = "invalid pubkey hex"; }
				else if (!store.Remove(pk)) { ok = false; msg = "not subscribed"; }
				else store.Save();
			}

			// List current entries (always in response).
			std::vector<eSELive::SubscriptionEntry> all;
			store.GetAll(all);
			CStringA arr;
			for (size_t i = 0; i < all.size(); ++i) {
				if (i > 0) arr += ",";
				CStringA pkHex;
				for (int b = 0; b < 32; ++b) {
					CStringA pair;
					pair.Format("%02x", all[i].channel_pubkey[b]);
					pkHex += pair;
				}
				CStringA line;
				line.Format("{\"pubkey\":\"%s\",\"name\":\"%s\",\"added\":%llu}",
					(LPCSTR)pkHex, (LPCSTR)EseJsonEscapeA(all[i].name),
					(unsigned long long)all[i].added_unix_ts);
				arr += line;
			}
			CStringA json;
			json.Format("{\"ok\":%s,\"msg\":\"%s\",\"count\":%u,\"subscriptions\":[%s]}",
				ok ? "true" : "false", (LPCSTR)msg, (unsigned)all.size(), (LPCSTR)arr);
			CStringA header;
			header.Format(
			    "HTTP/1.1 200 OK\r\n"
			    HTTPInit
			    "Content-Type: application/json\r\n"
			    "Content-Length: %d\r\n\r\n",
			    json.GetLength());
			Data.pSocket->SendData(header, header.GetLength());
			Data.pSocket->SendData(json, json.GetLength());
		} catch (...) {
			const char* err = "{\"ok\":false,\"msg\":\"exception in subscriptions handler\"}";
			CStringA header;
			header.Format("HTTP/1.1 200 OK\r\n" HTTPInit "Content-Type: application/json\r\nContent-Length: %d\r\n\r\n",
				(int)strlen(err));
			Data.pSocket->SendData(header, header.GetLength());
			Data.pSocket->SendData(err, (int)strlen(err));
		}
		return;
	}

	// --- /api/live/privacy/tunnel_search?keyword=foo --- v8.1 Sprint B —
	// REAL Kad search through the onion tunnel. Sends TUN_OP_KAD_SEARCH_V2;
	// the EXIT runs an actual dual-namespace Kad CSearch on V's behalf and
	// returns rich result records (TUN_OP_KAD_RESULT_V2, multi-cell). The
	// keyword is emitted to Kad from the EXIT's IP, never V's → V's identity
	// stays off the DHT. (The keyword does reach the exit in clear; encrypting
	// it toward the exit is v9.0 roadmap, thesis Decision 12.3.) Length: 31.
	if (Data.webRoute == ese::web::WebRouteId::ApiLivePrivacyTunnelSearch) {
		CString kwArg = _ParseURL(Data.sURL, _T("keyword"));
		if (kwArg.IsEmpty()) kwArg = _T("eselive");
		CStringA kwA(kwArg);
		kwA.MakeLower();
		std::string keyword((LPCSTR)kwA);
		std::string reply;
		bool ok = false;
		try {
			// 12 s: the exit accumulates real Kad results for ~7 s (the
			// window) before replying with TUN_OP_KAD_RESULT_V2.
			ok = eSELive::CLiveTunnel::Get().TunneledKadSearch(keyword, reply, 12000);
		} catch (...) {}

		CStringA json;
		if (ok) {
			// `reply` is already a JSON array of rich result records built by
			// TunneledKadSearch; embed it directly. Do NOT use Format here - a
			// '%' in a stream title would be misread as a format spec.
			const CStringA kwSafe = EseJsonEscapeA(kwA);
			// K6-1 (Kad6 DISCOVERY_ONLY): label the operation honestly. The
			// originator's IP never touches the DHT (the exit queries Kad from its
			// OWN IP), but the exit DOES see the keyword in clear (spec K6-SEARCH-010),
			// and this is discovery ONLY — transfer privacy is a separate policy
			// (STRICT suppresses direct dials; other profiles may permit them). These are additive
			// JSON fields; existing consumers of ok/keyword/results are unaffected.
			json = "{\"ok\":true,\"privacy\":\"DISCOVERY_ONLY\",\"originator_hidden_from_dht\":true,\"exit_sees_keyword\":true,\"keyword\":\"";
			json += kwSafe;
			json += "\",\"results\":";
			json += reply.c_str();
			json += "}";
		} else {
			json = "{\"ok\":false,\"privacy\":\"DISCOVERY_ONLY\",\"reason\":\"no active circuit or timeout - build a circuit first via test_circuit\"}";
		}
		CStringA header;
		header.Format(
		    "HTTP/1.1 200 OK\r\n"
		    HTTPInit
		    "Content-Type: application/json\r\n"
		    "Content-Length: %d\r\n\r\n",
		    json.GetLength());
		Data.pSocket->SendData(header, header.GetLength());
		Data.pSocket->SendData(json, json.GetLength());
		return;
	}

	// --- /api/live/privacy/tunnel_echo?bytes=N --- v8.1 A1.7 test op.
	// Sends an N-byte payload through the tunnel as a multi-cell
	// TUN_OP_ECHO_LARGE message and checks the reassembled reply is
	// byte-identical. Exercises fragmentation + reassembly + dispatcher
	// end-to-end. "/api/live/privacy/tunnel_echo" is exactly 29 chars.
	if (Data.webRoute == ese::web::WebRouteId::ApiLivePrivacyTunnelEcho) {
		CString bytesArg = _ParseURL(Data.sURL, _T("bytes"));
		int n = bytesArg.IsEmpty() ? 1024 : _ttoi(bytesArg);
		if (n < 0) n = 0;
		// Deterministic test pattern so the round-trip is verifiable.
		std::vector<uint8_t> payload((size_t)n);
		for (size_t i = 0; i < payload.size(); ++i)
			payload[i] = (uint8_t)((i * 31u + 7u) & 0xFF);
		std::vector<uint8_t> reply;
		bool ok = false;
		try {
			ok = eSELive::CLiveTunnel::Get().TunnelEchoLarge(payload, reply, 15000);
		} catch (...) {}
		const bool match = ok && reply.size() == payload.size()
			&& (payload.empty()
			    || memcmp(reply.data(), payload.data(), payload.size()) == 0);

		CStringA json;
		json.Format("{\"ok\":%s,\"bytes\":%d,\"replied\":%u,\"match\":%s}",
			ok ? "true" : "false", n, (unsigned)reply.size(),
			match ? "true" : "false");
		CStringA header;
		header.Format(
		    "HTTP/1.1 200 OK\r\n"
		    HTTPInit
		    "Content-Type: application/json\r\n"
		    "Content-Length: %d\r\n\r\n",
		    json.GetLength());
		Data.pSocket->SendData(header, header.GetLength());
		Data.pSocket->SendData(json, json.GetLength());
		return;
	}

	// "/api/live/privacy/tunnel_ping" is exactly 29 chars.
	if (Data.webRoute == ese::web::WebRouteId::ApiLivePrivacyTunnelPing) {
		CString textArg = _ParseURL(Data.sURL, _T("text"));
		if (textArg.IsEmpty()) textArg = _T("hello");
		std::string text((LPCSTR)CStringA(textArg));
		std::string reply;
		bool ok = false;
		try {
			ok = eSELive::CLiveTunnel::Get().TunnelPing(text, reply, 5000);
		} catch (...) {}

		const ese::web::SerializedWebResponse response =
			ese::web::Serialize(ese::web::WebTunnelPingResponseModel{
				ok,
				text,
				reply,
				"no active circuit or timeout - build a 2-hop circuit first "
				"via test_circuit?hops=2"});
		const CStringA json(
			response.body.data(),
			static_cast<int>(response.body.size()));

		CStringA header;
		header.Format(
		    "HTTP/1.1 %u %s\r\n"
		    HTTPInit
		    "Content-Type: %s\r\n"
		    "Content-Length: %d\r\n\r\n",
			response.status_code,
			response.reason_phrase.c_str(),
			response.content_type.c_str(),
		    json.GetLength());
		Data.pSocket->SendData(header, header.GetLength());
		Data.pSocket->SendData(json, json.GetLength());
		return;
	}

	// --- /api/live/privacy/circuits --- v0.71 B — per-circuit detail.
	// Enumerates all circuits in CLiveTunnel with id, role, state, age
	// in ms, hop count, and forwarding state (next_hop_set / next_circ_id
	// for relay circuits that have already received EXTEND). Used to
	// verify "Hops: 2" after BuildTestCircuit2Hop succeeds.
	if (Data.webRoute == ese::web::WebRouteId::ApiLivePrivacyCircuits) {
		std::vector<eSELive::CLiveTunnel::CircuitSnapshot> snap;
		try {
			eSELive::CLiveTunnel::Get().GetCircuitsSnapshot(snap);
		} catch (...) {}

		CStringA arr;
		for (size_t i = 0; i < snap.size(); ++i) {
			if (i > 0) arr += ",";
			const auto& s = snap[i];
			CStringA line;
			line.Format(
			    "{\"circ_id\":\"0x%08X\",\"role\":\"%s\","
			    "\"state\":\"%s\",\"age_ms\":%u,"
			    "\"hop_count\":%u,\"forwarding\":%s,"
			    "\"next_circ_id\":\"0x%08X\",\"auth_ok\":%s,"
			    "\"strict3\":%s,\"class5_shaped\":%s,"
			    "\"traffic_shaping_exposed\":%s,\"abort_reason\":\"%s\"}",
			    s.circ_id,
			    s.role == 0 ? "Originator" : "Relay",
			    (s.state == 0 ? "Pending"
			      : s.state == 1 ? "HalfBuilt"
			      : s.state == 2 ? "Built"
			      : s.state == 3 ? "Active"
			      : s.state == 4 ? "Destroyed" : "?"),
			    s.age_ms,
			    s.hop_count,
			    s.next_hop_set ? "true" : "false",
			    s.next_circ_id,
			    s.auth_ok ? "true" : "false",
			    s.strict3 ? "true" : "false",
			    s.shaped ? "true" : "false",
			    s.shaping_exposed ? "true" : "false",
			    s.abort_reason == 1 ? "STRICT_V1"
			      : s.abort_reason == 2 ? "PIN_MISMATCH"
			      : s.abort_reason == 3 ? "CAPS_FLOOR"
			      : s.abort_reason == 4 ? "SIG_FAIL"
			      : s.abort_reason == 5 ? "HANDSHAKE_TIMEOUT"
			      : s.abort_reason == 6 ? "EXTEND_TIMEOUT" : "NONE");
			arr += line;
		}

		CStringA json;
		json.Format("{\"total\":%u,\"circuits\":[%s]}",
		    (unsigned)snap.size(), (LPCSTR)arr);

		CStringA header;
		header.Format(
		    "HTTP/1.1 200 OK\r\n"
		    HTTPInit
		    "Content-Type: application/json\r\n"
		    "Content-Length: %d\r\n\r\n",
		    json.GetLength());
		Data.pSocket->SendData(header, header.GetLength());
		Data.pSocket->SendData(json, json.GetLength());
		return;
	}

	// --- /api/live/privacy/peers --- v0.71 P3.11 — debug helper.
	// Lists currently connected peers with their TAG_ESE_CAPS bitmap so
	// the user can verify which peers PC1 actually sees as fork-capable.
	// Critical for diagnosing why test_circuit creates Pending circuits
	// that never become Active (most common cause: PC2 not in ClientList,
	// or PC2 running an older binary that didn't emit TAG_ESE_CAPS).
	if (Data.webRoute == ese::web::WebRouteId::ApiLivePrivacyPeers) {
		// v0.72 — served from the main-thread-maintained peer cache; the
		// worker thread must never dereference CUpDownClient pointers.
		std::vector<eSELive::CLiveTunnel::PeerSnapshot> all;
		size_t tunnelingCount = 0;
		try {
			eSELive::CLiveTunnel::Get().GetPeersSnapshot(all, tunnelingCount);
		} catch (...) {}

		CStringA peersJson;
		for (size_t i = 0; i < all.size(); ++i) {
			if (i > 0) peersJson += ",";
			const eSELive::CLiveTunnel::PeerSnapshot& p = all[i];
			CStringA line;
			line.Format(
			    "{\"ip\":\"%s\",\"address\":\"%s\",\"port\":%u,"
			    "\"forkCaps\":\"0x%08X\",\"eseCaps\":\"0x%08X\","
			    "\"isFork\":%s}",
			    p.has_ipv4 ? CAddress::FromIPv4NetworkOrder(p.ip).ToString().c_str() : "",
			    p.address.c_str(),
			    (unsigned)p.port,
			    p.fork_caps, p.ese_caps,
			    (p.ese_caps & 0x00000100) ? "true" : "false");
			peersJson += line;
		}

		CStringA json;
		json.Format(
		    "{\"totalConnected\":%u,\"forkTunnelingCapable\":%u,\"peers\":[%s]}",
		    (unsigned)all.size(),
		    (unsigned)tunnelingCount,
		    (LPCSTR)peersJson);

		CStringA header;
		header.Format(
		    "HTTP/1.1 200 OK\r\n"
		    HTTPInit
		    "Content-Type: application/json\r\n"
		    "Content-Length: %d\r\n\r\n",
		    json.GetLength());
		Data.pSocket->SendData(header, header.GetLength());
		Data.pSocket->SendData(json, json.GetLength());
		return;
	}

	// --- /api/live/privacy/test_circuit --- v0.71 P3.6 — solo testing helper.
	// Builds a single-hop test circuit through a connected peer that
	// advertised ESE_CAP_PRIVACY_TUNNELING. Legacy peers are rejected
	// fail-closed instead of creating an unfinishable Pending circuit.
	// Length of "/api/live/privacy/test_circuit" is exactly 30 chars.
	// Left(30) matches both bare URL and URL with ?query suffix.
	if (Data.webRoute == ese::web::WebRouteId::ApiLivePrivacyTestCircuit) {
		// v0.71 B — optional ?hops=2 to build a 2-hop circuit. Default
		// is 1-hop (backward compat). 2-hop requires 2 distinct fork peers.
		// hops=3 invokes K6-6 STRICT3: three authenticated/shaped IPv6
		// identities with verified /48+ASN diversity and no repeated known
		// operator group, with no fallback.
		const CString hopsArg = _ParseURL(Data.sURL, _T("hops"));
		const int hops = hopsArg == _T("3") ? 3
		               : hopsArg == _T("2") ? 2 : 1;
		uint32_t circId = 0;
		CStringA result;
		try {
			// v0.72 — marshaled to the main thread (the build touches the
			// ClientList + peer sockets). Waits up to ~2.5 s for the result.
			circId = eSELive::CLiveTunnel::Get().RequestTestCircuit(hops, 2500);
		} catch (...) {}
		if (circId == 0) {
			result = hops == 3
				? "{\"ok\":false,\"reason\":\"strict3 unavailable: need 3 authenticated shaped IPv6 peers with verified /48+ASN diversity and no repeated known operator group - check /api/live/privacy/peers\"}"
				: hops == 2
				? "{\"ok\":false,\"reason\":\"two-hop circuit unavailable: need 2 distinct connected fork-capable peers - no loopback downgrade\"}"
				: "{\"ok\":false,\"reason\":\"no connected fork-capable peers - check /api/live/privacy/peers\"}";
		} else {
			CStringA tmp;
			tmp.Format("{\"ok\":true,\"circuit_id\":\"0x%08x\",\"hops_requested\":%d,\"note\":\"poll /api/live/privacy and /api/live/privacy/circuits to watch handshake progress\"}",
				(unsigned)circId, hops);
			result = tmp;
		}
		CStringA header;
		header.Format(
			"HTTP/1.1 200 OK\r\n"
			HTTPInit
			"Content-Type: application/json\r\n"
			"Content-Length: %d\r\n\r\n",
			result.GetLength());
		Data.pSocket->SendData(header, header.GetLength());
		Data.pSocket->SendData(result, result.GetLength());
		return;
	}

	// --- /api/live/privacy/kad6/release --- explicit public-exit release gate.
	// Installation and mutation are loopback-only. The host signs the evidence
	// with its persistent NodeIdentity; callers never supply a private key.
	if (Data.webRoute == ese::web::WebRouteId::ApiLivePrivacyKad6Release) {
		const CString enabledArg = _ParseURL(Data.sURL, _T("enabled"));
		bool mutationOk = true;
		CStringA mutationError;
		if (!enabledArg.IsEmpty()) {
			const bool local = Data.inadr.S_un.S_addr == htonl(INADDR_LOOPBACK);
			const bool validEnabled = enabledArg == _T("0") || enabledArg == _T("1");
			const CString challengeArg = _ParseURL(Data.sURL, _T("challenge"));
			if (!local) { mutationOk = false; mutationError = "local_only"; }
			else if (!validEnabled) { mutationOk = false; mutationError = "bad_enabled"; }
			else if (!eSELive::CLiveTunnel::Get().ConsumeK6ReleaseOperatorChallenge(
				std::string(CT2A(challengeArg, CP_UTF8)))) {
				mutationOk = false; mutationError = "challenge_required_or_expired";
			}
			else {
				kad6::K6ReleaseEvidence evidence;
				const kad6::K6ReleaseEvidence* evidencePtr = NULL;
				if (enabledArg == _T("1")) {
					const CString confirm = _ParseURL(Data.sURL, _T("confirm"));
					const CString fieldHex = _ParseURL(Data.sURL, _T("field_sha256"));
					const CString auditHex = _ParseURL(Data.sURL, _T("audit_sha256"));
					if (confirm != _T("ENABLE_KAD6_PUBLIC_EXIT")) {
						mutationOk = false; mutationError = "confirmation_required";
					} else if (!fieldHex.IsEmpty() || !auditHex.IsEmpty()) {
						auto parseDigest = [](const CString& text,
							kad6::Hash32& digest) -> bool {
							if (text.GetLength() != 64) return false;
							for (int i = 0; i < 32; ++i) {
								auto nibble = [](TCHAR c) -> int {
									if (c >= _T('0') && c <= _T('9')) return c - _T('0');
									if (c >= _T('a') && c <= _T('f')) return c - _T('a') + 10;
									if (c >= _T('A') && c <= _T('F')) return c - _T('A') + 10;
									return -1;
								};
								const int hi = nibble(text[i * 2]);
								const int lo = nibble(text[i * 2 + 1]);
								if (hi < 0 || lo < 0) return false;
								digest[i] = static_cast<uint8_t>((hi << 4) | lo);
							}
							return true;
						};
						const CString fromArg = _ParseURL(Data.sURL, _T("observed_from"));
						const CString toArg = _ParseURL(Data.sURL, _T("observed_to"));
						const CString attemptsArg = _ParseURL(Data.sURL, _T("admission_attempts"));
						const CString ppmArg = _ParseURL(Data.sURL, _T("admission_ppm"));
						const CString headroomArg = _ParseURL(Data.sURL, _T("headroom_bps"));
						const CString gatesArg = _ParseURL(Data.sURL, _T("gate_mask"));
						const CString validArg = _ParseURL(Data.sURL, _T("valid_until"));
						evidence.observed_from = _tcstoui64(fromArg, NULL, 10);
						evidence.observed_to = _tcstoui64(toArg, NULL, 10);
						evidence.admission_attempts = _tcstoui64(attemptsArg, NULL, 10);
						evidence.admission_success_ppm = static_cast<uint32>(
							_tcstoul(ppmArg, NULL, 10));
						evidence.useful_headroom_bps = _tcstoui64(headroomArg, NULL, 10);
						evidence.gate_mask = static_cast<uint16>(_tcstoul(gatesArg, NULL, 0));
						evidence.valid_until = _tcstoui64(validArg, NULL, 10);
						if (!parseDigest(fieldHex, evidence.field_digest) ||
							!parseDigest(auditHex, evidence.external_audit_digest) ||
							fromArg.IsEmpty() || toArg.IsEmpty() || attemptsArg.IsEmpty() ||
							ppmArg.IsEmpty() || headroomArg.IsEmpty() || gatesArg.IsEmpty()) {
							mutationOk = false; mutationError = "incomplete_or_bad_evidence";
						} else {
							evidencePtr = &evidence;
						}
					}
				}
				if (mutationOk) {
					int drain = _ttoi(_ParseURL(Data.sURL, _T("drain_seconds")));
					if (drain <= 0) drain = 300;
					if (drain > static_cast<int>(kad6::kK6MaxDrainSeconds))
						drain = static_cast<int>(kad6::kK6MaxDrainSeconds);
					try {
						mutationOk = eSELive::CLiveTunnel::Get().RequestK6PublicRelease(
							enabledArg == _T("1"), evidencePtr,
							static_cast<uint32>(drain), 5000);
					} catch (...) { mutationOk = false; }
					if (!mutationOk) mutationError = "gate_rejected_or_runtime_unhealthy";
				}
			}
		}
		eSELive::CLiveTunnel::K6ReleaseRuntimeSnapshot release;
		try { eSELive::CLiveTunnel::Get().GetK6ReleaseSnapshot(release); } catch (...) {}
		std::string operatorChallenge;
		if (Data.inadr.S_un.S_addr == htonl(INADDR_LOOPBACK))
			try { eSELive::CLiveTunnel::Get().GetK6ReleaseOperatorChallenge(
				operatorChallenge); } catch (...) { operatorChallenge.clear(); }
		const CStringA challengeJson(operatorChallenge.c_str());
		CStringA json;
		json.Format(
			"{\"ok\":%s,\"error\":\"%s\",\"status\":\"%s\",\"challenge\":\"%s\","
			"\"operator_opt_in\":%s,\"evidence_present\":%s,\"evidence_valid\":%s,"
			"\"runtime_healthy\":%s,\"public_exit_enabled\":%s,"
			"\"beta_exit_opt_in\":%s,\"beta_exit_enabled\":%s,"
			"\"gate_mask\":%u,\"observed_from\":%llu,\"observed_to\":%llu,"
			"\"valid_until\":%llu,\"admission_attempts\":%llu,"
			"\"admission_ppm\":%u,\"headroom_bps\":%llu}",
			mutationOk ? "true" : "false", (LPCSTR)mutationError,
			kad6::K6ReleaseGateStatusName(release.status),
			(LPCSTR)challengeJson,
			release.operator_opt_in ? "true" : "false",
			release.evidence_present ? "true" : "false",
			release.evidence_valid ? "true" : "false",
			release.runtime_healthy ? "true" : "false",
			release.public_exit_enabled ? "true" : "false",
			release.beta_exit_opt_in ? "true" : "false",
			release.beta_exit_enabled ? "true" : "false",
			static_cast<unsigned>(release.evidence.gate_mask),
			static_cast<unsigned long long>(release.evidence.observed_from),
			static_cast<unsigned long long>(release.evidence.observed_to),
			static_cast<unsigned long long>(release.evidence.valid_until),
			static_cast<unsigned long long>(release.evidence.admission_attempts),
			static_cast<unsigned>(release.evidence.admission_success_ppm),
			static_cast<unsigned long long>(release.evidence.useful_headroom_bps));
		CStringA header;
		header.Format("HTTP/1.1 200 OK\r\n" HTTPInit
			"Content-Type: application/json\r\nCache-Control: no-store\r\n"
			"Content-Length: %d\r\n\r\n", json.GetLength());
		Data.pSocket->SendData(header, header.GetLength());
		Data.pSocket->SendData(json, json.GetLength());
		return;
	}

	// --- /api/live/privacy/kad6/hardening --- K6-7 local incident control.
	// A mutation is loopback-only even when a remote Web UI token is valid: the
	// operator stop is intentionally local and never becomes a remote kill switch.
	if (Data.webRoute == ese::web::WebRouteId::ApiLivePrivacyKad6Hardening) {
		const CString serviceArg = _ParseURL(Data.sURL, _T("service"));
		const CString enabledArg = _ParseURL(Data.sURL, _T("enabled"));
		const CString drainArg = _ParseURL(Data.sURL, _T("drain_seconds"));
		bool mutationOk = true;
		CStringA mutationError;
		if (!serviceArg.IsEmpty() || !enabledArg.IsEmpty()) {
			kad6::K6Service service = kad6::K6Service::Count;
			if (serviceArg == _T("control")) service = kad6::K6Service::Control;
			else if (serviceArg == _T("exit_kad")) service = kad6::K6Service::ExitKad;
			else if (serviceArg == _T("exit_ed2k_dial")) service = kad6::K6Service::ExitEd2kDial;
			else if (serviceArg == _T("exit_ed2k_full")) service = kad6::K6Service::ExitEd2kFull;
			const bool validEnabled = enabledArg == _T("0") || enabledArg == _T("1");
			const bool local = Data.inadr.S_un.S_addr == htonl(INADDR_LOOPBACK);
			if (!local) { mutationOk = false; mutationError = "local_only"; }
			else if (service == kad6::K6Service::Count || !validEnabled) {
				mutationOk = false; mutationError = "bad_service_or_enabled";
			} else {
				int requestedDrain = drainArg.IsEmpty() ? 300 : _ttoi(drainArg);
				if (requestedDrain < 0) requestedDrain = 0;
				if (requestedDrain > static_cast<int>(kad6::kK6MaxDrainSeconds))
					requestedDrain = static_cast<int>(kad6::kK6MaxDrainSeconds);
				try {
					mutationOk = eSELive::CLiveTunnel::Get().RequestK6ServiceSwitch(
						service, enabledArg == _T("1"), static_cast<uint32>(requestedDrain), 3500);
				} catch (...) { mutationOk = false; }
				if (!mutationOk) mutationError = "release_gate_or_main_thread_timeout";
			}
		}

		eSELive::CLiveTunnel::K6HardeningRuntimeSnapshot snap;
		try { eSELive::CLiveTunnel::Get().GetK6HardeningSnapshot(snap); } catch (...) {}
		K6ExitNoticeServerSnapshot notice;
		try { notice = eSELive::CLiveTunnel::Get().GetK6ExitNoticeSnapshot(); } catch (...) {}
		CStringA services;
		for (size_t i = 0; i < snap.control.services.size(); ++i) {
			if (i != 0) services += ",";
			const kad6::K6ServiceSnapshot& s = snap.control.services[i];
			CStringA item;
			item.Format("{\"service\":\"%s\",\"state\":\"%s\","
				"\"changed_at\":%llu,\"drain_deadline\":%llu,\"admitting\":%s}",
				kad6::K6ServiceName(s.service), kad6::K6ServiceStateName(s.state),
				static_cast<unsigned long long>(s.changed_at),
				static_cast<unsigned long long>(s.drain_deadline),
				(snap.control.admission_mask & kad6::K6ServiceBit(s.service)) ? "true" : "false");
			services += item;
		}
		const bool degraded = snap.source_epoch_store_failed || snap.shaping_exposed_circuits != 0;
		auto occupancyBand = [](uint64 value) -> const char* {
			return value == 0 ? "zero" : value <= 4 ? "1_4" :
				value <= 16 ? "5_16" : value <= 64 ? "17_64" : "65_plus";
		};
		CStringA economy;
		for (size_t i = 0; i < snap.economy.size(); ++i) {
			if (i != 0) economy += ",";
			const kad6::K6EconomyWindowSnapshot& window = snap.economy[i];
			CStringA rho;
			if (snap.economy_measurement_ready && std::isfinite(snap.rho[i]))
				rho.Format("%.6f", snap.rho[i]);
			else
				rho = "null";
			CStringA item;
			item.Format("{\"service\":\"%s\",\"rho\":%s,\"sealed\":%s,"
				"\"starts_at\":%llu,\"ends_at\":%llu,\"samples\":%llu,"
				"\"admission_attempts\":%llu,\"admission_successes\":%llu,"
				"\"admission_ratio\":%.6f,\"rho_p50\":%.6f,\"rho_p95\":%.6f}",
				kad6::K6ServiceName(static_cast<kad6::K6Service>(i)), (LPCSTR)rho,
				window.sealed ? "true" : "false",
				static_cast<unsigned long long>(window.starts_at),
				static_cast<unsigned long long>(window.ends_at),
				static_cast<unsigned long long>(window.samples),
				static_cast<unsigned long long>(window.admission_attempts),
				static_cast<unsigned long long>(window.admission_successes),
				window.admission_ratio, window.rho_p50, window.rho_p95);
			economy += item;
		}
		CStringA json;
		json.Format("{\"ok\":%s,\"error\":\"%s\",\"health\":\"%s\","
			"\"revision\":%llu,\"services\":[%s],"
			"\"occupancy\":{\"leases\":\"%s\",\"publishes\":\"%s\","
			"\"dial_streams\":\"%s\",\"full_streams\":\"%s\",\"shaping_exposed\":%s},"
			"\"source_epoch_store_failed\":%s,"
			"\"metrics\":{\"window_ready\":%s,\"window_start\":%llu,\"window_end\":%llu,"
			"\"fixed_series\":%u,\"exported_series\":%u},"
			"\"economy\":{\"measurement_ready\":%s,\"strict_recommended\":%s,"
			"\"services\":[%s]},"
			"\"exit_notice\":{\"running\":%s,\"port\":%u,\"requests\":\"%s\","
			"\"rejected\":\"%s\",\"bytes_sent\":\"%s\"}}",
			mutationOk ? "true" : "false", (LPCSTR)mutationError,
			degraded ? "degraded" : "healthy",
			static_cast<unsigned long long>(snap.control.revision), (LPCSTR)services,
			occupancyBand(snap.active_leases), occupancyBand(snap.active_publishes),
			occupancyBand(snap.dial_streams), occupancyBand(snap.full_streams),
			snap.shaping_exposed_circuits != 0 ? "true" : "false",
			snap.source_epoch_store_failed ? "true" : "false",
			snap.metrics.ready ? "true" : "false",
			static_cast<unsigned long long>(snap.metrics.start),
			static_cast<unsigned long long>(snap.metrics.end),
			static_cast<unsigned>(snap.metrics.fixed_series),
			static_cast<unsigned>(snap.metrics.exported_series),
			snap.economy_measurement_ready ? "true" : "false",
			snap.strict_recommended ? "true" : "false", (LPCSTR)economy,
			notice.running ? "true" : "false", static_cast<unsigned>(notice.port),
			occupancyBand(notice.requests), occupancyBand(notice.rejected),
			occupancyBand(notice.bytes_sent));
		CStringA header;
		header.Format("HTTP/1.1 200 OK\r\n" HTTPInit
			"Content-Type: application/json\r\nCache-Control: no-store\r\n"
			"Content-Length: %d\r\n\r\n", json.GetLength());
		Data.pSocket->SendData(header, header.GetLength());
		Data.pSocket->SendData(json, json.GetLength());
		return;
	}

	// --- /api/live/privacy --- F5: expose Kad v2 mode + fallback policy + sensitive keywords.
	// GET: returns current state. PATCH (via query params): updates state.
	if (Data.webRoute == ese::web::WebRouteId::ApiLivePrivacy) {
		using Kademlia::CKadV2ModeSelector;
		using Kademlia::CKadV2Mode;
		auto& sel = CKadV2ModeSelector::Get();
		const CString modeArg     = _ParseURL(Data.sURL, _T("mode"));        // direct|tunneled|adaptive
		const CString fallbackArg = _ParseURL(Data.sURL, _T("fallback"));    // strict|balanced|best_effort
		const CString addSens     = _ParseURL(Data.sURL, _T("add_sensitive"));
		const CString rmSens      = _ParseURL(Data.sURL, _T("rm_sensitive"));
		if (!modeArg.IsEmpty()) {
			if      (modeArg == _T("direct"))    sel.SetDefaultMode(CKadV2Mode::Direct);
			else if (modeArg == _T("tunneled"))  sel.SetDefaultMode(CKadV2Mode::Tunneled);
			else if (modeArg == _T("adaptive"))  sel.SetDefaultMode(CKadV2Mode::Adaptive);
		}
		if (!fallbackArg.IsEmpty()) {
			if      (fallbackArg == _T("strict"))      sel.SetFallbackPolicy(CKadV2ModeSelector::STRICT_PRIVACY);
			else if (fallbackArg == _T("balanced"))    sel.SetFallbackPolicy(CKadV2ModeSelector::BALANCED);
			else if (fallbackArg == _T("best_effort")) sel.SetFallbackPolicy(CKadV2ModeSelector::BEST_EFFORT);
		}
		if (!addSens.IsEmpty()) sel.AddSensitiveKeyword((LPCWSTR)addSens);
		if (!rmSens.IsEmpty())  sel.RemoveSensitiveKeyword((LPCWSTR)rmSens);

		// D2 (Sprint D): mirror any change into the persisted prefs so the mode
		// survives restart. The selector update above already takes effect THIS
		// session (ShouldRouteThroughTunnel -> sel.Decide). We only set the pref
		// members here (cheap; the main thread reads them at startup-seed /
		// exit-save, not concurrently) — we do NOT call thePrefs.Save() from this
		// webserver WORKER thread (file I/O + project_ese_live_api_threadsafety);
		// persistence lands on eMule's normal exit-time Save().
		if (!modeArg.IsEmpty() || !fallbackArg.IsEmpty() || !addSens.IsEmpty() || !rmSens.IsEmpty()) {
			thePrefs.SetKadV2PrivacyMode((int)sel.GetDefaultMode());
			thePrefs.SetKadV2FallbackPolicy((int)sel.GetFallbackPolicy());
			std::vector<CStringW> persistKws;
			sel.GetSensitiveKeywords(persistKws);
			CString joined;
			for (size_t i = 0; i < persistKws.size(); ++i) {
				CString k(persistKws[i]);
				k.Replace(_T("|"), _T(" "));   // keep the '|' delimiter lossless
				if (!joined.IsEmpty()) joined += _T("|");
				joined += k;
			}
			thePrefs.SetKadV2SensitiveKeywords(joined);
		}

		const char* modeStr =
			sel.GetDefaultMode() == CKadV2Mode::Direct    ? "direct"   :
			sel.GetDefaultMode() == CKadV2Mode::Tunneled  ? "tunneled" : "adaptive";
		const char* fbStr =
			sel.GetFallbackPolicy() == CKadV2ModeSelector::STRICT_PRIVACY ? "strict"   :
			sel.GetFallbackPolicy() == CKadV2ModeSelector::BEST_EFFORT     ? "best_effort" : "balanced";
		std::vector<CStringW> kws;
		sel.GetSensitiveKeywords(kws);
		CStringA kwJson;
		for (size_t i = 0; i < kws.size(); ++i) {
			if (i > 0) kwJson += ",";
			kwJson += "\"";
			kwJson += EseJsonEscapeA(CStringA(kws[i]));
			kwJson += "\"";
		}

		// v0.71 P1.1 — runtime metrics. Each value is read from the live
		// singletons so the user can see what's actually happening, not
		// just what the settings say. Empty / zero values are an honest
		// signal that the module exists but isn't doing work yet (eg.
		// circuits=0 with mode=tunneled means the TCP-send path in F5 P3
		// isn't wired yet — the user knows where they stand).
		size_t circuitsActive = 0;
		size_t circuitsPending = 0;   // v0.71 P3.8 — visible Pending state
		size_t tunnelPoolSize = 0;
		size_t subscriptionCount = 0;
		uint32 capsRuntime = g_uEseCapsRuntime;
		CStringA proberV6Str = "";
		// v8.1 D8-web - tunnel byte/cell/RTT telemetry (mirrors the MFC Network Info panel).
		// Read-only scalar getters; safe to call from the webserver worker (same pattern as
		// ActiveCircuitCount below — a momentary torn read just yields a slightly stale count).
		uint64_t cellsSent = 0, cellsRecv = 0, bytesSent = 0, bytesRecv = 0;
		uint32 meanRttMs = 0;
		bool kad6CircuitActive = false;
		try {
			eSELive::CLiveTunnel& tunnel = eSELive::CLiveTunnel::Get();
			circuitsActive    = tunnel.ActiveCircuitCount();
			circuitsPending   = tunnel.PendingCircuitCount();
			tunnelPoolSize    = Kademlia::CKadV2TunnelPool::Get().Size();
			subscriptionCount = eSELive::CLiveSubscriptionStore::Get().Count();
			CAddress v6 = CFirewallProberV6::Instance().GetDetectedV6IP();
			if (!v6.IsNull()) proberV6Str = CStringA(v6.ToStringC());
			kad6CircuitActive = tunnel.HasActiveCircuitWithExitCaps(ESE_CAP_KAD6);
			cellsSent  = tunnel.CellsSentTotal();   // v8.1 D8-web
			cellsRecv  = tunnel.CellsRecvTotal();
			bytesSent  = tunnel.BytesSentTotal();
			bytesRecv  = tunnel.BytesRecvTotal();
			meanRttMs  = tunnel.MeanRttMs();
		} catch (...) {
			// keep zeros; this endpoint must never throw
		}
		const bool kad6Preferred = sel.GetDefaultMode() != CKadV2Mode::Direct;
		const char* routeState = !kad6Preferred ? "kad2_direct" :
			kad6CircuitActive ? "kad6" :
			circuitsActive != 0 ? "tunnel_kad2_compat" :
			sel.GetFallbackPolicy() == CKadV2ModeSelector::STRICT_PRIVACY
				? "blocked_waiting_kad6" : "kad2_fallback";

		// Build the human-readable caps array cleanly (no printf comma games).
		CStringA capsArr;
		auto appendCap = [&capsArr](const char* name) {
		    if (!capsArr.IsEmpty()) capsArr += ",";
		    capsArr += "\""; capsArr += name; capsArr += "\"";
		};
		if (capsRuntime & ESE_CAP_M1_SUBSCRIBER_PIN)   appendCap("M1_subscriber_pin");
		if (capsRuntime & ESE_CAP_M2_COMPOSITE_KEYS)   appendCap("M2_composite_keys");
		if (capsRuntime & ESE_CAP_M3_SHARDING)         appendCap("M3_sharding");
		if (capsRuntime & ESE_CAP_M4_TRIGRAMS)         appendCap("M4_trigrams");
		if (capsRuntime & ESE_CAP_M5_BLOOM_GOSSIP)     appendCap("M5_bloom_gossip");
		if (capsRuntime & ESE_CAP_M6_K_EFFECTIVE)      appendCap("M6_k_effective");
		if (capsRuntime & ESE_CAP_PRIVACY_TUNNELING)   appendCap("privacy_tunneling");
		if (capsRuntime & ESE_CAP_SEALED_RECORDS)      appendCap("sealed_records");
		if (capsRuntime & ESE_CAP_GOSSIP_PROTOCOL)     appendCap("gossip_protocol");
		if (capsRuntime & ESE_CAP_COVER_TRAFFIC)       appendCap("cover_traffic");
		if (capsRuntime & ESE_CAP_TUNNEL_AUTH)         appendCap("tunnel_auth");
		if (capsRuntime & ESE_CAP_KAD6)                appendCap("kad6");
		if (capsRuntime & ESE_CAP_TUNNEL_STRICT3)      appendCap("tunnel_strict3");
		if (capsRuntime & ESE_CAP_TUNNEL_SHAPED)       appendCap("tunnel_shaped");
		if (capsRuntime & ESE_CAP_NETLAB_V1)           appendCap("netlab_v1");

		CStringA json;
		json.Format(
		    "{"
		    "\"mode\":\"%s\","
		    "\"fallback\":\"%s\","
		    "\"sensitiveKeywords\":[%s],"
		    "\"runtime\":{"
		        "\"capsBits\":\"0x%08X\","
		        "\"capsHumanReadable\":[%s],"
		        "\"kad6Preferred\":%s,"
		        "\"kad6CircuitActive\":%s,"
		        "\"routeState\":\"%s\","
		        "\"circuitsActive\":%u,"
		        "\"circuitsPending\":%u,"
		        "\"tunnelPoolSize\":%u,"
		        "\"subscriptionsLoaded\":%u,"
		        "\"cellsSent\":%I64u,\"cellsRecv\":%I64u,"
		        "\"bytesSent\":%I64u,\"bytesRecv\":%I64u,"
		        "\"meanRttMs\":%u,"
		        "\"publicIPv6\":\"%s\""
		    "}"
		    "}",
		    modeStr, fbStr, (LPCSTR)kwJson,
		    capsRuntime,
		    (LPCSTR)capsArr,
		    kad6Preferred ? "true" : "false",
		    kad6CircuitActive ? "true" : "false",
		    routeState,
		    (unsigned)circuitsActive,
		    (unsigned)circuitsPending,
		    (unsigned)tunnelPoolSize,
		    (unsigned)subscriptionCount,
		    (unsigned __int64)cellsSent,
		    (unsigned __int64)cellsRecv,
		    (unsigned __int64)bytesSent,
		    (unsigned __int64)bytesRecv,
		    (unsigned)meanRttMs,
		    (LPCSTR)proberV6Str);
		CStringA header;
		header.Format(
			"HTTP/1.1 200 OK\r\n"
			HTTPInit
			"Content-Type: application/json\r\n"
			"Content-Length: %d\r\n\r\n",
			json.GetLength());
		Data.pSocket->SendData(header, header.GetLength());
		Data.pSocket->SendData(json, json.GetLength());
		return;
	}

	// --- /api/live/metrics --- V2-S04+S05: Prometheus exposition.
	// Plain text/plain (version=0.0.4) endpoint that Prometheus can scrape.
	// Exposes counters (chunks received/served/missing, peers by role, kad ops,
	// disconnects) plus latency percentiles from LatencyHistogram (V2-S05).
	if (Data.webRoute == ese::web::WebRouteId::ApiLiveMetrics) {
		CStringA body;
		LiveDebugSnapshot snap;
		bool haveSnap = false;
		if (theApp.liveStreamManager) {
			snap = theApp.liveStreamManager->BuildDebugSnapshot();
			haveSnap = true;
		}

		DWORD p50 = 0, p95 = 0, p99 = 0, mean = 0;
		int   nLat = 0;
		if (theApp.liveStreamManager) {
			theApp.liveStreamManager->ChunkArrivalLatency().Percentiles(p50, p95, p99);
			mean = theApp.liveStreamManager->ChunkArrivalLatency().Mean();
			nLat = theApp.liveStreamManager->ChunkArrivalLatency().SampleCount();
		}

		body.Format(
			"# HELP esmule_chunks_received_total Total chunks received from peers\n"
			"# TYPE esmule_chunks_received_total counter\n"
			"esmule_chunks_received_total %ld\n"
			"# HELP esmule_chunks_requested_total Chunk requests issued by us\n"
			"# TYPE esmule_chunks_requested_total counter\n"
			"esmule_chunks_requested_total %ld\n"
			"# HELP esmule_chunks_missing_total Chunk timeouts / missing detections\n"
			"# TYPE esmule_chunks_missing_total counter\n"
			"esmule_chunks_missing_total %ld\n"
			"# HELP esmule_chunks_served_total Chunks served to peers (mesh redistribution)\n"
			"# TYPE esmule_chunks_served_total counter\n"
			"esmule_chunks_served_total %d\n"
			"# HELP esmule_kad_publishes_total Total Kad publish operations queued\n"
			"# TYPE esmule_kad_publishes_total counter\n"
			"esmule_kad_publishes_total %ld\n"
			"# HELP esmule_kad_searches_total Total Kad search requests issued\n"
			"# TYPE esmule_kad_searches_total counter\n"
			"esmule_kad_searches_total %ld\n"
			"# HELP esmule_peer_disconnects_total Total peer disconnect events\n"
			"# TYPE esmule_peer_disconnects_total counter\n"
			"esmule_peer_disconnects_total %ld\n"
			"# HELP esmule_active_peers Currently connected peers, by role\n"
			"# TYPE esmule_active_peers gauge\n"
			"esmule_active_peers{role=\"viewer\"} %d\n"
			"esmule_active_peers{role=\"broadcaster\"} %d\n"
			"esmule_active_peers{role=\"mesh\"} %d\n"
			"# HELP esmule_chunk_buffer_count Chunks currently held in the ring buffer\n"
			"# TYPE esmule_chunk_buffer_count gauge\n"
			"esmule_chunk_buffer_count %d\n"
			"# HELP esmule_pending_requests Outstanding chunk requests awaiting a peer reply\n"
			"# TYPE esmule_pending_requests gauge\n"
			"esmule_pending_requests %d\n"
			"# HELP esmule_broadcasting Whether this instance is broadcasting (1) or not (0)\n"
			"# TYPE esmule_broadcasting gauge\n"
			"esmule_broadcasting %d\n"
			"# HELP esmule_viewing Whether this instance is viewing a live stream (1/0)\n"
			"# TYPE esmule_viewing gauge\n"
			"esmule_viewing %d\n"
			"# HELP esmule_chunk_latency_ms Chunk arrival latency in ms (broadcaster timestamp -> our recv)\n"
			"# TYPE esmule_chunk_latency_ms summary\n"
			"esmule_chunk_latency_ms_count %d\n"
			"esmule_chunk_latency_ms_sum %lu\n"
			"esmule_chunk_latency_ms{quantile=\"0.5\"} %lu\n"
			"esmule_chunk_latency_ms{quantile=\"0.95\"} %lu\n"
			"esmule_chunk_latency_ms{quantile=\"0.99\"} %lu\n"
			"# HELP esmule_kad_searches_empty_total Searches that returned 0 hits (DISC-S11)\n"
			"# TYPE esmule_kad_searches_empty_total counter\n"
			"esmule_kad_searches_empty_total %ld\n"
			"# HELP esmule_kad_searches_rate_limited_total Searches dropped by token bucket (DISC-S08)\n"
			"# TYPE esmule_kad_searches_rate_limited_total counter\n"
			"esmule_kad_searches_rate_limited_total %ld\n"
			"# HELP esmule_pending_dials_dropped_total FIFO drops in pending dial queue (DISC-S06)\n"
			"# TYPE esmule_pending_dials_dropped_total counter\n"
			"esmule_pending_dials_dropped_total %ld\n"
			"# HELP esmule_join_to_first_chunk_ms Average ms from JoinStream to first chunk (DISC-S12)\n"
			"# TYPE esmule_join_to_first_chunk_ms summary\n"
			"esmule_join_to_first_chunk_ms_count %ld\n"
			"esmule_join_to_first_chunk_ms_sum %ld\n",
			haveSnap ? snap.counters.chunksReceived : 0L,
			haveSnap ? snap.counters.chunksRequested : 0L,
			haveSnap ? snap.counters.chunksMissing : 0L,
			haveSnap ? snap.chunksServed : 0,
			haveSnap ? snap.counters.kadPublishes : 0L,
			haveSnap ? snap.counters.kadSearches : 0L,
			haveSnap ? snap.counters.peerDisconnects : 0L,
			haveSnap ? snap.viewPeers : 0,
			haveSnap ? snap.broadcastPeers : 0,
			haveSnap ? snap.meshPeers : 0,
			haveSnap ? snap.bufCount : 0,
			haveSnap ? snap.pendingRequests : 0,
			(haveSnap && snap.broadcasting) ? 1 : 0,
			(haveSnap && snap.viewing) ? 1 : 0,
			nLat,
			(unsigned long)((uint64)mean * (uint64)nLat),
			(unsigned long)p50,
			(unsigned long)p95,
			(unsigned long)p99,
			haveSnap ? snap.counters.kadSearchesEmpty : 0L,
			haveSnap ? snap.counters.kadSearchesRateLimited : 0L,
			haveSnap ? snap.counters.pendingDialsDropped : 0L,
			haveSnap ? snap.counters.joinToFirstChunkSamples : 0L,
			haveSnap ? snap.counters.joinToFirstChunkSumMs : 0L);
		try {
			const std::string kad6Metrics = eSELive::CLiveTunnel::Get().GetK6PrometheusMetrics();
			body += CStringA(kad6Metrics.c_str());
		} catch (...) {}

		CStringA hdr;
		hdr.Format(
			"HTTP/1.1 200 OK\r\n"
			"Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n"
			"Cache-Control: no-store\r\n"
			"Access-Control-Allow-Origin: *\r\n"
			"Content-Length: %d\r\n\r\n",
			body.GetLength());
		Data.pSocket->SendData(hdr, hdr.GetLength());
		Data.pSocket->SendData(body, body.GetLength());
		return;
	}

	// --- /api/live/log --- Tail of the in-process live debug log.
	// Returns JSON {"items":["HH:MM:SS [TAG] msg", ...]} oldest first. Used by
	// the MFC "Live Stream" tab and the web /live debug panel to surface the
	// same internal events that previously only went to AddLogLine().
	// ?n=N selects the last N entries (default 100, max 500).
	if (Data.webRoute == ese::web::WebRouteId::ApiLiveLog) {
		int n = _ttoi(_ParseURL(Data.sURL, _T("n")));
		if (n <= 0) n = 100;
		if (n > 500) n = 500;

		std::deque<CStringA> items;
		CLiveDebugLog::Get().GetRecent(n, items);

		ese::web::WebStringArrayResponseModel model;
		model.field_name = "items";
		model.values.reserve(items.size());
		for (const auto& l : items) {
			model.values.emplace_back(
				static_cast<LPCSTR>(l),
				static_cast<std::size_t>(l.GetLength()));
		}
		const ese::web::SerializedWebResponse response =
			ese::web::Serialize(model);
		const CStringA json(
			response.body.data(),
			static_cast<int>(response.body.size()));

		CStringA header;
		header.Format(
			"HTTP/1.1 %u %s\r\n"
			"Content-Type: %s\r\n"
			"Cache-Control: no-store\r\n"
			"Access-Control-Allow-Origin: *\r\n"
			"Content-Length: %d\r\n\r\n",
			response.status_code,
			response.reason_phrase.c_str(),
			response.content_type.c_str(),
			json.GetLength());
		Data.pSocket->SendData(header, header.GetLength());
		Data.pSocket->SendData(json, json.GetLength());
		return;
	}

	// --- /api/live/diagnose --- DISC-S10: comprehensive self-diagnostic.
	// Returns JSON with everything a user/support engineer needs to figure
	// out why a stream isn't discoverable. Usage: /api/live/diagnose?key=HEX32
	// (key is optional — without it, returns global discovery state).
	if (Data.webRoute == ese::web::WebRouteId::ApiLiveDiagnose) {
		CString keyT(_ParseURL(Data.sURL, _T("key")));
		uchar streamKey[16] = {0};
		bool keyValid = false;
		if (keyT.GetLength() == 32) {
			CStringA keyA = CT2A(keyT);
			keyValid = EseHexToKey16A(keyA, streamKey);
		}

		// Gather state under no lock — these accessors are atomic/snapshot.
		bool kadConnected = Kademlia::CKademlia::IsConnected();
		bool isBroadcasting = (theApp.liveStreamManager
			&& theApp.liveStreamManager->IsBroadcasting());
		bool isViewing = (theApp.liveStreamManager
			&& theApp.liveStreamManager->IsViewingLive());
		uint32 publicIP = theApp.GetPublicIP();
		uint16 tcpPort = theApp.GetAdvertisedTcpPort();

		LiveStreamEntry entry;
		bool inDirectory = false;
		if (keyValid && theApp.liveStreamManager) {
			inDirectory = theApp.liveStreamManager->GetKadBridge().GetStreamInfo(streamKey, entry);
		}
		int totalKnown = theApp.liveStreamManager
			? theApp.liveStreamManager->GetKadBridge().GetDirectoryCount() : 0;

		CStringA json;
		CStringA entryJson = "null";
		if (inDirectory) {
			const CStringA titleA =
				EseJsonEscapeA(CStringA(CT2A(entry.title)));
			CStringA t;
			t.Format("{\"title\":\"%s\",\"ip\":\"%s\",\"port\":%u,"
			         "\"bitrate\":%u,\"viewerCount\":%u,"
			         "\"lastSeenAgeMs\":%u,\"isOwn\":%s}",
				(LPCSTR)titleA,
				(LPCSTR)CStringA(ipstr(entry.broadcasterIP)),
				(unsigned)entry.broadcasterPort,
				(unsigned)entry.bitrate,
				(unsigned)entry.viewerCount,
				(unsigned)(GetTickCount() - entry.lastSeen),
				entry.isOwnStream ? "true" : "false");
			entryJson = t;
		}

		json.Format(
			"{\"keyProvided\":%s,\"keyValid\":%s,"
			"\"kadConnected\":%s,\"publicIP\":\"%s\",\"tcpPort\":%u,"
			"\"isBroadcasting\":%s,\"isViewing\":%s,"
			"\"directorySize\":%d,\"streamInDirectory\":%s,"
			"\"directoryEntry\":%s,"
			"\"hint\":\"%s\"}",
			keyT.IsEmpty() ? "false" : "true",
			keyValid ? "true" : "false",
			kadConnected ? "true" : "false",
			(LPCSTR)CStringA(ipstr(publicIP)),
			(unsigned)tcpPort,
			isBroadcasting ? "true" : "false",
			isViewing ? "true" : "false",
			totalKnown,
			inDirectory ? "true" : "false",
			(LPCSTR)entryJson,
			(!kadConnected) ? "Kad is not connected. Wait or check firewall."
			: (keyValid && !inDirectory) ? "Stream not in local directory. Run JoinStream first or wait for Kad propagation."
			: (isBroadcasting && !publicIP) ? "Broadcasting but no public IP detected. Check UPnP / port forward."
			: "OK");

		CStringA hdr;
		hdr.Format(
			"HTTP/1.1 200 OK\r\n"
			"Content-Type: application/json\r\n"
			"Cache-Control: no-store\r\n"
			"Access-Control-Allow-Origin: *\r\n"
			"Content-Length: %d\r\n\r\n",
			json.GetLength());
		Data.pSocket->SendData(hdr, hdr.GetLength());
		Data.pSocket->SendData(json, json.GetLength());
		return;
	}

	// --- /api/live/direct_join --- Bypass Kad: connect directly to a known peer.
	// Accepts either:
	//   ?link=ed2k://|live|HEXKEY|IP:PORT|TITLE|/
	//   ?link=ed2k://|live|HEXKEY|[IPv6]:PORT|TITLE|/
	//   ?key=HEXKEY&ip=1.2.3.4&port=4662&title=My+Stream
	// The "live" link is the format the broadcaster's Share panel produces when
	// its public IP is known. Direct Join skips the 30s Kad search cooldown and
	// the multi-minute DHT propagation delay — the viewer can connect within
	// seconds of the broadcaster pressing START.
	if (Data.webRoute == ese::web::WebRouteId::ApiLiveDirectJoin) {
		CString linkT(_ParseURL(Data.sURL, _T("link")));
		CString keyT (_ParseURL(Data.sURL, _T("key")));
		CString ipT  (_ParseURL(Data.sURL, _T("ip")));
		CString portT(_ParseURL(Data.sURL, _T("port")));
		CString titleT(_ParseURL(Data.sURL, _T("title")));

		// If a full link was provided, parse "ed2k://|live|HEX|IP:PORT|TITLE|/"
		if (!linkT.IsEmpty() && keyT.IsEmpty()) {
			// Tokenize on '|'. Expected order: ["ed2k://", "live", HEX, IP:PORT, TITLE, "/"]
			CStringArray parts;
			int start = 0;
			while (start <= linkT.GetLength()) {
				int end = linkT.Find(_T('|'), start);
				if (end < 0) end = linkT.GetLength();
				parts.Add(linkT.Mid(start, end - start));
				start = end + 1;
			}
			if (parts.GetCount() >= 5
				&& parts[1].CompareNoCase(_T("live")) == 0)
			{
				keyT = parts[2];
				CString ipPort = parts[3];
				if (!ipPort.IsEmpty() && ipPort[0] == _T('[')) {
					const int closeBracket = ipPort.Find(_T(']'));
					if (closeBracket > 1 && closeBracket + 1 < ipPort.GetLength()
						&& ipPort[closeBracket + 1] == _T(':')) {
						ipT   = ipPort.Mid(1, closeBracket - 1);
						portT = ipPort.Mid(closeBracket + 2);
					}
				} else {
					const int colon = ipPort.ReverseFind(_T(':'));
					if (colon > 0) {
						ipT   = ipPort.Left(colon);
						portT = ipPort.Mid(colon + 1);
					}
				}
				if (titleT.IsEmpty() && parts.GetCount() >= 5)
					titleT = parts[4];
			}
		}
		if (titleT.IsEmpty())
			titleT = _T("Live");

		uchar streamKey[16];
		bool keyOk = (theApp.liveStreamManager != NULL);
		if (keyOk) {
			CStringA keyA = CT2A(keyT);
			keyOk = EseHexToKey16A(keyA, streamKey);
		}

		// Anonymous links (ed2k://|live|HEX||TITLE|/) carry no IP — that's
		// the privacy default. We must NOT bail out here; instead we fall
		// back to a Kad-only join so the viewer searches the DHT for the
		// broadcaster's IP. The previous code returned 400 Bad Request and
		// the UI just showed "no hace nada".
		CAddress directAddress;
		uint16 port  = 0;
		if (keyOk && !ipT.IsEmpty() && !portT.IsEmpty()) {
			port  = (uint16)_ttoi(portT);
			CAddress parsed(ipT, false);
			uint32 ipv4 = 0;
			const bool validIPv4 = parsed.GetType() == CAddress::IPv4
				&& parsed.TryToUInt32(ipv4) && ipv4 != 0 && ipv4 != INADDR_NONE;
			const bool validIPv6 = parsed.GetType() == CAddress::IPv6
				&& parsed.IsUsableDirectIPv6();
			if (port != 0 && (validIPv4 || validIPv6)) {
				directAddress = parsed;
			} else {
				directAddress = CAddress();
				port = 0;  // treat as anonymous
			}
		}

		bool joined = false;
		bool dialed = false;
		const ProxySettings& proxy = thePrefs.GetProxySettings();
		const bool unsupportedIPv6Proxy =
			directAddress.GetType() == CAddress::IPv6
			&& proxy.bUseProxy
			&& (proxy.type == PROXYTYPE_SOCKS4
				|| proxy.type == PROXYTYPE_SOCKS4A);
		if (keyOk && !unsupportedIPv6Proxy) {
			// JoinStream + TryConnectToStreamSource mutate Live state and touch
			// Kad / the eD2K sockets — marshal both to the main thread in one
			// round-trip. This worker holds no Live lock, so the blocking
			// SendMessage cannot deadlock. Direct dial happens only when the
			// link carried an explicit endpoint; otherwise the Kad search
			// kicked off inside JoinStream finds the broadcaster.
			LiveWebJoinReq req;
			req.streamKey = streamKey;
			req.title     = titleT;
			req.address   = directAddress;
			req.port      = port;
			req.joined    = false;
			req.dialed    = false;
			if (theApp.emuledlg != NULL)
				theApp.emuledlg->SendMessage(UM_LIVE_WEB_JOIN, 0, (LPARAM)&req);
			joined = req.joined;
			dialed = req.dialed;
		}

		// SUCCESS = the join was accepted by the manager. For anonymous
		// links, dialed=false is expected — the search runs in background.
		const bool overall = keyOk && joined && !unsupportedIPv6Proxy;
		const char* error = unsupportedIPv6Proxy
			? "ipv6_not_supported_by_socks4"
			: (!keyOk ? "invalid_stream_key"
				: (!joined ? "join_rejected" : ""));
		const bool direct = directAddress.GetType() != CAddress::None && port != 0;
		const char* mode = unsupportedIPv6Proxy ? "rejected" :
			(direct ? "direct" : "kad-search");
		const char* hint = unsupportedIPv6Proxy
			? "SOCKS4/SOCKS4A cannot represent an IPv6 destination; use "
				"SOCKS5 or HTTP CONNECT"
			: overall
				? (direct
					? "Dialing broadcaster directly"
					: "Anonymous link — searching Kad for the broadcaster (5-30 s)")
				: (keyOk
					? "JoinStream rejected"
					: "Bad streamKey or eMule not ready");
		const CStringA keyA = CStringA(CT2A(keyT));
		const CStringA ipA = CStringA(CT2A(ipT));
		const ese::web::SerializedWebResponse response =
			ese::web::Serialize(ese::web::WebDirectJoinResponseModel{
				overall,
				joined,
				dialed,
				error,
				std::string(
					static_cast<LPCSTR>(keyA),
					static_cast<std::size_t>(keyA.GetLength())),
				std::string(
					static_cast<LPCSTR>(ipA),
					static_cast<std::size_t>(ipA.GetLength())),
				static_cast<unsigned>(port),
				mode,
				hint});
		const CStringA json(
			response.body.data(),
			static_cast<int>(response.body.size()));
		CStringA header;
		header.Format(
			"HTTP/1.1 %u %s\r\n"
			"Content-Type: %s\r\n"
			"Access-Control-Allow-Origin: http://127.0.0.1\r\n"
			"X-Content-Type-Options: nosniff\r\n"
			"Content-Length: %d\r\n\r\n",
			response.status_code,
			response.reason_phrase.c_str(),
			response.content_type.c_str(),
			json.GetLength());
		Data.pSocket->SendData(header, header.GetLength());
		Data.pSocket->SendData(json, json.GetLength());
		return;
	}

	// --- /api/live/channels --- JSON list of active streams
	if (Data.webRoute == ese::web::WebRouteId::ApiLiveChannels) {
		CStringA json = "{\"channels\":[";
		if (theApp.liveStreamManager != NULL) {
			LiveChannelSnapshot ch = theApp.liveStreamManager->GetChannelSnapshot();
			if (ch.broadcasting) {
			// Single broadcast model â€” expose our current stream
				CStringA hashHex = EseHexKey16A(ch.streamKey);
				CStringA titleA = EseJsonEscapeA(CStringA(CT2A((LPCTSTR)ch.title)));
				CStringA categoryA = EseJsonEscapeA(CStringA(CT2A((LPCTSTR)ch.category)));
				CStringA languageA = EseJsonEscapeA(CStringA(CT2A((LPCTSTR)ch.language)));
				uint32 br = ch.bitrate;
				const char* quality = "SD";
				if (br >= 8000) quality = "4K";
				else if (br >= 5000) quality = "FHD";
				else if (br >= 3000) quality = "HD";

				json.AppendFormat(
					"{\"hash\":\"%s\",\"title\":\"%s\",\"category\":\"%s\","
					"\"language\":\"%s\",\"startedAt\":%u,"
					"\"viewers\":%u,\"bitrate\":%u,\"quality\":\"%s\"}",
					(LPCSTR)hashHex, (LPCSTR)titleA, (LPCSTR)categoryA,
					(LPCSTR)languageA, ch.startedAt,
					ch.viewerCount,
					br, quality);
			}
		}
		json += "]}";

		CStringA header;
		header.Format(
			"HTTP/1.1 200 OK\r\n"
			"Content-Type: application/json\r\n"
			"Access-Control-Allow-Origin: http://127.0.0.1\r\n"
			"X-Content-Type-Options: nosniff\r\n"
			"Content-Length: %d\r\n\r\n", json.GetLength());
		Data.pSocket->SendData(header, header.GetLength());
		Data.pSocket->SendData(json, json.GetLength());
		return;
	}

	// --- /api/live/mesh --- Core P2P mesh stats for the Node bridge
	if (Data.webRoute == ese::web::WebRouteId::ApiLiveMesh) {
		ese::web::WebLiveMeshDiagnostics mesh;
		if (theApp.liveStreamManager != NULL) {
			// Lock-correct snapshot — BuildDebugSnapshot runs the trust-tier
			// census under m_lock. Never iterate m_peerBitmaps or dereference
			// CUpDownClient* / GetPeerTrust() from this worker thread.
			LiveDebugSnapshot s = theApp.liveStreamManager->BuildDebugSnapshot();
			mesh.mesh_peers = s.meshPeers;
			mesh.pending_requests = s.pendingRequests;
			mesh.chunks_served = s.chunksServed;
			mesh.total_redistributed = s.totalRedistributed;
			mesh.super_seeders = s.superSeeders;
			mesh.middle_peers = s.middlePeers;
			mesh.leaf_peers = s.leafPeers;
			mesh.upload_floor = s.minUploadRequired;
			mesh.emergency_mode = s.emergencyMode;
		}
		const std::string body =
			ese::web::WebDiagnostics::Serialize(mesh);
		const CStringA json(body.data(), static_cast<int>(body.size()));

		CStringA header;
		header.Format(
			"HTTP/1.1 200 OK\r\n"
			"Content-Type: application/json\r\n"
			"Access-Control-Allow-Origin: http://127.0.0.1\r\n"
			"X-Content-Type-Options: nosniff\r\n"
			"Content-Length: %d\r\n\r\n", json.GetLength());
		Data.pSocket->SendData(header, header.GetLength());
		Data.pSocket->SendData(json, json.GetLength());
		return;
	}

	// --- /api/live/kad/streams --- Kad-discovered live stream directory
	if (Data.webRoute == ese::web::WebRouteId::ApiLiveKadStreams) {
		CArray<LiveStreamEntry> streams;
		if (theApp.liveStreamManager != NULL) {
			// SearchStreams drives CSearchManager and adds a row to the Kad
			// search-list UI control (InsertItem -> cross-thread SendMessage),
			// all main-thread only. On this webserver worker it would hold the
			// KadBridge lock across that SendMessage and deadlock the UI
			// thread. Marshal the search to the main thread; the worker just
			// reads the already-cached directory below.
			if (theApp.emuledlg != NULL)
				theApp.emuledlg->PostMessage(UM_LIVE_KAD_REFRESH);
			theApp.liveStreamManager->GetKadBridge().GetKnownStreams(streams);
		}

		CStringA json;
		json.Format("{\"kadConnected\":%s,\"streams\":[",
			Kademlia::CKademlia::IsConnected() ? "true" : "false");

		for (INT_PTR i = 0; i < streams.GetCount(); i++) {
			const LiveStreamEntry& entry = streams[i];
			CStringA streamKey = EseHexKey16A(entry.streamKey);
			CStringA title = EseJsonEscapeA(CStringA(CT2A(entry.title)));
			CStringA category = EseJsonEscapeA(CStringA(CT2A(entry.category)));
			CStringA language = EseJsonEscapeA(CStringA(CT2A(entry.language)));

			if (i > 0)
				json += ",";

			json.AppendFormat(
				"{\"streamKey\":\"%s\","
				"\"title\":\"%s\","
				"\"category\":\"%s\","
				"\"language\":\"%s\","
				"\"bitrate\":%u,"
				"\"viewers\":%u,"
				"\"broadcasterIP\":%u,"
				"\"broadcasterPort\":%u,"
				"\"startedAt\":%u,"
				"\"lastSeenAgeMs\":%u,"
				"\"own\":%s,"
				"\"privacyOrigin\":\"%s\","
				"\"source\":\"kad\"}",
				(LPCSTR)streamKey,
				(LPCSTR)title,
				(LPCSTR)category,
				(LPCSTR)language,
				entry.bitrate,
				entry.viewerCount,
				entry.broadcasterIP,
				entry.broadcasterPort,
				entry.startedAt,
				GetTickCount() - entry.lastSeen,
				entry.isOwnStream ? "true" : "false",
				entry.privacyOrigin == ESE_PRIV_ORIGIN_KAD6_TUNNEL
					? "kad6_tunnel" : "direct");
		}
		json += "]}";

		CStringA header;
		header.Format(
			"HTTP/1.1 200 OK\r\n"
			"Content-Type: application/json\r\n"
			"Access-Control-Allow-Origin: http://127.0.0.1\r\n"
			"X-Content-Type-Options: nosniff\r\n"
			"Content-Length: %d\r\n\r\n", json.GetLength());
		Data.pSocket->SendData(header, header.GetLength());
		Data.pSocket->SendData(json, json.GetLength());
		return;
	}


#ifdef ESE_TEST_HOOKS
	// --- /api/live/test/edge_sabotage?on=1&mode=drop|delay&delay=6000 ---
	// TEST-ONLY (rogue node R): toggle selective live-edge sabotage in
	// OnPeerRequest for the 3-PC validation recipe. Compiled ONLY under
	// ESE_TEST_HOOKS, so the honest/production binary never links this route.
	// Loopback-only (the generic /api/live/ remote gate above already blocks
	// non-local callers); no full-trust requirement since it's a local test op.
	if (Data.webRoute == ese::web::WebRouteId::ApiLiveEdgeSabotage) {
		extern bool  g_eseTestSabotageOn;
		extern int   g_eseTestSabotageMode;
		extern DWORD g_eseTestSabotageDelayMs;
		CString onT   (_ParseURL(Data.sURL, _T("on")));
		CString modeT (_ParseURL(Data.sURL, _T("mode")));
		CString delayT(_ParseURL(Data.sURL, _T("delay")));
		g_eseTestSabotageOn   = (onT == _T("1"));
		g_eseTestSabotageMode = (modeT == _T("delay")) ? 1 : 0;
		int dl = _ttoi(delayT);
		g_eseTestSabotageDelayMs = (dl > 0) ? (DWORD)dl : 6000;
		CStringA json;
		json.Format("{\"ok\":true,\"on\":%s,\"mode\":\"%s\",\"delayMs\":%u}",
			g_eseTestSabotageOn ? "true" : "false",
			g_eseTestSabotageMode ? "delay" : "drop",
			g_eseTestSabotageDelayMs);
		CStringA header;
		header.Format(
			"HTTP/1.1 200 OK\r\n"
			"Content-Type: application/json\r\n"
			"Access-Control-Allow-Origin: http://127.0.0.1\r\n"
			"X-Content-Type-Options: nosniff\r\n"
			"Content-Length: %d\r\n\r\n",
			json.GetLength());
		Data.pSocket->SendData(header, header.GetLength());
		Data.pSocket->SendData(json, json.GetLength());
		return;
	}
#endif

	// --- /api/live/debug --- Phase 0 Observability (OBS-1)
	// Fix 1 (ALTA): All state is read via BuildDebugSnapshot() under m_lock.
	// No direct CMap/CTypedPtrList iteration from the WebServer thread.
	if (Data.webRoute == ese::web::WebRouteId::ApiLiveDebug) {
		ese::web::WebLiveDebugDiagnostics debug;

		if (theApp.liveStreamManager != NULL) {
			LiveDebugSnapshot s = theApp.liveStreamManager->BuildDebugSnapshot();
			debug.available = true;
			debug.broadcasting = s.broadcasting;
			debug.viewing = s.viewing;
			debug.emergency_mode = s.emergencyMode;
			debug.uptime_ms = s.uptimeMs;
			debug.total_redistributed = s.totalRedistributed;
			debug.now_ms = GetTickCount();
			debug.kad_connected = s.kad.kadConnected;
			debug.known_streams = s.kad.knownStreams;
			debug.known_streams_clean = s.kad.knownStreamsClean;
			debug.known_streams_legacy = s.kad.knownStreamsLegacy;
			debug.last_publish_time = s.kad.lastPublishTime;
			debug.last_search_time = s.kad.lastSearchTime;
			debug.last_result_time = s.kad.lastResultTime;
			debug.last_result_ip = s.kad.lastResultIP;
			debug.last_result_port = s.kad.lastResultPort;
			debug.view_peers = s.viewPeers;
			debug.broadcast_peers = s.broadcastPeers;
			debug.mesh_peers = s.meshPeers;
			debug.pending_requests = s.pendingRequests;
			debug.chunks_served = s.chunksServed;
			debug.super_seeders = s.superSeeders;
			debug.middle_peers = s.middlePeers;
			debug.leaf_peers = s.leafPeers;
			debug.chunk_count = s.bufCount;
			debug.oldest_sequence = s.oldestSeq;
			debug.newest_sequence = s.newestSeq;
			debug.chunk_bitmap = s.bitmap;
			debug.missing_chunks = s.missingChunks;
			debug.max_capacity = ESE_LIVE_MAX_SEGMENTS;
			debug.hls_segments_written = s.counters.hlsSegmentsWritten;
			debug.hls_playlist_refreshes = s.counters.hlsPlaylistRefresh;
			debug.last_chunk_received_at =
				static_cast<std::uint32_t>(
					s.counters.lastChunkReceivedAt);
			debug.segment_duration_seconds = ESE_LIVE_SEGMENT_DURATION;
			debug.kad_publishes = s.counters.kadPublishes;
			debug.kad_searches = s.counters.kadSearches;
			debug.kad_results_accepted = s.counters.kadResultsAccepted;
			debug.kad_results_rejected = s.counters.kadResultsRejected;
			debug.source_dial_attempts = s.counters.sourceDialAttempts;
			debug.subscribe_sent = s.counters.subscribeSent;
			debug.subscribe_accepted = s.counters.subscribeAccepted;
			debug.chunks_requested = s.counters.chunksRequested;
			debug.chunks_received = s.counters.chunksReceived;
			debug.chunks_missing = s.counters.chunksMissing;
			debug.duplicate_chunks_received =
				s.counters.duplicateChunksReceived;
			debug.requests_suppressed_inflight =
				s.counters.requestsSuppressedInflight;
			debug.peer_disconnects = s.counters.peerDisconnects;
			debug.skipped_initial_pushes = s.counters.skippedInitialPushes;
			debug.subscribes_rate_limited =
				s.counters.subscribesRateLimited;
			debug.requests_rate_limited = s.counters.requestsRateLimited;
			debug.ends_rejected_no_auth = s.counters.endsRejectedNoAuth;
			debug.tombstones_evicted = s.counters.tombstonesEvicted;

			const int peerCount = (std::max)(
				0,
				(std::min)(
					s.peerDetailCount,
					LiveDebugSnapshot::MAX_PEER_DBG));
			debug.peer_detail.reserve(static_cast<std::size_t>(peerCount));
			for (int index = 0; index < peerCount; ++index) {
				ese::web::WebLiveDebugPeerDiagnostics peer;
				peer.ip = s.peerDetail[index].ip;
				peer.port = s.peerDetail[index].port;
				peer.level = s.peerDetail[index].level;
				peer.fail_count = s.peerDetail[index].failCount;
				peer.response_percent = s.peerDetail[index].respPct;
				peer.rtt_ms = s.peerDetail[index].rttMs;
				debug.peer_detail.push_back(peer);
			}
		}
		const std::string body =
			ese::web::WebDiagnostics::Serialize(debug);
		const CStringA json(body.data(), static_cast<int>(body.size()));

		CStringA header;
		header.Format(
			"HTTP/1.1 200 OK\r\n"
			"Content-Type: application/json\r\n"
			"Access-Control-Allow-Origin: http://127.0.0.1\r\n"
			"X-Content-Type-Options: nosniff\r\n"
			"Content-Length: %d\r\n\r\n", json.GetLength());
		Data.pSocket->SendData(header, header.GetLength());
		Data.pSocket->SendData(json, json.GetLength());
		return;
	}

	// --- /api/live/{hash}/stream.m3u8 --- Dynamic HLS playlist
	// --- /api/live/{hash}/seg_NNNNN.ts --- Segment binary data
	if (Data.webRoute == ese::web::WebRouteId::ApiLiveStream) {
		CStringA hashHex = sURL.Mid(10, 32);
		CStringA resource = sURL.Mid(43); // after "/api/live/HASH/"
		const int query = resource.Find('?');
		if (query >= 0)
			resource = resource.Left(query);

		// Ghost-viewer watchdog: a validated per-stream HLS fetch proves a
		// player is alive (404s included — startup polls count).
		if (theApp.liveStreamManager != NULL) {
			uchar requestedKey[16], viewerKey[16];
			if (EseHexToKey16A(hashHex, requestedKey)
				&& theApp.liveStreamManager->CopyViewerStreamKey(viewerKey)
				&& memcmp(requestedKey, viewerKey, 16) == 0)
				theApp.liveStreamManager->NotePlayerFetch();
		}

		// Serve HLS files directly from disk â€” no stream hash verification needed
		// (the hash routes to the correct stream but doesn't gate access)

		// Match: stream.m3u8, stream_*.m3u8 (audio renditions), seg_*.ts (segments)
		bool isHlsFile = true;
		if (isHlsFile) {
			// Serve HLS files directly from FFmpeg's output directory on disk
			// This is faster and more reliable than the P2P buffer for local viewers
			TCHAR tmpPath[MAX_PATH];
			GetTempPath(MAX_PATH, tmpPath);
			CString filePath;
			// Phase 3 FIX-2: Per-stream subdir — matches GetLiveHlsDir() isolation
			filePath.Format(_T("%seMule_RTMP\\%s\\%s"), tmpPath,
				(LPCTSTR)CString(hashHex), (LPCTSTR)CString(resource));

			ese::web::WebFileResponseOptions hlsOptions;
			hlsOptions.corsOrigin = "http://127.0.0.1";
			Data.pSocket->SendFileResponse(
				filePath,
				resource,
				Data.sRange,
				hlsOptions,
				20ull * 1024ull * 1024ull,
				true,
				false);
			return;
		}
	}

	// --- /live --- Channel discovery page
	if (Data.webRoute == ese::web::WebRouteId::LiveIndex) {
		CStringA html =
			"<!DOCTYPE html><html><head><title>eSE Live - Channels</title>"
			"<style>"
			"*{margin:0;padding:0;box-sizing:border-box}"
			"body{background:#0e0e10;color:#efeff1;font-family:system-ui,-apple-system,sans-serif}"
			".header{background:#18181b;padding:16px 24px;border-bottom:1px solid #2f2f35}"
			".header h1{font-size:22px;font-weight:700}"
			".header h1 span{color:#9147ff}"
			".grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:16px;padding:24px}"
			".card{background:#1f1f23;border-radius:8px;overflow:hidden;cursor:pointer;transition:transform .15s}"
			".card:hover{transform:translateY(-4px)}"
			".card .thumb{height:180px;background:#000;display:flex;align-items:center;justify-content:center;color:#666;font-size:14px}"
			".card .info{padding:12px}"
			".card .title{font-weight:600;font-size:15px;margin-bottom:4px}"
			".card .meta{color:#adadb8;font-size:13px}"
			".live-dot{display:inline-block;width:8px;height:8px;background:#e74c3c;border-radius:50%;margin-right:4px;animation:pulse 1.5s infinite}"
			"@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}"
			".badge{background:#e74c3c;color:#fff;padding:2px 6px;border-radius:3px;font-size:11px;font-weight:700}"
			".empty{text-align:center;padding:80px 24px;color:#666;font-size:16px}"
			"</style></head><body>"
			"<div class='header'><h1><span>eSE</span> Live Channels</h1></div>"
			"<div class='grid' id='g'></div>"
			"<div class='empty' id='e'>Loading channels...</div>"
			"<script>"
			// SEC: broadcaster-supplied title/category/quality must be HTML-escaped
			// before being inserted into the DOM. A malicious peer publishing a
			// title like <img src=x onerror=fetch('/api/live/broadcast/stop')>
			// would otherwise execute in any viewer that opens this page.
			"function esc(s){return String(s==null?'':s).replace(/[&<>\"']/g,function(c){return({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'})[c]})}"
			// M1: B = the /s/{ses}/ prefix when the page is served token-routed,
			// "" when served at /live directly — keeps every fetch and link
			// inside the authenticated namespace.
			"const B=location.pathname.replace(/\\/live\\/?$/,'');"
			"function r(){fetch(B+'/api/live/channels').then(r=>r.json()).then(d=>{"
			"const g=document.getElementById('g'),e=document.getElementById('e');"
			"g.innerHTML='';"
			"if(!d.channels||d.channels.length===0){e.textContent='No live channels right now.';e.style.display='block';return}"
			"e.style.display='none';"
			"d.channels.forEach(c=>{"
			"const card=document.createElement('div');card.className='card';"
			"card.onclick=()=>location.href=B+'/live/'+encodeURIComponent(c.hash);"
			"card.innerHTML='<div class=\"thumb\"><span class=\"badge\">LIVE</span></div>'"
			"+'<div class=\"info\"><div class=\"title\"><span class=\"live-dot\"></span>'+esc(c.title)+'</div>'"
			"+'<div class=\"meta\">'+esc(c.category)+' | '+esc(c.quality)+' | '+esc(c.viewers)+' viewers</div></div>';"
			"g.appendChild(card)})})"
			".catch(()=>{document.getElementById('e').textContent='Failed to load channels.'})}"
			"r();setInterval(r,5000);"
			"</script></body></html>";

		CStringA header;
		header.Format(
			"HTTP/1.1 200 OK\r\n"
			"Content-Type: text/html; charset=utf-8\r\n"
			"Content-Length: %d\r\n\r\n", html.GetLength());
		Data.pSocket->SendData(header, header.GetLength());
		Data.pSocket->SendData(html, html.GetLength());
		return;
	}

	// --- /live/{hash} --- Player page with HLS.js
	if (Data.webRoute == ese::web::WebRouteId::LivePlayer) {
		CStringA hash = sURL.Mid(6, 32);

		CStringA html;
		html.Format(
			"<!DOCTYPE html><html><head><title>eSE Live</title>"
			"<script src='https://cdn.jsdelivr.net/npm/hls.js@latest'></script>"
			"<style>"
			"*{margin:0;padding:0;box-sizing:border-box}"
			"body{background:#0e0e10;color:#efeff1;font-family:system-ui}"
			".player{max-width:1280px;margin:0 auto}"
			"video{width:100%%;background:#000;display:block}"
			".info{padding:16px}"
			".info h1{font-size:20px;margin-bottom:8px}"
			".badge{background:#e74c3c;color:#fff;padding:3px 8px;border-radius:4px;font-size:12px;font-weight:700;margin-right:8px}"
			".meta{color:#adadb8;font-size:14px}"
			".back{display:inline-block;color:#9147ff;text-decoration:none;padding:12px 16px;font-size:14px}"
			".back:hover{text-decoration:underline}"
			"</style></head><body>"
			"<a class='back' href='/live'>< Back to channels</a>"
			"<div class='player'>"
			"<video id='v' controls autoplay muted></video>"
			"<div class='info'><h1><span class='badge'>LIVE</span>Stream</h1>"
			"<div class='meta' id='m'>Connecting...</div></div></div>"
			"<script>"
			// M1: same B-prefix trick as the channels page; also fixes the back
			// link so navigation never falls out of the /s/{ses}/ namespace.
			"const v=document.getElementById('v');"
			"const B=location.pathname.split('/live/')[0];"
			"document.querySelector('.back').href=B+'/live';"
			"const src=B+'/api/live/%s/stream.m3u8';"
			// window.Hls guard: with no internet the CDN script never loads and a
			// bare Hls.isSupported() would throw, killing the native-HLS fallback
			// below (Safari/iOS plays the stream without hls.js).
			"if(window.Hls&&Hls.isSupported()){"
			"const h=new Hls({"
			"liveSyncDurationCount:3,"
			"liveMaxLatencyDurationCount:8,"
			"liveDurationInfinity:true,"
			"maxBufferLength:30,"
			"maxMaxBufferLength:60,"
			"maxBufferHole:2,"
			"highBufferWatchdogPeriod:2,"
			"nudgeOffset:0.5,"
			"manifestLoadingMaxRetry:50,"
			"levelLoadingMaxRetry:50,"
			"fragLoadingMaxRetry:50"
			"});"
			"h.loadSource(src);h.attachMedia(v);"
			"h.on(Hls.Events.MANIFEST_PARSED,()=>v.play());"
			// Audio-distortion fix (2026-06): hls.js requires the two-step media
			// recovery — if a second fatal mediaError lands shortly after a
			// recoverMediaError(), swapAudioCodec() must be called first or the
			// audio is re-appended with the wrong AAC/HE-AAC signaling and plays
			// at the wrong sample rate (the deep/slow audio after stalls).
			"let mErrAt=0;"
			"h.on(Hls.Events.ERROR,(e,d)=>{"
			"if(!d.fatal)return;"
			"if(d.type==='mediaError'){"
			"const n=Date.now();"
			"if(n-mErrAt<6000){h.swapAudioCodec()}"
			"mErrAt=n;"
			"h.recoverMediaError()"
			"}"
			"else{setTimeout(()=>{h.loadSource(src);h.attachMedia(v)},3000)}"
			"});"
			"setInterval(()=>{if(v.paused&&v.readyState>=2)v.play()},2000);"
			// Ghost-viewer fix (2026-06): tell eMule we left when the page goes
			// away (navigation/close). keepalive lets the request outlive the
			// page. The 60 s idle watchdog in Process() is the backstop for
			// killed tabs where this never fires.
			"addEventListener('pagehide',()=>{try{fetch(B+'/api/live/leave?key=%s',{keepalive:true})}catch(_){}});"
			"const langNames={eng:'English',spa:'Spanish',fre:'French',ger:'German',ita:'Italian',por:'Portuguese',jpn:'Japanese',kor:'Korean',chi:'Chinese',rus:'Russian',ara:'Arabic',und:'Track'};"
			"const langFlags={eng:'[EN]',spa:'[ES]',fre:'[FR]',ger:'[DE]',ita:'[IT]',por:'[PT]',jpn:'[JP]',rus:'[RU]',kor:'[KR]',chi:'[CN]',ara:'[AR]',und:''};"
			"function buildAudioSel(tracks,setFn){"
			"if(document.getElementById('audioSel'))return;"
			"if(!tracks||tracks.length<2)return;"
			"const sel=document.createElement('select');"
			"sel.id='audioSel';"
			"sel.style.cssText='position:absolute;top:10px;right:10px;z-index:100;background:rgba(0,0,0,0.7);color:#fff;border:1px solid #555;padding:8px 14px;border-radius:8px;font-size:14px;cursor:pointer;backdrop-filter:blur(8px)';"
			"for(let i=0;i<tracks.length;i++){"
			"const lang=tracks[i].lang||tracks[i].language||'und';"
			"const flag=langFlags[lang]||'';"
			"const name=flag+' '+(langNames[lang]||lang)+' '+(i+1);"
			"sel.innerHTML+='<option value=\"'+i+'\">'+name+'</option>';"
			"}"
			"sel.onchange=()=>setFn(parseInt(sel.value));"
			"document.querySelector('.player').style.position='relative';"
			"document.querySelector('.player').appendChild(sel);"
			"}"
			"h.on(Hls.Events.AUDIO_TRACKS_UPDATED,()=>{"
			"const t=h.audioTrackController?h.audioTrackController.audioTracks:[];"
			"buildAudioSel(t,(i)=>{h.audioTrack=i});"
			"});"
			"v.addEventListener('loadedmetadata',()=>{"
			"if(v.audioTracks&&v.audioTracks.length>=2){"
			"const t=Array.from(v.audioTracks).map(a=>({lang:a.language||'und'}));"
			"buildAudioSel(t,(i)=>{"
			"for(let j=0;j<v.audioTracks.length;j++)v.audioTracks[j].enabled=(j===i);"
			"});"
			"}"
			"});"
			"}else if(v.canPlayType('application/vnd.apple.mpegurl')){v.src=src}"
			// SEC: same escaping concern as the channels grid - title is broadcaster-controlled.
			"function esc(s){return String(s==null?'':s).replace(/[&<>\"']/g,function(c){return({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'})[c]})}"
			"fetch(B+'/api/live/channels').then(r=>r.json()).then(d=>{"
			"const ch=d.channels.find(c=>c.hash==='%s');"
			"if(ch){document.querySelector('h1').innerHTML='<span class=\"badge\">LIVE</span> '+esc(ch.title);"
			"document.getElementById('m').textContent=ch.category+' | '+ch.quality+' | '+ch.viewers+' viewers'}});"
			"</script></body></html>",
			(LPCSTR)hash, (LPCSTR)hash, (LPCSTR)hash);

		CStringA header;
		header.Format(
			"HTTP/1.1 200 OK\r\n"
			"Content-Type: text/html; charset=utf-8\r\n"
			"Content-Length: %d\r\n\r\n", html.GetLength());
		Data.pSocket->SendData(header, header.GetLength());
		Data.pSocket->SendData(html, html.GetLength());
		return;
	}

	// Fallback 404
	Data.pSocket->SendReply("HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nNot found");
}

void CWebServer::_ProcessFileReq(const ThreadData &Data)
{
	const CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	if (pThis == NULL)
		return;

	CString filename(Data.sURL);
	const CStringA requestPath(Data.sURL);

	filename.Replace(_T('/'), _T('\\'));
	if (filename[0] == _T('\\'))
		filename.Delete(0, 1);
	filename.Insert(0, thePrefs.GetMuleDirectory(EMULE_WEBSERVERDIR));

	const ULONGLONG maximumBytes =
		static_cast<ULONGLONG>(thePrefs.GetMaxWebUploadFileSizeMB()) *
		1024ull * 1024ull;

	M2AModuleHandle templateSnapshot = CaptureWebTemplateSnapshot(WebTemplateParent(pThis)); const CStringA lastModified(GetWebTemplateLastModified(WebTemplateParent(pThis)));
	const CStringA etag(GetWebTemplateETag(WebTemplateParent(pThis)));
	ese::web::WebFileResponseOptions options;
	options.lastModified.assign((LPCSTR)lastModified, lastModified.GetLength());
	options.etag.assign((LPCSTR)etag, etag.GetLength());
	Data.pSocket->SendFileResponse(
		filename,
		requestPath,
		Data.sRange,
		options,
		maximumBytes,
		false,
		true);
}

CString CWebServer::_GetWebImageNameForFileType(const CString &filename)
{
	LPCTSTR p;
	switch (GetED2KFileTypeID(filename)) {
	case ED2KFT_AUDIO:
		p = _T("audio");
		break;
	case ED2KFT_VIDEO:
		p = _T("video");
		break;
	case ED2KFT_IMAGE:
		p = _T("picture");
		break;
	case ED2KFT_PROGRAM:
		p = _T("program");
		break;
	case ED2KFT_DOCUMENT:
		p = _T("document");
		break;
	case ED2KFT_ARCHIVE:
		p = _T("archive");
		break;
	case ED2KFT_CDIMAGE:
		p = _T("cdimage");
		break;
	case ED2KFT_EMULECOLLECTION:
		p = _T("emulecollection");
		break;
	default: /*ED2KFT_ANY:*/
		p = _T("other");
	}
	return CString(p);
}

CString CWebServer::_GetClientSummary(const CUpDownClient &client)
{
	CString buffer(GetResString(IDS_CD_UNAME));
	// name
	buffer.AppendFormat(_T(" %s\n"), client.GetUserName());
	// client version
	buffer.AppendFormat(_T("%s: %s\n"), (LPCTSTR)GetResString(IDS_CD_CSOFT), (LPCTSTR)client.GetClientSoftVer());

	// uploading file
	buffer.AppendFormat(_T("%s "), (LPCTSTR)GetResString(IDS_CD_UPLOADREQ));
	const CKnownFile *file = theApp.sharedfiles->GetFileByID(client.GetUploadFileID());
	ASSERT(file);
	if (file)
		buffer += file->GetFileName();

	// transferring time
	buffer.AppendFormat(_T("\n\n%s: %s\n"), (LPCTSTR)GetResString(IDS_UPLOADTIME), (LPCTSTR)CastSecondsToHM(client.GetUpStartTimeDelay() / SEC2MS(1)));

	// transferred data (up, down, global, session)
	buffer.AppendFormat(_T("%s (%s):\n"), (LPCTSTR)GetResString(IDS_FD_TRANS), (LPCTSTR)GetResString(IDS_STATS_SESSION));
	buffer.AppendFormat(_T(".....%s: %s (%s )\n"), (LPCTSTR)GetResString(IDS_PW_CON_UPLBL), (LPCTSTR)CastItoXBytes(client.GetTransferredUp()), (LPCTSTR)CastItoXBytes(client.GetSessionUp()));
	buffer.AppendFormat(_T(".....%s: %s (%s )\n"), (LPCTSTR)GetResString(IDS_DOWNLOAD), (LPCTSTR)CastItoXBytes(client.GetTransferredDown()), (LPCTSTR)CastItoXBytes(client.GetSessionDown()));

	return buffer;
}

void CWebServer::_GetClientversionImage(const CUpDownClient &client, TCHAR pSoft[2])
{
	switch (client.GetClientSoft()) {
	case SO_EMULE:
	case SO_OLDEMULE:
		*pSoft = _T('1');
		break;
	case SO_EDONKEYHYBRID:
		*pSoft = _T('h');
		break;
	case SO_AMULE:
		*pSoft = _T('a');
		break;
	case SO_SHAREAZA:
		*pSoft = _T('s');
		break;
	case SO_MLDONKEY:
		*pSoft = _T('m');
		break;
	case SO_LPHANT:
		*pSoft = _T('l');
		break;
	case SO_URL:
		*pSoft = _T('u');
		break;
	//case SO_EDONKEY:
	default:
		*pSoft = _T('0');
	}
	pSoft[1] = _T('\0');
}

CString CWebServer::_GetCommentlist(const ThreadData &Data)
{
	const CWebServer* owner = reinterpret_cast<CWebServer*>(Data.pThis); if (owner == NULL) return CString(); uchar hash[MDX_DIGEST_SIZE]; if (!strmd4(_ParseURL(Data.sURL, _T("filehash")), hash)) return CString();
	WebCommentListInput input; input.found = theApp.downloadqueue->WithFileByID(hash, [&](CPartFile* file) { input.fileName = file->GetFileName(); for (POSITION position = file->srclist.GetHeadPosition(); position != NULL;) { const CUpDownClient* client = file->srclist.GetNext(position); if (client->HasFileRating() || !client->GetFileComment().IsEmpty()) input.rows.push_back({client->GetUserName(), client->GetClientFilename(), client->GetFileComment(), GetRateString(client->GetFileRating())}); } const CTypedPtrList<CPtrList, Kademlia::CEntry*>& entries = file->getNotes(); for (POSITION position = entries.GetHeadPosition(); position != NULL;) { const Kademlia::CEntry* entry = entries.GetNext(position); input.rows.push_back({_T(""), entry->GetCommonFileName(), entry->GetStrTagValue(Kademlia::CKadTagNameString(TAG_DESCRIPTION)), GetRateString(static_cast<UINT>(entry->GetIntTagValue(Kademlia::CKadTagNameString(TAG_FILERATING))))}); } });
	return RenderWebCommentList(input, GetWebTemplate(WebTemplateParent(owner), WebTemplateId::CommentList), GetWebTemplate(WebTemplateParent(owner), WebTemplateId::CommentListLine));
}
int AFX_CDECL CWebServer::_DownloadCmp(void *prm, void const *pv1, void const *pv2)
{
	const DownloadFiles &p1 = *reinterpret_cast<const DownloadFiles*>(pv1);
	const DownloadFiles &p2 = *reinterpret_cast<const DownloadFiles*>(pv2);
	const auto compare = [](const auto& left, const auto& right) {
		return left < right ? -1 : (left > right ? 1 : 0);
	};
	const ese::web::WebTransferDownloadComparison comparison{
		compare(p1.iFileState, p2.iFileState),
		p1.sFileType.CompareNoCase(p2.sFileType),
		p1.sFileName.CompareNoCase(p2.sFileName),
		compare(p1.m_qwFileSize, p2.m_qwFileSize),
		compare(p1.m_qwFileTransferred, p2.m_qwFileTransferred),
		compare(p1.lFileSpeed, p2.lFileSpeed),
		compare(p1.m_dblCompleted, p2.m_dblCompleted),
		compare(p1.lSourceCount, p2.lSourceCount),
		compare(p1.nFilePrio, p2.nFilePrio),
		p1.sCategory.CompareNoCase(p2.sCategory)
	};
	const SortParams* sort = static_cast<const SortParams*>(prm);
	return ese::web::WebTransferController::CompareDownload(
		static_cast<unsigned>(sort->eSort), sort->bReverse, comparison);
}

int AFX_CDECL CWebServer::_SharedCmp(void *prm, void const *pv1, void const *pv2)
{
	const SharedFiles &p1 = *reinterpret_cast<const SharedFiles*>(pv1);
	const SharedFiles &p2 = *reinterpret_cast<const SharedFiles*>(pv2);
	const auto compare = [](const auto& left, const auto& right) {
		return left < right ? -1 : (left > right ? 1 : 0);
	};
	const ese::web::WebSharedComparison comparison{
		p2.sFileState.CompareNoCase(p1.sFileState),
		p2.sFileType.CompareNoCase(p1.sFileType),
		p1.sFileName.CompareNoCase(p2.sFileName),
		compare(p1.m_qwFileSize, p2.m_qwFileSize),
		compare(p1.nFileTransferred, p2.nFileTransferred),
		compare(p1.nFileAllTimeTransferred, p2.nFileAllTimeTransferred),
		compare(p1.nFileRequests, p2.nFileRequests),
		compare(p1.nFileAllTimeRequests, p2.nFileAllTimeRequests),
		compare(p1.nFileAccepts, p2.nFileAccepts),
		compare(p1.nFileAllTimeAccepts, p2.nFileAllTimeAccepts),
		compare(p1.dblFileCompletes, p2.dblFileCompletes),
		compare(CSharedFileList::GetRealPrio(p1.nFilePriority),
			CSharedFileList::GetRealPrio(p2.nFilePriority))
	};
	const SortParams* sort = static_cast<const SortParams*>(prm);
	return ese::web::WebSharedController::Compare(
		static_cast<unsigned>(sort->eSort), sort->bReverse, comparison);
}

int AFX_CDECL CWebServer::_UploadCmp(void *prm, void const *pv1, void const *pv2)
{
	const UploadUsers &p1 = *reinterpret_cast<const UploadUsers*>(pv1);
	const UploadUsers &p2 = *reinterpret_cast<const UploadUsers*>(pv2);
	const auto compare = [](const auto& left, const auto& right) {
		return left < right ? -1 : (left > right ? 1 : 0);
	};
	const ese::web::WebTransferUploadComparison comparison{
		compare(*p1.sClientSoft, *p2.sClientSoft),
		p1.sUserName.CompareNoCase(p2.sUserName),
		p1.sClientNameVersion.CompareNoCase(p2.sClientNameVersion),
		p1.sFileName.CompareNoCase(p2.sFileName),
		compare(p1.nTransferredUp, p2.nTransferredUp),
		compare(p1.nDataRate, p2.nDataRate)
	};
	const SortParams* sort = static_cast<const SortParams*>(prm);
	return ese::web::WebTransferController::CompareUpload(
		static_cast<unsigned>(sort->eSort), sort->bReverse, comparison);
}
