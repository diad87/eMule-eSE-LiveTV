#include "stdafx.h"
#ifdef K
#undef K
#endif
#include "../cryptopp/osrng.h"
#include "../cryptopp/sha.h"   // eSE 8.14: SHA256 for challenge-response
#include <locale.h>
#include <algorithm>
#include <vector>
#include "emule.h"
#include "StringConversion.h"
#include "WebServer.h"
#include "ClientCredits.h"
#include "ClientList.h"
#include "DownloadQueue.h"
#include "ED2KLink.h"
#include "emuledlg.h"
#include "FriendList.h"
#include "MD5Sum.h"
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
#include "QArray.h"
#include "TransferDlg.h"
#include "UploadQueue.h"
#include "UpDownClient.h"
#include "UPnPImpl.h"
#include "UPnPImplWrapper.h"
#include "UserMsgs.h"

static CryptoPP::AutoSeededRandomPool webRng;

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
	"Access-Control-Allow-Headers: Authorization, X-CSRF-Token, Content-Type\r\n"
#define HTTPInitGZ HTTPInit "Content-Encoding: gzip\r\n"
#define HTTPENCODING _T("utf-8")

#define WEB_SERVER_TEMPLATES_VERSION	7

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
	: m_Templates()
	, m_uCurIP()
	, m_iSearchSortby(3)
	, m_nIntruderDetect()
	, m_bServerWorking()
	, m_bSearchAsc()
	, m_bIsTempDisabled()
{
	CIni ini(thePrefs.GetConfigFile(), _T("WebServer"));

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
}

void CWebServer::_SaveWIConfigArray(BOOL *array, int size, LPCTSTR key)
{
	CIni ini(thePrefs.GetConfigFile(), _T("WebServer"));
	ini.SerGet(false, array, size, key);
}

bool CWebServer::ReloadTemplates()
{
	//Last-Modified: <day-name>, <day> <month-name> <year> <hour>:<minute>:<second> GMT
	//Day and month names must be 3 English letters, 30 characters total.
	_locale_t locale = _tcreate_locale(LC_TIME, _T("en-US"));
	TCHAR szTime[32];
	time_t t = time(NULL);
	if (!_tcsftime_l(szTime, _countof(szTime), _T("%a, %d %b %Y %H:%M:%S GMT"), gmtime(&t), locale))
		*szTime = _T('\0');
	m_Params.sLastModified = szTime;
	m_Params.sETag = MD5Sum(m_Params.sLastModified).GetHashString();

	const CString &sFile(thePrefs.GetTemplate());
	LIVE_LOG("WS", "ReloadTemplates: opening \"%S\" (exists=%d)",
		(LPCWSTR)sFile, (int)::PathFileExists(sFile));
	CStdioFile file;
	if (file.Open(sFile, CFile::modeRead | CFile::shareDenyWrite | CFile::typeText)) {
		LIVE_LOG("WS", "ReloadTemplates: file opened OK");
		CString sAll, sLine;
		while (file.ReadString(sLine))
			sAll.AppendFormat(_T("%s\n"), (LPCTSTR)sLine);
		file.Close();

		const CString &sVersion(_LoadTemplate(sAll, _T("TMPL_VERSION")));
		LIVE_LOG("WS", "ReloadTemplates: TMPL_VERSION=\"%S\" (need >= %d)",
			(LPCWSTR)sVersion, WEB_SERVER_TEMPLATES_VERSION);
		if (_tstol(sVersion) >= WEB_SERVER_TEMPLATES_VERSION) {
			m_Templates.sHeader = _LoadTemplate(sAll, _T("TMPL_HEADER"));
			m_Templates.sHeaderStylesheet = _LoadTemplate(sAll, _T("TMPL_HEADER_STYLESHEET"));
			m_Templates.sFooter = _LoadTemplate(sAll, _T("TMPL_FOOTER"));
			m_Templates.sServerList = _LoadTemplate(sAll, _T("TMPL_SERVER_LIST"));
			m_Templates.sServerLine = _LoadTemplate(sAll, _T("TMPL_SERVER_LINE"));
			m_Templates.sTransferImages = _LoadTemplate(sAll, _T("TMPL_TRANSFER_IMAGES"));
			m_Templates.sTransferList = _LoadTemplate(sAll, _T("TMPL_TRANSFER_LIST"));
			m_Templates.sTransferDownHeader = _LoadTemplate(sAll, _T("TMPL_TRANSFER_DOWN_HEADER"));
			m_Templates.sTransferDownFooter = _LoadTemplate(sAll, _T("TMPL_TRANSFER_DOWN_FOOTER"));
			m_Templates.sTransferDownLine = _LoadTemplate(sAll, _T("TMPL_TRANSFER_DOWN_LINE"));
			m_Templates.sTransferUpHeader = _LoadTemplate(sAll, _T("TMPL_TRANSFER_UP_HEADER"));
			m_Templates.sTransferUpFooter = _LoadTemplate(sAll, _T("TMPL_TRANSFER_UP_FOOTER"));
			m_Templates.sTransferUpLine = _LoadTemplate(sAll, _T("TMPL_TRANSFER_UP_LINE"));
			m_Templates.sTransferUpQueueShow = _LoadTemplate(sAll, _T("TMPL_TRANSFER_UP_QUEUE_SHOW"));
			m_Templates.sTransferUpQueueHide = _LoadTemplate(sAll, _T("TMPL_TRANSFER_UP_QUEUE_HIDE"));
			m_Templates.sTransferUpQueueLine = _LoadTemplate(sAll, _T("TMPL_TRANSFER_UP_QUEUE_LINE"));
			m_Templates.sTransferUpQueueBannedShow = _LoadTemplate(sAll, _T("TMPL_TRANSFER_UP_QUEUE_BANNED_SHOW"));
			m_Templates.sTransferUpQueueBannedHide = _LoadTemplate(sAll, _T("TMPL_TRANSFER_UP_QUEUE_BANNED_HIDE"));
			m_Templates.sTransferUpQueueBannedLine = _LoadTemplate(sAll, _T("TMPL_TRANSFER_UP_QUEUE_BANNED_LINE"));
			m_Templates.sTransferUpQueueFriendShow = _LoadTemplate(sAll, _T("TMPL_TRANSFER_UP_QUEUE_FRIEND_SHOW"));
			m_Templates.sTransferUpQueueFriendHide = _LoadTemplate(sAll, _T("TMPL_TRANSFER_UP_QUEUE_FRIEND_HIDE"));
			m_Templates.sTransferUpQueueFriendLine = _LoadTemplate(sAll, _T("TMPL_TRANSFER_UP_QUEUE_FRIEND_LINE"));
			m_Templates.sSharedList = _LoadTemplate(sAll, _T("TMPL_SHARED_LIST"));
			m_Templates.sSharedLine = _LoadTemplate(sAll, _T("TMPL_SHARED_LINE"));
			m_Templates.sGraphs = _LoadTemplate(sAll, _T("TMPL_GRAPHS"));
			m_Templates.sLog = _LoadTemplate(sAll, _T("TMPL_LOG"));
			m_Templates.sServerInfo = _LoadTemplate(sAll, _T("TMPL_SERVERINFO"));
			m_Templates.sDebugLog = _LoadTemplate(sAll, _T("TMPL_DEBUGLOG"));
			m_Templates.sStats = _LoadTemplate(sAll, _T("TMPL_STATS"));
			m_Templates.sPreferences = _LoadTemplate(sAll, _T("TMPL_PREFERENCES"));
			m_Templates.sLogin = _LoadTemplate(sAll, _T("TMPL_LOGIN"));
			m_Templates.sAddServerBox = _LoadTemplate(sAll, _T("TMPL_ADDSERVERBOX"));
			m_Templates.sSearch = _LoadTemplate(sAll, _T("TMPL_SEARCH"));
			m_Templates.iProgressbarWidth = (uint16)_tstoi(_LoadTemplate(sAll, _T("PROGRESSBARWIDTH")));
			m_Templates.sSearchHeader = _LoadTemplate(sAll, _T("TMPL_SEARCH_RESULT_HEADER"));
			m_Templates.sSearchResultLine = _LoadTemplate(sAll, _T("TMPL_SEARCH_RESULT_LINE"));
			m_Templates.sProgressbarImgs = _LoadTemplate(sAll, _T("PROGRESSBARIMGS"));
			m_Templates.sProgressbarImgsPercent = _LoadTemplate(sAll, _T("PROGRESSBARPERCENTIMG"));
			m_Templates.sCatArrow = _LoadTemplate(sAll, _T("TMPL_CATARROW"));
			m_Templates.sDownArrow = _LoadTemplate(sAll, _T("TMPL_DOWNARROW"));
			m_Templates.sUpArrow = _LoadTemplate(sAll, _T("TMPL_UPARROW"));
			m_Templates.sDownDoubleArrow = _LoadTemplate(sAll, _T("TMPL_DNDOUBLEARROW"));
			m_Templates.sUpDoubleArrow = _LoadTemplate(sAll, _T("TMPL_UPDOUBLEARROW"));
			m_Templates.sKad = _LoadTemplate(sAll, _T("TMPL_KADDLG"));
			m_Templates.sBootstrapLine = _LoadTemplate(sAll, _T("TMPL_BOOTSTRAPLINE"));
			m_Templates.sMyInfoLog = _LoadTemplate(sAll, _T("TMPL_MYINFO"));
			m_Templates.sCommentList = _LoadTemplate(sAll, _T("TMPL_COMMENTLIST"));
			m_Templates.sCommentListLine = _LoadTemplate(sAll, _T("TMPL_COMMENTLIST_LINE"));

			m_Templates.sProgressbarImgsPercent.Replace(_T("[PROGRESSGIFNAME]"), _T("%s"));
			m_Templates.sProgressbarImgsPercent.Replace(_T("[PROGRESSGIFINTERNAL]"), _T("%i"));
			m_Templates.sProgressbarImgs.Replace(_T("[PROGRESSGIFNAME]"), _T("%s"));
			m_Templates.sProgressbarImgs.Replace(_T("[PROGRESSGIFINTERNAL]"), _T("%i"));
			return true;
		}
		if (thePrefs.GetWSIsEnabled() || m_bServerWorking) {
			CString buffer;
			buffer.Format(GetResString(IDS_WS_ERR_LOADTEMPLATE), (LPCTSTR)sFile);
			AddLogLine(true, buffer);
			LIVE_LOG("WS", "ReloadTemplates: VERSION TOO OLD — popup + StopServer");
			AfxMessageBox(buffer, MB_OK);
			StopServer();
		}
	} else if (m_bServerWorking) {
		AddLogLine(true, GetResString(IDS_WEB_ERR_CANTLOAD), (LPCTSTR)sFile);
		LIVE_LOG("WS", "ReloadTemplates: file.Open FAILED — calling StopServer (this is what kills the WebServer)");
		StopServer();
	} else {
		LIVE_LOG("WS", "ReloadTemplates: file.Open FAILED but server not working anyway — no-op");
	}
	return false;
}

CString CWebServer::_LoadTemplate(const CString &sAll, const CString &sTemplateName)
{
	int len = sTemplateName.GetLength();
	CString sTemplate;
	sTemplate.Format(_T("<--%s-->"), (LPCTSTR)sTemplateName);
	int nStart = sAll.Find(sTemplate);
	sTemplate.Insert(len + 3, _T("_END"));
	int nEnd = sAll.Find(sTemplate);
	if (nStart >= 0 && nStart < nEnd) {
		nStart += len + 7;
		return sAll.Mid(nStart, nEnd - nStart - 1);
	}
	if (sTemplateName == _T("TMPL_VERSION"))
		AddLogLine(true, (LPCTSTR)GetResString(IDS_WS_ERR_LOADTEMPLATE), (LPCTSTR)sTemplateName);
	if (nStart == -1)
		AddLogLine(false, (LPCTSTR)GetResString(IDS_WEB_ERR_CANTLOAD), (LPCTSTR)sTemplateName);
	return CString();
}

//Cax2 - restarts the server with the new port settings
void CWebServer::RestartSockets()
{
	StopSockets();
	if (m_bServerWorking)
		StartSockets(this);
}

void CWebServer::StartServer()
{
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

void CWebServer::_RemoveServer(const CString &sIP, int nPort)
{
	CServer *server = theApp.serverlist->GetServerByAddress(sIP, (uint16)nPort);
	if (server != NULL)
		SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_SERVER_REMOVE, (LPARAM)server);
}

void CWebServer::_AddToStatic(const CString &sIP, int nPort)
{
	CServer *server = theApp.serverlist->GetServerByAddress(sIP, (uint16)nPort);
	if (server != NULL)
		SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_ADD_TO_STATIC, (LPARAM)server);
}

void CWebServer::_RemoveFromStatic(const CString &sIP, int nPort)
{
	CServer *server = theApp.serverlist->GetServerByAddress(sIP, (uint16)nPort);
	if (server != NULL)
		SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_REMOVE_FROM_STATIC, (LPARAM)server);
}


void CWebServer::AddStatsLine(const UpDown &line)
{
	m_Params.PointsForWeb.Add(line);
	if (m_Params.PointsForWeb.GetCount() > WEB_GRAPH_WIDTH)
		m_Params.PointsForWeb.RemoveAt(0);
}

CString CWebServer::_SpecialChars(const CString &cstr, bool noquote /*=false*/)
{
	CString str(cstr);
	str.Replace(_T("&"), _T("&amp;"));
	str.Replace(_T("<"), _T("&lt;"));
	str.Replace(_T(">"), _T("&gt;"));
	str.Replace(_T("\""), _T("&quot;"));
	if (noquote) {
		str.Replace(_T("'"), _T("&#8217;"));
		str.Replace(_T("\n"), _T("\\n"));
	}
	return str;
}

void CWebServer::_ConnectToServer(const CString &sIP, int nPort)
{
	CServer *server = theApp.serverlist->GetServerByAddress(sIP, (uint16)nPort);
	if (server != NULL)
		SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_CONNECTTOSERVER, (LPARAM)server);
}

void CWebServer::_ProcessURL(const ThreadData &Data)
{
	if (!theApp.IsRunning())
		return;

	CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	if (pThis == NULL)
		return;

	InitThreadLocale();

	//(0.29b)//////////////////////////////////////////////////////////////////
	// Here we are in real trouble! We are accessing the entire emule main thread
	// data without any synchronization!! Either we use the message pump for m_pdlgEmule
	// or use some hundreds of critical sections... For now, an exception handler
	// should avoid the worse things.
	//////////////////////////////////////////////////////////////////////////
	(void)CoInitialize(NULL);

#ifndef _DEBUG
	try {
#endif
		bool isUseGzip = thePrefs.GetWebUseGzip();

		uint32 myip = inet_addr(ipstrA(Data.inadr));

		// check for being banned
		int myfaults = 0;
		const DWORD curTick = ::GetTickCount();
		for (INT_PTR i = pThis->m_Params.badlogins.GetCount(); --i >= 0;) {
			if (curTick >= pThis->m_Params.badlogins[i].timestamp + MIN2MS(15))
				pThis->m_Params.badlogins.RemoveAt(i); // remove outdated entries
			else
				if (pThis->m_Params.badlogins[i].datalen == myip)
					++myfaults;
		}
		if (myfaults > 4) {
			Data.pSocket->SendContent(HTTPInit, _GetPlainResString(IDS_ACCESSDENIED));
			CoUninitialize();
			return;
		}

		bool justAddLink = false;
		bool login = false;
		CString sSession(_ParseURL(Data.sURL, _T("ses")));
		long lSession = _tstol(sSession);

		if (_ParseURL(Data.sURL, _T("w")) == _T("password")) {
			const CString &ip(ipstr(Data.inadr));

			if (!_ParseURL(Data.sURL, _T("c")).IsEmpty())
				// just sent password to add link remotely. Don't start a session.
				justAddLink = true;

			// eSE 8.14: Challenge-Response authentication
			{
				const CString sResponse(_ParseURL(Data.sURL, _T("r")));
				const CString sNonce(_ParseURL(Data.sURL, _T("n")));
				bool isAdmin = false;
				bool authOk  = false;

				if (!sResponse.IsEmpty() && !sNonce.IsEmpty()) {
					// New secure path: challenge-response
					authOk = _ValidateChallengeResponse(Data, sNonce, sResponse, isAdmin);
				} else {
					// Legacy fallback (TODO: remove in future version)
					const CString sPlain(_ParseURL(Data.sURL, _T("p")));
					if (!sPlain.IsEmpty()) {
						if (MD5Sum(sPlain).GetHashString() == thePrefs.GetWSPass()) {
							isAdmin = true;
							authOk = true;
						} else if (thePrefs.GetWSIsLowUserEnabled()
							&& !thePrefs.GetWSLowPass().IsEmpty()
							&& MD5Sum(sPlain).GetHashString() == thePrefs.GetWSLowPass())
						{
							authOk = true;
						}
					}
				}

				if (authOk) {
					if (!justAddLink) {
						Session ses;
						ses.admin = isAdmin;
						ses.startTime = CTime::GetCurrentTime();
						ses.lSession = lSession = (long)(webRng.GenerateWord32() & 0x7FFFFFFF);
						ses.lastcat = -thePrefs.GetCatFilter(0);
						pThis->m_Params.Sessions.Add(ses);
					}
					SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_UPDATEMYINFO, 0);
					if (isAdmin)
						AddLogLine(true, GetResString(IDS_WEB_ADMINLOGIN) + _T(" (%s)"), (LPCTSTR)ip);
					else
						AddLogLine(true, GetResString(IDS_WEB_GUESTLOGIN) + _T(" (%s)"), (LPCTSTR)ip);
					login = true;
				} else if (!sResponse.IsEmpty() || !_ParseURL(Data.sURL, _T("p")).IsEmpty()) {
					// Only log failure if user actually tried to authenticate
					LogWarning(LOG_STATUSBAR, GetResString(IDS_WEB_BADLOGINATTEMPT) + _T(" (%s)"), (LPCTSTR)ip);
					BadLogin newban = {myip, curTick};
					pThis->m_Params.badlogins.Add(newban);
					if (++myfaults > 4) {
						Data.pSocket->SendContent(HTTPInit, _GetPlainResString(IDS_ACCESSDENIED));
						CoUninitialize();
						return;
					}
				}
			}
			isUseGzip = false; // [Julien]
			if (login)	// on login, forget previous failed attempts
				for (INT_PTR i = pThis->m_Params.badlogins.GetCount(); --i >= 0;)
					if (pThis->m_Params.badlogins[i].datalen == myip)
						pThis->m_Params.badlogins.RemoveAt(i);
		}

		sSession.Format(_T("%ld"), lSession);
		if (_ParseURL(Data.sURL, _T("w")) == _T("logout"))
			_RemoveSession(Data, lSession);

		TCHAR *gzipOut = NULL;
		DWORD gzipLen = 0;
		CString Out;
		if (_IsLoggedIn(Data, lSession)) {
			bool bAdmin = _IsSessionAdmin(Data, sSession);
			if (_ParseURL(Data.sURL, _T("w")) == _T("close") && bAdmin && thePrefs.GetWebAdminAllowedHiLevFunc()) {
				theApp.m_app_state = APP_STATE_SHUTTINGDOWN;
				_RemoveSession(Data, lSession);

				// send answer...
				Out += _GetLoginScreen(Data);
				Data.pSocket->SendContent(HTTPInit, Out);

				SendMessage(theApp.emuledlg->m_hWnd, WM_CLOSE, 0, 0);

				CoUninitialize();
				return;
			}

			if (_ParseURL(Data.sURL, _T("w")) == _T("shutdown") && bAdmin) {
				_RemoveSession(Data, lSession);
				// send answer...
				Out += _GetLoginScreen(Data);
				Data.pSocket->SendContent(HTTPInit, Out);

				SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_WINFUNC, 1);

				CoUninitialize();
				return;
			}

			if (_ParseURL(Data.sURL, _T("w")) == _T("reboot") && bAdmin) {
				_RemoveSession(Data, lSession);

				// send answer...
				Out += _GetLoginScreen(Data);
				Data.pSocket->SendContent(HTTPInit, Out);

				SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_WINFUNC, 2);

				CoUninitialize();
				return;
			}

			if (_ParseURL(Data.sURL, _T("w")) == _T("commentlist")) {
				const CString &Out1(_GetCommentlist(Data));

				if (!Out1.IsEmpty()) {
					Data.pSocket->SendContent(HTTPInit, Out1);

					CoUninitialize();
					return;
				}
			} else if (_ParseURL(Data.sURL, _T("w")) == _T("getfile") && bAdmin) {
				uchar FileHash[MDX_DIGEST_SIZE];
				bool bHash = strmd4(_ParseURL(Data.sURL, _T("filehash")), FileHash);
				CKnownFile *kf = bHash ? theApp.sharedfiles->GetFileByID(FileHash) : NULL;
				if (kf) {
					if (thePrefs.GetMaxWebUploadFileSizeMB() != 0 && kf->GetFileSize() > (uint64)thePrefs.GetMaxWebUploadFileSizeMB() * 1024 * 1024) {
						Data.pSocket->SendReply("HTTP/1.1 403 Forbidden\r\n");

						CoUninitialize();
						return;
					}

					CFile file;
					if (file.Open(kf->GetFilePath(), CFile::modeRead | CFile::shareDenyWrite | CFile::typeBinary)) {
						EMFileSize filesize = kf->GetFileSize();

#define SENDFILEBUFSIZE 2048
						char *buffer = (char*)malloc(SENDFILEBUFSIZE);
						if (!buffer) {
							Data.pSocket->SendReply("HTTP/1.1 500 Internal Server Error\r\n");
							CoUninitialize();
							return;
						}

						CStringA fname(kf->GetFileName());
						CStringA szBuf;
						szBuf.Format("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
							"Content-Description: \"%s\"\r\n"
							"Content-Disposition: attachment; filename=\"%s\";\r\n"
							"Content-Transfer-Encoding: binary\r\n"
							"Content-Length: %I64u\r\n\r\n"
							, (LPCSTR)fname, (LPCSTR)fname, (uint64)filesize);
						Data.pSocket->SendData(szBuf, szBuf.GetLength());

						for (UINT r = 1; (uint64)filesize > 0 && r;) {
							r = file.Read(buffer, SENDFILEBUFSIZE);
							filesize -= r;
							Data.pSocket->SendData(buffer, r);
						}
						file.Close();

						free(buffer);
					} else
						Data.pSocket->SendReply("HTTP/1.1 404 File not found\r\n");
					CoUninitialize();
					return;
				}
			}

			Out += _GetHeader(Data, lSession);
			const CString &sPage(_ParseURL(Data.sURL, _T("w")));
			if (sPage == _T("server"))
				Out += _GetServerList(Data);
			else if (sPage == _T("shared"))
				Out += _GetSharedFilesList(Data);
			else if (sPage == _T("transfer"))
				Out += _GetTransferList(Data);
			else if (sPage == _T("search"))
				Out += _GetSearch(Data);
			else if (sPage == _T("graphs"))
				Out += _GetGraphs(Data);
			else if (sPage == _T("log"))
				Out += _GetLog(Data);
			else if (sPage == _T("sinfo"))
				Out += _GetServerInfo(Data);
			else if (sPage == _T("debuglog"))
				Out += _GetDebugLog(Data);
			else if (sPage == _T("myinfo"))
				Out += _GetMyInfo(Data);
			else if (sPage == _T("stats"))
				Out += _GetStats(Data);
			else if (sPage == _T("kad"))
				Out += _GetKadDlg(Data);
			else if (sPage == _T("options")) {
				isUseGzip = false;
				Out += _GetPreferences(Data);
			} else if (sPage.IsEmpty())
				isUseGzip = false;

			Out += _GetFooter(Data);

			if (isUseGzip) {
				bool bOk = false;
				try {
					CStringA strA(wc2utf8(Out));
					uLongf destLen = strA.GetLength() + 1024;
					gzipOut = new TCHAR[destLen];
					if (_GzipCompress((Bytef*)gzipOut, &destLen, (Bytef*)(LPCSTR)strA, strA.GetLength(), Z_DEFAULT_COMPRESSION) == Z_OK) {
						bOk = true;
						gzipLen = destLen;
					}
				} catch (...) {
					AddDebugLogLine(DLP_VERYHIGH, false, _T("*** Exception in CWebServer gzip compression"));
					ASSERT(0);
				}
				if (!bOk) {
					isUseGzip = false;
					delete[] gzipOut;
					gzipOut = NULL;
				}
			}
		} else if (justAddLink && login)
			Out += _GetRemoteLinkAddedOk(Data);
		else {
			isUseGzip = false;
			Out += justAddLink ? _GetRemoteLinkAddedFailed(Data) : _GetLoginScreen(Data);
		}

		// send answer...
		if (!isUseGzip)
			Data.pSocket->SendContent(HTTPInit, Out);
		else
			Data.pSocket->SendContent(HTTPInitGZ, gzipOut, gzipLen);

		delete[] gzipOut;

#ifndef _DEBUG
	} catch (...) {
		AddDebugLogLine(DLP_VERYHIGH, false, _T("*** Unknown exception in CWebServer::ProcessURL"));
		ASSERT(0);
	}
#endif

	CoUninitialize();
}

CString CWebServer::_ParseURLArray(CString URL, CString fieldname)
{
	URL.MakeLower();
	fieldname.MakeLower();
	CString res;
	while (!URL.IsEmpty()) {
		int pos = URL.Find(fieldname + _T('='));
		if (pos < 0)
			break;
		const CString &temp(_ParseURL(URL, fieldname));
		if (temp.IsEmpty())
			break;
		res.AppendFormat(_T("%s|"), (LPCTSTR)temp);
		URL.Delete(pos, 10);
	}
	return res;
}

CString CWebServer::_ParseURL(const CString &URL, const CString &fieldname)
{
	int findPos = URL.Find(_T('?'));
	if (findPos >= 0) {
		CString Parameter(URL.Mid(findPos + 1, URL.GetLength() - findPos - 1));

		int findLength;
		// search the field name beginning / middle and strip the rest...
		findPos = Parameter.Find(fieldname + _T('='));
		findLength = !findPos ? fieldname.GetLength() + 1 : 0;
		int iPos = Parameter.Find(_T('&') + fieldname + _T('='));
		if (iPos >= 0) {
			findPos = iPos;
			findLength = fieldname.GetLength() + 2;
		}
		if (findPos >= 0) {
			Parameter.Delete(0, findPos + findLength);
			iPos = Parameter.Find(_T('&'));
			if (iPos >= 0)
				Parameter.Truncate(iPos);
			Parameter.Replace(_T('+'), _T(' '));
			// decode value...
			return OptUtf8ToStr(URLDecode(Parameter, true));
		}
	}
	return CString();
}

CString CWebServer::_GetHeader(const ThreadData &Data, long lSession)
{
	const CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	if (pThis == NULL)
		return CString();

	CString sSession;
	sSession.Format(_T("%ld"), lSession);

	CString Out(pThis->m_Templates.sHeader);
	Out.Replace(_T("[CharSet]"), HTTPENCODING);

	//	Auto-refresh code
	const CString &sPage(_ParseURL(Data.sURL, _T("w")));
	bool bAdmin = _IsSessionAdmin(Data, lSession);

	CString sRefresh;
	if (sPage == _T("options") || sPage == _T("stats") || sPage == _T("password"))
		sRefresh += _T('0');
	else
		sRefresh.Format(_T("%d"), SEC2MS(thePrefs.GetWebPageRefresh()));

	CString swCommand(_ParseURL(Data.sURL, _T("w")));
	swCommand.AppendFormat(_T("&amp;cat=%s&amp;dummy=%u"), (LPCTSTR)_ParseURL(Data.sURL, _T("cat")), webRng.GenerateWord32());


	Out.Replace(_T("[admin]"), (bAdmin && thePrefs.GetWebAdminAllowedHiLevFunc()) ? _T("admin") : _T(""));
	Out.Replace(_T("[Session]"), sSession);
	Out.Replace(_T("[RefreshVal]"), sRefresh);
	Out.Replace(_T("[wCommand]"), swCommand);
	Out.Replace(_T("[eMuleAppName]"), _T("eMule"));
	Out.Replace(_T("[version]"), theApp.m_strCurVersionLong);
	Out.Replace(_T("[StyleSheet]"), pThis->m_Templates.sHeaderStylesheet);
	Out.Replace(_T("[WebControl]"), _GetPlainResString(IDS_WEB_CONTROL));
	Out.Replace(_T("[Transfer]"), _GetPlainResString(IDS_CD_TRANS));
	Out.Replace(_T("[Server]"), _GetPlainResString(IDS_SV_SERVERLIST));
	Out.Replace(_T("[Shared]"), _GetPlainResString(IDS_SHAREDFILES));
	Out.Replace(_T("[Graphs]"), _GetPlainResString(IDS_GRAPHS));
	Out.Replace(_T("[Log]"), _GetPlainResString(IDS_SV_LOG));
	Out.Replace(_T("[ServerInfo]"), _GetPlainResString(IDS_SV_SERVERINFO));
	Out.Replace(_T("[DebugLog]"), _GetPlainResString(IDS_SV_DEBUGLOG));
	Out.Replace(_T("[MyInfo]"), _GetPlainResString(IDS_MYINFO));
	Out.Replace(_T("[Stats]"), _GetPlainResString(IDS_SF_STATISTICS));
	Out.Replace(_T("[Options]"), _GetPlainResString(IDS_EM_PREFS));
	Out.Replace(_T("[Ed2klink]"), _GetPlainResString(IDS_SW_LINK));
	Out.Replace(_T("[Close]"), _GetPlainResString(IDS_WEB_SHUTDOWN));
	Out.Replace(_T("[Reboot]"), _GetPlainResString(IDS_WEB_REBOOT));
	Out.Replace(_T("[Shutdown]"), _GetPlainResString(IDS_WEB_SHUTDOWNSYSTEM));
	Out.Replace(_T("[WebOptions]"), _GetPlainResString(IDS_WEB_ADMINMENU));
	Out.Replace(_T("[Logout]"), _GetPlainResString(IDS_WEB_LOGOUT));
	Out.Replace(_T("[Search]"), _GetPlainResString(IDS_EM_SEARCH));
	Out.Replace(_T("[Download]"), _GetPlainResString(IDS_SW_DOWNLOAD));
	Out.Replace(_T("[Start]"), _GetPlainResString(IDS_SW_START));
	Out.Replace(_T("[Version]"), _GetPlainResString(IDS_VERSION));
	Out.Replace(_T("[VersionCheck]"), thePrefs.GetVersionCheckURL());
	Out.Replace(_T("[Kad]"), _GetPlainResString(IDS_KADEMLIA));

	Out.Replace(_T("[FileIsHashing]"), _GetPlainResString(IDS_HASHING));
	Out.Replace(_T("[FileIsErroneous]"), _GetPlainResString(IDS_ERRORLIKE));
	Out.Replace(_T("[FileIsCompleting]"), _GetPlainResString(IDS_COMPLETING));
	Out.Replace(_T("[FileDetails]"), _GetPlainResString(IDS_FD_TITLE));
	Out.Replace(_T("[FileComments]"), _GetPlainResString(IDS_CMT_SHOWALL));
	Out.Replace(_T("[ClearCompleted]"), _GetPlainResString(IDS_DL_CLEAR));
	Out.Replace(_T("[RunFile]"), _GetPlainResString(IDS_DOWNLOAD));
	Out.Replace(_T("[Resume]"), _GetPlainResString(IDS_DL_RESUME));
	Out.Replace(_T("[Stop]"), _GetPlainResString(IDS_DL_STOP));
	Out.Replace(_T("[Pause]"), _GetPlainResString(IDS_DL_PAUSE));
	Out.Replace(_T("[ConfirmCancel]"), _GetPlainResString(IDS_Q_CANCELDL2));
	Out.Replace(_T("[Cancel]"), _GetPlainResString(IDS_MAIN_BTN_CANCEL));
	Out.Replace(_T("[GetFLC]"), _GetPlainResString(IDS_DOWNLOADMOVIECHUNKS));
	Out.Replace(_T("[Rename]"), _GetPlainResString(IDS_RENAME));
	Out.Replace(_T("[Connect]"), _GetPlainResString(IDS_IRC_CONNECT));
	Out.Replace(_T("[ConfirmRemove]"), _GetPlainResString(IDS_WEB_CONFIRM_REMOVE_SERVER));
	Out.Replace(_T("[ConfirmClose]"), _GetPlainResString(IDS_WEB_MAIN_CLOSE));
	Out.Replace(_T("[ConfirmReboot]"), _GetPlainResString(IDS_WEB_MAIN_REBOOT));
	Out.Replace(_T("[ConfirmShutdown]"), _GetPlainResString(IDS_WEB_MAIN_SHUTDOWN));
	Out.Replace(_T("[RemoveServer]"), _GetPlainResString(IDS_REMOVETHIS));
	Out.Replace(_T("[StaticServer]"), _GetPlainResString(IDS_STATICSERVER));
	Out.Replace(_T("[Friend]"), _GetPlainResString(IDS_PW_FRIENDS));

	Out.Replace(_T("[PriorityVeryLow]"), _GetPlainResString(IDS_PRIOVERYLOW));
	Out.Replace(_T("[PriorityLow]"), _GetPlainResString(IDS_PRIOLOW));
	Out.Replace(_T("[PriorityNormal]"), _GetPlainResString(IDS_PRIONORMAL));
	Out.Replace(_T("[PriorityHigh]"), _GetPlainResString(IDS_PRIOHIGH));
	Out.Replace(_T("[PriorityRelease]"), _GetPlainResString(IDS_PRIORELEASE));
	Out.Replace(_T("[PriorityAuto]"), _GetPlainResString(IDS_PRIOAUTO));

	CString HTTPHelpU(_T('0'));
	CString HTTPHelpM(_T('0'));
	CString HTTPHelpV(_T('0'));
	CString HTTPHelpF(_T('0'));
	const CString &sCmd(_ParseURL(Data.sURL, _T("c")));
	bool disconnectissued = (sCmd == _T("disconnect"));
	bool connectissued = (sCmd == _T("connect"));

	CString HTTPConState, HTTPConText, HTTPHelp;
	if ((theApp.serverconnect->IsConnecting() && !disconnectissued) || connectissued) {
		HTTPConState = _T("connecting");
		HTTPConText = _GetPlainResString(IDS_CONNECTING);
	} else if (theApp.serverconnect->IsConnected() && !disconnectissued) {
		HTTPConState = theApp.serverconnect->IsLowID() ? _T("low") : _T("high");
		CServer *cur_server = theApp.serverlist->GetServerByAddress(
			theApp.serverconnect->GetCurrentServer()->GetAddress(),
			theApp.serverconnect->GetCurrentServer()->GetPort());

		if (cur_server) {
			HTTPConText = cur_server->GetListName();
			if (HTTPConText.GetLength() > SHORT_LENGTH)
				HTTPConText = HTTPConText.Left(SHORT_LENGTH - 3) + _T("...");

			if (bAdmin)
				HTTPConText.AppendFormat(_T(" (<a href=\"?ses=%s&amp;w=server&amp;c=disconnect\">%s</a>)"), (LPCTSTR)sSession, (LPCTSTR)_GetPlainResString(IDS_IRC_DISCONNECT));

			HTTPHelpU = CastItoIShort(cur_server->GetUsers());
			HTTPHelpM = CastItoIShort(cur_server->GetMaxUsers());
			HTTPHelpF = CastItoIShort(cur_server->GetFiles());
			if (cur_server->GetMaxUsers() > 0)
				HTTPHelpV.Format(_T("%.0f"), (100.0 * cur_server->GetUsers()) / cur_server->GetMaxUsers());
			else
				HTTPHelpV = _T("0");
		}

	} else {
		HTTPConState = _T("disconnected");
		HTTPConText = _GetPlainResString(IDS_DISCONNECTED);
		if (bAdmin)
			HTTPConText.AppendFormat(_T(" (<a href=\"?ses=%s&amp;w=server&amp;c=connect\">%s</a>)"), (LPCTSTR)sSession, (LPCTSTR)_GetPlainResString(IDS_CONNECTTOANYSERVER));
	}
	uint32 allUsers = 0;
	uint32 allFiles = 0;
	for (INT_PTR sc = theApp.serverlist->GetServerCount(); --sc >= 0;) {
		const CServer *cur_server = theApp.serverlist->GetServerAt(sc);
		allUsers += cur_server->GetUsers();
		allFiles += cur_server->GetFiles();
	}
	Out.Replace(_T("[AllUsers]"), CastItoIShort(allUsers));
	Out.Replace(_T("[AllFiles]"), CastItoIShort(allFiles));
	Out.Replace(_T("[ConState]"), HTTPConState);
	Out.Replace(_T("[ConText]"), HTTPConText);

	// kad status
	if (Kademlia::CKademlia::IsConnected()) {
		if (Kademlia::CKademlia::IsFirewalled()) {
			HTTPConText = GetResString(IDS_FIREWALLED);
			HTTPConText.AppendFormat(_T(" (<a href=\"?ses=%s&amp;w=kad&amp;c=rcfirewall\">%s</a>"), (LPCTSTR)sSession, (LPCTSTR)GetResString(IDS_KAD_RECHECKFW));
			HTTPConText.AppendFormat(_T(", <a href=\"?ses=%s&amp;w=kad&amp;c=disconnect\">%s</a>)"), (LPCTSTR)sSession, (LPCTSTR)GetResString(IDS_IRC_DISCONNECT));
		} else {
			HTTPConText = GetResString(IDS_CONNECTED);
			HTTPConText.AppendFormat(_T(" (<a href=\"?ses=%s&amp;w=kad&amp;c=disconnect\">%s</a>)"), (LPCTSTR)sSession, (LPCTSTR)GetResString(IDS_IRC_DISCONNECT));
		}
	} else {
		if (Kademlia::CKademlia::IsRunning())
			HTTPConText = GetResString(IDS_CONNECTING);
		else {
			HTTPConText = GetResString(IDS_DISCONNECTED);
			HTTPConText.AppendFormat(_T(" (<a href=\"?ses=%s&amp;w=kad&amp;c=connect\">%s</a>)"), (LPCTSTR)sSession, (LPCTSTR)GetResString(IDS_IRC_CONNECT));
		}
	}
	Out.Replace(_T("[KadConText]"), HTTPConText);

	TCHAR HTTPHeader[100];
	//100/1024 equals to 1/10.24
	if (thePrefs.GetMaxDownload() == UNLIMITED)
		_stprintf(HTTPHeader, _T("%.0f"), theApp.downloadqueue->GetDatarate() / 10.24 / thePrefs.GetMaxGraphDownloadRate());
	else
		_stprintf(HTTPHeader, _T("%.0f"), theApp.downloadqueue->GetDatarate() / 10.24 / thePrefs.GetMaxDownload());
	Out.Replace(_T("[DownloadValue]"), HTTPHeader);

	if (thePrefs.GetMaxUpload() == UNLIMITED)
		_stprintf(HTTPHeader, _T("%.0f"), theApp.uploadqueue->GetDatarate() / 10.24 / thePrefs.GetMaxGraphUploadRate(true));
	else
		_stprintf(HTTPHeader, _T("%.0f"), theApp.uploadqueue->GetDatarate() / 10.24 / thePrefs.GetMaxUpload());
	Out.Replace(_T("[UploadValue]"), HTTPHeader);

	_stprintf(HTTPHeader, _T("%.0f"), (100.0 * theApp.listensocket->GetOpenSockets()) / thePrefs.GetMaxConnections());
	Out.Replace(_T("[ConnectionValue]"), HTTPHeader);
	_stprintf(HTTPHeader, _T("%.1f"), theApp.uploadqueue->GetDatarate() / 1024.0);
	Out.Replace(_T("[CurUpload]"), HTTPHeader);
	_stprintf(HTTPHeader, _T("%.1f"), theApp.downloadqueue->GetDatarate() / 1024.0);
	Out.Replace(_T("[CurDownload]"), HTTPHeader);
	_stprintf(HTTPHeader, _T("%u.0"), theApp.listensocket->GetOpenSockets());
	Out.Replace(_T("[CurConnection]"), HTTPHeader);

	uint32 dwMax = thePrefs.GetMaxUpload();
	if (dwMax == UNLIMITED)
		HTTPHelp = GetResString(IDS_PW_UNLIMITED);
	else
		HTTPHelp.Format(_T("%u"), dwMax);
	Out.Replace(_T("[MaxUpload]"), HTTPHelp);

	dwMax = thePrefs.GetMaxDownload();
	if (dwMax == UNLIMITED)
		HTTPHelp = GetResString(IDS_PW_UNLIMITED);
	else
		HTTPHelp.Format(_T("%u"), dwMax);
	Out.Replace(_T("[MaxDownload]"), HTTPHelp);

	dwMax = thePrefs.GetMaxConnections();
	if (dwMax == UNLIMITED)
		HTTPHelp = GetResString(IDS_PW_UNLIMITED);
	else
		HTTPHelp.Format(_T("%u"), dwMax);
	Out.Replace(_T("[MaxConnection]"), HTTPHelp);
	Out.Replace(_T("[UserValue]"), HTTPHelpV);
	Out.Replace(_T("[MaxUsers]"), HTTPHelpM);
	Out.Replace(_T("[CurUsers]"), HTTPHelpU);
	Out.Replace(_T("[CurFiles]"), HTTPHelpF);
	Out.Replace(_T("[Connection]"), _GetPlainResString(IDS_CONNECTION));
	Out.Replace(_T("[QuickStats]"), _GetPlainResString(IDS_STATUS));

	Out.Replace(_T("[Users]"), _GetPlainResString(IDS_UUSERS));
	Out.Replace(_T("[Files]"), _GetPlainResString(IDS_FILES));
	Out.Replace(_T("[Con]"), _GetPlainResString(IDS_ST_ACTIVEC));
	Out.Replace(_T("[Up]"), _GetPlainResString(IDS_PW_CON_UPLBL));
	Out.Replace(_T("[Down]"), _GetPlainResString(IDS_PW_CON_DOWNLBL));

	if (thePrefs.GetCatCount() > 1)
		_InsertCatBox(Out, 0, pThis->m_Templates.sCatArrow, false, false, sSession, _T(""), true);
	else
		Out.Replace(_T("[CATBOXED2K]"), _T(""));

	return Out;
}

const CString CWebServer::_GetFooter(const ThreadData &Data)
{
	const CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	return (pThis == NULL) ? CString() : pThis->m_Templates.sFooter;
}

CString CWebServer::_GetServerList(const ThreadData &Data)
{
	CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	if (pThis == NULL)
		return CString();

	const CString &sSession(_ParseURL(Data.sURL, _T("ses")));
	bool bAdmin = _IsSessionAdmin(Data, sSession);
	const CString &sAddServerBox(_GetAddServerBox(Data));

	const CString &sCmd(_ParseURL(Data.sURL, _T("c")));
	const CString &sIP(_ParseURL(Data.sURL, _T("ip")));
	int nPort = _tstoi(_ParseURL(Data.sURL, _T("port")));
	if (bAdmin) {
		if (sCmd == _T("connect")) {
			if (sIP.IsEmpty())
				SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_CONNECTTOSERVER, 0);
			else
				_ConnectToServer(sIP, nPort);
		} else if (sCmd == _T("disconnect")) {
			if (theApp.serverconnect->IsConnecting())
				SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_STOPCONNECTING, 0);
			else
				SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_DISCONNECT, 1);
		} else if (sCmd == _T("remove")) {
			if (!sIP.IsEmpty())
				_RemoveServer(sIP, nPort);
		} else if (sCmd == _T("addtostatic")) {
			if (!sIP.IsEmpty())
				_AddToStatic(sIP, nPort);
		} else if (sCmd == _T("removefromstatic")) {
			if (!sIP.IsEmpty())
				_RemoveFromStatic(sIP, nPort);
		} else if (sCmd == _T("priolow")) {
			if (!sIP.IsEmpty()) {
				CServer *server = theApp.serverlist->GetServerByAddress(sIP, (uint16)nPort);
				if (server) {
					server->SetPreference(SRV_PR_LOW);
					SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_UPDATESERVER, (LPARAM)server);
				}
			}
		} else if (sCmd == _T("prionormal")) {
			if (!sIP.IsEmpty()) {
				CServer *server = theApp.serverlist->GetServerByAddress(sIP, (uint16)nPort);
				if (server) {
					server->SetPreference(SRV_PR_NORMAL);
					SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_UPDATESERVER, (LPARAM)server);
				}
			}
		} else if (sCmd == _T("priohigh")) {
			if (!sIP.IsEmpty()) {
				CServer *server = theApp.serverlist->GetServerByAddress(sIP, (uint16)nPort);
				if (server) {
					server->SetPreference(SRV_PR_HIGH);
					SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_UPDATESERVER, (LPARAM)server);
				}
			}
		}
	} else if (sCmd == _T("menu")) {
		int iMenu = _tstol(_ParseURL(Data.sURL, _T("m")));
		bool bValue = _ParseURL(Data.sURL, _T("v")) == _T("1");
		WSserverColumnHidden[iMenu] = bValue;
		_SaveWIConfigArray(WSserverColumnHidden, _countof(WSserverColumnHidden), _T("serverColumnHidden"));
	}

	CString strTmp(_ParseURL(Data.sURL, _T("sortreverse")));
	const CString &sSort(_ParseURL(Data.sURL, _T("sort")));

	if (!sSort.IsEmpty()) {
		bool bDirection = false;

		if (sSort == _T("state"))
			pThis->m_Params.ServerSort = SERVER_SORT_STATE;
		else if (sSort == _T("name")) {
			pThis->m_Params.ServerSort = SERVER_SORT_NAME;
			bDirection = true;
		} else if (sSort == _T("ip"))
			pThis->m_Params.ServerSort = SERVER_SORT_IP;
		else if (sSort == _T("description")) {
			pThis->m_Params.ServerSort = SERVER_SORT_DESCRIPTION;
			bDirection = true;
		} else if (sSort == _T("ping"))
			pThis->m_Params.ServerSort = SERVER_SORT_PING;
		else if (sSort == _T("users"))
			pThis->m_Params.ServerSort = SERVER_SORT_USERS;
		else if (sSort == _T("files"))
			pThis->m_Params.ServerSort = SERVER_SORT_FILES;
		else if (sSort == _T("priority"))
			pThis->m_Params.ServerSort = SERVER_SORT_PRIORITY;
		else if (sSort == _T("failed"))
			pThis->m_Params.ServerSort = SERVER_SORT_FAILED;
		else if (sSort == _T("limit"))
			pThis->m_Params.ServerSort = SERVER_SORT_LIMIT;
		else if (sSort == _T("version"))
			pThis->m_Params.ServerSort = SERVER_SORT_VERSION;

		if (strTmp.IsEmpty())
			pThis->m_Params.bServerSortReverse = bDirection;
	}
	if (!strTmp.IsEmpty())
		pThis->m_Params.bServerSortReverse = (strTmp == _T("true"));

	CString Out(pThis->m_Templates.sServerList);

	Out.Replace(_T("[AddServerBox]"), sAddServerBox);
	Out.Replace(_T("[Session]"), sSession);

	strTmp = (pThis->m_Params.bServerSortReverse) ? _T("&amp;sortreverse=false") : _T("&amp;sortreverse=true");

	if (pThis->m_Params.ServerSort == SERVER_SORT_STATE)
		Out.Replace(_T("[SortState]"), strTmp);
	else
		Out.Replace(_T("[SortState]"), _T(""));
	if (pThis->m_Params.ServerSort == SERVER_SORT_NAME)
		Out.Replace(_T("[SortName]"), strTmp);
	else
		Out.Replace(_T("[SortName]"), _T(""));
	if (pThis->m_Params.ServerSort == SERVER_SORT_IP)
		Out.Replace(_T("[SortIP]"), strTmp);
	else
		Out.Replace(_T("[SortIP]"), _T(""));
	if (pThis->m_Params.ServerSort == SERVER_SORT_DESCRIPTION)
		Out.Replace(_T("[SortDescription]"), strTmp);
	else
		Out.Replace(_T("[SortDescription]"), _T(""));
	if (pThis->m_Params.ServerSort == SERVER_SORT_PING)
		Out.Replace(_T("[SortPing]"), strTmp);
	else
		Out.Replace(_T("[SortPing]"), _T(""));
	if (pThis->m_Params.ServerSort == SERVER_SORT_USERS)
		Out.Replace(_T("[SortUsers]"), strTmp);
	else
		Out.Replace(_T("[SortUsers]"), _T(""));
	if (pThis->m_Params.ServerSort == SERVER_SORT_FILES)
		Out.Replace(_T("[SortFiles]"), strTmp);
	else
		Out.Replace(_T("[SortFiles]"), _T(""));
	if (pThis->m_Params.ServerSort == SERVER_SORT_PRIORITY)
		Out.Replace(_T("[SortPriority]"), strTmp);
	else
		Out.Replace(_T("[SortPriority]"), _T(""));
	if (pThis->m_Params.ServerSort == SERVER_SORT_FAILED)
		Out.Replace(_T("[SortFailed]"), strTmp);
	else
		Out.Replace(_T("[SortFailed]"), _T(""));
	if (pThis->m_Params.ServerSort == SERVER_SORT_LIMIT)
		Out.Replace(_T("[SortLimit]"), strTmp);
	else
		Out.Replace(_T("[SortLimit]"), _T(""));
	if (pThis->m_Params.ServerSort == SERVER_SORT_VERSION)
		Out.Replace(_T("[SortVersion]"), strTmp);
	else
		Out.Replace(_T("[SortVersion]"), _T(""));
	Out.Replace(_T("[ServerList]"), _GetPlainResString(IDS_SV_SERVERLIST));

	const TCHAR *pcSortIcon = (pThis->m_Params.bServerSortReverse) ? pThis->m_Templates.sUpArrow : pThis->m_Templates.sDownArrow;

	_GetPlainResString(strTmp, IDS_SL_SERVERNAME);
	if (WSserverColumnHidden[0]) {
		Out.Replace(_T("[ServernameI]"), _T(""));
		Out.Replace(_T("[ServernameH]"), _T(""));
	} else {
		Out.Replace(_T("[ServernameI]"), (pThis->m_Params.ServerSort == SERVER_SORT_NAME) ? pcSortIcon : _T(""));
		Out.Replace(_T("[ServernameH]"), strTmp);
	}
	Out.Replace(_T("[ServernameM]"), strTmp);

	_GetPlainResString(strTmp, IDS_IP);
	if (WSserverColumnHidden[1]) {
		Out.Replace(_T("[AddressI]"), _T(""));
		Out.Replace(_T("[AddressH]"), _T(""));
	} else {
		Out.Replace(_T("[AddressI]"), (pThis->m_Params.ServerSort == SERVER_SORT_IP) ? pcSortIcon : _T(""));
		Out.Replace(_T("[AddressH]"), strTmp);
	}
	Out.Replace(_T("[AddressM]"), strTmp);

	_GetPlainResString(strTmp, IDS_DESCRIPTION);
	if (WSserverColumnHidden[2]) {
		Out.Replace(_T("[DescriptionI]"), _T(""));
		Out.Replace(_T("[DescriptionH]"), _T(""));
	} else {
		Out.Replace(_T("[DescriptionI]"), (pThis->m_Params.ServerSort == SERVER_SORT_DESCRIPTION) ? pcSortIcon : _T(""));
		Out.Replace(_T("[DescriptionH]"), strTmp);
	}
	Out.Replace(_T("[DescriptionM]"), strTmp);

	_GetPlainResString(strTmp, IDS_PING);
	if (WSserverColumnHidden[3]) {
		Out.Replace(_T("[PingI]"), _T(""));
		Out.Replace(_T("[PingH]"), _T(""));
	} else {
		Out.Replace(_T("[PingI]"), (pThis->m_Params.ServerSort == SERVER_SORT_PING) ? pcSortIcon : _T(""));
		Out.Replace(_T("[PingH]"), strTmp);
	}
	Out.Replace(_T("[PingM]"), strTmp);

	_GetPlainResString(strTmp, IDS_UUSERS);
	if (WSserverColumnHidden[4]) {
		Out.Replace(_T("[UsersI]"), _T(""));
		Out.Replace(_T("[UsersH]"), _T(""));
	} else {
		Out.Replace(_T("[UsersI]"), (pThis->m_Params.ServerSort == SERVER_SORT_USERS) ? pcSortIcon : _T(""));
		Out.Replace(_T("[UsersH]"), strTmp);
	}
	Out.Replace(_T("[UsersM]"), strTmp);

	_GetPlainResString(strTmp, IDS_FILES);
	if (WSserverColumnHidden[5]) {
		Out.Replace(_T("[FilesI]"), _T(""));
		Out.Replace(_T("[FilesH]"), _T(""));
	} else {
		Out.Replace(_T("[FilesI]"), (pThis->m_Params.ServerSort == SERVER_SORT_FILES) ? pcSortIcon : _T(""));
		Out.Replace(_T("[FilesH]"), strTmp);
	}
	Out.Replace(_T("[FilesM]"), strTmp);

	_GetPlainResString(strTmp, IDS_PRIORITY);
	if (WSserverColumnHidden[6]) {
		Out.Replace(_T("[PriorityI]"), _T(""));
		Out.Replace(_T("[PriorityH]"), _T(""));
	} else {
		Out.Replace(_T("[PriorityI]"), (pThis->m_Params.ServerSort == SERVER_SORT_PRIORITY) ? pcSortIcon : _T(""));
		Out.Replace(_T("[PriorityH]"), strTmp);
	}
	Out.Replace(_T("[PriorityM]"), strTmp);

	_GetPlainResString(strTmp, IDS_UFAILED);
	if (WSserverColumnHidden[7]) {
		Out.Replace(_T("[FailedI]"), _T(""));
		Out.Replace(_T("[FailedH]"), _T(""));
	} else {
		Out.Replace(_T("[FailedI]"), (pThis->m_Params.ServerSort == SERVER_SORT_FAILED) ? pcSortIcon : _T(""));
		Out.Replace(_T("[FailedH]"), strTmp);
	}
	Out.Replace(_T("[FailedM]"), strTmp);

	_GetPlainResString(strTmp, IDS_SERVER_LIMITS);
	if (WSserverColumnHidden[8]) {
		Out.Replace(_T("[LimitI]"), _T(""));
		Out.Replace(_T("[LimitH]"), _T(""));
	} else {
		Out.Replace(_T("[LimitI]"), (pThis->m_Params.ServerSort == SERVER_SORT_LIMIT) ? pcSortIcon : _T(""));
		Out.Replace(_T("[LimitH]"), strTmp);
	}
	Out.Replace(_T("[LimitM]"), strTmp);

	_GetPlainResString(strTmp, IDS_SV_SERVERINFO);
	if (WSserverColumnHidden[9]) {
		Out.Replace(_T("[VersionI]"), _T(""));
		Out.Replace(_T("[VersionH]"), _T(""));
	} else {
		Out.Replace(_T("[VersionI]"), (pThis->m_Params.ServerSort == SERVER_SORT_VERSION) ? pcSortIcon : _T(""));
		Out.Replace(_T("[VersionH]"), strTmp);
	}
	Out.Replace(_T("[VersionM]"), strTmp);

	Out.Replace(_T("[Actions]"), _GetPlainResString(IDS_WEB_ACTIONS));

	CArray<ServerEntry> ServerArray;

	// Populating array
	for (INT_PTR sc = theApp.serverlist->GetServerCount(); --sc >= 0;) {
		const CServer &cur_serv = *theApp.serverlist->GetServerAt(sc);
		ServerEntry Entry;
		Entry.sServerName = _SpecialChars(cur_serv.GetListName());
		Entry.sServerIP = cur_serv.GetAddress();
		Entry.nServerPort = cur_serv.GetPort();
		Entry.sServerDescription = _SpecialChars(cur_serv.GetDescription());
		Entry.nServerPing = cur_serv.GetPing();
		Entry.nServerUsers = cur_serv.GetUsers();
		Entry.nServerMaxUsers = cur_serv.GetMaxUsers();
		Entry.nServerFiles = cur_serv.GetFiles();
		Entry.bServerStatic = cur_serv.IsStaticMember();
		UINT uid;
		switch (cur_serv.GetPreference()) {
		case SRV_PR_HIGH:
			uid = IDS_PRIOHIGH;
			Entry.nServerPriority = 2;
			break;
		case SRV_PR_NORMAL:
			uid = IDS_PRIONORMAL;
			Entry.nServerPriority = 1;
			break;
		case SRV_PR_LOW:
			uid = IDS_PRIOLOW;
			Entry.nServerPriority = 0;
			break;
		default:
			uid = 0;
			Entry.nServerPriority = 0;
		}
		if (uid)
			Entry.sServerPriority = _GetPlainResString(uid);
		Entry.nServerFailed = cur_serv.GetFailedCount();
		Entry.nServerSoftLimit = cur_serv.GetSoftFiles();
		Entry.nServerHardLimit = cur_serv.GetHardFiles();
		Entry.sServerVersion = cur_serv.GetVersion();
		if (inet_addr((CStringA)Entry.sServerIP) != INADDR_NONE) {
			CString &newip(Entry.sServerFullIP);
			for (int j = 0, iPos = 0; j < 4 && iPos >= 0; ++j) {
				const CString &temp(Entry.sServerIP.Tokenize(_T("."), iPos));
				newip.AppendFormat(&_T("000%s")[min(temp.GetLength(), 3)], (LPCTSTR)temp);
			}
		} else
			Entry.sServerFullIP = Entry.sServerIP;
		Entry.sServerState = cur_serv.GetFailedCount() ? _T("failed") : _T("disconnected");

		if (theApp.serverconnect->IsConnecting())
			Entry.sServerState = _T("connecting");
		else if (theApp.serverconnect->IsConnected()) {
			if (theApp.serverconnect->GetCurrentServer()->GetFullIP() == cur_serv.GetFullIP())
				Entry.sServerState = theApp.serverconnect->IsLowID() ? _T("low") : _T("high");
		}
		ServerArray.Add(Entry);
	}

	SortParams prm{ (int)pThis->m_Params.ServerSort, pThis->m_Params.bServerSortReverse };
	qsort_s(ServerArray.GetData(), ServerArray.GetCount(), sizeof(ServerEntry), &_ServerCmp, &prm);

	// Displaying
	CString OutE(pThis->m_Templates.sServerLine); // List Entry Templates

	OutE.Replace(_T("[admin]"), bAdmin ? _T("admin") : _T(""));
	OutE.Replace(_T("[session]"), sSession);

	CString sList, HTTPProcessData, sServerPort, ed2k;
	for (INT_PTR i = 0; i < ServerArray.GetCount(); ++i) {
		const ServerEntry &cur_srv(ServerArray[i]);
		HTTPProcessData = OutE;	// Copy Entry Line to Temp

		sServerPort.Format(_T("%i"), cur_srv.nServerPort);
		ed2k.Format(_T("ed2k://|server|%s|%s|/"), (LPCTSTR)cur_srv.sServerIP, (LPCTSTR)sServerPort);

		bool b = (cur_srv.sServerIP == _ParseURL(Data.sURL, _T("ip")) && sServerPort == _ParseURL(Data.sURL, _T("port")));
		HTTPProcessData.Replace(_T("[LastChangedDataset]"), b ?_T("checked") : _T("checked_no"));
		b = cur_srv.bServerStatic;
		HTTPProcessData.Replace(_T("[isstatic]"), b ? _T("staticsrv") : _T(""));
		HTTPProcessData.Replace(_T("[ServerType]"), b ? _T("static") : _T("none"));

		LPCTSTR pcSrvPriority;
		switch (cur_srv.nServerPriority) {
		case 0:
			pcSrvPriority = _T("Low");
			break;
		case 1:
			pcSrvPriority = _T("Normal");
			break;
		case 2:
			pcSrvPriority = _T("High");
			break;
		default:
			pcSrvPriority = _T("");
		}

		HTTPProcessData.Replace(_T("[ed2k]"), ed2k);
		HTTPProcessData.Replace(_T("[ip]"), cur_srv.sServerIP);
		HTTPProcessData.Replace(_T("[port]"), sServerPort);
		HTTPProcessData.Replace(_T("[server-priority]"), pcSrvPriority);

		// DonGato: reduced large server names or descriptions
		if (WSserverColumnHidden[0])
			HTTPProcessData.Replace(_T("[Servername]"), _T(""));
		else if (cur_srv.sServerName.GetLength() > (SHORT_LENGTH)) {
			CString s;
			s.Format(_T("<acronym title=\"%s\">%s...</acronym>"), (LPCTSTR)cur_srv.sServerName, (LPCTSTR)cur_srv.sServerName.Left(SHORT_LENGTH - 3));
			HTTPProcessData.Replace(_T("[Servername]"), s);
		} else
			HTTPProcessData.Replace(_T("[Servername]"), cur_srv.sServerName);

		if (WSserverColumnHidden[1])
			HTTPProcessData.Replace(_T("[Address]"), _T(""));
		else {
			CString sAddr(cur_srv.sServerIP);
			sAddr.AppendFormat(_T(":%d"), cur_srv.nServerPort);
			HTTPProcessData.Replace(_T("[Address]"), sAddr);
		}
		if (WSserverColumnHidden[2])
			HTTPProcessData.Replace(_T("[Description]"), _T(""));
		else if (cur_srv.sServerDescription.GetLength() > SHORT_LENGTH) {
			CString s;
			s.Format(_T("<acronym title=\"%s\">%s...</acronym>"), (LPCTSTR)cur_srv.sServerDescription, (LPCTSTR)cur_srv.sServerDescription.Left(SHORT_LENGTH - 3));
			HTTPProcessData.Replace(_T("[Description]"), s);
		} else
			HTTPProcessData.Replace(_T("[Description]"), cur_srv.sServerDescription);

		if (WSserverColumnHidden[3])
			HTTPProcessData.Replace(_T("[Ping]"), _T(""));
		else {
			CString sPing;
			sPing.Format(_T("%u"), cur_srv.nServerPing);
			HTTPProcessData.Replace(_T("[Ping]"), sPing);
		}

		if (WSserverColumnHidden[4])
			HTTPProcessData.Replace(_T("[Users]"), _T(""));
		else {
			CString sT;
			if (cur_srv.nServerUsers > 0) {
				sT = CastItoIShort(cur_srv.nServerUsers);
				if (cur_srv.nServerMaxUsers > 0)
					sT.AppendFormat(_T(" (%s)"), (LPCTSTR)CastItoIShort(cur_srv.nServerMaxUsers));
			}
			HTTPProcessData.Replace(_T("[Users]"), sT);
		}
		if (WSserverColumnHidden[5] && (cur_srv.nServerFiles > 0))
			HTTPProcessData.Replace(_T("[Files]"), _T(""));
		else
			HTTPProcessData.Replace(_T("[Files]"), CastItoIShort(cur_srv.nServerFiles));
		if (WSserverColumnHidden[6])
			HTTPProcessData.Replace(_T("[Priority]"), _T(""));
		else
			HTTPProcessData.Replace(_T("[Priority]"), cur_srv.sServerPriority);
		if (WSserverColumnHidden[7])
			HTTPProcessData.Replace(_T("[Failed]"), _T(""));
		else {
			CString sFailed;
			sFailed.Format(_T("%d"), cur_srv.nServerFailed);
			HTTPProcessData.Replace(_T("[Failed]"), sFailed);
		}
		if (WSserverColumnHidden[8])
			HTTPProcessData.Replace(_T("[Limit]"), _T(""));
		else {
			CString strTemp(CastItoIShort(cur_srv.nServerSoftLimit));
			strTemp.AppendFormat(_T(" (%s)"), (LPCTSTR)CastItoIShort(cur_srv.nServerHardLimit));
			HTTPProcessData.Replace(_T("[Limit]"), strTemp);
		}
		if (WSserverColumnHidden[9])
			HTTPProcessData.Replace(_T("[Version]"), _T(""));
		else if (cur_srv.sServerVersion.GetLength() > SHORT_LENGTH_MIN) {
			CString s;
			s.Format(_T("<acronym title=\"%s\">%s...</acronym>"), (LPCTSTR)cur_srv.sServerVersion, (LPCTSTR)cur_srv.sServerVersion.Left(SHORT_LENGTH_MIN - 3));
			HTTPProcessData.Replace(_T("[Version]"), s);
		} else
			HTTPProcessData.Replace(_T("[Version]"), cur_srv.sServerVersion);

		HTTPProcessData.Replace(_T("[ServerState]"), cur_srv.sServerState);
		sList += HTTPProcessData;
	}
	Out.Replace(_T("[ServersList]"), sList);
	Out.Replace(_T("[Session]"), sSession);

	return Out;
}

CString CWebServer::_GetTransferList(const ThreadData &Data)
{
	CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	if (pThis == NULL)
		return CString();

	const CString &sSession(_ParseURL(Data.sURL, _T("ses")));
	long lSession = _tstol(sSession);
	bool bAdmin = _IsSessionAdmin(Data, lSession);

	// cat
	int cat;
	const CString &catp(_ParseURL(Data.sURL, _T("cat")));
	if (catp.IsEmpty())
		cat = _GetLastUserCat(Data, lSession);
	else {
		cat = _tstoi(catp);
		_SetLastUserCat(Data, lSession, cat);
	}
	// commands
	CString sCat;
	if (cat != 0)
		sCat.Format(_T("&amp;cat=%i"), cat);

	CString Out;
	if (thePrefs.GetCatCount() > 1)
		_InsertCatBox(Out, cat, _T(""), true, true, sSession, CString());
	else
		Out.Replace(_T("[CATBOX]"), _T(""));


	const CString &sClear(_ParseURL(Data.sURL, _T("clearcompleted")));
	if (bAdmin && !sClear.IsEmpty()) {
		if (sClear.CompareNoCase(_T("all")) == 0)
			theApp.emuledlg->SendMessage(WEB_CLEAR_COMPLETED, (WPARAM)0, (LPARAM)cat);
		else if (!sClear.IsEmpty()) {
			uchar FileHash[MDX_DIGEST_SIZE];
			if (strmd4(sClear, FileHash)) {
				uchar *pFileHash = new uchar[MDX_DIGEST_SIZE];
				md4cpy(pFileHash, FileHash);
				theApp.emuledlg->SendMessage(WEB_CLEAR_COMPLETED, (WPARAM)1, reinterpret_cast<LPARAM>(pFileHash));
			}
		}
	}

	CString HTTPTemp(_ParseURL(Data.sURL, _T("ed2k")));

	if (bAdmin && !HTTPTemp.IsEmpty())
		theApp.emuledlg->SendMessage(WEB_ADDDOWNLOADS, (WPARAM)(LPCTSTR)HTTPTemp, cat);

	HTTPTemp = _ParseURL(Data.sURL, _T("c"));

	if (HTTPTemp == _T("menudown")) {
		int iMenu = _tstol(_ParseURL(Data.sURL, _T("m")));
		WSdownloadColumnHidden[iMenu] = (_tstol(_ParseURL(Data.sURL, _T("v"))) != 0);

		CIni ini(thePrefs.GetConfigFile(), _T("WebServer"));

		_SaveWIConfigArray(WSdownloadColumnHidden, _countof(WSdownloadColumnHidden), _T("downloadColumnHidden"));
	} else if (HTTPTemp == _T("menuup")) {
		int iMenu = _tstol(_ParseURL(Data.sURL, _T("m")));
		WSuploadColumnHidden[iMenu] = (_tstol(_ParseURL(Data.sURL, _T("v"))) != 0);
		_SaveWIConfigArray(WSuploadColumnHidden, _countof(WSuploadColumnHidden), _T("uploadColumnHidden"));
	} else if (HTTPTemp == _T("menuqueue")) {
		int iMenu = _tstol(_ParseURL(Data.sURL, _T("m")));
		WSqueueColumnHidden[iMenu] = (_tstol(_ParseURL(Data.sURL, _T("v"))) != 0);
		_SaveWIConfigArray(WSqueueColumnHidden, _countof(WSqueueColumnHidden), _T("queueColumnHidden"));
	} else if (HTTPTemp == _T("menuprio") && bAdmin) {
		const CString &sPrio(_ParseURL(Data.sURL, _T("p")));
		int prio;
		if (sPrio == _T("low"))
			prio = PR_LOW;
		else if (sPrio == _T("high"))
			prio = PR_HIGH;
		else if (sPrio == _T("normal"))
			prio = PR_NORMAL;
		else //if (sPrio == _T("auto"))
			prio = PR_AUTO; //make auto the default
		SendMessage(theApp.emuledlg->m_hWnd, WEB_CATPRIO, (WPARAM)cat, (LPARAM)prio);
	}

	if (bAdmin) {
		const CString &sOp(_ParseURL(Data.sURL, _T("op")));

		if (!sOp.IsEmpty()) {
			const CString &sFile(_ParseURL(Data.sURL, _T("file")));

			if (sFile.IsEmpty()) {
				const CString &sUser(_ParseURL(Data.sURL, _T("userhash")));
				uchar UserHash[MDX_DIGEST_SIZE];

				if (strmd4(sUser, UserHash)) {
					CUpDownClient *cur_client = theApp.clientlist->FindClientByUserHash(UserHash);
					if (cur_client) {
						if (sOp == _T("addfriend"))
							SendMessage(theApp.emuledlg->m_hWnd, WEB_ADDREMOVEFRIEND, (WPARAM)cur_client, (LPARAM)1);
						else if (sOp == _T("removefriend")) {
							const CFriend *f = theApp.friendlist->SearchFriend(UserHash, 0, 0);
							if (f)
								SendMessage(theApp.emuledlg->m_hWnd, WEB_ADDREMOVEFRIEND, (WPARAM)f, (LPARAM)0);
						}
					}
				}
			} else {
				uchar FileHash[MDX_DIGEST_SIZE];
				bool bHash = strmd4(sFile, FileHash);
				if (bHash) {
					// v7.4.0 — WithFileByID runs under the DownloadQueue lock; the
					// lambda mutates state but never re-enters DownloadQueue, so the
					// lock-order invariant holds. SendMessage callouts to the main
					// thread happen INSIDE the lock here — that's safe because the
					// main thread is the only one that mutates filelist, and it can't
					// re-enter WithFileByID while it's waiting on the SendMessage to
					// be processed by... wait, it IS the main thread. So we cache
					// what's needed and SendMessage AFTER the lock releases below.
					bool needsCatTabsUpdate = false;
					CPartFile *renamedFile = NULL;
					CString renameTo;
					theApp.downloadqueue->WithFileByID(FileHash, [&](CPartFile *found_file) {
						if (sOp == _T("stop"))
							found_file->StopFile();
						else if (sOp == _T("pause"))
							found_file->PauseFile();
						else if (sOp == _T("resume"))
							found_file->ResumeFile();
						else if (sOp == _T("cancel")) {
							found_file->DeletePartFile();
							needsCatTabsUpdate = true;
						} else if (sOp == _T("getflc"))
							found_file->GetPreviewPrio();
						else if (sOp == _T("rename")) {
							renamedFile = found_file;
							renameTo = _ParseURL(Data.sURL, _T("name"));
						} else if (sOp == _T("priolow")) {
							found_file->SetAutoDownPriority(false);
							found_file->SetDownPriority(PR_LOW);
						} else if (sOp == _T("prionormal")) {
							found_file->SetAutoDownPriority(false);
							found_file->SetDownPriority(PR_NORMAL);
						} else if (sOp == _T("priohigh")) {
							found_file->SetAutoDownPriority(false);
							found_file->SetDownPriority(PR_HIGH);
						} else if (sOp == _T("prioauto")) {
							found_file->SetAutoDownPriority(true);
							found_file->SetDownPriority(PR_HIGH);
						} else if (sOp == _T("setcat")) {
							const CString &newcat(_ParseURL(Data.sURL, _T("filecat")));
							if (!newcat.IsEmpty())
								found_file->SetCategory(_tstol(newcat));
						} else if (sOp == _T("streamseek")) {
							const CString &sPart(_ParseURL(Data.sURL, _T("part")));
							if (!sPart.IsEmpty()) {
								uint16 seekPart = (uint16)_tstol(sPart);
								found_file->SetStreamSeekPart(seekPart);
							}
						}
					});
					if (needsCatTabsUpdate)
						SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_UPD_CATTABS, 0);
					if (renamedFile)
						theApp.emuledlg->SendMessage(WEB_FILE_RENAME, (WPARAM)renamedFile, (LPARAM)(LPCTSTR)renameTo);
				}
			}
		}
	}

	HTTPTemp = _ParseURL(Data.sURL, _T("sortreverse"));
	const CString &sSort(_ParseURL(Data.sURL, _T("sort")));

	if (!sSort.IsEmpty()) {
		bool bDirection = false;
		if (sSort == _T("dstate"))
			pThis->m_Params.DownloadSort = DOWN_SORT_STATE;
		else if (sSort == _T("dtype"))
			pThis->m_Params.DownloadSort = DOWN_SORT_TYPE;
		else if (sSort == _T("dname")) {
			pThis->m_Params.DownloadSort = DOWN_SORT_NAME;
			bDirection = true;
		} else if (sSort == _T("dsize"))
			pThis->m_Params.DownloadSort = DOWN_SORT_SIZE;
		else if (sSort == _T("dtransferred"))
			pThis->m_Params.DownloadSort = DOWN_SORT_TRANSFERRED;
		else if (sSort == _T("dspeed"))
			pThis->m_Params.DownloadSort = DOWN_SORT_SPEED;
		else if (sSort == _T("dprogress"))
			pThis->m_Params.DownloadSort = DOWN_SORT_PROGRESS;
		else if (sSort == _T("dsources"))
			pThis->m_Params.DownloadSort = DOWN_SORT_SOURCES;
		else if (sSort == _T("dpriority"))
			pThis->m_Params.DownloadSort = DOWN_SORT_PRIORITY;
		else if (sSort == _T("dcategory")) {
			pThis->m_Params.DownloadSort = DOWN_SORT_CATEGORY;
			bDirection = true;
		} else if (sSort == _T("uuser")) {
			pThis->m_Params.UploadSort = UP_SORT_USER;
			bDirection = true;
		} else if (sSort == _T("uclient"))
			pThis->m_Params.UploadSort = UP_SORT_CLIENT;
		else if (sSort == _T("uversion"))
			pThis->m_Params.UploadSort = UP_SORT_VERSION;
		else if (sSort == _T("ufilename")) {
			pThis->m_Params.UploadSort = UP_SORT_FILENAME;
			bDirection = true;
		} else if (sSort == _T("utransferred"))
			pThis->m_Params.UploadSort = UP_SORT_TRANSFERRED;
		else if (sSort == _T("uspeed"))
			pThis->m_Params.UploadSort = UP_SORT_SPEED;
		else if (sSort == _T("qclient"))
			pThis->m_Params.QueueSort = QU_SORT_CLIENT;
		else if (sSort == _T("quser")) {
			pThis->m_Params.QueueSort = QU_SORT_USER;
			bDirection = true;
		} else if (sSort == _T("qversion"))
			pThis->m_Params.QueueSort = QU_SORT_VERSION;
		else if (sSort == _T("qfilename")) {
			pThis->m_Params.QueueSort = QU_SORT_FILENAME;
			bDirection = true;
		} else if (sSort == _T("qscore"))
			pThis->m_Params.QueueSort = QU_SORT_SCORE;

		if (!HTTPTemp.IsEmpty())
			bDirection = (HTTPTemp.CompareNoCase(_T("true")) == 0);

		switch (sSort[0]) {
		case _T('d'):
			pThis->m_Params.bDownloadSortReverse = bDirection;
			break;
		case _T('u'):
			pThis->m_Params.bUploadSortReverse = bDirection;
			break;
		case _T('q'):
			pThis->m_Params.bQueueSortReverse = bDirection;
		}
	}

	_SetBoolean(pThis->m_Params.bShowUploadQueue, Data.sURL, _T("showuploadqueue"));
	_SetBoolean(pThis->m_Params.bShowUploadQueueBanned, Data.sURL, _T("showuploadqueuebanned"));
	_SetBoolean(pThis->m_Params.bShowUploadQueueFriend, Data.sURL, _T("showuploadqueuefriend"));

	Out += pThis->m_Templates.sTransferImages;
	Out += pThis->m_Templates.sTransferList;
	Out.Replace(_T("[DownloadHeader]"), pThis->m_Templates.sTransferDownHeader);
	Out.Replace(_T("[DownloadFooter]"), pThis->m_Templates.sTransferDownFooter);
	Out.Replace(_T("[UploadHeader]"), pThis->m_Templates.sTransferUpHeader);
	Out.Replace(_T("[UploadFooter]"), pThis->m_Templates.sTransferUpFooter);
	_InsertCatBox(Out, cat, pThis->m_Templates.sCatArrow, true, true, sSession, _T(""));

	HTTPTemp = (pThis->m_Params.bDownloadSortReverse) ? _T("&amp;sortreverse=false") : _T("&amp;sortreverse=true");

	if (pThis->m_Params.DownloadSort == DOWN_SORT_STATE)
		Out.Replace(_T("[SortDState]"), HTTPTemp);
	else
		Out.Replace(_T("[SortDState]"), _T(""));
	if (pThis->m_Params.DownloadSort == DOWN_SORT_TYPE)
		Out.Replace(_T("[SortDType]"), HTTPTemp);
	else
		Out.Replace(_T("[SortDType]"), _T(""));
	if (pThis->m_Params.DownloadSort == DOWN_SORT_NAME)
		Out.Replace(_T("[SortDName]"), HTTPTemp);
	else
		Out.Replace(_T("[SortDName]"), _T(""));
	if (pThis->m_Params.DownloadSort == DOWN_SORT_SIZE)
		Out.Replace(_T("[SortDSize]"), HTTPTemp);
	else
		Out.Replace(_T("[SortDSize]"), _T(""));
	if (pThis->m_Params.DownloadSort == DOWN_SORT_TRANSFERRED)
		Out.Replace(_T("[SortDTransferred]"), HTTPTemp);
	else
		Out.Replace(_T("[SortDTransferred]"), _T(""));
	if (pThis->m_Params.DownloadSort == DOWN_SORT_SPEED)
		Out.Replace(_T("[SortDSpeed]"), HTTPTemp);
	else
		Out.Replace(_T("[SortDSpeed]"), _T(""));
	if (pThis->m_Params.DownloadSort == DOWN_SORT_PROGRESS)
		Out.Replace(_T("[SortDProgress]"), HTTPTemp);
	else
		Out.Replace(_T("[SortDProgress]"), _T(""));
	if (pThis->m_Params.DownloadSort == DOWN_SORT_SOURCES)
		Out.Replace(_T("[SortDSources]"), HTTPTemp);
	else
		Out.Replace(_T("[SortDSources]"), _T(""));
	if (pThis->m_Params.DownloadSort == DOWN_SORT_PRIORITY)
		Out.Replace(_T("[SortDPriority]"), HTTPTemp);
	else
		Out.Replace(_T("[SortDPriority]"), _T(""));
	if (pThis->m_Params.DownloadSort == DOWN_SORT_CATEGORY)
		Out.Replace(_T("[SortDCategory]"), HTTPTemp);
	else
		Out.Replace(_T("[SortDCategory]"), _T(""));

	HTTPTemp = (pThis->m_Params.bUploadSortReverse) ? _T("&amp;sortreverse=false") : _T("&amp;sortreverse=true");

	if (pThis->m_Params.UploadSort == UP_SORT_CLIENT)
		Out.Replace(_T("[SortUClient]"), HTTPTemp);
	else
		Out.Replace(_T("[SortUClient]"), _T(""));
	if (pThis->m_Params.UploadSort == UP_SORT_USER)
		Out.Replace(_T("[SortUUser]"), HTTPTemp);
	else
		Out.Replace(_T("[SortUUser]"), _T(""));
	if (pThis->m_Params.UploadSort == UP_SORT_VERSION)
		Out.Replace(_T("[SortUVersion]"), HTTPTemp);
	else
		Out.Replace(_T("[SortUVersion]"), _T(""));
	if (pThis->m_Params.UploadSort == UP_SORT_FILENAME)
		Out.Replace(_T("[SortUFilename]"), HTTPTemp);
	else
		Out.Replace(_T("[SortUFilename]"), _T(""));
	if (pThis->m_Params.UploadSort == UP_SORT_TRANSFERRED)
		Out.Replace(_T("[SortUTransferred]"), HTTPTemp);
	else
		Out.Replace(_T("[SortUTransferred]"), _T(""));
	if (pThis->m_Params.UploadSort == UP_SORT_SPEED)
		Out.Replace(_T("[SortUSpeed]"), HTTPTemp);
	else
		Out.Replace(_T("[SortUSpeed]"), _T(""));

	const TCHAR *pcSortIcon = (pThis->m_Params.bDownloadSortReverse) ? pThis->m_Templates.sUpArrow : pThis->m_Templates.sDownArrow;

	_GetPlainResString(HTTPTemp, IDS_DL_FILENAME);
	if (WSdownloadColumnHidden[0]) {
		Out.Replace(_T("[DFilenameI]"), _T(""));
		Out.Replace(_T("[DFilename]"), _T(""));
	} else {
		Out.Replace(_T("[DFilenameI]"), (pThis->m_Params.DownloadSort == DOWN_SORT_NAME) ? pcSortIcon : _T(""));
		Out.Replace(_T("[DFilename]"), HTTPTemp);
	}
	Out.Replace(_T("[DFilenameM]"), HTTPTemp);

	_GetPlainResString(HTTPTemp, IDS_DL_SIZE);
	if (WSdownloadColumnHidden[1]) {
		Out.Replace(_T("[DSizeI]"), _T(""));
		Out.Replace(_T("[DSize]"), _T(""));
	} else {
		Out.Replace(_T("[DSizeI]"), (pThis->m_Params.DownloadSort == DOWN_SORT_SIZE) ? pcSortIcon : _T(""));
		Out.Replace(_T("[DSize]"), HTTPTemp);
	}
	Out.Replace(_T("[DSizeM]"), HTTPTemp);

	_GetPlainResString(HTTPTemp, IDS_DL_TRANSFCOMPL);
	if (WSdownloadColumnHidden[2]) {
		Out.Replace(_T("[DTransferredI]"), _T(""));
		Out.Replace(_T("[DTransferred]"), _T(""));
	} else {
		Out.Replace(_T("[DTransferredI]"), (pThis->m_Params.DownloadSort == DOWN_SORT_TRANSFERRED) ? pcSortIcon : _T(""));
		Out.Replace(_T("[DTransferred]"), HTTPTemp);
	}
	Out.Replace(_T("[DTransferredM]"), HTTPTemp);

	_GetPlainResString(HTTPTemp, IDS_DL_PROGRESS);
	if (WSdownloadColumnHidden[3]) {
		Out.Replace(_T("[DProgressI]"), _T(""));
		Out.Replace(_T("[DProgress]"), _T(""));
	} else {
		Out.Replace(_T("[DProgressI]"), (pThis->m_Params.DownloadSort == DOWN_SORT_PROGRESS) ? pcSortIcon : _T(""));
		Out.Replace(_T("[DProgress]"), HTTPTemp);
	}
	Out.Replace(_T("[DProgressM]"), HTTPTemp);

	_GetPlainResString(HTTPTemp, IDS_DL_SPEED);
	if (WSdownloadColumnHidden[4]) {
		Out.Replace(_T("[DSpeedI]"), _T(""));
		Out.Replace(_T("[DSpeed]"), _T(""));
	} else {
		Out.Replace(_T("[DSpeedI]"), (pThis->m_Params.DownloadSort == DOWN_SORT_SPEED) ? pcSortIcon : _T(""));
		Out.Replace(_T("[DSpeed]"), HTTPTemp);
	}
	Out.Replace(_T("[DSpeedM]"), HTTPTemp);

	_GetPlainResString(HTTPTemp, IDS_DL_SOURCES);
	if (WSdownloadColumnHidden[5]) {
		Out.Replace(_T("[DSourcesI]"), _T(""));
		Out.Replace(_T("[DSources]"), _T(""));
	} else {
		Out.Replace(_T("[DSourcesI]"), (pThis->m_Params.DownloadSort == DOWN_SORT_SOURCES) ? pcSortIcon : _T(""));
		Out.Replace(_T("[DSources]"), HTTPTemp);
	}
	Out.Replace(_T("[DSourcesM]"), HTTPTemp);

	_GetPlainResString(HTTPTemp, IDS_PRIORITY);
	if (WSdownloadColumnHidden[6]) {
		Out.Replace(_T("[DPriorityI]"), _T(""));
		Out.Replace(_T("[DPriority]"), _T(""));
	} else {
		Out.Replace(_T("[DPriorityI]"), (pThis->m_Params.DownloadSort == DOWN_SORT_PRIORITY) ? pcSortIcon : _T(""));
		Out.Replace(_T("[DPriority]"), HTTPTemp);
	}
	Out.Replace(_T("[DPriorityM]"), HTTPTemp);

	_GetPlainResString(HTTPTemp, IDS_CAT);
	if (WSdownloadColumnHidden[7]) {
		Out.Replace(_T("[DCategoryI]"), _T(""));
		Out.Replace(_T("[DCategory]"), _T(""));
	} else {
		Out.Replace(_T("[DCategoryI]"), (pThis->m_Params.DownloadSort == DOWN_SORT_CATEGORY) ? pcSortIcon : _T(""));
		Out.Replace(_T("[DCategory]"), HTTPTemp);
	}
	Out.Replace(_T("[DCategoryM]"), HTTPTemp);

	// add 8th columns here

	pcSortIcon = (pThis->m_Params.bUploadSortReverse) ? pThis->m_Templates.sUpArrow : pThis->m_Templates.sDownArrow;

	_GetPlainResString(HTTPTemp, IDS_QL_USERNAME);
	if (WSuploadColumnHidden[0]) {
		Out.Replace(_T("[UUserI]"), _T(""));
		Out.Replace(_T("[UUser]"), _T(""));
	} else {
		Out.Replace(_T("[UUserI]"), (pThis->m_Params.UploadSort == UP_SORT_USER) ? pcSortIcon : _T(""));
		Out.Replace(_T("[UUser]"), HTTPTemp);
	}
	Out.Replace(_T("[UUserM]"), HTTPTemp);

	_GetPlainResString(HTTPTemp, IDS_CD_VERSION);
	if (WSuploadColumnHidden[1]) {
		Out.Replace(_T("[UVersionI]"), _T(""));
		Out.Replace(_T("[UVersion]"), _T(""));
	} else {
		Out.Replace(_T("[UVersionI]"), (pThis->m_Params.UploadSort == UP_SORT_VERSION) ? pcSortIcon : _T(""));
		Out.Replace(_T("[UVersion]"), HTTPTemp);
	}
	Out.Replace(_T("[UVersionM]"), HTTPTemp);

	_GetPlainResString(HTTPTemp, IDS_DL_FILENAME);
	if (WSuploadColumnHidden[2]) {
		Out.Replace(_T("[UFilenameI]"), _T(""));
		Out.Replace(_T("[UFilename]"), _T(""));
	} else {
		Out.Replace(_T("[UFilenameI]"), (pThis->m_Params.UploadSort == UP_SORT_FILENAME) ? pcSortIcon : _T(""));
		Out.Replace(_T("[UFilename]"), HTTPTemp);
	}
	Out.Replace(_T("[UFilenameM]"), HTTPTemp);

	_GetPlainResString(HTTPTemp, IDS_STATS_SRATIO);
	if (WSuploadColumnHidden[3]) {
		Out.Replace(_T("[UTransferredI]"), _T(""));
		Out.Replace(_T("[UTransferred]"), _T(""));
	} else {
		Out.Replace(_T("[UTransferredI]"), (pThis->m_Params.UploadSort == UP_SORT_TRANSFERRED) ? pcSortIcon : _T(""));
		Out.Replace(_T("[UTransferred]"), HTTPTemp);
	}
	Out.Replace(_T("[UTransferredM]"), HTTPTemp);

	_GetPlainResString(HTTPTemp, IDS_DL_SPEED);
	if (WSuploadColumnHidden[4]) {
		Out.Replace(_T("[USpeedI]"), _T(""));
		Out.Replace(_T("[USpeed]"), _T(""));
	} else {
		Out.Replace(_T("[USpeedI]"), (pThis->m_Params.UploadSort == UP_SORT_SPEED) ? pcSortIcon : _T(""));
		Out.Replace(_T("[USpeed]"), HTTPTemp);
	}
	Out.Replace(_T("[USpeedM]"), HTTPTemp);

	Out.Replace(_T("[DownloadList]"), _GetPlainResString(IDS_TW_DOWNLOADS));
	Out.Replace(_T("[UploadList]"), _GetPlainResString(IDS_TW_UPLOADS));
	Out.Replace(_T("[Actions]"), _GetPlainResString(IDS_WEB_ACTIONS));
	Out.Replace(_T("[TotalDown]"), _GetPlainResString(IDS_INFLST_USER_TOTALDOWNLOAD));
	Out.Replace(_T("[TotalUp]"), _GetPlainResString(IDS_INFLST_USER_TOTALUPLOAD));
	Out.Replace(_T("[admin]"), bAdmin ? _T("admin") : _T(""));
	_InsertCatBox(Out, cat, _T(""), true, true, sSession, _T(""));

	CArray<DownloadFiles> FilesArray;
	CArray<CPartFile*, CPartFile*> partlist;

	theApp.emuledlg->transferwnd->GetDownloadList()->GetDisplayedFiles(&partlist);

	// Populating array
	for (INT_PTR i = 0; i < partlist.GetCount(); ++i) {

		CPartFile *pPartFile = partlist[i];

		if (pPartFile) {
			if (cat < 0) {
				switch (cat) {
				case -1:
					if (pPartFile->GetCategory() != 0)
						continue;
					break;
				case -2:
					if (!pPartFile->IsPartFile())
						continue;
					break;
				case -3:
					if (pPartFile->IsPartFile())
						continue;
					break;
				case -4:
					if (!((pPartFile->GetStatus() == PS_READY || pPartFile->GetStatus() == PS_EMPTY) && pPartFile->GetTransferringSrcCount() == 0))
						continue;
					break;
				case -5:
					if (!((pPartFile->GetStatus() == PS_READY || pPartFile->GetStatus() == PS_EMPTY) && pPartFile->GetTransferringSrcCount() > 0))
						continue;
					break;
				case -6:
					if (pPartFile->GetStatus() != PS_ERROR)
						continue;
					break;
				case -7:
					if (pPartFile->GetStatus() != PS_PAUSED && !pPartFile->IsStopped())
						continue;
					break;
				case -8:
					if (pPartFile->lastseencomplete == 0)
						continue;
					break;
				case -9:
					if (!pPartFile->IsMovie())
						continue;
					break;
				case -10:
					if (ED2KFT_AUDIO != GetED2KFileTypeID(pPartFile->GetFileName()))
						continue;
					break;
				case -11:
					if (!pPartFile->IsArchive())
						continue;
					break;
				case -12:
					if (ED2KFT_CDIMAGE != GetED2KFileTypeID(pPartFile->GetFileName()))
						continue;
					break;
				case -13:
					if (ED2KFT_DOCUMENT != GetED2KFileTypeID(pPartFile->GetFileName()))
						continue;
					break;
				case -14:
					if (ED2KFT_IMAGE != GetED2KFileTypeID(pPartFile->GetFileName()))
						continue;
					break;
				case -15:
					if (ED2KFT_PROGRAM != GetED2KFileTypeID(pPartFile->GetFileName()))
						continue;
					break;
				case -16:
					if (ED2KFT_EMULECOLLECTION != GetED2KFileTypeID(pPartFile->GetFileName()))
						continue;
				//JOHNTODO: Not too sure here. I was going to add Collections but noticed something strange.
				//Are these supposed to match the list in PartFile around line 5132? Because they do not.
				}
			} else if (cat > 0 && pPartFile->GetCategory() != (UINT)cat)
				continue;

			DownloadFiles dFile;
			dFile.sFileName = _SpecialChars(pPartFile->GetFileName());
			dFile.sFileType = _GetWebImageNameForFileType(dFile.sFileName);
			dFile.sFileNameJS = _SpecialChars(pPartFile->GetFileName());	//for javascript
			dFile.m_qwFileSize = (uint64)pPartFile->GetFileSize();
			dFile.m_qwFileTransferred = (uint64)pPartFile->GetCompletedSize();
			dFile.m_dblCompleted = pPartFile->GetPercentCompleted();
			dFile.lFileSpeed = pPartFile->GetDatarate();

			if (pPartFile->HasComment() || pPartFile->HasRating())
				dFile.iComment = pPartFile->HasBadRating() ? 2 : 1;
			else
				dFile.iComment = 0;

			dFile.iFileState = pPartFile->getPartfileStatusRank();

			LPCTSTR pFileState;
			switch (pPartFile->GetStatus()) {
			case PS_HASHING:
				pFileState = _T("hashing");
				break;
			case PS_WAITINGFORHASH:
				pFileState = _T("waitinghash");
				break;
			case PS_ERROR:
				pFileState = _T("error");
				break;
			case PS_COMPLETING:
				pFileState = _T("completing");
				break;
			case PS_COMPLETE:
				pFileState = _T("complete");
				break;
			case PS_PAUSED:
				pFileState = pPartFile->IsStopped() ? _T("stopped") : _T("paused");
				break;
			default:
				pFileState = (pPartFile->GetDatarate() > 0) ? _T("downloading") : _T("waiting");
			}
			dFile.sFileState = CString(pFileState);

			dFile.bFileAutoPrio = pPartFile->IsAutoDownPriority();
			dFile.nFilePrio = pPartFile->GetDownPriority();
			int pCat = pPartFile->GetCategory();

			CString strCategory(thePrefs.GetCategory(pCat)->strTitle);
			strCategory.Replace(_T("'"), _T("\\'"));

			dFile.sCategory = strCategory;

			dFile.sFileHash = md4str(pPartFile->GetFileHash());
			dFile.lSourceCount = pPartFile->GetSourceCount();
			dFile.lNotCurrentSourceCount = pPartFile->GetNotCurrentSourcesCount();
			dFile.lTransferringSourceCount = pPartFile->GetTransferringSrcCount();
			dFile.bIsComplete = !pPartFile->IsPartFile();
			dFile.bIsPreview = pPartFile->IsReadyForPreview();
			dFile.bIsGetFLC = pPartFile->GetPreviewPrio();

			if (theApp.GetPublicIP() != 0 && !theApp.IsFirewalled())
				dFile.sED2kLink = pPartFile->GetED2kLink(false, false, false, true, theApp.GetPublicIP());
			else
				dFile.sED2kLink = pPartFile->GetED2kLink();

			dFile.sFileInfo = _SpecialChars(pPartFile->GetInfoSummary(true), false);

			FilesArray.Add(dFile);
		}
	}

	SortParams dprm{ (int)pThis->m_Params.DownloadSort, pThis->m_Params.bDownloadSortReverse };
	qsort_s(FilesArray.GetData(), FilesArray.GetCount(), sizeof(DownloadFiles), &_DownloadCmp, &dprm);

	CArray<UploadUsers> UploadArray;

	for (POSITION pos = theApp.uploadqueue->GetFirstFromUploadList(); pos != NULL;) {
		UploadUsers dUser;
		const CUpDownClient &cur_client(*theApp.uploadqueue->GetNextFromUploadList(pos));
		dUser.sUserHash = md4str(cur_client.GetUserHash());
		if (cur_client.GetUploadDatarate() > 0) {
			dUser.sActive = _T("downloading");
			dUser.sClientState = _T("uploading");
		} else {
			dUser.sActive = _T("waiting");
			dUser.sClientState = _T("connecting");
		}

		dUser.sFileInfo = _SpecialChars(_GetClientSummary(cur_client), false);
		dUser.sFileInfo.Replace(_T("\\"), _T("\\\\"));
		dUser.sFileInfo.Replace(_T("\n"), _T("<br>"));
		dUser.sFileInfo.Replace(_T("'"), _T("&#8217;"));

		_GetClientversionImage(cur_client, dUser.sClientSoft);

		if (cur_client.IsBanned())
			dUser.sClientExtra = _T("banned");
		else if (cur_client.IsFriend())
			dUser.sClientExtra = _T("friend");
		else if (cur_client.Credits()->GetScoreRatio(cur_client.GetIP()) > 1)
			dUser.sClientExtra = _T("credit");
		else
			dUser.sClientExtra = _T("none");

		CString cname(cur_client.GetUserName());
		if (cname.GetLength() > SHORT_LENGTH_MIN) {
			cname.Truncate(SHORT_LENGTH_MIN - 3);
			cname += _T("...");
		}
		dUser.sUserName = _SpecialChars(cname);

		CKnownFile *file = theApp.sharedfiles->GetFileByID(cur_client.GetUploadFileID());
		dUser.sFileName = file ? _SpecialChars(file->GetFileName()) : _GetPlainResString(IDS_REQ_UNKNOWNFILE);
		dUser.nTransferredDown = cur_client.GetTransferredDown();
		dUser.nTransferredUp = cur_client.GetTransferredUp();
		UINT uDataRate = cur_client.GetUploadDatarate();
		dUser.nDataRate = (uDataRate == UNLIMITED) ? 0 : uDataRate;
		dUser.sClientNameVersion = cur_client.GetClientSoftVer();
		UploadArray.Add(dUser);
	}

	SortParams uprm{ (int)pThis->m_Params.UploadSort, pThis->m_Params.bUploadSortReverse };
	qsort_s(UploadArray.GetData(), UploadArray.GetCount(), sizeof(UploadUsers), &_UploadCmp, &uprm);

	_MakeTransferList(Out, pThis, Data, &FilesArray, &UploadArray, bAdmin);

	Out.Replace(_T("[Session]"), sSession);
	Out.Replace(_T("[CatSel]"), sCat);

	return Out;
}

void CWebServer::_MakeTransferList(CString &Out, CWebServer *pThis, const ThreadData &Data, void *_FilesArray, void *_UploadArray, bool bAdmin)
{
	CArray<DownloadFiles> *FilesArray = (CArray<DownloadFiles>*)_FilesArray;
	CArray<UploadUsers> *UploadArray = (CArray<UploadUsers>*)_UploadArray;

	// Displaying
	int nCountQueue = 0;
	int nCountQueueBanned = 0;
	int nCountQueueFriend = 0;
	int nCountQueueSecure = 0;
	int nCountQueueBannedSecure = 0;
	int nCountQueueFriendSecure = 0;

	CQArray<QueueUsers, QueueUsers> QueueArray;
	for (POSITION pos = theApp.uploadqueue->waitinglist.GetHeadPosition(); pos != NULL;) {
		QueueUsers dUser;
		const CUpDownClient &cur_client(*theApp.uploadqueue->waitinglist.GetNext(pos));
		int iSecure = static_cast<int>(cur_client.Credits()->GetCurrentIdentState(cur_client.GetIP()) == IS_IDENTIFIED);
		if (cur_client.IsBanned()) {
			dUser.sClientExtra = _T("banned");
			++nCountQueueBanned;
			nCountQueueBannedSecure += iSecure;
		} else if (cur_client.IsFriend()) {
			dUser.sClientExtra = _T("friend");
			++nCountQueueFriend;
			nCountQueueFriendSecure += iSecure;
		} else {
			dUser.sClientExtra = _T("none");
			++nCountQueue;
			nCountQueueSecure += iSecure;
		}

		CString usn(cur_client.GetUserName());
		if (usn.GetLength() > SHORT_LENGTH_MIN) {
			usn.Truncate(SHORT_LENGTH_MIN - 3);
			usn += _T("...");
		}
		dUser.sUserName = _SpecialChars(usn);

		dUser.sClientNameVersion = cur_client.GetClientSoftVer();
		CKnownFile *file = theApp.sharedfiles->GetFileByID(cur_client.GetUploadFileID());
		dUser.sFileName = file ? _SpecialChars(file->GetFileName()) : _GetPlainResString(IDS_REQ_UNKNOWNFILE);
		dUser.sClientState = dUser.sClientExtra;
		dUser.sClientStateSpecial = _T("connecting");
		dUser.nScore = cur_client.GetScore(false);

		_GetClientversionImage(cur_client, dUser.sClientSoft);

		dUser.sUserHash = md4str(cur_client.GetUserHash());
		//SyruS CQArray-Sorting setting sIndex according to param
		switch (pThis->m_Params.QueueSort) {
		case QU_SORT_CLIENT:
			dUser.sIndex = dUser.sClientSoft;
			break;
		case QU_SORT_USER:
			dUser.sIndex = dUser.sUserName;
			break;
		case QU_SORT_VERSION:
			dUser.sIndex = dUser.sClientNameVersion;
			break;
		case QU_SORT_FILENAME:
			dUser.sIndex = dUser.sFileName;
			break;
		case QU_SORT_SCORE:
			dUser.sIndex.Format(_T("%09u"), dUser.nScore);
		}
		QueueArray.Add(dUser);
	}

	INT_PTR nNextPos = 0;	// position in queue of the user with the highest score -> next upload user
	uint32 nNextScore = 0;	// highest score -> next upload user
	for (INT_PTR i = QueueArray.GetCount(); --i >= 0;)
		if (QueueArray[i].nScore > nNextScore) {
			nNextPos = i;
			nNextScore = QueueArray[i].nScore;
		}

	if (theApp.uploadqueue->waitinglist.GetHeadPosition() != NULL) {
		QueueArray[nNextPos].sClientState = _T("next");
		QueueArray[nNextPos].sClientStateSpecial = QueueArray[nNextPos].sClientState;
	}

	if ((nCountQueue > 0 && pThis->m_Params.bShowUploadQueue)
		|| (nCountQueueBanned > 0 && pThis->m_Params.bShowUploadQueueBanned)
		|| (nCountQueueFriend > 0 && pThis->m_Params.bShowUploadQueueFriend))
	{
#ifdef _DEBUG
		const DWORD dwStart = ::GetTickCount();
#endif
		QueueArray.QuickSort(pThis->m_Params.bQueueSortReverse);
#ifdef _DEBUG
		AddDebugLogLine(false, _T("WebServer: Waitingqueue with %u elements sorted in %u ms"), QueueArray.GetCount(), ::GetTickCount() - dwStart);
#endif
	}

	CString HTTPProcessData;
	CString sDownList, HTTPTemp;
	LPCTSTR pcTmp;
	double fTotalSize = 0, fTotalTransferred = 0, fTotalSpeed = 0;

	CString OutE(pThis->m_Templates.sTransferDownLine);
	for (INT_PTR i = 0; i < FilesArray->GetCount(); ++i) {
		const DownloadFiles &downf((*FilesArray)[i]);
		HTTPProcessData = OutE;

		pcTmp = (downf.sFileHash == _ParseURL(Data.sURL, _T("file"))) ? _T("checked") : _T("checked_no");
		HTTPProcessData.Replace(_T("[LastChangedDataset]"), pcTmp);

		//CPartFile *found_file = theApp.downloadqueue->GetFileByID(_GetFileHash(dwnlf.sFileHash, FileHashA4AF));

		CString strFinfo(downf.sFileInfo);
		strFinfo.Replace(_T("\\"), _T("\\\\"));
		CString strFileInfo(strFinfo);

		strFinfo.Replace(_T("'"), _T("&#8217;"));
		strFinfo.Replace(_T("\n"), _T("\\n"));

		strFileInfo.Replace(_T("\n"), _T("<br>"));

		if (!downf.iComment) {
			HTTPProcessData.Replace(_T("[HASCOMMENT]"), _T("<!--"));
			HTTPProcessData.Replace(_T("[HASCOMMENT_END]"), _T("-->"));
		} else {
			HTTPProcessData.Replace(_T("[HASCOMMENT]"), _T(""));
			HTTPProcessData.Replace(_T("[HASCOMMENT_END]"), _T(""));
		}

		if (downf.sFileState.CompareNoCase(_T("downloading")) == 0 || downf.sFileState.CompareNoCase(_T("waiting")) == 0) {
			HTTPProcessData.Replace(_T("[ISACTIVE]"), _T("<!--"));
			HTTPProcessData.Replace(_T("[ISACTIVE_END]"), _T("-->"));
			HTTPProcessData.Replace(_T("[!ISACTIVE]"), _T(""));
			HTTPProcessData.Replace(_T("[!ISACTIVE_END]"), _T(""));
		} else {
			HTTPProcessData.Replace(_T("[ISACTIVE]"), _T(""));
			HTTPProcessData.Replace(_T("[ISACTIVE_END]"), _T(""));
			HTTPProcessData.Replace(_T("[!ISACTIVE]"), _T("<!--"));
			HTTPProcessData.Replace(_T("[!ISACTIVE_END]"), _T("-->"));
		}

		CString ed2k(downf.sED2kLink); //ed2klink
		ed2k.Replace(_T("'"), _T("&#8217;"));
		CString fsize; //file size
		fsize.Format(_T("%I64u"), downf.m_qwFileSize);
		const CString &session(_ParseURL(Data.sURL, _T("ses")));

		CString isgetflc; //getflc
		if (!downf.bIsPreview)
			isgetflc = downf.bIsGetFLC ? _T("enabled") : _T("disabled");

		//priority
		if (downf.bFileAutoPrio)
			pcTmp = _T("Auto");
		else {
			switch (downf.nFilePrio) {
			case 0:
				pcTmp = _T("Low");
				break;
			case 1:
				pcTmp = _T("Normal");
				break;
			case 2:
				pcTmp = _T("High");
				break;
			default:
				pcTmp = _T("");
			}
		}

		HTTPProcessData.Replace(_T("[admin]"), bAdmin ? _T("admin") : _T(""));
		HTTPProcessData.Replace(_T("[finfo]"), strFinfo);
		HTTPProcessData.Replace(_T("[fcomments]"), downf.iComment ? _T("yes") : _T(""));
		HTTPProcessData.Replace(_T("[ed2k]"), _SpecialChars(ed2k));
		HTTPProcessData.Replace(_T("[DownState]"), downf.sFileState);
		HTTPProcessData.Replace(_T("[isgetflc]"), isgetflc);
		HTTPProcessData.Replace(_T("[fname]"), _SpecialChars(downf.sFileNameJS));
		HTTPProcessData.Replace(_T("[fsize]"), fsize);
		HTTPProcessData.Replace(_T("[session]"), session);
		HTTPProcessData.Replace(_T("[filehash]"), downf.sFileHash);
		HTTPProcessData.Replace(_T("[down-priority]"), pcTmp);
		HTTPProcessData.Replace(_T("[FileType]"), downf.sFileType);
		HTTPProcessData.Replace(_T("[downloadable]"), (bAdmin && (thePrefs.GetMaxWebUploadFileSizeMB() == 0 || downf.m_qwFileSize < ((uint64)thePrefs.GetMaxWebUploadFileSizeMB()) * 1024 * 1024)) ? _T("yes") : _T("no"));

		// comment icon
		switch (downf.iComment) {
		case 1:
			pcTmp = _T("cmtgood");
			break;
		case 2:
			pcTmp = _T("cmtbad");
			break;
		//case 0:
		default:
			pcTmp = _T("none");
		}
		HTTPProcessData.Replace(_T("[FileCommentIcon]"), pcTmp);

		pcTmp = (!downf.bIsPreview && downf.bIsGetFLC) ? _T("getflc") : _T("halfnone");
		HTTPProcessData.Replace(_T("[FileIsGetFLC]"), pcTmp);

		if (WSdownloadColumnHidden[0])
			HTTPProcessData.Replace(_T("[ShortFileName]"), _T(""));
		else if (downf.sFileName.GetLength() > (SHORT_LENGTH_MAX))
			HTTPProcessData.Replace(_T("[ShortFileName]"), downf.sFileName.Left(SHORT_LENGTH_MAX - 3) + _T("..."));
		else
			HTTPProcessData.Replace(_T("[ShortFileName]"), downf.sFileName);

		HTTPProcessData.Replace(_T("[FileInfo]"), strFileInfo);
		fTotalSize += downf.m_qwFileSize;

		HTTPProcessData.Replace(_T("[2]"), WSdownloadColumnHidden[1] ? _T("") : (LPCTSTR)CastItoXBytes(downf.m_qwFileSize));

		if (WSdownloadColumnHidden[2])
			HTTPProcessData.Replace(_T("[3]"), _T(""));
		else if (downf.m_qwFileTransferred > 0) {
			fTotalTransferred += downf.m_qwFileTransferred;
			HTTPProcessData.Replace(_T("[3]"), CastItoXBytes(downf.m_qwFileTransferred));
		} else
			HTTPProcessData.Replace(_T("[3]"), _T("-"));

		HTTPProcessData.Replace(_T("[DownloadBar]"), WSdownloadColumnHidden[3] ? _T("") : (LPCTSTR)_GetDownloadGraph(Data, downf.sFileHash));

		if (WSdownloadColumnHidden[4])
			pcTmp = _T("");
		else if (downf.lFileSpeed > 0) {
			fTotalSpeed += downf.lFileSpeed;
			HTTPTemp.Format(_T("%8.2f"), downf.lFileSpeed / 1024.0);
			pcTmp = HTTPTemp;
		} else
			pcTmp = _T("-");
		HTTPProcessData.Replace(_T("[4]"), pcTmp);

		if (WSdownloadColumnHidden[5])
			pcTmp = _T("");
		else if (downf.lSourceCount > 0) {
			HTTPTemp.Format(_T("%li&nbsp;/&nbsp;%8li&nbsp;(%li)"),
				downf.lSourceCount - downf.lNotCurrentSourceCount,
				downf.lSourceCount,
				downf.lTransferringSourceCount);
			pcTmp = HTTPTemp;
		} else
			pcTmp = _T("-");
		HTTPProcessData.Replace(_T("[5]"), pcTmp);

		if (WSdownloadColumnHidden[6] || downf.nFilePrio < 0 || downf.nFilePrio > 2)
			HTTPProcessData.Replace(_T("[PrioVal]"), _T(""));
		else {
			static const UINT uprio[2][3] =
			{
				{IDS_PRIOLOW, IDS_PRIONORMAL, IDS_PRIOHIGH},
				{IDS_PRIOAUTOLOW, IDS_PRIOAUTONORMAL, IDS_PRIOAUTOHIGH}
			};
			HTTPProcessData.Replace(_T("[PrioVal]"), GetResString(uprio[static_cast<unsigned>(downf.bFileAutoPrio)][downf.nFilePrio]));
		}

		pcTmp = WSdownloadColumnHidden[7] ? _T("") : (LPCTSTR)downf.sCategory;
		HTTPProcessData.Replace(_T("[Category]"), pcTmp);

		_InsertCatBox(HTTPProcessData, 0, _T(""), false, false, session, downf.sFileHash);

		sDownList += HTTPProcessData;
	}

	Out.Replace(_T("[DownloadFilesList]"), sDownList);
	Out.Replace(_T("[TotalDownSize]"), CastItoXBytes(fTotalSize));

	Out.Replace(_T("[TotalDownTransferred]"), CastItoXBytes(fTotalTransferred));

	HTTPTemp.Format(_T("%8.2f"), fTotalSpeed / 1024.0);
	Out.Replace(_T("[TotalDownSpeed]"), HTTPTemp);

	HTTPTemp.Format(_T("%s: %i"), (LPCTSTR)GetResString(IDS_SF_FILE), (int)FilesArray->GetCount());
	Out.Replace(_T("[TotalFiles]"), HTTPTemp);

	HTTPTemp.Format(_T("%i"), pThis->m_Templates.iProgressbarWidth);
	Out.Replace(_T("[PROGRESSBARWIDTHVAL]"), HTTPTemp);

	fTotalSize = fTotalTransferred = fTotalSpeed = 0;

	OutE = pThis->m_Templates.sTransferUpLine;
	OutE.Replace(_T("[admin]"), bAdmin ? _T("admin") : _T(""));

	CString sUpList;
	for (INT_PTR i = 0; i < UploadArray->GetCount(); ++i) {
		const UploadUsers &ulu((*UploadArray)[i]);
		HTTPProcessData = OutE;

		HTTPProcessData.Replace(_T("[UserHash]"), ulu.sUserHash);
		HTTPProcessData.Replace(_T("[UpState]"), ulu.sActive);
		HTTPProcessData.Replace(_T("[FileInfo]"), ulu.sFileInfo);
		HTTPProcessData.Replace(_T("[ClientState]"), ulu.sClientState);
		HTTPProcessData.Replace(_T("[ClientSoft]"), ulu.sClientSoft);
		HTTPProcessData.Replace(_T("[ClientExtra]"), ulu.sClientExtra);

		pcTmp = WSuploadColumnHidden[0] ? _T("") : (LPCTSTR)ulu.sUserName;
		HTTPProcessData.Replace(_T("[1]"), pcTmp);

		pcTmp = WSuploadColumnHidden[1] ? _T("") : (LPCTSTR)ulu.sClientNameVersion;
		HTTPProcessData.Replace(_T("[ClientSoftV]"), pcTmp);

		pcTmp = WSuploadColumnHidden[2] ? _T("") : (LPCTSTR)ulu.sFileName;
		HTTPProcessData.Replace(_T("[2]"), pcTmp);

		if (WSuploadColumnHidden[3])
			pcTmp = _T("");
		else {
			fTotalSize += ulu.nTransferredDown;
			fTotalTransferred += ulu.nTransferredUp;
			HTTPTemp.Format(_T("%s / %s"), (LPCTSTR)CastItoXBytes(ulu.nTransferredDown), (LPCTSTR)CastItoXBytes(ulu.nTransferredUp));
			pcTmp = HTTPTemp;
		}
		HTTPProcessData.Replace(_T("[3]"), pcTmp);

		if (WSuploadColumnHidden[4])
			pcTmp = _T("");
		else {
			fTotalSpeed += ulu.nDataRate;
			HTTPTemp.Format(_T("%8.2f "), max(ulu.nDataRate / 1024.0, 0.0));
			pcTmp = HTTPTemp;
		}
		HTTPProcessData.Replace(_T("[4]"), pcTmp);

		sUpList += HTTPProcessData;
	}
	Out.Replace(_T("[UploadFilesList]"), sUpList);
	HTTPTemp.Format(_T("%s / %s"), (LPCTSTR)CastItoXBytes(fTotalSize), (LPCTSTR)CastItoXBytes(fTotalTransferred));
	Out.Replace(_T("[TotalUpTransferred]"), HTTPTemp);
	HTTPTemp.Format(_T("%8.2f "), max(fTotalSpeed / 1024, 0.0));
	Out.Replace(_T("[TotalUpSpeed]"), HTTPTemp);

	if (pThis->m_Params.bShowUploadQueue) {
		Out.Replace(_T("[UploadQueue]"), pThis->m_Templates.sTransferUpQueueShow);
		Out.Replace(_T("[UploadQueueList]"), _GetPlainResString(IDS_ONQUEUE));

		OutE = pThis->m_Templates.sTransferUpQueueLine;
		OutE.Replace(_T("[admin]"), bAdmin ? _T("admin") : _T(""));

		CString sQueue;
		for (INT_PTR i = 0; i < QueueArray.GetCount(); ++i) {
			if (QueueArray[i].sClientExtra == _T("none")) {
				HTTPProcessData = OutE;
				pcTmp = WSqueueColumnHidden[0] ? _T("") : (LPCTSTR)QueueArray[i].sUserName;
				HTTPProcessData.Replace(_T("[UserName]"), pcTmp);

				pcTmp = WSqueueColumnHidden[1] ? _T("") : (LPCTSTR)QueueArray[i].sClientNameVersion;
				HTTPProcessData.Replace(_T("[ClientSoftV]"), pcTmp);

				pcTmp = WSqueueColumnHidden[2] ? _T("") : (LPCTSTR)QueueArray[i].sFileName;
				HTTPProcessData.Replace(_T("[FileName]"), pcTmp);

				TCHAR HTTPTempC[20];
				if (WSqueueColumnHidden[3])
					*HTTPTempC = _T('\0');
				else
					_stprintf(HTTPTempC, _T("%i"), QueueArray[i].nScore);
				HTTPProcessData.Replace(_T("[Score]"), HTTPTempC);
				HTTPProcessData.Replace(_T("[ClientState]"), QueueArray[i].sClientState);
				HTTPProcessData.Replace(_T("[ClientStateSpecial]"), QueueArray[i].sClientStateSpecial);
				HTTPProcessData.Replace(_T("[ClientSoft]"), QueueArray[i].sClientSoft);
				HTTPProcessData.Replace(_T("[ClientExtra]"), QueueArray[i].sClientExtra);
				HTTPProcessData.Replace(_T("[UserHash]"), QueueArray[i].sUserHash);

				sQueue += HTTPProcessData;
			}
		}
		Out.Replace(_T("[QueueList]"), sQueue);
	} else
		Out.Replace(_T("[UploadQueue]"), pThis->m_Templates.sTransferUpQueueHide);

	if (pThis->m_Params.bShowUploadQueueBanned) {
		Out.Replace(_T("[UploadQueueBanned]"), pThis->m_Templates.sTransferUpQueueBannedShow);
		Out.Replace(_T("[UploadQueueBannedList]"), _GetPlainResString(IDS_BANNED));

		OutE = pThis->m_Templates.sTransferUpQueueBannedLine;

		CString sQueueBanned;
		for (INT_PTR i = 0; i < QueueArray.GetCount(); ++i) {
			if (QueueArray[i].sClientExtra == _T("banned")) {
				HTTPProcessData = OutE;
				pcTmp = WSqueueColumnHidden[0] ? _T("") : (LPCTSTR)QueueArray[i].sUserName;
				HTTPProcessData.Replace(_T("[UserName]"), pcTmp);

				pcTmp = WSqueueColumnHidden[1] ? _T("") : (LPCTSTR)QueueArray[i].sClientNameVersion;
				HTTPProcessData.Replace(_T("[ClientSoftV]"), pcTmp);

				pcTmp = WSqueueColumnHidden[2] ? _T("") : (LPCTSTR)QueueArray[i].sFileName;
				HTTPProcessData.Replace(_T("[FileName]"), pcTmp);

				TCHAR HTTPTempC[20];
				if (WSqueueColumnHidden[3])
					*HTTPTempC = _T('\0');
				else
					_stprintf(HTTPTempC, _T("%i"), QueueArray[i].nScore);
				HTTPProcessData.Replace(_T("[Score]"), HTTPTempC);

				HTTPProcessData.Replace(_T("[ClientState]"), QueueArray[i].sClientState);
				HTTPProcessData.Replace(_T("[ClientStateSpecial]"), QueueArray[i].sClientStateSpecial);
				HTTPProcessData.Replace(_T("[ClientSoft]"), QueueArray[i].sClientSoft);
				HTTPProcessData.Replace(_T("[ClientExtra]"), QueueArray[i].sClientExtra);
				HTTPProcessData.Replace(_T("[UserHash]"), QueueArray[i].sUserHash);

				sQueueBanned += HTTPProcessData;
			}
		}
		Out.Replace(_T("[QueueListBanned]"), sQueueBanned);
	} else
		Out.Replace(_T("[UploadQueueBanned]"), pThis->m_Templates.sTransferUpQueueBannedHide);

	if (pThis->m_Params.bShowUploadQueueFriend) {
		Out.Replace(_T("[UploadQueueFriend]"), pThis->m_Templates.sTransferUpQueueFriendShow);
		Out.Replace(_T("[UploadQueueFriendList]"), _GetPlainResString(IDS_IRC_ADDTOFRIENDLIST));

		OutE = pThis->m_Templates.sTransferUpQueueFriendLine;

		CString sQueueFriend;
		for (INT_PTR i = 0; i < QueueArray.GetCount(); ++i) {
			if (QueueArray[i].sClientExtra == _T("friend")) {
				HTTPProcessData = OutE;
				pcTmp = WSqueueColumnHidden[0] ? _T("") : (LPCTSTR)QueueArray[i].sUserName;
				HTTPProcessData.Replace(_T("[UserName]"), pcTmp);

				pcTmp = WSqueueColumnHidden[1] ? _T("") : (LPCTSTR)QueueArray[i].sClientNameVersion;
				HTTPProcessData.Replace(_T("[ClientSoftV]"), pcTmp);

				pcTmp = WSqueueColumnHidden[2] ? _T("") : (LPCTSTR)QueueArray[i].sFileName;
				HTTPProcessData.Replace(_T("[FileName]"), pcTmp);

				TCHAR HTTPTempC[20];
				if (WSqueueColumnHidden[3])
					*HTTPTempC = _T('\0');
				else
					_stprintf(HTTPTempC, _T("%i"), QueueArray[i].nScore);
				HTTPProcessData.Replace(_T("[Score]"), HTTPTempC);

				HTTPProcessData.Replace(_T("[ClientState]"), QueueArray[i].sClientState);
				HTTPProcessData.Replace(_T("[ClientStateSpecial]"), QueueArray[i].sClientStateSpecial);
				HTTPProcessData.Replace(_T("[ClientSoft]"), QueueArray[i].sClientSoft);
				HTTPProcessData.Replace(_T("[ClientExtra]"), QueueArray[i].sClientExtra);
				HTTPProcessData.Replace(_T("[UserHash]"), QueueArray[i].sUserHash);

				sQueueFriend += HTTPProcessData;
			}
		}
		Out.Replace(_T("[QueueListFriend]"), sQueueFriend);
	} else
		Out.Replace(_T("[UploadQueueFriend]"), pThis->m_Templates.sTransferUpQueueFriendHide);


	CString mCounter;
	mCounter.Format(_T("%i"), nCountQueue);
	Out.Replace(_T("[CounterQueue]"), mCounter);
	mCounter.Format(_T("%i"), nCountQueueBanned);
	Out.Replace(_T("[CounterQueueBanned]"), mCounter);
	mCounter.Format(_T("%i"), nCountQueueFriend);
	Out.Replace(_T("[CounterQueueFriend]"), mCounter);
	mCounter.Format(_T("%i"), nCountQueueSecure);
	Out.Replace(_T("[CounterQueueSecure]"), mCounter);
	mCounter.Format(_T("%i"), nCountQueueBannedSecure);
	Out.Replace(_T("[CounterQueueBannedSecure]"), mCounter);
	mCounter.Format(_T("%i"), nCountQueueFriendSecure);
	Out.Replace(_T("[CounterQueueFriendSecure]"), mCounter);
	mCounter.Format(_T("%i"), nCountQueue + nCountQueueBanned + nCountQueueFriend);
	Out.Replace(_T("[CounterAll]"), mCounter);
	mCounter.Format(_T("%i"), nCountQueueSecure + nCountQueueBannedSecure + nCountQueueFriendSecure);
	Out.Replace(_T("[CounterAllSecure]"), mCounter);
	Out.Replace(_T("[ShowUploadQueue]"), _GetPlainResString(IDS_VIEWQUEUE));
	Out.Replace(_T("[ShowUploadQueueList]"), _GetPlainResString(IDS_WEB_SHOW_UPLOAD_QUEUE));

	Out.Replace(_T("[ShowUploadQueueListBanned]"), _GetPlainResString(IDS_WEB_SHOW_UPLOAD_QUEUE_BANNED));
	Out.Replace(_T("[ShowUploadQueueListFriend]"), _GetPlainResString(IDS_WEB_SHOW_UPLOAD_QUEUE_FRIEND));

	CString strTmp(pThis->m_Params.bQueueSortReverse ? _T("&amp;sortreverse=false") : _T("&amp;sortreverse=true"));

	if (pThis->m_Params.QueueSort == QU_SORT_CLIENT)
		Out.Replace(_T("[SortQClient]"), strTmp);
	else
		Out.Replace(_T("[SortQClient]"), _T(""));
	if (pThis->m_Params.QueueSort == QU_SORT_USER)
		Out.Replace(_T("[SortQUser]"), strTmp);
	else
		Out.Replace(_T("[SortQUser]"), _T(""));
	if (pThis->m_Params.QueueSort == QU_SORT_VERSION)
		Out.Replace(_T("[SortQVersion]"), strTmp);
	else
		Out.Replace(_T("[SortQVersion]"), _T(""));
	if (pThis->m_Params.QueueSort == QU_SORT_FILENAME)
		Out.Replace(_T("[SortQFilename]"), strTmp);
	else
		Out.Replace(_T("[SortQFilename]"), _T(""));
	if (pThis->m_Params.QueueSort == QU_SORT_SCORE)
		Out.Replace(_T("[SortQScore]"), strTmp);
	else
		Out.Replace(_T("[SortQScore]"), _T(""));

	CString pcSortIcon(pThis->m_Params.bQueueSortReverse ? pThis->m_Templates.sUpArrow : pThis->m_Templates.sDownArrow);

	_GetPlainResString(strTmp, IDS_QL_USERNAME);
	if (WSqueueColumnHidden[0]) {
		Out.Replace(_T("[UserNameTitleI]"), _T(""));
		Out.Replace(_T("[UserNameTitle]"), _T(""));
	} else {
		if (pThis->m_Params.QueueSort == QU_SORT_USER)
			Out.Replace(_T("[UserNameTitleI]"), pcSortIcon);
		else
			Out.Replace(_T("[UserNameTitleI]"), _T(""));
		//Out.Replace (_T("[UserNameTitleI]"), (pThis->m_Params.QueueSort == QU_SORT_USER) ? (LPCTSTR)pcSortIcon : _T(""));
		Out.Replace(_T("[UserNameTitle]"), strTmp);
	}
	Out.Replace(_T("[UserNameTitleM]"), strTmp);

	_GetPlainResString(strTmp, IDS_CD_CSOFT);
	if (WSqueueColumnHidden[1]) {
		Out.Replace(_T("[VersionI]"), _T(""));
		Out.Replace(_T("[Version]"), _T(""));
	} else {
		if (pThis->m_Params.QueueSort == QU_SORT_VERSION)
			Out.Replace(_T("[VersionI]"), pcSortIcon);
		else
			Out.Replace(_T("[VersionI]"), _T(""));
		//Out.Replace (_T("[VersionI]"), (pThis->m_Params.QueueSort == QU_SORT_VERSION) ? (LPCTSTR)pcSortIcon : _T(""));
		Out.Replace(_T("[Version]"), strTmp);
	}
	Out.Replace(_T("[VersionM]"), strTmp);

	_GetPlainResString(strTmp, IDS_DL_FILENAME);
	if (WSqueueColumnHidden[2]) {
		Out.Replace(_T("[FileNameTitleI]"), _T(""));
		Out.Replace(_T("[FileNameTitle]"), _T(""));
	} else {
		if (pThis->m_Params.QueueSort == QU_SORT_FILENAME)
			Out.Replace(_T("[FileNameTitleI]"), pcSortIcon);
		else
			Out.Replace(_T("[FileNameTitleI]"), _T(""));
		//Out.Replace (_T("[FileNameTitleI]"), (pThis->m_Params.QueueSort == QU_SORT_FILENAME) ? (LPCTSTR)pcSortIcon : _T(""));
		Out.Replace(_T("[FileNameTitle]"), strTmp);
	}
	Out.Replace(_T("[FileNameTitleM]"), strTmp);

	_GetPlainResString(strTmp, IDS_SCORE);
	if (WSqueueColumnHidden[3]) {
		Out.Replace(_T("[ScoreTitleI]"), _T(""));
		Out.Replace(_T("[ScoreTitle]"), _T(""));
	} else {
		if (pThis->m_Params.QueueSort == QU_SORT_SCORE)
			Out.Replace(_T("[ScoreTitleI]"), pcSortIcon);
		else
			Out.Replace(_T("[ScoreTitleI]"), _T(""));
		//Out.Replace (_T("[ScoreTitleI]"), (pThis->m_Params.QueueSort == QU_SORT_SCORE) ? (LPCTSTR)pcSortIcon : _T(""));
		Out.Replace(_T("[ScoreTitle]"), strTmp);
	}
	Out.Replace(_T("[ScoreTitleM]"), strTmp);
}

void CWebServer::_SetBoolean(bool &var, const CString &URL, LPCTSTR pFieldname)
{
	const CString &sBool(_ParseURL(URL, pFieldname));
	if (sBool == _T("true"))
		var = true;
	else if (sBool == _T("false"))
		var = false;
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

	if (!strSort.IsEmpty()) {
		bool bDirection = false;

		if (strSort == _T("state"))
			pThis->m_Params.SharedSort = SHARED_SORT_STATE;
		else if (strSort == _T("type"))
			pThis->m_Params.SharedSort = SHARED_SORT_TYPE;
		else if (strSort == _T("name")) {
			pThis->m_Params.SharedSort = SHARED_SORT_NAME;
			bDirection = true;
		} else if (strSort == _T("size"))
			pThis->m_Params.SharedSort = SHARED_SORT_SIZE;
		else if (strSort == _T("transferred"))
			pThis->m_Params.SharedSort = SHARED_SORT_TRANSFERRED;
		else if (strSort == _T("alltimetransferred"))
			pThis->m_Params.SharedSort = SHARED_SORT_ALL_TIME_TRANSFERRED;
		else if (strSort == _T("requests"))
			pThis->m_Params.SharedSort = SHARED_SORT_REQUESTS;
		else if (strSort == _T("alltimerequests"))
			pThis->m_Params.SharedSort = SHARED_SORT_ALL_TIME_REQUESTS;
		else if (strSort == _T("accepts"))
			pThis->m_Params.SharedSort = SHARED_SORT_ACCEPTS;
		else if (strSort == _T("alltimeaccepts"))
			pThis->m_Params.SharedSort = SHARED_SORT_ALL_TIME_ACCEPTS;
		else if (strSort == _T("completes"))
			pThis->m_Params.SharedSort = SHARED_SORT_COMPLETES;
		else if (strSort == _T("priority"))
			pThis->m_Params.SharedSort = SHARED_SORT_PRIORITY;

		if (strTmp.IsEmpty())
			pThis->m_Params.bSharedSortReverse = bDirection;
	}
	if (!strTmp.IsEmpty())
		pThis->m_Params.bSharedSortReverse = (strTmp == _T("true"));

	if (bAdmin) {
		CString hash(_ParseURL(Data.sURL, _T("hash")));
		const CString &sPrio(_ParseURL(Data.sURL, _T("prio")));
		if (!hash.IsEmpty() && !sPrio.IsEmpty()) {
			uchar fileid[MDX_DIGEST_SIZE];
			if (hash.GetLength() == 32 && DecodeBase16(hash, hash.GetLength(), fileid, _countof(fileid))) {
				CKnownFile *pFile = theApp.sharedfiles->GetFileByID(fileid);
				if (pFile != NULL) {
					uint8 uPrio;
					if (sPrio == _T("verylow"))
						uPrio = PR_VERYLOW;
					else if (sPrio == _T("low"))
						uPrio = PR_LOW;
					else if (sPrio == _T("normal"))
						uPrio = PR_NORMAL;
					else if (sPrio == _T("high"))
						uPrio = PR_HIGH;
					else if (sPrio == _T("release"))
						uPrio = PR_VERYHIGH;
					else //if (sPrio == _T("auto"))
						uPrio = PR_AUTO;
					if (uPrio == PR_AUTO) {
						pFile->SetAutoUpPriority(true);
						pFile->UpdateAutoUpPriority();
					} else {
						pFile->SetAutoUpPriority(false);
						pFile->SetUpPriority(uPrio);
					}
					SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_UPD_SFUPDATE, (LPARAM)pFile);
				}
			}
		}
	}

	if (_ParseURL(Data.sURL, _T("c")) == _T("menu")) {
		int iMenu = _tstoi(_ParseURL(Data.sURL, _T("m")));
		bool bValue = _tstoi(_ParseURL(Data.sURL, _T("v"))) != 0;
		WSsharedColumnHidden[iMenu] = bValue;
		_SaveWIConfigArray(WSsharedColumnHidden, _countof(WSsharedColumnHidden), _T("sharedColumnHidden"));
	}
	if (_ParseURL(Data.sURL, _T("reload")) == _T("true"))
		SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_SHARED_FILES_RELOAD, 0);

	strTmp = (pThis->m_Params.bSharedSortReverse) ? _T("false") : _T("true");

	CString Out(pThis->m_Templates.sSharedList);
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

	const TCHAR *pcSortIcon = (pThis->m_Params.bSharedSortReverse) ? pThis->m_Templates.sUpArrow : pThis->m_Templates.sDownArrow;

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
		LPCTSTR pcIconTmp = (pThis->m_Params.SharedSort == SHARED_SORT_TRANSFERRED) ? pcSortIcon : _T("");
		if (pThis->m_Params.SharedSort == SHARED_SORT_ALL_TIME_TRANSFERRED)
			pcIconTmp = (pThis->m_Params.bSharedSortReverse) ? pThis->m_Templates.sUpDoubleArrow : pThis->m_Templates.sDownDoubleArrow;
		Out.Replace(_T("[FileTransferredI]"), pcIconTmp);
		Out.Replace(_T("[FileTransferred]"), strTmp);
	}
	Out.Replace(_T("[FileTransferredM]"), strTmp);

	_GetPlainResString(strTmp, IDS_SF_REQUESTS);
	if (WSsharedColumnHidden[2]) {
		Out.Replace(_T("[FileRequestsI]"), _T(""));
		Out.Replace(_T("[FileRequests]"), _T(""));
	} else {
		LPCTSTR pcIconTmp = (pThis->m_Params.SharedSort == SHARED_SORT_REQUESTS) ? pcSortIcon : _T("");
		if (pThis->m_Params.SharedSort == SHARED_SORT_ALL_TIME_REQUESTS)
			pcIconTmp = (pThis->m_Params.bSharedSortReverse) ? pThis->m_Templates.sUpDoubleArrow : pThis->m_Templates.sDownDoubleArrow;
		Out.Replace(_T("[FileRequestsI]"), pcIconTmp);
		Out.Replace(_T("[FileRequests]"), strTmp);
	}
	Out.Replace(_T("[FileRequestsM]"), strTmp);

	_GetPlainResString(strTmp, IDS_SF_ACCEPTS);
	if (WSsharedColumnHidden[3]) {
		Out.Replace(_T("[FileAcceptsI]"), _T(""));
		Out.Replace(_T("[FileAccepts]"), _T(""));
	} else {
		LPCTSTR pcIconTmp = (pThis->m_Params.SharedSort == SHARED_SORT_ACCEPTS) ? pcSortIcon : _T("");
		if (pThis->m_Params.SharedSort == SHARED_SORT_ALL_TIME_ACCEPTS)
			pcIconTmp = (pThis->m_Params.bSharedSortReverse) ? pThis->m_Templates.sUpDoubleArrow : pThis->m_Templates.sDownDoubleArrow;
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

	CString OutE(pThis->m_Templates.sSharedLine);

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

			if (pFile->m_nCompleteSourcesCountLo == 0)
				dFile.sFileCompletes.Format(_T("< %hu"), pFile->m_nCompleteSourcesCountHi);
			else if (pFile->m_nCompleteSourcesCountLo == pFile->m_nCompleteSourcesCountHi)
				dFile.sFileCompletes.Format(_T("%hu"), pFile->m_nCompleteSourcesCountLo);
			else
				dFile.sFileCompletes.Format(_T("%hu - %hu"), pFile->m_nCompleteSourcesCountLo, pFile->m_nCompleteSourcesCountHi);

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

		LPCTSTR sharedpriority;	//priority
		if (SharedArray[i].bFileAutoPriority)
			sharedpriority = _T("Auto");
		else
			switch (SharedArray[i].nFilePriority) {
			case PR_VERYLOW:
				sharedpriority = _T("VeryLow");
				break;
			case PR_LOW:
				sharedpriority = _T("Low");
				break;
			case PR_NORMAL:
				sharedpriority = _T("Normal");
				break;
			case PR_HIGH:
				sharedpriority = _T("High");
				break;
			case PR_VERYHIGH:
				sharedpriority = _T("Release");
				break;
			default:
				sharedpriority = _T("");
			}

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
				downloadable = !cur_file->IsPartFile() && (thePrefs.GetMaxWebUploadFileSizeMB() == 0 || SharedArray[i].m_qwFileSize < ((uint64)thePrefs.GetMaxWebUploadFileSizeMB()) * 1024 * 1024);
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

	CString Out(pThis->m_Templates.sGraphs);

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

CString CWebServer::_GetAddServerBox(const ThreadData &Data)
{
	const CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	if (pThis == NULL)
		return CString();

	const CString &sSession(_ParseURL(Data.sURL, _T("ses")));
	if (!_IsSessionAdmin(Data, sSession))
		return CString();

	CString resultlog(_SpecialChars(theApp.emuledlg->GetLastLogEntry())); //Pick-up last line of the log

	CString Out(pThis->m_Templates.sAddServerBox);
	if (_ParseURL(Data.sURL, _T("addserver")) == _T("true")) {
		CString strServerAddress(_ParseURL(Data.sURL, _T("serveraddr")));
		CString strServerPort(_ParseURL(Data.sURL, _T("serverport")));
		if (!strServerAddress.Trim().IsEmpty() && !strServerPort.Trim().IsEmpty()) {
			CString strServerName(_ParseURL(Data.sURL, _T("servername")));
			if (strServerName.Trim().IsEmpty())
				strServerName = strServerAddress;
			CServer *srv = new CServer((uint16)_tstoi(strServerPort), strServerAddress);
			srv->SetListName(strServerName);
			if (!theApp.emuledlg->serverwnd->serverlistctrl.AddServer(srv, true)) {
				delete srv;
				Out.Replace(_T("[Message]"), _GetPlainResString(IDS_ERROR));
			} else {
				const CString &sPrio(_ParseURL(Data.sURL, _T("priority")));
				if (sPrio == _T("low"))
					srv->SetPreference(PR_LOW);
				else if (sPrio == _T("normal"))
					srv->SetPreference(PR_NORMAL);
				else if (sPrio == _T("high"))
					srv->SetPreference(PR_HIGH);

				SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_UPDATESERVER, (LPARAM)srv);

				if (_ParseURL(Data.sURL, _T("addtostatic")) == _T("true")) {
					_AddToStatic(_ParseURL(Data.sURL, _T("serveraddr")), _tstoi(_ParseURL(Data.sURL, _T("serverport"))));
					resultlog.AppendFormat(_T("<br>%s"), (LPCTSTR)_SpecialChars(theApp.emuledlg->GetLastLogEntry())); //Pick-up last line of the log
				}
				resultlog.TrimRight(_T('\n'));
				resultlog.Delete(0, resultlog.ReverseFind(_T('\n')));
				Out.Replace(_T("[Message]"), resultlog);
				if (_ParseURL(Data.sURL, _T("connectnow")) == _T("true"))
					_ConnectToServer(_ParseURL(Data.sURL, _T("serveraddr")), _tstoi(_ParseURL(Data.sURL, _T("serverport"))));
			}
		} else
			Out.Replace(_T("[Message]"), _GetPlainResString(IDS_ERROR));
	} else if (_ParseURL(Data.sURL, _T("updateservermetfromurl")) == _T("true")) {
		const CString &url(_ParseURL(Data.sURL, _T("servermeturl")));
		SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_UPDATESERVERMETFROMURL, (LPARAM)(LPCTSTR)url);

		resultlog = _SpecialChars(theApp.emuledlg->GetLastLogEntry());
		resultlog.TrimRight(_T('\n'));
		resultlog.Delete(0, resultlog.ReverseFind(_T('\n')));
		Out.Replace(_T("[Message]"), resultlog);
	} else
		Out.Replace(_T("[Message]"), _T(""));

	Out.Replace(_T("[AddServer]"), _GetPlainResString(IDS_SV_NEWSERVER));
	Out.Replace(_T("[IP]"), _GetPlainResString(IDS_SV_ADDRESS));
	Out.Replace(_T("[Port]"), _GetPlainResString(IDS_PORT));
	Out.Replace(_T("[Name]"), _GetPlainResString(IDS_SW_NAME));
	Out.Replace(_T("[Static]"), _GetPlainResString(IDS_STATICSERVER));
	Out.Replace(_T("[ConnectNow]"), _GetPlainResString(IDS_IRC_CONNECT));
	Out.Replace(_T("[Priority]"), _GetPlainResString(IDS_PRIORITY));
	Out.Replace(_T("[Low]"), _GetPlainResString(IDS_PRIOLOW));
	Out.Replace(_T("[Normal]"), _GetPlainResString(IDS_PRIONORMAL));
	Out.Replace(_T("[High]"), _GetPlainResString(IDS_PRIOHIGH));
	Out.Replace(_T("[Add]"), _GetPlainResString(IDS_SV_ADD));
	Out.Replace(_T("[UpdateServerMetFromURL]"), _GetPlainResString(IDS_SV_MET));
	Out.Replace(_T("[URL]"), _GetPlainResString(IDS_SV_URL));
	Out.Replace(_T("[Apply]"), _GetPlainResString(IDS_PW_APPLY));
	//for admin only (verified on entry)
	CString s;
	s.Format(_T("?ses=%s&amp;w=server&amp;c=disconnect"), (LPCTSTR)sSession);
	Out.Replace(_T("[URL_Disconnect]"), s);
	s.Format(_T("?ses=%s&amp;w=server&amp;c=connect"), (LPCTSTR)sSession);
	Out.Replace(_T("[URL_Connect]"), s);

	Out.Replace(_T("[Disconnect]"), _GetPlainResString(IDS_IRC_DISCONNECT));
	Out.Replace(_T("[Connect]"), _GetPlainResString(IDS_CONNECTTOANYSERVER));
	Out.Replace(_T("[ServerOptions]"), _GetPlainResString(IDS_CONNECTION));
	Out.Replace(_T("[Execute]"), _GetPlainResString(IDS_IRC_PERFORM));

	return Out;
}

CString CWebServer::_GetLog(const ThreadData &Data)
{
	const CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	if (pThis == NULL)
		return CString();

	const CString &sSession(_ParseURL(Data.sURL, _T("ses")));

	CString Out(pThis->m_Templates.sLog);

	if (_ParseURL(Data.sURL, _T("clear")) == _T("yes") && _IsSessionAdmin(Data, sSession))
		theApp.emuledlg->ResetLog();

	Out.Replace(_T("[Clear]"), _GetPlainResString(IDS_PW_RESET));
	Out.Replace(_T("[Log]"), _SpecialChars(theApp.emuledlg->GetAllLogEntries(), false) + _T("<br><a name=\"end\"></a>"));
	Out.Replace(_T("[Session]"), sSession);

	return Out;
}

CString CWebServer::_GetServerInfo(const ThreadData &Data)
{
	const CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	if (pThis == NULL)
		return CString();

	const CString &sSession(_ParseURL(Data.sURL, _T("ses")));

	CString Out(pThis->m_Templates.sServerInfo);

	if (_ParseURL(Data.sURL, _T("clear")) == _T("yes") && _IsSessionAdmin(Data, sSession))
		theApp.emuledlg->ResetServerInfo();

	Out.Replace(_T("[Clear]"), _GetPlainResString(IDS_PW_RESET));
	Out.Replace(_T("[ServerInfo]"), _SpecialChars(theApp.emuledlg->GetServerInfoText(), false) + _T("<br><a name=\"end\"></a>"));
	Out.Replace(_T("[Session]"), sSession);

	return Out;
}

CString CWebServer::_GetDebugLog(const ThreadData &Data)
{
	const CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	if (pThis == NULL)
		return CString();

	const CString &sSession(_ParseURL(Data.sURL, _T("ses")));

	CString Out(pThis->m_Templates.sDebugLog);

	if (_ParseURL(Data.sURL, _T("clear")) == _T("yes") && _IsSessionAdmin(Data, sSession))
		theApp.emuledlg->ResetDebugLog();

	Out.Replace(_T("[Clear]"), _GetPlainResString(IDS_PW_RESET));
	Out.Replace(_T("[DebugLog]"), _SpecialChars(theApp.emuledlg->GetAllDebugLogEntries(), false) + _T("<br><a name=\"end\"></a>"));
	Out.Replace(_T("[Session]"), sSession);

	return Out;
}

CString CWebServer::_GetMyInfo(const ThreadData &Data)
{
	const CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	if (pThis == NULL)
		return CString();

	//(void)_ParseURL(Data.sURL, _T("ses"));
	CString Out(pThis->m_Templates.sMyInfoLog);

	Out.Replace(_T("[MYINFOLOG]"), theApp.emuledlg->serverwnd->GetMyInfoString());

	return Out;
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
	CString Out(pThis->m_Templates.sKad);

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
	Out.Replace(_T("[BOOTSTRAPLINE]"), Kademlia::CKademlia::IsConnected() ? _T("") : (LPCTSTR)pThis->m_Templates.sBootstrapLine);

	// Infos
	CString buffer;
	if (Kademlia::CKademlia::IsConnected())
		if (Kademlia::CKademlia::IsFirewalled()) {
			Out.Replace(_T("[KADSTATUS]"), GetResString(IDS_FIREWALLED));
			buffer.Format(_T("<a href=\"?ses=%s&amp;w=kad&amp;c=rcfirewall\">%s</a>"), (LPCTSTR)sSession, (LPCTSTR)GetResString(IDS_KAD_RECHECKFW));
			buffer.AppendFormat(_T("<br><a href=\"?ses=%s&amp;w=kad&amp;c=disconnect\">%s</a>"), (LPCTSTR)sSession, (LPCTSTR)GetResString(IDS_IRC_DISCONNECT));
		} else {
			Out.Replace(_T("[KADSTATUS]"), GetResString(IDS_CONNECTED));
			buffer.Format(_T("<a href=\"?ses=%s&amp;w=kad&amp;c=disconnect\">%s</a>"), (LPCTSTR)sSession, (LPCTSTR)GetResString(IDS_IRC_DISCONNECT));
		} else if (Kademlia::CKademlia::IsRunning()) {
			Out.Replace(_T("[KADSTATUS]"), GetResString(IDS_CONNECTING));
			buffer.Format(_T("<a href=\"?ses=%s&amp;w=kad&amp;c=disconnect\">%s</a>"), (LPCTSTR)sSession, (LPCTSTR)GetResString(IDS_IRC_DISCONNECT));
		} else {
			Out.Replace(_T("[KADSTATUS]"), GetResString(IDS_DISCONNECTED));
			buffer.Format(_T("<a href=\"?ses=%s&amp;w=kad&amp;c=connect\">%s</a>"), (LPCTSTR)sSession, (LPCTSTR)GetResString(IDS_IRC_CONNECT));
		}

		Out.Replace(_T("[KADACTION]"), buffer);

		// kadstats
		// labels
		buffer.Format(_T("%s<br>%s"), (LPCTSTR)GetResString(IDS_KADCONTACTLAB), (LPCTSTR)GetResString(IDS_KADSEARCHLAB));
		Out.Replace(_T("[KADSTATSLABELS]"), buffer);

		// numbers
		buffer.Format(_T("%u<br>%i"), theApp.emuledlg->kademliawnd->GetContactCount()
			, theApp.emuledlg->kademliawnd->searchList->GetItemCount());
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
	const CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	if (pThis == NULL)
		return CString();

	//(void)_ParseURL(Data.sURL, _T("ses"));
	// refresh statistics
	SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_SHOWSTATISTICS, 1);

	CString Out(pThis->m_Templates.sStats);
	// eklmn: new stats
	Out.Replace(_T("[Stats]"), theApp.emuledlg->statisticswnd->m_stattree.GetHTMLForExport());

	return Out;
}

CString CWebServer::_GetPreferences(const ThreadData &Data)
{
	const CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	if (pThis == NULL)
		return CString();

	const CString &sSession(_ParseURL(Data.sURL, _T("ses")));

	CString Out(pThis->m_Templates.sPreferences);
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
	m_sTestURL.Format(PORTTESTURL, thePrefs.GetPort(), thePrefs.GetUDPPort(), thePrefs.GetLanguageID());

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
	const CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	if (pThis == NULL)
		return CString();

	//(void)_ParseURL(Data.sURL, _T("ses"));
	CString Out(pThis->m_Templates.sLogin);

	// eSE 8.14: Generate fresh cryptographic nonce for challenge-response
	CStringA aNonce = _GenerateNonce(Data);
	CString sNonce(aNonce);

	Out.Replace(_T("[CharSet]"), HTTPENCODING);
	Out.Replace(_T("[eMuleAppName]"), _T("eMule"));
	Out.Replace(_T("[version]"), theApp.m_strCurVersionLong);
	Out.Replace(_T("[Login]"), _GetPlainResString(IDS_WEB_LOGIN));
	Out.Replace(_T("[EnterPassword]"), _GetPlainResString(IDS_WEB_ENTER_PASSWORD));
	Out.Replace(_T("[LoginNow]"), _GetPlainResString(IDS_WEB_LOGIN_NOW));
	Out.Replace(_T("[WebControl]"), _GetPlainResString(IDS_WEB_CONTROL));
	Out.Replace(_T("[ChallengeNonce]"), sNonce);  // eSE 8.14

	CString sFailed;
	if (pThis->m_nIntruderDetect >= 1)
		sFailed.Format(_T("<p class=\"failed\">%s</p>"), (LPCTSTR)_GetPlainResString(IDS_WEB_BADLOGINATTEMPT));
	else
		sFailed = _T("&nbsp;");
	Out.Replace(_T("[FailedLogin]"), sFailed);

	return Out;
}

// eSE 8.14: Generate a CSPRNG nonce for challenge-response login
CStringA CWebServer::_GenerateNonce(const ThreadData &Data)
{
	CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	if (pThis == NULL)
		return CStringA();

	_PurgeStaleChallenges(Data);

	// 32 cryptographically random bytes -> 64 hex chars
	BYTE nonceBytes[32];
	webRng.GenerateBlock(nonceBytes, sizeof(nonceBytes));

	CStringA sNonce;
	for (int i = 0; i < 32; ++i)
		sNonce.AppendFormat("%02x", nonceBytes[i]);

	// Store the challenge bound to client IP
	PendingChallenge ch;
	ch.sNonce = sNonce;
	ch.dwTimestamp = ::GetTickCount();
	ch.dwClientIP = inet_addr(ipstrA(Data.inadr));
	pThis->m_Params.pendingChallenges.Add(ch);

	// Memory cap: max 64 pending challenges
	while (pThis->m_Params.pendingChallenges.GetCount() > 64)
		pThis->m_Params.pendingChallenges.RemoveAt(0);

	return sNonce;
}

// eSE 8.14: Remove challenges older than 5 minutes
void CWebServer::_PurgeStaleChallenges(const ThreadData &Data)
{
	CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	if (pThis == NULL)
		return;

	const DWORD dwNow = ::GetTickCount();
	for (INT_PTR i = pThis->m_Params.pendingChallenges.GetCount(); --i >= 0;)
		if (dwNow >= pThis->m_Params.pendingChallenges[i].dwTimestamp + 300000u)
			pThis->m_Params.pendingChallenges.RemoveAt(i);
}

// eSE 8.14: Validate SHA256(nonce + storedHash) == clientResponse
bool CWebServer::_ValidateChallengeResponse(const ThreadData &Data,
	const CString &sNonce, const CString &sResponse, bool &outIsAdmin)
{
	CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	if (pThis == NULL)
		return false;

	outIsAdmin = false;

	CStringA aNonce = CT2A(sNonce);
	CStringA aResponse = CT2A(sResponse);
	aNonce.MakeLower();
	aResponse.MakeLower();

	// Find and CONSUME the nonce (one-time use, IP-bound)
	uint32 clientIP = inet_addr(ipstrA(Data.inadr));
	bool nonceFound = false;
	for (INT_PTR i = pThis->m_Params.pendingChallenges.GetCount(); --i >= 0;) {
		const PendingChallenge &ch = pThis->m_Params.pendingChallenges[i];
		if (ch.sNonce == aNonce && ch.dwClientIP == clientIP) {
			pThis->m_Params.pendingChallenges.RemoveAt(i);
			nonceFound = true;
			break;
		}
	}
	if (!nonceFound)
		return false;

	// Helper lambda: compute SHA256(nonce + hashHex) as lowercase hex
	auto computeExpected = [&](const CString &storedHash) -> CStringA {
		CStringA aStored = CT2A(storedHash);
		aStored.MakeLower();
		CStringA toHash = aNonce + aStored;

		CryptoPP::byte digest[CryptoPP::SHA256::DIGESTSIZE];
		CryptoPP::SHA256().CalculateDigest(digest,
			(const CryptoPP::byte*)(LPCSTR)toHash, toHash.GetLength());

		CStringA hexOut;
		for (int j = 0; j < CryptoPP::SHA256::DIGESTSIZE; ++j)
			hexOut.AppendFormat("%02x", digest[j]);
		return hexOut;
	};

	// Check admin password first
	if (!thePrefs.GetWSPass().IsEmpty()) {
		if (computeExpected(thePrefs.GetWSPass()) == aResponse) {
			outIsAdmin = true;
			return true;
		}
	}

	// Check low-privilege password
	if (thePrefs.GetWSIsLowUserEnabled() && !thePrefs.GetWSLowPass().IsEmpty()) {
		if (computeExpected(thePrefs.GetWSLowPass()) == aResponse)
			return true;  // outIsAdmin stays false
	}

	return false;
}

// We have to add gz-header and some other stuff
// to standard zlib functions
// in order to use gzip in web pages
int CWebServer::_GzipCompress(Bytef *dest, uLongf *destLen, const Bytef *source, uLong sourceLen, int level)
{
	static const int gz_magic[2] = {0x1f, 0x8b}; // gzip magic header
	z_stream stream = {};
	stream.zalloc = (alloc_func)NULL;
	stream.zfree = (free_func)NULL;
	stream.opaque = (voidpf)NULL;
	uLong crc = crc32(0, Z_NULL, 0);
	// init Zlib stream
	// NOTE windowBits is passed < 0 to suppress zlib header
	int err = deflateInit2(&stream, level, Z_DEFLATED, -MAX_WBITS, MAX_MEM_LEVEL, Z_DEFAULT_STRATEGY);
	if (err != Z_OK)
		return err;

	if (*destLen < 18) { deflateEnd(&stream); return Z_BUF_ERROR; }
	const BYTE gz_header[10] = { gz_magic[0], gz_magic[1], Z_DEFLATED, 0, 0, 0, 0, 0, 0, 255 };
	memcpy(dest, gz_header, 10);

	// wire buffers
	stream.next_in = (Bytef*)source;
	stream.avail_in = (uInt)sourceLen;
	stream.next_out = &dest[10];
	stream.avail_out = *destLen - 18;
	// do it
	err = deflate(&stream, Z_FINISH);
	if (err != Z_STREAM_END) {
		deflateEnd(&stream);
		return err;
	}
	err = deflateEnd(&stream);
	crc = crc32(crc, (Bytef*)source, (uInt)sourceLen);
	size_t i = 10 + stream.total_out;
	if (i + 8 > *destLen) return Z_BUF_ERROR;
	//CRC
	memcpy(&dest[i], &crc, sizeof(uLong));
	// Length
	memcpy(&dest[i + sizeof(uLong)], &sourceLen, sizeof(uLong));
	*destLen = 10 + stream.total_out + 8;

	return err;
}

bool CWebServer::_IsLoggedIn(const ThreadData &Data, long lSession)
{
	CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	if (pThis == NULL)
		return false;

	_RemoveTimeOuts(Data);

	// find our session
	// i should have used CMap there, but i like CArray more ;-)
	if (lSession != 0)
		for (INT_PTR i = pThis->m_Params.Sessions.GetCount(); --i >= 0;)
			if (pThis->m_Params.Sessions[i].lSession == lSession) {
				// if found, also reset expiration time
				pThis->m_Params.Sessions[i].startTime = CTime::GetCurrentTime();
				return true;
			}

	return false;
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

	// find our session
	for (INT_PTR i = pThis->m_Params.Sessions.GetCount(); --i >= 0;)
		if (pThis->m_Params.Sessions[i].lSession == lSession) {
			pThis->m_Params.Sessions.RemoveAt(i);
			AddLogLine(true, (LPCTSTR)GetResString(IDS_WEB_SESSIONEND), (LPCTSTR)ipstr(pThis->m_uCurIP));
			SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_UPDATEMYINFO, 0);
			return true;
		}

	return false;
}

Session CWebServer::_GetSessionByID(const ThreadData &Data, long sessionID)
{
	CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	if (pThis != NULL && sessionID != 0)
		for (INT_PTR i = pThis->m_Params.Sessions.GetCount(); --i >= 0;)
			if (pThis->m_Params.Sessions[i].lSession == sessionID)
				return pThis->m_Params.Sessions[i];

	return Session{};
}

bool CWebServer::_IsSessionAdmin(const ThreadData &Data, long sessionID)
{
	CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	if (pThis != NULL && sessionID != 0)
		for (INT_PTR i = pThis->m_Params.Sessions.GetCount(); --i >= 0;)
			if (pThis->m_Params.Sessions[i].lSession == sessionID)
				return pThis->m_Params.Sessions[i].admin;

	return false;
}

bool CWebServer::_IsSessionAdmin(const ThreadData &Data, const CString &strSsessionID)
{
	return _IsSessionAdmin(Data, _tstol(strSsessionID));
}

CString CWebServer::_GetPermissionDenied()
{
	CString s;
	s.Format(_T("javascript:alert(\'%s\')"), (LPCTSTR)_GetPlainResString(IDS_ACCESSDENIED));
	return s;
}

CString CWebServer::_GetPlainResString(UINT nID, bool noquote)
{
	CString sRet(GetResString(nID));
	sRet.Remove(_T('&'));
	if (noquote) {
		sRet.Replace(_T("'"), _T("&#8217;"));
		sRet.Replace(_T("\n"), _T("\\n"));
	}
	return sRet;
}

void CWebServer::_GetPlainResString(CString &rstrOut, UINT nID, bool noquote)
{
	rstrOut = _GetPlainResString(nID, noquote);
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
	snap.barWidth = pThis->m_Templates.iProgressbarWidth;
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
		Out.Format(pThis->m_Templates.sProgressbarImgsPercent, barcolours[10], snap.barWidth);
		Out += _T("<br>");
		Out.AppendFormat(pThis->m_Templates.sProgressbarImgs, barcolours[0], snap.barWidth);
	} else {
		const CStringA &s_ChunkBar = snap.chunkBar;
		// and now make a graph out of the array - need to be in a progressive way

		int compl = static_cast<int>((snap.barWidth / 100.0) * snap.percentCompleted);
		Out.Format(pThis->m_Templates.sProgressbarImgsPercent, barcolours[compl > 0 ? 10 : 11], (compl > 0 ? compl : 5));
		Out += _T("<br>");

		BYTE lastcolor = 1;
		uint16 lastindex = 0;
		const uint16 uBarWidth = snap.barWidth;
		for (uint16 i = 0; i < uBarWidth; ++i) {
			BYTE c = (BYTE)(s_ChunkBar[i] - '0');
			if (c >= _countof(styles_active)) c = 0;          // defence-in-depth clamp
			if (lastcolor != c) {
				if (i > lastindex && lastcolor < _countof(styles_active))
					Out.AppendFormat(pThis->m_Templates.sProgressbarImgs, barcolours[lastcolor], i - lastindex);
				lastcolor = c;
				lastindex = i;
			}
		}
		if (lastcolor >= _countof(styles_active)) lastcolor = 0;   // hard clamp
		Out.AppendFormat(pThis->m_Templates.sProgressbarImgs, barcolours[lastcolor], uBarWidth - lastindex);
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
	CString Out(pThis->m_Templates.sSearch);

	if (!_ParseURL(Data.sURL, _T("downloads")).IsEmpty() && bSessionAdmin) {
		const CString &downloads(_ParseURLArray(Data.sURL, _T("downloads")));

		for (int iPos = 0; iPos >= 0;) {
			const CString &resToken(downloads.Tokenize(_T("|"), iPos));
			if (resToken.GetLength() == 32)
				SendMessage(theApp.emuledlg->m_hWnd, WEB_ADDDOWNLOADS, (LPARAM)(LPCTSTR)resToken, cat);
		}
	}

	if (_ParseURL(Data.sURL, _T("c")) == _T("menu")) {
		int iMenu = _tstoi(_ParseURL(Data.sURL, _T("m")));
		bool bValue = _tstoi(_ParseURL(Data.sURL, _T("v"))) != 0;
		WSsearchColumnHidden[iMenu] = bValue;

		_SaveWIConfigArray(WSsearchColumnHidden, _countof(WSsearchColumnHidden), _T("searchColumnHidden"));
	}

	if (!_ParseURL(Data.sURL, _T("tosearch")).IsEmpty() && bSessionAdmin) {

		// perform search
		SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_DELETEALLSEARCHES, 0);

		// get method
		const CString &method((_ParseURL(Data.sURL, _T("method"))));

		SSearchParams *pParams = new SSearchParams;
		pParams->strExpression = _ParseURL(Data.sURL, _T("tosearch"));
		pParams->strFileType = _ParseURL(Data.sURL, _T("type"));
		// for safety: this string is sent to servers and/or kad nodes, validate it!
		if (!pParams->strFileType.IsEmpty()
			&& pParams->strFileType != _T(ED2KFTSTR_ARCHIVE)
			&& pParams->strFileType != _T(ED2KFTSTR_AUDIO)
			&& pParams->strFileType != _T(ED2KFTSTR_CDIMAGE)
			&& pParams->strFileType != _T(ED2KFTSTR_DOCUMENT)
			&& pParams->strFileType != _T(ED2KFTSTR_IMAGE)
			&& pParams->strFileType != _T(ED2KFTSTR_PROGRAM)
			&& pParams->strFileType != _T(ED2KFTSTR_VIDEO)
			&& pParams->strFileType != _T(ED2KFTSTR_EMULECOLLECTION))
		{
			ASSERT(0);
			pParams->strFileType.Empty();
		}
		pParams->ullMinSize = _tstoi64(_ParseURL(Data.sURL, _T("min"))) * 1048576ui64;
		pParams->ullMaxSize = _tstoi64(_ParseURL(Data.sURL, _T("max"))) * 1048576ui64;
		if (pParams->ullMaxSize < pParams->ullMinSize)
			pParams->ullMaxSize = 0;

		const CString &s(_ParseURL(Data.sURL, _T("avail")));
		pParams->uAvailability = s.IsEmpty() ? 0 : _tstoi(s);
		if (pParams->uAvailability > 1000000)
			pParams->uAvailability = 1000000;

		pParams->strExtension = _ParseURL(Data.sURL, _T("ext"));
		if (method == _T("kademlia"))
			pParams->eType = SearchTypeKademlia;
		else if (method == _T("global"))
			pParams->eType = SearchTypeEd2kGlobal;
		else
			pParams->eType = SearchTypeEd2kServer;

		CString strResponse(_GetPlainResString(IDS_SW_SEARCHINGINFO));
		try {
			if (pParams->eType != SearchTypeKademlia) {
				if (!theApp.emuledlg->searchwnd->DoNewEd2kSearch(pParams)) {
					delete pParams;
					pParams = NULL;
					strResponse = _GetPlainResString(IDS_ERR_NOTCONNECTED);
				}
				// BUG-013 FIX: Removed Sleep(SEC2MS(2)) that blocked HTTP worker thread.
				// Search results arrive asynchronously; the UI refreshes to display them.
			} else {
				if (!theApp.emuledlg->searchwnd->DoNewKadSearch(pParams)) {
					delete pParams;
					pParams = NULL;
					strResponse = _GetPlainResString(IDS_ERR_NOTCONNECTEDKAD);
				}
			}
		} catch (...) {
			AddDebugLogLine(DLP_VERYHIGH, false, _T("*** Exception in CWebServer::_GetSearch search dispatch"));
			strResponse = _GetPlainResString(IDS_ERROR);
			ASSERT(0);
			delete pParams;
			pParams = NULL;
		}
		Out.Replace(_T("[Message]"), strResponse);

	}
	else if (!_ParseURL(Data.sURL, _T("tosearch")).IsEmpty() && !_IsSessionAdmin(Data, sSession)) {
		Out.Replace(_T("[Message]"), _GetPlainResString(IDS_ACCESSDENIED));
	}
	else
		Out.Replace(_T("[Message]"), _GetPlainResString(IDS_SW_REFETCHRES));

	CString sSort = _ParseURL(Data.sURL, _T("sort"));
	if (sSort.GetLength() > 0)
		pThis->m_iSearchSortby = _tstoi(sSort);
	sSort = _ParseURL(Data.sURL, _T("sortAsc"));
	if (sSort.GetLength() > 0)
		pThis->m_bSearchAsc = _tstoi(sSort) != 0;

	CString result(pThis->m_Templates.sSearchHeader);
	CQArray<SearchFileStruct, SearchFileStruct> SearchFileArray;
	theApp.searchlist->GetWebList(&SearchFileArray, pThis->m_iSearchSortby);
	SearchFileArray.QuickSort(pThis->m_bSearchAsc);

	uchar aFileHash[16];
	uchar nRed, nGreen, nBlue;
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
		nRed = nGreen = nBlue = 255;
		DecodeBase16(structFile.m_strFileHash, 32, aFileHash, _countof(aFileHash));
		strOverlayImage = _T("none");
		if (theApp.downloadqueue->HasFileByID(aFileHash)) {
			nBlue = 128;
			nGreen = 128;
		} else {
			sameFile = theApp.sharedfiles->GetFileByID(aFileHash);
			if (sameFile == NULL)
				sameFile = theApp.knownfiles->FindKnownFileByID(aFileHash);
			if (sameFile != NULL) {
				nBlue = 128;
				nRed = 128;
			}
		}
		strColorPrefix.Format(_T("<font color=#%02x%02x%02x>"), nRed, nGreen, nBlue);

		if (structFile.m_uSourceCount < 5)
			strSourcesImage = _T("0");
		else if (structFile.m_uSourceCount < 10)
			strSourcesImage = _T("5");
		else if (structFile.m_uSourceCount < 25)
			strSourcesImage = _T("10");
		else if (structFile.m_uSourceCount < 50)
			strSourcesImage = _T("25");
		else
			strSourcesImage = _T("50");

		strSources.Format(_T("%u(%u)"), structFile.m_uSourceCount, structFile.m_dwCompleteSourceCount);
		strFilename = structFile.m_strFileName;
		strFilename.Replace(_T("'"), _T("\\'"));

		strTemp2.Format(_T("ed2k://|file|%s|%I64u|%s|/"),
			(LPCTSTR)strFilename, structFile.m_uFileSize, (LPCTSTR)structFile.m_strFileHash);

		strTemp.Format(pThis->m_Templates.sSearchResultLine,
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
		_InsertCatBox(Out, 0, pThis->m_Templates.sCatArrow, false, false, sSession, _T(""));
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

	const TCHAR *pcSortIcon = (pThis->m_bSearchAsc) ? pThis->m_Templates.sUpArrow : pThis->m_Templates.sDownArrow;

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
	INT_PTR oldvalue = m_Params.Sessions.GetCount();
	for (INT_PTR i = 0; i < m_Params.Sessions.GetCount();)
	{
		CTimeSpan ts = CTime::GetCurrentTime() - m_Params.Sessions[i].startTime;
		if (thePrefs.GetWebTimeoutMins() > 0 && ts.GetTotalSeconds() > thePrefs.GetWebTimeoutMins() * 60)
			m_Params.Sessions.RemoveAt(i);
		else
			i++;
	}

	if (oldvalue != m_Params.Sessions.GetCount())
		SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_UPDATEMYINFO, 0);

	return m_Params.Sessions.GetCount();
}

void CWebServer::_InsertCatBox(CString &Out, int preselect, LPCTSTR boxlabel, bool jump, bool extraCats, const CString &sSession, const CString &sFileHash, bool ed2kbox)
{
	CString tempBuf = _T("<form action=\"\">");
	tempBuf.Append(boxlabel);
	tempBuf += _T("<select name=\"cat\" size=\"1\"");

	if (jump)
		tempBuf += _T(" onchange=GotoCat(this.form.cat.options[this.form.cat.selectedIndex].value)>");
	else
		tempBuf += _T(">");

	for (int i = 0; i < thePrefs.GetCatCount(); i++)
	{
		CString strCategory = thePrefs.GetCategory(i)->strTitle;
		strCategory.Replace(_T("'"), _T("\\'"));
		tempBuf.AppendFormat(_T("<option%s value=\"%i\">%s</option>\n"), (i == preselect) ? _T(" selected") : _T(""), i, (LPCTSTR)strCategory);
	}
	if (extraCats)
	{
		if (thePrefs.GetCatCount() > 1)
		{
			tempBuf += _T("<option>-------------------</option>\n");
		}
		for (int i = 1; i < 16; i++)
		{
			tempBuf.AppendFormat(_T("<option%s value=\"%i\">%s</option>\n"), (0 - i == preselect) ? _T(" selected") : _T(""), 0 - i, (LPCTSTR)_GetSubCatLabel(0 - i));
		}
	}
	tempBuf.Append(_T("</select></form>"));
	Out.Replace(ed2kbox ? _T("[CATBOXED2K]") : _T("[CATBOX]"), tempBuf);

	CString tempBuff3, tempBuff4;
	CString tempBuff;
	CString strCategory;

	for (int i = 0; i < thePrefs.GetCatCount(); i++)
	{
		if (i == preselect)
		{
			tempBuff3 = _T("checked.gif");
			tempBuff4 = (i == 0) ? GetResString(IDS_ALL) : thePrefs.GetCategory(i)->strTitle;
		}
		else
			tempBuff3 = _T("checked_no.gif");

		strCategory = (i == 0) ? GetResString(IDS_ALL) : thePrefs.GetCategory(i)->strTitle;
		strCategory.Replace(_T("'"), _T("\\'"));

		tempBuff.AppendFormat(_T("<a href=&quot;/?ses=%s&w=transfer&cat=%d&quot;><div class=menuitems><img class=menuchecked src=%s>%s&nbsp;</div></a>"),
			(LPCTSTR)sSession, i, (LPCTSTR)tempBuff3, (LPCTSTR)strCategory);
	}
	if (extraCats)
	{
		tempBuff.Append(_T("<div class=menuitems>&nbsp;------------------------------&nbsp;</div>"));
		for (int i = 1; i < 16; i++)
		{
			if ((0 - i) == preselect)
			{
				tempBuff3 = _T("checked.gif");
				tempBuff4 = _GetSubCatLabel(0 - i);
			}
			else
				tempBuff3 = _T("checked_no.gif");

			tempBuff.AppendFormat(_T("<a href=&quot;/?ses=%s&w=transfer&cat=%d&quot;><div class=menuitems><img class=menuchecked src=%s>%s&nbsp;</div></a>"),
				(LPCTSTR)sSession, 0 - i, (LPCTSTR)tempBuff3, (LPCTSTR)_GetSubCatLabel(0 - i));
		}
	}
	Out.Replace(_T("[CatBox]"), tempBuff);
	Out.Replace(_T("[Category]"), tempBuff4);

	tempBuff.Empty();

	// v7.4.0 — snapshot the category once before the loop, under the lock.
	// Previous code re-resolved found_file every iteration AND held a raw
	// CPartFile* in flight across calls that may trigger a GUI message-pump.
	int snapshotCategory = preselect;
	bool foundFile = false;
	if (!sFileHash.IsEmpty()) {
		uchar FileHash[16];
		if (strmd4(sFileHash, FileHash)) {
			theApp.downloadqueue->WithFileByID(FileHash, [&](CPartFile *f) {
				snapshotCategory = f->GetCategory();
				foundFile = true;
			});
		}
	}

	// For each user category index...
	for (int i = 0; i < thePrefs.GetCatCount(); i++)
	{
		if (foundFile)
			preselect = snapshotCategory;

		if (i == preselect)
		{
			tempBuff3 = _T("checked.gif");
			tempBuff4 = (i == 0) ? GetResString(IDS_ALL) : thePrefs.GetCategory(i)->strTitle;
		}
		else
			tempBuff3 = _T("checked_no.gif");

		strCategory = (i == 0) ? GetResString(IDS_CAT_UNASSIGN) : thePrefs.GetCategory(i)->strTitle;
		strCategory.Replace(_T("'"), _T("\\'"));

		tempBuff.AppendFormat(_T("<a href=&quot;/?ses=%s&w=transfer[CatSel]&op=setcat&file=%s&filecat=%d&quot;><div class=menuitems><img class=menuchecked src=%s>%s&nbsp;</div></a>"),
			(LPCTSTR)sSession, (LPCTSTR)sFileHash, i, (LPCTSTR)tempBuff3, (LPCTSTR)strCategory);
	}


	Out.Replace(_T("[SetCatBox]"), tempBuff);
}

CString CWebServer::_GetSubCatLabel(int cat)
{
	switch (cat) {
		case -1: return _GetPlainResString(IDS_ALLOTHERS);
		case -2: return _GetPlainResString(IDS_STATUS_NOTCOMPLETED);
		case -3: return _GetPlainResString(IDS_DL_TRANSFCOMPL);
		case -4: return _GetPlainResString(IDS_WAITING);
		case -5: return _GetPlainResString(IDS_DOWNLOADING);
		case -6: return _GetPlainResString(IDS_ERRORLIKE);
		case -7: return _GetPlainResString(IDS_PAUSED);
		case -8: return _GetPlainResString(IDS_SEENCOMPL);
		case -9: return _GetPlainResString(IDS_VIDEO);
		case -10: return _GetPlainResString(IDS_AUDIO);
		case -11: return _GetPlainResString(IDS_SEARCH_ARC);
		case -12: return _GetPlainResString(IDS_SEARCH_CDIMG);
		case -13: return _GetPlainResString(IDS_SEARCH_DOC);
		case -14: return _GetPlainResString(IDS_SEARCH_PICS);
		case -15: return _GetPlainResString(IDS_SEARCH_PRG);
	}
	return _T("?");
}

CString CWebServer::_GetRemoteLinkAddedOk(const ThreadData &Data)
{
	CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	if (pThis == NULL)
		return CString();

	CString Out;

	int cat = _tstoi(_ParseURL(Data.sURL, _T("cat")));
	CString HTTPTemp = _ParseURL(Data.sURL, _T("c"));

	const TCHAR *buf = HTTPTemp;
	theApp.emuledlg->SendMessage(WEB_ADDDOWNLOADS, (WPARAM)buf, cat);

	Out += _T("<status result=\"OK\">");
	Out += _T("<description>") + GetResString(IDS_WEB_REMOTE_LINK_ADDED) + _T("</description>");
	Out += _T("<filename>") + HTTPTemp + _T("</filename>");
	Out += _T("</status>");

	return Out;
}

CString CWebServer::_GetRemoteLinkAddedFailed(const ThreadData &Data)
{
	CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	if (pThis == NULL)
		return CString();

	CString Out;

	Out += _T("<status result=\"FAILED\" reason=\"WRONG_PASSWORD\">");
	Out += _T("<description>") + GetResString(IDS_WEB_REMOTE_LINK_NOT_ADDED) + _T("</description>");
	Out += _T("</status>");

	return Out;
}

void CWebServer::_SetLastUserCat(const ThreadData &Data, long lSession, int cat)
{
	CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	if (pThis == NULL)
		return;

	_RemoveTimeOuts(Data);

	// find our session
	for (INT_PTR i = 0; i < pThis->m_Params.Sessions.GetCount(); i++)
	{
		if (pThis->m_Params.Sessions[i].lSession == lSession && lSession != 0)
		{
			// if found, also reset expiration time
			pThis->m_Params.Sessions[i].startTime = CTime::GetCurrentTime();
			pThis->m_Params.Sessions[i].lastcat = cat;
			return;
		}
	}
}

int CWebServer::_GetLastUserCat(const ThreadData &Data, long lSession)
{
	CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	if (pThis == NULL)
		return 0;

	_RemoveTimeOuts(Data);

	// find our session
	for (INT_PTR i = 0; i < pThis->m_Params.Sessions.GetCount(); i++)
	{
		if (pThis->m_Params.Sessions[i].lSession == lSession && lSession != 0)
		{
			// if found, also reset expiration time
			pThis->m_Params.Sessions[i].startTime = CTime::GetCurrentTime();
			return pThis->m_Params.Sessions[i].lastcat;
		}
	}

	return 0;
}



static CStringA EseJsonEscapeA(const CStringA& input)
{
	CStringA output;
	for (int i = 0; i < input.GetLength(); i++) {
		const unsigned char ch = (unsigned char)input[i];
		switch (ch) {
		case '\"':
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
			if (ch < 0x20)
				output.AppendFormat("\\u%04x", ch);
			else
				output += input[i];
			break;
		}
	}
	return output;
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

static bool EseIsHexA(const CStringA& value)
{
	if (value.GetLength() != 32)
		return false;
	for (int i = 0; i < value.GetLength(); i++) {
		const char c = value[i];
		if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
			return false;
	}
	return true;
}

static bool EseIsSafeHlsResourceA(const CStringA& resource)
{
	if (resource.IsEmpty() || resource.Find('/') >= 0 || resource.Find('\\') >= 0 || resource.Find("..") >= 0)
		return false;

	for (int i = 0; i < resource.GetLength(); i++) {
		const char c = resource[i];
		if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == '-' || c == '.'))
			return false;
	}

	if (resource == "stream.m3u8")
		return true;
	if (resource.Left(7) == "stream_" && resource.Right(5) == ".m3u8")
		return true;
	if (resource.Left(4) == "seg_" && resource.Right(3) == ".ts")
		return true;
	return false;
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
	CStringA sURL(CT2A(Data.sURL));

	// --- SECURITY GATE -------------------------------------------------------
	// Critical: this dispatch in WebSocket.cpp:88 BYPASSES the password gate
	// that _ProcessURL applies to the classic WebServer. Without this guard,
	// any host on the LAN that AllowedRemoteAccessIPs admits (default = ALLOW
	// ALL) can issue GET /api/live/broadcast/start?source=screen&title=Pwned
	// and start streaming the victim's desktop, then read it via the published
	// Kad link. Same attack works against /api/holepunch/* and /api/live/log.
	//
	// Mitigation: only accept these endpoints from localhost. The legitimate
	// Node.js dashboard on :8080 proxies through 127.0.0.1 -> 127.0.0.1:4711
	// so it keeps working. Genuine remote-admin use cases must go through the
	// password-gated routes in _ProcessURL or hit the Node side which has
	// session/cookie auth.
	bool bIsLiveOrHolepunch =
		(sURL.Left(10) == "/api/live/")
		|| (sURL.Left(15) == "/api/holepunch/")
		|| (sURL == "/api/status")
		|| (sURL == "/dashboard") || (sURL == "/dashboard/")
		|| (sURL.Left(5) == "/hls/");
	if (bIsLiveOrHolepunch) {
		const uint32 clientIP = Data.inadr.S_un.S_addr; // network order
		const uint32 loopback = htonl(INADDR_LOOPBACK);
		if (clientIP != loopback) {
			CStringA body = "{\"error\":\"forbidden\",\"hint\":\"this API is localhost-only\"}";
			CStringA hdr;
			hdr.Format(
				"HTTP/1.1 403 Forbidden\r\n"
				"Content-Type: application/json\r\n"
				"Cache-Control: no-store\r\n"
				"Content-Length: %d\r\n\r\n",
				body.GetLength());
			Data.pSocket->SendData(hdr, hdr.GetLength());
			Data.pSocket->SendData(body, body.GetLength());
			LIVE_LOG("SEC", "Blocked remote /api/live request from %lu.%lu.%lu.%lu  url=%s",
				(unsigned long)(clientIP & 0xFF),
				(unsigned long)((clientIP >> 8) & 0xFF),
				(unsigned long)((clientIP >> 16) & 0xFF),
				(unsigned long)((clientIP >> 24) & 0xFF),
				(LPCSTR)sURL);
			return;
		}
	}

	// --- /api/status --- eSE Network health for React alerts (Fase 2)
	if (sURL == "/api/status") {
		CStringA json;
		// Determine UPnP port forwarding state: "true", "false", "unknown"
		const char* szUpnpFwd = "unknown";
		if (theApp.m_pUPnPFinder && theApp.m_pUPnPFinder->GetImplementation()) {
			TRISTATE ts = theApp.m_pUPnPFinder->GetImplementation()->ArePortsForwarded();
			szUpnpFwd = (ts == TRIS_TRUE) ? "true" : (ts == TRIS_FALSE) ? "false" : "unknown";
		}
		json.Format(
			"{\"upnp_critical_error\":%s,"
			"\"utp_hole_punch_enabled\":%s,"
			"\"web_upnp_active\":%s,"
			"\"upnp_ports_forwarded\":\"%s\","
			"\"kad_connected\":%s,"
			"\"ed2k_connected\":%s,"
			"\"hole_punch_attempts\":%u,"
			"\"hole_punch_success\":%u,"
			"\"hole_punch_sym_nat_fail\":%u,"
			"\"hole_punch_encrypted\":%u,"
			"\"hole_punch_plaintext\":%u}",
			thePrefs.GetUPnPCriticalError() ? "true" : "false",
			thePrefs.GetUtpHolePunchEnabled() ? "true" : "false",
			thePrefs.GetWSUseUPnP() ? "true" : "false",
			szUpnpFwd,
			Kademlia::CKademlia::IsConnected() ? "true" : "false",
			(theApp.serverconnect && theApp.serverconnect->IsConnected()) ? "true" : "false",
			CStatistics::m_dwHolePunchAttempts,
			CStatistics::m_dwHolePunchSuccess,
			CStatistics::m_dwHolePunchSymNATFail,
			CStatistics::m_dwHolePunchEncrypted,
			CStatistics::m_dwHolePunchPlaintext
		);
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
	if (sURL.Left(14) == "/api/live/join") {
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
			req.ip        = 0;
			req.port      = 0;
			req.joined    = false;
			req.dialed    = false;
			if (theApp.emuledlg != NULL)
				theApp.emuledlg->SendMessage(UM_LIVE_WEB_JOIN, 0, (LPARAM)&req);
			ok = req.joined;
		}

		CStringA json;
		json.Format("{\"success\":%s,\"streamKey\":\"%s\"}", ok ? "true" : "false", (LPCSTR)keyA);
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

	// --- /api/live/broadcast/start --- Tier 2.2: web-driven broadcast launch.
	// Lets the user start a stream from the browser without ever opening the
	// MFC "Live" tab. Source: testpattern (default), screen, file, rtmp.
	// Example: GET /api/live/broadcast/start?source=testpattern&title=Mi+Canal&bitrate=1500
	// (Use Left() match so query string doesn't break the route.)
	if (sURL.Left(25) == "/api/live/broadcast/start") {
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
				DWORD t0 = GetTickCount();
				for (;;) {
					bool alive = false;
					int  chunks = 0;
					theApp.liveStreamManager->GetBroadcastLivenessStatus(alive, chunks);
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
					if (chunks >= 3)
						break;
					if (GetTickCount() - t0 >= 14000)
						break;
					Sleep(100);
				}
			}
		}

		// Build the share link if broadcast started + we know our IP.
		CStringA linkA;
		if (ok) {
			const uchar* key = theApp.liveStreamManager->GetStreamKey();
			uint32 pubIP = theApp.GetPublicIP();
			uint16 port  = thePrefs.GetPort();
			if (key) {
				CStringA hex = EseHexKey16A(key);
				CString titleEnc = titleT;
				titleEnc.Replace(_T(" "), _T("+"));

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

				// Both variants get exposed in the JSON so a smart caller
				// can show a "switch to anonymous" toggle to its user.
				CStringA jsonLinks;
				jsonLinks.Format(
					"{\"success\":%s,\"source\":\"%s\",\"bitrate\":%u,"
					"\"link\":\"%s\",\"link_anonymous\":\"%s\",\"link_direct\":\"%s\"}",
					ok ? "true" : "false",
					(LPCSTR)CT2A(sourceT), (unsigned)bitrate,
					(LPCSTR)linkA, (LPCSTR)linkAnon,
					(LPCSTR)(linkDirect.IsEmpty() ? linkAnon : linkDirect));

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
		json.Format(
			"{\"success\":%s,\"source\":\"%s\",\"bitrate\":%u,\"link\":\"%s\"}",
			ok ? "true" : "false",
			(LPCSTR)CT2A(sourceT), (unsigned)bitrate,
			(LPCSTR)linkA);
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
	if (sURL == "/api/live/broadcast/stop") {
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
	if (sURL.Left(5) == "/hls/") {
		CStringA req = sURL.Mid(5);
		// Strip query string
		int q = req.Find('?'); if (q >= 0) req = req.Left(q);
		// Sanitize: only allow [A-Za-z0-9_.-], no slashes (path traversal guard)
		bool ok = !req.IsEmpty() && req.GetLength() < 64;
		for (int i = 0; ok && i < req.GetLength(); ++i) {
			char c = req[i];
			if (!(isalnum((unsigned char)c) || c == '.' || c == '_' || c == '-')) ok = false;
		}
		// Only allow .m3u8 and .ts extensions
		bool isPlay = req.Right(5).CompareNoCase(".m3u8") == 0;
		bool isSeg  = req.Right(3).CompareNoCase(".ts") == 0;
		if (!ok || !(isPlay || isSeg)) {
			const char* hdr = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
			Data.pSocket->SendData(hdr, (int)strlen(hdr));
			return;
		}
		TCHAR tmp[MAX_PATH]; GetTempPath(MAX_PATH, tmp);
		CString fp;
		fp.Format(_T("%seMule_RTMP\\%hs"), tmp, (LPCSTR)req);
		HANDLE hF = CreateFile(fp, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL, OPEN_EXISTING, 0, NULL);
		if (hF == INVALID_HANDLE_VALUE) {
			const char* hdr = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
			Data.pSocket->SendData(hdr, (int)strlen(hdr));
			return;
		}
		DWORD sz = GetFileSize(hF, NULL);
		const char* mime = isPlay ? "application/vnd.apple.mpegurl" : "video/mp2t";
		const char* cache = isPlay ? "no-cache" : "max-age=30";
		CStringA hdr;
		hdr.Format(
			"HTTP/1.1 200 OK\r\n"
			"Content-Type: %s\r\n"
			"Content-Length: %u\r\n"
			"Cache-Control: %s\r\n"
			"Access-Control-Allow-Origin: *\r\n\r\n",
			mime, (unsigned)sz, cache);
		Data.pSocket->SendData(hdr, hdr.GetLength());
		// Stream file in 64 KB chunks (small player segments are < 1 MB anyway)
		BYTE buf[65536];
		DWORD got = 0;
		while (ReadFile(hF, buf, sizeof(buf), &got, NULL) && got > 0) {
			Data.pSocket->SendData((const char*)buf, (int)got);
		}
		CloseHandle(hF);
		return;
	}

	// --- /dashboard --- Sprint 5: minimal embedded dashboard (no Node.js needed).
	// Self-contained HTML page that talks to the C++ WebServer endpoints we
	// already expose. Lets the user broadcast + diagnose without ese-server.exe.
	// For the full polished experience, the Node.js dashboard at :8080 is still
	// preferred — but this guarantees emule.exe alone is functional.
	// Only catches /dashboard explicitly — leaves "/" and other paths to the
	// classic eMule WebServer pages so we don't shadow the legacy UI.
	if (sURL == "/dashboard" || sURL == "/dashboard/") {
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
"PF();MON();setInterval(PF,8000);setInterval(MON,2000);"
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
	if (sURL.Left(19) == "/api/holepunch/test") {
		static DWORD s_lastManualHolePunch = 0;
		DWORD now = ::GetTickCount();
		if (now - s_lastManualHolePunch < 5000) {
			CStringA json = "{\"success\":false,\"error\":\"rate_limited\",\"retry_after_ms\":";
			CStringA n;
			n.Format("%u}", 5000 - (now - s_lastManualHolePunch));
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
		uint32 ipNet = (uint32)inet_addr((LPCSTR)ipA);
		uint16 udpPort = (uint16)_ttoi(portT);

		bool ok = false;
		const char* errCode = "ok";
		DWORD attemptsBefore = CStatistics::m_dwHolePunchAttempts;

		if (ipNet == INADDR_NONE || ipNet == 0 || udpPort == 0) {
			errCode = "invalid_ip_port";
		} else if (!Kademlia::CKademlia::IsConnected() || Kademlia::CKademlia::GetUDPListener() == NULL) {
			errCode = "kad_not_ready";
		} else if (!thePrefs.GetUtpHolePunchEnabled()) {
			errCode = "holepunch_disabled";
		} else {
			// SendEseHolePunchReq expects host-order IP, host-order port.
			Kademlia::CKademlia::GetUDPListener()->SendEseHolePunchReq(ntohl(ipNet), udpPort);
			s_lastManualHolePunch = now;
			ok = true;
		}

		CStringA json;
		json.Format(
			"{\"success\":%s,\"error\":\"%s\","
			"\"target_ip\":\"%s\",\"target_udp_port\":%u,"
			"\"attempts_before\":%u,\"attempts_after\":%u,"
			"\"counters\":{"
			"\"attempts\":%u,\"success\":%u,\"sym_nat_fail\":%u,"
			"\"encrypted\":%u,\"plaintext\":%u}}",
			ok ? "true" : "false",
			errCode,
			(LPCSTR)CT2A(ipT), (unsigned)udpPort,
			(unsigned)attemptsBefore, (unsigned)CStatistics::m_dwHolePunchAttempts,
			(unsigned)CStatistics::m_dwHolePunchAttempts,
			(unsigned)CStatistics::m_dwHolePunchSuccess,
			(unsigned)CStatistics::m_dwHolePunchSymNATFail,
			(unsigned)CStatistics::m_dwHolePunchEncrypted,
			(unsigned)CStatistics::m_dwHolePunchPlaintext);
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
	if (sURL == "/api/live/preflight") {
		bool kadConn = Kademlia::CKademlia::IsConnected();
		// Tier 1.5: differentiate between "firewall test completed and we ARE
		// firewalled" vs "test still running, don't know yet". This avoids
		// the pre-flight panel flashing a red ❌ during the first 30-90 s of
		// Kad's startup when the tester hasn't reported yet.
		bool fwVerified = Kademlia::CUDPFirewallTester::IsVerified();
		bool kadFw   = theApp.IsFirewalled();
		bool ed2kFw  = (theApp.serverconnect && theApp.serverconnect->IsConnected()
		                && theApp.serverconnect->IsLowID());
		bool highId  = !kadFw && !ed2kFw;
		bool fwChecking = !fwVerified && kadConn && !ed2kFw;  // still measuring
		uint32 maxUpKBs = thePrefs.GetMaxUpload();   // KB/s, 0 = unlimited
		uint16 port = thePrefs.GetPort();
		uint32 pubIP = theApp.GetPublicIP();
		CString ffPath = CRTMPIngest::FindFFmpeg();
		bool ffmpegFound = (GetFileAttributes(ffPath) != INVALID_FILE_ATTRIBUTES);

		CStringA pubIpA;
		if (pubIP != 0)
			pubIpA = (LPCSTR)CT2A(ipstr(pubIP));
		else
			pubIpA = "";

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
	if (sURL.Left(33) == "/api/live/privacy/subscriptions") {
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
					(LPCSTR)pkHex, (LPCSTR)all[i].name,
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

	// --- /api/live/privacy/tunnel_search?keyword=foo --- v0.71 P1.A —
	// REAL operation through onion tunnel. Sends TUN_OP_KAD_SEARCH; exit
	// relay queries its local stream directory and returns matching
	// streams as KAD_RESULT. V's keyword is NEVER sent to Kad directly
	// → preserves privacy of WHAT V is looking for. Length: 31 chars.
	if (sURL.Left(31) == "/api/live/privacy/tunnel_search") {
		CString kwArg = _ParseURL(Data.sURL, _T("keyword"));
		if (kwArg.IsEmpty()) kwArg = _T("eselive");
		CStringA kwA(kwArg);
		kwA.MakeLower();
		std::string keyword((LPCSTR)kwA);
		std::string reply;
		bool ok = false;
		try {
			ok = eSELive::CLiveTunnel::Get().TunneledKadSearch(keyword, reply, 5000);
		} catch (...) {}

		CStringA json;
		if (ok) {
			CStringA safe;
			for (char c : reply) {
				if (c == '"' || c == '\\') safe += '\\';
				safe += c;
			}
			json.Format("{\"ok\":true,\"keyword\":\"%s\",\"raw_hits\":\"%s\",\"format\":\"title|bitrate|viewers;\"}",
				(LPCSTR)kwA, (LPCSTR)safe);
		} else {
			json = "{\"ok\":false,\"reason\":\"no active circuit or timeout - build a circuit first via test_circuit\"}";
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
	if (sURL.Left(29) == "/api/live/privacy/tunnel_echo") {
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
	if (sURL.Left(29) == "/api/live/privacy/tunnel_ping") {
		CString textArg = _ParseURL(Data.sURL, _T("text"));
		if (textArg.IsEmpty()) textArg = _T("hello");
		std::string text((LPCSTR)CStringA(textArg));
		std::string reply;
		bool ok = false;
		try {
			ok = eSELive::CLiveTunnel::Get().TunnelPing(text, reply, 5000);
		} catch (...) {}

		CStringA json;
		if (ok) {
			// Escape any quotes/backslashes in reply just in case
			CStringA safe;
			for (char c : reply) {
				if (c == '"' || c == '\\') safe += '\\';
				safe += c;
			}
			json.Format("{\"ok\":true,\"sent\":\"%s\",\"received\":\"%s\"}",
				(LPCSTR)CStringA(textArg), (LPCSTR)safe);
		} else {
			json = "{\"ok\":false,\"reason\":\"no active circuit or timeout - build a 2-hop circuit first via test_circuit?hops=2\"}";
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

	// --- /api/live/privacy/circuits --- v0.71 B — per-circuit detail.
	// Enumerates all circuits in CLiveTunnel with id, role, state, age
	// in ms, hop count, and forwarding state (next_hop_set / next_circ_id
	// for relay circuits that have already received EXTEND). Used to
	// verify "Hops: 2" after BuildTestCircuit2Hop succeeds.
	if (sURL == "/api/live/privacy/circuits") {
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
			    "\"next_circ_id\":\"0x%08X\"}",
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
			    s.next_circ_id);
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
	if (sURL == "/api/live/privacy/peers") {
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
			    "{\"ip\":\"%u.%u.%u.%u\",\"port\":%u,"
			    "\"forkCaps\":\"0x%08X\",\"eseCaps\":\"0x%08X\","
			    "\"isFork\":%s}",
			    (unsigned)(p.ip & 0xFF),
			    (unsigned)((p.ip >> 8) & 0xFF),
			    (unsigned)((p.ip >> 16) & 0xFF),
			    (unsigned)((p.ip >> 24) & 0xFF),
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
	// Builds a single-hop test circuit through any currently connected peer
	// (or a specific peer if &peerip= is supplied). The originator code
	// path runs end-to-end (X25519 keygen → CELL_CREATE → TCP send). If
	// the chosen peer runs this fork, the handshake completes and the
	// circuit reaches Active; if not, the circuit stays Pending until
	// the ~6 s timeout reaps it. Either way the user gets visible proof
	// the SEND path is wired (Privacidad panel shows circuit count +1
	// briefly even on failure).
	// Length of "/api/live/privacy/test_circuit" is exactly 30 chars.
	// Left(30) matches both bare URL and URL with ?query suffix.
	if (sURL.Left(30) == "/api/live/privacy/test_circuit") {
		// v0.71 B — optional ?hops=2 to build a 2-hop circuit. Default
		// is 1-hop (backward compat). 2-hop picks 2 fork peers if
		// available; with 1 fork peer it loops hop2 back (testing aid).
		const CString hopsArg = _ParseURL(Data.sURL, _T("hops"));
		const int hops = (hopsArg == _T("2")) ? 2 : 1;
		uint32_t circId = 0;
		CStringA result;
		try {
			// v0.72 — marshaled to the main thread (the build touches the
			// ClientList + peer sockets). Waits up to ~2.5 s for the result.
			circId = eSELive::CLiveTunnel::Get().RequestTestCircuit(hops, 2500);
		} catch (...) {}
		if (circId == 0) {
			result = "{\"ok\":false,\"reason\":\"no connected fork-capable peers - check /api/live/privacy/peers\"}";
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

	// --- /api/live/privacy --- F5: expose Kad v2 mode + fallback policy + sensitive keywords.
	// GET: returns current state. PATCH (via query params): updates state.
	if (sURL.Left(17) == "/api/live/privacy") {
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
			kwJson += "\""; kwJson += CStringA(kws[i]); kwJson += "\"";
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
		try {
			circuitsActive    = eSELive::CLiveTunnel::Get().ActiveCircuitCount();
			circuitsPending   = eSELive::CLiveTunnel::Get().PendingCircuitCount();
			tunnelPoolSize    = Kademlia::CKadV2TunnelPool::Get().Size();
			subscriptionCount = eSELive::CLiveSubscriptionStore::Get().Count();
			CAddress v6 = CFirewallProberV6::Instance().GetDetectedV6IP();
			if (!v6.IsNull()) proberV6Str = CStringA(v6.ToStringC());
		} catch (...) {
			// keep zeros; this endpoint must never throw
		}

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

		CStringA json;
		json.Format(
		    "{"
		    "\"mode\":\"%s\","
		    "\"fallback\":\"%s\","
		    "\"sensitiveKeywords\":[%s],"
		    "\"runtime\":{"
		        "\"capsBits\":\"0x%08X\","
		        "\"capsHumanReadable\":[%s],"
		        "\"circuitsActive\":%u,"
		        "\"circuitsPending\":%u,"
		        "\"tunnelPoolSize\":%u,"
		        "\"subscriptionsLoaded\":%u,"
		        "\"publicIPv6\":\"%s\""
		    "}"
		    "}",
		    modeStr, fbStr, (LPCSTR)kwJson,
		    capsRuntime,
		    (LPCSTR)capsArr,
		    (unsigned)circuitsActive,
		    (unsigned)circuitsPending,
		    (unsigned)tunnelPoolSize,
		    (unsigned)subscriptionCount,
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
	if (sURL == "/api/live/metrics") {
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
	if (sURL.Left(13) == "/api/live/log") {
		int n = _ttoi(_ParseURL(Data.sURL, _T("n")));
		if (n <= 0) n = 100;
		if (n > 500) n = 500;

		std::deque<CStringA> items;
		CLiveDebugLog::Get().GetRecent(n, items);

		CStringA json = "{\"items\":[";
		bool first = true;
		for (const auto& l : items) {
			if (!first) json += ",";
			first = false;
			// Escape minimally for JSON: backslash and double-quote only.
			CStringA esc = l;
			esc.Replace("\\", "\\\\");
			esc.Replace("\"", "\\\"");
			json += "\"";
			json += esc;
			json += "\"";
		}
		json += "]}";

		CStringA header;
		header.Format(
			"HTTP/1.1 200 OK\r\n"
			"Content-Type: application/json; charset=utf-8\r\n"
			"Cache-Control: no-store\r\n"
			"Access-Control-Allow-Origin: *\r\n"
			"Content-Length: %d\r\n\r\n",
			json.GetLength());
		Data.pSocket->SendData(header, header.GetLength());
		Data.pSocket->SendData(json, json.GetLength());
		return;
	}

	// --- /api/live/diagnose --- DISC-S10: comprehensive self-diagnostic.
	// Returns JSON with everything a user/support engineer needs to figure
	// out why a stream isn't discoverable. Usage: /api/live/diagnose?key=HEX32
	// (key is optional — without it, returns global discovery state).
	if (sURL.Left(18) == "/api/live/diagnose") {
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
		uint16 tcpPort = thePrefs.GetPort();

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
			CStringA titleA = CT2A(entry.title);
			titleA.Replace("\"", "\\\"");
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
	//   ?key=HEXKEY&ip=1.2.3.4&port=4662&title=My+Stream
	// The "live" link is the format the broadcaster's Share panel produces when
	// its public IP is known. Direct Join skips the 30s Kad search cooldown and
	// the multi-minute DHT propagation delay — the viewer can connect within
	// seconds of the broadcaster pressing START.
	if (sURL.Left(21) == "/api/live/direct_join") {
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
				int colon = ipPort.Find(_T(':'));
				if (colon > 0) {
					ipT   = ipPort.Left(colon);
					portT = ipPort.Mid(colon + 1);
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
		uint32 ipNet = 0;
		uint16 port  = 0;
		if (keyOk && !ipT.IsEmpty() && !portT.IsEmpty()) {
			CStringA ipA = CT2A(ipT);
			ipNet = (uint32)inet_addr((LPCSTR)ipA);
			port  = (uint16)_ttoi(portT);
			if (ipNet == INADDR_NONE || ipNet == 0 || port == 0) {
				ipNet = 0; port = 0;  // treat as anonymous
			}
		}

		bool joined = false;
		bool dialed = false;
		if (keyOk) {
			// JoinStream + TryConnectToStreamSource mutate Live state and touch
			// Kad / the eD2K sockets — marshal both to the main thread in one
			// round-trip. This worker holds no Live lock, so the blocking
			// SendMessage cannot deadlock. Direct dial happens only when the
			// link carried an explicit endpoint; otherwise the Kad search
			// kicked off inside JoinStream finds the broadcaster.
			LiveWebJoinReq req;
			req.streamKey = streamKey;
			req.title     = titleT;
			req.ip        = ipNet;
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
		bool overall = keyOk && joined;

		CStringA json;
		json.Format(
			"{\"success\":%s,\"joined\":%s,\"dialed\":%s,"
			"\"streamKey\":\"%s\",\"ip\":\"%s\",\"port\":%u,"
			"\"mode\":\"%s\",\"hint\":\"%s\"}",
			overall ? "true" : "false",
			joined ? "true" : "false",
			dialed ? "true" : "false",
			(LPCSTR)CStringA(CT2A(keyT)),
			(LPCSTR)CStringA(CT2A(ipT)),
			(unsigned)port,
			(ipNet != 0 && port != 0) ? "direct" : "kad-search",
			overall
				? ((ipNet != 0 && port != 0)
					? "Dialing broadcaster directly"
					: "Anonymous link — searching Kad for the broadcaster (5-30 s)")
				: (keyOk ? "JoinStream rejected" : "Bad streamKey or eMule not ready"));
		CStringA header;
		header.Format(
			"HTTP/1.1 %s\r\n"
			"Content-Type: application/json\r\n"
			"Access-Control-Allow-Origin: http://127.0.0.1\r\n"
			"X-Content-Type-Options: nosniff\r\n"
			"Content-Length: %d\r\n\r\n",
			overall ? "200 OK" : "400 Bad Request",
			json.GetLength());
		Data.pSocket->SendData(header, header.GetLength());
		Data.pSocket->SendData(json, json.GetLength());
		return;
	}

	// --- /api/live/channels --- JSON list of active streams
	if (sURL == "/api/live/channels") {
		CStringA json = "{\"channels\":[";
		if (theApp.liveStreamManager != NULL) {
			LiveChannelSnapshot ch = theApp.liveStreamManager->GetChannelSnapshot();
			if (ch.broadcasting) {
			// Single broadcast model â€” expose our current stream
				CStringA hashHex = EseHexKey16A(ch.streamKey);
				CStringA titleA = EseJsonEscapeA(CStringA(CT2A((LPCTSTR)ch.title)));
				uint32 br = ch.bitrate;
				const char* quality = "SD";
				if (br >= 8000) quality = "4K";
				else if (br >= 5000) quality = "FHD";
				else if (br >= 3000) quality = "HD";

				json.AppendFormat(
					"{\"hash\":\"%s\",\"title\":\"%s\",\"category\":\"General\","
					"\"viewers\":%u,\"bitrate\":%u,\"quality\":\"%s\"}",
					(LPCSTR)hashHex, (LPCSTR)titleA,
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
	if (sURL == "/api/live/mesh") {
		CStringA json;
		if (theApp.liveStreamManager != NULL) {
			// Lock-correct snapshot — BuildDebugSnapshot runs the trust-tier
			// census under m_lock. Never iterate m_peerBitmaps or dereference
			// CUpDownClient* / GetPeerTrust() from this worker thread.
			LiveDebugSnapshot s = theApp.liveStreamManager->BuildDebugSnapshot();
			json.Format(
				"{\"meshPeers\":%d,"
				"\"pendingRequests\":%d,"
				"\"chunksServed\":%d,"
				"\"totalRedistributed\":%I64u,"
				"\"trustLevels\":{\"superSeeders\":%d,\"middle\":%d,\"leaf\":%d},"
				"\"uploadFloor\":%u,"
				"\"emergencyMode\":%s,"
				"\"source\":\"emule-core\"}",
				s.meshPeers,
				s.pendingRequests,
				s.chunksServed,
				(unsigned __int64)s.totalRedistributed,
				s.superSeeders, s.middlePeers, s.leafPeers,
				s.minUploadRequired,
				s.emergencyMode ? "true" : "false");
		}
		else {
			json = "{\"meshPeers\":0,\"pendingRequests\":0,\"chunksServed\":0,"
				"\"totalRedistributed\":0,"
				"\"trustLevels\":{\"superSeeders\":0,\"middle\":0,\"leaf\":0},"
				"\"uploadFloor\":0,\"emergencyMode\":false,\"source\":\"emule-core\"}";
		}

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
	if (sURL == "/api/live/kad/streams") {
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
				entry.isOwnStream ? "true" : "false");
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


	// --- /api/live/debug --- Phase 0 Observability (OBS-1)
	// Fix 1 (ALTA): All state is read via BuildDebugSnapshot() under m_lock.
	// No direct CMap/CTypedPtrList iteration from the WebServer thread.
	if (sURL == "/api/live/debug") {
		CStringA json;

		if (theApp.liveStreamManager != NULL) {
			LiveDebugSnapshot s = theApp.liveStreamManager->BuildDebugSnapshot();
			DWORD now = GetTickCount();

			// --- Discovery section ---
			DWORD lastPublishAge = (s.kad.lastPublishTime > 0)
				? (now - s.kad.lastPublishTime) : 0;
			DWORD lastSearchAge = (s.kad.lastSearchTime > 0)
				? (now - s.kad.lastSearchTime) : 0;
			DWORD lastResultAge = (s.kad.lastResultTime > 0)
				? (now - s.kad.lastResultTime) : 0;

			CStringA discovery;
			discovery.Format(
				"\"discovery\":{"
				"\"kadConnected\":%s,"
				"\"knownStreams\":%d,"
				"\"knownStreamsClean\":%d,"
				"\"knownStreamsLegacy\":%d,"
				"\"lastPublishAgeMs\":%u,"
				"\"lastSearchAgeMs\":%u,"
				"\"lastResultAgeMs\":%u,"
				"\"lastResultIP\":%u,"
				"\"lastResultPort\":%u}",
				s.kad.kadConnected ? "true" : "false",
				s.kad.knownStreams,
				s.kad.knownStreamsClean,
				s.kad.knownStreamsLegacy,
				lastPublishAge,
				lastSearchAge,
				lastResultAge,
				s.kad.lastResultIP,
				(unsigned)s.kad.lastResultPort);

			// --- Peer section ---
			CStringA peers;
			peers.Format(
				"\"peers\":{"
				"\"viewPeers\":%d,"
				"\"broadcastPeers\":%d,"
				"\"meshPeers\":%d,"
				"\"pendingRequests\":%d,"
				"\"chunksServed\":%d,"
				"\"trustLevels\":{\"superSeeders\":%d,\"middle\":%d,\"leaf\":%d}}",
				s.viewPeers,
				s.broadcastPeers,
				s.meshPeers,
				s.pendingRequests,
				s.chunksServed,
				s.superSeeders, s.middlePeers, s.leafPeers);

			// --- Chunk buffer section ---
			CStringA chunks;
			chunks.Format(
				"\"chunks\":{"
				"\"count\":%d,"
				"\"oldestSeq\":%u,"
				"\"newestSeq\":%u,"
				"\"bitmap\":%u,"
				"\"missing\":%d,"
				"\"maxCapacity\":%d}",
				s.bufCount, s.oldestSeq, s.newestSeq,
				(unsigned)s.bitmap, s.missingChunks,
				ESE_LIVE_MAX_SEGMENTS);

			// --- HLS status section ---
			DWORD lastChunkAge = (s.counters.lastChunkReceivedAt > 0)
				? (now - s.counters.lastChunkReceivedAt) : 0;

			CStringA hlsStatus;
			hlsStatus.Format(
				"\"hls\":{"
				"\"segmentsWritten\":%u,"
				"\"playlistRefreshes\":%u,"
				"\"lastChunkAgeMs\":%u,"
				"\"segmentDurationSec\":%d}",
				s.counters.hlsSegmentsWritten,
				s.counters.hlsPlaylistRefresh,
				lastChunkAge,
				ESE_LIVE_SEGMENT_DURATION);

			// --- Counters section (Fix 4: added sourceDialAttempts; v7.3.0: skipped/rate-limit/auth/evict) ---
			CStringA ctrJson;
			ctrJson.Format(
				"\"counters\":{"
				"\"kadPublishes\":%u,"
				"\"kadSearches\":%u,"
				"\"kadResultsAccepted\":%u,"
				"\"kadResultsRejected\":%u,"
				"\"sourceDialAttempts\":%u,"
				"\"subscribeSent\":%u,"
				"\"subscribeAccepted\":%u,"
				"\"chunksRequested\":%u,"
				"\"chunksReceived\":%u,"
				"\"chunksMissing\":%u,"
				"\"peerDisconnects\":%u,"
				"\"skippedInitialPushes\":%u,"
				"\"subscribesRateLimited\":%u,"
				"\"endsRejectedNoAuth\":%u,"
				"\"tombstonesEvicted\":%u}",
				s.counters.kadPublishes, s.counters.kadSearches,
				s.counters.kadResultsAccepted, s.counters.kadResultsRejected,
				s.counters.sourceDialAttempts,
				s.counters.subscribeSent, s.counters.subscribeAccepted,
				s.counters.chunksRequested, s.counters.chunksReceived,
				s.counters.chunksMissing, s.counters.peerDisconnects,
				s.counters.skippedInitialPushes, s.counters.subscribesRateLimited,
				s.counters.endsRejectedNoAuth, s.counters.tombstonesEvicted);

			// --- Assemble final JSON ---
			json.Format(
				"{\"broadcasting\":%s,"
				"\"viewing\":%s,"
				"\"emergencyMode\":%s,"
				"\"uptimeMs\":%u,"
				"\"totalRedistributed\":%I64u,"
				"%s,%s,%s,%s,%s,"
				"\"source\":\"emule-core-debug\"}",
				s.broadcasting ? "true" : "false",
				s.viewing ? "true" : "false",
				s.emergencyMode ? "true" : "false",
				s.uptimeMs,
				(unsigned __int64)s.totalRedistributed,
				(LPCSTR)discovery, (LPCSTR)peers, (LPCSTR)chunks,
				(LPCSTR)hlsStatus, (LPCSTR)ctrJson);
		} else {
			json = "{\"broadcasting\":false,\"viewing\":false,"
				"\"emergencyMode\":false,\"uptimeMs\":0,\"totalRedistributed\":0,"
				"\"discovery\":{\"kadConnected\":false,\"knownStreams\":0,"
				"\"knownStreamsClean\":0,\"knownStreamsLegacy\":0,"
				"\"lastPublishAgeMs\":0,\"lastSearchAgeMs\":0,\"lastResultAgeMs\":0,"
				"\"lastResultIP\":0,\"lastResultPort\":0},"
				"\"peers\":{\"viewPeers\":0,\"broadcastPeers\":0,\"meshPeers\":0,"
				"\"pendingRequests\":0,\"chunksServed\":0,"
				"\"trustLevels\":{\"superSeeders\":0,\"middle\":0,\"leaf\":0}},"
				"\"chunks\":{\"count\":0,\"oldestSeq\":0,\"newestSeq\":0,"
				"\"bitmap\":0,\"missing\":0,\"maxCapacity\":15},"
				"\"hls\":{\"segmentsWritten\":0,\"playlistRefreshes\":0,"
				"\"lastChunkAgeMs\":0,\"segmentDurationSec\":4},"
				"\"counters\":{\"kadPublishes\":0,\"kadSearches\":0,"
				"\"kadResultsAccepted\":0,\"kadResultsRejected\":0,"
				"\"sourceDialAttempts\":0,"
				"\"subscribeSent\":0,\"subscribeAccepted\":0,"
				"\"chunksRequested\":0,\"chunksReceived\":0,"
				"\"chunksMissing\":0,\"peerDisconnects\":0},"
				"\"source\":\"emule-core-debug\"}";
		}

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
	if (sURL.Left(10) == "/api/live/" && sURL.GetLength() > 42) {
		CStringA hashHex = sURL.Mid(10, 32);
		CStringA resource = sURL.Mid(43); // after "/api/live/HASH/"

		if (sURL.GetLength() <= 43 || sURL[42] != '/' || !EseIsHexA(hashHex) || !EseIsSafeHlsResourceA(resource)) {
			Data.pSocket->SendReply("HTTP/1.1 400 Bad Request\r\nContent-Length: 11\r\n\r\nBad request");
			return;
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

			HANDLE hFile = CreateFile(filePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
				NULL, OPEN_EXISTING, 0, NULL);
			if (hFile == INVALID_HANDLE_VALUE) {
				Data.pSocket->SendReply("HTTP/1.1 404 Not Found\r\nContent-Length: 14\r\n\r\nFile not found");
				return;
			}
			DWORD fileSize = GetFileSize(hFile, NULL);
			if (fileSize == 0 || fileSize > 20 * 1024 * 1024) {
				CloseHandle(hFile);
				Data.pSocket->SendReply("HTTP/1.1 404 Not Found\r\nContent-Length: 12\r\n\r\nEmpty or big");
				return;
			}
			BYTE* buf = new BYTE[fileSize];
			DWORD bytesRead = 0;
			ReadFile(hFile, buf, fileSize, &bytesRead, NULL);
			CloseHandle(hFile);

			const char* ct = (resource.Right(5) == ".m3u8")
				? "application/vnd.apple.mpegurl" : "video/mp2t";
			const char* cache = (resource.Right(5) == ".m3u8")
				? "Cache-Control: no-cache\r\n" : "";

			CStringA header;
			header.Format(
				"HTTP/1.1 200 OK\r\n"
				"Content-Type: %s\r\n"
				"Access-Control-Allow-Origin: http://127.0.0.1\r\n"
			"X-Content-Type-Options: nosniff\r\n"
				"%s"
				"Content-Length: %u\r\n\r\n", ct, cache, bytesRead);
			Data.pSocket->SendData(header, header.GetLength());
			Data.pSocket->SendData(buf, bytesRead);
			delete[] buf;
			return;
		}
	}

	// --- /live --- Channel discovery page
	if (sURL == "/live" || sURL == "/live/") {
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
			"function r(){fetch('/api/live/channels').then(r=>r.json()).then(d=>{"
			"const g=document.getElementById('g'),e=document.getElementById('e');"
			"g.innerHTML='';"
			"if(!d.channels||d.channels.length===0){e.textContent='No live channels right now.';e.style.display='block';return}"
			"e.style.display='none';"
			"d.channels.forEach(c=>{"
			"const card=document.createElement('div');card.className='card';"
			"card.onclick=()=>location.href='/live/'+encodeURIComponent(c.hash);"
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
	if (sURL.Left(6) == "/live/" && sURL.GetLength() >= 38) {
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
			"const v=document.getElementById('v');"
			"const src='/api/live/%s/stream.m3u8';"
			"if(Hls.isSupported()){"
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
			"h.on(Hls.Events.ERROR,(e,d)=>{"
			"if(!d.fatal)return;"
			"if(d.type==='mediaError'){h.recoverMediaError()}"
			"else{setTimeout(()=>{h.loadSource(src);h.attachMedia(v)},3000)}"
			"});"
			"setInterval(()=>{if(v.paused&&v.readyState>=2)v.play()},2000);"
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
			"fetch('/api/live/channels').then(r=>r.json()).then(d=>{"
			"const ch=d.channels.find(c=>c.hash==='%s');"
			"if(ch){document.querySelector('h1').innerHTML='<span class=\"badge\">LIVE</span> '+esc(ch.title);"
			"document.getElementById('m').textContent=ch.category+' | '+ch.quality+' | '+ch.viewers+' viewers'}});"
			"</script></body></html>",
			(LPCSTR)hash, (LPCSTR)hash);

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
	CString contenttype;

	CString filename(Data.sURL);
	LPCTSTR pDot = ::PathFindExtension(filename);
	if (CPTR(filename, filename.GetLength()) > pDot + 2) { //at least 2 characters
		CString ext(pDot + 1); //skip the dot
		ext.MakeLower();
		if (ext == _T("bmp") || ext == _T("gif") || ext == _T("jpeg") || ext == _T("jpg") || ext == _T("png"))
			contenttype.Format(_T("Content-Type: image/%s\r\n"), (LPCTSTR)ext);
		//DonQ - additional file types
		else if (ext == _T("ico"))
			contenttype = _T("Content-Type: image/x-icon\r\n");
		else if (ext == _T("css"))
			contenttype = _T("Content-Type: text/css\r\n");
		else if (ext == _T("js"))
			contenttype = _T("Content-Type: text/javascript\r\n");
	}

	contenttype.AppendFormat(_T("Last-Modified: %s\r\nETag: %s\r\n"), (LPCTSTR)pThis->m_Params.sLastModified, (LPCTSTR)pThis->m_Params.sETag);

	filename.Replace(_T('/'), _T('\\'));
	if (filename[0] == _T('\\'))
		filename.Delete(0, 1);
	filename.Insert(0, thePrefs.GetMuleDirectory(EMULE_WEBSERVERDIR));

	CFile file;
	if (file.Open(filename, CFile::modeRead | CFile::shareDenyWrite | CFile::typeBinary)) {
		if (thePrefs.GetMaxWebUploadFileSizeMB() == 0 || file.GetLength() <= thePrefs.GetMaxWebUploadFileSizeMB() * 1024ull * 1024ull) {
			UINT filesize = (UINT)file.GetLength();

			char *buffer = new char[filesize];
			UINT size = file.Read(buffer, filesize);
			file.Close();
			Data.pSocket->SendContent((CStringA)contenttype, buffer, size);
			delete[] buffer;
		} else
			Data.pSocket->SendReply("HTTP/1.1 403 Forbidden\r\n");
	} else
		Data.pSocket->SendReply("HTTP/1.1 404 File not found\r\n");
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
	uchar FileHash[MDX_DIGEST_SIZE];
	bool bHash = strmd4(_ParseURL(Data.sURL, _T("filehash")), FileHash);
	if (!bHash)
		return CString();

	const CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);

	// v7.4.0 — snapshot everything we need under the lock; never iterate srclist
	// or getNotes() outside it.
	struct CommentSrc { CString user, file, comment, rating; };
	struct NoteEntry  { CString file, descr, rating; };
	CString          fileNameSnap;
	std::vector<CommentSrc> srcSnap;
	std::vector<NoteEntry>  noteSnap;
	bool found = theApp.downloadqueue->WithFileByID(FileHash, [&](CPartFile *pPartFile) {
		fileNameSnap = pPartFile->GetFileName();
		for (POSITION pos = pPartFile->srclist.GetHeadPosition(); pos != NULL;) {
			const CUpDownClient *cur_src = pPartFile->srclist.GetNext(pos);
			if (cur_src->HasFileRating() || !cur_src->GetFileComment().IsEmpty()) {
				CommentSrc c;
				c.user    = _SpecialChars(cur_src->GetUserName());
				c.file    = _SpecialChars(cur_src->GetClientFilename());
				c.comment = _SpecialChars(cur_src->GetFileComment());
				c.rating  = _SpecialChars(GetRateString(cur_src->GetFileRating()));
				srcSnap.push_back(c);
			}
		}
		const CTypedPtrList<CPtrList, Kademlia::CEntry*> &list = pPartFile->getNotes();
		for (POSITION pos = list.GetHeadPosition(); pos != NULL;) {
			const Kademlia::CEntry *entry = list.GetNext(pos);
			NoteEntry n;
			n.file   = _SpecialChars(entry->GetCommonFileName());
			n.descr  = _SpecialChars(entry->GetStrTagValue(Kademlia::CKadTagNameString(TAG_DESCRIPTION)));
			n.rating = _SpecialChars(GetRateString((UINT)entry->GetIntTagValue(Kademlia::CKadTagNameString(TAG_FILERATING))));
			noteSnap.push_back(n);
		}
	});
	if (!found)
		return CString();

	CString Out(pThis->m_Templates.sCommentList);

	CString comments(GetResString(IDS_COMMENT));
	comments.AppendFormat(_T(": %s"), (LPCTSTR)fileNameSnap);
	Out.Replace(_T("[COMMENTS]"), comments);

	CString commentlines;
	for (const auto &c : srcSnap) {
		commentlines.AppendFormat(pThis->m_Templates.sCommentListLine,
			(LPCTSTR)c.user, (LPCTSTR)c.file, (LPCTSTR)c.comment, (LPCTSTR)c.rating);
	}
	for (const auto &n : noteSnap) {
		commentlines.AppendFormat(pThis->m_Templates.sCommentListLine,
			_T(""), (LPCTSTR)n.file, (LPCTSTR)n.descr, (LPCTSTR)n.rating);
	}

	Out.Replace(_T("[COMMENTLINES]"), commentlines);

	Out.Replace(_T("[COMMENTS]"), _T(""));
	Out.Replace(_T("[USERNAME]"), GetResString(IDS_QL_USERNAME));
	Out.Replace(_T("[FILENAME]"), GetResString(IDS_DL_FILENAME));
	Out.Replace(_T("[COMMENT]"), GetResString(IDS_COMMENT));
	Out.Replace(_T("[RATING]"), GetResString(IDS_QL_RATING));
	Out.Replace(_T("[CLOSE]"), GetResString(IDS_CW_CLOSE));
	Out.Replace(_T("[CharSet]"), HTTPENCODING);

	return Out;
}

int AFX_CDECL CWebServer::_DownloadCmp(void *prm, void const *pv1, void const *pv2)
{
	const DownloadFiles &p1 = *reinterpret_cast<const DownloadFiles*>(pv1);
	const DownloadFiles &p2 = *reinterpret_cast<const DownloadFiles*>(pv2);
	int iOrd;
	switch ((DownloadSort)((SortParams*)prm)->eSort) {
	case DOWN_SORT_STATE:
		iOrd = p1.iFileState - p2.iFileState;
		break;
	case DOWN_SORT_TYPE:
		iOrd = p1.sFileType.CompareNoCase(p2.sFileType);
		break;
	case DOWN_SORT_NAME:
		iOrd = p1.sFileName.CompareNoCase(p2.sFileName);
		break;
	case DOWN_SORT_SIZE:
		iOrd = CompareUnsigned(p1.m_qwFileSize, p2.m_qwFileSize);
		break;
	case DOWN_SORT_TRANSFERRED:
		iOrd = CompareUnsigned(p1.m_qwFileTransferred, p2.m_qwFileTransferred);
		break;
	case DOWN_SORT_SPEED:
		iOrd = p1.lFileSpeed - p2.lFileSpeed;
		break;
	case DOWN_SORT_PROGRESS:
		iOrd = sgn(p1.m_dblCompleted - p2.m_dblCompleted);
		break;
	case DOWN_SORT_SOURCES:
		iOrd = p1.lSourceCount - p2.lSourceCount;
		break;
	case DOWN_SORT_PRIORITY:
		iOrd = p1.nFilePrio - p2.nFilePrio;
		break;
	case DOWN_SORT_CATEGORY:
		iOrd = p1.sCategory.CompareNoCase(p2.sCategory);
		break;
	default: //unknown
		return 0;
	}
	return ((SortParams*)prm)->bReverse ? iOrd : -iOrd;
}

int AFX_CDECL CWebServer::_ServerCmp(void *prm, void const *pv1, void const *pv2)
{
	const ServerEntry &p1 = *reinterpret_cast<const ServerEntry*>(pv1);
	const ServerEntry &p2 = *reinterpret_cast<const ServerEntry*>(pv2);
	int iOrd;
	switch ((ServerSort)((SortParams*)prm)->eSort) {
	case SERVER_SORT_STATE:
		iOrd = p2.sServerState.CompareNoCase(p1.sServerState); //reversed
		break;
	case SERVER_SORT_NAME:
		iOrd = p1.sServerName.CompareNoCase(p2.sServerName);
		break;
	case SERVER_SORT_IP:
		iOrd = p1.sServerFullIP.Compare(p2.sServerFullIP);
		if (!iOrd)
			iOrd = p1.nServerPort - p2.nServerPort;
		break;
	case SERVER_SORT_DESCRIPTION:
		iOrd = p1.sServerDescription.CompareNoCase(p2.sServerDescription);
		break;
	case SERVER_SORT_PING:
		iOrd = p1.nServerPing - p2.nServerPing;
		break;
	case SERVER_SORT_USERS:
		iOrd = p1.nServerUsers - p2.nServerUsers;
		break;
	case SERVER_SORT_FILES:
		iOrd = p1.nServerFiles - p2.nServerFiles;
		break;
	case SERVER_SORT_PRIORITY:
		iOrd = p1.nServerPriority - p2.nServerPriority;
		break;
	case SERVER_SORT_FAILED:
		iOrd = p1.nServerFailed - p2.nServerFailed;
		break;
	case SERVER_SORT_LIMIT:
		iOrd = p1.nServerSoftLimit - p2.nServerSoftLimit;
		break;
	case SERVER_SORT_VERSION:
		iOrd = p1.sServerVersion.Compare(p2.sServerVersion);
		break;
	default: //unknown
		return 0;
	}
	return ((SortParams*)prm)->bReverse ? iOrd : -iOrd;
}

int AFX_CDECL CWebServer::_SharedCmp(void *prm, void const *pv1, void const *pv2)
{
	const SharedFiles &p1 = *reinterpret_cast<const SharedFiles*>(pv1);
	const SharedFiles &p2 = *reinterpret_cast<const SharedFiles*>(pv2);
	int iOrd;
	switch ((SharedSort)((SortParams*)prm)->eSort) {
	case SHARED_SORT_STATE:
		iOrd = p2.sFileState.CompareNoCase(p1.sFileState); //reversed
		break;
	case SHARED_SORT_TYPE:
		iOrd = p2.sFileType.CompareNoCase(p1.sFileType); //reversed
		break;
	case SHARED_SORT_NAME:
		iOrd = p1.sFileName.CompareNoCase(p2.sFileName);
		break;
	case SHARED_SORT_SIZE:
		iOrd = CompareUnsigned(p1.m_qwFileSize, p2.m_qwFileSize);
		break;
	case SHARED_SORT_TRANSFERRED:
		iOrd = CompareUnsigned(p1.nFileTransferred, p2.nFileTransferred);
		break;
	case SHARED_SORT_ALL_TIME_TRANSFERRED:
		iOrd = CompareUnsigned(p1.nFileAllTimeTransferred, p2.nFileAllTimeTransferred);
		break;
	case SHARED_SORT_REQUESTS:
		iOrd = p1.nFileRequests - p2.nFileRequests;
		break;
	case SHARED_SORT_ALL_TIME_REQUESTS:
		iOrd = p1.nFileAllTimeRequests - p2.nFileAllTimeRequests;
		break;
	case SHARED_SORT_ACCEPTS:
		iOrd = p1.nFileAccepts - p2.nFileAccepts;
		break;
	case SHARED_SORT_ALL_TIME_ACCEPTS:
		iOrd = p1.nFileAllTimeAccepts - p2.nFileAllTimeAccepts;
		break;
	case SHARED_SORT_COMPLETES:
		iOrd = sgn(p1.dblFileCompletes - p2.dblFileCompletes);
		break;
	case SHARED_SORT_PRIORITY:
		iOrd = CSharedFileList::GetRealPrio(p1.nFilePriority) - CSharedFileList::GetRealPrio(p2.nFilePriority);
		break;
	default: //unknown
		return 0;
	}
	return ((SortParams*)prm)->bReverse ? iOrd : -iOrd;
}

int AFX_CDECL CWebServer::_UploadCmp(void *prm, void const *pv1, void const *pv2)
{
	const UploadUsers &p1 = *reinterpret_cast<const UploadUsers*>(pv1);
	const UploadUsers &p2 = *reinterpret_cast<const UploadUsers*>(pv2);
	int iOrd;
	switch ((UploadSort)((SortParams*)prm)->eSort) {
	case UP_SORT_CLIENT:
		iOrd = *p1.sClientSoft - *p2.sClientSoft;
		break;
	case UP_SORT_USER:
		iOrd = p1.sUserName.CompareNoCase(p2.sUserName);
		break;
	case UP_SORT_VERSION:
		iOrd = p1.sClientNameVersion.CompareNoCase(p2.sClientNameVersion);
		break;
	case UP_SORT_FILENAME:
		iOrd = p1.sFileName.CompareNoCase(p2.sFileName);
		break;
	case UP_SORT_TRANSFERRED:
		iOrd = CompareUnsigned(p1.nTransferredUp, p2.nTransferredUp);
		break;
	case UP_SORT_SPEED:
		iOrd = p1.nDataRate - p2.nDataRate;
		break;
	default: //unknown
		return 0;
	}
	return ((SortParams*)prm)->bReverse ? iOrd : -iOrd;
}
