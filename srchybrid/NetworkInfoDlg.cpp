#include "stdafx.h"
#include "emule.h"
#include "NetworkInfoDlg.h"
#include "RichEditCtrlX.h"
#include "OtherFunctions.h"
#include "ServerConnect.h"
#include "Preferences.h"
#include "ServerList.h"
#include "Server.h"
#include "kademlia/kademlia/kademlia.h"
#include "kademlia/kademlia/UDPFirewallTester.h"
#include "kademlia/kademlia/prefs.h"
#include "kademlia/kademlia/indexed.h"
#include "WebServer.h"
#include "clientlist.h"
#include "ListenSocket.h"        // v0.71 IPv6 Sprint 9 — IsDualStack()
#include "FirewallProberV6.h"    // v0.71 IPv6 Sprint 3 — GetDetectedV6IP()
// v0.71 P2.1 — Privacidad block. Reads live state from the privacy
// singletons so the user can verify the modules are actually running.
#include "LiveTunnel.h"
#include "LiveSubscriptionStore.h"
#include "kademlia/kademlia/KadV2TunnelPool.h"
#include "kademlia/kademlia/KadV2ModeSelector.h"
#include "Opcodes.h"   // g_uEseCapsRuntime + ESE_CAP_* bits

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

#define	PREF_INI_SECTION	_T("NetworkInfoDlg")

IMPLEMENT_DYNAMIC(CNetworkInfoDlg, CDialog)

BEGIN_MESSAGE_MAP(CNetworkInfoDlg, CResizableDialog)
	ON_WM_TIMER()        // v0.71 P3.9 — periodic refresh
	ON_WM_DESTROY()
	ON_CBN_SELCHANGE(IDC_NETINFO_KADMODE, &CNetworkInfoDlg::OnKadModeChanged)   // v8.1 D6
	ON_BN_CLICKED(IDC_NETINFO_COPY, &CNetworkInfoDlg::OnCopyInfo)
END_MESSAGE_MAP()

CNetworkInfoDlg::CNetworkInfoDlg(CWnd *pParent /*=NULL*/)
	: CResizableDialog(CNetworkInfoDlg::IDD, pParent)
{
	ZeroMemory(&m_rcfDef, sizeof m_rcfDef);
	ZeroMemory(&m_rcfBold, sizeof m_rcfBold);
}

CNetworkInfoDlg::~CNetworkInfoDlg()
{
}

void CNetworkInfoDlg::DoDataExchange(CDataExchange *pDX)
{
	CResizableDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_NETWORK_INFO, m_info);
	DDX_Control(pDX, IDC_NETINFO_KADMODE, m_cbKadMode);   // v8.1 D6
}

BOOL CNetworkInfoDlg::OnInitDialog()
{
	ReplaceRichEditCtrl(GetDlgItem(IDC_NETWORK_INFO), this, GetDlgItem(IDC_NETWORK_INFO_LABEL)->GetFont());
	CResizableDialog::OnInitDialog();
	InitWindowStyles(this);

	AddAnchor(IDC_NETWORK_INFO, TOP_LEFT, BOTTOM_RIGHT);
	AddAnchor(IDC_NETINFO_COPY, BOTTOM_RIGHT);
	AddAnchor(IDOK, BOTTOM_RIGHT);

	// v8.1 D6 - native privacy-mode dropdown (parity with the web /privacy selector). Populate
	// ONCE here (not in the 2s refresh timer, which would reset the user's open selection). The
	// 3 items map 1:1 to CKadV2Mode (Direct=0, Tunneled=1, Adaptive=2).
	AddAnchor(IDC_NETINFO_KADMODE, TOP_LEFT, TOP_RIGHT);
	m_cbKadMode.ResetContent();
	m_cbKadMode.AddString(GetResString(IDS_NETINFO_KADMODE_DIRECT));
	m_cbKadMode.AddString(GetResString(IDS_NETINFO_KADMODE_TUNNELED));
	m_cbKadMode.AddString(GetResString(IDS_NETINFO_KADMODE_ADAPTIVE));
	m_cbKadMode.SetCurSel((int)Kademlia::CKadV2ModeSelector::Get().GetDefaultMode());

	EnableSaveRestore(PREF_INI_SECTION);

	SetWindowText(GetResString(IDS_NETWORK_INFO));
	SetDlgItemText(IDC_NETINFO_COPY, GetResString(IDS_COPY));
	SetDlgItemText(IDOK, GetResString(IDS_TREEOPTIONS_OK));

	SetDlgItemText(IDC_NETWORK_INFO_LABEL, GetResString(IDS_NETWORK_INFO));

	m_info.SendMessage(EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN, MAKELONG(3, 3));
	m_info.SetAutoURLDetect();
	m_info.SetEventMask(m_info.GetEventMask() | ENM_LINK);

	CHARFORMAT cfDef = {};
	CHARFORMAT cfBold = {};

	PARAFORMAT pf = {};
	pf.cbSize = (UINT)sizeof pf;
	if (m_info.GetParaFormat(pf)) {
		pf.dwMask |= PFM_TABSTOPS;
		pf.cTabCount = 4;
		pf.rgxTabs[0] = 900;
		pf.rgxTabs[1] = 1000;
		pf.rgxTabs[2] = 1100;
		pf.rgxTabs[3] = 1200;
		m_info.SetParaFormat(pf);
	}

	cfDef.cbSize = (UINT)sizeof cfDef;
	if (m_info.GetSelectionCharFormat(cfDef)) {
		cfBold = cfDef;
		cfBold.dwMask |= CFM_BOLD;
		cfBold.dwEffects |= CFE_BOLD;
	}

	// v0.71 P3.9 — cache the formats so the timer refresh can re-render
	// without re-querying them every tick.
	m_rcfDef  = cfDef;
	m_rcfBold = cfBold;

	CreateNetworkInfo(m_info, cfDef, cfBold, true);
	DisableAutoSelect(m_info);

	// v0.71 P3.9 — periodic refresh (every 2 s) so live counters
	// (privacy circuits, connection state, IP) update without the user
	// having to close+reopen the dialog. Cost is one full text rebuild
	// every 2 s — cheap, no perceivable CPU.
	m_nRefreshTimer = SetTimer(0xE5E1 /* eSE Info ID */, 2000, NULL);
	return TRUE;
}

// v8.1 D6 - dropdown changed: set the mode in the selector + mirror into prefs (persists at
// eMule's exit-time Save, exactly like the web /privacy handler — no Save() from here). Refresh
// the panel so the read-only "Modo:" line updates immediately.
void CNetworkInfoDlg::OnKadModeChanged()
{
	int sel = m_cbKadMode.GetCurSel();
	if (sel == CB_ERR) return;
	Kademlia::CKadV2ModeSelector& s = Kademlia::CKadV2ModeSelector::Get();
	s.SetDefaultMode((Kademlia::CKadV2Mode)sel);
	thePrefs.SetKadV2PrivacyMode((int)s.GetDefaultMode());
	RefreshNow();
}

void CNetworkInfoDlg::OnCopyInfo()
{
	CString report;
	m_info.GetWindowText(report);
	theApp.CopyTextToClipboard(report);
}

// v0.71 P3.9 — full re-render of the rich-edit content, preserving the
// user's scroll position so the panel doesn't jump while they're reading.
void CNetworkInfoDlg::RefreshNow()
{
	if (theApp.IsClosing()) return;

	// Save scroll position so the refresh doesn't yank the viewport.
	CPoint scroll(0, 0);
	m_info.GetScrollPos(SB_HORZ);  // dummy to trigger; not strictly needed
	int yPos = m_info.GetFirstVisibleLine();

	m_info.SetRedraw(FALSE);
	m_info.SetSel(0, -1);
	m_info.ReplaceSel(_T(""));
	CreateNetworkInfo(m_info, m_rcfDef, m_rcfBold, true);
	DisableAutoSelect(m_info);
	// Restore scroll
	int curLine = m_info.GetFirstVisibleLine();
	if (curLine != yPos)
		m_info.LineScroll(yPos - curLine);
	m_info.SetRedraw(TRUE);
	m_info.Invalidate();
}

void CNetworkInfoDlg::OnTimer(UINT_PTR nIDEvent)
{
	if (nIDEvent == 0xE5E1) {
		RefreshNow();
		return;
	}
	CResizableDialog::OnTimer(nIDEvent);
}

void CNetworkInfoDlg::OnDestroy()
{
	if (m_nRefreshTimer) {
		KillTimer(m_nRefreshTimer);
		m_nRefreshTimer = 0;
	}
	CResizableDialog::OnDestroy();
}

void CreateNetworkInfo(CRichEditCtrlX &rCtrl, CHARFORMAT &rcfDef, CHARFORMAT &rcfBold, bool bFullInfo)
{
	if (bFullInfo) {
		///////////////////////////////////////////////////////////////////////////
		// Ports Info
		///////////////////////////////////////////////////////////////////////////
		rCtrl.SetSelectionCharFormat(rcfBold);
		rCtrl << GetResString(IDS_CLIENT) << _T("\r\n");
		rCtrl.SetSelectionCharFormat(rcfDef);

		rCtrl << GetResString(IDS_PW_NICK) << _T(":\t") << thePrefs.GetUserNick() << _T("\r\n");
		rCtrl << GetResString(IDS_CD_UHASH) << _T("\t") << md4str(thePrefs.GetUserHash()) << _T("\r\n");
		rCtrl << _T("TCP ") << GetResString(IDS_PORT) << _T(":\t") << thePrefs.GetPort() << _T("\r\n");
		rCtrl << _T("UDP ") << GetResString(IDS_PORT) << _T(":\t") << thePrefs.GetUDPPort() << _T("\r\n");
		rCtrl << _T("\r\n");
	}

	///////////////////////////////////////////////////////////////////////////
	// v0.71 IPv6 Sprint 9 — Connectivity (IPv4 / IPv6)
	///////////////////////////////////////////////////////////////////////////
	rCtrl.SetSelectionCharFormat(rcfBold);
	rCtrl << GetResString(IDS_NETINFO_CONNECTIVITY_HDR) << _T("\r\n");
	rCtrl.SetSelectionCharFormat(rcfDef);

	// Modo (pref del usuario).
	rCtrl << GetResString(IDS_NETINFO_MODE_LABEL);
	switch (thePrefs.GetIPv6Mode()) {
		case CPreferences::IPv6OffMode:       rCtrl << GetResString(IDS_NETINFO_IPV6_OFF); break;
		case CPreferences::IPv6AutoMode:      rCtrl << GetResString(IDS_NETINFO_IPV6_AUTO); break;
		case CPreferences::IPv6PreferredMode: rCtrl << GetResString(IDS_NETINFO_IPV6_PREFERRED); break;
		default:                              rCtrl << GetResString(IDS_NETINFO_UNKNOWN_Q); break;
	}
	rCtrl << _T("\r\n");

	// Estado real del listener (independiente de la preferencia). Auto y
	// Preferido intentan dual-stack; si el sistema no permite AF_INET6,
	// se muestra explícitamente el fallback IPv4.
	rCtrl << GetResString(IDS_NETINFO_LISTENER_LABEL);
	{
		CString s;
		if (theApp.listensocket && theApp.listensocket->IsDualStack()) {
			s.Format(GetResString(IDS_NETINFO_LISTENER_DUALSTACK), thePrefs.GetPort());
		} else if (thePrefs.IsIPv6Enabled()) {
			s.Format(GetResString(IDS_NETINFO_LISTENER_V6FAIL), thePrefs.GetPort());
		} else {
			s.Format(GetResString(IDS_NETINFO_LISTENER_V4ONLY), thePrefs.GetPort());
		}
		rCtrl << s;
	}
	rCtrl << _T("\r\n");

	if (theApp.GetPublicIP() != 0) {
		rCtrl << GetResString(IDS_NETINFO_PUBIP4_LABEL) << ipstr(theApp.GetPublicIP()) << _T("\r\n");
	}
	rCtrl << GetResString(IDS_NETINFO_PUBIP6_LABEL);
	{
		CAddress v6 = CFirewallProberV6::Instance().GetDetectedV6IP();
		if (v6.IsNull())
			rCtrl << GetResString(IDS_NETINFO_PUBIP6_NONE);
		else
			rCtrl << v6.ToStringC();
	}
	rCtrl << _T("\r\n");

	rCtrl << _T("\r\n");

	///////////////////////////////////////////////////////////////////////////
	// v0.71 P2.1 — Privacidad (eSE V1)
	///////////////////////////////////////////////////////////////////////////
	// Este bloque demuestra al usuario qué partes del stack de privacidad
	// (tesis de seguridad + Kad Search v2) están REALMENTE encendidas. La
	// auditoría 2026-05-19 reveló que los módulos F2-F5 existían como
	// código pero nadie los instanciaba en runtime. P0 los enchufa al
	// arranque; este bloque hace visible que están vivos.
	rCtrl.SetSelectionCharFormat(rcfBold);
	rCtrl << GetResString(IDS_NETINFO_PRIVACY_HDR) << _T("\r\n");
	rCtrl.SetSelectionCharFormat(rcfDef);

	{
		using namespace Kademlia;
		CKadV2ModeSelector& sel = CKadV2ModeSelector::Get();

		// Modo activo (preferencia del usuario)
		rCtrl << GetResString(IDS_NETINFO_MODE_LABEL);
		switch (sel.GetDefaultMode()) {
			case CKadV2Mode::Direct:   rCtrl << GetResString(IDS_NETINFO_PRIV_DIRECT); break;
			case CKadV2Mode::Tunneled: rCtrl << GetResString(IDS_NETINFO_PRIV_TUNNELED); break;
			case CKadV2Mode::Adaptive: rCtrl << GetResString(IDS_NETINFO_PRIV_ADAPTIVE); break;
			default:                   rCtrl << GetResString(IDS_NETINFO_UNKNOWN_Q); break;
		}
		rCtrl << _T("\r\n");

		// Política de fallback si faltan relays
		rCtrl << GetResString(IDS_NETINFO_FALLBACK_LABEL);
		switch (sel.GetFallbackPolicy()) {
			case CKadV2ModeSelector::STRICT_PRIVACY: rCtrl << GetResString(IDS_NETINFO_FALLBACK_STRICT); break;
			case CKadV2ModeSelector::BALANCED:       rCtrl << GetResString(IDS_NETINFO_FALLBACK_BALANCED); break;
			case CKadV2ModeSelector::BEST_EFFORT:    rCtrl << GetResString(IDS_NETINFO_FALLBACK_BESTEFFORT); break;
			default:                                 rCtrl << GetResString(IDS_NETINFO_UNKNOWN_Q); break;
		}
		rCtrl << _T("\r\n");

		// Capabilities runtime — bitmap TAG_ESE_CAPS. Refleja qué módulos
		// reales se han instanciado al arranque (P0.3). 0x00000000 sería
		// señal de stack apagado.
		rCtrl << GetResString(IDS_NETINFO_CAPS_LABEL);
		{
			CString cs;
			cs.Format(_T("0x%08X"), (unsigned)g_uEseCapsRuntime);
			rCtrl << cs;
			if (g_uEseCapsRuntime == 0) {
				rCtrl << GetResString(IDS_NETINFO_CAPS_OFF);
			} else {
				rCtrl << _T("  [");
				bool first = true;
				#define APPEND_CAP(bit, name) \
					do { if (g_uEseCapsRuntime & (bit)) { \
						if (!first) rCtrl << _T(", "); \
						rCtrl << _T(name); first = false; \
					} } while (0)
				APPEND_CAP(ESE_CAP_M1_SUBSCRIBER_PIN, "M1");
				APPEND_CAP(ESE_CAP_M2_COMPOSITE_KEYS, "M2");
				APPEND_CAP(ESE_CAP_M3_SHARDING,       "M3");
				APPEND_CAP(ESE_CAP_M4_TRIGRAMS,       "M4");
				APPEND_CAP(ESE_CAP_M5_BLOOM_GOSSIP,   "M5");
				APPEND_CAP(ESE_CAP_M6_K_EFFECTIVE,    "M6");
				APPEND_CAP(ESE_CAP_SEALED_RECORDS,    "Sealed");
				APPEND_CAP(ESE_CAP_GOSSIP_PROTOCOL,   "Gossip");
				APPEND_CAP(ESE_CAP_PRIVACY_TUNNELING, "Tunneling");
				APPEND_CAP(ESE_CAP_COVER_TRAFFIC,     "Cover");
				APPEND_CAP(ESE_CAP_TUNNEL_AUTH,       "TunnelAuth");
				APPEND_CAP(ESE_CAP_HOLEPUNCH_RDV,     "RDV");
				APPEND_CAP(ESE_CAP_LIVE_RELAY,        "Relay");
				APPEND_CAP(ESE_CAP_KAD6,              "Kad6");
				APPEND_CAP(ESE_CAP_TUNNEL_STRICT3,    "Strict3");
				APPEND_CAP(ESE_CAP_NETLAB_V1,         "NetLab");
				APPEND_CAP(ESE_CAP_TUNNEL_SHAPED,     "Class5");
				#undef APPEND_CAP
				rCtrl << _T("]");
			}
		}
		rCtrl << _T("\r\n");
		if (g_uEseCapsRuntime & ESE_CAP_KAD6) {
			rCtrl << _T("Kad6 discovery:\tDISCOVERY_ONLY — origin hidden from DHT; exit sees keyword; transfer privacy is separate\r\n");
		}

		// Circuitos onion. Mostramos pending + active separadamente
		// porque un test_circuit contra peer legacy crea un Pending que
		// NUNCA llega a Active — ocultar Pending hacía parecer que no
		// pasaba nada (panel mostraba 0 todo el rato aunque el código
		// sí enviase la cell). Honestidad > simplicidad.
		size_t circuitsActive = 0;
		size_t circuitsPending = 0;
		size_t pool = 0;
		size_t subs = 0;
		size_t strict3Circuits = 0;
		size_t shapedCircuits = 0;
		size_t shapingExposed = 0;
		uint64_t cellsSent = 0, cellsRecv = 0, bytesSent = 0, bytesRecv = 0;  // v8.1 D8
		uint32_t meanRtt = 0;                                                 // v8.1 D8
		try {
			circuitsActive  = eSELive::CLiveTunnel::Get().ActiveCircuitCount();
			circuitsPending = eSELive::CLiveTunnel::Get().PendingCircuitCount();
			pool            = CKadV2TunnelPool::Get().Size();
			subs            = eSELive::CLiveSubscriptionStore::Get().Count();
			cellsSent       = eSELive::CLiveTunnel::Get().CellsSentTotal();   // v8.1 D8
			cellsRecv       = eSELive::CLiveTunnel::Get().CellsRecvTotal();
			bytesSent       = eSELive::CLiveTunnel::Get().BytesSentTotal();
			bytesRecv       = eSELive::CLiveTunnel::Get().BytesRecvTotal();
			meanRtt         = eSELive::CLiveTunnel::Get().MeanRttMs();
			std::vector<eSELive::CLiveTunnel::CircuitSnapshot> snapshots;
			eSELive::CLiveTunnel::Get().GetCircuitsSnapshot(snapshots);
			for (const auto& circuit : snapshots) {
				if (circuit.state != (uint8_t)eSELive::CircuitState::Active) continue;
				if (circuit.strict3) ++strict3Circuits;
				if (circuit.shaped) ++shapedCircuits;
				if (circuit.shaping_exposed) ++shapingExposed;
			}
		} catch (...) {}

		{
			CString cs;
			cs.Format(GetResString(IDS_NETINFO_TUNNELS_COUNT_FMT),
				(unsigned)circuitsActive, (unsigned)circuitsPending, (unsigned)pool);
			rCtrl << GetResString(IDS_NETINFO_ONIONTUNNELS_LABEL) << cs;
			if (circuitsActive == 0 && circuitsPending == 0
			    && sel.GetDefaultMode() != CKadV2Mode::Direct)
			{
				// P3 done: TCP send wired. No circuits anywhere means
				// no fork peer has been encountered yet and no manual
				// test has run.
				rCtrl << GetResString(IDS_NETINFO_TUNNELS_WAITING);
			} else if (circuitsActive == 0 && circuitsPending > 0) {
				// Pending only — handshake in flight or doomed to time
				// out against a legacy peer. Visible proof that send
				// pipeline is working.
				rCtrl << GetResString(IDS_NETINFO_TUNNELS_NEGOTIATING);
			}
			rCtrl << _T("\r\n");

			// v8.1 D8 — tunnel wire-byte/cell telemetry (honest: counts only cells
			// carried by the onion tunnel, not direct eD2K traffic). 0/0 until a
			// circuit is built + used.
			cs.Format(GetResString(IDS_NETINFO_TRAFFIC_FMT),
				cellsSent, bytesSent / 1024, cellsRecv, bytesRecv / 1024);
			rCtrl << GetResString(IDS_NETINFO_TRAFFIC_LABEL) << cs << _T("\r\n");
			if (strict3Circuits || shapedCircuits || shapingExposed) {
				cs.Format(_T("Kad6 STRICT:\t%u strict3 / %u class-5%s\r\n"),
					(unsigned)strict3Circuits, (unsigned)shapedCircuits,
					shapingExposed ? _T(" — DEGRADED: TRAFFIC_SHAPING_EXPOSED") : _T(""));
				rCtrl << cs;
			}

			// v8.1 D8 - mean end-to-end tunnel RTT (only shown once a probe round-trips).
			if (meanRtt > 0) {
				cs.Format(GetResString(IDS_NETINFO_RTT_FMT), meanRtt);
				rCtrl << GetResString(IDS_NETINFO_RTT_LABEL) << cs << _T("\r\n");
			}

			cs.Format(GetResString(IDS_NETINFO_SUBS_FMT), (unsigned)subs);
			rCtrl << GetResString(IDS_NETINFO_SUBS_LABEL) << cs << _T("\r\n");
		}
	}

	rCtrl << _T("\r\n");

	///////////////////////////////////////////////////////////////////////////
	// ED2K
	///////////////////////////////////////////////////////////////////////////
	rCtrl.SetSelectionCharFormat(rcfBold);
	rCtrl << _T("eD2K ") << GetResString(IDS_NETWORK) << _T("\r\n");
	rCtrl.SetSelectionCharFormat(rcfDef);

	rCtrl << GetResString(IDS_STATUS) << _T(":\t");
	UINT uid;
	if (theApp.serverconnect->IsConnected())
		uid = IDS_CONNECTED;
	else if (theApp.serverconnect->IsConnecting())
		uid = IDS_CONNECTING;
	else
		uid = IDS_DISCONNECTED;
	rCtrl << GetResString(uid) << _T("\r\n");

	//I only show this in full display as the normal display is not
	//updated at regular intervals.
	if (bFullInfo && theApp.serverconnect->IsConnected()) {
		uint32 uTotalUser = 0;
		uint32 uTotalFile = 0;

		theApp.serverlist->GetUserFileStatus(uTotalUser, uTotalFile);
		rCtrl << GetResString(IDS_UUSERS) << _T(":\t") << GetFormatedUInt(uTotalUser) << _T("\r\n");
		rCtrl << GetResString(IDS_PW_FILES) << _T(":\t") << GetFormatedUInt(uTotalFile) << _T("\r\n");
	}

	CString buffer;
	if (theApp.serverconnect->IsConnected()) {
		rCtrl << GetResString(IDS_IP) << _T(":") << GetResString(IDS_PORT) << _T(":");
		if (theApp.serverconnect->IsLowID() && theApp.GetED2KPublicIP() == 0)
			buffer = GetResString(IDS_UNKNOWN);
		else
			buffer.Format(_T("%s:%u"), (LPCTSTR)ipstr(theApp.GetED2KPublicIP()), theApp.GetAdvertisedTcpPort());
		rCtrl << _T("\t") << buffer << _T("\r\n");

		rCtrl << GetResString(IDS_ID) << _T(":\t");
		if (theApp.serverconnect->IsConnected()) {
			buffer.Format(_T("%u"), theApp.serverconnect->GetClientID());
			rCtrl << buffer;
		}
		rCtrl << _T("\r\n");

		rCtrl << _T("\t");
		rCtrl << GetResString(theApp.serverconnect->IsLowID() ? IDS_IDLOW : IDS_IDHIGH);
		rCtrl << _T("\r\n");

		CServer *cur_server = theApp.serverconnect->GetCurrentServer();
		CServer *srv = cur_server ? theApp.serverlist->GetServerByAddress(cur_server->GetAddress(), cur_server->GetPort()) : NULL;
		if (srv) {
			rCtrl << _T("\r\n");
			rCtrl.SetSelectionCharFormat(rcfBold);
			rCtrl << _T("eD2K ") << GetResString(IDS_SERVER) << _T("\r\n");
			rCtrl.SetSelectionCharFormat(rcfDef);

			rCtrl << GetResString(IDS_SW_NAME) << _T(":\t") << srv->GetListName() << _T("\r\n");
			rCtrl << GetResString(IDS_DESCRIPTION) << _T(":\t") << srv->GetDescription() << _T("\r\n");
			rCtrl << GetResString(IDS_IP) << _T(":") << GetResString(IDS_PORT) << _T(":\t") << srv->GetAddress() << _T(":") << srv->GetPort() << _T("\r\n");
			rCtrl << GetResString(IDS_VERSION) << _T(":\t") << srv->GetVersion() << _T("\r\n");
			rCtrl << GetResString(IDS_UUSERS) << _T(":\t") << GetFormatedUInt(srv->GetUsers()) << _T("\r\n");
			rCtrl << GetResString(IDS_PW_FILES) << _T(":\t") << GetFormatedUInt(srv->GetFiles()) << _T("\r\n");
			rCtrl << GetResString(IDS_CONNECTIONS) << _T(":\t");
			rCtrl << GetResString(theApp.serverconnect->IsConnectedObfuscated() ? IDS_OBFUSCATED : IDS_PRIONORMAL);
			rCtrl << _T("\r\n");


			if (bFullInfo) {
				rCtrl << GetResString(IDS_IDLOW) << _T(":\t") << GetFormatedUInt(srv->GetLowIDUsers()) << _T("\r\n");
				rCtrl << GetResString(IDS_PING) << _T(":\t") << (UINT)srv->GetPing() << _T(" ms\r\n");

				rCtrl << _T("\r\n");
				rCtrl.SetSelectionCharFormat(rcfBold);
				rCtrl << _T("eD2K ") << GetResString(IDS_SERVER) << _T(" ") << GetResString(IDS_FEATURES) << _T("\r\n");
				rCtrl.SetSelectionCharFormat(rcfDef);

				rCtrl << GetResString(IDS_SERVER_LIMITS) << _T(": ") << GetFormatedUInt(srv->GetSoftFiles()) << _T("/") << GetFormatedUInt(srv->GetHardFiles()) << _T("\r\n");

				if (thePrefs.IsExtControlsEnabled()) {
					CString sNo, sYes;
					sNo.Format(_T(": %s\r\n"), (LPCTSTR)GetResString(IDS_NO));
					sYes.Format(_T(": %s\r\n"), (LPCTSTR)GetResString(IDS_YES));
					bool bYes = srv->GetTCPFlags() & SRV_TCPFLG_COMPRESSION;
					rCtrl << GetResString(IDS_SRV_TCPCOMPR) << (bYes ? sYes : sNo);

					bYes = (srv->GetTCPFlags() & SRV_TCPFLG_NEWTAGS) || (srv->GetUDPFlags() & SRV_UDPFLG_NEWTAGS);
					rCtrl << GetResString(IDS_SHORTTAGS) << (bYes ? sYes : sNo);

					bYes = (srv->GetTCPFlags() & SRV_TCPFLG_UNICODE) || (srv->GetUDPFlags() & SRV_UDPFLG_UNICODE);
					rCtrl << _T("Unicode") << (bYes ? sYes : sNo);

					bYes = srv->GetTCPFlags() & SRV_TCPFLG_TYPETAGINTEGER;
					rCtrl << GetResString(IDS_SERVERFEATURE_INTTYPETAGS) << (bYes ? sYes : sNo);

					bYes = srv->GetUDPFlags() & SRV_UDPFLG_EXT_GETSOURCES;
					rCtrl << GetResString(IDS_SRV_UDPSR) << (bYes ? sYes : sNo);

					bYes = srv->GetUDPFlags() & SRV_UDPFLG_EXT_GETSOURCES2;
					rCtrl << GetResString(IDS_SRV_UDPSR) << _T(" #2") << (bYes ? sYes : sNo);

					bYes = srv->GetUDPFlags() & SRV_UDPFLG_EXT_GETFILES;
					rCtrl << GetResString(IDS_SRV_UDPFR) << (bYes ? sYes : sNo);

					bYes = srv->SupportsLargeFilesTCP() || srv->SupportsLargeFilesUDP();
					rCtrl << GetResString(IDS_SRV_LARGEFILES) << (bYes ? sYes : sNo);

					bYes = srv->SupportsObfuscationUDP();
					rCtrl << GetResString(IDS_PROTOCOLOBFUSCATION) << _T(" (UDP)") << (bYes ? sYes : sNo);

					bYes = srv->SupportsObfuscationTCP();
					rCtrl << GetResString(IDS_PROTOCOLOBFUSCATION) << _T(" (TCP)") << (bYes ? sYes : sNo);
				}
			}
		}
	}
	rCtrl << _T("\r\n");

	///////////////////////////////////////////////////////////////////////////
	// Kademlia
	///////////////////////////////////////////////////////////////////////////
	rCtrl.SetSelectionCharFormat(rcfBold);
	rCtrl << GetResString(IDS_KADEMLIA) << _T(" ") << GetResString(IDS_NETWORK) << _T("\r\n");
	rCtrl.SetSelectionCharFormat(rcfDef);

	rCtrl << _T("Kad2 ") << GetResString(IDS_STATUS) << _T(":\t");
	if (Kademlia::CKademlia::IsKad2Connected()) {
		rCtrl << GetResString(Kademlia::CKademlia::IsFirewalled() ? IDS_FIREWALLED : IDS_KADOPEN);
		if (Kademlia::CKademlia::IsRunningInLANMode())
			rCtrl << _T(" (") << GetResString(IDS_LANMODE) << _T(")");
		rCtrl << _T("\r\n");
		rCtrl << _T("UDP ") << GetResString(IDS_STATUS) << _T(":\t");
		if (Kademlia::CUDPFirewallTester::IsFirewalledUDP(true))
			rCtrl << GetResString(IDS_FIREWALLED);
		else {
			rCtrl << GetResString(IDS_KADOPEN);
			if (!Kademlia::CUDPFirewallTester::IsVerified())
				rCtrl << _T(" (") << GetResString(IDS_UNVERIFIED).MakeLower() << _T(")");
		}
		rCtrl << _T("\r\n");

		buffer.Format(_T("%s:%i"), (LPCTSTR)ipstr(htonl(Kademlia::CKademlia::GetPrefs()->GetIPAddress())), theApp.GetAdvertisedUdpPort());
		rCtrl << GetResString(IDS_IP) << _T(":") << GetResString(IDS_PORT) << _T(":\t") << buffer << _T("\r\n");

		buffer.Format(_T("%u"), Kademlia::CKademlia::GetPrefs()->GetIPAddress());
		rCtrl << GetResString(IDS_ID) << _T(":\t") << buffer << _T("\r\n");
		if (Kademlia::CKademlia::GetPrefs()->GetUseExternKadPort() && Kademlia::CKademlia::GetPrefs()->GetExternalKadPort() != 0
			&& Kademlia::CKademlia::GetPrefs()->GetInternKadPort() != Kademlia::CKademlia::GetPrefs()->GetExternalKadPort())
		{
			buffer.Format(_T("%u"), Kademlia::CKademlia::GetPrefs()->GetExternalKadPort());
			rCtrl << GetResString(IDS_EXTERNUDPPORT) << _T(":\t") << buffer << _T("\r\n");
		}

		if (Kademlia::CUDPFirewallTester::IsFirewalledUDP(true)) {
			rCtrl << GetResString(IDS_BUDDY) << _T(":\t");
			switch (theApp.clientlist->GetBuddyStatus()) {
			case Disconnected:
				uid = IDS_BUDDYNONE;
				break;
			case Connecting:
				uid = IDS_CONNECTING;
				break;
			case Connected:
				uid = IDS_CONNECTED;
				break;
			default:
				uid = 0;
			}
			if (uid)
				rCtrl << GetResString(uid);
			rCtrl << _T("\r\n");
		}

		if (bFullInfo) {
			CString sKadID;
			Kademlia::CKademlia::GetPrefs()->GetKadID(sKadID);
			rCtrl << GetResString(IDS_CD_UHASH) << _T("\t") << sKadID << _T("\r\n");

			rCtrl << GetResString(IDS_UUSERS) << _T(":\t") << GetFormatedUInt(Kademlia::CKademlia::GetKademliaUsers()) << _T(" (Experimental: ") << GetFormatedUInt(Kademlia::CKademlia::GetKademliaUsers(true)) << _T(")\r\n");
			//rCtrl << GetResString(IDS_UUSERS) << _T(":\t") << GetFormatedUInt(Kademlia::CKademlia::GetKademliaUsers()) << _T("\r\n");
			rCtrl << GetResString(IDS_PW_FILES) << _T(":\t") << GetFormatedUInt(Kademlia::CKademlia::GetKademliaFiles()) << _T("\r\n");
			rCtrl << GetResString(IDS_INDEXED) << _T(":\r\n");
			buffer.Format(GetResString(IDS_KADINFO_SRC), Kademlia::CKademlia::GetIndexed()->m_uTotalIndexSource);
			rCtrl << buffer;
			buffer.Format(GetResString(IDS_KADINFO_KEYW), Kademlia::CKademlia::GetIndexed()->m_uTotalIndexKeyword);
			rCtrl << buffer;
			buffer.Format(_T("\t%s: %u\r\n"), (LPCTSTR)GetResString(IDS_NOTES), Kademlia::CKademlia::GetIndexed()->m_uTotalIndexNotes);
			rCtrl << buffer;
			buffer.Format(_T("\t%s: %u\r\n"), (LPCTSTR)GetResString(IDS_THELOAD), Kademlia::CKademlia::GetIndexed()->m_uTotalIndexLoad);
			rCtrl << buffer;
		}
	} else
		rCtrl << GetResString(Kademlia::CKademlia::IsKad2Running()
			? IDS_CONNECTING : IDS_DISCONNECTED) << _T("\r\n");

	rCtrl << _T("Kad6 ") << GetResString(IDS_STATUS) << _T(":\t")
		<< GetResString(Kademlia::CKademlia::IsKad6Connected()
			? IDS_CONNECTED
			: (Kademlia::CKademlia::IsKad6Running()
				? IDS_CONNECTING : IDS_DISCONNECTED))
		<< _T("\r\n");
	if (Kademlia::CKademlia::IsKad6Running())
		rCtrl << _T("Kad6 ") << GetResString(IDS_KADCONTACTLAB) << _T(":\t")
			<< GetFormatedUInt(Kademlia::CKademlia::GetKad6VerifiedContacts())
			<< _T("\r\n");

	rCtrl << _T("\r\n");

	///////////////////////////////////////////////////////////////////////////
	// Web Interface
	///////////////////////////////////////////////////////////////////////////
	rCtrl.SetSelectionCharFormat(rcfBold);
	rCtrl << GetResString(IDS_WEBSRV) << _T("\r\n");
	rCtrl.SetSelectionCharFormat(rcfDef);
	rCtrl << GetResString(IDS_STATUS) << _T(":\t");
	rCtrl << GetResString(thePrefs.GetWSIsEnabled() ? IDS_ENABLED : IDS_DISABLED) << _T("\r\n");
	if (thePrefs.GetWSIsEnabled()) {
		CString sTemp;
		sTemp.Format(_T("%d %s"), static_cast<int>(theApp.webserver->GetSessionCount()), (LPCTSTR)GetResString(IDS_ACTSESSIONS));
		rCtrl << _T("\t") << sTemp << _T("\r\n"); //count

		if (thePrefs.GetYourHostname().IsEmpty() || thePrefs.GetYourHostname().Find(_T('.')) < 0)
			sTemp = ipstr(theApp.serverconnect->GetLocalIP());
		else
			sTemp = thePrefs.GetYourHostname();
		rCtrl << _T("URL:\t") << (thePrefs.GetWebUseHttps() ? _T("https://") : _T("http://"));
		rCtrl << sTemp << _T(":") << thePrefs.GetWSPort() << _T("/\r\n"); //web interface host name
	}
}
