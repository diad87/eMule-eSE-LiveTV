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
END_MESSAGE_MAP()

CNetworkInfoDlg::CNetworkInfoDlg(CWnd *pParent /*=NULL*/)
	: CResizableDialog(CNetworkInfoDlg::IDD, pParent)
{
}

void CNetworkInfoDlg::DoDataExchange(CDataExchange *pDX)
{
	CResizableDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_NETWORK_INFO, m_info);
}

BOOL CNetworkInfoDlg::OnInitDialog()
{
	ReplaceRichEditCtrl(GetDlgItem(IDC_NETWORK_INFO), this, GetDlgItem(IDC_NETWORK_INFO_LABEL)->GetFont());
	CResizableDialog::OnInitDialog();
	InitWindowStyles(this);

	AddAnchor(IDC_NETWORK_INFO, TOP_LEFT, BOTTOM_RIGHT);
	AddAnchor(IDOK, BOTTOM_RIGHT);
	EnableSaveRestore(PREF_INI_SECTION);

	SetWindowText(GetResString(IDS_NETWORK_INFO));
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

	CreateNetworkInfo(m_info, cfDef, cfBold, true);
	DisableAutoSelect(m_info);
	return TRUE;
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
	rCtrl << _T("Conectividad\r\n");
	rCtrl.SetSelectionCharFormat(rcfDef);

	// Modo (pref del usuario). Texto con escapes \u00xx para tildes y
	// — (em-dash) porque el .cpp está en Windows-1252 sin BOM y
	// MSVC interpretaría los UTF-8 raw como mojibake (pública -> pÃºblica).
	rCtrl << _T("Modo:\t");
	switch (thePrefs.GetIPv6Mode()) {
		case CPreferences::IPv6OffMode:       rCtrl << _T("IPv4 (IPv6 desactivado)"); break;
		case CPreferences::IPv6AutoMode:      rCtrl << _T("Auto (v4 listener + v6 prober)"); break;
		case CPreferences::IPv6PreferredMode: rCtrl << _T("IPv6 preferido (dual-stack experimental)"); break;
		default:                              rCtrl << _T("?"); break;
	}
	rCtrl << _T("\r\n");

	// Estado real del listener (independiente de la pref). Auto deja el
	// listener en v4 puro (HighID estable) y solo corre el prober v6
	// para mostrar la IP pública v6. Dual-stack TCP es opt-in en modo
	// "IPv6 preferido" — ver comentario en ListenSocket::StartListening.
	rCtrl << _T("Listener:\t");
	if (theApp.listensocket && theApp.listensocket->IsDualStack()) {
		rCtrl << _T("Dual-stack ([::]:") << thePrefs.GetPort() << _T(", IPV6_V6ONLY=0)");
	} else if (thePrefs.GetIPv6Mode() == CPreferences::IPv6PreferredMode) {
		// "AF_INET6 fallo - ver log" con escapes Unicode (ó = o-acute, — = em-dash).
		rCtrl << _T("IPv4 solo (dual-stack pedido pero AF_INET6 falló — ver log)");
	} else if (thePrefs.GetIPv6Mode() == CPreferences::IPv6AutoMode) {
		rCtrl << _T("IPv4 (0.0.0.0:") << thePrefs.GetPort() << _T(") + prober v6 activo");
	} else {
		rCtrl << _T("IPv4 solo (0.0.0.0:") << thePrefs.GetPort() << _T(")");
	}
	rCtrl << _T("\r\n");

	// "IP pública v4" con escape para la "ú" (ú).
	if (theApp.GetPublicIP() != 0) {
		rCtrl << _T("IP pública v4:\t") << ipstr(theApp.GetPublicIP()) << _T("\r\n");
	}
	// "IP pública v6" + mensaje con escapes para "público", "—", "aún".
	rCtrl << _T("IP pública v6:\t");
	{
		CAddress v6 = CFirewallProberV6::Instance().GetDetectedV6IP();
		if (v6.IsNull())
			rCtrl << _T("(sin IPv6 público — ISP no provee o probe aún corriendo)");
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
	rCtrl << _T("Privacidad (eSE V1)\r\n");
	rCtrl.SetSelectionCharFormat(rcfDef);

	{
		using namespace Kademlia;
		CKadV2ModeSelector& sel = CKadV2ModeSelector::Get();

		// Modo activo (preferencia del usuario)
		rCtrl << _T("Modo:\t");
		switch (sel.GetDefaultMode()) {
			case CKadV2Mode::Direct:   rCtrl << _T("Directo (sin onion routing)"); break;
			case CKadV2Mode::Tunneled: rCtrl << _T("Tunelizado (todo a través de 2-hop onion)"); break;
			case CKadV2Mode::Adaptive: rCtrl << _T("Adaptativo (decide por consulta)"); break;
			default:                   rCtrl << _T("?"); break;
		}
		rCtrl << _T("\r\n");

		// Política de fallback si faltan relays
		rCtrl << _T("Fallback:\t");
		switch (sel.GetFallbackPolicy()) {
			case CKadV2ModeSelector::STRICT_PRIVACY: rCtrl << _T("Estricto (aborta si no hay relays)"); break;
			case CKadV2ModeSelector::BALANCED:       rCtrl << _T("Equilibrado (reduce fanout)"); break;
			case CKadV2ModeSelector::BEST_EFFORT:    rCtrl << _T("Best effort (cae a Directo y avisa)"); break;
			default:                                 rCtrl << _T("?"); break;
		}
		rCtrl << _T("\r\n");

		// Capabilities runtime — bitmap TAG_ESE_CAPS. Refleja qué módulos
		// reales se han instanciado al arranque (P0.3). 0x00000000 sería
		// señal de stack apagado.
		rCtrl << _T("Capabilities:\t");
		{
			CString cs;
			cs.Format(_T("0x%08X"), (unsigned)g_uEseCapsRuntime);
			rCtrl << cs;
			if (g_uEseCapsRuntime == 0) {
				rCtrl << _T("  (stack apagado — privacy code no inicializado)");
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
				#undef APPEND_CAP
				rCtrl << _T("]");
			}
		}
		rCtrl << _T("\r\n");

		// Circuitos onion activos (LiveTunnel). 0 con modo != Directo
		// significa que el TCP send path (F5 P3) aún no está cableado —
		// es un signo honesto al usuario.
		size_t circuits = 0;
		size_t pool = 0;
		size_t subs = 0;
		try {
			circuits = eSELive::CLiveTunnel::Get().ActiveCircuitCount();
			pool     = CKadV2TunnelPool::Get().Size();
			subs     = eSELive::CLiveSubscriptionStore::Get().Count();
		} catch (...) {}

		{
			CString cs;
			cs.Format(_T("%u activos / pool PST %u"), (unsigned)circuits, (unsigned)pool);
			rCtrl << _T("Onion tunnels:\t") << cs;
			if (circuits == 0 && sel.GetDefaultMode() != CKadV2Mode::Direct) {
				// P3 done: TCP send wired. Now the reason for 0 circuits
				// is no eSE V1 peer in handshake range. Honest disclosure
				// to the user about WHY the count is 0 without pretending
				// the protocol is broken.
				rCtrl << _T("  (esperando peer eSE V1; prueba /api/live/privacy/test_circuit)");
			}
			rCtrl << _T("\r\n");

			cs.Format(_T("%u canales (DPAPI)"), (unsigned)subs);
			rCtrl << _T("Suscripciones:\t") << cs << _T("\r\n");
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
			buffer.Format(_T("%s:%u"), (LPCTSTR)ipstr(theApp.GetED2KPublicIP()), thePrefs.GetPort());
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

	rCtrl << GetResString(IDS_STATUS) << _T(":\t");
	if (Kademlia::CKademlia::IsConnected()) {
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

		buffer.Format(_T("%s:%i"), (LPCTSTR)ipstr(htonl(Kademlia::CKademlia::GetPrefs()->GetIPAddress())), thePrefs.GetUDPPort());
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
		rCtrl << GetResString(Kademlia::CKademlia::IsRunning() ? IDS_CONNECTING : IDS_DISCONNECTED) << _T("\r\n");

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