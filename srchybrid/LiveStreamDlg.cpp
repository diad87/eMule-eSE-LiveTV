//this file is part of eMule — eSE Live Stream Dialog
//Copyright (C)2024 eSE Team
#include "stdafx.h"
#include "LiveStreamDlg.h"
#include "LiveDebugLog.h"
#include "LiveStreamManager.h"
#include "Statistics.h"
#include "emule.h"
#include "OtherFunctions.h"
#include "Preferences.h"
#include "ServerConnect.h"
#include "Kademlia/Kademlia/UDPFirewallTester.h"
#include <deque>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif


BEGIN_MESSAGE_MAP(CLiveStreamDlg, CResizableDialog)
	ON_BN_CLICKED(IDC_LIVE_STARTSTOP,    OnBnClickedStartStop)
	ON_BN_CLICKED(IDC_LIVE_COPY_ED2K,    OnBnClickedCopyED2K)
	ON_BN_CLICKED(IDC_LIVE_COPY_RTMP,    OnBnClickedCopyRTMP)
	ON_BN_CLICKED(IDC_LIVE_OPENBROWSER,  OnBnClickedOpenBrowser)
	ON_CBN_SELCHANGE(IDC_LIVE_SOURCE,    OnCbnSelchangeSource)
	ON_WM_TIMER()
	ON_WM_CTLCOLOR()
END_MESSAGE_MAP()

CLiveStreamDlg::CLiveStreamDlg(CWnd* pParent)
	: CResizableDialog(CLiveStreamDlg::IDD, pParent)
	, m_bBroadcasting(false)
	, m_nTimerID(0)
	, m_nLastLogCount(-1)
{
	// Init brushes here — CreateSolidBrush is safe before any window
	m_brStart.CreateSolidBrush(RGB(0, 120, 0));    // verde oscuro para START
	m_brStop.CreateSolidBrush(RGB(180, 0, 0));     // rojo oscuro para STOP
}

CLiveStreamDlg::~CLiveStreamDlg()
{
	if (m_nTimerID)
		KillTimer(m_nTimerID);
}

void CLiveStreamDlg::DoDataExchange(CDataExchange* pDX)
{
	CResizableDialog::DoDataExchange(pDX);
	// ── Broadcast config ──────────────────────────────────────────
	DDX_Control(pDX, IDC_LIVE_TITLE,      m_editTitle);
	DDX_Control(pDX, IDC_LIVE_SOURCE,     m_comboSource);
	DDX_Control(pDX, IDC_LIVE_BITRATE,    m_comboBitrate);
	DDX_Control(pDX, IDC_LIVE_CATEGORY,   m_comboCategory);
	DDX_Control(pDX, IDC_LIVE_LANGUAGE,   m_comboLanguage);
	DDX_Control(pDX, IDC_LIVE_STARTSTOP,  m_btnStartStop);
	// ── Stream Status ─────────────────────────────────────────────
	DDX_Control(pDX, IDC_LIVE_STATUS,     m_staticStatus);
	DDX_Control(pDX, IDC_LIVE_VIEWERS,    m_staticViewers);
	DDX_Control(pDX, IDC_LIVE_UPTIME,     m_staticUptime);
	DDX_Control(pDX, IDC_LIVE_MESHPROG,   m_progressMesh);
	DDX_Control(pDX, IDC_LIVE_PEER_VAL,   m_staticPeerVal);
	DDX_Control(pDX, IDC_LIVE_UPLOAD_VAL, m_staticUploadVal);
	DDX_Control(pDX, IDC_LIVE_BITRATE_VAL,m_staticBitrateVal);
	// ── Share panel ───────────────────────────────────────────────
	DDX_Control(pDX, IDC_LIVE_ED2KLINK,   m_editED2KLink);
	DDX_Control(pDX, IDC_LIVE_RTMPURL,    m_editRTMPUrl);
	DDX_Control(pDX, IDC_LIVE_COPY_ED2K,  m_btnCopyED2K);
	DDX_Control(pDX, IDC_LIVE_COPY_RTMP,  m_btnCopyRTMP);
	DDX_Control(pDX, IDC_LIVE_OPENBROWSER,m_btnOpenBrowser);
	// ── NAT Traversal Health ─────────────────────────────────────
	DDX_Control(pDX, IDC_LIVE_HP_ATTEMPTS,  m_staticHpAttempts);
	DDX_Control(pDX, IDC_LIVE_HP_SUCCESS,   m_staticHpSuccess);
	DDX_Control(pDX, IDC_LIVE_HP_SYMNATFAIL,m_staticHpSymFail);
	DDX_Control(pDX, IDC_LIVE_HP_RATE,      m_staticHpRate);
	// ── Hidden DDX (zero-size peer list) ─────────────────────────
	DDX_Control(pDX, IDC_LIVE_PEERS,      m_listPeers);
	// ── Debug log ────────────────────────────────────────────────
	DDX_Control(pDX, IDC_LIVE_DEBUGLOG,   m_editDebugLog);
}

BOOL CLiveStreamDlg::OnInitDialog()
{
	CResizableDialog::OnInitDialog();

	// Title placeholder
	m_editTitle.SendMessage(EM_SETCUEBANNER, TRUE, (LPARAM)(LPCTSTR)GetResString(IDS_LIVE_TITLE_PLACEHOLDER));

	// Source combo
	m_comboSource.AddString(GetResString(IDS_LIVE_SRC_OBS));
	m_comboSource.AddString(GetResString(IDS_LIVE_SRC_FILE));
	m_comboSource.AddString(GetResString(IDS_LIVE_SRC_SCREEN));
	m_comboSource.AddString(GetResString(IDS_LIVE_SRC_TESTPATTERN));
	m_comboSource.SetCurSel(0);

	// Category combo
	m_comboCategory.AddString(GetResString(IDS_LIVE_CAT_GENERAL));
	m_comboCategory.AddString(GetResString(IDS_LIVE_CAT_SPORTS));
	m_comboCategory.AddString(GetResString(IDS_LIVE_CAT_GAMING));
	m_comboCategory.AddString(GetResString(IDS_LIVE_CAT_MOVIES));
	m_comboCategory.AddString(GetResString(IDS_LIVE_CAT_MUSIC));
	m_comboCategory.AddString(GetResString(IDS_LIVE_CAT_EDUCATION));
	m_comboCategory.AddString(GetResString(IDS_LIVE_CAT_TALK));
	m_comboCategory.AddString(GetResString(IDS_LIVE_CAT_247));
	m_comboCategory.SetCurSel(0);

	// Language combo
	m_comboLanguage.AddString(GetResString(IDS_LIVE_LANG_EN));
	m_comboLanguage.AddString(GetResString(IDS_LIVE_LANG_ES));
	m_comboLanguage.AddString(GetResString(IDS_LIVE_LANG_FR));
	m_comboLanguage.AddString(GetResString(IDS_LIVE_LANG_DE));
	m_comboLanguage.AddString(GetResString(IDS_LIVE_LANG_PT));
	m_comboLanguage.SetCurSel(0);

	// Bitrate combo — v7.3.0: 6 tiers including a real 4K option and a
	// low-bitrate 360p option for slow uploads. The previous "8000 kbps
	// (4K)" label was misleading: ffmpeg only encoded up to 1080p so
	// selecting it just wasted bits. Now index 5 is truly 4K (3840×2160).
	m_comboBitrate.AddString(GetResString(IDS_LIVE_BR_360P));
	m_comboBitrate.AddString(GetResString(IDS_LIVE_BR_540P));
	m_comboBitrate.AddString(GetResString(IDS_LIVE_BR_720P));
	m_comboBitrate.AddString(GetResString(IDS_LIVE_BR_1080P));
	m_comboBitrate.AddString(GetResString(IDS_LIVE_BR_1080P_HIGH));
	m_comboBitrate.AddString(GetResString(IDS_LIVE_BR_4K));
	// Default to 720p HD — equilibrio razonable. Quien tenga upload <2 Mbps
	// debería bajar a 360p o 540p manualmente. v7.3.0 idealmente añadiría
	// un pre-flight que sugiera el tier según la subida medida.
	m_comboBitrate.SetCurSel(2);

	// Progress bar range
	m_progressMesh.SetRange(0, 100);
	m_progressMesh.SetPos(0);

	// ── Resizable anchors ───────────────────────────────────────────
	// CResizableDialog HIDES any control that is not explicitly anchored.
	// This was the real cause of the "missing labels" — they had IDs in
	// the .rc but no AddAnchor here, so CResizableDialog dropped them on
	// every resize. We now anchor EVERY control declared in IDD_LIVESTREAM.

	// Pre-flight bar (top)
	AddAnchor(IDC_LIVE_GRP_PREFLIGHT, TOP_LEFT, TOP_RIGHT);
	AddAnchor(IDC_LIVE_PF_KAD,        TOP_LEFT);
	AddAnchor(IDC_LIVE_PF_HIGHID,     TOP_LEFT);
	AddAnchor(IDC_LIVE_PF_FFMPEG,     TOP_LEFT);
	AddAnchor(IDC_LIVE_PF_PUBIP,      TOP_LEFT, TOP_RIGHT);

	// Your Broadcast group + its labels
	AddAnchor(IDC_LIVE_GRP_BROADCAST, TOP_LEFT, TOP_RIGHT);
	AddAnchor(IDC_LIVE_LBL_TITLE,     TOP_LEFT);
	AddAnchor(IDC_LIVE_TITLE,         TOP_LEFT, TOP_RIGHT);
	AddAnchor(IDC_LIVE_LBL_SOURCE,    TOP_LEFT);
	AddAnchor(IDC_LIVE_SOURCE,        TOP_LEFT);
	AddAnchor(IDC_LIVE_LBL_QUALITY,   TOP_LEFT);
	AddAnchor(IDC_LIVE_BITRATE,       TOP_LEFT);
	AddAnchor(IDC_LIVE_LBL_CATEGORY,  TOP_LEFT);
	AddAnchor(IDC_LIVE_CATEGORY,      TOP_LEFT);
	AddAnchor(IDC_LIVE_LBL_LANGUAGE,  TOP_LEFT);
	AddAnchor(IDC_LIVE_LANGUAGE,      TOP_LEFT);
	AddAnchor(IDC_LIVE_STARTSTOP,     TOP_LEFT, TOP_RIGHT);

	// Stream Status group + labels + values
	AddAnchor(IDC_LIVE_GRP_STATUS,    TOP_LEFT, TOP_RIGHT);
	AddAnchor(IDC_LIVE_STATUS,        TOP_LEFT);
	AddAnchor(IDC_LIVE_VIEWERS,       TOP_LEFT);
	AddAnchor(IDC_LIVE_UPTIME,        TOP_LEFT);
	AddAnchor(IDC_LIVE_LBL_NETHEALTH, TOP_LEFT);
	AddAnchor(IDC_LIVE_MESHPROG,      TOP_LEFT, TOP_RIGHT);
	AddAnchor(IDC_LIVE_PEER_VAL,      TOP_LEFT);
	AddAnchor(IDC_LIVE_UPLOAD_VAL,    TOP_LEFT);
	AddAnchor(IDC_LIVE_BITRATE_VAL,   TOP_LEFT);
	AddAnchor(IDC_LIVE_CHUNKS,        TOP_LEFT, TOP_RIGHT);

	// Share Your Stream group + labels + values
	AddAnchor(IDC_LIVE_GRP_SHARE,     TOP_LEFT, TOP_RIGHT);
	AddAnchor(IDC_LIVE_LBL_ED2K,      TOP_LEFT);
	AddAnchor(IDC_LIVE_ED2KLINK,      TOP_LEFT, TOP_RIGHT);
	AddAnchor(IDC_LIVE_COPY_ED2K,     TOP_RIGHT);
	AddAnchor(IDC_LIVE_LBL_RTMP,      TOP_LEFT);
	AddAnchor(IDC_LIVE_RTMPURL,       TOP_LEFT, TOP_RIGHT);
	AddAnchor(IDC_LIVE_COPY_RTMP,     TOP_RIGHT);
	AddAnchor(IDC_LIVE_LBL_RTMPHINT,  TOP_LEFT);
	AddAnchor(IDC_LIVE_OPENBROWSER,   TOP_RIGHT);

	// NAT Traversal Health group + values
	AddAnchor(IDC_LIVE_GRP_NAT,       TOP_LEFT, TOP_RIGHT);
	AddAnchor(IDC_LIVE_HP_ATTEMPTS,   TOP_LEFT);
	AddAnchor(IDC_LIVE_HP_SUCCESS,    TOP_LEFT);
	AddAnchor(IDC_LIVE_HP_SYMNATFAIL, TOP_LEFT);
	AddAnchor(IDC_LIVE_HP_RATE,       TOP_LEFT);

	// Debug log group + edit (stretches with dialog)
	AddAnchor(IDC_LIVE_GRP_DEBUGLOG,  TOP_LEFT, BOTTOM_RIGHT);
	AddAnchor(IDC_LIVE_DEBUGLOG,      TOP_LEFT, BOTTOM_RIGHT);

	// Set fixed-pitch font on the log so the timestamps line up
	HFONT hFont = (HFONT)GetStockObject(ANSI_FIXED_FONT);
	if (hFont) m_editDebugLog.SetFont(CFont::FromHandle(hFont));

	// ── Share panel initial state (disabled until broadcasting) ─────
	m_editED2KLink.SetWindowText(_T(""));
	m_editED2KLink.EnableWindow(FALSE);
	m_editRTMPUrl.SetWindowText(_T(""));
	m_editRTMPUrl.EnableWindow(FALSE);
	m_btnCopyED2K.EnableWindow(FALSE);
	m_btnCopyRTMP.EnableWindow(FALSE);
	m_btnOpenBrowser.EnableWindow(FALSE);

	// Show RTMP URL hint when OBS is selected (default source)
	UpdateRTMPUrlField();

	// Start refresh timer (2 seconds)
	m_nTimerID = SetTimer(1, 2000, nullptr);

	UpdateStatusBar();

	return TRUE;
}

void CLiveStreamDlg::OnBnClickedStartStop()
{
	if (!theApp.liveStreamManager) return;
	auto* mgr = theApp.liveStreamManager;

	if (m_bBroadcasting) {
		StopBroadcast();
	}
	else {
		StartBroadcast();
	}
}

void CLiveStreamDlg::StartBroadcast()
{
	if (!theApp.liveStreamManager) return;
	auto* mgr = theApp.liveStreamManager;

	CString title;
	m_editTitle.GetWindowText(title);
	if (title.IsEmpty())
		title = GetResString(IDS_LIVE_DEFAULT_TITLE);

	uint8 category = (uint8)m_comboCategory.GetCurSel();

	// Pack language as uint16 (ISO 639-1): en, es, fr, de, pt
	static const uint16 langCodes[] = { 0x656E, 0x6573, 0x6672, 0x6465, 0x7074 };
	uint16 language = langCodes[min(m_comboLanguage.GetCurSel(), 4)];

	// v7.3.0 — 6 quality tiers covering 360p (slow upload / 4G) up to 4K.
	// Index 0: 800   kbps = 360p   (subida ~1 Mbps, 4G, ADSL slow)
	// Index 1: 1500  kbps = 540p   (subida ~2 Mbps, ADSL típico)
	// Index 2: 3000  kbps = 720p   (subida ~4 Mbps, fibra básica)
	// Index 3: 5000  kbps = 1080p  (subida ~6 Mbps, fibra estándar)
	// Index 4: 8000  kbps = 1080p+ (subida ~10 Mbps)
	// Index 5: 12000 kbps = 4K     (subida ~15 Mbps, NVENC required)
	// RTMPIngest maps these to ABR variant 0/1/2/3/3/4 respectively.
	static const uint32 bitrates[] = { 800, 1500, 3000, 5000, 8000, 12000 };
	uint32 bitrate = bitrates[min(m_comboBitrate.GetCurSel(), 5)];

	// Phase 3.5 ROB-LowID: warn the user before they start broadcasting if
	// their TCP port is REALLY closed. We only fire this warning when the Kad
	// firewall test has COMPLETED and reports firewalled. If the test is still
	// running (typical for the first ~60 s after launch), we suppress the
	// warning — false positives at startup were annoying and misleading.
	{
		bool fwVerified = Kademlia::CUDPFirewallTester::IsVerified();
		bool kadFw  = theApp.IsFirewalled();
		bool lowId  = (theApp.serverconnect && theApp.serverconnect->IsConnected()
		               && theApp.serverconnect->IsLowID());
		// Only consider Kad firewall status if the test actually finished.
		bool reallyFirewalled = (fwVerified && kadFw) || lowId;
		if (reallyFirewalled) {
			CString warn;
			warn.Format(GetResString(IDS_LIVE_WARN_PORT_CLOSED),
				theApp.GetAdvertisedTcpPort(), theApp.GetAdvertisedTcpPort());
			if (AfxMessageBox(warn, MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2) != IDYES)
				return;
		}
		// If !fwVerified we just proceed silently — the user can check the
		// pre-flight in the web dashboard which has the proper "Comprobando NAT…"
		// state instead of a false-positive popup.
	}

	// Tier 2.2: delegate to the unified launcher in CLiveStreamManager.
	// The dialog only collects UI inputs and shows the result; all the
	// FFmpeg/Kad/PRE-WARM logic lives in the manager and is shared with
	// the web API endpoint /api/live/broadcast/start.
	int sourceIdx = m_comboSource.GetCurSel();
	CString chosenFile;
	CString sourceType;
	if (sourceIdx == 0)      sourceType = _T("rtmp");
	else if (sourceIdx == 1) sourceType = _T("file");
	else if (sourceIdx == 2) sourceType = _T("screen");
	else                     sourceType = _T("testpattern");

	if (sourceIdx == 1) {
		CFileDialog fdlg(TRUE, NULL, NULL, OFN_FILEMUSTEXIST | OFN_HIDEREADONLY,
			GetResString(IDS_LIVE_FILEDLG_FILTER),
			this);
		if (fdlg.DoModal() != IDOK)
			return;
		chosenFile = fdlg.GetPathName();
	}

	CString catStr, langStr;
	m_comboCategory.GetLBText(m_comboCategory.GetCurSel(), catStr);
	m_comboLanguage.GetLBText(m_comboLanguage.GetCurSel(), langStr);

	if (!mgr->StartBroadcastWithSource(sourceType, title, catStr, langStr,
	                                   (uint16)bitrate, chosenFile))
	{
		// Surface the real reason from the debug log instead of the
		// generic "verifica ffmpeg / puerto / log" text. The user
		// already has the log on screen, but seeing the immediate cause
		// in the popup avoids the round-trip.
		std::deque<CStringA> tail;
		CLiveDebugLog::Get().GetRecent(15, tail);
		CString detail;
		for (const auto& l : tail) {
			if (l.Find("[RTMP]") < 0
			    && l.Find("[FFMPEG]") < 0
			    && l.Find("[MGR]") < 0) continue;
			CString w(l);
			detail += w + _T("\r\n");
		}
		if (detail.IsEmpty())
			detail = GetResString(IDS_LIVE_LOG_EMPTY);

		CString msg;
		msg.Format(GetResString(IDS_LIVE_ERR_START_FAILED), (LPCTSTR)detail);
		AfxMessageBox(msg, MB_ICONERROR);
		return;
	}

	// Show source-specific status string.
	CString statusMsg;
	if (sourceIdx == 0) {
		statusMsg.Format(GetResString(IDS_LIVE_STATUS_WAITING_OBS),
			(LPCTSTR)mgr->GetRTMPIngest().GetRTMPUrl());
	} else if (sourceIdx == 1) {
		statusMsg = GetResString(IDS_LIVE_STATUS_BC_FILE);
	} else if (sourceIdx == 2) {
		statusMsg = GetResString(IDS_LIVE_STATUS_BC_SCREEN);
	} else {
		statusMsg = GetResString(IDS_LIVE_STATUS_BC_TESTPATTERN);
	}
	m_staticStatus.SetWindowText(statusMsg);

	m_bBroadcasting = true;
	m_btnStartStop.SetWindowText(GetResString(IDS_LIVE_BTN_STOP));
	m_btnStartStop.Invalidate();
	PopulateSharePanel();
	UpdateStatusBar();
}

void CLiveStreamDlg::StopBroadcast()
{
	if (theApp.liveStreamManager)
		theApp.liveStreamManager->StopBroadcastFull();
	m_bBroadcasting = false;
	m_btnStartStop.SetWindowText(GetResString(IDS_LIVE_BTN_START));
	m_btnStartStop.Invalidate();
	ClearSharePanel();
	UpdateStatusBar();
}

// ──────────────────────────────────────────────────────────────────────────
// OnCtlColor — dynamic colours for status text + counter values + button
// ──────────────────────────────────────────────────────────────────────────
HBRUSH CLiveStreamDlg::OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor)
{
	HBRUSH hbr = CResizableDialog::OnCtlColor(pDC, pWnd, nCtlColor);

	// START/STOP button — coloured background, white text (existing behaviour)
	if (nCtlColor == CTLCOLOR_BTN && pWnd->GetDlgCtrlID() == IDC_LIVE_STARTSTOP) {
		pDC->SetTextColor(RGB(255, 255, 255));
		pDC->SetBkMode(TRANSPARENT);
		return m_bBroadcasting ? (HBRUSH)m_brStop : (HBRUSH)m_brStart;
	}

	// A1 + A5 — coloured static text for status indicator + counter values.
	// Only override when the control is a static. Returns null brush so the
	// dialog default background paints behind the text.
	if (nCtlColor == CTLCOLOR_STATIC) {
		switch (pWnd->GetDlgCtrlID()) {
		case IDC_LIVE_STATUS:
			// LED prefix is part of the text. Green when broadcasting, dim red
			// otherwise. CResizableDialog erased the IDC_STATIC labels, but
			// IDC_LIVE_* controls still get our colour.
			pDC->SetTextColor(m_bBroadcasting ? RGB(46, 204, 113) : RGB(180, 80, 80));
			pDC->SetBkMode(TRANSPARENT);
			return hbr;
		case IDC_LIVE_VIEWERS:
		case IDC_LIVE_PEER_VAL:
			// Green when > 0, neutral grey when 0 (active/inactive cue).
			{
				CString t; pWnd->GetWindowText(t);
				bool active = m_bBroadcasting && t.Find(_T(": 0")) < 0;
				pDC->SetTextColor(active ? RGB(46, 204, 113) : RGB(160, 160, 160));
				pDC->SetBkMode(TRANSPARENT);
			}
			return hbr;
		case IDC_LIVE_UPTIME:
		case IDC_LIVE_UPLOAD_VAL:
		case IDC_LIVE_BITRATE_VAL:
			// White-ish when broadcasting (relevant), grey when idle.
			pDC->SetTextColor(m_bBroadcasting ? RGB(220, 220, 220) : RGB(140, 140, 140));
			pDC->SetBkMode(TRANSPARENT);
			return hbr;
		case IDC_LIVE_HP_SUCCESS:
			// Green when we have any successful hole-punch
			{
				CString t; pWnd->GetWindowText(t);
				pDC->SetTextColor(t.Find(_T(": 0")) < 0
					? RGB(46, 204, 113) : RGB(160, 160, 160));
				pDC->SetBkMode(TRANSPARENT);
			}
			return hbr;
		case IDC_LIVE_HP_SYMNATFAIL:
			// Yellow/orange when symmetric NAT detected (warn user)
			{
				CString t; pWnd->GetWindowText(t);
				pDC->SetTextColor(t.Find(_T(": 0")) < 0
					? RGB(243, 156, 18) : RGB(160, 160, 160));
				pDC->SetBkMode(TRANSPARENT);
			}
			return hbr;
		}
	}
	return hbr;
}
