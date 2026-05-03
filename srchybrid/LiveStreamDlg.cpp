//this file is part of eMule — eSE Live Stream Dialog
//Copyright (C)2024 eSE Team
#include "stdafx.h"
#include "LiveStreamDlg.h"
#include "LiveStreamManager.h"
#include "Statistics.h"
#include "emule.h"
#include "OtherFunctions.h"

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
}

BOOL CLiveStreamDlg::OnInitDialog()
{
	CResizableDialog::OnInitDialog();

	// Title placeholder
	m_editTitle.SendMessage(EM_SETCUEBANNER, TRUE, (LPARAM)_T("Enter your stream title here..."));

	// Source combo
	m_comboSource.AddString(_T("OBS Studio (RTMP)"));
	m_comboSource.AddString(_T("Media File (FFmpeg)"));
	m_comboSource.AddString(_T("Screen Capture (FFmpeg)"));
	m_comboSource.AddString(_T("Test Pattern"));
	m_comboSource.SetCurSel(0);

	// Category combo
	m_comboCategory.AddString(_T("General"));
	m_comboCategory.AddString(_T("Sports"));
	m_comboCategory.AddString(_T("Gaming"));
	m_comboCategory.AddString(_T("Movies"));
	m_comboCategory.AddString(_T("Music"));
	m_comboCategory.AddString(_T("Education"));
	m_comboCategory.AddString(_T("Talk"));
	m_comboCategory.AddString(_T("24/7"));
	m_comboCategory.SetCurSel(0);

	// Language combo
	m_comboLanguage.AddString(_T("English"));
	m_comboLanguage.AddString(_T("Spanish"));
	m_comboLanguage.AddString(_T("French"));
	m_comboLanguage.AddString(_T("German"));
	m_comboLanguage.AddString(_T("Portuguese"));
	m_comboLanguage.SetCurSel(0);

	// Bitrate combo
	m_comboBitrate.AddString(_T("1500 kbps (SD)"));
	m_comboBitrate.AddString(_T("3000 kbps (HD)"));
	m_comboBitrate.AddString(_T("5000 kbps (FHD)"));
	m_comboBitrate.AddString(_T("8000 kbps (4K)"));
	m_comboBitrate.SetCurSel(1);

	// Progress bar range
	m_progressMesh.SetRange(0, 100);
	m_progressMesh.SetPos(0);

	// ── Resizable anchors ───────────────────────────────────────────
	// Broadcast config
	AddAnchor(IDC_LIVE_TITLE,         TOP_LEFT, TOP_RIGHT);
	AddAnchor(IDC_LIVE_SOURCE,        TOP_LEFT);
	AddAnchor(IDC_LIVE_BITRATE,       TOP_LEFT);
	AddAnchor(IDC_LIVE_CATEGORY,      TOP_LEFT);
	AddAnchor(IDC_LIVE_LANGUAGE,      TOP_LEFT);
	AddAnchor(IDC_LIVE_STARTSTOP,     TOP_LEFT, TOP_RIGHT);
	// Stream Status
	AddAnchor(IDC_LIVE_STATUS,        TOP_LEFT);
	AddAnchor(IDC_LIVE_VIEWERS,       TOP_LEFT);
	AddAnchor(IDC_LIVE_UPTIME,        TOP_LEFT);
	AddAnchor(IDC_LIVE_MESHPROG,      TOP_LEFT, TOP_RIGHT);
	AddAnchor(IDC_LIVE_PEER_VAL,      TOP_LEFT);
	AddAnchor(IDC_LIVE_UPLOAD_VAL,    TOP_LEFT);
	AddAnchor(IDC_LIVE_BITRATE_VAL,   TOP_LEFT);
	// Share panel
	AddAnchor(IDC_LIVE_ED2KLINK,      TOP_LEFT, TOP_RIGHT);
	AddAnchor(IDC_LIVE_COPY_ED2K,     TOP_RIGHT);
	AddAnchor(IDC_LIVE_RTMPURL,       TOP_LEFT, TOP_RIGHT);
	AddAnchor(IDC_LIVE_COPY_RTMP,     TOP_RIGHT);
	AddAnchor(IDC_LIVE_OPENBROWSER,   TOP_RIGHT);
	// NAT Health
	AddAnchor(IDC_LIVE_HP_ATTEMPTS,   TOP_LEFT);
	AddAnchor(IDC_LIVE_HP_SUCCESS,    TOP_LEFT);
	AddAnchor(IDC_LIVE_HP_SYMNATFAIL, TOP_LEFT);
	AddAnchor(IDC_LIVE_HP_RATE,       TOP_LEFT);

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
		title = _T("My Stream");

	uint8 category = (uint8)m_comboCategory.GetCurSel();

	// Pack language as uint16 (ISO 639-1): en, es, fr, de, pt
	static const uint16 langCodes[] = { 0x656E, 0x6573, 0x6672, 0x6465, 0x7074 };
	uint16 language = langCodes[min(m_comboLanguage.GetCurSel(), 4)];

	static const uint32 bitrates[] = { 1500, 3000, 5000, 8000 };
	uint32 bitrate = bitrates[min(m_comboBitrate.GetCurSel(), 3)];

	// Register broadcast in P2P layer first
	CString catStr, langStr;
	m_comboCategory.GetLBText(m_comboCategory.GetCurSel(), catStr);
	m_comboLanguage.GetLBText(m_comboLanguage.GetCurSel(), langStr);
	if (!mgr->StartBroadcast(title, catStr, langStr, (uint16)bitrate)) {
		AfxMessageBox(_T("Failed to start P2P broadcast"), MB_ICONERROR);
		return;
	}

	// If source is "OBS Studio", "Media File", "Screen Capture", or "Test Pattern", start FFmpeg
	int sourceIdx = m_comboSource.GetCurSel();
	if (sourceIdx >= 0 && sourceIdx <= 3) {
		// Create temp dir for HLS segments
		CString tempDir;
		TCHAR tmpPath[MAX_PATH];
		GetTempPath(MAX_PATH, tmpPath);
		tempDir.Format(_T("%seMule_RTMP"), tmpPath);

		auto chunkCb = [](const BYTE* data, DWORD size, UINT /*seq*/) {
			if (theApp.liveStreamManager) theApp.liveStreamManager->FeedSegment(data, size);
		};

		bool started = false;
		if (sourceIdx == 0) {
			// OBS Studio (RTMP) — listen for incoming RTMP stream
			started = m_rtmpIngest.Start(1935, bitrate, tempDir, chunkCb);
		} else if (sourceIdx == 1) {
			// Media File — pick a video file and broadcast it in a loop
			CFileDialog dlg(TRUE, NULL, NULL, OFN_FILEMUSTEXIST | OFN_HIDEREADONLY,
				_T("Video Files (*.mkv;*.mp4;*.avi;*.ts;*.flv;*.wmv)|*.mkv;*.mp4;*.avi;*.ts;*.flv;*.wmv|All Files (*.*)|*.*||"),
				this);
			if (dlg.DoModal() != IDOK) {
				mgr->StopBroadcast();
				return;
			}
			started = m_rtmpIngest.StartMediaFile(dlg.GetPathName(), bitrate, tempDir, chunkCb);
		} else if (sourceIdx == 2) {
			// Screen Capture — capture desktop via FFmpeg gdigrab
			started = m_rtmpIngest.StartScreenCapture(bitrate, tempDir, chunkCb);
		} else {
			// Test Pattern — generate color bars with FFmpeg
			started = m_rtmpIngest.StartTestPattern(bitrate, tempDir, chunkCb);
		}

		if (!started) {
			mgr->StopBroadcast();
			AfxMessageBox(
				_T("Failed to start FFmpeg.\n\n")
				_T("Make sure ffmpeg.exe is installed and in your PATH\n")
				_T("or in the same folder as emule.exe."),
				MB_ICONERROR);
			return;
		}

		// Show status
		CString statusMsg;
		if (sourceIdx == 0) {
			statusMsg.Format(_T("Status: Waiting for OBS on %s"),
				(LPCTSTR)m_rtmpIngest.GetRTMPUrl());
		} else if (sourceIdx == 1) {
			statusMsg = _T("Status: Broadcasting Media File (looping)");
		} else if (sourceIdx == 2) {
			statusMsg = _T("Status: Broadcasting Screen Capture");
		} else {
			statusMsg = _T("Status: Broadcasting Test Pattern");
		}
		m_staticStatus.SetWindowText(statusMsg);
	}

	m_bBroadcasting = true;
	m_btnStartStop.SetWindowText(_T("STOP BROADCAST"));
	m_btnStartStop.Invalidate();   // force OnCtlColor repaint → red
	PopulateSharePanel();           // fill ed2k link + RTMP URL
	UpdateStatusBar();
}

void CLiveStreamDlg::StopBroadcast()
{
	// Stop RTMP ingest first
	if (m_rtmpIngest.IsRunning())
		m_rtmpIngest.Stop();

	if (theApp.liveStreamManager) theApp.liveStreamManager->StopBroadcast();
	m_bBroadcasting = false;
	m_btnStartStop.SetWindowText(_T("START BROADCAST"));
	m_btnStartStop.Invalidate();   // force OnCtlColor repaint → green
	ClearSharePanel();              // disable + reset share fields
	UpdateStatusBar();
}

// ──────────────────────────────────────────────────────────────────────────
// OnCtlColor — dynamic START (green) / STOP (red) button color
// ──────────────────────────────────────────────────────────────────────────
HBRUSH CLiveStreamDlg::OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor)
{
	HBRUSH hbr = CResizableDialog::OnCtlColor(pDC, pWnd, nCtlColor);
	if (nCtlColor == CTLCOLOR_BTN && pWnd->GetDlgCtrlID() == IDC_LIVE_STARTSTOP) {
		pDC->SetTextColor(RGB(255, 255, 255));
		pDC->SetBkMode(TRANSPARENT);
		return m_bBroadcasting ? (HBRUSH)m_brStop : (HBRUSH)m_brStart;
	}
	return hbr;
}
