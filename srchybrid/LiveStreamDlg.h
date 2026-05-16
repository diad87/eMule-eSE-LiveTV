//this file is part of eMule — eSE Live Stream Dialog
//Copyright (C)2024 eSE Team
#pragma once

#include "LiveStreamManager.h"
#include "Resource.h"
#include "ResizableLib\ResizableDialog.h"
// RTMPIngest now lives inside CLiveStreamManager (Tier 2.2). The dialog
// reaches it via theApp.liveStreamManager->GetRTMPIngest().

// MFC Dialog for live streaming control in eMule's main window
// Integrates as a tab in the Transfer window
class CLiveStreamDlg : public CResizableDialog
{
public:
	CLiveStreamDlg(CWnd* pParent = nullptr);
	virtual ~CLiveStreamDlg();

	enum { IDD = IDD_LIVESTREAM };

	// Update UI from timer
	void Refresh();

	// Start/stop broadcasting from UI
	void StartBroadcast();
	void StopBroadcast();

	// Join a stream from directory
	void JoinStream(const uchar* streamHash);

protected:
	virtual void DoDataExchange(CDataExchange* pDX);
	virtual BOOL OnInitDialog();

	afx_msg void OnBnClickedStartStop();
	afx_msg void OnTimer(UINT_PTR nIDEvent);
	// Phase 2 — Share panel + dynamic button color
	afx_msg void OnBnClickedCopyED2K();
	afx_msg void OnBnClickedCopyRTMP();
	afx_msg void OnBnClickedOpenBrowser();
	afx_msg void OnCbnSelchangeSource();
	afx_msg HBRUSH OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor);

	DECLARE_MESSAGE_MAP()

private:
	// ── Broadcast config ──────────────────────────────────────────
	CEdit			m_editTitle;
	CComboBox		m_comboSource;
	CComboBox		m_comboBitrate;
	CComboBox		m_comboCategory;
	CComboBox		m_comboLanguage;
	CButton			m_btnStartStop;

	// ── Stream Status ───────────────────────────────────────────────
	CStatic			m_staticStatus;
	CStatic			m_staticViewers;
	CStatic			m_staticUptime;
	CProgressCtrl	m_progressMesh;
	CStatic			m_staticPeerVal;     // IDC_LIVE_PEER_VAL
	CStatic			m_staticUploadVal;   // IDC_LIVE_UPLOAD_VAL
	CStatic			m_staticBitrateVal;  // IDC_LIVE_BITRATE_VAL

	// ── Share panel ─────────────────────────────────────────────────
	CEdit			m_editED2KLink;      // IDC_LIVE_ED2KLINK (readonly)
	CEdit			m_editRTMPUrl;       // IDC_LIVE_RTMPURL  (readonly)
	CButton			m_btnCopyED2K;       // IDC_LIVE_COPY_ED2K
	CButton			m_btnCopyRTMP;       // IDC_LIVE_COPY_RTMP
	CButton			m_btnOpenBrowser;    // IDC_LIVE_OPENBROWSER

	// ── Dynamic button colors ────────────────────────────────────────
	CBrush			m_brStart;           // verde para START
	CBrush			m_brStop;            // rojo  para STOP

	// ── NAT Traversal Health panel ───────────────────────────────────
	CStatic			m_staticHpAttempts;  // IDC_LIVE_HP_ATTEMPTS
	CStatic			m_staticHpSuccess;   // IDC_LIVE_HP_SUCCESS
	CStatic			m_staticHpSymFail;   // IDC_LIVE_HP_SYMNATFAIL
	CStatic			m_staticHpRate;      // IDC_LIVE_HP_RATE

	// ── Hidden DDX (zero-size) ───────────────────────────────────────
	CListCtrl		m_listPeers;         // IDC_LIVE_PEERS — DDX only, size 0

	// ── Debug log panel ──────────────────────────────────────────────
	// Read-only multi-line edit at the bottom of the dialog. Mirrors
	// /api/live/log. Refreshed every timer tick from CLiveDebugLog::GetRecent().
	CEdit			m_editDebugLog;      // IDC_LIVE_DEBUGLOG
	int				m_nLastLogCount;     // last GetCount() seen — skip refresh if unchanged

	// State
	bool			m_bBroadcasting;
	UINT_PTR		m_nTimerID;
	// (CRTMPIngest moved to CLiveStreamManager — Tier 2.2)

	// ── Internal helpers ────────────────────────────────────────────
	void UpdatePeerList();
	void UpdateStatusBar();
	void PopulateSharePanel();    // fills ed2k + RTMP fields after StartBroadcast
	void UpdateRTMPUrlField();    // shows/hides RTMP URL based on source combo
	void ClearSharePanel();       // resets + disables share fields on StopBroadcast
	void CopyToClipboard(CEdit& editCtrl); // generic clipboard helper
	CString FormatUptime(uint32 seconds);
	CString GetCategoryName(uint8 cat);
};
