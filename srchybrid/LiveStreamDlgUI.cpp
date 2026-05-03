//this file is part of eMule — eSE Live Stream Dialog (UI update methods)
//Separated from LiveStreamDlg.cpp for ~300 line limit
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

// ========================================================
// Timer & refresh
// ========================================================

void CLiveStreamDlg::OnTimer(UINT_PTR nIDEvent)
{
	if (nIDEvent == 1) {
		Refresh();
	}
	CResizableDialog::OnTimer(nIDEvent);
}

void CLiveStreamDlg::Refresh()
{
	UpdatePeerList();
	UpdateStatusBar();

	// Process live stream manager
	if (theApp.liveStreamManager)
		theApp.liveStreamManager->Process();
}

// ========================================================
// Peer mesh list (stub — real UI is in eSE web)
// ========================================================

void CLiveStreamDlg::UpdatePeerList()
{
	if (!theApp.liveStreamManager) {
		if (m_listPeers.GetItemCount() > 0)
			m_listPeers.DeleteAllItems();
		return;
	}
	// Peer details now shown in eSE /live P2P panel — native list is zero-size DDX only
	m_listPeers.DeleteAllItems();
}

// ========================================================
// Status bar
// ========================================================

void CLiveStreamDlg::UpdateStatusBar()
{
	if (!theApp.liveStreamManager) {
		m_staticStatus.SetWindowText(_T("Inactivo"));
		m_staticViewers.SetWindowText(_T("0"));
		m_staticUptime.SetWindowText(_T("--"));
		m_staticPeerVal.SetWindowText(_T("0"));
		m_staticUploadVal.SetWindowText(_T("0 KB/s"));
		m_staticBitrateVal.SetWindowText(_T("--"));
		m_progressMesh.SetPos(0);
		return;
	}

	if (m_bBroadcasting && theApp.liveStreamManager->IsBroadcasting()) {
		m_staticStatus.SetWindowText(_T("EMITIENDO"));

		CString viewers;
		viewers.Format(_T("%u"), theApp.liveStreamManager->GetViewerCount());
		m_staticViewers.SetWindowText(viewers);

		m_staticUptime.SetWindowText(FormatUptime(
			(uint32)(time(nullptr) - theApp.liveStreamManager->GetBroadcastStartTime())));

		// Peer count — from mesh manager
		auto* mgr = theApp.liveStreamManager;
		uint32 peerCount = (uint32)mgr->GetMeshManager().GetMeshPeerCount();
		CString peers;
		peers.Format(_T("%u"), peerCount);
		m_staticPeerVal.SetWindowText(peers);

		// Upload estimate — GetMinUploadRequired() returns bytes/s
		CString upload;
		upload.Format(_T("%u KB/s"), mgr->GetMinUploadRequired() / 1024);
		m_staticUploadVal.SetWindowText(upload);

		// Bitrate — from stream info (always available after StartBroadcast)
		CString bitrate;
		bitrate.Format(_T("%u kbps"), mgr->GetBitrate());
		m_staticBitrateVal.SetWindowText(bitrate);

		// Mesh health proxy: min(peers*12, 100)
		m_progressMesh.SetPos((int)min(peerCount * 12u, 100u));
	}
	else {
		m_staticStatus.SetWindowText(_T("Inactivo"));
		m_staticViewers.SetWindowText(_T("0"));
		m_staticUptime.SetWindowText(_T("--"));
		m_staticPeerVal.SetWindowText(_T("0"));
		m_staticUploadVal.SetWindowText(_T("0 KB/s"));
		m_staticBitrateVal.SetWindowText(_T("--"));
		m_progressMesh.SetPos(0);
	}

	// ── NAT Traversal Health (always-on, not gated by broadcasting) ──
	DWORD attempts = CStatistics::m_dwHolePunchAttempts;
	DWORD success  = CStatistics::m_dwHolePunchSuccess;
	DWORD symFail  = CStatistics::m_dwHolePunchSymNATFail;

	CString sAttempts, sSuccess, sSymFail, sRate;
	sAttempts.Format(_T("%lu"), attempts);
	sSuccess.Format(_T("%lu"), success);
	sSymFail.Format(_T("%lu"), symFail);

	if (attempts > 0)
		sRate.Format(_T("Rate: %.0f%%"), (double)success / (double)attempts * 100.0);
	else
		sRate = _T("Rate: --");

	m_staticHpAttempts.SetWindowText(sAttempts);
	m_staticHpSuccess.SetWindowText(sSuccess);
	m_staticHpSymFail.SetWindowText(sSymFail);
	m_staticHpRate.SetWindowText(sRate);
}

// ========================================================
// Share panel helpers
// ========================================================

void CLiveStreamDlg::PopulateSharePanel()
{
	if (!theApp.liveStreamManager) return;

	// ED2K link: built from stream key (16 bytes) + UI title
	CString ed2k;
	const uchar* key = theApp.liveStreamManager->GetStreamKey();
	if (key) {
		CString hexKey;
		for (int i = 0; i < 16; i++)
			hexKey.AppendFormat(_T("%02X"), key[i]);
		CString title;
		m_editTitle.GetWindowText(title);
		if (title.IsEmpty()) title = _T("Live Stream");
		title.Replace(_T(" "), _T("+"));
		ed2k.Format(_T("ed2k://|stream|%s|%s|/"), (LPCTSTR)title, (LPCTSTR)hexKey);
	}
	m_editED2KLink.SetWindowText(ed2k);
	m_editED2KLink.EnableWindow(!ed2k.IsEmpty());
	m_btnCopyED2K.EnableWindow(!ed2k.IsEmpty());

	// RTMP/HLS URL for sharing
	UpdateRTMPUrlField();
	m_btnCopyRTMP.EnableWindow(TRUE);
	m_btnOpenBrowser.EnableWindow(TRUE);
}

void CLiveStreamDlg::UpdateRTMPUrlField()
{
	int src = m_comboSource.GetCurSel();
	CString url;
	if (src == 0) {
		// OBS → show local RTMP ingest URL
		url = m_rtmpIngest.IsRunning() ? m_rtmpIngest.GetRTMPUrl() : _T("rtmp://localhost:1935/live");
	} else {
		// Other sources → show HLS URL served by Node.js
		url.Format(_T("http://localhost:8080/hls/stream.m3u8"));
	}
	m_editRTMPUrl.SetWindowText(url);
}

void CLiveStreamDlg::ClearSharePanel()
{
	m_editED2KLink.SetWindowText(_T(""));
	m_editED2KLink.EnableWindow(FALSE);
	m_editRTMPUrl.SetWindowText(_T(""));
	m_editRTMPUrl.EnableWindow(FALSE);
	m_btnCopyED2K.EnableWindow(FALSE);
	m_btnCopyRTMP.EnableWindow(FALSE);
	m_btnOpenBrowser.EnableWindow(FALSE);
}

void CLiveStreamDlg::CopyToClipboard(CEdit& editCtrl)
{
	CString text;
	editCtrl.GetWindowText(text);
	if (text.IsEmpty()) return;

	if (!OpenClipboard()) return;
	EmptyClipboard();

	// Allocate global memory and copy text
	SIZE_T len = (text.GetLength() + 1) * sizeof(TCHAR);
	HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, len);
	if (hMem) {
		LPTSTR pMem = (LPTSTR)GlobalLock(hMem);
		if (pMem) {
			_tcscpy_s(pMem, len / sizeof(TCHAR), (LPCTSTR)text);
			GlobalUnlock(hMem);
#ifdef UNICODE
			SetClipboardData(CF_UNICODETEXT, hMem);
#else
			SetClipboardData(CF_TEXT, hMem);
#endif
		}
	}
	CloseClipboard();
}

// ========================================================
// Phase 2 — Share panel button handlers
// ========================================================

void CLiveStreamDlg::OnBnClickedCopyED2K()
{
	CopyToClipboard(m_editED2KLink);
}

void CLiveStreamDlg::OnBnClickedCopyRTMP()
{
	CopyToClipboard(m_editRTMPUrl);
}

void CLiveStreamDlg::OnBnClickedOpenBrowser()
{
	CString url;
	url.Format(_T("http://localhost:8080/live"));
	ShellExecute(NULL, _T("open"), url, NULL, NULL, SW_SHOWNORMAL);
}

void CLiveStreamDlg::OnCbnSelchangeSource()
{
	UpdateRTMPUrlField();
}

// ========================================================
// Helpers
// ========================================================

CString CLiveStreamDlg::FormatUptime(uint32 seconds)
{
	CString s;
	if (seconds >= 3600)
		s.Format(_T("%uh %02um"), seconds / 3600, (seconds % 3600) / 60);
	else
		s.Format(_T("%um %02us"), seconds / 60, seconds % 60);
	return s;
}

CString CLiveStreamDlg::GetCategoryName(uint8 cat)
{
	static const LPCTSTR names[] = {
		_T("General"), _T("Deportes"), _T("Gaming"), _T("Cine"),
		_T("Música"), _T("Educación"), _T("Webcam"), _T("24/7")
	};
	if (cat < _countof(names))
		return names[cat];
	return _T("Otro");
}

void CLiveStreamDlg::JoinStream(const uchar* /*streamHash*/)
{
	// Joining via native UI — delegates to eSE web
	CString url;
	url.Format(_T("http://localhost:%u/live"), 8080);
	ShellExecute(NULL, _T("open"), url, NULL, NULL, SW_SHOWNORMAL);
}
