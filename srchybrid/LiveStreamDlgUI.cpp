//this file is part of eMule — eSE Live Stream Dialog (UI update methods)
//Separated from LiveStreamDlg.cpp for ~300 line limit
//Copyright (C)2024 eSE Team
#include "stdafx.h"
#include "LiveStreamDlg.h"
#include "LiveDebugLog.h"
#include "LiveStreamManager.h"
#include <deque>
#include "Statistics.h"
#include "emule.h"
#include "OtherFunctions.h"
#include "Preferences.h"
#include "ServerConnect.h"
#include "RTMPIngest.h"
#include "Kademlia/Kademlia/Kademlia.h"
#include "Kademlia/Kademlia/UDPFirewallTester.h"

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
	// UI Polish (16 May 2026):
	// A1 — LED prefix in Status text. The whole IDC_LIVE_STATUS turns green
	//      when broadcasting, red when stopped, via OnCtlColor handler.
	// A5 — Counter values (Viewers/Peers/Upload/Bitrate) get coloured by
	//      OnCtlColor based on whether they're actively non-zero.
	// A6 — When idle, status reads "\u25CF Inactivo \u00B7 pulsa START para emitir"
	//      instead of just "Status: Inactivo".
	//
	// Underlying MFC label fix still applies: every dynamic value embeds its
	// own label because CResizableDialog hides bare IDC_STATIC labels.
	// Source file encoding is UTF-8 without BOM; MFC reads literals as ANSI
	// and special chars get mangled. Use \uXXXX escapes for the LED/dot glyphs.
	if (!theApp.liveStreamManager) {
		m_staticStatus.SetWindowText(GetResString(IDS_LIVE_STATUS_UNAVAILABLE));
		m_staticViewers.SetWindowText(GetResString(IDS_LIVE_VIEWERS_IDLE));
		m_staticUptime.SetWindowText(GetResString(IDS_LIVE_UPTIME_IDLE));
		m_staticPeerVal.SetWindowText(GetResString(IDS_LIVE_PEERS_IDLE));
		m_staticUploadVal.SetWindowText(GetResString(IDS_LIVE_UPLOAD_IDLE));
		m_staticBitrateVal.SetWindowText(GetResString(IDS_LIVE_BITRATE_IDLE));
		m_progressMesh.SetPos(0);
		return;
	}

	if (m_bBroadcasting && theApp.liveStreamManager->IsBroadcasting()) {
		m_staticStatus.SetWindowText(GetResString(IDS_LIVE_STATUS_BROADCASTING));

		CString viewers;
		viewers.Format(GetResString(IDS_LIVE_VIEWERS_FMT), theApp.liveStreamManager->GetViewerCount());
		m_staticViewers.SetWindowText(viewers);

		CString upStr;
		upStr.Format(GetResString(IDS_LIVE_UPTIME_FMT),
			(LPCTSTR)FormatUptime((uint32)(time(nullptr)
				- theApp.liveStreamManager->GetBroadcastStartTime())));
		m_staticUptime.SetWindowText(upStr);

		// Peer count — from mesh manager
		auto* mgr = theApp.liveStreamManager;
		uint32 peerCount = (uint32)mgr->GetMeshManager().GetMeshPeerCount();
		CString peers;
		peers.Format(GetResString(IDS_LIVE_PEERS_FMT), peerCount);
		m_staticPeerVal.SetWindowText(peers);

		// Upload estimate — GetMinUploadRequired() returns bytes/s
		CString upload;
		upload.Format(GetResString(IDS_LIVE_UPLOAD_FMT), mgr->GetMinUploadRequired() / 1024);
		m_staticUploadVal.SetWindowText(upload);

		// Bitrate — from stream info (always available after StartBroadcast)
		CString bitrate;
		bitrate.Format(GetResString(IDS_LIVE_BITRATE_FMT), mgr->GetBroadcastBitrate());
		m_staticBitrateVal.SetWindowText(bitrate);

		// Mesh health proxy: min(peers*12, 100)
		m_progressMesh.SetPos((int)min(peerCount * 12u, 100u));
	}
	else {
		// A6 — empty state: friendlier prompt instead of bare "Inactivo".
		m_staticStatus.SetWindowText(GetResString(IDS_LIVE_STATUS_IDLE));
		m_staticViewers.SetWindowText(GetResString(IDS_LIVE_VIEWERS_IDLE));
		m_staticUptime.SetWindowText(GetResString(IDS_LIVE_UPTIME_IDLE));
		m_staticPeerVal.SetWindowText(GetResString(IDS_LIVE_PEERS_IDLE));
		m_staticUploadVal.SetWindowText(GetResString(IDS_LIVE_UPLOAD_IDLE));
		m_staticBitrateVal.SetWindowText(GetResString(IDS_LIVE_BITRATE_IDLE));
		m_progressMesh.SetPos(0);
	}

	// ── NAT Traversal Health (always-on, not gated by broadcasting) ──
	DWORD attempts = CStatistics::m_dwHolePunchAttempts;
	DWORD success  = CStatistics::m_dwHolePunchSuccess;
	DWORD symFail  = CStatistics::m_dwHolePunchSymNATFail;

	CString sAttempts, sSuccess, sSymFail, sRate;
	sAttempts.Format(GetResString(IDS_LIVE_HP_ATTEMPTS_FMT), attempts);
	sSuccess.Format(GetResString(IDS_LIVE_HP_SUCCESS_FMT), success);
	sSymFail.Format(GetResString(IDS_LIVE_HP_SYMNAT_FMT), symFail);

	if (attempts > 0)
		sRate.Format(GetResString(IDS_LIVE_HP_RATE_FMT), (double)success / (double)attempts * 100.0);
	else
		sRate = GetResString(IDS_LIVE_HP_RATE_IDLE);

	m_staticHpAttempts.SetWindowText(sAttempts);
	m_staticHpSuccess.SetWindowText(sSuccess);
	m_staticHpSymFail.SetWindowText(sSymFail);
	m_staticHpRate.SetWindowText(sRate);

	// ── Pre-flight inline (16 May 2026) ─────────────────────────────────
	// Mirrors what /api/live/preflight reports in the web dashboard so the
	// MFC user has the same situational awareness without opening a browser.
	bool kadConn = Kademlia::CKademlia::IsConnected();
	bool fwVer   = Kademlia::CUDPFirewallTester::IsVerified();
	bool kadFw   = theApp.IsFirewalled();
	bool ed2kFw  = (theApp.serverconnect && theApp.serverconnect->IsConnected()
	                && theApp.serverconnect->IsLowID());
	bool highId  = !kadFw && !ed2kFw;
	uint32 pubIP = theApp.GetPublicIP();
	CString ffPath = CRTMPIngest::FindFFmpeg();
	bool ffOk    = (GetFileAttributes(ffPath) != INVALID_FILE_ATTRIBUTES);

	auto Pf = [this](int id, bool ok, bool checking, LPCTSTR label) {
		CWnd* w = GetDlgItem(id);
		if (!w) return;
		CString s;
		CString state;
		if (ok)            state = GetResString(IDS_LIVE_PF_OK);
		else if (checking) state = _T("\u2026");
		else                state = GetResString(IDS_LIVE_PF_KO);
		s.Format(_T("%s %s: %s"), _T("\u25CF"), label, (LPCTSTR)state);
		w->SetWindowText(s);
	};
	Pf(IDC_LIVE_PF_KAD,    kadConn, false, _T("Kad"));
	Pf(IDC_LIVE_PF_HIGHID, highId,  !fwVer && kadConn, _T("HighID"));
	Pf(IDC_LIVE_PF_FFMPEG, ffOk,    false, _T("FFmpeg"));

	CWnd* ip = GetDlgItem(IDC_LIVE_PF_PUBIP);
	if (ip) {
		CString s;
		if (pubIP != 0)
			s.Format(GetResString(IDS_LIVE_IP_FMT), (LPCTSTR)ipstr(pubIP), theApp.GetAdvertisedTcpPort());
		else
			s = GetResString(IDS_LIVE_IP_DETECTING);
		ip->SetWindowText(s);
	}

	// ── Chunk buffer health ─────────────────────────────────────────────
	// The most direct evidence that the broadcast is actually flowing:
	// "Buffer: N segs \u00B7 written: K". When broadcasting properly N grows
	// from 1 → 16 (ring full) and K grows monotonically. If N stays at 1
	// while K grows, something is rejecting new segments (regression
	// detector for the uint32 underflow bug we squashed earlier).
	CWnd* chunks = GetDlgItem(IDC_LIVE_CHUNKS);
	if (chunks && theApp.liveStreamManager) {
		auto snap = theApp.liveStreamManager->BuildDebugSnapshot();
		CString s;
		if (snap.broadcasting) {
			s.Format(GetResString(IDS_LIVE_BUFFER_BC_FMT),
				snap.bufCount, snap.oldestSeq, snap.newestSeq,
				(long)snap.counters.hlsSegmentsWritten,
				(long)snap.counters.kadPublishes);
		} else if (snap.viewing) {
			s.Format(GetResString(IDS_LIVE_BUFFER_VIEW_FMT),
				snap.bufCount,
				(long)snap.counters.chunksReceived,
				(long)snap.counters.chunksMissing);
		} else {
			s = GetResString(IDS_LIVE_BUFFER_IDLE);
		}
		chunks->SetWindowText(s);
	}

	// ── Debug log tail ───────────────────────────────────────────────
	// Mirror the in-process CLiveDebugLog into the readonly EDIT control.
	// Skip the refresh entirely if no new lines have arrived since last tick
	// to avoid flicker / cursor jumps when the user is reading.
	int curCount = CLiveDebugLog::Get().GetCount();
	if (curCount != m_nLastLogCount) {
		m_nLastLogCount = curCount;
		std::deque<CStringA> lines;
		CLiveDebugLog::Get().GetRecent(120, lines);
		CStringA blob;
		for (const auto& l : lines) {
			blob += l;
			blob += "\r\n";
		}
		// CEdit is wide in this Unicode build — convert UTF-8 to wide.
		int wlen = MultiByteToWideChar(CP_UTF8, 0, blob, blob.GetLength(), NULL, 0);
		CString wblob;
		if (wlen > 0) {
			MultiByteToWideChar(CP_UTF8, 0, blob, blob.GetLength(),
				wblob.GetBuffer(wlen), wlen);
			wblob.ReleaseBuffer(wlen);
		}
		m_editDebugLog.SetWindowText(wblob);
		// Auto-scroll to the bottom
		int n = m_editDebugLog.GetWindowTextLength();
		m_editDebugLog.SetSel(n, n);
	}
}

// ========================================================
// Share panel helpers
// ========================================================

void CLiveStreamDlg::PopulateSharePanel()
{
	if (!theApp.liveStreamManager) return;

	// Phase 1 (Direct Join): build a "live" link that embeds the broadcaster's
	// public IP + listen port. Viewers paste this link in the web UI and connect
	// directly via TryConnectToStreamSource, bypassing Kad lookup. Format:
	//   ed2k://|live|HEXKEY|PUBLIC_IP:PORT|TITLE|/
	// If the public IP is unknown (LowID, Kad/UPnP not yet ready) we fall back
	// to the legacy stream link without endpoint, which still works via Kad.
	CString ed2k;
	const uchar* key = theApp.liveStreamManager->GetBroadcastStreamKey();
	if (key) {
		CString hexKey;
		for (int i = 0; i < 16; i++)
			hexKey.AppendFormat(_T("%02X"), key[i]);
		CString title;
		m_editTitle.GetWindowText(title);
		if (title.IsEmpty()) title = GetResString(IDS_LIVE_LINK_DEFAULT_TITLE);
		title.Replace(_T(" "), _T("+"));

		// 16 May 2026 — Privacy default: MFC generates the ANONYMOUS link.
		// Viewers receive `ed2k://|live|HEX||TITLE|/` (empty IP slot) and
		// discover the broadcaster via Kad. Adds ~30 s to first-frame time
		// vs the direct version, but the link itself doesn't expose the
		// broadcaster's public IP — only the streamKey.
		//
		// If the user wants the faster direct link (with IP), they can
		// generate it via the web API:
		//   GET /api/live/broadcast/start?...        → returns link with IP
		//   GET /api/live/broadcast/start?...&anon=1 → returns anonymous link
		ed2k.Format(_T("ed2k://|live|%s||%s|/"),
			(LPCTSTR)hexKey, (LPCTSTR)title);
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

	// 16 May 2026 — UNDO the hide-when-not-OBS behaviour. Hiding info is
	// confusing ("where did the URL go?"). Instead, the row stays VISIBLE
	// always; we just update the hint label below it to clarify when the
	// RTMP URL is actually meaningful (= when source is OBS).
	CWnd* hint = GetDlgItem(IDC_LIVE_LBL_RTMPHINT);
	if (hint) {
		if (src == 0) {
			hint->SetWindowText(GetResString(IDS_LIVE_HINT_OBS));
		} else {
			hint->SetWindowText(GetResString(IDS_LIVE_HINT_NOTOBS));
		}
	}

	CString url;
	if (src == 0) {
		// OBS → show local RTMP ingest URL
		// Tier 2.2: ingest now lives in the manager.
		url = (theApp.liveStreamManager && theApp.liveStreamManager->GetRTMPIngest().IsRunning())
		      ? theApp.liveStreamManager->GetRTMPIngest().GetRTMPUrl()
		      : _T("rtmp://localhost:1935/live");
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
	// Same 8 categories/order as the combo box in OnInitDialog — keep in sync.
	static const UINT ids[] = {
		IDS_LIVE_CAT_GENERAL, IDS_LIVE_CAT_SPORTS, IDS_LIVE_CAT_GAMING, IDS_LIVE_CAT_MOVIES,
		IDS_LIVE_CAT_MUSIC, IDS_LIVE_CAT_EDUCATION, IDS_LIVE_CAT_TALK, IDS_LIVE_CAT_247
	};
	if (cat < _countof(ids))
		return GetResString(ids[cat]);
	return GetResString(IDS_LIVE_CAT_OTHER);
}

void CLiveStreamDlg::JoinStream(const uchar* /*streamHash*/)
{
	// Joining via native UI — delegates to eSE web
	CString url;
	url.Format(_T("http://localhost:%u/live"), 8080);
	ShellExecute(NULL, _T("open"), url, NULL, NULL, SW_SHOWNORMAL);
}
