#pragma once

#include "ResizableLib/ResizableDialog.h"
#include "RichEditCtrlX.h"

// CNetworkInfoDlg dialog

class CNetworkInfoDlg : public CResizableDialog
{
	DECLARE_DYNAMIC(CNetworkInfoDlg)

	enum
	{
		IDD = IDD_NETWORK_INFO
	};

public:
	explicit CNetworkInfoDlg(CWnd *pParent = NULL);   // standard constructor
	virtual ~CNetworkInfoDlg();

protected:
	CRichEditCtrlX m_info;
	CComboBox      m_cbKadMode;  // v8.1 D6 — native privacy-mode dropdown
	CHARFORMAT     m_rcfDef;     // v0.71 P3.9 — cached for timer refresh
	CHARFORMAT     m_rcfBold;
	UINT_PTR       m_nRefreshTimer = 0;

	virtual BOOL OnInitDialog();
	virtual void DoDataExchange(CDataExchange *pDX);    // DDX/DDV support
	afx_msg void OnTimer(UINT_PTR nIDEvent);            // v0.71 P3.9 — periodic refresh
	afx_msg void OnDestroy();                           // v0.71 P3.9 — KillTimer
	afx_msg void OnKadModeChanged();                    // v8.1 D6 — dropdown -> SetDefaultMode
	afx_msg void OnCopyInfo();                          // Copies the complete report to the clipboard

	void RefreshNow();   // v0.71 P3.9 — re-render the panel, preserve scroll

	DECLARE_MESSAGE_MAP()
};

void CreateNetworkInfo(CRichEditCtrlX &rCtrl, CHARFORMAT &rcfDef, CHARFORMAT &rcfBold, bool bFullInfo = false);
