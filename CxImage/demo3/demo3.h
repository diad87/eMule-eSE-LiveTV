// demo3.h : main header file for the DEMO3 application
//

#if !defined(AFX_DEMO3_H__E6F819C7_257C_42E0_BC77_16E12A78D58A__INCLUDED_)
#define AFX_DEMO3_H__E6F819C7_257C_42E0_BC77_16E12A78D58A__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#ifndef __AFXWIN_H__
	#error include 'stdafx.h' before including this file for PCH
#endif

#include "resource.h"       // main symbols

/////////////////////////////////////////////////////////////////////////////
// CDemo3App:
// See demo3.cpp for the implementation of this class
//

class CDemo3App : public CWinApp
{
public:
	CDemo3App();

	CMultiDocTemplate *demoTemplate;

// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CDemo3App)
	public:
	virtual BOOL InitInstance();
	//}}AFX_VIRTUAL

	BOOL PromptForFileName(CString& fileName, UINT nIDSTitle, 
		DWORD dwFlags, BOOL bOpenFileDialog, int* pType=NULL);
	int GetIndexFromType(int nDocType, BOOL bOpenFileDialog);
	int GetTypeFromIndex(int nIndex, BOOL bOpenFileDialog);
	CString GetExtFromType(int nDocType);
	CString GetDescFromType(int nDocType);
	CString GetFileTypes(BOOL bOpenFileDialog);
	BOOL GetWritableType(int nDocType);

	// Implementation
	//{{AFX_MSG(CDemo3App)
	afx_msg void OnAppAbout();
	afx_msg void OnFileOpen();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

extern CDemo3App theApp;

struct DocType
{
public:
	int nID;
	BOOL bRead;
	BOOL bWrite;
	const char* description;
	const char* ext;
};

/////////////////////////////////////////////////////////////////////////////

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_DEMO3_H__E6F819C7_257C_42E0_BC77_16E12A78D58A__INCLUDED_)
