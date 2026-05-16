// demo3Doc.h : interface of the CDemo3Doc class
//
/////////////////////////////////////////////////////////////////////////////

#if !defined(AFX_DEMO3DOC_H__4E9F84DE_DACD_4618_ADA6_BC099C4874DE__INCLUDED_)
#define AFX_DEMO3DOC_H__4E9F84DE_DACD_4618_ADA6_BC099C4874DE__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#define	WM_USER_NEWIMAGE WM_USER+1

class CxImage;

class CDemo3Doc : public CDocument
{
protected: // create from serialization only
	CDemo3Doc();
	DECLARE_DYNCREATE(CDemo3Doc)

// Attributes
public:

// Operations
public:
	inline CxImage *GetImage() { return image; }
	CString FindExtension(const CString& name);
	int FindType(const CString& ext);

// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CDemo3Doc)
	public:
	virtual BOOL OnNewDocument();
	virtual void Serialize(CArchive& ar);
	virtual BOOL OnOpenDocument(LPCTSTR lpszPathName);
	virtual BOOL OnSaveDocument(LPCTSTR lpszPathName);
	virtual BOOL DoSave(LPCTSTR pszPathName, BOOL bReplace =TRUE);
	//}}AFX_VIRTUAL

// Implementation
public:
	CxImage* image;
	virtual ~CDemo3Doc();
#ifdef _DEBUG
	virtual void AssertValid() const;
	virtual void Dump(CDumpContext& dc) const;
#endif

protected:

// Generated message map functions
protected:
	//{{AFX_MSG(CDemo3Doc)
	afx_msg void OnEditCopy();
	afx_msg void OnEditDither();
	afx_msg void OnEditFlip();
	afx_msg void OnEditGrayscale();
	afx_msg void OnEditMirror();
	afx_msg void OnEditNegative();
	afx_msg void OnEditSharpen();
	afx_msg void OnEditSoften();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

/////////////////////////////////////////////////////////////////////////////

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_DEMO3DOC_H__4E9F84DE_DACD_4618_ADA6_BC099C4874DE__INCLUDED_)
