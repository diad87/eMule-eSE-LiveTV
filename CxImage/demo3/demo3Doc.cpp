// demo3Doc.cpp : implementation of the CDemo3Doc class
//

#include "stdafx.h"
#include "demo3.h"

#include "demo3Doc.h"

#include "ximage.h"
#include "xfile.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CDemo3Doc

IMPLEMENT_DYNCREATE(CDemo3Doc, CDocument)

BEGIN_MESSAGE_MAP(CDemo3Doc, CDocument)
	//{{AFX_MSG_MAP(CDemo3Doc)
	ON_COMMAND(ID_EDIT_COPY, OnEditCopy)
	ON_COMMAND(ID_EDIT_DITHER, OnEditDither)
	ON_COMMAND(ID_EDIT_FLIP, OnEditFlip)
	ON_COMMAND(ID_EDIT_GRAYSCALE, OnEditGrayscale)
	ON_COMMAND(ID_EDIT_MIRROR, OnEditMirror)
	ON_COMMAND(ID_EDIT_NEGATIVE, OnEditNegative)
	ON_COMMAND(ID_EDIT_SHARPEN, OnEditSharpen)
	ON_COMMAND(ID_EDIT_SOFTEN, OnEditSoften)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CDemo3Doc construction/destruction

CDemo3Doc::CDemo3Doc()
{
	image=0;
}

CDemo3Doc::~CDemo3Doc()
{
	if (image) delete image;
}

BOOL CDemo3Doc::OnNewDocument()
{
	if (!CDocument::OnNewDocument())
		return FALSE;

	return TRUE;
}



/////////////////////////////////////////////////////////////////////////////
// CDemo3Doc serialization

void CDemo3Doc::Serialize(CArchive& ar)
{
	if (ar.IsStoring())
	{
	}
	else
	{
	}
}

/////////////////////////////////////////////////////////////////////////////
// CDemo3Doc diagnostics

#ifdef _DEBUG
void CDemo3Doc::AssertValid() const
{
	CDocument::AssertValid();
}

void CDemo3Doc::Dump(CDumpContext& dc) const
{
	CDocument::Dump(dc);
}
#endif //_DEBUG

/////////////////////////////////////////////////////////////////////////////
// CDemo3Doc commands
CString CDemo3Doc::FindExtension(const CString& name)
{
	int len = name.GetLength();
	int i;
	for (i = len-1; i >= 0; i--){
		if (name[i] == '.'){
			return name.Mid(i+1);
		}
	}
	return CString("");
}
//////////////////////////////////////////////////////////////////////////////
int CDemo3Doc::FindType(const CString& ext)
{
	int type = 0;
	if (ext == "bmp")					type = CXIMAGE_FORMAT_BMP;
#if CXIMAGE_SUPPORT_JPG
	else if (ext=="jpg"||ext=="jpeg")	type = CXIMAGE_FORMAT_JPG;
#endif
#if CXIMAGE_SUPPORT_GIF
	else if (ext == "gif")				type = CXIMAGE_FORMAT_GIF;
#endif
#if CXIMAGE_SUPPORT_PNG
	else if (ext == "png")				type = CXIMAGE_FORMAT_PNG;
#endif
#if CXIMAGE_SUPPORT_MNG
	else if (ext=="mng"||ext=="jng")	type = CXIMAGE_FORMAT_MNG;
#endif
#if CXIMAGE_SUPPORT_ICO
	else if (ext == "ico")				type = CXIMAGE_FORMAT_ICO;
#endif
#if CXIMAGE_SUPPORT_TIF
	else if (ext=="tiff"||ext=="tif")	type = CXIMAGE_FORMAT_TIF;
#endif
#if CXIMAGE_SUPPORT_TGA
	else if (ext=="tga")				type = CXIMAGE_FORMAT_TGA;
#endif
#if CXIMAGE_SUPPORT_PCX
	else if (ext=="pcx")				type = CXIMAGE_FORMAT_PCX;
#endif
#if CXIMAGE_SUPPORT_WBMP
	else if (ext=="wbmp")				type = CXIMAGE_FORMAT_WBMP;
#endif
#if CXIMAGE_SUPPORT_WMF
	else if (ext=="wmf"||ext=="emf")	type = CXIMAGE_FORMAT_WMF;
#endif
#if CXIMAGE_SUPPORT_J2K
	else if (ext=="j2k"||ext=="jp2")	type = CXIMAGE_FORMAT_J2K;
#endif
#if CXIMAGE_SUPPORT_JBG
	else if (ext=="jbg")				type = CXIMAGE_FORMAT_JBG;
#endif
#if CXIMAGE_SUPPORT_JP2
	else if (ext=="jp2"||ext=="j2k")	type = CXIMAGE_FORMAT_JP2;
#endif
#if CXIMAGE_SUPPORT_JPC
	else if (ext=="jpc"||ext=="j2c")	type = CXIMAGE_FORMAT_JPC;
#endif
#if CXIMAGE_SUPPORT_PGX
	else if (ext=="pgx")				type = CXIMAGE_FORMAT_PGX;
#endif
#if CXIMAGE_SUPPORT_RAS
	else if (ext=="ras")				type = CXIMAGE_FORMAT_RAS;
#endif
#if CXIMAGE_SUPPORT_PNM
	else if (ext=="pnm"||ext=="pgm"||ext=="ppm") type = CXIMAGE_FORMAT_PNM;
#endif
	else type = CXIMAGE_FORMAT_UNKNOWN;

	return type;
}
//////////////////////////////////////////////////////////////////////////////
BOOL CDemo3Doc::OnOpenDocument(LPCTSTR lpszPathName) 
{
	CString filename(lpszPathName);
	CString ext(FindExtension(filename));
	ext.MakeLower();
	if (ext == "") return FALSE;

	int type = FindType(ext);

	image = new CxImage(filename, type);

	if (!image->IsValid()){
		CString s = image->GetLastError();
		AfxMessageBox(s);
		delete image;
		image = NULL;
		return FALSE;
	}

	UpdateAllViews(NULL,WM_USER_NEWIMAGE);

	//multiple images (TIFF/ICO)
	if (image->GetNumFrames()>1){
		CString s;
		s.Format(_T("File with %d images. Read all?"),image->GetNumFrames());
		if (AfxMessageBox(s,MB_OKCANCEL)==IDOK){
			
			int j; // points to the document name
			for(j=filename.GetLength()-1;j>=0;j--){
				if (filename[j]=='\\'){	j++; break;	}
			}
			// create the documents for the other images
			for(int i=1;i<image->GetNumFrames();i++){
				CDemo3Doc *NewDoc=(CDemo3Doc*)((CDemo3App*)AfxGetApp())->demoTemplate->OpenDocumentFile(NULL);
				if (NewDoc)	{
					CxImage *newImage = new CxImage();
					newImage->SetFrame(i);
					newImage->Load(filename,type);
					NewDoc->image = newImage;
					CString s;
					s.Format(_T("%s (%d)"),filename.Mid(j),i+1);
					NewDoc->SetTitle(s);
					NewDoc->UpdateAllViews(NULL,WM_USER_NEWIMAGE);
				}
			}
		}
	}

	return TRUE;
}
//////////////////////////////////////////////////////////////////////////////
BOOL CDemo3Doc::OnSaveDocument(LPCTSTR lpszPathName) 
{
	CString filename(lpszPathName);
	CString ext(FindExtension(filename));
	ext.MakeLower();
	if (ext == "") return FALSE;

	int type = FindType(ext);
	if (type == CXIMAGE_FORMAT_UNKNOWN) return FALSE;

	bool retval;
	retval = image->Save(filename, type);
	if (retval) return TRUE;
	CString s = image->GetLastError();
	AfxMessageBox(s);

	return FALSE;
}
//////////////////////////////////////////////////////////////////////////////
BOOL CDemo3Doc::DoSave(LPCTSTR pszPathName, BOOL bReplace /*=TRUE*/)
{
	if (!image)	return FALSE;

	CString newName = pszPathName;
	BOOL bModified = IsModified();

	BOOL bSaveAs = FALSE;
	if (newName.IsEmpty()) bSaveAs = TRUE;
	else if (!theApp.GetWritableType(image->GetType()))	bSaveAs = TRUE;

	if (bSaveAs){
		newName = m_strPathName;
		if (bReplace && newName.IsEmpty()){
			newName = m_strTitle;
			int iBad = newName.FindOneOf(_T("#%;/\\"));    // dubious filename
			if (iBad != -1)	//newName.ReleaseBuffer(iBad);
				newName = "UntitledImage";

			// append the default suffix if there is one
			if (image->GetType()) newName += theApp.GetExtFromType(image->GetType()).Mid(1,4);
		}

		int nDocType = image->GetType();
		if (!theApp.PromptForFileName(newName, 
			bReplace ? AFX_IDS_SAVEFILE : AFX_IDS_SAVEFILECOPY,
			OFN_HIDEREADONLY | OFN_PATHMUSTEXIST, FALSE, &nDocType))
		{
			return FALSE;       // don't even try to save
		}
	}

	BeginWaitCursor();
	if (!OnSaveDocument(newName)){
		if (pszPathName == NULL){
			// be sure to delete the file
			TRY 
			{
				CFile::Remove(newName);
			}
			CATCH_ALL(e)
			{
				TRACE0("Warning: failed to delete file after failed SaveAs\n");
			}
			END_CATCH_ALL
		}
		EndWaitCursor();
		return FALSE;
	}

	EndWaitCursor();
	if (bReplace) {
		// Reset the title and change the document name
		SetPathName(newName, TRUE);
		ASSERT(m_strPathName == newName); // must be set
	}
	else // SaveCopyAs
	{
		SetModifiedFlag(bModified);
	}
	return TRUE;        // success
}

void CDemo3Doc::OnEditCopy() 
{
	if (image==0) return;
	if (!image->IsValid()) return;

	HANDLE hDIB=image->CopyToHandle();

	if (::OpenClipboard(AfxGetApp()->m_pMainWnd->GetSafeHwnd())) {
		if(::EmptyClipboard()) {
			if (::SetClipboardData(CF_DIB,hDIB) == NULL ) {
				AfxMessageBox(_T("Unable to set Clipboard data"));
			}
		}
	}
	CloseClipboard();
	
}

void CDemo3Doc::OnEditDither() 
{
	if (image==0) return;
	if (!image->IsValid()) return;

	image->Dither();
	UpdateAllViews(NULL);
}

void CDemo3Doc::OnEditFlip() 
{
	if (image==0) return;
	if (!image->IsValid()) return;

	image->Flip();	
	UpdateAllViews(NULL);
}

void CDemo3Doc::OnEditGrayscale() 
{
	if (image==0) return;
	if (!image->IsValid()) return;

	image->GrayScale();	
	UpdateAllViews(NULL);
}

void CDemo3Doc::OnEditMirror() 
{
	if (image==0) return;
	if (!image->IsValid()) return;

	image->Mirror();	
	UpdateAllViews(NULL);
}

void CDemo3Doc::OnEditNegative() 
{
	if (image==0) return;
	if (!image->IsValid()) return;

	image->Negative();	
	UpdateAllViews(NULL);
}

void CDemo3Doc::OnEditSharpen() 
{
	if (image==0) return;
	if (!image->IsValid()) return;

	int kernel[]={-1,-1,-1,-1,15,-1,-1,-1,-1};
	image->Filter(kernel,3,7,0);
	UpdateAllViews(NULL);
}

void CDemo3Doc::OnEditSoften() 
{
	if (image==0) return;
	if (!image->IsValid()) return;
	
	int kernel[]={1,1,1,1,8,1,1,1,1};
	image->Filter(kernel,3,16,0);
	UpdateAllViews(NULL);
}
