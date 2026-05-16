// demo3View.cpp : implementation of the CDemo3View class
//

#include "stdafx.h"
#include "demo3.h"

#include "MainFrm.h"
#include "demo3Doc.h"
#include "demo3View.h"
#include "memdc.h"

#include "ximage.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CDemo3View

IMPLEMENT_DYNCREATE(CDemo3View, CScrollView)

BEGIN_MESSAGE_MAP(CDemo3View, CScrollView)
	//{{AFX_MSG_MAP(CDemo3View)
	ON_WM_ERASEBKGND()
	//}}AFX_MSG_MAP
	// Standard printing commands
	ON_COMMAND(ID_FILE_PRINT, CScrollView::OnFilePrint)
	ON_COMMAND(ID_FILE_PRINT_DIRECT, CScrollView::OnFilePrint)
	ON_COMMAND(ID_FILE_PRINT_PREVIEW, CScrollView::OnFilePrintPreview)
	ON_MESSAGE(WM_USER_NEWIMAGE, OnNewImage)
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CDemo3View construction/destruction

CDemo3View::CDemo3View()
{
	SetScrollSizes(MM_TEXT, CSize(0, 0));
   VERIFY(m_brHatch.CreateHatchBrush(HS_DIAGCROSS, RGB(191, 191, 191)));
}

CDemo3View::~CDemo3View()
{
}

BOOL CDemo3View::PreCreateWindow(CREATESTRUCT& cs)
{
	return CScrollView::PreCreateWindow(cs);
}

/////////////////////////////////////////////////////////////////////////////
// CDemo3View drawing

void CDemo3View::OnDraw(CDC* pDC)
{
	CDemo3Doc* pDoc = GetDocument();
	ASSERT_VALID(pDoc);

	BOOL bPrinting = pDC->IsPrinting();

	CMemDC* pMemDC = NULL;
	if (!bPrinting) pDC = pMemDC = new CMemDC(pDC);

	if (!bPrinting && m_brHatch.m_hObject){
		CRect rect;
		GetClientRect(&rect);
		rect.right  = max(rect.right , m_totalDev.cx);
		rect.bottom = max(rect.bottom, m_totalDev.cy);
		m_brHatch.UnrealizeObject();
		CPoint pt(0, 0);
		pDC->LPtoDP(&pt);
		pt = pDC->SetBrushOrg(pt.x % 8, pt.y % 8);
		CBrush* old = pDC->SelectObject(&m_brHatch);
		pDC->FillRect(&rect, &m_brHatch);
		pDC->SelectObject(old);
	}

	CxImage* ima = pDoc->GetImage(); 
	if (ima) {
		if (bPrinting) {
			// get size of printer page (in pixels)
			int cxPage = pDC->GetDeviceCaps(HORZRES);
			int cyPage = pDC->GetDeviceCaps(VERTRES);
			// get printer pixels per inch
			int cxInch = pDC->GetDeviceCaps(LOGPIXELSX);
			int cyInch = pDC->GetDeviceCaps(LOGPIXELSY);
			// Best Fit case: create a rectangle which preserves the aspect ratio
			int cx=(ima->GetWidth()*cxInch)/ima->GetXDPI();
			int cy=(ima->GetHeight()*cyInch)/ima->GetYDPI();
			// print it!
			CxImage tmp;
			tmp.Copy(*ima);
			RGBQUAD c={255,255,255,0};
			tmp.SetTransColor(c);
			tmp.AlphaStrip();
			tmp.Stretch(pDC->GetSafeHdc(), CRect(100,100,cx,cy));
		}
		else
		{
			ima->Draw(pDC->GetSafeHdc());
		}
	}

	delete pMemDC;
}
//////////////////////////////////////////////////////////////////////////////
BOOL CDemo3View::OnEraseBkgnd(CDC* pDC) 
{
	return 1;
}
/////////////////////////////////////////////////////////////////////////////
// CDemo3View printing

BOOL CDemo3View::OnPreparePrinting(CPrintInfo* pInfo)
{
	// default preparation
	pInfo->SetMaxPage(1);
	return DoPreparePrinting(pInfo);
}

void CDemo3View::OnBeginPrinting(CDC* /*pDC*/, CPrintInfo* /*pInfo*/)
{
}

void CDemo3View::OnEndPrinting(CDC* /*pDC*/, CPrintInfo* /*pInfo*/)
{
}

/////////////////////////////////////////////////////////////////////////////
// CDemo3View diagnostics

#ifdef _DEBUG
void CDemo3View::AssertValid() const
{
	CScrollView::AssertValid();
}

void CDemo3View::Dump(CDumpContext& dc) const
{
	CScrollView::Dump(dc);
}

CDemo3Doc* CDemo3View::GetDocument() // non-debug version is inline
{
	ASSERT(m_pDocument->IsKindOf(RUNTIME_CLASS(CDemo3Doc)));
	return (CDemo3Doc*)m_pDocument;
}
#endif //_DEBUG

/////////////////////////////////////////////////////////////////////////////
// CDemo3View message handlers
//////////////////////////////////////////////////////////////////////////////
void CDemo3View::OnUpdate(CView* pSender, LPARAM lHint, CObject* pHint) 
{
	switch (lHint)
	{
	case WM_USER_NEWIMAGE:
		{
			CDemo3Doc* pDoc = GetDocument();
			CxImage*  ima  = pDoc->GetImage();
			if (ima) {
				int px=GetScrollPos(SB_HORZ);
				int py=GetScrollPos(SB_VERT);
				CSize sz(GetTotalSize());
				int x=(int)(ima->GetWidth());
				int y=(int)(ima->GetHeight());
				SetScrollSizes(MM_TEXT,	CSize(x,y));
				CSize sz2(GetTotalSize());

				CWnd* pFrame=GetParentFrame();
				RECT rClient;
				pFrame->GetClientRect(&rClient);

				if (sz.cx!=0 && sz.cy!=0){
					if (x>rClient.right) SetScrollPos(SB_HORZ,sz2.cx*px/sz.cx); else  SetScrollPos(SB_HORZ,0);
					if (y>rClient.bottom) SetScrollPos(SB_VERT,sz2.cy*py/sz.cy); else SetScrollPos(SB_VERT,0);
				}

				if (!(pFrame->IsIconic()||pFrame->IsZoomed())){
					RECT rMainCl,rFrame,rMainFr;
					((CMainFrame *)(AfxGetApp()->m_pMainWnd))->GetClientRect(&rMainCl);
					((CMainFrame *)(AfxGetApp()->m_pMainWnd))->GetWindowRect(&rMainFr);
					pFrame->GetWindowRect(&rFrame);
					pFrame->SetWindowPos(0,0,0,
						(4+rFrame.right-rFrame.left-rClient.right+rClient.left)+
						min(rMainCl.right-(rFrame.left-rMainFr.left+12),x),
						(4+rFrame.bottom-rFrame.top-rClient.bottom+rClient.top)+
						min(rMainCl.bottom-(rFrame.top-rMainFr.top+12),y),
						SWP_NOMOVE|SWP_NOZORDER);
					//ResizeParentToFit(1);
				}
			}

			break;
		}
	default:
		{
			CDemo3Doc* pDoc = GetDocument();
			if (pDoc){
				CxImage*  ima  = pDoc->GetImage();
				if (ima){
					SetScrollSizes(MM_TEXT,CSize((int)(ima->GetWidth()),(int)(ima->GetHeight())));
				}
			}
		}
	}
	CScrollView::OnUpdate(pSender, lHint, pHint);
}
//////////////////////////////////////////////////////////////////////////////
LRESULT CDemo3View::OnNewImage(WPARAM wParam, LPARAM lParam)
{
	CDemo3Doc* pDoc = GetDocument();
	pDoc->UpdateAllViews(0,WM_USER_NEWIMAGE);
	return 0;
}
//////////////////////////////////////////////////////////////////////////////
