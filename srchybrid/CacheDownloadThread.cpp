//this file is part of eMule
//Copyright (C)2024 Merkur ( strEmail.Format("%s@%s", "devteam", "emule-project.net") / https://www.emule-project.net )
//
//This program is free software; you can redistribute it and/or
//modify it under the terms of the GNU General Public License
//as published by the Free Software Foundation; either
//version 2 of the License, or (at your option) any later version.
//
//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License
//along with this program; if not, write to the Free Software
//Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#include "StdAfx.h"
#include <winhttp.h>
#include "CacheDownloadThread.h"
#include "emule.h"
#include "PartFile.h"
#include "Opcodes.h"
#include "log.h"
#include "preferences.h"
#include "otherfunctions.h"
#include "MD4.h"

#pragma comment(lib, "winhttp.lib")

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

IMPLEMENT_DYNCREATE(CCacheDownloadThread, CWinThread)

CCacheDownloadThread::CCacheDownloadThread()
	: m_pNodeList(NULL)
	, m_eventThreadEnded(FALSE, TRUE)
	, m_eventNewRequest(FALSE, FALSE)
	, m_bRunning(false)
	, m_nActiveDownloads(0)
	, m_uTotalBytesDownloaded(0)
{
	AfxBeginThread(RunProc, (LPVOID)this, THREAD_PRIORITY_BELOW_NORMAL);
}

CCacheDownloadThread::~CCacheDownloadThread()
{
	ASSERT(!m_bRunning);
}

UINT AFX_CDECL CCacheDownloadThread::RunProc(LPVOID pParam)
{
	DbgSetThreadName("CacheDownloadThread");
	InitThreadLocale();
	return pParam ? static_cast<CCacheDownloadThread*>(pParam)->RunInternal() : 1;
}

void CCacheDownloadThread::EndThread()
{
	m_bRunning = false;
	m_eventNewRequest.SetEvent(); // wake up the thread so it can exit
	m_eventThreadEnded.Lock();
}

UINT CCacheDownloadThread::RunInternal()
{
	m_bRunning = true;
	AddLogLine(false, _T("Cache download thread started"));

	while (m_bRunning) {
		// Wait for new requests or thread termination
		::WaitForSingleObject(m_eventNewRequest, 5000); // wake up every 5s or on signal

		if (!m_bRunning)
			break;

		// Process pending requests one at a time
		while (m_bRunning) {
			CacheChunkRequest request;
			bool bHaveRequest = false;
			{
				CSingleLock lock(&m_csRequests, TRUE);
				if (!m_listRequests.IsEmpty()) {
					request = m_listRequests.RemoveHead();
					bHaveRequest = true;
				}
			}

			if (!bHaveRequest)
				break;

			InterlockedIncrement((LONG*)&m_nActiveDownloads);
			CacheChunkResult *pResult = ProcessRequest(request);
			InterlockedDecrement((LONG*)&m_nActiveDownloads);

			if (pResult) {
				CSingleLock lock(&m_csResults, TRUE);
				m_listResults.AddTail(pResult);
			}
		}
	}

	m_bRunning = false;
	AddLogLine(false, _T("Cache download thread stopped"));
	m_eventThreadEnded.SetEvent();
	return 0;
}

bool CCacheDownloadThread::RequestChunk(const CacheChunkRequest &request)
{
	if (!m_bRunning || m_pNodeList == NULL)
		return false;

	CSingleLock lock(&m_csRequests, TRUE);
	CacheChunkRequest req = request;
	req.dwRequestTime = ::GetTickCount();
	m_listRequests.AddTail(req);

	m_eventNewRequest.SetEvent(); // wake up the thread
	return true;
}

int CCacheDownloadThread::GetResults(CArray<CacheChunkResult*> &raResults)
{
	CSingleLock lock(&m_csResults, TRUE);
	int nCount = 0;
	while (!m_listResults.IsEmpty()) {
		raResults.Add(m_listResults.RemoveHead());
		++nCount;
	}
	return nCount;
}

void CCacheDownloadThread::CancelFile(CPartFile *pFile)
{
	CSingleLock lock(&m_csRequests, TRUE);
	for (POSITION pos = m_listRequests.GetHeadPosition(); pos != NULL;) {
		POSITION posCur = pos;
		const CacheChunkRequest &req = m_listRequests.GetNext(pos);
		if (req.pFile == pFile)
			m_listRequests.RemoveAt(posCur);
	}
}

uint32 CCacheDownloadThread::GetPendingRequests() const
{
	return (uint32)const_cast<CCacheDownloadThread*>(this)->m_listRequests.GetCount();
}

CString CCacheDownloadThread::HashToHexString(const uchar *pHash)
{
	CString s;
	for (int i = 0; i < 16; ++i) {
		CString t;
		t.Format(_T("%02X"), pHash[i]);
		s += t;
	}
	return s;
}

CacheChunkResult* CCacheDownloadThread::ProcessRequest(const CacheChunkRequest &request)
{
	if (m_pNodeList == NULL)
		return NULL;

	CacheChunkResult *pResult = new CacheChunkResult;
	pResult->request = request;
	pResult->eResult = CDR_NO_NODES;

	// Get healthy nodes sorted by speed
	CArray<CacheNode*> aNodes;
	m_pNodeList->GetHealthyNodes(aNodes);

	if (aNodes.GetCount() == 0) {
		return pResult;
	}

	CString strHash = HashToHexString(request.abyFileHash);

	// Try each node until we succeed
	for (INT_PTR i = 0; i < aNodes.GetCount() && m_bRunning; ++i) {
		CacheNode *pNode = aNodes[i];

		// Build URL: {base_url}/{hash}
		CString strURL = pNode->GetFileURL(strHash);

		BYTE *pData = NULL;
		uint32 dwDataSize = 0;
		DWORD dwHttpStatus = 0;
		DWORD dwElapsedMs = 0;

		ECacheDownloadResult eRes = DownloadFromURL(
			strURL,
			request.uStart,
			request.uEnd - 1, // Range header is inclusive
			&pData,
			&dwDataSize,
			&dwHttpStatus,
			&dwElapsedMs);

		if (eRes == CDR_SUCCESS && pData != NULL && dwDataSize > 0) {
			// Verify data size matches expected
			uint32 dwExpected = (uint32)(request.uEnd - request.uStart);
			if (dwDataSize == dwExpected) {
				pResult->eResult = CDR_SUCCESS;
				pResult->pData = pData;
				pResult->dwDataSize = dwDataSize;
				pResult->dwDownloadMs = dwElapsedMs;
				pResult->strNodeURL = pNode->strURL;
				pResult->dwHttpStatus = dwHttpStatus;

				// Update node stats
				m_pNodeList->OnNodeSuccess(pNode->strURL, dwElapsedMs);

				// Update total bytes counter
				InterlockedExchange64((LONG64*)&m_uTotalBytesDownloaded,
					m_uTotalBytesDownloaded + dwDataSize);

				AddLogLine(false, _T("Cache: Downloaded %s part %u (%s) from %s in %lums"),
					(LPCTSTR)strHash, request.nPart,
					(LPCTSTR)CastItoXBytes(dwDataSize),
					(LPCTSTR)pNode->strURL, dwElapsedMs);

				return pResult;
			}
			delete[] pData;
			pData = NULL;
		} else {
			delete[] pData;
		}

		// This node failed, try next
		if (dwHttpStatus == 404)
			m_pNodeList->OnNodeFailure(pNode->strURL, 404);
		else if (eRes == CDR_NETWORK_ERROR)
			m_pNodeList->OnNodeFailure(pNode->strURL, dwHttpStatus);

		pResult->eResult = (dwHttpStatus == 404) ? CDR_NOT_FOUND : CDR_NETWORK_ERROR;
	}

	return pResult;
}

ECacheDownloadResult CCacheDownloadThread::DownloadFromURL(
	const CString &strURL,
	uint64 uRangeStart,
	uint64 uRangeEnd,
	BYTE **ppOutData,
	uint32 *pdwOutSize,
	DWORD *pdwHttpStatus,
	DWORD *pdwElapsedMs)
{
	*ppOutData = NULL;
	*pdwOutSize = 0;
	*pdwHttpStatus = 0;
	*pdwElapsedMs = 0;

	DWORD dwStartTick = ::GetTickCount();

	// Parse the URL into components
	URL_COMPONENTS urlComp;
	memset(&urlComp, 0, sizeof urlComp);
	urlComp.dwStructSize = sizeof urlComp;
	urlComp.dwSchemeLength = (DWORD)-1;
	urlComp.dwHostNameLength = (DWORD)-1;
	urlComp.dwUrlPathLength = (DWORD)-1;
	urlComp.dwExtraInfoLength = (DWORD)-1;

	CStringW strURLW(strURL);
	if (!WinHttpCrackUrl(strURLW, (DWORD)strURLW.GetLength(), 0, &urlComp))
		return CDR_NETWORK_ERROR;

	CStringW strHostName(urlComp.lpszHostName, urlComp.dwHostNameLength);
	CStringW strUrlPath(urlComp.lpszUrlPath, urlComp.dwUrlPathLength);
	bool bSecure = (urlComp.nScheme == INTERNET_SCHEME_HTTPS);

	// Open WinHTTP session
	HINTERNET hSession = WinHttpOpen(
		L"eMule/0.70b CacheClient",
		WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS, 0);
	if (!hSession)
		return CDR_NETWORK_ERROR;

	// Set timeouts: 5s connect, 10s send, 30s receive
	WinHttpSetTimeouts(hSession, 5000, 5000, 10000, 30000);

	ECacheDownloadResult eResult = CDR_NETWORK_ERROR;

	// Connect
	HINTERNET hConnect = WinHttpConnect(hSession, strHostName,
		urlComp.nPort ? urlComp.nPort : (bSecure ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT),
		0);
	if (hConnect) {
		// Create request
		HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", strUrlPath,
			NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
			bSecure ? WINHTTP_FLAG_SECURE : 0);
		if (hRequest) {
			// Add Range header for partial download
			CStringW strRange;
			strRange.Format(L"bytes=%I64u-%I64u", uRangeStart, uRangeEnd);
			WinHttpAddRequestHeaders(hRequest,
				CStringW(L"Range: ") + strRange,
				(DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD);

			// Send request
			if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
				WINHTTP_NO_REQUEST_DATA, 0, 0, 0)
				&& WinHttpReceiveResponse(hRequest, NULL))
			{
				// Check status code
				DWORD dwStatusCode = 0;
				DWORD dwSize = sizeof dwStatusCode;
				WinHttpQueryHeaders(hRequest,
					WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
					WINHTTP_HEADER_NAME_BY_INDEX, &dwStatusCode, &dwSize,
					WINHTTP_NO_HEADER_INDEX);

				*pdwHttpStatus = dwStatusCode;

				if (dwStatusCode == 200 || dwStatusCode == 206) {
					// Calculate expected data size
					uint32 dwExpectedSize = (uint32)(uRangeEnd - uRangeStart + 1);

					// Allocate buffer (limit to reasonable size to prevent OOM)
					if (dwExpectedSize > 0 && dwExpectedSize <= PARTSIZE + 1024) {
						BYTE *pBuffer = new(std::nothrow) BYTE[dwExpectedSize];
						if (pBuffer) {
							uint32 dwTotalRead = 0;
							bool bReadOK = true;

							while (dwTotalRead < dwExpectedSize && m_bRunning) {
								DWORD dwAvailable = 0;
								if (!WinHttpQueryDataAvailable(hRequest, &dwAvailable))
									break;
								if (dwAvailable == 0)
									break;

								DWORD dwToRead = min(dwAvailable, dwExpectedSize - dwTotalRead);
								DWORD dwRead = 0;
								if (!WinHttpReadData(hRequest, pBuffer + dwTotalRead, dwToRead, &dwRead)) {
									bReadOK = false;
									break;
								}
								if (dwRead == 0)
									break;
								dwTotalRead += dwRead;
							}

							if (bReadOK && dwTotalRead == dwExpectedSize) {
								*ppOutData = pBuffer;
								*pdwOutSize = dwTotalRead;
								eResult = CDR_SUCCESS;
							} else {
								delete[] pBuffer;
								eResult = CDR_NETWORK_ERROR;
							}
						}
					}
				} else if (dwStatusCode == 404 || dwStatusCode == 410) {
					eResult = CDR_NOT_FOUND;
				} else if (dwStatusCode == 416) {
					eResult = CDR_RANGE_NOT_SUPPORTED;
				}
			}
			WinHttpCloseHandle(hRequest);
		}
		WinHttpCloseHandle(hConnect);
	}
	WinHttpCloseHandle(hSession);

	*pdwElapsedMs = ::GetTickCount() - dwStartTick;
	return eResult;
}
