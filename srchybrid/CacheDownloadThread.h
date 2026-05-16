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
#pragma once
#include "CacheNodeList.h"

class CPartFile;

// Result of a cache chunk download attempt
enum ECacheDownloadResult
{
	CDR_SUCCESS = 0,		// Chunk downloaded and hash verified OK
	CDR_NOT_FOUND,			// File/chunk not found on any cache node (404)
	CDR_HASH_MISMATCH,		// Downloaded data but hash didn't match
	CDR_NETWORK_ERROR,		// Connection/network error
	CDR_NO_NODES,			// No healthy cache nodes available
	CDR_CANCELLED,			// Download was cancelled
	CDR_RANGE_NOT_SUPPORTED	// Cache node doesn't support Range requests
};

// Pending request for a chunk to download from cache
struct CacheChunkRequest
{
	CPartFile	*pFile;			// The part file this chunk belongs to
	uchar		abyFileHash[16];// MD4 hash of the file
	UINT		nPart;			// Part number (0-based)
	uint64		uStart;			// Start offset
	uint64		uEnd;			// End offset (exclusive)
	DWORD		dwRequestTime;	// When the request was made

	CacheChunkRequest()
		: pFile(NULL)
		, nPart(0)
		, uStart(0)
		, uEnd(0)
		, dwRequestTime(0)
	{
		memset(abyFileHash, 0, sizeof abyFileHash);
	}
};

// Result delivered back to the main thread
struct CacheChunkResult
{
	CacheChunkRequest	request;		// Original request
	ECacheDownloadResult eResult;		// What happened
	BYTE				*pData;			// Downloaded data (caller must free with delete[])
	uint32				dwDataSize;		// Size of downloaded data
	DWORD				dwDownloadMs;	// How long it took
	CString				strNodeURL;		// Which node served this chunk
	DWORD				dwHttpStatus;	// HTTP status code

	CacheChunkResult()
		: eResult(CDR_NETWORK_ERROR)
		, pData(NULL)
		, dwDataSize(0)
		, dwDownloadMs(0)
		, dwHttpStatus(0)
	{
	}

	~CacheChunkResult()
	{
		delete[] pData;
	}
};

// Background thread that downloads chunks from HTTP cache nodes.
// Uses WinHTTP for async HTTP requests with Range support.
//
// Usage:
//   1. Create and start the thread
//   2. Post chunk requests with RequestChunk()
//   3. Collect results with GetResults()
//   4. Results contain verified data ready to write to the PartFile
//
class CCacheDownloadThread : public CWinThread
{
	DECLARE_DYNCREATE(CCacheDownloadThread)
public:
	CCacheDownloadThread();
	~CCacheDownloadThread();
	CCacheDownloadThread(const CCacheDownloadThread&) = delete;
	CCacheDownloadThread& operator=(const CCacheDownloadThread&) = delete;

	// Start/stop
	void	EndThread();
	bool	IsRunning() const				{ return m_bRunning; }

	// Request a chunk to be downloaded from cache
	// Thread-safe. Returns false if request couldn't be queued.
	bool	RequestChunk(const CacheChunkRequest &request);

	// Retrieve completed results. Thread-safe. Caller owns the result pointers.
	// Returns number of results retrieved.
	int		GetResults(CArray<CacheChunkResult*> &raResults);

	// Cancel all pending requests for a specific file
	void	CancelFile(CPartFile *pFile);

	// Get stats
	uint64	GetTotalBytesDownloaded() const	{ return m_uTotalBytesDownloaded; }
	uint32	GetActiveDownloads() const		{ return m_nActiveDownloads; }
	uint32	GetPendingRequests() const;

	// Set the cache node list to use
	void	SetCacheNodeList(CCacheNodeList *pList)	{ m_pNodeList = pList; }

private:
	static UINT AFX_CDECL RunProc(LPVOID pParam);
	UINT	RunInternal();

	// Process one chunk request: try each healthy cache node until success
	CacheChunkResult* ProcessRequest(const CacheChunkRequest &request);

	// Download data from a single URL with Range support using WinHTTP
	ECacheDownloadResult DownloadFromURL(
		const CString &strURL,
		uint64 uRangeStart,
		uint64 uRangeEnd,
		BYTE **ppOutData,
		uint32 *pdwOutSize,
		DWORD *pdwHttpStatus,
		DWORD *pdwElapsedMs);

	// Convert file hash to hex string for URL
	static CString HashToHexString(const uchar *pHash);

	CCacheNodeList				*m_pNodeList;
	CEvent						m_eventThreadEnded;
	CEvent						m_eventNewRequest;

	CCriticalSection			m_csRequests;
	CList<CacheChunkRequest>	m_listRequests;

	CCriticalSection			m_csResults;
	CList<CacheChunkResult*>	m_listResults;

	volatile bool				m_bRunning;
	volatile uint32				m_nActiveDownloads;
	volatile uint64				m_uTotalBytesDownloaded;
};
