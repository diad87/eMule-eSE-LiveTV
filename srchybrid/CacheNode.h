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

// A cache node is a simple HTTP server that stores and serves
// file chunks indexed by their ed2k MD4 hash.
// No registration, no authentication. Just HTTP GET by hash.
//
// URL pattern: {base_url}/{md4_hash_hex}
// Supports Range requests for downloading specific parts.
//
// Example:
//   GET http://185.21.0.1:8080/31D6CFE0D16AE931B73C59D7E0C089C0
//   Range: bytes=0-9437183
//
struct CacheNode
{
	CString		strURL;			// Base URL, e.g. "http://185.21.0.1:8080" or "https://cache.example.net"
	CString		strName;		// Optional friendly name
	DWORD		dwLastPingTime;	// Last successful response time (ms), 0 = never tested
	DWORD		dwLastPingResult; // HTTP status code from last ping (200 = OK)
	DWORD		dwFailedCount;	// Consecutive failures
	uint32		dwAvgResponseMs;// Average response time in ms
	bool		bEnabled;		// Is this node active?
	bool		bSupportsRange;	// Does it support HTTP Range requests?
	bool		bSupportsHTTPS;	// Is it HTTPS?

	CacheNode()
		: dwLastPingTime(0)
		, dwLastPingResult(0)
		, dwFailedCount(0)
		, dwAvgResponseMs(0)
		, bEnabled(true)
		, bSupportsRange(true)
		, bSupportsHTTPS(false)
	{
	}

	// Build the full URL for a file hash
	CString GetFileURL(const CString &strMD4Hash) const
	{
		CString url;
		url.Format(_T("%s/%s"), (LPCTSTR)strURL, (LPCTSTR)strMD4Hash);
		return url;
	}

	// Build a URL for a specific part of a file
	CString GetPartURL(const CString &strMD4Hash, UINT nPart) const
	{
		CString url;
		url.Format(_T("%s/%s/%u"), (LPCTSTR)strURL, (LPCTSTR)strMD4Hash, nPart);
		return url;
	}

	// Check if the node seems healthy
	bool IsHealthy() const
	{
		return bEnabled && dwFailedCount < 5;
	}

	// Mark a successful response
	void OnSuccess(DWORD dwResponseMs)
	{
		dwLastPingTime = ::GetTickCount();
		dwLastPingResult = 200;
		dwFailedCount = 0;
		// Rolling average
		if (dwAvgResponseMs == 0)
			dwAvgResponseMs = dwResponseMs;
		else
			dwAvgResponseMs = (dwAvgResponseMs * 3 + dwResponseMs) / 4;
	}

	// Mark a failed response
	void OnFailure(DWORD dwHttpStatus = 0)
	{
		dwLastPingTime = ::GetTickCount();
		dwLastPingResult = dwHttpStatus;
		++dwFailedCount;
		// Auto-disable after too many failures
		if (dwFailedCount >= 10)
			bEnabled = false;
	}
};
