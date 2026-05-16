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
#include "CacheNodeList.h"
#include "emule.h"
#include "preferences.h"
#include "log.h"
#include "otherfunctions.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

CCacheNodeList::CCacheNodeList()
{
}

CCacheNodeList::~CCacheNodeList()
{
	RemoveAllNodes();
}

void CCacheNodeList::RemoveAllNodes()
{
	for (INT_PTR i = m_aNodes.GetCount(); --i >= 0;)
		delete m_aNodes[i];
	m_aNodes.RemoveAll();
}

CString CCacheNodeList::NormalizeURL(const CString &strURL)
{
	CString s(strURL);
	s.Trim();
	// Remove trailing slash
	while (s.GetLength() > 0 && s[s.GetLength() - 1] == _T('/'))
		s.Truncate(s.GetLength() - 1);
	return s;
}

CString CCacheNodeList::GetDefaultCacheMetPath()
{
	return thePrefs.GetMuleDirectory(EMULE_CONFIGDIR) + _T("cache.met");
}

CacheNode* CCacheNodeList::FindNode(const CString &strURL) const
{
	CString sNorm = NormalizeURL(strURL);
	for (INT_PTR i = m_aNodes.GetCount(); --i >= 0;)
		if (NormalizeURL(m_aNodes[i]->strURL).CompareNoCase(sNorm) == 0)
			return m_aNodes[i];
	return NULL;
}

bool CCacheNodeList::LoadCacheNodes(LPCTSTR pszFilePath)
{
	CSingleLock lock(&m_cs, TRUE);

	CStdioFile file;
	if (!file.Open(pszFilePath, CFile::modeRead | CFile::typeText | CFile::shareDenyWrite))
		return false;

	CString sLine;
	int nLoaded = 0;
	while (file.ReadString(sLine)) {
		sLine.Trim();
		// Skip empty lines and comments
		if (sLine.IsEmpty() || sLine[0] == _T('#') || sLine[0] == _T(';'))
			continue;

		// Parse: URL [TAB name] [TAB avgMs] [TAB failCount] [TAB enabled]
		CString strURL, strName;
		DWORD dwAvgMs = 0;
		DWORD dwFailCount = 0;
		bool bEnabled = true;

		int nTab = sLine.Find(_T('\t'));
		if (nTab >= 0) {
			strURL = sLine.Left(nTab);
			CString sRest = sLine.Mid(nTab + 1);
			
			// Parse name
			nTab = sRest.Find(_T('\t'));
			if (nTab >= 0) {
				strName = sRest.Left(nTab);
				sRest = sRest.Mid(nTab + 1);
				
				// Parse avgMs
				nTab = sRest.Find(_T('\t'));
				if (nTab >= 0) {
					dwAvgMs = (DWORD)_ttol(sRest.Left(nTab));
					sRest = sRest.Mid(nTab + 1);
					
					// Parse failCount
					nTab = sRest.Find(_T('\t'));
					if (nTab >= 0) {
						dwFailCount = (DWORD)_ttol(sRest.Left(nTab));
						bEnabled = (_ttol(sRest.Mid(nTab + 1)) != 0);
					} else {
						dwFailCount = (DWORD)_ttol(sRest);
					}
				} else {
					dwAvgMs = (DWORD)_ttol(sRest);
				}
			} else {
				strName = sRest;
			}
		} else {
			strURL = sLine;
		}

		strURL = NormalizeURL(strURL);
		if (strURL.IsEmpty())
			continue;

		// Check for duplicates
		if (FindNode(strURL) != NULL)
			continue;

		// Validate URL format (must start with http:// or https://)
		CString sLower(strURL);
		sLower.MakeLower();
		if (sLower.Find(_T("http://")) != 0 && sLower.Find(_T("https://")) != 0)
			continue;

		CacheNode *pNode = new CacheNode;
		pNode->strURL = strURL;
		pNode->strName = strName;
		pNode->dwAvgResponseMs = dwAvgMs;
		pNode->dwFailedCount = dwFailCount;
		pNode->bEnabled = bEnabled;
		pNode->bSupportsHTTPS = (sLower.Find(_T("https://")) == 0);
		m_aNodes.Add(pNode);
		++nLoaded;
	}

	if (nLoaded > 0)
		AddLogLine(false, _T("Loaded %d cache nodes from \"%s\""), nLoaded, pszFilePath);

	return nLoaded > 0;
}

bool CCacheNodeList::SaveCacheNodes(LPCTSTR pszFilePath) const
{
	CSingleLock lock(const_cast<CCriticalSection*>(&m_cs), TRUE);

	CStdioFile file;
	if (!file.Open(pszFilePath, CFile::modeCreate | CFile::modeWrite | CFile::typeText | CFile::shareDenyWrite))
		return false;

	file.WriteString(_T("# eMule Cache Node List\n"));
	file.WriteString(_T("# Format: URL<TAB>name<TAB>avgMs<TAB>failCount<TAB>enabled\n"));
	file.WriteString(_T("# Load this list for high-speed HTTP chunk downloads alongside P2P\n"));
	file.WriteString(_T("#\n"));

	for (INT_PTR i = 0; i < m_aNodes.GetCount(); ++i) {
		const CacheNode *pNode = m_aNodes[i];
		CString sLine;
		sLine.Format(_T("%s\t%s\t%lu\t%lu\t%d\n"),
			(LPCTSTR)pNode->strURL,
			(LPCTSTR)pNode->strName,
			pNode->dwAvgResponseMs,
			pNode->dwFailedCount,
			pNode->bEnabled ? 1 : 0);
		file.WriteString(sLine);
	}

	return true;
}

bool CCacheNodeList::LoadCacheNodesFromURL(LPCTSTR /*pszURL*/)
{
	// TODO: Implement URL-based loading using WinHTTP
	// Download the cache.met from the URL and parse it
	// This should be done asynchronously in a background thread
	return false;
}

bool CCacheNodeList::AddNode(const CString &strURL, const CString &strName)
{
	CSingleLock lock(&m_cs, TRUE);

	CString sNorm = NormalizeURL(strURL);
	if (sNorm.IsEmpty())
		return false;

	// Validate URL
	CString sLower(sNorm);
	sLower.MakeLower();
	if (sLower.Find(_T("http://")) != 0 && sLower.Find(_T("https://")) != 0)
		return false;

	// Check for duplicates
	if (FindNode(sNorm) != NULL)
		return false;

	CacheNode *pNode = new CacheNode;
	pNode->strURL = sNorm;
	pNode->strName = strName;
	pNode->bSupportsHTTPS = (sLower.Find(_T("https://")) == 0);
	m_aNodes.Add(pNode);

	AddLogLine(false, _T("Added cache node: %s"), (LPCTSTR)sNorm);
	return true;
}

bool CCacheNodeList::RemoveNode(const CString &strURL)
{
	CSingleLock lock(&m_cs, TRUE);

	CString sNorm = NormalizeURL(strURL);
	for (INT_PTR i = m_aNodes.GetCount(); --i >= 0;) {
		if (NormalizeURL(m_aNodes[i]->strURL).CompareNoCase(sNorm) == 0) {
			delete m_aNodes[i];
			m_aNodes.RemoveAt(i);
			return true;
		}
	}
	return false;
}

void CCacheNodeList::GetHealthyNodes(CArray<CacheNode*> &raNodes) const
{
	CSingleLock lock(const_cast<CCriticalSection*>(&m_cs), TRUE);

	raNodes.RemoveAll();
	for (INT_PTR i = 0; i < m_aNodes.GetCount(); ++i) {
		if (m_aNodes[i]->IsHealthy())
			raNodes.Add(m_aNodes[i]);
	}

	// Sort by average response time (fastest first)
	// Simple insertion sort since list is typically small
	for (INT_PTR i = 1; i < raNodes.GetCount(); ++i) {
		CacheNode *pKey = raNodes[i];
		INT_PTR j = i - 1;
		while (j >= 0 && raNodes[j]->dwAvgResponseMs > pKey->dwAvgResponseMs) {
			raNodes[j + 1] = raNodes[j];
			--j;
		}
		raNodes[j + 1] = pKey;
	}
}

CacheNode* CCacheNodeList::GetNodeByURL(const CString &strURL)
{
	CSingleLock lock(&m_cs, TRUE);
	return FindNode(strURL);
}

INT_PTR CCacheNodeList::GetHealthyNodeCount() const
{
	CSingleLock lock(const_cast<CCriticalSection*>(&m_cs), TRUE);
	INT_PTR n = 0;
	for (INT_PTR i = m_aNodes.GetCount(); --i >= 0;)
		if (m_aNodes[i]->IsHealthy())
			++n;
	return n;
}

void CCacheNodeList::OnNodeSuccess(const CString &strURL, DWORD dwResponseMs)
{
	CSingleLock lock(&m_cs, TRUE);
	CacheNode *pNode = FindNode(strURL);
	if (pNode)
		pNode->OnSuccess(dwResponseMs);
}

void CCacheNodeList::OnNodeFailure(const CString &strURL, DWORD dwHttpStatus)
{
	CSingleLock lock(&m_cs, TRUE);
	CacheNode *pNode = FindNode(strURL);
	if (pNode)
		pNode->OnFailure(dwHttpStatus);
}

void CCacheNodeList::ResetAllNodes()
{
	CSingleLock lock(&m_cs, TRUE);
	for (INT_PTR i = m_aNodes.GetCount(); --i >= 0;) {
		m_aNodes[i]->bEnabled = true;
		m_aNodes[i]->dwFailedCount = 0;
	}
}
