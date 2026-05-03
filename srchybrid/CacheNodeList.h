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
#include "CacheNode.h"

// Manages a list of cache nodes loaded from cache.met files.
// Works exactly like server.met but for HTTP cache nodes.
//
// cache.met format (simple text, one node per line):
//   # Comment lines start with #
//   # Format: URL [TAB name]
//   http://185.21.0.1:8080	Community Cache 1
//   https://cache.emule-community.net	Main CDN
//   http://93.44.12.5:8080
//
// Can also load from a URL (like server.met auto-update):
//   http://www.emule-project.net/cache.met
//
class CCacheNodeList
{
public:
	CCacheNodeList();
	~CCacheNodeList();

	// Load cache.met from local file
	bool LoadCacheNodes(LPCTSTR pszFilePath);

	// Save cache.met to local file (preserving health data)
	bool SaveCacheNodes(LPCTSTR pszFilePath) const;

	// Load cache.met from URL (background, non-blocking)
	bool LoadCacheNodesFromURL(LPCTSTR pszURL);

	// Add a single node manually
	bool AddNode(const CString &strURL, const CString &strName = CString());

	// Remove a node
	bool RemoveNode(const CString &strURL);

	// Get all healthy nodes sorted by response time (fastest first)
	void GetHealthyNodes(CArray<CacheNode*> &raNodes) const;

	// Get a specific node by URL
	CacheNode* GetNodeByURL(const CString &strURL);

	// Get total node count
	INT_PTR GetNodeCount() const { return m_aNodes.GetCount(); }

	// Get healthy node count
	INT_PTR GetHealthyNodeCount() const;

	// Mark a node as succeeded/failed (thread-safe)
	void OnNodeSuccess(const CString &strURL, DWORD dwResponseMs);
	void OnNodeFailure(const CString &strURL, DWORD dwHttpStatus);

	// Re-enable all disabled nodes (for retry)
	void ResetAllNodes();

	// Get path to default cache.met
	static CString GetDefaultCacheMetPath();

	CCriticalSection m_cs; // for thread-safe access

private:
	CArray<CacheNode*> m_aNodes;

	CacheNode* FindNode(const CString &strURL) const;
	void RemoveAllNodes();

	// URL normalization
	static CString NormalizeURL(const CString &strURL);
};
