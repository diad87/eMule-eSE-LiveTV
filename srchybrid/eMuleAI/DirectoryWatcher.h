// filepath: srchybrid/eMuleAI/DirectoryWatcher.h
// eSE: Real-time shared directory watcher using ReadDirectoryChangesW
// Detects file additions/deletions/renames without manual Reload

#ifndef DIRECTORYWATCHER_H
#define DIRECTORYWATCHER_H

#pragma once
#include <vector>

class CSharedFileList;

class CDirectoryWatcher
{
public:
	CDirectoryWatcher();
	~CDirectoryWatcher();
	CDirectoryWatcher(const CDirectoryWatcher&) = delete;
	CDirectoryWatcher& operator=(const CDirectoryWatcher&) = delete;

	void Start();
	void Stop();
	bool IsRunning() const { return m_bRunning; }

	// Thread-safe: called from main thread to collect pending file additions
	// Returns true if there were pending files
	bool GetPendingFiles(CStringList &listOut);

private:
	static UINT WatcherThreadProc(LPVOID pParam);
	void WatcherThread();

	struct WatchedDir
	{
		CString strPath;
		HANDLE  hDir;
	};

	CWinThread      *m_pThread;
	HANDLE           m_hStopEvent;
	volatile bool    m_bRunning;

	// Thread-safe pending file queue
	CCriticalSection m_csQueue;
	CStringList      m_listPendingFiles;
};

#endif // DIRECTORYWATCHER_H
