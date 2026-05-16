// filepath: srchybrid/eMuleAI/DirectoryWatcher.cpp
// eSE: Real-time shared directory watcher using ReadDirectoryChangesW
// Monitors all shared directories and queues new file paths for processing
// by CSharedFileList::Process() on the main thread.

#include "stdafx.h"
#include "eMuleAI/DirectoryWatcher.h"
#include "emule.h"
#include "Preferences.h"
#include "Log.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

CDirectoryWatcher::CDirectoryWatcher()
	: m_pThread(NULL)
	, m_hStopEvent(NULL)
	, m_bRunning(false)
{
}

CDirectoryWatcher::~CDirectoryWatcher()
{
	Stop();
}

void CDirectoryWatcher::Start()
{
	if (m_bRunning)
		return;

	m_hStopEvent = ::CreateEvent(NULL, TRUE, FALSE, NULL);
	if (m_hStopEvent == NULL)
		return;

	m_bRunning = true;
	m_pThread = AfxBeginThread(WatcherThreadProc, this, THREAD_PRIORITY_BELOW_NORMAL, 0, 0, NULL);
	if (m_pThread == NULL) {
		m_bRunning = false;
		::CloseHandle(m_hStopEvent);
		m_hStopEvent = NULL;
	}
}

void CDirectoryWatcher::Stop()
{
	if (!m_bRunning)
		return;

	m_bRunning = false;
	if (m_hStopEvent != NULL)
		::SetEvent(m_hStopEvent);

	// Wait for the thread to finish (max 5 seconds)
	if (m_pThread != NULL && m_pThread->m_hThread != NULL)
		::WaitForSingleObject(m_pThread->m_hThread, 5000);

	if (m_hStopEvent != NULL) {
		::CloseHandle(m_hStopEvent);
		m_hStopEvent = NULL;
	}
	m_pThread = NULL;
}

bool CDirectoryWatcher::GetPendingFiles(CStringList &listOut)
{
	CSingleLock lock(&m_csQueue, TRUE);
	if (m_listPendingFiles.IsEmpty())
		return false;
	listOut.AddTail(&m_listPendingFiles);
	m_listPendingFiles.RemoveAll();
	return true;
}

UINT CDirectoryWatcher::WatcherThreadProc(LPVOID pParam)
{
	CDirectoryWatcher *pThis = static_cast<CDirectoryWatcher*>(pParam);
	if (pThis != NULL)
		pThis->WatcherThread();
	return 0;
}

void CDirectoryWatcher::WatcherThread()
{
	// Collect all shared directories
	std::vector<WatchedDir> watchedDirs;
	std::vector<HANDLE> waitHandles;

	// Stop event is the first handle
	waitHandles.push_back(m_hStopEvent);

	// Helper lambda to add a directory to watch
	auto addDir = [&](const CString &strDir)
	{
		if (strDir.IsEmpty())
			return;

		// Skip duplicates
		for (size_t i = 0; i < watchedDirs.size(); ++i)
			if (watchedDirs[i].strPath.CompareNoCase(strDir) == 0)
				return;

		CString strClean(strDir);
		if (strClean.Right(1) != _T("\\"))
			strClean += _T('\\');

		HANDLE hDir = ::CreateFile(strClean, FILE_LIST_DIRECTORY,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, NULL);
		if (hDir != INVALID_HANDLE_VALUE) {
			HANDLE hEvent = ::CreateEvent(NULL, TRUE, FALSE, NULL);
			if (hEvent != NULL) {
				WatchedDir wd;
				wd.strPath = strClean;
				wd.hDir = hDir;
				watchedDirs.push_back(wd);
				waitHandles.push_back(hEvent);
			} else {
				::CloseHandle(hDir);
			}
		}
	};

	// Add incoming directory
	addDir(thePrefs.GetMuleDirectory(EMULE_INCOMINGDIR));

	// Add category directories
	for (INT_PTR i = 1; i < thePrefs.GetCatCount(); ++i)
		addDir(thePrefs.GetCatPath(i));

	// Add user-configured shared directories
	for (POSITION pos = thePrefs.shareddir_list.GetHeadPosition(); pos != NULL;)
		addDir(thePrefs.shareddir_list.GetNext(pos));

	if (watchedDirs.empty()) {
		AddDebugLogLine(false, _T("eSE DirectoryWatcher: No shared directories to watch"));
		return;
	}

	AddDebugLogLine(false, _T("eSE DirectoryWatcher: Monitoring %u shared directories"), (unsigned)watchedDirs.size());

	// Allocate OVERLAPPED structures and buffers (64 KB each)
	static const DWORD BUFFER_SIZE = 64 * 1024;
	std::vector<OVERLAPPED> overlaps(watchedDirs.size());
	std::vector<std::vector<BYTE>> buffers(watchedDirs.size());

	for (size_t i = 0; i < watchedDirs.size(); ++i) {
		buffers[i].resize(BUFFER_SIZE);
		ZeroMemory(&overlaps[i], sizeof(OVERLAPPED));
		overlaps[i].hEvent = waitHandles[i + 1];

		::ReadDirectoryChangesW(
			watchedDirs[i].hDir,
			&buffers[i][0],
			BUFFER_SIZE,
			FALSE, // Don't watch subtree
			FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE,
			NULL,
			&overlaps[i],
			NULL);
	}

	// Main loop
	while (m_bRunning && theApp.IsRunning()) {
		DWORD dwResult = ::WaitForMultipleObjects(
			(DWORD)waitHandles.size(),
			&waitHandles[0],
			FALSE,
			5000); // Wake up every 5s to check m_bRunning

		if (dwResult == WAIT_OBJECT_0) {
			break; // Stop event
		}

		if (dwResult == WAIT_TIMEOUT)
			continue;

		if (dwResult >= WAIT_OBJECT_0 + 1 && dwResult < WAIT_OBJECT_0 + waitHandles.size()) {
			size_t idx = dwResult - WAIT_OBJECT_0 - 1;

			DWORD dwBytesReturned = 0;
			if (::GetOverlappedResult(watchedDirs[idx].hDir, &overlaps[idx], &dwBytesReturned, FALSE)
				&& dwBytesReturned > 0)
			{
				// Debounce: wait 500ms for file system to settle
				::Sleep(500);

				// Parse notification buffer
				BYTE *pBuf = &buffers[idx][0];
				for (;;) {
					FILE_NOTIFY_INFORMATION *pNotify = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(pBuf);

					CString strFileName(pNotify->FileName, pNotify->FileNameLength / sizeof(WCHAR));
					CString strFullPath = watchedDirs[idx].strPath + strFileName;

					if (pNotify->Action == FILE_ACTION_ADDED ||
						pNotify->Action == FILE_ACTION_RENAMED_NEW_NAME)
					{
						// Skip directories, temporary files, and .part files
						DWORD dwAttr = ::GetFileAttributes(strFullPath);
						if (dwAttr != INVALID_FILE_ATTRIBUTES &&
							!(dwAttr & FILE_ATTRIBUTE_DIRECTORY) &&
							strFullPath.Right(5).CompareNoCase(_T(".part")) != 0 &&
							strFullPath.Right(4).CompareNoCase(_T(".tmp")) != 0)
						{
							CSingleLock lock(&m_csQueue, TRUE);
							// Avoid duplicates in the queue
							bool bDuplicate = false;
							for (POSITION qpos = m_listPendingFiles.GetHeadPosition(); qpos != NULL;) {
								if (m_listPendingFiles.GetNext(qpos).CompareNoCase(strFullPath) == 0) {
									bDuplicate = true;
									break;
								}
							}
							if (!bDuplicate) {
								m_listPendingFiles.AddTail(strFullPath);
								AddDebugLogLine(false, _T("eSE DirectoryWatcher: Queued new file '%s'"),
									(LPCTSTR)strFullPath);
							}
						}
					}

					if (pNotify->NextEntryOffset == 0)
						break;
					pBuf += pNotify->NextEntryOffset;
				}
			}

			// Re-arm the watch
			::ResetEvent(overlaps[idx].hEvent);
			::ReadDirectoryChangesW(
				watchedDirs[idx].hDir,
				&buffers[idx][0],
				BUFFER_SIZE,
				FALSE,
				FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE,
				NULL,
				&overlaps[idx],
				NULL);
		}
	}

	// Cleanup
	for (size_t i = 0; i < watchedDirs.size(); ++i) {
		::CancelIo(watchedDirs[i].hDir);
		::CloseHandle(watchedDirs[i].hDir);
		::CloseHandle(overlaps[i].hEvent);
	}

	AddDebugLogLine(false, _T("eSE DirectoryWatcher: Stopped"));
}
