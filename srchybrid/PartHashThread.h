//this file is part of eMule
//Copyright (C)2020-2024 Merkur ( strEmail.Format("%s@%s", "devteam", "emule-project.net") / https://www.emule-project.net )
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

#include "SHAHashSet.h"
#include "OtherFunctions.h" // MDX_DIGEST_SIZE

class CPartFile;

// MD4+AICH verification of completed parts off the main thread. A job is a
// snapshot taken on the main thread; the worker never touches
// CPartFile state and reads the .part through its own handle. The verdict goes back to
// the main thread via TM_PARTHASHED (CemuleDlg::OnPartHashed), where it is compared
// against the file's current hashsets and validated by generation.
struct PartHashJob_Struct
{
	CPartFile *pFile;	//opaque token for the verdict; never dereferenced by the worker
	CString sFilePath;	//full path of the .part file
	uint64 uStart;
	uint64 uLength;
	uint64 uAICHDataSize;
	uint64 uAICHBaseSize;
	UINT uPart;
	UINT uGen;
	bool bComputeAICH;
	bool bAICHLeftBranch;
	bool bNoAICH;
};

struct PartHashVerdict_Struct
{
	UINT uPart;
	UINT uGen;
	uchar aMD4Hash[MDX_DIGEST_SIZE];
	CAICHHash aichHash;
	bool bAICHValid;
	bool bNoAICH;
	bool bReadError;
};

class CPartHashThread
{
public:
	CPartHashThread();
	~CPartHashThread();
	CPartHashThread(const CPartHashThread&) = delete;
	CPartHashThread& operator=(const CPartHashThread&) = delete;

	bool	IsRunning() const							{ return m_Run > 0; }
	void	EndThread();		//lets the job in flight finish, discards the queue, joins
	void	QueueJob(PartHashJob_Struct *pJob);			//main thread only
	void	CancelFile(const CPartFile *pFile);			//main thread only; purges queued (not in-flight) jobs

private:
	static UINT AFX_CDECL RunProc(LPVOID pParam);
	UINT	RunInternal();
	void	ProcessJob(const PartHashJob_Struct *pJob);

	CTypedPtrList<CPtrList, PartHashJob_Struct*> m_Queue;
	CCriticalSection m_lockQueue;
	CEvent	m_eventWakeUp;
	CEvent	m_eventThreadEnded;
	volatile char m_Run; //0 - not running; 1 - running
};
