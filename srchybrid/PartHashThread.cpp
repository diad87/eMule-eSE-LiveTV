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
#include "StdAfx.h"
#include "PartHashThread.h"
#include "emule.h"
#include "emuledlg.h"
#include "KnownFile.h"
#include "OtherFunctions.h"
#include "Log.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

CPartHashThread::CPartHashThread()
	: m_eventWakeUp(FALSE, FALSE)		//auto-reset
	, m_eventThreadEnded(FALSE, TRUE)	//manual-reset
	, m_Run(1)
{
	AfxBeginThread(RunProc, (LPVOID)this, THREAD_PRIORITY_BELOW_NORMAL);
}

CPartHashThread::~CPartHashThread()
{
	ASSERT(!m_Run && m_Queue.IsEmpty());
}

UINT AFX_CDECL CPartHashThread::RunProc(LPVOID pParam)
{
	DbgSetThreadName("PartHashThread");
	InitThreadLocale();
	return pParam ? static_cast<CPartHashThread*>(pParam)->RunInternal() : 1;
}

void CPartHashThread::EndThread()
{
	//the job in flight (at most one part) is allowed to finish; its verdict will simply
	//never be processed. Everything still queued is discarded - on a clean shutdown the
	//leftover parts stay marked in CPartFile::m_aChangedPart and are re-verified
	//synchronously by the destructors.
	m_Run = 0;
	m_eventWakeUp.SetEvent();
	m_eventThreadEnded.Lock();
}

UINT CPartHashThread::RunInternal()
{
	while (m_Run) {
		PartHashJob_Struct *pJob = NULL;
		m_lockQueue.Lock();
		if (!m_Queue.IsEmpty())
			pJob = m_Queue.RemoveHead();
		m_lockQueue.Unlock();

		if (pJob == NULL) {
			m_eventWakeUp.Lock();
			continue;
		}
		ProcessJob(pJob);
		delete pJob;
	}

	//discard whatever is still queued
	m_lockQueue.Lock();
	while (!m_Queue.IsEmpty())
		delete m_Queue.RemoveHead();
	m_lockQueue.Unlock();

	m_eventThreadEnded.SetEvent();
	return 0;
}

void CPartHashThread::ProcessJob(const PartHashJob_Struct *pJob)
{
	PartHashVerdict_Struct *pVerdict = new PartHashVerdict_Struct{};
	pVerdict->uPart = pJob->uPart;
	pVerdict->uGen = pJob->uGen;
	pVerdict->bNoAICH = pJob->bNoAICH;

	CAICHHashTree *pAICHTree = NULL;
	try {
		CFile file;
		CFileException fex;
		//own read handle; the .part is opened with shareDenyNone everywhere else
		if (file.Open(pJob->sFilePath, CFile::modeRead | CFile::shareDenyNone | CFile::osSequentialScan, &fex)) {
			if (pJob->bComputeAICH)
				pAICHTree = new CAICHHashTree(pJob->uAICHDataSize, pJob->bAICHLeftBranch, pJob->uAICHBaseSize);
			file.Seek((LONGLONG)pJob->uStart, CFile::begin);
			CKnownFile::CreateHash(&file, pJob->uLength, pVerdict->aMD4Hash, pAICHTree);
			if (pAICHTree != NULL && pAICHTree->m_bHashValid) {
				pVerdict->aichHash = pAICHTree->m_Hash;
				pVerdict->bAICHValid = true;
			}
		} else {
			theApp.QueueDebugLogLineEx(LOG_ERROR, _T("PartHashThread: failed to open \"%s\" for reading: %s"), (LPCTSTR)pJob->sFilePath, (LPCTSTR)GetErrorMessage(fex.m_lOsError, 1));
			pVerdict->bReadError = true;
		}
	} catch (CFileException *ex) {
		pVerdict->bReadError = true;
		ex->Delete();
	}
	delete pAICHTree;

	if (theApp.emuledlg == NULL
		|| !::IsWindow(theApp.emuledlg->m_hWnd)
		|| !theApp.emuledlg->PostMessage(TM_PARTHASHED, (WPARAM)pVerdict, (LPARAM)pJob->pFile))
	{
		delete pVerdict;
	}
}

void CPartHashThread::QueueJob(PartHashJob_Struct *pJob)
{
	m_lockQueue.Lock();
	m_Queue.AddTail(pJob);
	m_lockQueue.Unlock();
	m_eventWakeUp.SetEvent();
}

void CPartHashThread::CancelFile(const CPartFile *pFile)
{
	m_lockQueue.Lock();
	for (POSITION pos = m_Queue.GetHeadPosition(); pos != NULL;) {
		POSITION pos2 = pos;
		const PartHashJob_Struct *pJob = m_Queue.GetNext(pos);
		if (pJob->pFile == pFile) {
			m_Queue.RemoveAt(pos2);
			delete pJob;
		}
	}
	m_lockQueue.Unlock();
}
