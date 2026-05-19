//this file is part of eMule
//Copyright (C)2002-2024 Merkur ( strEmail.Format("%s@%s", "devteam", "emule-project.net") / https://www.emule-project.net )
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
#include "stdafx.h"
#include "DebugHelpers.h"
#include "emule.h"
#include "ListenSocket.h"
#include "opcodes.h"
#include "LiveStreamManager.h"
#include "LiveCrypto.h"        // v7.6.0 — StreamKeyMatchesPubkey
#include "LiveTunnel.h"        // v0.71 P3.4 — OP_LIVE_TUNNEL_CELL dispatch
#include "LiveCellQueue.h"     // v0.71 P3.4 — CELL_TOTAL_BYTES + CellUnpack
#include "../cryptopp/sha.h"   // v7.7.0 — SHA256 for OP_LIVE_CHUNK_V2 verify
#include "eMuleAI/Address.h"   // v0.71 IPv6 Sprint 7 — CAddress in PEER_LIST_V2
#include "UpDownClient.h"
#include "ClientList.h"
#include "DownloadQueue.h"
#include "Statistics.h"
#include "IPFilter.h"
#include "SharedFileList.h"
#include "PartFile.h"
#include "SafeFile.h"
#include "Packets.h"
#include "UploadQueue.h"
#include "ServerList.h"
#include "Server.h"
#include "ServerConnect.h"
#include "emuledlg.h"
#include "TransferDlg.h"
#include "ClientListCtrl.h"
#include "ChatWnd.h"
#include "Exceptions.h"
#include "Kademlia/Utils/uint128.h"
#include "Kademlia/Kademlia/kademlia.h"
#include "Kademlia/Kademlia/prefs.h"
#include "ClientUDPSocket.h"
#include "SHAHashSet.h"
#include "Log.h"
#include "eMuleAI/UtpSocket.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

// CClientReqSocket

IMPLEMENT_DYNCREATE(CClientReqSocket, CEMSocket)

CClientReqSocket::CClientReqSocket(CUpDownClient *in_client)
	: deltimer()
	, m_nOnConnect(SS_Other)
	, deletethis()
	, m_bPortTestCon()
	, m_pUtpLayer(NULL)
{
	SetClient(in_client);
	theApp.listensocket->AddSocket(this);
	ResetTimeOutTimer();
}

CUtpSocket* CClientReqSocket::InitUtpSupport()
{
	if (m_pUtpLayer != NULL)
		return m_pUtpLayer; // already initialized

	CUtpSocket* pUtpLayer = new CUtpSocket();
	if (AddLayer(pUtpLayer)) {
		m_pUtpLayer = pUtpLayer;
		if (thePrefs.GetVerbose())
			DebugLog(_T("[eSE] InitUtpSupport: uTP layer added to CClientReqSocket %p"), this);
		return m_pUtpLayer;
	}
	// AddLayer failed
	delete pUtpLayer;
	DebugLogWarning(_T("[eSE] InitUtpSupport: AddLayer FAILED on CClientReqSocket %p"), this);
	return NULL;
}

void CClientReqSocket::SetConState(SocketState val)
{
	//If no change, do nothing.
	if ((uint32)val == m_nOnConnect)
		return;
	//Decrease count for the old state
	switch (m_nOnConnect) {
	case SS_Half:
		--theApp.listensocket->m_nHalfOpen;
		break;
	case SS_Complete:
		--theApp.listensocket->m_nComp;
	}
	//Set the new state
	m_nOnConnect = val;
	//Increase count for the new state
	switch (m_nOnConnect) {
	case SS_Half:
		++theApp.listensocket->m_nHalfOpen;
		break;
	case SS_Complete:
		++theApp.listensocket->m_nComp;
	}
}

void CClientReqSocket::WaitForOnConnect()
{
	SetConState(SS_Half);
}

CClientReqSocket::~CClientReqSocket()
{
	//This will update our statistics.
	SetConState(SS_Other);
	if (client)
		client->socket = 0;
	client = NULL;
	theApp.listensocket->RemoveSocket(this);

	DEBUG_ONLY(theApp.clientlist->Debug_SocketDeleted(this));
}

void CClientReqSocket::SetClient(CUpDownClient *pClient)
{
	client = pClient;
	if (client)
		client->socket = this;
}

void CClientReqSocket::ResetTimeOutTimer()
{
	timeout_timer = ::GetTickCount();
}

bool CClientReqSocket::CheckTimeOut()
{
	const DWORD curTick = ::GetTickCount();
	if (m_nOnConnect == SS_Half) {
		//This socket is still in a half connection state. Because of SP2, we don't know
		//if this socket is actually failing, or if this socket is just queued in SP2's new
		//protection queue. Therefore we give the socket a chance to either finally report
		//the connection error, or finally make it through SP2's new queued socket system.
		if (curTick < timeout_timer + CEMSocket::GetTimeOut() * 4)
			return false;
		timeout_timer = curTick;
		CString str;
		str.Format(_T("Timeout: State:%u = SS_Half"), m_nOnConnect);
		Disconnect(str);
		return true;
	}
	DWORD uTimeout = GetTimeOut();
	if (client)
		if (client->GetKadState() == KS_CONNECTED_BUDDY)
			uTimeout += MIN2MS(15);
		else if (client->IsDownloading() && curTick < client->GetUpStartTime() + 4 * CONNECTION_TIMEOUT)
			//TCP flow control might need more time to begin throttling for slow peers
			uTimeout += 4 * CONNECTION_TIMEOUT; //2'30" or slightly more
		else if (client->GetChatState() != MS_NONE)
			//We extend the timeout time here to avoid chatting people from disconnecting too fast.
			uTimeout += CONNECTION_TIMEOUT;

	if (curTick < timeout_timer + uTimeout)
		return false;
	timeout_timer = curTick;
	CString str;
	str.Format(_T("Timeout: State:%u (0 = SS_Other, 1 = SS_Half, 2 = SS_Complete)"), m_nOnConnect);
	Disconnect(str);
	return true;
}

void CClientReqSocket::OnClose(int nErrorCode)
{
	ASSERT(theApp.listensocket->IsValidSocket(this));
	CEMSocket::OnClose(nErrorCode);

	if (nErrorCode)
		Disconnect(thePrefs.GetVerbose() ? GetErrorMessage(nErrorCode, 1) : NULL);
	else
		Disconnect(_T("Close"));
}

void CClientReqSocket::Disconnect(LPCTSTR pszReason)
{
	CEMSocket::SetConState(EMS_DISCONNECTED);
	AsyncSelect(FD_CLOSE);
	if (client) {
		CString sMsg;
		sMsg.Format(_T("CClientReqSocket::Disconnect(): %s"), pszReason);
		if (client->Disconnected(sMsg, true)) {
			const CUpDownClient *temp = client;
			client->socket = NULL;
			client = NULL;
			delete temp;
		} else
			client = NULL;
	}
	Safe_Delete();
}

void CClientReqSocket::Delete_Timed()
{
// it seems that MFC Sockets call socket functions after they are deleted, even if the socket is closed
// and select(0) is set. So we need to wait some time to make sure this doesn't happen
// we currently also rely on this for multithreading; rework synchronization if this ever changes
	if (::GetTickCount() >= deltimer + SEC2MS(10))
		delete this;
}

void CClientReqSocket::Safe_Delete()
{
	ASSERT(theApp.listensocket->IsValidSocket(this));
	CEMSocket::SetConState(EMS_DISCONNECTED);
	AsyncSelect(FD_CLOSE);
	deltimer = ::GetTickCount();
	if (m_SocketData.hSocket != INVALID_SOCKET) // deadlake PROXYSUPPORT - changed to AsyncSocketEx
		ShutDown(CAsyncSocket::both);
	if (client) {
		client->socket = NULL;
		client = NULL;
	}
	deletethis = true;
}

bool CClientReqSocket::ProcessPacket(const BYTE *packet, uint32 size, UINT opcode)
{
	switch (opcode) {
	case OP_HELLOANSWER:
		theStats.AddDownDataOverheadOther(size);
		client->ProcessHelloAnswer(packet, size);
		// BUG-009 FIX: client may be invalidated by ProcessHelloAnswer
		if (!client)
			break;
		if (thePrefs.GetDebugClientTCPLevel() > 0) {
			DebugRecv("OP_HelloAnswer", client);
			Debug(_T("  %s\n"), (LPCTSTR)client->DbgGetClientInfo());
		}

		// start secure identification, if
		//  - we have received OP_EMULEINFO and OP_HELLOANSWER (old eMule)
		//	- we have received eMule-OP_HELLOANSWER (new eMule)
		if (client->GetInfoPacketsReceived() == IP_BOTH)
			client->InfoPacketsReceived();

		client->ConnectionEstablished();
		theApp.emuledlg->transferwnd->GetClientList()->RefreshClient(client);
		break;
	case OP_HELLO:
		{
			theStats.AddDownDataOverheadOther(size);

			bool bNewClient = !client;
			if (bNewClient)
				// create new client to save standard information
				client = new CUpDownClient(this);

			bool bIsMuleHello;
			try {
				bIsMuleHello = client->ProcessHelloPacket(packet, size);
			} catch (...) {
				if (bNewClient) {
					// Don't let CUpDownClient::Disconnected process a client which is not in the list of clients.
					delete client;
					client = NULL;
				}
				throw;
			}

			if (thePrefs.GetDebugClientTCPLevel() > 0) {
				DebugRecv("OP_Hello", client);
				Debug(_T("  %s\n"), (LPCTSTR)client->DbgGetClientInfo());
			}

			// now we check if we know this client already. if yes this socket will
			// be attached to the known client, the new client will be deleted
			// and the var. "client" will point to the known client.
			// if not we keep our new-constructed client ;)
			if (theApp.clientlist->AttachToAlreadyKnown(&client, this))
				// update the old client informations
				bIsMuleHello = client->ProcessHelloPacket(packet, size);
			else {
				theApp.clientlist->AddClient(client);
				client->SetCommentDirty();
			}

			theApp.emuledlg->transferwnd->GetClientList()->RefreshClient(client);

			// send a response packet with standard informations
			if (client->GetHashType() == SO_EMULE && !bIsMuleHello)
				client->SendMuleInfoPacket(false);

			client->SendHelloAnswer();

			if (client)
				client->ConnectionEstablished();

			ASSERT(client);
			if (client) {
				// start secure identification, if
				//	- we have received eMule-OP_HELLO (new eMule)
				if (client->GetInfoPacketsReceived() == IP_BOTH)
					client->InfoPacketsReceived();

				if (client->GetKadPort() && client->GetKadVersion() >= KADEMLIA_VERSION2_47a)
					Kademlia::CKademlia::Bootstrap(ntohl(client->GetIP()), client->GetKadPort());
			}
		}
		break;
	case OP_REQUESTFILENAME:
		{
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugRecv("OP_FileRequest", client, (size >= 16) ? packet : NULL);
			theStats.AddDownDataOverheadFileRequest(size);

			if (size >= 16) {
				if (!client->GetWaitStartTime())
					client->SetWaitStartTime();

				CSafeMemFile data_in(packet, size);
				uchar reqfilehash[MDX_DIGEST_SIZE];
				data_in.ReadHash16(reqfilehash);

				CKnownFile *reqfile = theApp.sharedfiles->GetFileByID(reqfilehash);
				if (reqfile == NULL) {
					reqfile = theApp.downloadqueue->GetFileByID(reqfilehash);
					if (reqfile == NULL || (uint64)((CPartFile*)reqfile)->GetCompletedSize() < PARTSIZE) {
						client->CheckFailedFileIdReqs(reqfilehash);
						break;
					}
				}

				if (reqfile->IsLargeFile() && !client->SupportsLargeFiles()) {
					DebugLogWarning(_T("Client without 64bit file support requested large file; %s, File=\"%s\""), (LPCTSTR)client->DbgGetClientInfo(), (LPCTSTR)reqfile->GetFileName());
					break;
				}

				// check to see if this is a new file they are asking for
				if (!md4equ(client->GetUploadFileID(), reqfilehash))
					client->SetCommentDirty();
				client->SetUploadFileID(reqfile);

				if (!client->ProcessExtendedInfo(data_in, reqfile)) {
					if (thePrefs.GetDebugClientTCPLevel() > 0)
						DebugSend("OP_FileReqAnsNoFil", client, packet);
					Packet *replypacket = new Packet(OP_FILEREQANSNOFIL, 16);
					md4cpy(replypacket->pBuffer, reqfile->GetFileHash());
					theStats.AddUpDataOverheadFileRequest(replypacket->size);
					SendPacket(replypacket);
					DebugLogWarning(_T("Partcount mismatch on requested file, sending FNF; %s, File=\"%s\""), (LPCTSTR)client->DbgGetClientInfo(), (LPCTSTR)reqfile->GetFileName());
					break;
				}

				// if we are downloading this file, this could be a new source
				// no passive adding of files with only one part
				if (reqfile->IsPartFile() && (uint64)reqfile->GetFileSize() > PARTSIZE)
					if (static_cast<CPartFile*>(reqfile)->GetMaxSources() > static_cast<CPartFile*>(reqfile)->GetSourceCount())
						theApp.downloadqueue->CheckAndAddKnownSource(static_cast<CPartFile*>(reqfile), client, true);

				// send filename etc
				CSafeMemFile data_out(128);
				data_out.WriteHash16(reqfile->GetFileHash());
				data_out.WriteString(reqfile->GetFileName(), client->GetUnicodeSupport());
				Packet *packet1 = new Packet(data_out);
				packet1->opcode = OP_REQFILENAMEANSWER;
				if (thePrefs.GetDebugClientTCPLevel() > 0)
					DebugSend("OP_FileReqAnswer", client, reqfile->GetFileHash());
				theStats.AddUpDataOverheadFileRequest(packet1->size);
				SendPacket(packet1);

				client->SendCommentInfo(reqfile);
				break;
			}
		}
		throw GetResString(IDS_ERR_WRONGPACKETSIZE);
	case OP_SETREQFILEID:
		{
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugRecv("OP_SetReqFileID", client, (size >= 16) ? packet : NULL);
			theStats.AddDownDataOverheadFileRequest(size);

			if (size == 16) {
				if (!client->GetWaitStartTime())
					client->SetWaitStartTime();

				CKnownFile *reqfile = theApp.sharedfiles->GetFileByID(packet);
				if (reqfile == NULL) {
					reqfile = theApp.downloadqueue->GetFileByID(packet);
					if (reqfile == NULL)
						break;
					if (reqfile->GetFileSize() > PARTSIZE) {
					 // send file request no such file packet (0x48)
						if (thePrefs.GetDebugClientTCPLevel() > 0)
							DebugSend("OP_FileReqAnsNoFil", client, packet);
						Packet *replypacket = new Packet(OP_FILEREQANSNOFIL, 16);
						md4cpy(replypacket->pBuffer, packet);
						theStats.AddUpDataOverheadFileRequest(replypacket->size);
						SendPacket(replypacket);
						client->CheckFailedFileIdReqs(packet);
						break;
					}
				}
				if (reqfile->IsLargeFile() && !client->SupportsLargeFiles()) {
					if (thePrefs.GetDebugClientTCPLevel() > 0)
						DebugSend("OP_FileReqAnsNoFil", client, packet);
					Packet *replypacket = new Packet(OP_FILEREQANSNOFIL, 16);
					md4cpy(replypacket->pBuffer, packet);
					theStats.AddUpDataOverheadFileRequest(replypacket->size);
					SendPacket(replypacket);
					DebugLogWarning(_T("Client without 64bit file support requested large file; %s, File=\"%s\""), (LPCTSTR)client->DbgGetClientInfo(), (LPCTSTR)reqfile->GetFileName());
					break;
				}

				// check to see if this is a new file they are asking for
				if (!md4equ(client->GetUploadFileID(), packet))
					client->SetCommentDirty();

				client->SetUploadFileID(reqfile);

				// send file status
				CSafeMemFile data(16 + 16);
				data.WriteHash16(reqfile->GetFileHash());
				if (reqfile->IsPartFile())
					static_cast<CPartFile*>(reqfile)->WritePartStatus(data);
				else
					data.WriteUInt16(0);
				Packet *packet2 = new Packet(data);
				packet2->opcode = OP_FILESTATUS;
				if (thePrefs.GetDebugClientTCPLevel() > 0)
					DebugSend("OP_FileStatus", client, reqfile->GetFileHash());
				theStats.AddUpDataOverheadFileRequest(packet2->size);
				SendPacket(packet2);
				break;
			}
		}
		throw GetResString(IDS_ERR_WRONGPACKETSIZE);
	case OP_FILEREQANSNOFIL:
		if (thePrefs.GetDebugClientTCPLevel() > 0)
			DebugRecv("OP_FileReqAnsNoFil", client, (size >= 16) ? packet : NULL);
		theStats.AddDownDataOverheadFileRequest(size);
		if (size == 16) {
			CPartFile *rqfile = theApp.downloadqueue->GetFileByID(packet);
			if (!rqfile) {
				client->CheckFailedFileIdReqs(packet);
				break;
			}
			rqfile->m_DeadSourceList.AddDeadSource(*client);
			// if that client does not have my file maybe has another different
			// we try to swap to another file ignoring no needed parts files
			switch (client->GetDownloadState()) {
			case DS_CONNECTED:
			case DS_ONQUEUE:
			case DS_NONEEDEDPARTS:
				client->DontSwapTo(rqfile); // ZZ:DownloadManager
				if (!client->SwapToAnotherFile(_T("Source says it doesn't have the file. CClientReqSocket::ProcessPacket()"), true, true, true, NULL, false, false)) // ZZ:DownloadManager
					theApp.downloadqueue->RemoveSource(client);
			}
			break;
		}
		throw GetResString(IDS_ERR_WRONGPACKETSIZE);
	case OP_REQFILENAMEANSWER:
		{
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugRecv("OP_FileReqAnswer", client, (size >= 16) ? packet : NULL);
			theStats.AddDownDataOverheadFileRequest(size);

			CSafeMemFile data(packet, size);
			uchar cfilehash[MDX_DIGEST_SIZE];
			data.ReadHash16(cfilehash);
			CPartFile *file = theApp.downloadqueue->GetFileByID(cfilehash);
			if (file == NULL)
				client->CheckFailedFileIdReqs(cfilehash);
			client->ProcessFileInfo(data, file);
		}
		break;
	case OP_FILESTATUS:
		{
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugRecv("OP_FileStatus", client, (size >= 16) ? packet : NULL);
			theStats.AddDownDataOverheadFileRequest(size);

			CSafeMemFile data(packet, size);
			uchar cfilehash[MDX_DIGEST_SIZE];
			data.ReadHash16(cfilehash);
			CPartFile *file = theApp.downloadqueue->GetFileByID(cfilehash);
			if (file == NULL)
				client->CheckFailedFileIdReqs(cfilehash);
			client->ProcessFileStatus(false, data, file);
		}
		break;
	case OP_STARTUPLOADREQ:
		if (thePrefs.GetDebugClientTCPLevel() > 0)
			DebugRecv("OP_StartUpLoadReq", client, (size >= 16) ? packet : NULL);
		theStats.AddDownDataOverheadFileRequest(size);

		if (!client->CheckHandshakeFinished())
			break;
		if (size == 16) {
			CKnownFile *reqfile = theApp.sharedfiles->GetFileByID(packet);
			if (reqfile) {
				if (!md4equ(client->GetUploadFileID(), packet))
					client->SetCommentDirty();
				client->SetUploadFileID(reqfile);
				client->SendCommentInfo(reqfile);
				theApp.uploadqueue->AddClientToQueue(client);
			} else
				client->CheckFailedFileIdReqs(packet);
		}
		break;
	case OP_QUEUERANK:
		if (thePrefs.GetDebugClientTCPLevel() > 0)
			DebugRecv("OP_QueueRank", client);
		theStats.AddDownDataOverheadFileRequest(size);
		client->ProcessEdonkeyQueueRank(packet, size);
		break;
	case OP_ACCEPTUPLOADREQ:
		if (thePrefs.GetDebugClientTCPLevel() > 0) {
			DebugRecv("OP_AcceptUploadReq", client, (size >= 16) ? packet : NULL);
			if (size > 0)
				Debug(_T("  ***NOTE: Packet contains %u additional bytes\n"), size);
			Debug(_T("  QR=%d\n"), client->IsRemoteQueueFull() ? UINT_MAX : client->GetRemoteQueueRank());
		}
		theStats.AddDownDataOverheadFileRequest(size);
		client->ProcessAcceptUpload();
		break;
	case OP_REQUESTPARTS:
		{
			// see also OP_REQUESTPARTS_I64
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugRecv("OP_RequestParts", client, (size >= 16) ? packet : NULL);
			theStats.AddDownDataOverheadFileRequest(size);

			CSafeMemFile data(packet, size);
			uchar reqfilehash[MDX_DIGEST_SIZE];
			data.ReadHash16(reqfilehash);

			uint32 aOffset[3 * 2]; //3 starts, then 3 ends
			for (unsigned i = 0; i < 3 * 2; ++i)
				aOffset[i] = data.ReadUInt32();

			if (thePrefs.GetDebugClientTCPLevel() > 0)
				for (unsigned i = 0; i < 3; ++i)
					Debug(_T("  Start[%u]=%u  End[%u]=%u  Size=%u\n"), i, aOffset[i], i, aOffset[i + 3], aOffset[i + 3] - aOffset[i]);

			for (unsigned i = 0; i < 3; ++i) { // BUG-007 FIX: explicit braces
				if (aOffset[i] < aOffset[i + 3]) {
					Requested_Block_Struct *reqblock = new Requested_Block_Struct;
					reqblock->StartOffset = aOffset[i];
					reqblock->EndOffset = aOffset[i + 3];
					md4cpy(reqblock->FileID, reqfilehash);
					reqblock->transferred = 0;
					client->AddReqBlock(reqblock, false);
				} else if (thePrefs.GetVerbose() && (aOffset[i + 3] != 0 || aOffset[i] != 0))
					DebugLogWarning(_T("Client requests invalid %u. file block %u-%u (%d bytes): %s"), i, aOffset[i], aOffset[i + 3], aOffset[i + 3] - aOffset[i], (LPCTSTR)client->DbgGetClientInfo());

			} // BUG-007 FIX: end for-loop body
			client->AddReqBlock(NULL, true);
		}
		break;
	case OP_CANCELTRANSFER:
		if (thePrefs.GetDebugClientTCPLevel() > 0)
			DebugRecv("OP_CancelTransfer", client);
		theStats.AddDownDataOverheadFileRequest(size);
		theApp.uploadqueue->RemoveFromUploadQueue(client, _T("Remote client cancelled transfer."));
		break;
	case OP_END_OF_DOWNLOAD:
		if (thePrefs.GetDebugClientTCPLevel() > 0)
			DebugRecv("OP_EndOfDownload", client, (size >= 16) ? packet : NULL);
		theStats.AddDownDataOverheadFileRequest(size);
		if (size >= 16 && md4equ(client->GetUploadFileID(), packet))
			theApp.uploadqueue->RemoveFromUploadQueue(client, _T("Remote client ended transfer."));
		else if (size >= 16) // BUG-010 FIX: prevent OOB read
			client->CheckFailedFileIdReqs(packet);
		break;
	case OP_HASHSETREQUEST:
		if (thePrefs.GetDebugClientTCPLevel() > 0)
			DebugRecv("OP_HashSetReq", client, (size >= 16) ? packet : NULL);
		theStats.AddDownDataOverheadFileRequest(size);

		if (size != 16)
			throw GetResString(IDS_ERR_WRONGHPACKETSIZE);
		client->SendHashsetPacket(packet, 16, false);
		break;
	case OP_HASHSETANSWER:
		if (thePrefs.GetDebugClientTCPLevel() > 0)
			DebugRecv("OP_HashSetAnswer", client, (size >= 16) ? packet : NULL);
		theStats.AddDownDataOverheadFileRequest(size);
		client->ProcessHashSet(packet, size, false);
		break;
	case OP_SENDINGPART:
		{
			// see also OP_SENDINGPART_I64
			if (thePrefs.GetDebugClientTCPLevel() > 1)
				DebugRecv("OP_SendingPart", client, (size >= 16) ? packet : NULL);
			theStats.AddDownDataOverheadFileRequest(16 + 2 * 4);
			client->CheckHandshakeFinished();
			EDownloadState newDS = DS_NONE;
			const CPartFile *creqfile = client->GetRequestFile();
			if (creqfile) {
				if (!creqfile->IsStopped() && (creqfile->GetStatus() == PS_READY || creqfile->GetStatus() == PS_EMPTY)) {
					client->ProcessBlockPacket(packet, size, false, false);
					// BUG-006 FIX: Added parentheses to fix operator precedence
					if (!creqfile->IsStopped() && (creqfile->GetStatus() == PS_PAUSED || creqfile->GetStatus() == PS_ERROR))
						newDS = DS_ONQUEUE;
					else
						newDS = DS_CONNECTED; //any state but DS_NONE or DS_ONQUEUE
				}
			}
			if (newDS != DS_CONNECTED && client) { //client could have been deleted while debugging
				client->SendCancelTransfer();
				client->SetDownloadState(newDS);
			}
		}
		break;
	case OP_OUTOFPARTREQS:
		if (thePrefs.GetDebugClientTCPLevel() > 0)
			DebugRecv("OP_OutOfPartReqs", client);
		theStats.AddDownDataOverheadFileRequest(size);
		if (client->GetDownloadState() == DS_DOWNLOADING)
			client->SetDownloadState(DS_ONQUEUE, _T("The remote client decided to stop/complete the transfer (got OP_OutOfPartReqs)."));
		break;
	case OP_CHANGE_CLIENT_ID:
		if (size < 8) {
			throwCStr(_T("invalid OP_CHANGE_CLIENT_ID packet"));
		}
		{
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugRecv("OP_ChangedClientID", client);
			theStats.AddDownDataOverheadOther(size);

			CSafeMemFile data(packet, size);
			uint32 nNewUserID = data.ReadUInt32();
			uint32 nNewServerIP = data.ReadUInt32();
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				Debug(_T("  NewUserID=%u (%08x, %s)  NewServerIP=%u (%08x, %s)\n"), nNewUserID, nNewUserID, (LPCTSTR)ipstr(nNewUserID), nNewServerIP, nNewServerIP, (LPCTSTR)ipstr(nNewServerIP));
			if (::IsLowID(nNewUserID)) { // client changed server and has a LowID
				CServer *pNewServer = theApp.serverlist->GetServerByIP(nNewServerIP);
				if (pNewServer != NULL) {
					client->SetUserIDHybrid(nNewUserID); // update UserID only if we know the server
					client->SetServerIP(nNewServerIP);
					client->SetServerPort(pNewServer->GetPort());
				}
			} else if (nNewUserID == client->GetIP()) {	// client changed server and has a HighID(IP)
				client->SetUserIDHybrid(ntohl(nNewUserID));
				CServer *pNewServer = theApp.serverlist->GetServerByIP(nNewServerIP);
				if (pNewServer != NULL) {
					client->SetServerIP(nNewServerIP);
					client->SetServerPort(pNewServer->GetPort());
				}
			} else if (thePrefs.GetDebugClientTCPLevel() > 0)
				Debug(_T("***NOTE: OP_ChangedClientID unknown contents\n"));

			UINT uAddData = (UINT)(data.GetLength() - data.GetPosition());
			if (uAddData > 0 && thePrefs.GetDebugClientTCPLevel() > 0)
				Debug(_T("***NOTE: OP_ChangedClientID contains add. data %s\n"), (LPCTSTR)DbgGetHexDump(packet + data.GetPosition(), uAddData));
		}
		break;
	case OP_CHANGE_SLOT:
		if (thePrefs.GetDebugClientTCPLevel() > 0)
			DebugRecv("OP_ChangeSlot", client, (size >= 16) ? packet : NULL);
		theStats.AddDownDataOverheadFileRequest(size);
		// sometimes sent by Hybrid
		break;
	case OP_MESSAGE:
		{
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugRecv("OP_Message", client);
			theStats.AddDownDataOverheadOther(size);

			if (size < 2)
				throwCStr(_T("invalid message packet"));
			CSafeMemFile data(packet, size);
			UINT length = data.ReadUInt16();
			if (length + 2 > size)
				throwCStr(_T("invalid message packet"));

			if (length > MAX_CLIENT_MSG_LEN) {
				if (thePrefs.GetVerbose())
					AddDebugLogLine(false, _T("Message from '%s' (IP:%s) exceeds limit by %u chars, truncated."), client->GetUserName(), (LPCTSTR)ipstr(client->GetConnectIP()), length - MAX_CLIENT_MSG_LEN);
				length = MAX_CLIENT_MSG_LEN;
			}

			client->ProcessChatMessage(data, length);
		}
		break;
	case OP_ASKSHAREDFILES:
		{
			// client wants to know what we have in share, let's see if we allow him to know that
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugRecv("OP_AskSharedFiles", client);
			theStats.AddDownDataOverheadOther(size);

			CPtrList list;
			if (thePrefs.CanSeeShares() == vsfaEverybody || (thePrefs.CanSeeShares() == vsfaFriends && client->IsFriend())) {
				for (const CKnownFilesMap::CPair *pair = theApp.sharedfiles->m_Files_map.PGetFirstAssoc(); pair != NULL; pair = theApp.sharedfiles->m_Files_map.PGetNextAssoc(pair))
					if (!pair->value->IsLargeFile() || client->SupportsLargeFiles())
						list.AddTail((void*)pair->value);

				AddLogLine(true, GetResString(IDS_REQ_SHAREDFILES), (LPCTSTR)client->GetUserName(), client->GetUserIDHybrid(), (LPCTSTR)GetResString(IDS_ACCEPTED));
			} else
				DebugLog(GetResString(IDS_REQ_SHAREDFILES), client->GetUserName(), client->GetUserIDHybrid(), (LPCTSTR)GetResString(IDS_DENIED));

			// now create the memfile for the packet
			CSafeMemFile tempfile(80);
			tempfile.WriteUInt32((uint32)list.GetCount());
			while (!list.IsEmpty())
				theApp.sharedfiles->CreateOfferedFilePacket(reinterpret_cast<CKnownFile*>(list.RemoveHead()), tempfile, NULL, client);

			// create a packet and send it
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugSend("OP_AskSharedFilesAnswer", client);
			Packet *replypacket = new Packet(tempfile);
			replypacket->opcode = OP_ASKSHAREDFILESANSWER;
			theStats.AddUpDataOverheadOther(replypacket->size);
			SendPacket(replypacket, true);
		}
		break;
	case OP_ASKSHAREDFILESANSWER:
		if (thePrefs.GetDebugClientTCPLevel() > 0)
			DebugRecv("OP_AskSharedFilesAnswer", client);
		theStats.AddDownDataOverheadOther(size);
		client->ProcessSharedFileList(packet, size);
		break;
	case OP_ASKSHAREDDIRS:
		{
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugRecv("OP_AskSharedDirectories", client);
			theStats.AddDownDataOverheadOther(size);

			if (thePrefs.CanSeeShares() == vsfaEverybody || (thePrefs.CanSeeShares() == vsfaFriends && client->IsFriend())) {
				AddLogLine(true, GetResString(IDS_SHAREDREQ1), client->GetUserName(), client->GetUserIDHybrid(), (LPCTSTR)GetResString(IDS_ACCEPTED));
				client->SendSharedDirectories();
			} else {
				DebugLog(GetResString(IDS_SHAREDREQ1), client->GetUserName(), client->GetUserIDHybrid(), (LPCTSTR)GetResString(IDS_DENIED));
				if (thePrefs.GetDebugClientTCPLevel() > 0)
					DebugSend("OP_AskSharedDeniedAnswer", client);
				Packet *replypacket = new Packet(OP_ASKSHAREDDENIEDANS, 0);
				theStats.AddUpDataOverheadOther(replypacket->size);
				SendPacket(replypacket, true);
			}
		}
		break;
	case OP_ASKSHAREDFILESDIR:
		{
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugRecv("OP_AskSharedFilesInDirectory", client);
			theStats.AddDownDataOverheadOther(size);

			Packet *replypacket;
			CSafeMemFile data(packet, size);
			CString strReqDir(data.ReadString(client->GetUnicodeSupport() != UTF8strNone));
			if (thePrefs.CanSeeShares() == vsfaEverybody || (thePrefs.CanSeeShares() == vsfaFriends && client->IsFriend())) {
				AddLogLine(true, GetResString(IDS_SHAREDREQ2), (LPCTSTR)client->GetUserName(), client->GetUserIDHybrid(), (LPCTSTR)strReqDir, (LPCTSTR)GetResString(IDS_ACCEPTED));
				ASSERT(data.GetPosition() == data.GetLength());
				CTypedPtrList<CPtrList, CKnownFile*> list;
				const CString strOrgReqDir(strReqDir);
				if (strReqDir == OP_INCOMPLETE_SHARED_FILES) {
					for (POSITION pos = NULL; ;) { // get all shared files from download queue
						CPartFile *pFile = theApp.downloadqueue->GetFileNext(pos);
						if (pFile && pFile->GetStatus(true) == PS_READY && (!pFile->IsLargeFile() || client->SupportsLargeFiles()))
							list.AddTail(pFile);
						if (pos == NULL)
							break;
					}
				} else {
					bool bSingleSharedFiles = (strReqDir == OP_OTHER_SHARED_FILES);
					if (!bSingleSharedFiles)
						strReqDir = theApp.sharedfiles->GetDirNameByPseudo(strReqDir);
					if (!strReqDir.IsEmpty()) {
						// get all shared files from requested directory
						for (const CKnownFilesMap::CPair *pair = theApp.sharedfiles->m_Files_map.PGetFirstAssoc(); pair != NULL; pair = theApp.sharedfiles->m_Files_map.PGetNextAssoc(pair)) {
							CKnownFile *cur_file = pair->value;
							// all files not in shared directories have to be single shared files
							if (((!bSingleSharedFiles && EqualPaths(strReqDir, cur_file->GetSharedDirectory()))
								|| (bSingleSharedFiles && !theApp.sharedfiles->ShouldBeShared(cur_file->GetSharedDirectory(), NULL, false))
								)
								&& (!cur_file->IsLargeFile() || client->SupportsLargeFiles()))
							{
								list.AddTail(cur_file);
							}
						}
					} else
						DebugLogError(_T("View shared files: Pseudonym for requested Directory (%s) was not found - sending empty result"), (LPCTSTR)strOrgReqDir);
				}

				// Currently we are sending each shared directory, even if it does not contain any files.
				// Because of this we also have to send an empty shared files list.
				CSafeMemFile tempfile(80);
				tempfile.WriteString(strOrgReqDir, client->GetUnicodeSupport());
				tempfile.WriteUInt32((uint32)list.GetCount());
				while (!list.IsEmpty())
					theApp.sharedfiles->CreateOfferedFilePacket(list.RemoveHead(), tempfile, NULL, client);

				if (thePrefs.GetDebugClientTCPLevel() > 0)
					DebugSend("OP_AskSharedFilesInDirectoryAnswer", client);
				replypacket = new Packet(tempfile);
				replypacket->opcode = OP_ASKSHAREDFILESDIRANS;
			} else {
				DebugLog(GetResString(IDS_SHAREDREQ2), client->GetUserName(), client->GetUserIDHybrid(), (LPCTSTR)strReqDir, (LPCTSTR)GetResString(IDS_DENIED));
				if (thePrefs.GetDebugClientTCPLevel() > 0)
					DebugSend("OP_AskSharedDeniedAnswer", client);
				replypacket = new Packet(OP_ASKSHAREDDENIEDANS, 0);
			}
			theStats.AddUpDataOverheadOther(replypacket->size);
			SendPacket(replypacket, true);
		}
		break;
	case OP_ASKSHAREDDIRSANS:
		{
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugRecv("OP_AskSharedDirectoriesAnswer", client);
			theStats.AddDownDataOverheadOther(size);
			if (client->GetFileListRequested() == 1) {
				CSafeMemFile data(packet, size);
				uint32 uDirs = data.ReadUInt32();
				for (uint32 i = uDirs; i > 0; --i) {
					const CString &strDir(data.ReadString(client->GetUnicodeSupport() != UTF8strNone));
					// Better send the received and untouched directory string back to that client
					AddLogLine(true, GetResString(IDS_SHAREDANSW), client->GetUserName(), client->GetUserIDHybrid(), (LPCTSTR)strDir);

					if (thePrefs.GetDebugClientTCPLevel() > 0)
						DebugSend("OP_AskSharedFilesInDirectory", client);
					CSafeMemFile tempfile(80);
					tempfile.WriteString(strDir, client->GetUnicodeSupport());
					Packet *replypacket = new Packet(tempfile);
					replypacket->opcode = OP_ASKSHAREDFILESDIR;
					theStats.AddUpDataOverheadOther(replypacket->size);
					SendPacket(replypacket, true);
				}
				ASSERT(data.GetPosition() == data.GetLength());
				client->SetFileListRequested(uDirs);
			} else
				AddLogLine(true, GetResString(IDS_SHAREDANSW2), client->GetUserName(), client->GetUserIDHybrid());
		}
		break;
	case OP_ASKSHAREDFILESDIRANS:
		{
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugRecv("OP_AskSharedFilesInDirectoryAnswer", client);
			theStats.AddDownDataOverheadOther(size);

			CSafeMemFile data(packet, size);
			CString strDir(data.ReadString(client->GetUnicodeSupport() != UTF8strNone));

			if (client->GetFileListRequested() > 0) {
				AddLogLine(true, GetResString(IDS_SHAREDINFO1), client->GetUserName(), client->GetUserIDHybrid(), (LPCTSTR)strDir);
				client->ProcessSharedFileList(packet + data.GetPosition(), (uint32)(size - data.GetPosition()), strDir);
				if (client->GetFileListRequested() == 0)
					AddLogLine(true, GetResString(IDS_SHAREDINFO2), client->GetUserName(), client->GetUserIDHybrid());
			} else
				AddLogLine(true, GetResString(IDS_SHAREDANSW3), client->GetUserName(), client->GetUserIDHybrid(), (LPCTSTR)strDir);
		}
		break;
	case OP_ASKSHAREDDENIEDANS:
		if (thePrefs.GetDebugClientTCPLevel() > 0)
			DebugRecv("OP_AskSharedDeniedAnswer", client);
		theStats.AddDownDataOverheadOther(size);

		AddLogLine(true, GetResString(IDS_SHAREDREQDENIED), client->GetUserName(), client->GetUserIDHybrid());
		client->SetFileListRequested(0);
		break;
	default:
		theStats.AddDownDataOverheadOther(size);
		PacketToDebugLogLine(_T("eDonkey"), packet, size, opcode);
	}
	return true;
}

bool CClientReqSocket::ProcessExtPacket(const BYTE *packet, uint32 size, UINT opcode, UINT uRawSize)
{
	try {
		// v7.7.0 — range now includes 0xCC (OP_LIVE_CHUNK_V2). OP_LIVE_PEER_LIST=0xCA,
		// PONG=0xCB, CHUNK_V2=0xCC; bump the upper bound accordingly.
		if (opcode >= OP_LIVE_ANNOUNCE && opcode <= OP_LIVE_CHUNK_V2 && !client->SupportsLiveP2P()) {
			theStats.AddDownDataOverheadOther(uRawSize);
			DebugLogWarning(_T("Ignoring eSE live opcode 0x%02X from non-eSE client %s"),
				opcode, (LPCTSTR)client->DbgGetClientInfo());
			return true;
		}

		switch (opcode) {
		case OP_MULTIPACKET: // deprecated
		case OP_MULTIPACKET_EXT: // deprecated
		case OP_MULTIPACKET_EXT2:
			{
				if (thePrefs.GetDebugClientTCPLevel() > 0)
					if (opcode == OP_MULTIPACKET)
						DebugRecv("OP_MultiPacket", client, (size >= 16) ? packet : NULL);
					else
						DebugRecv((opcode == OP_MULTIPACKET_EXT2 ? "OP_MultiPacket_Ext2" : "OP_MultiPacket_Ext"), client, (size >= 24) ? packet : NULL);

				theStats.AddDownDataOverheadFileRequest(uRawSize);
				client->CheckHandshakeFinished();

				if (client->GetKadPort() && client->GetKadVersion() >= KADEMLIA_VERSION2_47a)
					Kademlia::CKademlia::Bootstrap(ntohl(client->GetIP()), client->GetKadPort());

				CSafeMemFile data_in(packet, size);
				CKnownFile *reqfile;
				bool bNotFound = false;
				uchar reqfilehash[MDX_DIGEST_SIZE];
				if (opcode == OP_MULTIPACKET_EXT2) { // file identifier support
					CFileIdentifierSA fileIdent;
					if (!fileIdent.ReadIdentifier(data_in)) {
						DebugLogWarning(_T("Error while reading file identifier from MultiPacket_Ext2 - %s"), (LPCTSTR)client->DbgGetClientInfo());
						break;
					}
					md4cpy(reqfilehash, fileIdent.GetMD4Hash()); // need this in case we want to sent a FNF
					reqfile = theApp.sharedfiles->GetFileByID(fileIdent.GetMD4Hash());
					if (reqfile == NULL) {
						reqfile = theApp.downloadqueue->GetFileByID(fileIdent.GetMD4Hash());
						if (reqfile == NULL || (uint64)((CPartFile*)reqfile)->GetCompletedSize() < PARTSIZE) {
							bNotFound = true;
							client->CheckFailedFileIdReqs(fileIdent.GetMD4Hash());
						}
					}
					if (!bNotFound && !reqfile->GetFileIdentifier().CompareRelaxed(fileIdent)) {
						bNotFound = true;
						DebugLogWarning(_T("FileIdentifier Mismatch on requested file, sending FNF; %s, File=\"%s\", Local Ident: %s, Received Ident: %s"), (LPCTSTR)client->DbgGetClientInfo()
							, (LPCTSTR)reqfile->GetFileName(), (LPCTSTR)reqfile->GetFileIdentifier().DbgInfo(), (LPCTSTR)fileIdent.DbgInfo());
					}
				} else { // no file identifier
					data_in.ReadHash16(reqfilehash);
					uint64 nSize = (opcode == OP_MULTIPACKET_EXT) ? data_in.ReadUInt64() : 0;
					reqfile = theApp.sharedfiles->GetFileByID(reqfilehash);
					if (reqfile == NULL) {
						reqfile = theApp.downloadqueue->GetFileByID(reqfilehash);
						if (reqfile == NULL || (uint64)((CPartFile*)reqfile)->GetCompletedSize() < PARTSIZE) {
							bNotFound = true;
							client->CheckFailedFileIdReqs(reqfilehash);
						}
					}
					if (!bNotFound && nSize != 0 && nSize != reqfile->GetFileSize()) {
						bNotFound = true;
						DebugLogWarning(_T("Size Mismatch on requested file, sending FNF; %s, File=\"%s\""), (LPCTSTR)client->DbgGetClientInfo(), (LPCTSTR)reqfile->GetFileName());
					}
				}

				if (!bNotFound && reqfile->IsLargeFile() && !client->SupportsLargeFiles()) {
					bNotFound = true;
					DebugLogWarning(_T("Client without 64bit file support requested large file; %s, File=\"%s\""), (LPCTSTR)client->DbgGetClientInfo(), (LPCTSTR)reqfile->GetFileName());
				}
				if (bNotFound) {
					// send file request answer - no such file packet (0x48)
					if (thePrefs.GetDebugClientTCPLevel() > 0)
						DebugSend("OP_FileReqAnsNoFil", client, packet);
					Packet *replypacket = new Packet(OP_FILEREQANSNOFIL, 16);
					md4cpy(replypacket->pBuffer, reqfilehash);
					theStats.AddUpDataOverheadFileRequest(replypacket->size);
					SendPacket(replypacket);
					break;
				}

				if (!client->GetWaitStartTime())
					client->SetWaitStartTime();

				// if we are downloading this file, this could be a new source
				// no passive adding of files with only one part
				if (reqfile->IsPartFile() && (uint64)reqfile->GetFileSize() > PARTSIZE)
					if (static_cast<CPartFile*>(reqfile)->GetMaxSources() > static_cast<CPartFile*>(reqfile)->GetSourceCount())
						theApp.downloadqueue->CheckAndAddKnownSource(static_cast<CPartFile*>(reqfile), client, true);

				// check to see if this is a new file they are asking for
				if (!md4equ(client->GetUploadFileID(), reqfile->GetFileHash()))
					client->SetCommentDirty();

				client->SetUploadFileID(reqfile);

				CSafeMemFile data_out(128);
				if (opcode == OP_MULTIPACKET_EXT2) // file identifier support
					reqfile->GetFileIdentifierC().WriteIdentifier(data_out);
				else
					data_out.WriteHash16(reqfile->GetFileHash());
				bool bAnswerFNF = false;
				while (data_in.GetLength() > data_in.GetPosition() && !bAnswerFNF) {
					uint8 opcode_in = data_in.ReadUInt8();
					switch (opcode_in) {
					case OP_REQUESTFILENAME:
						if (thePrefs.GetDebugClientTCPLevel() > 0)
							DebugRecv("OP_MPReqFileName", client, packet);

						if (!client->ProcessExtendedInfo(data_in, reqfile)) {
							if (thePrefs.GetDebugClientTCPLevel() > 0)
								DebugSend("OP_FileReqAnsNoFil", client, packet);
							Packet *replypacket = new Packet(OP_FILEREQANSNOFIL, 16);
							md4cpy(replypacket->pBuffer, reqfile->GetFileHash());
							theStats.AddUpDataOverheadFileRequest(replypacket->size);
							SendPacket(replypacket);
							DebugLogWarning(_T("Partcount mismatch on requested file, sending FNF; %s, File=\"%s\""), (LPCTSTR)client->DbgGetClientInfo(), (LPCTSTR)reqfile->GetFileName());
							bAnswerFNF = true;
						} else {
							data_out.WriteUInt8(OP_REQFILENAMEANSWER);
							data_out.WriteString(reqfile->GetFileName(), client->GetUnicodeSupport());
						}
						break;
					case OP_AICHFILEHASHREQ:
						if (thePrefs.GetDebugClientTCPLevel() > 0)
							DebugRecv("OP_MPAichFileHashReq", client, packet);

						if (client->SupportsFileIdentifiers() || opcode == OP_MULTIPACKET_EXT2) // not allowed any more with file idents supported
							DebugLogWarning(_T("Client requested AICH Hash packet, but supports FileIdentifiers, ignored - %s"), (LPCTSTR)client->DbgGetClientInfo());
						else if (client->IsSupportingAICH() && reqfile->GetFileIdentifier().HasAICHHash()) {
							data_out.WriteUInt8(OP_AICHFILEHASHANS);
							reqfile->GetFileIdentifier().GetAICHHash().Write(data_out);
						}
						break;
					case OP_SETREQFILEID:
						if (thePrefs.GetDebugClientTCPLevel() > 0)
							DebugRecv("OP_MPSetReqFileID", client, packet);

						data_out.WriteUInt8(OP_FILESTATUS);
						if (reqfile->IsPartFile())
							static_cast<CPartFile*>(reqfile)->WritePartStatus(data_out);
						else
							data_out.WriteUInt16(0);
						break;
					//We still send the source packet separately.
					case OP_REQUESTSOURCES2:
					case OP_REQUESTSOURCES:
						{
							if (thePrefs.GetDebugClientTCPLevel() > 0)
								DebugRecv(opcode_in == OP_REQUESTSOURCES ? "OP_MPReqSources2" : "OP_MPReqSources", client, packet);

							if (thePrefs.GetDebugSourceExchange())
								AddDebugLogLine(false, _T("SXRecv: Client source request; %s, File=\"%s\""), (LPCTSTR)client->DbgGetClientInfo(), (LPCTSTR)reqfile->GetFileName());

							uint8 byRequestedVersion = 0;
							uint16 byRequestedOptions = 0;
							if (opcode_in == OP_REQUESTSOURCES2) { // SX2 requests contains additional data
								byRequestedVersion = data_in.ReadUInt8();
								byRequestedOptions = data_in.ReadUInt16();
							}
							//Although this shouldn't happen, it's just in case for any Mods that mess with version numbers.
							if (byRequestedVersion > 0 || client->GetSourceExchange1Version() > 1) {
								DWORD dwTimePassed = ::GetTickCount() - client->GetLastSrcReqTime() + CONNECTION_LATENCY;
								bool bNeverAskedBefore = client->GetLastSrcReqTime() == 0;
								if ( //if not complete and file is rare
									(reqfile->IsPartFile()
										&& (bNeverAskedBefore || dwTimePassed > SOURCECLIENTREASKS)
										&& static_cast<CPartFile*>(reqfile)->GetSourceCount() <= RARE_FILE
									)
										//OR if file is not rare or is complete
									|| bNeverAskedBefore || dwTimePassed > SOURCECLIENTREASKS * MINCOMMONPENALTY
								   )
								{
									client->SetLastSrcReqTime();
									Packet *tosend = reqfile->CreateSrcInfoPacket(client, byRequestedVersion, byRequestedOptions);
									if (tosend) {
										if (thePrefs.GetDebugClientTCPLevel() > 0)
											DebugSend("OP_AnswerSources", client, reqfile->GetFileHash());
										theStats.AddUpDataOverheadSourceExchange(tosend->size);
										SendPacket(tosend);
									}
								}/* else if (thePrefs.GetVerbose())
									AddDebugLogLine(false, _T("RCV: Source Request too fast. (This is testing the new timers to see how much older client will not receive this)"));
								*/
							}
						}
						break;
					default:
						{
							CString strError;
							strError.Format(_T("Invalid sub opcode 0x%02x received"), opcode_in);
							throw strError;
						}
					}
				}
				if (data_out.GetLength() > 16 && !bAnswerFNF) {
					if (thePrefs.GetDebugClientTCPLevel() > 0)
						DebugSend("OP_MultiPacketAns", client, reqfile->GetFileHash());
					Packet *reply = new Packet(data_out, OP_EMULEPROT);
					reply->opcode = (opcode == OP_MULTIPACKET_EXT2) ? OP_MULTIPACKETANSWER_EXT2 : OP_MULTIPACKETANSWER;
					theStats.AddUpDataOverheadFileRequest(reply->size);
					SendPacket(reply);
				}
			}
			break;
		case OP_MULTIPACKETANSWER:
		case OP_MULTIPACKETANSWER_EXT2:
			{
				if (thePrefs.GetDebugClientTCPLevel() > 0)
					DebugRecv("OP_MultiPacketAns", client, (size >= 16) ? packet : NULL);
				theStats.AddDownDataOverheadFileRequest(uRawSize);
				client->CheckHandshakeFinished();

				if (client->GetKadPort() && client->GetKadVersion() >= KADEMLIA_VERSION2_47a)
					Kademlia::CKademlia::Bootstrap(ntohl(client->GetIP()), client->GetKadPort());

				CSafeMemFile data_in(packet, size);

				CPartFile *reqfile = NULL;
				if (opcode == OP_MULTIPACKETANSWER_EXT2) {
					CFileIdentifierSA fileIdent;
					if (!fileIdent.ReadIdentifier(data_in))
						throw GetResString(IDS_ERR_WRONGFILEID) + _T(" (OP_MULTIPACKETANSWER_EXT2; ReadIdentifier() failed)");
					reqfile = theApp.downloadqueue->GetFileByID(fileIdent.GetMD4Hash());
					if (reqfile == NULL) {
						client->CheckFailedFileIdReqs(fileIdent.GetMD4Hash());
						throw GetResString(IDS_ERR_WRONGFILEID) + _T(" (OP_MULTIPACKETANSWER_EXT2; reqfile==NULL)");
					}
					if (!reqfile->GetFileIdentifier().CompareRelaxed(fileIdent))
						throw GetResString(IDS_ERR_WRONGFILEID) + _T(" (OP_MULTIPACKETANSWER_EXT2; FileIdentifier mismatch)");
					if (fileIdent.HasAICHHash())
						client->ProcessAICHFileHash(NULL, reqfile, &fileIdent.GetAICHHash());
				} else {
					uchar reqfilehash[MDX_DIGEST_SIZE];
					data_in.ReadHash16(reqfilehash);
					reqfile = theApp.downloadqueue->GetFileByID(reqfilehash);
					//Make sure we are downloading this file.
					if (reqfile == NULL) {
						client->CheckFailedFileIdReqs(reqfilehash);
						throw GetResString(IDS_ERR_WRONGFILEID) + _T(" (OP_MULTIPACKETANSWER; reqfile==NULL)");
					}
				}
				if (client->GetRequestFile() == NULL)
					throw GetResString(IDS_ERR_WRONGFILEID) + _T(" (OP_MULTIPACKETANSWER; client->GetRequestFile()==NULL)");
				if (reqfile != client->GetRequestFile())
					throw GetResString(IDS_ERR_WRONGFILEID) + _T(" (OP_MULTIPACKETANSWER; reqfile!=client->GetRequestFile())");
				while (data_in.GetLength() > data_in.GetPosition()) {
					uint8 opcode_in = data_in.ReadUInt8();
					switch (opcode_in) {
					case OP_REQFILENAMEANSWER:
						if (thePrefs.GetDebugClientTCPLevel() > 0)
							DebugRecv("OP_MPReqFileNameAns", client, packet);

						client->ProcessFileInfo(data_in, reqfile);
						break;
					case OP_FILESTATUS:
						if (thePrefs.GetDebugClientTCPLevel() > 0)
							DebugRecv("OP_MPFileStatus", client, packet);

						client->ProcessFileStatus(false, data_in, reqfile);
						break;
					case OP_AICHFILEHASHANS:
						if (thePrefs.GetDebugClientTCPLevel() > 0)
							DebugRecv("OP_MPAichFileHashAns", client);

						client->ProcessAICHFileHash(&data_in, reqfile, NULL);
						break;
					default:
						{
							CString strError;
							strError.Format(_T("Invalid sub opcode 0x%02x received"), opcode_in);
							throw strError;
						}
					}
				}
			}
			break;
		case OP_EMULEINFO:
			theStats.AddDownDataOverheadOther(uRawSize);
			client->ProcessMuleInfoPacket(packet, size);
			if (thePrefs.GetDebugClientTCPLevel() > 0) {
				DebugRecv("OP_EmuleInfo", client);
				Debug(_T("  %s\n"), (LPCTSTR)client->DbgGetMuleInfo());
			}

			// start secure identification, if
			//  - we have received eD2K and eMule info (old eMule)
			if (client->GetInfoPacketsReceived() == IP_BOTH)
				client->InfoPacketsReceived();

			client->SendMuleInfoPacket(true);
			break;
		case OP_EMULEINFOANSWER:
			theStats.AddDownDataOverheadOther(uRawSize);
			client->ProcessMuleInfoPacket(packet, size);
			if (thePrefs.GetDebugClientTCPLevel() > 0) {
				DebugRecv("OP_EmuleInfoAnswer", client);
				Debug(_T("  %s\n"), (LPCTSTR)client->DbgGetMuleInfo());
			}

			// start secure identification, if
			//  - we have received eD2K and eMule info (old eMule)
			if (client->GetInfoPacketsReceived() == IP_BOTH)
				client->InfoPacketsReceived();
			break;
		case OP_SECIDENTSTATE:
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugRecv("OP_SecIdentState", client);
			theStats.AddDownDataOverheadOther(uRawSize);

			client->ProcessSecIdentStatePacket(packet, size);
			if (client->GetSecureIdentState() == IS_SIGNATURENEEDED)
				client->SendSignaturePacket();
			else if (client->GetSecureIdentState() == IS_KEYANDSIGNEEDED) {
				client->SendPublicKeyPacket();
				client->SendSignaturePacket();
			}
			break;
		case OP_PUBLICKEY:
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugRecv("OP_PublicKey", client);
			theStats.AddDownDataOverheadOther(uRawSize);

			client->ProcessPublicKeyPacket(packet, size);
			break;
		case OP_SIGNATURE:
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugRecv("OP_Signature", client);
			theStats.AddDownDataOverheadOther(uRawSize);

			client->ProcessSignaturePacket(packet, size);
			break;
		case OP_QUEUERANKING:
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugRecv("OP_QueueRanking", client);
			theStats.AddDownDataOverheadFileRequest(uRawSize);
			client->CheckHandshakeFinished();

			client->ProcessEmuleQueueRank(packet, size);
			break;
		case OP_REQUESTSOURCES:
		case OP_REQUESTSOURCES2:
			{
				CSafeMemFile data(packet, size);
				if (thePrefs.GetDebugClientTCPLevel() > 0)
					DebugRecv(opcode == OP_REQUESTSOURCES2 ? "OP_MPReqSources2" : "OP_MPReqSources", client, (size >= 16) ? packet : NULL);

				theStats.AddDownDataOverheadSourceExchange(uRawSize);
				client->CheckHandshakeFinished();

				uint8 byRequestedVersion = 0;
				uint16 byRequestedOptions = 0;
				if (opcode == OP_REQUESTSOURCES2) { // SX2 requests contains additional data
					byRequestedVersion = data.ReadUInt8();
					byRequestedOptions = data.ReadUInt16();
				}
				//Although this shouldn't happen, it's just in case to any Mods that mess with version numbers.
				if (byRequestedVersion > 0 || client->GetSourceExchange1Version() > 1) {
					if (size < 16)
						throw GetResString(IDS_ERR_BADSIZE);

					if (thePrefs.GetDebugSourceExchange())
						AddDebugLogLine(false, _T("SXRecv: Client source request; %s, %s"), (LPCTSTR)client->DbgGetClientInfo(), (LPCTSTR)DbgGetFileInfo(packet));

					//first check shared file list, then download list
					uchar ucHash[MDX_DIGEST_SIZE];
					data.ReadHash16(ucHash);
					CKnownFile *reqfile = theApp.sharedfiles->GetFileByID(ucHash);
					if (!reqfile)
						reqfile = theApp.downloadqueue->GetFileByID(ucHash);
					if (reqfile) {
						// There are some clients which do not follow the correct protocol procedure of sending
						// the sequence OP_REQUESTFILENAME, OP_SETREQFILEID, OP_REQUESTSOURCES. If those clients
						// are doing this, they will not get the optimal set of sources which we could offer if
						// the would follow the above noted protocol sequence. They better to it the right way
						// or they will get just a random set of sources because we do not know their download
						// part status which may get cleared with the call of 'SetUploadFileID'.
						client->SetUploadFileID(reqfile);

						DWORD dwTimePassed = ::GetTickCount() - client->GetLastSrcReqTime() + CONNECTION_LATENCY;
						bool bNeverAskedBefore = (client->GetLastSrcReqTime() == 0);
						if ( //if not complete and file is rare
							(reqfile->IsPartFile()
								&& (bNeverAskedBefore || dwTimePassed > SOURCECLIENTREASKS)
								&& static_cast<CPartFile*>(reqfile)->GetSourceCount() <= RARE_FILE
							)
								//OR if file is not rare or is complete
							|| bNeverAskedBefore || dwTimePassed > SOURCECLIENTREASKS * MINCOMMONPENALTY
						   )
						{
							client->SetLastSrcReqTime();
							Packet *tosend = reqfile->CreateSrcInfoPacket(client, byRequestedVersion, byRequestedOptions);
							if (tosend) {
								if (thePrefs.GetDebugClientTCPLevel() > 0)
									DebugSend("OP_AnswerSources", client, reqfile->GetFileHash());
								theStats.AddUpDataOverheadSourceExchange(tosend->size);
								SendPacket(tosend, true);
							}
						}
					} else
						client->CheckFailedFileIdReqs(ucHash);
				}
			}
			break;
		case OP_ANSWERSOURCES:
			{
				if (thePrefs.GetDebugClientTCPLevel() > 0)
					DebugRecv("OP_AnswerSources", client, (size >= 16) ? packet : NULL);
				theStats.AddDownDataOverheadSourceExchange(uRawSize);
				client->CheckHandshakeFinished();

				CSafeMemFile data(packet, size);
				uchar hash[MDX_DIGEST_SIZE];
				data.ReadHash16(hash);
				CKnownFile *file = theApp.downloadqueue->GetFileByID(hash);
				if (file == NULL)
					client->CheckFailedFileIdReqs(hash);
				else if (file->IsPartFile()) {
					//set the client's answer time
					client->SetLastSrcAnswerTime();
					//and set the file's last answer time
					static_cast<CPartFile*>(file)->SetLastAnsweredTime();
					static_cast<CPartFile*>(file)->AddClientSources(&data, client->GetSourceExchange1Version(), false, client);
				}
			}
			break;
		case OP_ANSWERSOURCES2:
			{
				if (thePrefs.GetDebugClientTCPLevel() > 0)
					DebugRecv("OP_AnswerSources2", client, (size >= 17) ? packet : NULL);
				theStats.AddDownDataOverheadSourceExchange(uRawSize);
				client->CheckHandshakeFinished();

				CSafeMemFile data(packet, size);
				uint8 byVersion = data.ReadUInt8();
				uchar hash[MDX_DIGEST_SIZE];
				data.ReadHash16(hash);
				CKnownFile *file = theApp.downloadqueue->GetFileByID(hash);
				if (file == NULL)
					client->CheckFailedFileIdReqs(hash);
				else if (file->IsPartFile()) {
					//set the client's answer time
					client->SetLastSrcAnswerTime();
					//and set the file's last answer time
					static_cast<CPartFile*>(file)->SetLastAnsweredTime();
					static_cast<CPartFile*>(file)->AddClientSources(&data, byVersion, true, client);
				}
			}
			break;
		case OP_FILEDESC:
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugRecv("OP_FileDesc", client);
			theStats.AddDownDataOverheadFileRequest(uRawSize);
			client->CheckHandshakeFinished();

			client->ProcessMuleCommentPacket(packet, size);
			break;
		case OP_REQUESTPREVIEW:
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugRecv("OP_RequestPreView", client, (size >= 16) ? packet : NULL);
			theStats.AddDownDataOverheadOther(uRawSize);
			client->CheckHandshakeFinished();

			if (thePrefs.CanSeeShares() == vsfaEverybody || (thePrefs.CanSeeShares() == vsfaFriends && client->IsFriend())) {
				if (thePrefs.GetVerbose())
					AddDebugLogLine(true, _T("Client '%s' (%s) requested Preview - accepted"), client->GetUserName(), (LPCTSTR)ipstr(client->GetConnectIP()));
				client->ProcessPreviewReq(packet, size);
			} else {
				// we don't send any answer here, because the client should know that he was not allowed to ask
				if (thePrefs.GetVerbose())
					AddDebugLogLine(true, _T("Client '%s' (%s) requested Preview - denied"), client->GetUserName(), (LPCTSTR)ipstr(client->GetConnectIP()));
			}
			break;
		case OP_PREVIEWANSWER:
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugRecv("OP_PreviewAnswer", client, (size >= 16) ? packet : NULL);
			theStats.AddDownDataOverheadOther(uRawSize);
			client->CheckHandshakeFinished();

			client->ProcessPreviewAnswer(packet, size);
			break;
		case OP_PEERCACHE_QUERY:
		case OP_PEERCACHE_ANSWER:
		case OP_PEERCACHE_ACK:
			theStats.AddDownDataOverheadFileRequest(uRawSize);
			break;
		case OP_PUBLICIP_ANSWER:
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugRecv("OP_PublicIPAns", client);
			theStats.AddDownDataOverheadOther(uRawSize);

			client->ProcessPublicIPAnswer(packet, size);
			break;
		case OP_PUBLICIP_REQ:
			{
				if (thePrefs.GetDebugClientTCPLevel() > 0)
					DebugRecv("OP_PublicIPReq", client);
				theStats.AddDownDataOverheadOther(uRawSize);

				if (thePrefs.GetDebugClientTCPLevel() > 0)
					DebugSend("OP_PublicIPAns", client);
				Packet *pPacket = new Packet(OP_PUBLICIP_ANSWER, 4, OP_EMULEPROT);
				PokeUInt32(pPacket->pBuffer, client->GetIP());
				theStats.AddUpDataOverheadOther(pPacket->size);
				SendPacket(pPacket);
			}
			break;
		case OP_PORTTEST:
			{
				if (thePrefs.GetDebugClientTCPLevel() > 0)
					DebugRecv("OP_PortTest", client);
				theStats.AddDownDataOverheadOther(uRawSize);

				m_bPortTestCon = true;
				if (thePrefs.GetDebugClientTCPLevel() > 0)
					DebugSend("OP_PortTest", client);
				Packet *replypacket = new Packet(OP_PORTTEST, 1);
				replypacket->pBuffer[0] = 0x12;
				theStats.AddUpDataOverheadOther(replypacket->size);
				SendPacket(replypacket);
			}
			break;
		case OP_CALLBACK:
			{
				if (thePrefs.GetDebugClientTCPLevel() > 0)
					DebugRecv("OP_Callback", client);
				theStats.AddDownDataOverheadFileRequest(uRawSize);

				if (!Kademlia::CKademlia::IsRunning())
					break;
				CSafeMemFile data(packet, size);
				Kademlia::CUInt128 check;
				data.ReadUInt128(check);
				check.Xor(Kademlia::CUInt128(true));
				if (check == Kademlia::CKademlia::GetPrefs()->GetKadID()) {
					Kademlia::CUInt128 fileid;
					data.ReadUInt128(fileid);
					uchar fileid2[MDX_DIGEST_SIZE];
					fileid.ToByteArray(fileid2);
					if (theApp.sharedfiles->GetFileByID(fileid2) == NULL) {
						if (theApp.downloadqueue->GetFileByID(fileid2) == NULL) {
							client->CheckFailedFileIdReqs(fileid2);
							break;
						}
					}

					uint32 ip = data.ReadUInt32();
					uint16 tcp = data.ReadUInt16();
					CUpDownClient *callback = theApp.clientlist->FindClientByConnIP(ntohl(ip), tcp);
					if (callback == NULL) {
						callback = new CUpDownClient(NULL, tcp, ip, 0, 0);
						theApp.clientlist->AddClient(callback);
					}

					callback->TryToConnect(true);
				}
			}
			break;
		case OP_BUDDYPING:
			{
				if (thePrefs.GetDebugClientTCPLevel() > 0)
					DebugRecv("OP_BuddyPing", client);
				theStats.AddDownDataOverheadOther(uRawSize);

				CUpDownClient *buddy = theApp.clientlist->GetBuddy();
				//Check that ping was from our buddy, correct version, and not too soon
				if (buddy != client || !client->GetKadVersion() || !client->AllowIncomeingBuddyPingPong())
					break; // ignore otherwise
				if (thePrefs.GetDebugClientTCPLevel() > 0)
					DebugSend("OP_BuddyPong", client);
				Packet *replypacket = new Packet(OP_BUDDYPONG, 0, OP_EMULEPROT);
				theStats.AddUpDataOverheadOther(replypacket->size); // BUG-008 FIX: Pong is outbound
				SendPacket(replypacket);
				client->SetLastBuddyPingPongTime();
			}
			break;
		case OP_BUDDYPONG:
			{
				if (thePrefs.GetDebugClientTCPLevel() > 0)
					DebugRecv("OP_BuddyPong", client);
				theStats.AddDownDataOverheadOther(uRawSize);

				CUpDownClient *buddy = theApp.clientlist->GetBuddy();
				if (buddy != client || !client->GetKadVersion())
					//This pong was not from our buddy or wrong version. Ignore
					break;
				client->SetLastBuddyPingPongTime();
				//All this is for is to reset our socket timeout.
			}
			break;
		case OP_REASKCALLBACKTCP:
			{
				theStats.AddDownDataOverheadFileRequest(uRawSize);
				CUpDownClient *buddy = theApp.clientlist->GetBuddy();
				if (buddy != client) {
					if (thePrefs.GetDebugClientTCPLevel() > 0)
						DebugRecv("OP_ReaskCallbackTCP", client, NULL);
					//This callback was not from our buddy. Ignore.
					break;
				}
				CSafeMemFile data_in(packet, size);
				uint32 destip = data_in.ReadUInt32();
				uint16 destport = data_in.ReadUInt16();
				uchar reqfilehash[MDX_DIGEST_SIZE];
				data_in.ReadHash16(reqfilehash);
				if (thePrefs.GetDebugClientTCPLevel() > 0)
					DebugRecv("OP_ReaskCallbackTCP", client, reqfilehash);
				CKnownFile *reqfile = theApp.sharedfiles->GetFileByID(reqfilehash);

				bool bSenderMultipleIpUnknown = false;
				CUpDownClient *sender = theApp.uploadqueue->GetWaitingClientByIP_UDP(destip, destport, true, &bSenderMultipleIpUnknown);
				if (!reqfile) {
					if (thePrefs.GetDebugClientUDPLevel() > 0)
						DebugSend("OP_FileNotFound", NULL);
					Packet *response = new Packet(OP_FILENOTFOUND, 0, OP_EMULEPROT);
					theStats.AddUpDataOverheadFileRequest(response->size);
					if (sender != NULL)
						theApp.clientudp->SendPacket(response, destip, destport, sender->ShouldReceiveCryptUDPPackets(), sender->GetUserHash(), false, 0);
					else
						theApp.clientudp->SendPacket(response, destip, destport, false, NULL, false, 0);
					break;
				}

				if (sender) {
					//Make sure we are still thinking about the same file
					if (md4equ(reqfilehash, sender->GetUploadFileID())) {
						sender->IncrementAskedCount();
						sender->SetLastUpRequest();
						//I messed up when I first added extended info to UDP
						//I should have originally used the entire ProcessExtenedInfo the first time.
						//So now I am forced to check UDPVersion to see if we are sending all the extended info.
						//For now on, we should not have to change anything here if we change
						//anything to the extended info data as this will be taken care of in ProcessExtendedInfo()
						//Update extended info.
						if (sender->GetUDPVersion() > 3)
							sender->ProcessExtendedInfo(data_in, reqfile);
							//Update our complete source counts.
						else if (sender->GetUDPVersion() > 2) {
							uint16 nCompleteCountLast = sender->GetUpCompleteSourcesCount();
							uint16 nCompleteCountNew = data_in.ReadUInt16();
							sender->SetUpCompleteSourcesCount(nCompleteCountNew);
							if (nCompleteCountLast != nCompleteCountNew)
								reqfile->UpdatePartsInfo();
						}
						CSafeMemFile data_out(128);
						if (sender->GetUDPVersion() > 3)
							if (reqfile->IsPartFile())
								static_cast<CPartFile*>(reqfile)->WritePartStatus(data_out);
							else
								data_out.WriteUInt16(0);

						data_out.WriteUInt16((uint16)theApp.uploadqueue->GetWaitingPosition(sender));
						if (thePrefs.GetDebugClientUDPLevel() > 0)
							DebugSend("OP_ReaskAck", sender);
						Packet *response = new Packet(data_out, OP_EMULEPROT);
						response->opcode = OP_REASKACK;
						theStats.AddUpDataOverheadFileRequest(response->size);
						theApp.clientudp->SendPacket(response, destip, destport, sender->ShouldReceiveCryptUDPPackets(), sender->GetUserHash(), false, 0);
					} else {
						DebugLogWarning(_T("Client UDP socket; OP_REASKCALLBACKTCP; reqfile does not match"));
						TRACE(_T("reqfile:         %s\n"), (LPCTSTR)DbgGetFileInfo(reqfile->GetFileHash()));
						TRACE(_T("sender->GetRequestFile(): %s\n"), sender->GetRequestFile() ? (LPCTSTR)DbgGetFileInfo(sender->GetRequestFile()->GetFileHash()) : _T("(null)"));
					}
				} else {
					if (!bSenderMultipleIpUnknown) {
						if (theApp.uploadqueue->GetWaitingUserCount() + 50 > thePrefs.GetQueueSize()) {
							if (thePrefs.GetDebugClientUDPLevel() > 0)
								DebugSend("OP_QueueFull", NULL);
							Packet *response = new Packet(OP_QUEUEFULL, 0, OP_EMULEPROT);
							theStats.AddUpDataOverheadFileRequest(response->size);
							theApp.clientudp->SendPacket(response, destip, destport, false, NULL, false, 0);
						}
					} else
						DebugLogWarning(_T("OP_REASKCALLBACKTCP Packet received - multiple clients with the same IP but different UDP port found. Possible UDP Port mapping problem, enforcing TCP connection. IP: %s, Port: %u"), (LPCTSTR)ipstr(destip), destport);
				}
			}
			break;
		case OP_AICHANSWER:
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugRecv("OP_AichAnswer", client, (size >= 16) ? packet : NULL);
			theStats.AddDownDataOverheadFileRequest(uRawSize);

			client->ProcessAICHAnswer(packet, size);
			break;
		case OP_AICHREQUEST:
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugRecv("OP_AichRequest", client, (size >= 16) ? packet : NULL);
			theStats.AddDownDataOverheadFileRequest(uRawSize);

			client->ProcessAICHRequest(packet, size);
			break;
		case OP_AICHFILEHASHANS:
			{
				// those should not be received normally, since we should only get those in MULTIPACKET
				if (thePrefs.GetDebugClientTCPLevel() > 0)
					DebugRecv("OP_AichFileHashAns", client, (size >= 16) ? packet : NULL);
				theStats.AddDownDataOverheadFileRequest(uRawSize);

				CSafeMemFile data(packet, size);
				client->ProcessAICHFileHash(&data, NULL, NULL);
			}
			break;
		case OP_AICHFILEHASHREQ:
			{
				if (thePrefs.GetDebugClientTCPLevel() > 0)
					DebugRecv("OP_AichFileHashReq", client, (size >= 16) ? packet : NULL);
				theStats.AddDownDataOverheadFileRequest(uRawSize);

				// those should not be received normally, since we should only get those in MULTIPACKET
				CSafeMemFile data(packet, size);
				uchar abyHash[MDX_DIGEST_SIZE];
				data.ReadHash16(abyHash);
				CKnownFile *pPartFile = theApp.sharedfiles->GetFileByID(abyHash);
				if (pPartFile == NULL) {
					client->CheckFailedFileIdReqs(abyHash);
					break;
				}
				if (client->IsSupportingAICH() && pPartFile->GetFileIdentifier().HasAICHHash()) {
					if (thePrefs.GetDebugClientTCPLevel() > 0)
						DebugSend("OP_AichFileHashAns", client, abyHash);
					CSafeMemFile data_out;
					data_out.WriteHash16(abyHash);
					pPartFile->GetFileIdentifier().GetAICHHash().Write(data_out);
					Packet *response = new Packet(data_out, OP_EMULEPROT, OP_AICHFILEHASHANS);
					theStats.AddUpDataOverheadFileRequest(response->size);
					SendPacket(response);
				}
			}
			break;
		case OP_REQUESTPARTS_I64:
			{
				// see also OP_REQUESTPARTS
				if (thePrefs.GetDebugClientTCPLevel() > 0)
					DebugRecv("OP_RequestParts_I64", client, (size >= 16) ? packet : NULL);
				theStats.AddDownDataOverheadFileRequest(size);

				CSafeMemFile data(packet, size);
				uchar reqfilehash[MDX_DIGEST_SIZE];
				data.ReadHash16(reqfilehash);

				uint64 aOffset[3 * 2]; //3 starts, then 3 ends
				for (unsigned i = 0; i < 3 * 2; ++i)
					aOffset[i] = data.ReadUInt64();
				if (thePrefs.GetDebugClientTCPLevel() > 0)
					for (unsigned i = 0; i < 3; ++i)
						Debug(_T("  Start[%u]=%I64u  End[%u]=%I64u  Size=%I64u\n"), i, aOffset[i], i, aOffset[i + 3], aOffset[i + 3] - aOffset[i]);

				for (unsigned i = 0; i < 3; ++i) { // BUG-007 FIX: explicit braces
					if (aOffset[i] < aOffset[i + 3]) {
						Requested_Block_Struct *reqblock = new Requested_Block_Struct;
						reqblock->StartOffset = aOffset[i];
						reqblock->EndOffset = aOffset[i + 3];
						md4cpy(reqblock->FileID, reqfilehash);
						reqblock->transferred = 0;
						client->AddReqBlock(reqblock, false);
					} else if (thePrefs.GetVerbose() && (aOffset[i + 3] != 0 || aOffset[i] != 0))
						DebugLogWarning(_T("Client requests invalid %u. file block %I64u-%I64u (%I64d bytes): %s"), i, aOffset[i], aOffset[i + 3], aOffset[i + 3] - aOffset[i], (LPCTSTR)client->DbgGetClientInfo());

				} // BUG-007 FIX: end for-loop body
				client->AddReqBlock(NULL, true);
			}
			break;
		case OP_COMPRESSEDPART:
		case OP_SENDINGPART_I64:
		case OP_COMPRESSEDPART_I64:
			{
				// see also OP_SENDINGPART
				if (thePrefs.GetDebugClientTCPLevel() > 1) {
					LPCSTR sOp;
					switch (opcode) {
					case OP_COMPRESSEDPART:
						sOp = "OP_CompressedPart";
						break;
					case OP_SENDINGPART_I64:
						sOp = "OP_SendingPart_I64";
						break;
					default: //OP_COMPRESSEDPART_I64
						sOp = "OP_CompressedPart_I64";
					}
					DebugRecv(sOp, client, (size >= 16) ? packet : NULL);
				}

				bool bCompress = (opcode != OP_SENDINGPART_I64);
				bool b64 = (opcode != OP_COMPRESSEDPART);
				theStats.AddDownDataOverheadFileRequest(16 + (b64 ? 8 : 4) + (bCompress ? 4 : 8));
				client->CheckHandshakeFinished();
				EDownloadState newDS = DS_NONE;
				const CPartFile *creqfile = client->GetRequestFile();
				if (creqfile) {
					if (!creqfile->IsStopped() && (creqfile->GetStatus() == PS_READY || creqfile->GetStatus() == PS_EMPTY)) {
						client->ProcessBlockPacket(packet, size, bCompress, b64);
						// BUG-006 FIX: Added parentheses to fix operator precedence
						if (!creqfile->IsStopped() && (creqfile->GetStatus() == PS_PAUSED || creqfile->GetStatus() == PS_ERROR))
							newDS = DS_ONQUEUE;
						else
							newDS = DS_CONNECTED; //any state but DS_NONE or DS_ONQUEUE
					}
				}
				if (newDS != DS_CONNECTED && client) { //client could have been deleted while debugging
					client->SendCancelTransfer();
					client->SetDownloadState(newDS);
				}
			}
			break;
		case OP_CHATCAPTCHAREQ:
			{
				if (thePrefs.GetDebugClientTCPLevel() > 0)
					DebugRecv("OP_CHATCAPTCHAREQ", client);
				theStats.AddDownDataOverheadOther(uRawSize);
				CSafeMemFile data(packet, size);
				client->ProcessCaptchaRequest(data);
			}
			break;
		case OP_CHATCAPTCHARES:
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugRecv("OP_CHATCAPTCHARES", client);
			theStats.AddDownDataOverheadOther(uRawSize);
			if (size < 1)
				throw GetResString(IDS_ERR_BADSIZE);
			client->ProcessCaptchaReqRes(packet[0]);
			break;
		case OP_FWCHECKUDPREQ: //*Support required for Kad version >= 6
			{
				// Kad related packet
				if (thePrefs.GetDebugClientTCPLevel() > 0)
					DebugRecv("OP_FWCHECKUDPREQ", client);
				theStats.AddDownDataOverheadOther(uRawSize);
				CSafeMemFile data(packet, size);
				client->ProcessFirewallCheckUDPRequest(data);
			}
			break;
		case OP_KAD_FWTCPCHECK_ACK: //*Support required for Kad version >= 7
			// Kad related packet, replaces KADEMLIA_FIREWALLED_ACK_RES
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugRecv("OP_KAD_FWTCPCHECK_ACK", client);
			if (theApp.clientlist->IsKadFirewallCheckIP(client->GetIP())) {
				if (Kademlia::CKademlia::IsRunning())
					Kademlia::CKademlia::GetPrefs()->IncFirewalled();
			} else
				DebugLogWarning(_T("Unrequested OP_KAD_FWTCPCHECK_ACK packet from client %s"), (LPCTSTR)client->DbgGetClientInfo());
			break;
		case OP_HASHSETANSWER2:
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugRecv("OP_HashSetAnswer2", client);
			theStats.AddDownDataOverheadFileRequest(size);
			client->ProcessHashSet(packet, size, true);
			break;
		case OP_HASHSETREQUEST2:
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugRecv("OP_HashSetReq2", client);
			theStats.AddDownDataOverheadFileRequest(size);
			client->SendHashsetPacket(packet, size, true);
			break;
		// ========================================================
		// eSE Live — P2P streaming protocol handlers
		// ========================================================
		case OP_LIVE_SUBSCRIBE:
			{
				if (thePrefs.GetDebugClientTCPLevel() > 0)
					DebugRecv("OP_LiveSubscribe", client, (size >= 16) ? packet : NULL);
				theStats.AddDownDataOverheadOther(uRawSize);
				if (size < 32) break; // streamKey(16) + viewerHash(16)

				CSafeMemFile data(packet, size);
				uchar streamKey[16];
				data.ReadHash16(streamKey);
				uchar viewerHash[16];
				data.ReadHash16(viewerHash); // consume viewerHash before uploadCapacity
				uint32 uploadCapacity = (size >= 36) ? data.ReadUInt32() : 0;

				if (theApp.liveStreamManager)
					theApp.liveStreamManager->OnPeerJoin(client, streamKey, uploadCapacity);
			}
			break;
		case OP_LIVE_UNSUBSCRIBE:
			{
				if (thePrefs.GetDebugClientTCPLevel() > 0)
					DebugRecv("OP_LiveUnsubscribe", client);
				theStats.AddDownDataOverheadOther(uRawSize);

				if (theApp.liveStreamManager)
					theApp.liveStreamManager->OnPeerDisconnected(client);
			}
			break;
		case OP_LIVE_REQUEST:
			{
				if (thePrefs.GetDebugClientTCPLevel() > 0)
					DebugRecv("OP_LiveRequest", client, (size >= 16) ? packet : NULL);
				theStats.AddDownDataOverheadOther(uRawSize);
				if (size < 20) break; // streamKey(16) + seqNum(4)

				CSafeMemFile data(packet, size);
				uchar streamKey[16];
				data.ReadHash16(streamKey);
				uint32 seqNum = data.ReadUInt32();

				if (theApp.liveStreamManager)
					theApp.liveStreamManager->OnPeerRequest(client, streamKey, seqNum);
			}
			break;
		case OP_LIVE_CHUNK:
			{
				if (thePrefs.GetDebugClientTCPLevel() > 1) // level > 1 to avoid flooding
					DebugRecv("OP_LiveChunk", client, (size >= 16) ? packet : NULL);
				theStats.AddDownDataOverheadOther(uRawSize);
				if (size < 28) break; // streamKey(16) + seqNum(4) + chunkSize(4) + timestamp(4)

				CSafeMemFile data(packet, size);
				uchar streamKey[16];
				data.ReadHash16(streamKey);
				uint32 seqNum = data.ReadUInt32();
				uint32 timestamp = data.ReadUInt32();
				uint32 chunkSize = data.ReadUInt32();

				// Sanity check: chunk size must not exceed remaining data
				if (chunkSize > size - 28 || chunkSize > 4 * 1024 * 1024) break; // max 4MB

				const BYTE* chunkData = packet + 28;
				if (theApp.liveStreamManager)
					theApp.liveStreamManager->OnChunkReceived(client, streamKey,
						seqNum, timestamp, chunkData, chunkSize);
			}
			break;
		case OP_LIVE_CHUNK_V2:
			{
				// v7.7.0 — signed chunk.
				// Format: streamKey(16) + seqNum(4) + ts(4) + dataSize(4) + bitrate(2)
				//        + sha256(32) + sig(64) + data(dataSize).
				if (thePrefs.GetDebugClientTCPLevel() > 1)
					DebugRecv("OP_LiveChunkV2", client, (size >= 16) ? packet : NULL);
				theStats.AddDownDataOverheadOther(uRawSize);
				if (size < 126) break;  // header alone

				CSafeMemFile data(packet, size);
				uchar streamKey[16];
				data.ReadHash16(streamKey);
				uint32 seqNum    = data.ReadUInt32();
				uint32 timestamp = data.ReadUInt32();
				uint32 chunkSize = data.ReadUInt32();
				/*uint16 bitrate =*/ data.ReadUInt16();
				uchar digest[32];
				data.Read(digest, 32);
				uchar sig[64];
				data.Read(sig, 64);

				if (chunkSize > size - 126 || chunkSize > 4 * 1024 * 1024) break;

				const BYTE* chunkData = packet + 126;

				// 1. Need a pinned pubkey for this streamKey; without it we
				//    can't verify. Drop silently — V1 path will retry if/when
				//    an ANNOUNCE carries the pubkey.
				uchar pubkey[32];
				if (!theApp.liveStreamManager ||
				    !theApp.liveStreamManager->GetPinnedPubkey(streamKey, pubkey)) {
					break;
				}

				// 2. Verify sha256(data) matches digest. Cheap integrity check
				//    that also amortises the cost of the signature path: if a
				//    peer corrupts even one byte we fail here before doing
				//    the expensive Ed25519 verify.
				{
					CryptoPP::SHA256 hash;
					uchar computed[32];
					hash.CalculateDigest(computed, chunkData, chunkSize);
					if (memcmp(computed, digest, 32) != 0) {
						AddLogLine(true, _T("eSE Live: chunk seq=%u digest mismatch — dropping"), seqNum);
						break;
					}
				}

				// 3. Verify signature over (streamKey || seqNum || digest).
				{
					uchar signMsg[16 + 4 + 32];
					memcpy(signMsg, streamKey, 16);
					memcpy(signMsg + 16, &seqNum, 4);
					memcpy(signMsg + 20, digest, 32);
					if (!eSELive::VerifySignature(pubkey, signMsg, sizeof signMsg, sig)) {
						AddLogLine(true, _T("eSE Live: chunk seq=%u bad signature — dropping"), seqNum);
						break;
					}
				}

				// All checks passed — hand to the manager exactly like V1.
				theApp.liveStreamManager->OnChunkReceived(client, streamKey,
					seqNum, timestamp, chunkData, chunkSize);
			}
			break;
		case OP_LIVE_PEER_LIST:
			{
				if (thePrefs.GetDebugClientTCPLevel() > 0)
					DebugRecv("OP_LivePeerList", client);
				theStats.AddDownDataOverheadOther(uRawSize);
				if (size < 18) break; // streamKey(16) + count(2)

				CSafeMemFile data(packet, size);
				uchar streamKey[16];
				data.ReadHash16(streamKey);
				uint16 count = data.ReadUInt16();

				// v7.5.0 — hard cap on peer-list size. A hostile peer that
				// announces count=65535 would otherwise force us to launch
				// up to 65535 TCP connect() attempts (FD exhaustion + SYN
				// reflection). 16 candidates is plenty for mesh recovery.
				const uint16 ESE_LIVE_MAX_PEER_LIST = 16;
				if (count > ESE_LIVE_MAX_PEER_LIST)
					count = ESE_LIVE_MAX_PEER_LIST;

				CArray<DWORD> ips;
				CArray<uint16> ports;
				for (uint16 i = 0; i < count && data.GetPosition() + 6 <= data.GetLength(); i++) {
					ips.Add(data.ReadUInt32());
					ports.Add(data.ReadUInt16());
				}

				if (theApp.liveStreamManager)
					theApp.liveStreamManager->OnPeerListReceived(client, streamKey, ips, ports);
			}
			break;
		case OP_LIVE_PEER_LIST_V2:
			{
				// v0.71 IPv6 Sprint 7 — peer list with CAddress payload.
				// Layout: <StreamKey 16><Count 2>(<CAddress 6 or 18><Port 2>) × Count
				// Receiver cap is identical to OP_LIVE_PEER_LIST (16 entries).
				if (thePrefs.GetDebugClientTCPLevel() > 0)
					DebugRecv("OP_LivePeerListV2", client);
				theStats.AddDownDataOverheadOther(uRawSize);
				if (size < 18) break;
				CSafeMemFile data(packet, size);
				uchar streamKey[16];
				data.ReadHash16(streamKey);
				uint16 count = data.ReadUInt16();
				const uint16 ESE_LIVE_MAX_PEER_LIST_V2 = 16;
				if (count > ESE_LIVE_MAX_PEER_LIST_V2)
					count = ESE_LIVE_MAX_PEER_LIST_V2;

				// Sprint 7 follow-up: pass CAddress entries through to the
				// V6-aware receiver, which splits v4 and v6 internally. v4
				// peers reach the existing dial path; v6 peers are logged
				// and counted until Sprint-4 Kad-v6 wires a real v6 socket
				// helper to CUpDownClient (see OnPeerListReceivedV6 notes).
				CArray<CAddress> addrs;
				CArray<uint16> ports;
				for (uint16 i = 0; i < count && data.GetPosition() + 4 <= data.GetLength(); ++i) {
					CAddress addr;
					if (!addr.ReadFromBuffer(&data)) break;
					if (data.GetPosition() + 2 > data.GetLength()) break;
					uint16 port = data.ReadUInt16();
					addrs.Add(addr);
					ports.Add(port);
				}
				if (theApp.liveStreamManager)
					theApp.liveStreamManager->OnPeerListReceivedV6(client, streamKey, addrs, ports);
			}
			break;
		case OP_LIVE_HEARTBEAT:
			{
				if (thePrefs.GetDebugClientTCPLevel() > 0)
					DebugRecv("OP_LiveHeartbeat", client);
				theStats.AddDownDataOverheadOther(uRawSize);
				if (size < 18) break; // streamKey(16) + bitmap(2)

				CSafeMemFile data(packet, size);
				uchar streamKey[16];
				data.ReadHash16(streamKey);
				uint16 bitmap = data.ReadUInt16();
				uint32 oldestSeq = (size >= 22) ? data.ReadUInt32() : 0;

				if (theApp.liveStreamManager)
					theApp.liveStreamManager->OnPeerBitmap(client, streamKey, oldestSeq, bitmap);

				// Decentralized Capa 1 (PEX): optional trailing block
				// <pexCount 1><entry pexCount * 22>. Each entry is
				// streamKey(16) + ip(4) + port(2). Skipped by old peers
				// because they stop reading at byte 22.
				if (size >= 23 && theApp.liveStreamManager) {
					uint8 pexCount = data.ReadUInt8();
					if (pexCount > 5) pexCount = 5; // sanity cap
					const UINT pexBytes = (UINT)pexCount * 22U;
					if (data.GetPosition() + pexBytes <= (UINT)size) {
						for (uint8 i = 0; i < pexCount; ++i) {
							uchar pexKey[16];
							data.ReadHash16(pexKey);
							uint32 pexIP   = data.ReadUInt32();
							uint16 pexPort = data.ReadUInt16();
							theApp.liveStreamManager->OnPexEntry(pexKey, pexIP, pexPort);
						}
					}
				}
			}
			break;
		case OP_LIVE_ANNOUNCE:
			{
				if (thePrefs.GetDebugClientTCPLevel() > 0)
					DebugRecv("OP_LiveAnnounce", client, (size >= 16) ? packet : NULL);
				theStats.AddDownDataOverheadOther(uRawSize);
				if (size < 22) break; // streamKey(16) + newestSeq(4) + bitrate(2)

				CSafeMemFile data(packet, size);
				uchar streamKey[16];
				data.ReadHash16(streamKey);
				uint32 newestSeq = data.ReadUInt32();
				/*uint16 bitrate =*/ data.ReadUInt16();

				// v7.6.0 — optional pubkey trailer (32 bytes). If present and
				// it doesn't hash to the announced streamKey, the peer is
				// either confused or attempting to claim a streamKey it can't
				// sign for. Drop the announcement silently in that case.
				if (size >= 54) {
					uchar pubkey[32];
					data.Read(pubkey, 32);
					if (!eSELive::StreamKeyMatchesPubkey(streamKey, pubkey)) {
						// Mismatch — log + reject.
						break;
					}
					// v7.7.0 — pin the pubkey for this streamKey so future
					// signed chunks/END packets can be verified. Idempotent
					// for the same (streamKey, pubkey) pair.
					if (theApp.liveStreamManager)
						theApp.liveStreamManager->PinStreamPubkey(streamKey, pubkey);
				}

				// Trigger segment request for the newly announced segment
				if (theApp.liveStreamManager && theApp.liveStreamManager->IsViewingLive())
					theApp.liveStreamManager->GetMeshManager().OnSegmentAnnounced(newestSeq);
			}
			break;
		case OP_LIVE_DENY:
			{
				if (thePrefs.GetDebugClientTCPLevel() > 0)
					DebugRecv("OP_LiveDeny", client);
				theStats.AddDownDataOverheadOther(uRawSize);
				if (size >= 17) {
					uint8 reason = packet[16];
					AddLogLine(true, _T("eSE Live: Stream access denied (reason=%u)"), reason);
				}
			}
			break;
		case OP_LIVE_END:
			{
				if (thePrefs.GetDebugClientTCPLevel() > 0)
					DebugRecv("OP_LiveEnd", client);
				theStats.AddDownDataOverheadOther(uRawSize);
				// Payload: <streamKey 16><reason 1> [<sig 64>]
				// v7.7.0: if a 64-byte sig is appended (total >= 81 bytes),
				// verify it against the pinned pubkey for streamKey. A peer
				// without the broadcaster's privkey cannot forge this sig,
				// so signed ENDs are accepted regardless of source.
				// Unsigned ENDs still go through the v7.5.0 auth path in
				// LiveStreamManager::OnStreamEnded (must come from a known
				// m_broadcastPeers/m_viewPeers member, or watchdog NULL).
				if (size >= 16 && theApp.liveStreamManager) {
					uint8 reason = (size >= 17) ? packet[16] : 0;
					CUpDownClient* effectivePeer = client;
					if (size >= 81) {
						uchar pubkey[32];
						if (theApp.liveStreamManager->GetPinnedPubkey(packet, pubkey)) {
							uchar msg[17];
							memcpy(msg, packet, 16);
							msg[16] = reason;
							const uchar* sigPtr = packet + 17;
							if (eSELive::VerifySignature(pubkey, msg, sizeof msg, sigPtr)) {
								// Signed END from the legitimate broadcaster.
								// Pass NULL as peer so OnStreamEnded skips
								// the "must be in m_viewPeers" auth check.
								effectivePeer = NULL;
							} else {
								AddLogLine(true, _T("eSE Live: rejected END (bad signature)"));
								break;
							}
						}
					}
					AddLogLine(true, _T("eSE Live: Stream ended (reason=%u)"), reason);
					theApp.liveStreamManager->OnStreamEnded(packet, reason, effectivePeer);
				} else if (theApp.liveStreamManager) {
					AddLogLine(true, _T("eSE Live: Stream ended (malformed END)"));
					theApp.liveStreamManager->OnPeerDisconnected(client);
				}
			}
			break;
		case OP_LIVE_PING:
			{
				// V2-S03: <streamKey 16><pingId 4><sendTick 8> — echo back as PONG.
				if (thePrefs.GetDebugClientTCPLevel() > 1)
					DebugRecv("OP_LivePing", client);
				theStats.AddDownDataOverheadOther(uRawSize);
				if (size < 28) break;
				CSafeMemFile data(packet, size);
				uchar streamKey[16];
				data.ReadHash16(streamKey);
				uint32 pingId   = data.ReadUInt32();
				uint64 sendTick = data.ReadUInt64();
				if (theApp.liveStreamManager)
					theApp.liveStreamManager->OnLivePing(client, streamKey, pingId, sendTick);
			}
			break;
		case OP_LIVE_PONG:
			{
				// V2-S03: <streamKey 16><pingId 4><echoTick 8> — feed RTT EWMA.
				if (thePrefs.GetDebugClientTCPLevel() > 1)
					DebugRecv("OP_LivePong", client);
				theStats.AddDownDataOverheadOther(uRawSize);
				if (size < 28) break;
				CSafeMemFile data(packet, size);
				uchar streamKey[16];
				data.ReadHash16(streamKey);
				uint32 pingId   = data.ReadUInt32();
				uint64 echoTick = data.ReadUInt64();
				if (theApp.liveStreamManager)
					theApp.liveStreamManager->OnLivePong(client, streamKey, pingId, echoTick);
			}
			break;

		// === v0.71 P3.4 — OP_LIVE_TUNNEL_CELL real handler ===========
		// A 512B onion cell arrived. Hand to CLiveTunnel which:
		//   - If circ_id is one WE originated: complete the handshake
		//     (CREATED → derive K_send/K_recv, set HalfBuilt) or peel
		//     a returned RELAY layer for our consumer.
		//   - If circ_id is one we're RELAYING for (intermediate hop):
		//     peel ONE layer with our hop key and forward to next hop
		//     using the relay-side circuit table.
		//   - If unknown: drop with debug log (could be late from a
		//     destroyed circuit, not necessarily malicious).
		case OP_LIVE_TUNNEL_CELL:
			theStats.AddDownDataOverheadOther(uRawSize);
			if (size != eSELive::CELL_TOTAL_BYTES) {
				DebugLog(_T("OP_LIVE_TUNNEL_CELL: wrong size %u (expected %u) from %s — dropping"),
					size, (unsigned)eSELive::CELL_TOTAL_BYTES,
					client ? (LPCTSTR)ipstr(client->GetIP()) : _T("?"));
				break;
			}
			{
				uint32_t circId;
				uint8_t cmd;
				const uint8_t* cellPayload = NULL;
				uint16_t cellPayloadLen = 0;
				if (!eSELive::CellUnpack(packet, circId, cmd, cellPayload, cellPayloadLen)) {
					DebugLog(_T("OP_LIVE_TUNNEL_CELL: CellUnpack failed — dropping"));
					break;
				}
				bool consumed = eSELive::CLiveTunnel::Get().OnCellReceived(
					circId, cmd, cellPayload, cellPayloadLen, client);
				if (!consumed) {
					DebugLog(_T("OP_LIVE_TUNNEL_CELL: circ=0x%08x cmd=0x%02x not consumed (unknown circuit)"),
						circId, cmd);
				}
			}
			break;

		// === F0 (unified plan) — remaining eSE Live Tunneled opcodes ==
		// Stub handlers for opcodes whose data plane (F5 P3+) is not yet
		// implemented. Channel ops (0xD0-0xD3) land here until F3 wires
		// the channel store; T_* (0xD6-0xDD) wait for tunneled wrappers.
		case OP_LIVE_CHANNEL_GOSSIP:
		case OP_LIVE_CHANNEL_REQUEST:
		case OP_LIVE_CHANNEL_ANSWER:
		case OP_LIVE_CHANNEL_REVOKE:
		case OP_LIVE_T_SUBSCRIBE:
		case OP_LIVE_T_UNSUBSCRIBE:
		case OP_LIVE_T_REQUEST:
		case OP_LIVE_T_CHUNK:
		case OP_LIVE_T_HEARTBEAT:
		case OP_LIVE_T_ANNOUNCE:
		case OP_LIVE_T_DENY:
		case OP_LIVE_T_END:
		case OP_LIVE_PEER_INVITE:
		case OP_LIVE_RENDEZVOUS_PEERS:
			theStats.AddDownDataOverheadOther(uRawSize);
			DebugLog(_T("[STUB F0] OP_LIVE_T_* opcode 0x%02x received from %s — reserved, no handler yet (unified plan F3-F5)"),
				(unsigned)opcode,
				client ? (LPCTSTR)ipstr(client->GetIP()) : _T("?"));
			break;

		default:
			theStats.AddDownDataOverheadOther(uRawSize);
			PacketToDebugLogLine(_T("eMule"), packet, size, opcode);
		}
	} catch(CFileException *ex) {
		ex->Delete();
		throw GetResString(IDS_ERR_INVALIDPACKET);
	} catch(CMemoryException *ex) {
		ex->Delete();
		throwCStr(_T("Memory exception"));
	}
	return true;
}

void CClientReqSocket::PacketToDebugLogLine(LPCTSTR protocol, const uchar *packet, uint32 size, UINT opcode)
{
	if (thePrefs.GetVerbose()) {
		CString buffer;
		buffer.Format(_T("Unknown %s protocol Opcode: 0x%02x, Size=%u, Data=["), protocol, opcode, size);
		UINT i;
		for (i = 0; i < size && i < 50; ++i)
			buffer.AppendFormat(*(&_T(" %02x")[static_cast<int>(i > 0)]), packet[i]);

		buffer += (i < size) ? _T("... ]") : _T(" ]");
		DbgAppendClientInfo(buffer);
		DebugLogWarning(_T("%s"), (LPCTSTR)buffer);
	}
}

CString CClientReqSocket::DbgGetClientInfo()
{
	SOCKADDR_IN sockAddr = {};
	int nSockAddrLen = sizeof sockAddr;
	GetPeerName((LPSOCKADDR)&sockAddr, &nSockAddrLen);
	CString str;
	if (sockAddr.sin_addr.s_addr != 0 && (client == NULL || sockAddr.sin_addr.s_addr != client->GetIP()))
		str.Format(_T("IP=%s"), (LPCTSTR)ipstr(sockAddr.sin_addr));
	if (client)
		str.AppendFormat(&_T("; Client=%s")[str.IsEmpty() ? 2 : 0], (LPCTSTR)client->DbgGetClientInfo());
	return str;
}

void CClientReqSocket::DbgAppendClientInfo(CString &str)
{
	CString strClientInfo(DbgGetClientInfo());
	if (!strClientInfo.IsEmpty())
		str.AppendFormat(&_T("; %s")[str.IsEmpty() ? 2 : 0], (LPCTSTR)strClientInfo);
}

void CClientReqSocket::OnConnect(int nErrorCode)
{
	SetConState(SS_Complete);
	CEMSocket::OnConnect(nErrorCode);
	if (nErrorCode) {
		if (thePrefs.GetVerbose()) {
			const CString &strTCPError(GetFullErrorMessage(nErrorCode));
			if ((nErrorCode != WSAECONNREFUSED && nErrorCode != WSAETIMEDOUT) || !GetLastProxyError().IsEmpty())
				DebugLogError(_T("Client TCP socket (OnConnect): %s; %s"), (LPCTSTR)strTCPError, (LPCTSTR)DbgGetClientInfo());
			Disconnect(strTCPError);
		} else
			Disconnect(_T(""));
	} else
		//This socket may have been delayed by SP2 protection, lets make sure it doesn't time out instantly.
		ResetTimeOutTimer();
}

void CClientReqSocket::OnSend(int nErrorCode)
{
	ResetTimeOutTimer();
	CEMSocket::OnSend(nErrorCode);
}

void CClientReqSocket::OnError(int nErrorCode)
{
	CString strTCPError;
	if (thePrefs.GetVerbose()) {
		if (nErrorCode == ERR_WRONGHEADER)
			strTCPError = _T("Error: Wrong header");
		else if (nErrorCode == ERR_TOOBIG)
			strTCPError = _T("Error: Too much data sent");
		else if (nErrorCode == ERR_ENCRYPTION)
			strTCPError = _T("Error: Encryption layer error");
		else if (nErrorCode == ERR_ENCRYPTION_NOTALLOWED)
			strTCPError = _T("Error: Unencrypted Connection when Encryption was required");
		else
			strTCPError = GetErrorMessage(nErrorCode);
		DebugLogWarning(_T("Client TCP socket: %s; %s"), (LPCTSTR)strTCPError, (LPCTSTR)DbgGetClientInfo());
	}
	Disconnect(strTCPError);
}

bool CClientReqSocket::PacketReceived(Packet *packet)
{
	CString *psErr;
	bool bDelClient;
	const uint8 opcode = packet->opcode;
	const UINT uRawSize = packet->size;
	try {
		try {
			switch (packet->prot) {
			case OP_EDONKEYPROT:
				if (client) {
					if (opcode != OP_HELLO && opcode != OP_HELLOANSWER)
						client->CheckHandshakeFinished();
				} else if (opcode != OP_HELLO) {
					theStats.AddDownDataOverheadOther(packet->size);
					throw GetResString(IDS_ERR_NOHELLO);
				}

				return ProcessPacket((BYTE*)packet->pBuffer, uRawSize, opcode);
			case OP_PACKEDPROT:
				if (!packet->UnPackPacket()) {
					if (thePrefs.GetVerbose())
						DebugLogError(_T("Failed to decompress client TCP packet; %s; %s"), (LPCTSTR)DbgGetClientTCPPacket(packet->prot, packet->opcode, packet->size), (LPCTSTR)DbgGetClientInfo());
					break;
				}
			/* falls through */ // BUG-011 FIX: intentional fall-through after successful unpack
			case OP_EMULEPROT:
				if (opcode != OP_PORTTEST) {
					if (!client) {
						theStats.AddDownDataOverheadOther(uRawSize);
						throw GetResString(IDS_ERR_UNKNOWNCLIENTACTION);
					}
					if (thePrefs.m_iDbgHeap >= 2)
						ASSERT_VALID(client);
				}

				return ProcessExtPacket((BYTE*)packet->pBuffer, packet->size, packet->opcode, uRawSize);
			default:
				theStats.AddDownDataOverheadOther(uRawSize);
				if (thePrefs.GetVerbose())
					DebugLogWarning(_T("Received unknown client TCP packet; %s; %s"), (LPCTSTR)DbgGetClientTCPPacket(packet->prot, packet->opcode, packet->size), (LPCTSTR)DbgGetClientInfo());

				if (client)
					client->SetDownloadState(DS_ERROR, _T("Unknown protocol"));
				Disconnect(_T("Unknown protocol"));
			}
		} catch (CFileException *ex) {
			ex->Delete();
			throw GetResString(IDS_ERR_INVALIDPACKET);
		} catch (CMemoryException *ex) {
			ex->Delete();
			throwCStr(_T("Memory exception"));
		} catch (...) { //trying to catch "Unspecified error"
			throwCStr(_T("Unhandled exception"));
		}
		return true;
	} catch (CClientException *ex) { // similar to 'CString&' exception but client deletion is optional
		bDelClient = ex->m_bDelete;
		psErr = new CString(ex->m_strMsg);
		ex->Delete();
	} catch (const CString &ex) {
		bDelClient = true;
		psErr = new CString(ex);
	}
	//Error handling
	bool bIsDonkey = (packet->prot == OP_EDONKEYPROT);
	LPCTSTR sProtocol = bIsDonkey ? _T("eDonkey") : _T("eMule");
	if (thePrefs.GetVerbose())
		DebugLogWarning(_T("Error: '%s' while processing %s packet: opcode=%s  size=%u; %s")
			, (LPCTSTR)*psErr
			, sProtocol
			, (LPCTSTR)(bIsDonkey ? DbgGetDonkeyClientTCPOpcode(opcode) : DbgGetMuleClientTCPOpcode(opcode))
			, uRawSize
			, (LPCTSTR)DbgGetClientInfo());

	CString sErr2;
	sErr2.Format(_T("Error while processing %s packet:  %s"), (LPCTSTR)sProtocol, (LPCTSTR)*psErr);
	if (bDelClient && client)
		client->SetDownloadState(DS_ERROR, sErr2);
	Disconnect(sErr2);
	delete psErr;
	return false;
}

void CClientReqSocket::OnReceive(int nErrorCode)
{
	ResetTimeOutTimer();
	CEMSocket::OnReceive(nErrorCode);
}

bool CClientReqSocket::Create()
{
	theApp.listensocket->AddConnection();
	return CAsyncSocketEx::Create(0, SOCK_STREAM, FD_WRITE | FD_READ | FD_CLOSE | FD_CONNECT, thePrefs.GetBindAddr());
}

SocketSentBytes CClientReqSocket::SendControlData(uint32 maxNumberOfBytesToSend, uint32 overchargeMaxBytesToSend)
{
	SocketSentBytes returnStatus = CEMSocket::SendControlData(maxNumberOfBytesToSend, overchargeMaxBytesToSend);
	if (returnStatus.success && (returnStatus.sentBytesControlPackets > 0 || returnStatus.sentBytesStandardPackets > 0))
		ResetTimeOutTimer();
	return returnStatus;
}

SocketSentBytes CClientReqSocket::SendFileAndControlData(uint32 maxNumberOfBytesToSend, uint32 overchargeMaxBytesToSend)
{
	SocketSentBytes returnStatus = CEMSocket::SendFileAndControlData(maxNumberOfBytesToSend, overchargeMaxBytesToSend);
	if (returnStatus.success && (returnStatus.sentBytesControlPackets > 0 || returnStatus.sentBytesStandardPackets > 0))
		ResetTimeOutTimer();
	return returnStatus;
}

void CClientReqSocket::SendPacket(Packet *packet, bool controlpacket, uint32 actualPayloadSize, bool bForceImmediateSend)
{
	ResetTimeOutTimer();
	CEMSocket::SendPacket(packet, controlpacket, actualPayloadSize, bForceImmediateSend);
}

bool CListenSocket::SendPortTestReply(char result, bool disconnect)
{
	for (POSITION pos = socket_list.GetHeadPosition(); pos != NULL;) {
		CClientReqSocket *cur_sock = socket_list.GetNext(pos);
		if (cur_sock->m_bPortTestCon) {
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugSend("OP_PortTest", cur_sock->client);
			Packet *replypacket = new Packet(OP_PORTTEST, 1);
			replypacket->pBuffer[0] = result;
			theStats.AddUpDataOverheadOther(replypacket->size);
			cur_sock->SendPacket(replypacket);
			if (disconnect)
				cur_sock->m_bPortTestCon = false;
			return true;
		}
	}
	return false;
}

CListenSocket::CListenSocket()
	: bListening()
	, m_OpenSocketsInterval()
	, maxconnectionreached()
	, m_ConnectionStates()
	, m_nPendingConnections()
	, peakconnections()
	, totalconnectionchecks()
	, averageconnections()
	, activeconnections()
	, m_port()
	, m_nHalfOpen()
	, m_nComp()
{
}

CListenSocket::~CListenSocket()
{
	CListenSocket::Close();
	KillAllSockets();
}

bool CListenSocket::Rebind()
{
	if (thePrefs.GetPort() == m_port)
		return false;

	Close();
	KillAllSockets();

	return StartListening();
}

bool CListenSocket::StartListening()
{
	bListening = true;

	// Creating the socket with SO_REUSEADDR may solve LowID issues if emule was restarted
	// quickly or started after a crash, but(!) it will also create another problem. If the
	// socket is already used by some other application (e.g. a 2nd emule), we though bind
	// to that socket leading to the situation that 2 applications are listening on the same
	// port!

	// v0.71 IPv6 Sprint 3 + Sprint 9 hotfix — dual-stack AF_INET6 listener is
	// now OPT-IN (only IPv6PreferredMode). Real-world testing on Windows
	// 10/11 + consumer routers shows that even with IPV6_V6ONLY=0 and the
	// SOCKADDR_STORAGE OnAccept normalization, the eD2K server TCP callback
	// test and Kad firewall test fail intermittently — the kernel surfaces
	// v4 traffic via WSAAccept paths the legacy code wasn't expecting, and
	// some NAT/conntrack helpers don't see the SYN-ACK in time. Auto mode
	// therefore stays on the rock-solid AF_INET path; users who explicitly
	// pick "IPv6 preferido" in Preferences→Conexión opt into the dual-stack
	// experiment. The v6 prober (FirewallProberV6) still runs in Auto so
	// the panel shows the detected public v6 address either way.
	bool bUsingV6 = false;
	if (thePrefs.GetIPv6Mode() == CPreferences::IPv6PreferredMode) {
		// Bind address NULL means "[::]" — listen on all v6 interfaces. We
		// don't pass thePrefs.GetBindAddr() because it's the v4 bind addr
		// (TCHAR* dotted-quad) and would fail an AF_INET6 parse. If the user
		// configured a specific v6 bind addr, it lives in prefs::IPv6BindAddr.
		LPCTSTR v6Bind = thePrefs.GetIPv6BindAddr();
		if (v6Bind == NULL || v6Bind[0] == 0)
			v6Bind = _T("::");
		if (Create(thePrefs.GetPort(), SOCK_STREAM, FD_ACCEPT, v6Bind, AF_INET6)) {
			// Disable V6ONLY so v4 connections via IPv4-mapped addresses also
			// land on this listener.
			DWORD v6only = 0;
			VERIFY( SetSockOpt(IPV6_V6ONLY, &v6only, sizeof v6only, IPPROTO_IPV6) );
			bUsingV6 = true;
			AddDebugLogLine(false, _T("ListenSocket: dual-stack v6 bound on [%s]:%u (IPV6_V6ONLY=0, opt-in IPv6PreferredMode)"),
				v6Bind, (unsigned)thePrefs.GetPort());
		} else {
			AddDebugLogLine(false, _T("ListenSocket: AF_INET6 Create failed err=%u, falling back to v4-only"),
				::WSAGetLastError());
		}
	}
	if (!bUsingV6) {
		if (!Create(thePrefs.GetPort(), SOCK_STREAM, FD_ACCEPT, thePrefs.GetBindAddr(), AF_INET))
			return false;
	}
	m_bDualStack = bUsingV6;   // v0.71 IPv6 Sprint 9 — expose to UI status bar

	// Rejecting a connection with conditional WSAAccept and not using SO_CONDITIONAL_ACCEPT
	// -------------------------------------------------------------------------------------
	// recv: SYN
	// send: SYN ACK (!)
	// recv: ACK
	// send: ACK RST
	// recv: PSH ACK + OP_HELLO packet
	// send: RST
	// --- 455 total bytes (depending on OP_HELLO packet)
	// In case SO_CONDITIONAL_ACCEPT is not used, the TCP/IP stack establishes the connection
	// before WSAAccept has a chance to reject it. That's why the remote peer starts to send
	// its first data packet.
	// ---
	// Not using SO_CONDITIONAL_ACCEPT gives us 6 TCP packets and the OP_HELLO data. We
	// have to lookup the IP only 1 time. This is still way less traffic than rejecting the
	// connection by closing it after the 'Accept'.

	// Rejecting a connection with conditional WSAAccept and using SO_CONDITIONAL_ACCEPT
	// ---------------------------------------------------------------------------------
	// recv: SYN
	// send: ACK RST
	// recv: SYN
	// send: ACK RST
	// recv: SYN
	// send: ACK RST
	// --- 348 total bytes
	// The TCP/IP stack tries to establish the connection 3 times until it gives up.
	// Furthermore the remote peer experiences a total timeout of ~ 1 minute which is
	// supposed to be the default TCP/IP connection timeout (as noted in MSDN).
	// ---
	// Although we get a total of 6 TCP packets in case of using SO_CONDITIONAL_ACCEPT,
	// it's still less than not using SO_CONDITIONAL_ACCEPT. But, we have to lookup
	// the IP 3 times instead of 1 time.

	//if (thePrefs.GetConditionalTCPAccept() && !thePrefs.GetProxySettings().bUseProxy) {
	//	int iOptVal = 1;
	//	VERIFY( SetSockOpt(SO_CONDITIONAL_ACCEPT, &iOptVal, sizeof iOptVal) );
	//}

	if (!Listen())
		return false;

	m_port = thePrefs.GetPort();
	return true;
}

void CListenSocket::ReStartListening()
{
	bListening = true;

	ASSERT(m_nPendingConnections >= 0);
	if (m_nPendingConnections > 0) {
		--m_nPendingConnections;
		OnAccept(0);
	}
}

void CListenSocket::StopListening()
{
	bListening = false;
	++maxconnectionreached;
}

static int s_iAcceptConnectionCondRejected;

int CALLBACK AcceptConnectionCond(LPWSABUF lpCallerId, LPWSABUF /*lpCallerData*/, LPQOS /*lpSQOS*/, LPQOS /*lpGQOS*/,
	LPWSABUF /*lpCalleeId*/, LPWSABUF /*lpCalleeData*/, GROUP FAR* /*g*/, DWORD_PTR /*dwCallbackData*/) noexcept
{
	if (lpCallerId && lpCallerId->buf && lpCallerId->len >= sizeof SOCKADDR_IN) {
		LPSOCKADDR_IN pSockAddr = (LPSOCKADDR_IN)lpCallerId->buf;
		ASSERT(pSockAddr->sin_addr.s_addr != 0 && pSockAddr->sin_addr.s_addr != INADDR_NONE);

		if (theApp.ipfilter->IsFiltered(pSockAddr->sin_addr.s_addr)) {
			if (thePrefs.GetLogFilteredIPs())
				AddDebugLogLine(false, _T("Rejecting connection attempt (IP=%s) - IP filter (%s)"), (LPCTSTR)ipstr(pSockAddr->sin_addr.s_addr), (LPCTSTR)theApp.ipfilter->GetLastHit());
			s_iAcceptConnectionCondRejected = 1;
			return CF_REJECT;
		}

		if (theApp.clientlist->IsBannedClient(pSockAddr->sin_addr.s_addr)) {
			if (thePrefs.GetLogBannedClients()) {
				CUpDownClient *pClient = theApp.clientlist->FindClientByIP(pSockAddr->sin_addr.s_addr);
				if (pClient != NULL)
					AddDebugLogLine(false, _T("Rejecting connection attempt of banned client %s %s"), (LPCTSTR)ipstr(pSockAddr->sin_addr.s_addr), (LPCTSTR)pClient->DbgGetClientInfo());
			}
			s_iAcceptConnectionCondRejected = 2;
			return CF_REJECT;
		}
	} else if (thePrefs.GetVerbose())
		DebugLogError(_T("Client TCP socket: AcceptConnectionCond unexpected lpCallerId"));

	return CF_ACCEPT;
}

void CListenSocket::OnAccept(int nErrorCode)
{
	if (!nErrorCode) {
		if (++m_nPendingConnections < 1) {
			ASSERT(0);
			m_nPendingConnections = 1;
		}

		if (TooManySockets(true) && !theApp.serverconnect->IsConnecting()) {
			StopListening();
			return;
		}
		if (!bListening)
			ReStartListening(); //If the client is still at maxconnections, this will allow it to go above it. But if you don't, you will get a low ID on all servers.

		uint32 nFataErrors = 0;
		while (m_nPendingConnections > 0) {
			--m_nPendingConnections;

			CClientReqSocket *newclient;
			// v0.71 IPv6 Sprint 9 hotfix — when the listener is bound as
			// AF_INET6 (dual-stack), incoming v4 connections arrive as
			// IPv4-mapped IPv6 addresses (::ffff:1.2.3.4) wrapped in a
			// SOCKADDR_IN6 (28 bytes). Using a SOCKADDR_IN (16 bytes)
			// buffer truncates the address and Accept() either returns
			// junk in sin_addr.s_addr or fails silently — which makes
			// Kad report TCP "firewalled" because no inbound connections
			// reach the upper-layer dispatcher.
			// Fix: use SOCKADDR_STORAGE (>= 28 bytes) and normalize to
			// SOCKADDR_IN after the Accept call. v6-native peers (not
			// v4-mapped) are dropped here for now — the rest of eMule
			// only understands v4 endpoints; full v6 peer support is
			// future work.
			SOCKADDR_STORAGE SockStorage = {};
			SOCKADDR_IN SockAddr = {};
			int iSockAddrLen = (int)sizeof SockStorage;
			if (thePrefs.GetConditionalTCPAccept() && !thePrefs.GetProxySettings().bUseProxy) {
				s_iAcceptConnectionCondRejected = 0;
				SOCKET sNew = WSAAccept(m_SocketData.hSocket, (LPSOCKADDR)&SockStorage, &iSockAddrLen, AcceptConnectionCond, 0);
				if (sNew == INVALID_SOCKET) {
					DWORD nError = CAsyncSocket::GetLastError();
					if (nError == WSAEWOULDBLOCK) {
						DebugLogError(LOG_STATUSBAR, _T("%hs: Backlog counter says %u connections waiting, Accept() says WSAEWOULDBLOCK - setting counter to zero!"), __FUNCTION__, m_nPendingConnections);
						m_nPendingConnections = 0;
						break;
					}

					if (nError != WSAECONNREFUSED || s_iAcceptConnectionCondRejected == 0) {
						DebugLogError(LOG_STATUSBAR, _T("%hs: Backlog counter says %u connections waiting, Accept() says %s - setting counter to zero!"), __FUNCTION__, m_nPendingConnections, (LPCTSTR)GetErrorMessage(nError, 1));
						if (++nFataErrors > 10) {
							// the question is what todo on an error. We can't just ignore it because then the backlog will fill up
							// and lock everything. We cannot also just endlessly try to repeat it because this will lock up eMule
							// this should basically never happen anyway
							// however if we are in such position, try to reinitialize the socket.
							DebugLogError(LOG_STATUSBAR, _T("%hs: Accept() Error Loop, recreating socket"), __FUNCTION__);
							Close();
							StartListening();
							m_nPendingConnections = 0;
							break;
						}
					} else if (s_iAcceptConnectionCondRejected == 1)
						++theStats.filteredclients;

					continue;
				}
				newclient = new CClientReqSocket;
				VERIFY(newclient->InitAsyncSocketExInstance());
				newclient->m_SocketData.hSocket = sNew;
				newclient->AttachHandle();

				// Normalize address: v4 → SOCKADDR_IN direct;
				// v6 v4-mapped → extract last 4 bytes; v6 native → drop.
				if (SockStorage.ss_family == AF_INET) {
					memcpy(&SockAddr, &SockStorage, sizeof SockAddr);
				} else if (SockStorage.ss_family == AF_INET6) {
					SOCKADDR_IN6 *p6 = (SOCKADDR_IN6*)&SockStorage;
					if (IN6_IS_ADDR_V4MAPPED(&p6->sin6_addr)) {
						SockAddr.sin_family      = AF_INET;
						SockAddr.sin_port        = p6->sin6_port;
						// v4 lives in the last 4 bytes of the v6 addr.
						memcpy(&SockAddr.sin_addr.s_addr,
							   &p6->sin6_addr.u.Byte[12], 4);
					} else {
						// Native v6 peer — no upper-layer handling yet.
						DebugLogWarning(_T("Native v6 peer dropped (upper-layer is v4-only): %hs"),
							"::");
						newclient->Safe_Delete();
						continue;
					}
				} else {
					newclient->Safe_Delete();
					continue;
				}

				AddConnection();
			} else {
				newclient = new CClientReqSocket;
				if (!Accept(*newclient, (LPSOCKADDR)&SockStorage, &iSockAddrLen)) {
					newclient->Safe_Delete();
					DWORD nError = CAsyncSocket::GetLastError();
					if (nError == WSAEWOULDBLOCK) {
						DebugLogError(LOG_STATUSBAR, _T("%hs: Backlog counter says %u connections waiting, Accept() says WSAEWOULDBLOCK - setting counter to zero!"), __FUNCTION__, m_nPendingConnections);
						m_nPendingConnections = 0;
						break;
					}
					DebugLogError(LOG_STATUSBAR, _T("%hs: Backlog counter says %u connections waiting, Accept() says %s - setting counter to zero!"), __FUNCTION__, m_nPendingConnections, (LPCTSTR)GetErrorMessage(nError, 1));
					if (++nFataErrors > 10) {
						// the question is what to do on an error. We can't just ignore it because then the backlog will fill up
						// and lock everything. We cannot also just endlessly try to repeat it because this will lock up eMule
						// this should basically never happen anyway
						// however if we are in such a position, try to reinitialize the socket.
						DebugLogError(LOG_STATUSBAR, _T("%hs: Accept() Error Loop, recreating socket"), __FUNCTION__);
						Close();
						StartListening();
						m_nPendingConnections = 0;
						break;
					}
					continue;
				}

				AddConnection();

				// v0.71 IPv6 Sprint 9 hotfix — normalize as above for the
				// non-conditional Accept path. Same rationale.
				if (SockStorage.ss_family == AF_INET) {
					memcpy(&SockAddr, &SockStorage, sizeof SockAddr);
				} else if (SockStorage.ss_family == AF_INET6) {
					SOCKADDR_IN6 *p6 = (SOCKADDR_IN6*)&SockStorage;
					if (IN6_IS_ADDR_V4MAPPED(&p6->sin6_addr)) {
						SockAddr.sin_family = AF_INET;
						SockAddr.sin_port   = p6->sin6_port;
						memcpy(&SockAddr.sin_addr.s_addr,
							   &p6->sin6_addr.u.Byte[12], 4);
					} else {
						DebugLogWarning(_T("Native v6 peer dropped (upper-layer is v4-only)"));
						newclient->Safe_Delete();
						continue;
					}
				} else {
					newclient->Safe_Delete();
					continue;
				}

				if (SockAddr.sin_addr.s_addr == INADDR_ANY) { // for safety.
					int iLen4 = (int)sizeof SockAddr;
					newclient->GetPeerName((LPSOCKADDR)&SockAddr, &iLen4);
					DebugLogWarning(_T("SockAddr.sin_addr.s_addr == 0;  GetPeerName returned %s"), (LPCTSTR)ipstr(SockAddr.sin_addr.s_addr));
				}

				ASSERT(SockAddr.sin_addr.s_addr != INADDR_ANY && SockAddr.sin_addr.s_addr != INADDR_NONE);

				if (theApp.ipfilter->IsFiltered(SockAddr.sin_addr.s_addr)) {
					if (thePrefs.GetLogFilteredIPs())
						AddDebugLogLine(false, _T("Rejecting connection attempt (IP=%s) - IP filter (%s)"), (LPCTSTR)ipstr(SockAddr.sin_addr.s_addr), (LPCTSTR)theApp.ipfilter->GetLastHit());
					newclient->Safe_Delete();
					++theStats.filteredclients;
					continue;
				}

				if (theApp.clientlist->IsBannedClient(SockAddr.sin_addr.s_addr)) {
					if (thePrefs.GetLogBannedClients()) {
						CUpDownClient *pClient = theApp.clientlist->FindClientByIP(SockAddr.sin_addr.s_addr);
						if (pClient)
							AddDebugLogLine(false, _T("Rejecting connection attempt of banned client %s %s"), (LPCTSTR)ipstr(SockAddr.sin_addr.s_addr), (LPCTSTR)pClient->DbgGetClientInfo());
					}
					newclient->Safe_Delete();
					continue;
				}
			}
			newclient->AsyncSelect(FD_WRITE | FD_READ | FD_CLOSE);
		}

		ASSERT(m_nPendingConnections >= 0);
	}
}

void CListenSocket::Process()
{
	m_OpenSocketsInterval = 0;
	for (POSITION pos = socket_list.GetHeadPosition(); pos != NULL;) {
		CClientReqSocket *cur_sock = socket_list.GetNext(pos);
		if (cur_sock->deletethis) {
			if (cur_sock->m_SocketData.hSocket != INVALID_SOCKET)
				cur_sock->Close();			// calls 'closesocket'
			else
				cur_sock->Delete_Timed();	// may delete 'cur_sock'
		} else
			cur_sock->CheckTimeOut();		// may call 'shutdown'
	}

	if ((GetOpenSockets() + 5 < thePrefs.GetMaxConnections() || theApp.serverconnect->IsConnecting()) && !bListening)
		ReStartListening();
}

void CListenSocket::RecalculateStats()
{
	memset(m_ConnectionStates, 0, sizeof m_ConnectionStates);
	for (POSITION pos = socket_list.GetHeadPosition(); pos != NULL;)
		switch (socket_list.GetNext(pos)->GetConState()) {
		case EMS_DISCONNECTED:
			++m_ConnectionStates[0];
			break;
		case EMS_NOTCONNECTED:
			++m_ConnectionStates[1];
			break;
		case EMS_CONNECTED:
			++m_ConnectionStates[2];
		}
}

void CListenSocket::AddSocket(CClientReqSocket *toadd)
{
	socket_list.AddTail(toadd);
}

void CListenSocket::RemoveSocket(CClientReqSocket *todel)
{
	POSITION pos = socket_list.Find(todel);
	if (pos != NULL)
		socket_list.RemoveAt(pos);
}

void CListenSocket::KillAllSockets()
{
	while (!socket_list.IsEmpty()) {
		const CClientReqSocket *cur_socket = socket_list.GetHead();
		if (cur_socket->client)
			delete cur_socket->client;
		else
			delete cur_socket;
	}
}

void CListenSocket::AddConnection()
{
	++m_OpenSocketsInterval;
}

bool CListenSocket::TooManySockets(bool bIgnoreInterval)
{
	return GetOpenSockets() > thePrefs.GetMaxConnections()
		|| (m_OpenSocketsInterval > thePrefs.GetMaxConperFive() * GetMaxConperFiveModifier() && !bIgnoreInterval)
		|| (m_nHalfOpen >= thePrefs.GetMaxHalfConnections() && !bIgnoreInterval);
}

bool CListenSocket::IsValidSocket(CClientReqSocket *totest)
{
	return socket_list.Find(totest) != NULL;
}

#ifdef _DEBUG
void CListenSocket::Debug_ClientDeleted(CUpDownClient *deleted)
{
	for (POSITION pos = socket_list.GetHeadPosition(); pos != NULL;) {
		CClientReqSocket *cur_sock = socket_list.GetNext(pos);
		if (!cur_sock)
			AfxDebugBreak();
		if (thePrefs.m_iDbgHeap >= 2)
			ASSERT_VALID(cur_sock);
		if (cur_sock->client == deleted)
			AfxDebugBreak();
	}
}
#endif

void CListenSocket::UpdateConnectionsStatus()
{
	activeconnections = GetOpenSockets();

	// Update statistics for 'peak connections'
	if (peakconnections < activeconnections)
		peakconnections = activeconnections;
	if (peakconnections > thePrefs.GetConnPeakConnections())
		thePrefs.SetConnPeakConnections(peakconnections);

	if (theApp.IsConnected()) {
		if (++totalconnectionchecks == 0)
			 // wrap around occurred, avoid division by zero
			totalconnectionchecks = 100;

		// Get a weight for the 'avg. connections' value. The longer we run the higher
		// gets the weight (the percent of 'avg. connections' we use).
		float fPercent = (totalconnectionchecks - 1) / (float)totalconnectionchecks;
		if (fPercent > 0.99f)
			fPercent = 0.99f;

		// The longer we run the more we use the 'avg. connections' value and the less we
		// use the 'active connections' value. However, if we are running quite some time
		// without any connections (except the server connection) we will eventually create
		// a floating point underflow exception.
		averageconnections = averageconnections * fPercent + activeconnections * (1.0f - fPercent);
		if (averageconnections < 0.001f)
			averageconnections = 0.001f;	// avoid floating point underflow
	}
}

float CListenSocket::GetMaxConperFiveModifier()
{
	float SpikeSize = max(1.0f, GetOpenSockets() - averageconnections);
	float SpikeTolerance = 25.0f * thePrefs.GetMaxConperFive() / 10.0f;

	return (SpikeSize > SpikeTolerance) ? 0.0f : 1.0f - SpikeSize / SpikeTolerance;
}
