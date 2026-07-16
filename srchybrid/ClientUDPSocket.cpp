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
#include "emule.h"
#include "ClientUDPSocket.h"
#include "Packets.h"
#include "UpDownClient.h"
#include "DownloadQueue.h"
#include "Statistics.h"
#include "PartFile.h"
#include "SharedFileList.h"
#include "UploadQueue.h"
#include "Preferences.h"
#include "ClientList.h"
#include "EncryptedDatagramSocket.h"
#include "IPFilter.h"
#include "Listensocket.h"
#include "Log.h"
#include "SafeFile.h"
#include "kademlia/kademlia/Kademlia.h"
#include "kademlia/kademlia/UDPFirewallTester.h"
#include "kademlia/net/KademliaUDPListener.h"
#include "kademlia/io/IOException.h"
#include "kademlia/kademlia/prefs.h"
#include "kademlia/utils/KadUDPKey.h"
#include "zlib/zlib.h"
#include "eMuleAI/UtpSocket.h" // eSE: uTP NAT traversal bridge
#include "eMuleAI/Address.h"
#include "Opcodes.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif


// CClientUDPSocket

static void UpdateHolePunchRuntimeCaps(bool bReady)
{
	volatile LONG* pCaps = reinterpret_cast<volatile LONG*>(&g_uEseCapsRuntime);
	const LONG mask = (LONG)(ESE_CAP_HOLEPUNCH_COOKIE | ESE_CAP_HOLEPUNCH_RDV);
	::InterlockedAnd(pCaps, ~mask);
	if (bReady && thePrefs.GetUtpHolePunchEnabled()) {
		::InterlockedOr(pCaps, (LONG)ESE_CAP_HOLEPUNCH_COOKIE);
		if (thePrefs.GetEseKad3Rendezvous())
			::InterlockedOr(pCaps, (LONG)ESE_CAP_HOLEPUNCH_RDV);
	}
}

CClientUDPSocket::CClientUDPSocket()
{
	m_bWouldBlock = false;
	m_bDualStack = false;
	m_bIPv6BindRequested = false;
	m_port = 0;
}

CClientUDPSocket::~CClientUDPSocket()
{
	theApp.uploadBandwidthThrottler->RemoveFromAllQueuesLocked(this); // ZZ:UploadBandWithThrottler (UDP)
	while (!controlpacket_queue.IsEmpty()) {
		const UDPPack *p = controlpacket_queue.RemoveHead();
		delete p->packet;
		delete p;
	}
	// Destroy the shared uTP context (must happen after all CUtpSocket instances
	// using it are destroyed, which is guaranteed by eMule shutdown order).
	if (m_pUtpContext) {
		CUtpSocket::OnContextDestroyed((utp_context*)m_pUtpContext);
		utp_destroy((utp_context*)m_pUtpContext);
		m_pUtpContext = NULL;
	}
}

void CClientUDPSocket::OnReceive(int nErrorCode)
{
	if (nErrorCode) {
		if (thePrefs.GetVerbose())
			DebugLogError(_T("Error: Client UDP socket, error on receive event: %s"), (LPCTSTR)GetErrorMessage(nErrorCode, 1));
	}

	BYTE buffer[8192]; //5000 was too low sometimes
	SOCKADDR_STORAGE rawSockAddr = {};
	int iRawSockAddrLen = sizeof rawSockAddr;
	int nRealLen = ReceiveFrom(buffer, sizeof buffer,
		(LPSOCKADDR)&rawSockAddr, &iRawSockAddrLen);
	if (nRealLen == SOCKET_ERROR) {
		const DWORD dwError = (DWORD)CAsyncSocket::GetLastError();
		if (dwError != WSAEWOULDBLOCK && dwError != WSAECONNRESET
			&& thePrefs.GetVerbose())
			DebugLogError(_T("Error: Client UDP socket receive failed: %s"),
				(LPCTSTR)GetErrorMessage(dwError, 1));
		return;
	}

	CAddress sourceAddress;
	uint16 sourcePort = 0;
	sourceAddress.FromSA((const sockaddr*)&rawSockAddr, iRawSockAddrLen,
		&sourcePort);
	if (sourcePort == 0 || sourceAddress.IsNull())
		return;

	// Native IPv6 never enters legacy UDP obfuscation or the uint32-keyed Kad2
	// routing table. K6-2 owns only these bounded plaintext routing opcodes.
	if (sourceAddress.GetType() == CAddress::IPv6) {
		if (!sourceAddress.IsPublicIP())
			return;
		if (nRealLen > 0 && CUtpSocket::FeedRawUdp(buffer, nRealLen,
				(const sockaddr*)&rawSockAddr, iRawSockAddrLen))
			return;
		if (nRealLen < 2 || buffer[0] != OP_KADEMLIAHEADER)
			return;
		switch (buffer[1]) {
			case KADEMLIA3_BOOTSTRAP_REQ:
			case KADEMLIA3_BOOTSTRAP_RES:
			case KADEMLIA3_HELLO_REQ:
			case KADEMLIA3_HELLO_RES:
			case KADEMLIA3_REQ:
			case KADEMLIA3_RES:
				theStats.AddDownDataOverheadKad(nRealLen);
				Kademlia::CKademlia::ProcessPacketV6(buffer, nRealLen,
					sourceAddress.Data(), sourcePort);
				break;
			default:
				break;
		}
		return;
	}
	if (sourceAddress.GetType() != CAddress::IPv4)
		return;

	// AF_INET6 dual-stack sockets report IPv4 senders as mapped addresses.
	// Normalize those to the exact sockaddr_in form expected by all existing
	// uTP, IP-filter, encryption and Kad2 code below.
	SOCKADDR_IN sockAddr = {};
	sockAddr.sin_family = AF_INET;
	sockAddr.sin_port = htons(sourcePort);
	sockAddr.sin_addr.s_addr = sourceAddress.ToUInt32(false);
	int iSockAddrLen = sizeof sockAddr;
	if (theApp.ipfilter->IsFiltered(sockAddr.sin_addr.s_addr) || theApp.clientlist->IsBannedClient(sockAddr.sin_addr.s_addr) || !sockAddr.sin_port)
		return;

	// eSE: Feed raw UDP data to libutp BEFORE eMule protocol decryption.
	// uTP packets have their own binary format (version byte, connection IDs, etc.)
	// and must NOT pass through DecryptReceivedClient which would corrupt them.
	// If libutp recognizes this as a uTP packet, it handles it internally and we're done.
	if (nRealLen > 0 && CUtpSocket::FeedRawUdp(buffer, nRealLen, (const sockaddr*)&sockAddr, iSockAddrLen))
		return; // consumed by libutp

	BYTE *pBuffer;
	uint32 nReceiverVerifyKey;
	uint32 nSenderVerifyKey;
	int nPacketLen = DecryptReceivedClient(buffer, nRealLen, &pBuffer, sockAddr.sin_addr.s_addr, &nReceiverVerifyKey, &nSenderVerifyKey);
	if (nPacketLen > 0) {
		CString strError;
		try {
			switch (pBuffer[0]) {
			case OP_EMULEPROT:
				if (nPacketLen < 2)
					strError = _T("eMule packet too short");
				else
					ProcessPacket(pBuffer + 2, nPacketLen - 2, pBuffer[1], sockAddr.sin_addr.s_addr, ntohs(sockAddr.sin_port));
				break;
			case OP_KADEMLIAPACKEDPROT:
				theStats.AddDownDataOverheadKad(nPacketLen);
				if (nPacketLen < 2)
					strError = _T("Kad packet (compressed) too short");
				else {
					BYTE *unpack = NULL;
					uLongf unpackedsize = 0;
					uint32 nNewSize = nPacketLen * 10 + 300;
					int iZLibResult = Z_OK;
					do {
						delete[] unpack;
						unpack = new BYTE[nNewSize];
						unpackedsize = nNewSize - 2;
						iZLibResult = uncompress(unpack + 2, &unpackedsize, pBuffer + 2, nPacketLen - 2);
						nNewSize *= 2; // size for the next try if needed
					} while (iZLibResult == Z_BUF_ERROR && nNewSize < 250000);

					if (iZLibResult != Z_OK) {
						delete[] unpack;
						strError.Format(_T("Failed to uncompress Kad packet: zip error: %d (%hs)"), iZLibResult, zError(iZLibResult));
					} else {
						unpack[0] = OP_KADEMLIAHEADER;
						unpack[1] = pBuffer[1];
						try {
							Kademlia::CKademlia::ProcessPacket(unpack, unpackedsize + 2
								, ntohl(sockAddr.sin_addr.s_addr), ntohs(sockAddr.sin_port)
								, (Kademlia::CPrefs::GetUDPVerifyKey(sockAddr.sin_addr.s_addr) == nReceiverVerifyKey)
								, Kademlia::CKadUDPKey(nSenderVerifyKey, theApp.GetPublicIP()));
						} catch (...) {
							delete[] unpack;
							throw;
						}
						delete[] unpack;
					}
				}
				break;
			case OP_KADEMLIAHEADER:
				theStats.AddDownDataOverheadKad(nPacketLen);
				if (nPacketLen < 2)
					strError = _T("Kad packet too short");
				else
					Kademlia::CKademlia::ProcessPacket(pBuffer, nPacketLen, ntohl(sockAddr.sin_addr.s_addr), ntohs(sockAddr.sin_port)
						, (Kademlia::CPrefs::GetUDPVerifyKey(sockAddr.sin_addr.s_addr) == nReceiverVerifyKey)
						, Kademlia::CKadUDPKey(nSenderVerifyKey, theApp.GetPublicIP()));
				break;
			default:
				strError.Format(_T("Unknown protocol 0x%02x"), pBuffer[0]);
			}
			//code above does not need to throw strError
		} catch (CFileException *ex) {
			ex->Delete();
			strError = _T("Invalid packet received");
		} catch (CMemoryException *ex) {
			ex->Delete();
			strError = _T("Memory exception");
		} catch (const CString &ex) {
			strError = ex;
		} catch (Kademlia::CIOException *ex) {
			ex->Delete();
			strError = _T("Invalid packet received");
		} catch (CException *ex) {
			ex->Delete();
			strError = _T("General packet error");
#ifndef _DEBUG
		} catch (...) {
			strError = _T("Unknown exception");
			ASSERT(0);
#endif
		}
		if (thePrefs.GetVerbose() && !strError.IsEmpty()) {
			CString strClientInfo;
			CUpDownClient *client;
			if (pBuffer[0] == OP_EMULEPROT)
				client = theApp.clientlist->FindClientByIP_UDP(sockAddr.sin_addr.s_addr, ntohs(sockAddr.sin_port));
			else
				client = theApp.clientlist->FindClientByIP_KadPort(sockAddr.sin_addr.s_addr, ntohs(sockAddr.sin_port));
			if (client)
				strClientInfo = client->DbgGetClientInfo();
			else
				strClientInfo.Format(_T("%s:%hu"), (LPCTSTR)ipstr(sockAddr.sin_addr), ntohs(sockAddr.sin_port));

			DebugLogWarning(_T("Client UDP socket: prot=0x%02x  opcode=0x%02x  sizeaftercrypt=%u realsize=%u  %s: %s"), pBuffer[0], pBuffer[1], nPacketLen, nRealLen, (LPCTSTR)strError, (LPCTSTR)strClientInfo);
		}
	} else if (nPacketLen == SOCKET_ERROR) {
		DWORD dwError = WSAGetLastError();
		if (dwError == WSAECONNRESET) {
			// Depending on local and remote OS and depending on used local (remote?) router we may receive
			// WSAECONNRESET errors. According to some KB articles, this is a special way of winsock to report
			// that a sent UDP packet was not received by the remote host because it was not listening on
			// the specified port -> no eMule running there.
			//
			// TODO: So, actually we should do something with this information and drop the related Kad node
			// or eMule client...
			;
		} else if (thePrefs.GetVerbose()) {
			CString strClientInfo;
			if (iSockAddrLen > 0 && sockAddr.sin_addr.s_addr != 0 && sockAddr.sin_addr.s_addr != INADDR_NONE)
				strClientInfo.Format(_T(" from %s:%u"), (LPCTSTR)ipstr(sockAddr.sin_addr), ntohs(sockAddr.sin_port));
			DebugLogError(_T("Error: Client UDP socket, failed to receive data%s: %s"), (LPCTSTR)strClientInfo, (LPCTSTR)GetErrorMessage(dwError, 1));
		}
	}
}

bool CClientUDPSocket::ProcessPacket(const BYTE *packet, UINT size, uint8 opcode, uint32 ip, uint16 port)
{
	switch (opcode) {
	case OP_REASKCALLBACKUDP:
		{
			if (thePrefs.GetDebugClientUDPLevel() > 0)
				DebugRecv("OP_ReaskCallbackUDP", NULL, NULL, ip);
			theStats.AddDownDataOverheadOther(size);
			CUpDownClient *buddy = theApp.clientlist->GetBuddy();
			if (buddy) {
				if (size < 17 || buddy->socket == NULL)
					break;
				if (md4equ(packet, buddy->GetBuddyID())) {
					PokeUInt32(const_cast<BYTE*>(packet) + 10, ip);
					PokeUInt16(const_cast<BYTE*>(packet) + 14, port);
					Packet *response = new Packet(OP_EMULEPROT);
					response->opcode = OP_REASKCALLBACKTCP;
					response->pBuffer = new char[size - 10]; // BUG-018 FIX: allocate exact needed size
					memcpy(response->pBuffer, packet + 10, size - 10);
					response->size = size - 10;
					if (thePrefs.GetDebugClientTCPLevel() > 0)
						DebugSend("OP_ReaskCallbackTCP", buddy);
					theStats.AddUpDataOverheadFileRequest(response->size);
					buddy->SendPacket(response);
				}
			}
		}
		break;
	case OP_REASKFILEPING:
		{
			theStats.AddDownDataOverheadFileRequest(size);
			CSafeMemFile data_in(packet, size);
			uchar reqfilehash[MDX_DIGEST_SIZE];
			data_in.ReadHash16(reqfilehash);
			CKnownFile *reqfile = theApp.sharedfiles->GetFileByID(reqfilehash);

			bool bSenderMultipleIpUnknown = false;
			CUpDownClient *sender = theApp.uploadqueue->GetWaitingClientByIP_UDP(ip, port, true, &bSenderMultipleIpUnknown);
			if (!reqfile) {
				if (thePrefs.GetDebugClientUDPLevel() > 0) {
					DebugRecv("OP_ReaskFilePing", NULL, reqfilehash, ip);
					DebugSend("OP_FileNotFound", NULL);
				}

				Packet *response = new Packet(OP_FILENOTFOUND, 0, OP_EMULEPROT);
				theStats.AddUpDataOverheadFileRequest(response->size);
				if (sender != NULL)
					SendPacket(response, ip, port, sender->ShouldReceiveCryptUDPPackets(), sender->GetUserHash(), false, 0);
				else
					SendPacket(response, ip, port, false, NULL, false, 0);
				break;
			}
			if (sender) {
				if (thePrefs.GetDebugClientUDPLevel() > 0)
					DebugRecv("OP_ReaskFilePing", sender, reqfilehash);

				//Make sure we are still thinking about the same file
				if (md4equ(reqfilehash, sender->GetUploadFileID())) {
					sender->IncrementAskedCount();
					sender->SetLastUpRequest();
					//I messed up when I first added extended info to UDP
					//I should have originally used the entire ProcessExtendedInfo the first time.
					//So now I am forced to check UDPVersion to see if we are sending all the extended info.
					//From now on, we should not have to change anything here if we change
					//something in the extended info data as this will be taken care of in ProcessExtendedInfo()
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
					if (sender->GetUDPVersion() > 3) {
						if (reqfile->IsPartFile())
							static_cast<CPartFile*>(reqfile)->WritePartStatus(data_out);
						else
							data_out.WriteUInt16(0);
					}
					data_out.WriteUInt16((uint16)(theApp.uploadqueue->GetWaitingPosition(sender)));
					if (thePrefs.GetDebugClientUDPLevel() > 0)
						DebugSend("OP_ReaskAck", sender);
					Packet *response = new Packet(data_out, OP_EMULEPROT);
					response->opcode = OP_REASKACK;
					theStats.AddUpDataOverheadFileRequest(response->size);
					SendPacket(response, ip, port, sender->ShouldReceiveCryptUDPPackets(), sender->GetUserHash(), false, 0);
				} else {
					DebugLogError(_T("Client UDP socket; ReaskFilePing; reqfile does not match"));
					TRACE(_T("m_reqfile:         %s\n"), (LPCTSTR)DbgGetFileInfo(reqfile->GetFileHash()));
					TRACE(_T("sender->GetRequestFile(): %s\n"), sender->GetRequestFile() ? (LPCTSTR)DbgGetFileInfo(sender->GetRequestFile()->GetFileHash()) : _T("(null)"));
				}
			} else {
				if (thePrefs.GetDebugClientUDPLevel() > 0)
					DebugRecv("OP_ReaskFilePing", NULL, reqfilehash, ip);
				// Don't answer him. We probably have him on our queue already, but can't locate him. Force him to establish a TCP connection
				if (!bSenderMultipleIpUnknown) {
					if (theApp.uploadqueue->GetWaitingUserCount() + 50 > thePrefs.GetQueueSize()) {
						if (thePrefs.GetDebugClientUDPLevel() > 0)
							DebugSend("OP_QueueFull", NULL);
						Packet *response = new Packet(OP_QUEUEFULL, 0, OP_EMULEPROT);
						theStats.AddUpDataOverheadFileRequest(response->size);
						SendPacket(response, ip, port, false, NULL, false, 0); // we cannot answer this one encrypted since we don't know this client
					}
				} else
					DebugLogWarning(_T("UDP Packet received - multiple clients with the same IP but different UDP port found. Possible UDP Port mapping problem, enforcing TCP connection. IP: %s, Port: %u"), (LPCTSTR)ipstr(ip), port);
			}
		}
		break;
	case OP_QUEUEFULL:
		{
			theStats.AddDownDataOverheadFileRequest(size);
			CUpDownClient *sender = theApp.downloadqueue->GetDownloadClientByIP_UDP(ip, port, true);
			if (thePrefs.GetDebugClientUDPLevel() > 0)
				DebugRecv("OP_QueueFull", sender, NULL, ip);
			if (sender && sender->UDPPacketPending()) {
				sender->SetRemoteQueueFull(true);
				sender->UDPReaskACK(0);
			} else if (sender != NULL)
				DebugLogError(_T("Received UDP Packet (OP_QUEUEFULL) which was not requested (pendingflag == false); Ignored packet - %s"), (LPCTSTR)sender->DbgGetClientInfo());
		}
		break;
	case OP_REASKACK:
		{
			theStats.AddDownDataOverheadFileRequest(size);
			CUpDownClient *sender = theApp.downloadqueue->GetDownloadClientByIP_UDP(ip, port, true);
			if (thePrefs.GetDebugClientUDPLevel() > 0)
				DebugRecv("OP_ReaskAck", sender, NULL, ip);
			if (sender && sender->UDPPacketPending()) {
				CSafeMemFile data_in(packet, size);
				if (sender->GetUDPVersion() > 3)
					sender->ProcessFileStatus(true, data_in, sender->GetRequestFile());

				uint16 nRank = data_in.ReadUInt16();
				sender->SetRemoteQueueFull(false);
				sender->UDPReaskACK(nRank);
				sender->IncrementAskedCountDown();
			} else if (sender != NULL)
				DebugLogError(_T("Received UDP Packet (OP_REASKACK) which was not requested (pendingflag == false); Ignored packet - %s"), (LPCTSTR)sender->DbgGetClientInfo());
		}
		break;
	case OP_FILENOTFOUND:
		{
			theStats.AddDownDataOverheadFileRequest(size);
			CUpDownClient *sender = theApp.downloadqueue->GetDownloadClientByIP_UDP(ip, port, true);
			if (thePrefs.GetDebugClientUDPLevel() > 0)
				DebugRecv("OP_FileNotFound", sender, NULL, ip);
			if (sender != NULL)
				if (sender->UDPPacketPending())
					sender->UDPReaskFNF(); // may delete 'sender'!
				else
					DebugLogError(_T("Received UDP Packet (OP_FILENOTFOUND) which was not requested (pendingflag == false); Ignored packet - %s"), (LPCTSTR)sender->DbgGetClientInfo());

			break;
		}
	case OP_PORTTEST:
		if (thePrefs.GetDebugClientUDPLevel() > 0)
			DebugRecv("OP_PortTest", NULL, NULL, ip);
		theStats.AddDownDataOverheadOther(size);
		if (size == 1 && packet[0] == 0x12) {
			bool ret = theApp.listensocket->SendPortTestReply('1', true);
			AddDebugLogLine(true, _T("UDP Port check packet arrived - ACK sent back (status=%i)"), ret);
		}
		break;
	case OP_DIRECTCALLBACKREQ:
		{
			if (thePrefs.GetDebugClientUDPLevel() > 0)
				DebugRecv("OP_DIRECTCALLBACKREQ", NULL, NULL, ip);
			if (!theApp.clientlist->AllowCalbackRequest(ip)) {
				DebugLogWarning(_T("Ignored DirectCallback Request because this IP (%s) has sent too many request within a short time"), (LPCTSTR)ipstr(ip));
				break;
			}
			// do we accept callback requests at all?
			if (Kademlia::CKademlia::IsRunning() && Kademlia::CKademlia::IsFirewalled()) {
				theApp.clientlist->AddTrackCallbackRequests(ip);
				CSafeMemFile data(packet, size);
				uint16 nRemoteTCPPort = data.ReadUInt16();
				uchar uchUserHash[MDX_DIGEST_SIZE];
				data.ReadHash16(uchUserHash);
				uint8 byConnectOptions = data.ReadUInt8();
				CUpDownClient *pRequester = theApp.clientlist->FindClientByUserHash(uchUserHash, ip, nRemoteTCPPort);
				if (pRequester == NULL) {
					pRequester = new CUpDownClient(NULL, nRemoteTCPPort, ip, 0, 0, true);
					pRequester->SetUserHash(uchUserHash);
					theApp.clientlist->AddClient(pRequester);
				} else {
					pRequester->SetConnectIP(ip);
					pRequester->SetUserPort(nRemoteTCPPort);
				}
				pRequester->SetConnectOptions(byConnectOptions, true, false);
				pRequester->SetDirectUDPCallbackSupport(false);
				DEBUG_ONLY(DebugLog(_T("Accepting incoming DirectCallbackRequest from %s"), (LPCTSTR)pRequester->DbgGetClientInfo()));
				pRequester->TryToConnect();
			} else
				DebugLogWarning(_T("Ignored DirectCallback Request because we do not accept DirectCall backs at all (%s)"), (LPCTSTR)ipstr(ip));
		}
		break;
	default:
		theStats.AddDownDataOverheadOther(size);
		if (thePrefs.GetDebugClientUDPLevel() > 0) {
			CUpDownClient *sender = theApp.downloadqueue->GetDownloadClientByIP_UDP(ip, port, true);
			Debug(_T("Unknown client UDP packet: host=%s:%u (%s) opcode=0x%02x  size=%u\n"), (LPCTSTR)ipstr(ip), port, sender ? (LPCTSTR)sender->DbgGetClientInfo() : _T(""), opcode, size);
		}
		return false;
	}
	return true;
}

void CClientUDPSocket::OnSend(int nErrorCode)
{
	if (nErrorCode) {
		if (thePrefs.GetVerbose())
			DebugLogError(_T("Error: Client UDP socket, error on send event: %s"), (LPCTSTR)GetErrorMessage(nErrorCode, 1));
		return;
	}

// ZZ:UploadBandWithThrottler (UDP) -->
	sendLocker.Lock();
	m_bWouldBlock = false;

	if (!controlpacket_queue.IsEmpty())
		theApp.uploadBandwidthThrottler->QueueForSendingControlPacket(this);
	sendLocker.Unlock();
// <-- ZZ:UploadBandWithThrottler (UDP)
}

SocketSentBytes CClientUDPSocket::SendControlData(uint32 maxNumberOfBytesToSend, uint32 /*minFragSize*/)
{
// ZZ:UploadBandWithThrottler (UDP) -->
// NOTE: *** This function is invoked from a *different* thread!
	uint32 sentBytes = 0;
	DWORD curTick;

	sendLocker.Lock();
// <-- ZZ:UploadBandWithThrottler (UDP)
	curTick = ::GetTickCount();
	while (!controlpacket_queue.IsEmpty() && !IsBusy() && sentBytes < maxNumberOfBytesToSend) { // ZZ:UploadBandWithThrottler (UDP)
		UDPPack *cur_packet = controlpacket_queue.RemoveHead();
		if (curTick < cur_packet->dwTime + UDPMAXQUEUETIME) {
			int nLen = (int)cur_packet->packet->size + 2;
			int iLen = cur_packet->bEncrypt && !cur_packet->bIPv6
				&& (theApp.GetPublicIP() > 0 || cur_packet->bKad)
				? EncryptOverheadSize(cur_packet->bKad) : 0;
			uchar *sendbuffer = new uchar[nLen + iLen];
			memcpy(sendbuffer + iLen, cur_packet->packet->GetUDPHeader(), 2);
			memcpy(sendbuffer + iLen + 2, cur_packet->packet->pBuffer, cur_packet->packet->size);

			if (iLen) {
				nLen = EncryptSendClient(sendbuffer, nLen, cur_packet->pachTargetClientHashORKadID, cur_packet->bKad, cur_packet->nReceiverVerifyKey, (cur_packet->bKad ? Kademlia::CPrefs::GetUDPVerifyKey(cur_packet->dwIP) : 0u));
				//DEBUG_ONLY(  AddDebugLogLine(DLP_VERYLOW, false, _T("Sent obfuscated UDP packet to clientIP: %s, Kad: %s, ReceiverKey: %u"), (LPCTSTR)ipstr(cur_packet->dwIP), cur_packet->bKad ? _T("Yes") : _T("No"), cur_packet->nReceiverVerifyKey) );
			}
			iLen = cur_packet->bIPv6
				? SendToV6(sendbuffer, nLen, cur_packet->abyIPv6, cur_packet->nPort)
				: SendTo(sendbuffer, nLen, cur_packet->dwIP, cur_packet->nPort);
			if (iLen >= 0) {
				sentBytes += iLen; // ZZ:UploadBandWithThrottler (UDP)
				delete cur_packet->packet;
				delete cur_packet;
			} else {
				controlpacket_queue.AddHead(cur_packet); //try to resend on next throttler tick
				delete[] sendbuffer; //the buffer is rebuilt from cur_packet on the next attempt
				break; // BUG-013 FIX: yield to throttler instead of Sleep(20) blocking
			}
			delete[] sendbuffer;
		} else {
			delete cur_packet->packet;
			delete cur_packet;
		}
	}

// ZZ:UploadBandWithThrottler (UDP) -->
	if (!IsBusy() && !controlpacket_queue.IsEmpty())
		theApp.uploadBandwidthThrottler->QueueForSendingControlPacket(this);

	sendLocker.Unlock();

	return SocketSentBytes{ 0, sentBytes, true };
// <-- ZZ:UploadBandWithThrottler (UDP)
}

int CClientUDPSocket::SendTo(uchar *lpBuf, int nBufLen, uint32 dwIP, uint16 nPort)
{
	// NOTE: *** This function is invoked from a *different* thread!
	//Currently called only locally; sendLocker must be locked by the caller
	int result;
	if (m_bDualStack) {
		SOCKADDR_IN6 sa6 = {};
		sa6.sin6_family = AF_INET6;
		sa6.sin6_port = htons(nPort);
		sa6.sin6_addr.u.Byte[10] = 0xFF;
		sa6.sin6_addr.u.Byte[11] = 0xFF;
		memcpy(&sa6.sin6_addr.u.Byte[12], &dwIP, 4);
		result = CAsyncSocket::SendTo(lpBuf, nBufLen,
			(const SOCKADDR*)&sa6, sizeof sa6);
	} else {
		result = CAsyncSocket::SendTo(lpBuf, nBufLen, nPort, ipstr(dwIP));
	}
	if (result == SOCKET_ERROR) {
		DWORD dwError = (DWORD)CAsyncSocket::GetLastError();
		if (dwError == WSAEWOULDBLOCK) {
			m_bWouldBlock = true;
			return -1; //blocked
		}
		if (thePrefs.GetVerbose())
			DebugLogError(_T("Error: Client UDP socket, failed to send data to %s:%u: %s"), (LPCTSTR)ipstr(dwIP), nPort, (LPCTSTR)GetErrorMessage(dwError, 1));
		return 0; //error
	}
	return result; //success
}

// K6-2 native IPv6 send primitive. Builds a sockaddr_in6
// from the 16-byte NETWORK-order address (as stored in CContact::GetIPv6Address / the
// TAG_ESE_KADIP_V6 HELLO root-link) and transmits UNOBFUSCATED via the sockaddr form of SendTo
// (the obfuscation layer keys on the uint32 v4 IP, which a native-v6 peer lacks).
// SendPacketV6 is the active queueing call site. Receive dispatch is keyed by
// the payload KadID and remains outside the uint32-addressed Kad2 path.
int CClientUDPSocket::SendToV6(uchar *lpBuf, int nBufLen, const uint8 v6Addr[16], uint16 nPort)
{
	sockaddr_in6 sa6 = {};
	sa6.sin6_family = AF_INET6;
	sa6.sin6_port = htons(nPort);
	memcpy(&sa6.sin6_addr, v6Addr, 16);   // network order, opaque end-to-end (no byte swap)
	int result = CAsyncSocket::SendTo(lpBuf, nBufLen, (const SOCKADDR*)&sa6, sizeof sa6);
	if (result == SOCKET_ERROR) {
		DWORD dwError = (DWORD)CAsyncSocket::GetLastError();
		if (dwError == WSAEWOULDBLOCK) {
			m_bWouldBlock = true;
			return -1; //blocked
		}
		if (thePrefs.GetVerbose())
			DebugLogError(_T("Error: Client UDP socket, failed to send v6 data on port %u: %s"), nPort, (LPCTSTR)GetErrorMessage(dwError, 1));
		return 0; //error
	}
	return result; //success
}

bool CClientUDPSocket::SendPacket(Packet *packet, uint32 dwIP, uint16 nPort, bool bEncrypt, const uchar *pachTargetClientHashORKadID, bool bKad, uint32 nReceiverVerifyKey)
{
	UDPPack *newpending = new UDPPack;
	newpending->dwIP = dwIP;
	memset(newpending->abyIPv6, 0, sizeof newpending->abyIPv6);
	newpending->nPort = nPort;
	newpending->packet = packet;
	newpending->dwTime = ::GetTickCount();
	newpending->bIPv6 = false;
	newpending->bEncrypt = bEncrypt && (pachTargetClientHashORKadID != NULL || (bKad && nReceiverVerifyKey != 0));
	newpending->bKad = bKad;
	newpending->nReceiverVerifyKey = nReceiverVerifyKey;

#ifdef _DEBUG
	if (newpending->packet->size > UDP_KAD_MAXFRAGMENT)
		DebugLogWarning(_T("Sending UDP packet > UDP_KAD_MAXFRAGMENT, opcode: %X, size: %u"), packet->opcode, packet->size);
#endif

	if (newpending->bEncrypt && pachTargetClientHashORKadID != NULL)
		md4cpy(newpending->pachTargetClientHashORKadID, pachTargetClientHashORKadID);
	else
		md4clr(newpending->pachTargetClientHashORKadID);
// ZZ:UploadBandWithThrottler (UDP) -->
	sendLocker.Lock();
	controlpacket_queue.AddTail(newpending);
	sendLocker.Unlock();

	theApp.uploadBandwidthThrottler->QueueForSendingControlPacket(this);
	return true;
// <-- ZZ:UploadBandWithThrottler (UDP)
}

bool CClientUDPSocket::SendPacketV6(Packet *packet, const uint8 v6Addr[16], uint16 nPort)
{
	if (packet == NULL || v6Addr == NULL || nPort == 0 || !m_bDualStack) {
		delete packet;
		return false;
	}

	UDPPack *newpending = new UDPPack;
	newpending->packet = packet;
	newpending->dwIP = 0;
	memcpy(newpending->abyIPv6, v6Addr, sizeof newpending->abyIPv6);
	newpending->nPort = nPort;
	newpending->dwTime = ::GetTickCount();
	newpending->bIPv6 = true;
	newpending->bEncrypt = false;
	newpending->bKad = true;
	newpending->nReceiverVerifyKey = 0;
	md4clr(newpending->pachTargetClientHashORKadID);

#ifdef _DEBUG
	if (newpending->packet->size > UDP_KAD_MAXFRAGMENT)
		DebugLogWarning(_T("Sending native-v6 UDP packet > UDP_KAD_MAXFRAGMENT, opcode: %X, size: %u"),
			packet->opcode, packet->size);
#endif

	sendLocker.Lock();
	controlpacket_queue.AddTail(newpending);
	sendLocker.Unlock();
	theApp.uploadBandwidthThrottler->QueueForSendingControlPacket(this);
	return true;
}

bool CClientUDPSocket::Create()
{
	m_bIPv6BindRequested = thePrefs.IsIPv6Enabled();
	if (thePrefs.GetUDPPort()) {
		m_bDualStack = false;
		if (thePrefs.IsIPv6Enabled()
			&& CAsyncSocket::Socket(SOCK_DGRAM, FD_READ | FD_WRITE,
				IPPROTO_UDP, AF_INET6)) {
			DWORD v6Only = 0;
			if (SetSockOpt(IPV6_V6ONLY, &v6Only, sizeof v6Only, IPPROTO_IPV6)) {
				SOCKADDR_IN6 bindAddress = {};
				bindAddress.sin6_family = AF_INET6;
				bindAddress.sin6_port = htons(thePrefs.GetUDPPort());
				LPCTSTR configured = thePrefs.GetIPv6BindAddr();
				bool validBind = configured == NULL || configured[0] == 0
					|| _tcscmp(configured, _T("::")) == 0;
				if (!validBind) {
					CAddress configuredAddress(configured, false);
					if (configuredAddress.GetType() == CAddress::IPv6) {
						memcpy(&bindAddress.sin6_addr, configuredAddress.Data(), 16);
						validBind = true;
					}
				}
				if (validBind) {
					m_bDualStack = CAsyncSocket::Bind(
						(const SOCKADDR*)&bindAddress, sizeof bindAddress) != FALSE;
				}
			}
			if (!m_bDualStack)
				Close();
		}
		if (!m_bDualStack
			&& !CAsyncSocket::Create(thePrefs.GetUDPPort(), SOCK_DGRAM,
				FD_READ | FD_WRITE, thePrefs.GetBindAddr())) {
			UpdateHolePunchRuntimeCaps(false);
			return false;
		}
		if (m_bDualStack && thePrefs.GetVerbose())
			AddDebugLogLine(DLP_LOW, false,
				_T("Client UDP socket: dual-stack IPv6 bound on port %u"),
				(UINT)thePrefs.GetUDPPort());
		m_port = thePrefs.GetUDPPort();
		// the default socket size seems to be insufficient for this UDP socket
		// because we tend to drop packets if several arrived at the same time
		int val = 64 * 1024;
		if (!SetSockOpt(SO_RCVBUF, &val, sizeof val))
			DebugLogError(_T("Failed to increase socket size on UDP socket"));

		// eSE: Create the shared libutp context for uTP NAT Traversal.
		// One context per UDP socket is the standard libutp architecture.
		// The context owns all uTP socket state machines and callback dispatch.
		if (!m_pUtpContext) {
			utp_context* ctx = utp_init(2); // libutp API version 2
			if (ctx) {
				// Bind this CClientUDPSocket as context userdata so the
				// UTP_SENDTO callback can route outbound frames through us.
				utp_context_set_userdata(ctx, this);
				CUtpSocket::EnsureCallbacks(ctx);
				// eSE: Override LEDBAT target delay for streaming workloads.
				// Default is 100ms (CCONTROL_TARGET) which causes scavenger-class
				// behavior — too aggressive backoff under any concurrent traffic.
				// 300ms allows uTP to hold a stable streaming bitrate alongside
				// normal TCP traffic without starving the media pipeline.
				utp_context_set_option(ctx, UTP_TARGET_DELAY, 300000); // 300ms in µs
				m_pUtpContext = ctx;
				if (thePrefs.GetVerbose())
					AddDebugLogLine(DLP_LOW, false, _T("[NAT-T][uTP] Context created on UDP port %u"), (UINT)m_port);
			} else {
				DebugLogError(_T("[NAT-T][uTP] utp_init(2) FAILED - uTP disabled"));
			}
		}
	} else {
		m_port = 0;
		m_bDualStack = false;
	}
	UpdateHolePunchRuntimeCaps(IsUtpReady());
	return true;
}

bool CClientUDPSocket::Rebind()
{
	if (thePrefs.GetUDPPort() == m_port
		&& thePrefs.IsIPv6Enabled() == m_bIPv6BindRequested)
		return false;
	// Destroy old uTP context before recreating the socket on a new port
	if (m_pUtpContext) {
		CUtpSocket::OnContextDestroyed((utp_context*)m_pUtpContext);
		utp_destroy((utp_context*)m_pUtpContext);
		m_pUtpContext = NULL;
	}
	Close();
	m_bDualStack = false;
	return Create();
}

// eSE: uTP NAT Traversal bridge functions
// These connect the Kademlia hole-punch signaling to the libutp transport layer.

void CClientUDPSocket::SendUtpPacket(const byte* pData, size_t nDataLen, const sockaddr* to, int tolen)
{
	// Called by libutp's UTP_SENDTO callback to transmit uTP protocol frames
	// over the existing eMule UDP socket (port sharing).
	if (!pData || nDataLen == 0 || !to || tolen <= 0)
		return;

	if (to->sa_family == AF_INET && tolen >= (int)sizeof(SOCKADDR_IN)) {
		const SOCKADDR_IN* pAddr = reinterpret_cast<const SOCKADDR_IN*>(to);
		// SendTo expects network-order IP as uint32 and host-order port
		sendLocker.Lock();
		SendTo(const_cast<uchar*>(pData), (int)nDataLen,
			pAddr->sin_addr.s_addr, ntohs(pAddr->sin_port));
		sendLocker.Unlock();
	}
	else if (to->sa_family == AF_INET6 && tolen >= (int)sizeof(SOCKADDR_IN6)) {
		const SOCKADDR_IN6* pAddr = reinterpret_cast<const SOCKADDR_IN6*>(to);
		sendLocker.Lock();
		SendToV6(const_cast<uchar*>(pData), (int)nDataLen,
			reinterpret_cast<const uint8*>(&pAddr->sin6_addr),
			ntohs(pAddr->sin6_port));
		sendLocker.Unlock();
	}
}

void CClientUDPSocket::SeedNatTraversalExpectation(CUpDownClient* /*pClient*/, uint32 dwIP, uint16 nPort)
{
	// Called from Process_ESE_HOLEPUNCH_ACK after a successful hole-punch handshake.
	// Registers the peer's endpoint (IP:port) in the global expected-peers table
	// so that when libutp receives a SYN from this endpoint, on_utp_accept() can
	// match it and adopt it onto a CClientReqSocket.
	//
	// dwIP = host byte order (as used by Kad), nPort = host byte order
	if (dwIP == 0 || nPort == 0)
		return;

	SOCKADDR_IN sa = {};
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(dwIP); // Kad uses host-order, sockaddr needs network-order
	sa.sin_port = htons(nPort);

	// Register the peer endpoint in g_expectedPeers via the static bridge.
	// on_utp_accept consumes one incoming SYN from this exact endpoint, or from
	// the uniquely-nearest endpoint inside its small NAT-remap port window.
	CUtpSocket::RegisterExpectedPeer(reinterpret_cast<const sockaddr*>(&sa), sizeof(sa));

	DebugLog(_T("eSE: SeedNatTraversalExpectation — registered peer %s:%u for uTP accept matching"),
		(LPCTSTR)ipstr(htonl(dwIP)), nPort);
}

bool CClientUDPSocket::InitiateUtpConnect(uint32 dwIP, uint16 nUDPPort, CUpDownClient* pExpectedClient)
{
	// Called from Process_ESE_HOLEPUNCH_ACK on the INITIATOR side.
	// After the REQ→ACK handshake punched NAT pinholes on both sides,
	// this function actively sends a uTP SYN through the pinhole.
	// dwIP = host byte order (Kad convention), nUDPPort = host byte order.
	if (dwIP == 0 || nUDPPort == 0 || !IsUtpReady() || theApp.clientlist == NULL)
		return false;

	// 1. Resolve the eD2K client independently from the Kad identity carried
	// by HOLEPUNCH_ACK.  Prefer the pointer captured with the nonce (validated
	// again against the live list and endpoint), then use exact endpoint
	// lookups for manual/rendezvous requests.  Never interpret a Kad node ID
	// as an eD2K user hash.
	const uint32 uIPNetwork = htonl(dwIP);
	CUpDownClient* pClient = NULL;
	if (pExpectedClient != NULL && theApp.clientlist->IsValidClient(pExpectedClient)) {
		const uint32 uExpectedIP = pExpectedClient->GetConnectIP() != 0
			? pExpectedClient->GetConnectIP() : pExpectedClient->GetIP();
		if (uExpectedIP == uIPNetwork)
			pClient = pExpectedClient;
	}
	if (pClient == NULL)
		pClient = theApp.clientlist->FindClientByIP_KadPort(uIPNetwork, nUDPPort);
	if (pClient == NULL)
		pClient = theApp.clientlist->FindClientByIP_UDP(uIPNetwork, nUDPPort);
	if (pClient == NULL) {
		if (thePrefs.GetVerbose())
			DebugLog(_T("eSE: InitiateUtpConnect — no client found for endpoint %s:%u"),
				(LPCTSTR)ipstr(uIPNetwork), nUDPPort);
		return false;
	}

	// 2. If already connected, skip
	if (pClient->socket != NULL && pClient->socket->IsConnected()) {
		if (thePrefs.GetVerbose())
			DebugLog(_T("eSE: InitiateUtpConnect — client already connected, skipping: %s"), (LPCTSTR)pClient->DbgGetClientInfo());
		return true; // already connected — success
	}

	// 3. Clean up any existing non-connected socket.
	// IMPORTANT: Detach the client from the old socket BEFORE Safe_Delete.
	// Safe_Delete is deferred — when the destructor runs later, it does
	// `if (client) client->socket = 0;` which would NULL out the NEW socket.
	if (pClient->socket != NULL) {
		pClient->socket->client = NULL;  // Prevent destructor from clearing new socket
		pClient->socket->Safe_Delete();
		pClient->socket = NULL;
	}

	// 4. Create new CClientReqSocket with uTP layer
	CClientReqSocket* pNewSocket = new CClientReqSocket(pClient);
	if (!pNewSocket->Create()) {
		pNewSocket->Safe_Delete();
		if (thePrefs.GetVerbose())
			DebugLogError(_T("eSE: InitiateUtpConnect — failed to create socket for %s"), (LPCTSTR)pClient->DbgGetClientInfo());
		return false;
	}
	pClient->socket = pNewSocket;

	// 5. Add uTP transport layer
	CUtpSocket* utpLayer = pNewSocket->InitUtpSupport();
	if (utpLayer == NULL) {
		if (thePrefs.GetVerbose())
			DebugLogError(_T("eSE: InitiateUtpConnect — failed to init uTP layer for %s"), (LPCTSTR)pClient->DbgGetClientInfo());
		pNewSocket->Safe_Delete();
		pClient->socket = NULL;
		return false;
	}

	// 6. Override the peer's connect port to use the UDP port (for uTP)
	// The Kad port is what we hole-punched, not the TCP port.
	// We build the sockaddr directly for the uTP layer and let Connect() use it.
	// CUpDownClient::Connect() uses GetUserPort() (TCP), but for uTP we need
	// the Kad UDP port. We call the layer's Connect directly.
	pNewSocket->SetConnectionEncryption(false, NULL, false); // Disable TCP crypto for uTP

	SOCKADDR_IN sa = {};
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(dwIP); // Kad→network order
	sa.sin_port = htons(nUDPPort);

	pNewSocket->WaitForOnConnect();
	BOOL bRes = pNewSocket->Connect((LPSOCKADDR)&sa, sizeof(sa)); // Goes through uTP layer
	if (!bRes && ::WSAGetLastError() != WSAEWOULDBLOCK) {
		if (thePrefs.GetVerbose())
			DebugLogError(_T("eSE: InitiateUtpConnect — Connect() failed for %s"), (LPCTSTR)pClient->DbgGetClientInfo());
		pNewSocket->Safe_Delete();
		pClient->socket = NULL;
		return false;
	}

	// 7. Enqueue the Hello packet — will be flushed when uTP connect completes
	pClient->SendHelloPacket();

	theApp.listensocket->AddConnection();

	if (thePrefs.GetVerbose())
		DebugLog(_T("eSE: InitiateUtpConnect — uTP SYN sent to %s:%u, Hello enqueued for %s"),
			(LPCTSTR)ipstr(htonl(dwIP)), nUDPPort, (LPCTSTR)pClient->DbgGetClientInfo());

	return true;
}
