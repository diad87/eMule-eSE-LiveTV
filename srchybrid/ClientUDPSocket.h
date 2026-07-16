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
#pragma once
#include "UploadBandwidthThrottler.h" // ZZ:UploadBandWithThrottler (UDP)
#include "EncryptedDatagramSocket.h"

class Packet;

#pragma pack(push, 1)
struct UDPPack
{
	Packet	*packet;
	uint32	dwIP;
	uint8	abyIPv6[16];
	uint16	nPort;
	DWORD	dwTime;
	bool	bIPv6;
	bool	bEncrypt;
	bool	bKad;
	uint32	nReceiverVerifyKey;
	uchar	pachTargetClientHashORKadID[16];
	//uint16 nPriority; We could add a priority system here to force some packets.
};
#pragma pack(pop)

class CAddress;
class CUpDownClient;
class CClientUDPSocket : public CAsyncSocket, public CEncryptedDatagramSocket, public ThrottledControlSocket // ZZ:UploadBandWithThrottler (UDP)
{
public:
	void* m_pUtpContext = NULL;
	void* GetUtpContext() const { return m_pUtpContext; }
	bool IsUtpReady() const { return m_port != 0 && m_pUtpContext != NULL; }
	void SendUtpPacket(const byte* pData, size_t nDataLen, const sockaddr* to, int tolen);
	void SeedNatTraversalExpectation(CUpDownClient* pClient, uint32 dwIP, uint16 nPort);
	bool InitiateUtpConnect(uint32 dwIP, uint16 nUDPPort, CUpDownClient* pExpectedClient);





	CClientUDPSocket();
	virtual	~CClientUDPSocket();

	bool	Create();
	bool	Rebind();
	uint16	GetConnectedPort()		{ return m_port; }
	bool	IsDualStack() const		{ return m_bDualStack; }
	bool	SendPacket(Packet *packet, uint32 dwIP, uint16 nPort, bool bEncrypt, const uchar *pachTargetClientHashORKadID, bool bKad, uint32 nReceiverVerifyKey);
	bool	SendPacketV6(Packet *packet, const uint8 v6Addr[16], uint16 nPort);
	SocketSentBytes  SendControlData(uint32 maxNumberOfBytesToSend, uint32 /*minFragSize*/); // ZZ:UploadBandWithThrottler (UDP)

protected:
	bool	ProcessPacket(const BYTE *packet, UINT size, uint8 opcode, uint32 ip, uint16 port);

	virtual void	OnSend(int nErrorCode);
	virtual void	OnReceive(int nErrorCode);

private:
	int		SendTo(uchar *lpBuf, int nBufLen, uint32 dwIP, uint16 nPort);
	int		SendToV6(uchar *lpBuf, int nBufLen, const uint8 v6Addr[16], uint16 nPort);
	bool	IsBusy() const			{ return m_bWouldBlock; }

	CTypedPtrList<CPtrList, UDPPack*> controlpacket_queue;

	CCriticalSection sendLocker; // ZZ:UploadBandWithThrottler (UDP)

	uint16	m_port;
	bool	m_bWouldBlock;
	bool	m_bDualStack;
	// Preference state used for this bind attempt. This is separate from
	// m_bDualStack because an IPv6 request may safely fall back to IPv4.
	bool	m_bIPv6BindRequested;
};
