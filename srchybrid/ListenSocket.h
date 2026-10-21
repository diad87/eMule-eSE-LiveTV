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
#include "EMSocket.h"
#include "eMuleAI/Address.h"
#include "kad6/kad6_frontdoor.h"

#include <array>
#include <vector>
#include "EseEd2kFramer.h"
#include "reach/part_contributions.h"
#include "reach/direct_coordinator.h"

class CUpDownClient;
class CPartFile;
class CPacket;
class CTimerWnd;
enum EDebugLogPriority : int;

enum SocketState
{
	SS_Other,	//These are sockets we created that may or may not be used. Or incoming connections.
	SS_Half,	//These are sockets that we called ->connect(...) and waiting for some kind of response.
	SS_Complete	//These are sockets that have responded with either a connection or error.
};

class CUtpSocket;
namespace ese { class QuicEd2kWriter; }
class CClientReqSocket : public CEMSocket
{
	friend class CListenSocket;
	friend class CDirectReachabilityManager;
	friend class CNativeDirectSelfTestAccess; // read-only explicit native lab diagnostics
	DECLARE_DYNCREATE(CClientReqSocket)

public:
	class CUtpSocket* GetUtpLayer() const { return m_pUtpLayer; }
	class CUtpSocket* InitUtpSupport();
	virtual void RemoveAllLayers();  // eSE: also delete the owned uTP layer (mirror of CEMSocket); fixes per-connection CUtpSocket leak + g_UtpSockets orphan

	explicit CClientReqSocket(CUpDownClient *in_client = NULL);

	void	SetClient(CUpDownClient *pClient);
	bool AttachDirectWriter(uint64 owner, reach::DirectHandle, uint32 route, uint64 epoch,
		const std::shared_ptr<ese::QuicEd2kWriter>&);
	CAddress GetPeerCAddress() override;
	uint32 GetPeerAddressV4() override;
	void RecordDirectUsefulBytes(uint32 bytes);
	void RecordDirectPartBytes(CPartFile*,uint64 start,uint64 end,uint32 bytes);
	void StopDirectOutput() { StopDirectWriter(); }
	bool HasAuthenticatedDirectConnection() const;
	std::optional<reach::DirectPartContributor> LegacyDirectPartContributor() const;
	std::optional<reach::DirectCandidate> ObservedLegacyTcpCandidate();
	void RememberClassicDirectChallenge(uint32 challenge);
	// Explicit LAB owner registration only. Connected is not authentication;
	// the mixed transport consumer must perform Hello/SecureIdent before adoption.
	bool RegisterLegacyDirectRoute(reach::DirectHandle,const reach::DirectSessionRoute&,uint64 epoch,uint64 transferLifetime=0);
	uint64 LegacyDirectTransferLifetime() const noexcept { return m_legacyTransferLifetime; }
	// Called only by ProcessSignaturePacket after the existing VerifyIdent.
	// No cookie/HELLO or cached identity state may substitute for that result.
	void NotifyLegacySecureIdentResult(bool verified);
	bool AdoptLegacyDirectRoute(reach::DirectHandle,uint32 route,uint64 epoch);
	bool OwnsLegacyDirectRoute(reach::DirectHandle handle,uint32 route,uint64 epoch) const {
		return !m_legacyDirectClosed && handle.slot==m_legacyDirectHandle.slot &&
			handle.generation==m_legacyDirectHandle.generation && route && route==m_legacyDirectRoute && epoch==m_legacyDirectEpoch;
	}
	bool ProcessDirectFrame(uint64 owner, reach::DirectHandle, uint32 route, uint64 epoch,
		const ese::Ed2kFramer&);
	bool PumpDirectStream(uint64 owner, reach::DirectHandle, uint32 route, uint64 epoch,
		ese::Ed2kFramer&, size_t byteBudget = 64 * 1024, size_t frameBudget = 64);
	reach::DirectSendResult QueueDirectBytes(uint64 owner, reach::DirectHandle,
		uint32 route, uint64 epoch, ese::QuicEd2kWriter&, reach::DirectByteView);
	reach::DirectSendResult FlushDirectStream(uint64 owner, reach::DirectHandle,
		uint32 route, uint64 epoch, ese::QuicEd2kWriter&, size_t budget = 64 * 1024);
	virtual void Disconnect(LPCTSTR pszReason);
	void	WaitForOnConnect();
	void	ResetTimeOutTimer();
	bool	CheckTimeOut();
	virtual void Safe_Delete();
	//virtual void Close()				{ CAsyncSocketEx::Close(); }

	bool	Create(ADDRESS_FAMILY nFamily = AF_INET);
	virtual void SendPacket(Packet *packet, bool controlpacket = true, uint32 actualPayloadSize = 0, bool bForceImmediateSend = false);
	virtual SocketSentBytes SendControlData(uint32 maxNumberOfBytesToSend, uint32 overchargeMaxBytesToSend);
	virtual SocketSentBytes SendFileAndControlData(uint32 maxNumberOfBytesToSend, uint32 overchargeMaxBytesToSend);

	void	 OnClose(int nErrorCode);
	virtual void OnConnect(int nErrorCode);
	void	 OnReceive(int nErrorCode);
	void	 OnSend(int nErrorCode);

	void	DbgAppendClientInfo(CString &str);
	CString DbgGetClientInfo();

	CUpDownClient *client;
protected:
	bool ReportLegacyVerifiedPart(); // manager only after accepted PartFile hash proof
	bool HasDirectTransferAuthority(reach::DirectHandle) const;
	bool ValidateDirectHelloIdentity(const BYTE*,uint32,bool hashLengthPrefix) const;
	bool ReportLegacyDirectRouteEvent(reach::DirectEventType,reach::DirectReason,uint64 usefulBytes=0);
	bool MatchesLegacyDirectEndpoint();
	bool MatchesTcpEndpoint(const reach::DirectCandidate&);
	void CaptureClassicDirectTcpEndpoint();
	std::optional<reach::DirectCandidate> m_classicDirectTcpCandidate;
	std::array<uint8,16> m_classicDirectTcpHash{};
	uint64 m_classicDirectTcpLifetime=0;
	uint32 m_classicDirectChallenge=0;
	bool m_classicDirectVerified=false;
	uint64 m_classicLabParsedSignatures=0; // explicit selftest wire-consumption evidence only
	reach::DirectCandidate m_legacyDirectCandidate;
	std::optional<std::array<std::uint8_t,16>> m_legacyExpectedHash;
	reach::DirectHandle m_legacyDirectHandle;
	uint32 m_legacyDirectRoute=0;
	uint64 m_legacyDirectEpoch=0,m_legacyDirectGeneration=0,m_legacyDirectLifetime=0,m_legacyDirectSequence=0;
	uint64 m_legacyTransferLifetime=0;
	std::vector<BYTE> m_legacyHelloPacket;
	bool m_legacyHelloPrefix=false;
	bool m_legacyDirectConnected=false,m_legacyDirectClosed=false;
	bool m_legacyHelloAccepted=false,m_legacySecureIdentReported=false;
	bool m_legacySecureIdentVerified=false,m_legacyDirectAdopted=false;
	bool m_legacyVerifiedPartReported=false;
	uint64 m_legacyLabParsedBlocks=0; // explicit self-test diagnostic, not useful-byte accounting
	uint64 m_directPeerOwner=0,m_directPeerEpoch=0;
	reach::DirectHandle m_directPeerHandle;
	uint32 m_directPeerRoute=0;
	CAddress m_directPeerAddress;
	bool m_directFrameTracking=false;
	uint64 m_directFrameUsefulBytes=0;
	reach::DirectPartContributor m_directFrameContributor;
	virtual	~CClientReqSocket();
	void	Delete_Timed();

	void	 OnError(int nErrorCode);

	virtual bool PacketReceived(Packet *packet);

	bool	ProcessPacket(const BYTE *packet, uint32 size, UINT opcode);
	bool	ProcessExtPacket(const BYTE *packet, uint32 size, UINT opcode, UINT uRawSize);
	void	PacketToDebugLogLine(LPCTSTR protocol, const uchar *packet, uint32 size, UINT opcode);
	void	SetConState(SocketState val);

	DWORD	timeout_timer;
	DWORD	deltimer;
	uint32	m_nOnConnect;
	bool	deletethis;
	bool	m_bPortTestCon;
	CUtpSocket* m_pUtpLayer;  // eSE: uTP transport layer (owned by CAsyncSocketEx layer chain)
};


class CListenSocket : public CAsyncSocketEx
{
	friend class CClientReqSocket;

public:
	CListenSocket();
	virtual	~CListenSocket();

	bool	StartListening();
	void	StopListening();
	// v0.71 IPv6 Sprint 9 — true when AF_INET6 Create succeeded and the
	// listener is bound as dual-stack (IPV6_V6ONLY=0). False if v6 is
	// off in prefs or v6 Create failed (fallback to v4-only).
	bool	IsDualStack() const { return m_bDualStack; }
	virtual void OnAccept(int nErrorCode);
	void	Process();
	void	RemoveSocket(CClientReqSocket *todel);
	void	AddSocket(CClientReqSocket *toadd);
	UINT	GetOpenSockets()			{ return static_cast<UINT>(socket_list.GetCount() + m_k6PreAuthGate.Stats().active); }
	const kad6::K6PreAuthStats& GetK6PreAuthStats() const { return m_k6PreAuthGate.Stats(); }
	void	KillAllSockets();
	bool	TooManySockets(bool bIgnoreInterval = false);
	uint32	GetMaxConnectionReached()	{ return maxconnectionreached; }
	bool    IsValidSocket(CClientReqSocket *totest);
	void	AddConnection();
	void	RecalculateStats();
	void	ReStartListening();
	void	Debug_ClientDeleted(CUpDownClient *deleted);
	bool	Rebind();
	bool	SendPortTestReply(char result, bool disconnect = false);

	void	UpdateConnectionsStatus();
	float	GetMaxConperFiveModifier();
	uint32	GetPeakConnections()		{ return peakconnections; }
	uint32	GetTotalConnectionChecks()	{ return totalconnectionchecks; }
	float	GetAverageConnections()		{ return averageconnections; }
	uint32	GetActiveConnections()		{ return activeconnections; }
	uint16	GetConnectedPort()			{ return GetSocketHandle() == INVALID_SOCKET ? 0 : m_port; }
	uint32	GetTotalHalfCon()			{ return m_nHalfOpen; }
	uint32	GetTotalComp()				{ return m_nComp; }

private:
	struct K6PreAuthNativeSlot {
		SOCKET socket = INVALID_SOCKET;
		ADDRESS_FAMILY family = AF_UNSPEC;
	};
	bool AcceptK6PreAuth();
	void ProcessK6PreAuth();
	void CloseK6PreAuth();
	kad6::K6PreAuthGate m_k6PreAuthGate;
	std::array<K6PreAuthNativeSlot, kad6::kK6PreAuthMaxSlots> m_k6PreAuthSockets{};
	bool bListening;
	bool m_bDualStack = false;   // v0.71 IPv6 Sprint 9
	CTypedPtrList<CPtrList, CClientReqSocket*> socket_list;
	uint16	m_OpenSocketsInterval;
	uint32	maxconnectionreached;
	uint16	m_ConnectionStates[3];
	int		m_nPendingConnections;
	uint32	peakconnections;
	uint32	totalconnectionchecks;
	float	averageconnections;
	uint32	activeconnections;
	uint16  m_port;
	uint32	m_nHalfOpen;
	uint32	m_nComp;
};
