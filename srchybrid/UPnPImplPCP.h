// PCP (RFC 6887) IPv4 port-mapping implementation.
#pragma once

#include "UPnPImpl.h"
#include "natmap/pcp_codec.h"

#include <array>

class CUPnPImplPCP : public CUPnPImpl
{
public:
	CUPnPImplPCP();
	virtual ~CUPnPImplPCP();

	virtual void StartDiscovery(uint16 nTCPPort, uint16 nUDPPort, uint16 nTCPWebPort);
	virtual bool CheckAndRefresh();
	virtual void StopAsyncFind();
	virtual void DeletePorts();
	virtual bool IsReady();
	virtual int GetImplementationID() { return UPNP_IMPL_PCP; }

	class CStartDiscoveryThread : public CWinThread
	{
		DECLARE_DYNCREATE(CStartDiscoveryThread)
	protected:
		CStartDiscoveryThread();

	public:
		virtual BOOL InitInstance();
		virtual int Run();
		void SetValues(CUPnPImplPCP* pOwner) { m_pOwner = pOwner; }

	private:
		CUPnPImplPCP* m_pOwner;
	};

protected:
	void DeletePorts(bool bSkipLock);

private:
	static const uint16 PCP_PORT = 5351;
	static const uint8 PCP_PROTOCOL_TCP = 6;
	static const uint8 PCP_PROTOCOL_UDP = 17;

	static uint32 GetDefaultGateway();
	static bool GetClientAddress(uint32 nGatewayIP,
		std::array<uint8, 16>& clientAddress);
	static bool GenerateNonce(std::array<uint8, 12>& nonce);
	static bool ExtractIPv4(const std::array<std::uint8_t, 16>& address,
		uint32& ipv4);

	bool MapPort(uint32 nGatewayIP,
		const std::array<uint8, 16>& clientAddress, uint16 nPrivatePort,
		uint16 nSuggestedExternalPort, bool bTCP, uint32 nLifetime,
		std::array<uint8, 12>& nonce, natmap::PcpMapResponse& response);
	bool UnmapPort(uint32 nGatewayIP,
		const std::array<uint8, 16>& clientAddress, uint16 nPrivatePort,
		bool bTCP, const std::array<uint8, 12>& nonce);
	bool ExchangeMap(uint32 nGatewayIP, const natmap::PcpMapRequest& request,
		natmap::PcpMapResponse& response, bool bDeletion);
	void StartThread();

	static CMutex m_mutBusy;

	uint32 m_dwGatewayIP;
	std::array<uint8, 16> m_clientAddress;
	std::array<uint8, 12> m_tcpNonce;
	std::array<uint8, 12> m_udpNonce;
	std::array<uint8, 12> m_webNonce;
	std::array<uint8, 12> m_oldTCPNonce;
	std::array<uint8, 12> m_oldUDPNonce;
	std::array<uint8, 12> m_oldWebNonce;
	HANDLE m_hThreadHandle;
	bool m_bSucceededOnce;
	volatile bool m_bAbortDiscovery;
};
