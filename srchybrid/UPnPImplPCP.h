// PCP (RFC 6887) IPv4 port-mapping implementation.
#pragma once

#include "UPnPImpl.h"
#include "natmap/pcp_codec.h"
#include "natmap/pcp_map_projection.h"
#include "natmap/pcp_mapping_identity.h"
#include "natmap/pcp_route_binding.h"

#include <array>
#include <atomic>

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
	virtual natmap::MapperKind GetMapperKind() const
		{ return natmap::MapperKind::Pcp; }
	virtual natmap::MapperSource GetMapperSource() const
		{ return natmap::MapperSource::PcpCpe; }
	virtual uint16 RequestedExternalPort(
		natmap::Transport transport, uint16 localPort) const;

	class CStartDiscoveryThread : public CWinThread
	{
		DECLARE_DYNCREATE(CStartDiscoveryThread)
	protected:
		CStartDiscoveryThread();

	public:
		virtual BOOL InitInstance();
		virtual int Run();
		void SetValues(CUPnPImplPCP* pOwner)
		{
			m_pOwner = pOwner;
			m_operation = pOwner->CaptureMappingOperation();
		}

	private:
		CUPnPImplPCP* m_pOwner;
		MappingOperationContext m_operation;
	};

protected:
	bool DeletePorts(bool bSkipLock);
	virtual natmap::MapperResultData BuildMapperResultData(
		const MappingOperationContext& operation) const;

private:
	static const uint16 PCP_PORT = 5351;
	static const uint8 PCP_PROTOCOL_TCP = 6;
	static const uint8 PCP_PROTOCOL_UDP = 17;

	static bool GenerateNonce(std::array<uint8, 12>& nonce);
	static bool ExtractIPv4(const std::array<std::uint8_t, 16>& address,
		uint32& ipv4);
	static bool ReadExplicitUpstreamGateway(
		uint32& gateway, bool& enabled);

	bool MapPort(uint32 nGatewayIP, uint32 nInterfaceIndex,
		const std::array<uint8, 16>& bindAddress,
		const std::array<uint8, 16>& clientAddress,
		natmap::Transport transport, uint16 nPrivatePort,
		uint16 nSuggestedExternalPort,
		const std::array<uint8, 16>& suggestedExternalAddress,
		uint32 nLifetime, natmap::PcpMappingIdentity& identity,
		natmap::PcpMapProjection& projection,
		natmap::PcpResultCode* resultCode = NULL);
	bool UnmapPort(uint32 nGatewayIP, uint32 nInterfaceIndex,
		const std::array<uint8, 16>& bindAddress,
		const std::array<uint8, 16>& clientAddress,
		const natmap::PcpMappingIdentity& identity);
	bool ExchangeMap(uint32 nGatewayIP, uint32 nInterfaceIndex,
		const std::array<uint8, 16>& bindAddress,
		const natmap::PcpMapRequest& request,
		natmap::PcpMapResponse& response, bool bDeletion);
	bool SendResultIfLifecycleLive(
		const MappingOperationContext& operation);
	void StartThread();

	static CMutex m_mutBusy;

	uint32 m_dwGatewayIP;
	uint32 m_dwOldGatewayIP;
	uint32 m_dwInterfaceIndex;
	uint32 m_dwOldInterfaceIndex;
	uint32 m_dwUpstreamGatewayIP;
	uint32 m_dwOldUpstreamGatewayIP;
	std::array<uint8, 16> m_clientAddress;
	std::array<uint8, 16> m_oldClientAddress;
	std::array<uint8, 16> m_upstreamClientAddress;
	std::array<uint8, 16> m_oldUpstreamClientAddress;
	std::array<uint8, 16> m_tcpExternalAddress;
	std::array<uint8, 16> m_udpExternalAddress;
	std::array<uint8, 16> m_webExternalAddress;
	uint16 m_nRequestedTCPExternalPort;
	uint16 m_nRequestedUDPExternalPort;
	uint16 m_nRequestedWebExternalPort;
	natmap::PcpMappingIdentity m_tcpIdentity;
	natmap::PcpMappingIdentity m_udpIdentity;
	natmap::PcpMappingIdentity m_webIdentity;
	// Layer-two identities are never shared with CPE identities: delete and
	// refresh must prove ownership at each PCP server independently.
	natmap::PcpMappingIdentity m_upstreamTcpIdentity;
	natmap::PcpMappingIdentity m_upstreamUdpIdentity;
	natmap::PcpMappingIdentity m_oldUpstreamTcpIdentity;
	natmap::PcpMappingIdentity m_oldUpstreamUdpIdentity;
	natmap::PcpMappingIdentity m_oldTCPIdentity;
	natmap::PcpMappingIdentity m_oldUDPIdentity;
	natmap::PcpMappingIdentity m_oldWebIdentity;
	HANDLE m_hThreadHandle;
	bool m_bSucceededOnce;
	std::atomic<std::uint64_t> m_nextExchangeId;
	std::atomic<std::uint64_t> m_activeExchangeId;
	std::mutex m_lifecycleMutex;
	std::atomic_bool m_initialMappingInFlight;
	std::atomic_bool m_bShuttingDown;
	std::atomic_bool m_bAbortDiscovery;
};
