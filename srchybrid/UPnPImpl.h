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
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License
//along with this program; if not, write to the Free Software
//Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#pragma once
#include <exception>
#include <memory>
#include <mutex>
#include "natmap/natmap_policy.h"
#include "natmap/mapping_request.h"
#include "natmap/mapping_result_mailbox.h"

enum TRISTATE
{
	TRIS_FALSE,
	TRIS_UNKNOWN,
	TRIS_TRUE
};

enum UPNP_IMPLEMENTATION
{
	UPNP_IMPL_WINDOWSERVICE = 0,
	UPNP_IMPL_MINIUPNPLIB,
	UPNP_IMPL_NATPMP,
	// Appended to preserve the persisted IDs of the three legacy mappers.
	UPNP_IMPL_PCP,
	UPNP_IMPL_NONE	/*last*/
};

enum UPNP_DIAGNOSTIC_STAGE
{
	UPNP_DIAG_NOT_RUN = 0,
	UPNP_DIAG_DISCOVERING,
	UPNP_DIAG_NO_GATEWAY,
	UPNP_DIAG_PROTOCOL_UNAVAILABLE,
	UPNP_DIAG_EXTERNAL_ADDRESS,
	UPNP_DIAG_TCP_MAPPING,
	UPNP_DIAG_UDP_MAPPING,
	UPNP_DIAG_VERIFY_MAPPING,
	UPNP_DIAG_TABLE_FULL,
	UPNP_DIAG_SUCCESS,
	// Append only: numeric stages are emitted in diagnostics.
	UPNP_DIAG_OWNERSHIP_PERSISTENCE
};


class CUPnPImpl
{
	HWND m_hResultWindow;
	UINT m_nResultMessageID;

public:
	CUPnPImpl();
	virtual	~CUPnPImpl() = default;
	struct MappingOperationContext
	{
		natmap::MappingRequestContext request;
		natmap::IpAddress local_address;
		natmap::IpAddress gateway_address;
	};
	struct UPnPError : public std::exception	{};
	enum
	{
		UPNP_OK,
		UPNP_FAILED,
		UPNP_TIMEOUT
	};

	virtual void StartDiscovery(uint16 nTCPPort, uint16 nUDPPort, uint16 nTCPWebPort) = 0;
	virtual bool CheckAndRefresh() = 0;
	virtual void StopAsyncFind() = 0;
	virtual void DeletePorts() = 0;
	virtual bool IsReady() = 0;
	virtual int GetImplementationID() = 0;
	virtual natmap::MapperKind GetMapperKind() const
		{ return natmap::MapperKind::None; }
	virtual natmap::MapperSource GetMapperSource() const
		{ return natmap::MapperSource::None; }
	virtual bool SupportsMappingHealthCheck() const { return true; }

	void LateEnableWebServerPort(uint16 nPort);	// Add Web Server port to already existing port mapping

	void SetMessageOnResult(CWnd *cwnd, UINT nMessageID,
		const std::shared_ptr<natmap::MappingResultMailbox>& mailbox =
			std::shared_ptr<natmap::MappingResultMailbox>());
	void BeginMappingRequest(const natmap::MappingRequestContext& context,
		const natmap::IpAddress& localAddress,
		const natmap::IpAddress& gatewayAddress);
	TRISTATE ArePortsForwarded() const					{ return m_bUPnPPortsForwarded; }
	uint16 GetUsedTCPPort() const						{ return m_nTCPPort; }
	uint16 GetUsedUDPPort() const						{ return m_nUDPPort; }
	uint16 GetUsedTCPWebPort() const					{ return m_nTCPWebPort; }
	uint16 GetExternalTCPPort() const					{ return m_nExternalTCPPort; }
	uint16 GetExternalUDPPort() const					{ return m_nExternalUDPPort; }
	uint16 GetExternalTCPWebPort() const				{ return m_nExternalTCPWebPort; }
	uint32 GetMappingExternalIP() const				{ return m_dwMappingExternalIP; }
	uint32 GetMappingLeaseLifetime() const			{ return m_dwMappingLeaseLifetime; }
	uint32 GetMapperEpoch() const						{ return m_dwMapperEpoch; }
	LONG GetDiagnosticStage() const						{ return m_nDiagnosticStage; }
	LPCSTR GetDiagnosticStageName() const;
	void RecordLeaseSuccess();
	bool IsLeaseRefreshDue() const;
	bool IsLeaseExpired() const;
	void BeginLeaseRefreshAttempt();
	uint64 GetLeaseRefreshSecondsUntilDue() const;
	uint32 GetLeaseRefreshAttemptCount() const;

// Implementation
protected:
	MappingOperationContext CaptureMappingOperation() const;
	bool IsCurrentMappingOperation(
		const MappingOperationContext& operation) const;
	// Source-compatible fail-closed seam for external legacy subclasses.
	// Native producers must use the operation-bound overload below.
	void SendResultMessage();
	void SendResultMessage(const MappingOperationContext& operation);
	natmap::MapperResultData BuildMapperResultData(
		const MappingOperationContext& operation) const;
	volatile TRISTATE m_bUPnPPortsForwarded;
	uint16 m_nOldTCPPort;
	uint16 m_nOldTCPWebPort;
	uint16 m_nOldUDPPort;
	uint16 m_nTCPPort;
	uint16 m_nTCPWebPort;
	uint16 m_nUDPPort;
	uint16 m_nExternalTCPPort;
	uint16 m_nExternalTCPWebPort;
	uint16 m_nExternalUDPPort;
	uint32 m_dwMappingExternalIP;
	uint32 m_dwMappingLeaseLifetime;
	uint32 m_dwMapperEpoch;
	volatile LONG m_nDiagnosticStage;
	bool m_bCheckAndRefresh;
	natmap::LeaseRefreshSchedule m_leaseRefreshSchedule;
	natmap::PermanentMappingProbeSchedule m_permanentProbeSchedule;

private:
	mutable std::mutex m_resultMutex;
	std::shared_ptr<natmap::MappingResultMailbox> m_resultMailbox;
	natmap::MappingRequestContext m_requestContext;
	natmap::IpAddress m_requestLocalAddress;
	natmap::IpAddress m_requestGatewayAddress;
};

// Dummy Implementation to be used when no other implementation is available
class CUPnPImplNone : public CUPnPImpl
{
public:
	virtual void StartDiscovery(uint16, uint16, uint16)	{ ASSERT(0); }
	virtual bool CheckAndRefresh()						{ return false; }
	virtual void StopAsyncFind()						{}
	virtual void DeletePorts()							{}
	virtual bool IsReady()								{ return false; }
	virtual int GetImplementationID()					{ return UPNP_IMPL_NONE; }
	virtual natmap::MapperKind GetMapperKind() const
		{ return natmap::MapperKind::None; }
	virtual natmap::MapperSource GetMapperSource() const
		{ return natmap::MapperSource::None; }
};
