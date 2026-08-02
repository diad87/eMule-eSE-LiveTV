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
#include "StdAfx.h"
#include "UPnPImpl.h"

#include <chrono>
#include <limits>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

namespace {
uint64 MonotonicMilliseconds()
{
	return static_cast<uint64>(std::chrono::duration_cast<
		std::chrono::milliseconds>(std::chrono::steady_clock::now()
			.time_since_epoch()).count());
}

natmap::EndpointSource EndpointSourceForMapper(
	natmap::MapperKind mapper)
{
	switch (mapper) {
	case natmap::MapperKind::Pcp:
		return natmap::EndpointSource::PcpMap;
	case natmap::MapperKind::NatPmp:
		return natmap::EndpointSource::NatPmpPublicAddress;
	case natmap::MapperKind::UpnpIgd:
		return natmap::EndpointSource::UpnpExternalAddress;
	default:
		return natmap::EndpointSource::None;
	}
}

natmap::IpAddress IPv4FromNetworkOrder(uint32 address)
{
	const uint8* bytes = reinterpret_cast<const uint8*>(&address);
	return natmap::IpAddress::V4(
		bytes[0], bytes[1], bytes[2], bytes[3]);
}

uint64 EffectiveExpiry(uint32 lifetimeSeconds)
{
	if (lifetimeSeconds == 0)
		return 0;
	const uint64 now = MonotonicMilliseconds();
	const uint64 duration = static_cast<uint64>(lifetimeSeconds) * 1000u;
	const uint64 maximum = (std::numeric_limits<uint64>::max)();
	return duration > maximum - now
		? maximum
		: now + duration;
}
}

CUPnPImpl::CUPnPImpl()
	: m_hResultWindow()
	, m_nResultMessageID()
	, m_bUPnPPortsForwarded(TRIS_FALSE)
	, m_nOldTCPPort()
	, m_nOldTCPWebPort()
	, m_nOldUDPPort()
	, m_nTCPPort()
	, m_nTCPWebPort()
	, m_nUDPPort()
	, m_nExternalTCPPort()
	, m_nExternalTCPWebPort()
	, m_nExternalUDPPort()
	, m_dwMappingExternalIP()
	, m_dwMappingLeaseLifetime()
	, m_dwMapperEpoch()
	, m_bMapperEpochReset()
	, m_nDiagnosticStage(UPNP_DIAG_NOT_RUN)
	, m_bCheckAndRefresh()
	, m_requestInterfaceIndex()
{
}

void CUPnPImpl::SetMessageOnResult(CWnd *cwnd, UINT nMessageID,
	const std::shared_ptr<natmap::MappingResultMailbox>& mailbox)
{
	std::lock_guard<std::mutex> lock(m_resultMutex);
	m_hResultWindow = cwnd != NULL ? cwnd->GetSafeHwnd() : NULL;
	m_nResultMessageID = nMessageID;
	m_resultMailbox = mailbox;
}

void CUPnPImpl::BeginMappingRequest(
	const natmap::MappingRequestContext& context,
	std::uint32_t interfaceIndex,
	const natmap::IpAddress& localAddress,
	const natmap::IpAddress& gatewayAddress)
{
	std::lock_guard<std::mutex> lock(m_resultMutex);
	m_requestContext = context;
	m_requestInterfaceIndex = interfaceIndex;
	m_requestLocalAddress = localAddress;
	m_requestGatewayAddress = gatewayAddress;
}

CUPnPImpl::MappingOperationContext
CUPnPImpl::CaptureMappingOperation() const
{
	std::lock_guard<std::mutex> lock(m_resultMutex);
	MappingOperationContext operation;
	operation.request = m_requestContext;
	operation.interface_index = m_requestInterfaceIndex;
	operation.local_address = m_requestLocalAddress;
	operation.gateway_address = m_requestGatewayAddress;
	return operation;
}

bool CUPnPImpl::IsCurrentMappingOperation(
	const MappingOperationContext& operation) const
{
	std::lock_guard<std::mutex> lock(m_resultMutex);
	return operation.request.request_id != 0
		&& operation.request.request_id == m_requestContext.request_id
		&& operation.request.topology_generation
			== m_requestContext.topology_generation
		&& operation.request.operation == m_requestContext.operation;
}

natmap::MapperResultData CUPnPImpl::BuildMapperResultData(
	const MappingOperationContext& operation) const
{
	natmap::MapperResultData data;
	data.mapper = GetMapperKind();
	data.source = GetMapperSource();
	data.gateway.address = operation.gateway_address;
	data.gateway.source = natmap::EndpointSource::LocalInterface;
	data.request_interface_index = operation.interface_index;
	data.request_local_address = operation.local_address;
	data.mapper_epoch = m_dwMapperEpoch;
	data.mapper_epoch_reset = m_bMapperEpochReset;
	data.request_id = operation.request.request_id;
	data.topology_generation =
		operation.request.topology_generation;
	data.operation = operation.request.operation;

	const bool success = m_bUPnPPortsForwarded == TRIS_TRUE;
	if (!success) {
		data.status = natmap::MappingStatus::Failed;
		data.protocol_result_code = UPNP_FAILED;
		data.reason = natmap::ReasonCode::MappingDenied;
		data.verification = natmap::VerificationState::Failed;
		return data;
	}

	data.status = data.operation == natmap::MappingOperation::Refresh
		? natmap::MappingStatus::Renewed
		: data.operation == natmap::MappingOperation::Delete
			? natmap::MappingStatus::Deleted
			: natmap::MappingStatus::Created;
	data.ownership = natmap::OwnershipState::Unverifiable;
	data.verification = natmap::VerificationState::Pending;
	if (data.operation == natmap::MappingOperation::Delete)
		return data;

	const natmap::EndpointSource externalSource =
		EndpointSourceForMapper(data.mapper);
	const natmap::IpAddress externalAddress =
		IPv4FromNetworkOrder(m_dwMappingExternalIP);
	const uint64 effectiveExpiry =
		EffectiveExpiry(m_dwMappingLeaseLifetime);
	if (m_nTCPPort != 0) {
		natmap::TransportMappingResult& tcp =
			data.mappings[data.mapping_count++];
		tcp.transport = natmap::Transport::Tcp;
		tcp.local_endpoint = natmap::Endpoint{
			operation.local_address, m_nTCPPort,
			natmap::EndpointSource::LocalInterface};
		tcp.requested_external_port = RequestedExternalPort(
			natmap::Transport::Tcp, m_nTCPPort);
		tcp.granted_external_endpoint = natmap::Endpoint{
			externalAddress, m_nExternalTCPPort, externalSource};
		tcp.lifetime_seconds = m_dwMappingLeaseLifetime;
		tcp.effective_expiry_monotonic_ms =
			effectiveExpiry;
	}
	if (m_nUDPPort != 0 &&
		data.mapping_count < data.mappings.size()) {
		natmap::TransportMappingResult& udp =
			data.mappings[data.mapping_count++];
		udp.transport = natmap::Transport::Udp;
		udp.local_endpoint = natmap::Endpoint{
			operation.local_address, m_nUDPPort,
			natmap::EndpointSource::LocalInterface};
		udp.requested_external_port = RequestedExternalPort(
			natmap::Transport::Udp, m_nUDPPort);
		udp.granted_external_endpoint = natmap::Endpoint{
			externalAddress, m_nExternalUDPPort, externalSource};
		udp.lifetime_seconds = m_dwMappingLeaseLifetime;
		udp.effective_expiry_monotonic_ms =
			effectiveExpiry;
	}
	return data;
}

void CUPnPImpl::SendResultMessage()
{
	// An unbound callback cannot prove which request produced its fields.
	// Keep legacy subclasses source-compatible, but never publish it.
}

bool CUPnPImpl::SendResultMessage(
	const MappingOperationContext& operation)
{
	std::lock_guard<std::mutex> lock(m_resultMutex);
	if (operation.request.request_id == 0
		|| operation.request.request_id != m_requestContext.request_id
		|| operation.request.topology_generation
			!= m_requestContext.topology_generation
		|| operation.request.operation != m_requestContext.operation)
		return false;

	const HWND resultWindow = m_hResultWindow;
	const UINT resultMessage = m_nResultMessageID;
	const std::shared_ptr<natmap::MappingResultMailbox> mailbox =
		m_resultMailbox;
	m_nResultMessageID = 0;
	m_hResultWindow = NULL;
	m_resultMailbox.reset();
	if (resultWindow == NULL || resultMessage == 0 || !mailbox)
		return false;

	const natmap::MapperResultData resultData =
		BuildMapperResultData(operation);
	const natmap::MailboxPublish published =
		mailbox->Publish(resultData);
	if (!published.IsPublished())
		return false;
	const WPARAM messageToken = static_cast<WPARAM>(
		0x80000000u | published.delivery_id);
	if (!::PostMessage(resultWindow, resultMessage, messageToken, 0)) {
		mailbox->Discard(published.delivery_id);
		return false;
	}
	return true;
}

bool CUPnPImpl::SendMapperResultMessage(
	const MappingOperationContext& operation,
	const natmap::MapperResultData& resultData)
{
	natmap::MapperResultData boundResult = resultData;
	boundResult.request_interface_index = operation.interface_index;
	boundResult.request_local_address = operation.local_address;
	const natmap::MappingRouteIdentity operationRoute{
		operation.interface_index,
		operation.local_address,
		operation.gateway_address};
	if (boundResult.request_id != operation.request.request_id
		|| boundResult.topology_generation
			!= operation.request.topology_generation
		|| boundResult.operation != operation.request.operation
		|| boundResult.mapper != GetMapperKind()
		|| boundResult.source != GetMapperSource()
		|| !natmap::IsMapperResultRouteCurrent(
			boundResult, operationRoute)
		|| !natmap::MapperResult(boundResult).IsStructurallyValid())
		return false;

	std::lock_guard<std::mutex> lock(m_resultMutex);
	if (operation.request.request_id == 0
		|| operation.request.request_id != m_requestContext.request_id
		|| operation.request.topology_generation
			!= m_requestContext.topology_generation
		|| operation.request.operation != m_requestContext.operation)
		return false;
	const HWND resultWindow = m_hResultWindow;
	const UINT resultMessage = m_nResultMessageID;
	const std::shared_ptr<natmap::MappingResultMailbox> mailbox =
		m_resultMailbox;
	m_nResultMessageID = 0;
	m_hResultWindow = NULL;
	m_resultMailbox.reset();
	if (resultWindow == NULL || resultMessage == 0 || !mailbox)
		return false;

	const natmap::MailboxPublish published =
		mailbox->Publish(boundResult);
	if (!published.IsPublished())
		return false;
	const WPARAM messageToken = static_cast<WPARAM>(
		0x80000000u | published.delivery_id);
	if (!::PostMessage(resultWindow, resultMessage, messageToken, 0)) {
		mailbox->Discard(published.delivery_id);
		return false;
	}
	return true;
}

bool CUPnPImpl::SendPcpUpstreamBundleMessage(
	const MappingOperationContext& operation,
	const natmap::PcpUpstreamResultBundle& bundle)
{
	const natmap::MappingRouteIdentity operationRoute{
		operation.interface_index,
		operation.local_address,
		operation.gateway_address};
	if (!bundle.IsValid()
		|| bundle.cpe.request_id != operation.request.request_id
		|| bundle.cpe.topology_generation
			!= operation.request.topology_generation
		|| bundle.cpe.operation != operation.request.operation
		|| !natmap::IsMapperResultRouteCurrent(
			bundle.cpe, operationRoute))
		return false;

	std::lock_guard<std::mutex> lock(m_resultMutex);
	if (operation.request.request_id == 0
		|| operation.request.request_id != m_requestContext.request_id
		|| operation.request.topology_generation
			!= m_requestContext.topology_generation
		|| operation.request.operation != m_requestContext.operation)
		return false;
	const HWND resultWindow = m_hResultWindow;
	const UINT resultMessage = m_nResultMessageID;
	const std::shared_ptr<natmap::MappingResultMailbox> mailbox =
		m_resultMailbox;
	m_nResultMessageID = 0;
	m_hResultWindow = NULL;
	m_resultMailbox.reset();
	if (resultWindow == NULL || resultMessage == 0 || !mailbox)
		return false;

	const natmap::MailboxPublish published =
		mailbox->PublishPcpUpstreamBundle(bundle);
	if (!published.IsPublished())
		return false;
	const WPARAM messageToken = static_cast<WPARAM>(
		0x80000000u | published.delivery_id);
	if (!::PostMessage(resultWindow, resultMessage, messageToken, 0)) {
		mailbox->Discard(published.delivery_id);
		return false;
	}
	return true;
}

void CUPnPImpl::LateEnableWebServerPort(uint16 nPort)
{
	UNREFERENCED_PARAMETER(nPort);
	// V9.2 invariant: automatic reachability never exposes the WebServer.
	m_nTCPWebPort = 0;
	m_nExternalTCPWebPort = 0;
}

void CUPnPImpl::RecordLeaseSuccess()
{
	const uint64 now = MonotonicMilliseconds();
	if (m_leaseRefreshSchedule.Activate(m_dwMappingLeaseLifetime, now))
		m_permanentProbeSchedule.Clear();
	else if (SupportsMappingHealthCheck())
		m_permanentProbeSchedule.Activate(now);
	else
		m_permanentProbeSchedule.Clear();
}

bool CUPnPImpl::IsLeaseRefreshDue() const
{
	const uint64 now = MonotonicMilliseconds();
	return m_leaseRefreshSchedule.ShouldAttempt(now)
		|| m_permanentProbeSchedule.ShouldAttempt(now);
}

bool CUPnPImpl::IsLeaseExpired() const
{
	return m_leaseRefreshSchedule.IsExpired(MonotonicMilliseconds());
}

void CUPnPImpl::BeginLeaseRefreshAttempt()
{
	const uint64 now = MonotonicMilliseconds();
	if (m_leaseRefreshSchedule.IsFinite())
		m_leaseRefreshSchedule.MarkAttempt(now);
	else
		m_permanentProbeSchedule.MarkAttempt(now);
}

uint64 CUPnPImpl::GetLeaseRefreshSecondsUntilDue() const
{
	const uint64 now = MonotonicMilliseconds();
	const uint64 due = m_leaseRefreshSchedule.IsFinite()
		? m_leaseRefreshSchedule.next_attempt_ms()
		: m_permanentProbeSchedule.next_attempt_ms();
	return due > now ? (due - now) / 1000 : 0;
}

uint32 CUPnPImpl::GetLeaseRefreshAttemptCount() const
{
	return m_leaseRefreshSchedule.IsFinite()
		? m_leaseRefreshSchedule.attempt_count()
		: m_permanentProbeSchedule.attempt_count();
}

LPCSTR CUPnPImpl::GetDiagnosticStageName() const
{
	switch (m_nDiagnosticStage) {
	case UPNP_DIAG_NOT_RUN: return "not_run";
	case UPNP_DIAG_DISCOVERING: return "discovering";
	case UPNP_DIAG_NO_GATEWAY: return "no_gateway";
	case UPNP_DIAG_PROTOCOL_UNAVAILABLE: return "protocol_unavailable";
	case UPNP_DIAG_EXTERNAL_ADDRESS: return "external_address";
	case UPNP_DIAG_TCP_MAPPING: return "tcp_mapping";
	case UPNP_DIAG_UDP_MAPPING: return "udp_mapping";
	case UPNP_DIAG_VERIFY_MAPPING: return "verify_mapping";
	case UPNP_DIAG_TABLE_FULL: return "table_full";
	case UPNP_DIAG_SUCCESS: return "success";
	case UPNP_DIAG_OWNERSHIP_PERSISTENCE: return "ownership_persistence";
	default: return "unknown";
	}
}
