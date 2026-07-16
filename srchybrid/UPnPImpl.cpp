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
}

CUPnPImpl::CUPnPImpl()
	: m_wndResultMessage()
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
	, m_nDiagnosticStage(UPNP_DIAG_NOT_RUN)
	, m_bCheckAndRefresh()
{
}

void CUPnPImpl::SetMessageOnResult(CWnd *cwnd, UINT nMessageID)
{
	m_wndResultMessage = cwnd;
	m_nResultMessageID = nMessageID;
}

void CUPnPImpl::SendResultMessage()
{
	if (m_wndResultMessage != NULL && m_nResultMessageID != 0)
		m_wndResultMessage->PostMessage(m_nResultMessageID, (WPARAM)(m_bUPnPPortsForwarded == TRIS_TRUE ? UPNP_OK : UPNP_FAILED), (LPARAM)m_bCheckAndRefresh);
	m_nResultMessageID = 0;
	m_wndResultMessage = NULL;
}

void CUPnPImpl::LateEnableWebServerPort(uint16 nPort)
{
	if (ArePortsForwarded() == TRIS_TRUE && IsReady()) {
		m_nOldTCPWebPort = (m_nTCPWebPort == nPort ? 0 : m_nTCPWebPort);
		m_nTCPWebPort = nPort;
		m_nExternalTCPWebPort = nPort;
		CheckAndRefresh();
	}
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
