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
#include "MapperWindowsNotification.h"
#include "Preferences.h"

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
	auto previous=std::atomic_exchange(&m_ownedNotification,std::shared_ptr<OwnedNotification>{});
	if(previous) previous->publisher.Cancel();
	m_wndResultMessage = cwnd;
	m_nResultMessageID = nMessageID;
}

bool CUPnPImpl::SetOwnedMessageOnResult(CWnd* window,UINT message,
	std::shared_ptr<natmap::MapperResultMailbox> queue,uint64 operation)
{
	if(!window || !window->GetSafeHwnd() || !message || !queue || !operation || !IsReady()) return false;
	auto notification=std::make_shared<OwnedNotification>(std::move(queue),operation,window->GetSafeHwnd(),message);
	auto previous=std::atomic_exchange(&m_ownedNotification,std::move(notification));
	if(previous) previous->publisher.Cancel();
	return true;
}

uint64 CUPnPImpl::GetOwnedResultOperation() const
{
	auto notification=std::atomic_load(&m_ownedNotification);
	return notification ? notification->operation : 0;
}

void CUPnPImpl::SendResultMessage()
{
	SendResultMessage(CaptureResultNotification());
}

std::shared_ptr<CUPnPImpl::OwnedNotification> CUPnPImpl::CaptureResultNotification() const
{
	return std::atomic_load(&m_ownedNotification);
}

void CUPnPImpl::SendResultMessage(const std::shared_ptr<OwnedNotification>& notification)
{
	if(notification) {
		natmap::MapperResult result;
		result.success=m_bUPnPPortsForwarded==TRIS_TRUE;
		result.external_ipv4=m_dwMappingExternalIP; result.lifetime=m_dwMappingLeaseLifetime;
		result.epoch=m_dwMapperEpoch; result.external_tcp=m_nExternalTCPPort; result.external_udp=m_nExternalUDPPort;
		notification->publisher.Publish(result,[&](uint64 id) {
			return natmap::PostMapperOperation(notification->window,notification->message,id);
		});
		return; // never downgrade failed owned publication to mutable legacy getters
	}
	if (CaptureResultNotification()) return; // legacy worker cannot publish into a later owned operation
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
	RecordLeaseSuccess(m_dwMappingLeaseLifetime);
}

void CUPnPImpl::RecordLeaseSuccess(uint32 lifetime)
{
	const uint64 now = MonotonicMilliseconds();
	if (m_leaseRefreshSchedule.Activate(lifetime, now))
		m_permanentProbeSchedule.Clear();
	else if (SupportsMappingHealthCheck())
		m_permanentProbeSchedule.Activate(now);
	else
		m_permanentProbeSchedule.Clear();
    if(thePrefs.IsEseNetLabActive() && SupportsMappingHealthCheck()) m_healthReadback.Activate(lifetime,now);
    else m_healthReadback.Clear();
}

bool CUPnPImpl::IsLeaseRefreshDue() const
{
	const uint64 now = MonotonicMilliseconds();
	return m_leaseRefreshSchedule.ShouldAttempt(now)
		|| m_permanentProbeSchedule.ShouldAttempt(now) || IsMappingHealthReadbackDue();
}
bool CUPnPImpl::IsMappingHealthReadbackDue() const
{
    return thePrefs.IsEseNetLabActive() && m_healthReadback.Due(MonotonicMilliseconds());
}
void CUPnPImpl::SynchronizeMappingHealthReadback()
{
    if(!thePrefs.IsEseNetLabActive() || !SupportsMappingHealthCheck() || ArePortsForwarded()!=TRIS_TRUE)
        m_healthReadback.Clear();
    else if(!m_healthReadback.Interval())
        m_healthReadback.Activate(m_dwMappingLeaseLifetime,MonotonicMilliseconds());
}

bool CUPnPImpl::IsLeaseExpired() const
{
	return m_leaseRefreshSchedule.IsExpired(MonotonicMilliseconds());
}

void CUPnPImpl::BeginLeaseRefreshAttempt()
{
	const uint64 now = MonotonicMilliseconds();
    if(IsMappingHealthReadbackDue()) m_healthReadback.Mark(now);
	if (m_leaseRefreshSchedule.ShouldAttempt(now))
		m_leaseRefreshSchedule.MarkAttempt(now);
	else if(m_permanentProbeSchedule.ShouldAttempt(now))
		m_permanentProbeSchedule.MarkAttempt(now);
}

uint64 CUPnPImpl::GetLeaseRefreshSecondsUntilDue() const
{
	const uint64 now = MonotonicMilliseconds();
	uint64 due = m_leaseRefreshSchedule.IsFinite()
		? m_leaseRefreshSchedule.next_attempt_ms()
		: m_permanentProbeSchedule.next_attempt_ms();
    if(thePrefs.IsEseNetLabActive() && m_healthReadback.Next() && (!due || m_healthReadback.Next()<due))
        due=m_healthReadback.Next();
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
