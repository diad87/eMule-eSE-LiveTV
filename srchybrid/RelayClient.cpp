// SPDX-License-Identifier: GPL-2.0-or-later
#include "stdafx.h"
#include "RelayClient.h"

#include "Emule.h"
#include "Preferences.h"
#include "UserMsgs.h"
#include "NodeIdentity.h"
#include "OtherFunctions.h"

#include "relayclient/relay_client.h"
#include "relayclient/relay_wss_transport.h"
#include "relay/krp_auth.h"

#include <algorithm>
#include <atomic>
#include <cstring>
#include <limits>

namespace {

constexpr UINT_PTR kKrpRetryTimerId = 0x4B52;

uint64 KrpMonotonicMilliseconds() noexcept
{
	// Main-thread extension for the SDK baseline which has no GetTickCount64.
	static DWORD previous = 0;
	static uint64 epoch = 0;
	const DWORD current = ::GetTickCount();
	if (current < previous)
		epoch += (1ull << 32);
	previous = current;
	return epoch + current;
}

const char* ShortStateName(const char* value) noexcept
{
	if (value == NULL)
		return "Unknown";
	const char* separator = strrchr(value, ':');
	return separator == NULL ? value : separator + 1;
}

void CALLBACK KrpRetryTimerProc(HWND hwnd, UINT, UINT_PTR timer, DWORD) noexcept
{
	::KillTimer(hwnd, timer);
	::PostMessage(hwnd, UM_KRP_CLIENT_EVENT, 0, 0);
}

relayclient::RelayClientConfig RelayConfigFromPreferences()
{
	relayclient::RelayClientConfig config;
	config.enabled = thePrefs.GetKrpRelayEnabled();
	config.kill_switch = thePrefs.GetKrpRelayKillSwitch();
	config.endpoint_host = CStringA(thePrefs.GetKrpRelayEndpointHost()).GetString();
	config.endpoint_port = thePrefs.GetKrpRelayEndpointPort();
	config.expected_server_name =
		CStringA(thePrefs.GetKrpRelayExpectedServerName()).GetString();
	config.ca_bundle_path =
		CStringA(thePrefs.GetKrpRelayCaBundlePath()).GetString();
	config.experimental_tcp_data_plane =
		thePrefs.GetKrpRelayExperimentalTcp();
	config.auth_token_path =
		CStringA(thePrefs.GetKrpRelayAuthTokenPath()).GetString();
	config.local_tcp_port = thePrefs.GetPort();
	config.server_policy = thePrefs.GetKrpRelayAllowAnyServer()
		? relayclient::RelayServerPolicy::AnyConnectedServer
		: relayclient::RelayServerPolicy::SelectedServerOnly;
	return config;
}

class CRelayNodeIdentitySigner final : public relay::INodeIdentitySigner
{
public:
	bool IsPersistent() const noexcept override
	{
		return eSELive::NodeIdentityIsPersistent() &&
			eSELive::NodeIdentityPub() != NULL;
	}

	const relay::NodeId& PublicNodeId() const noexcept override
	{
		const uint8* pub = eSELive::NodeIdentityPub();
		if (pub != NULL)
			std::copy(pub, pub + m_nodeId.size(), m_nodeId.begin());
		else
			m_nodeId.fill(0);
		return m_nodeId;
	}

	bool Sign(const relay::Byte* message, std::size_t messageSize,
		relay::KrpAuthSignature& signature) noexcept override
	{
		return IsPersistent() && eSELive::NodeIdentitySign(
			message, messageSize, signature.data());
	}

private:
	mutable relay::NodeId m_nodeId{};
};

} // namespace

class CRelayClient::CWindowNotifier final : public relayclient::IRelayEventNotifier
{
public:
	void Attach(HWND hwnd) noexcept { m_hwnd.store(hwnd, std::memory_order_release); }

	void Notify(std::uint64_t generation) noexcept override
	{
		const HWND hwnd = m_hwnd.load(std::memory_order_acquire);
		if (hwnd != NULL)
			::PostMessage(hwnd, UM_KRP_CLIENT_EVENT,
				static_cast<WPARAM>(generation & 0xFFFFFFFFu), 0);
	}

private:
	std::atomic<HWND> m_hwnd{NULL};
};

CRelayClient::CRelayClient()
	: m_notifier(new CWindowNotifier())
	, m_identitySigner(new CRelayNodeIdentitySigner())
	, m_transport(new relayclient::RelayWssTransport(m_notifier.get(), m_identitySigner.get()))
	, m_manager(new relayclient::RelayClientManager(*m_transport))
	, m_hMainWindow(NULL)
	, m_initialized(false)
	, m_shutdown(false)
	, m_appliedEnabled(false)
	, m_appliedKillSwitch(true)
	, m_tlsRuntimeInUse(false)
	, m_relayHighIdObserved(false)
	, m_relayHighIdSelectedServer(false)
{
	UpdateStatusCache();
}

CRelayClient::~CRelayClient()
{
	Shutdown();
}

bool CRelayClient::Initialize(HWND hMainWindow) noexcept
{
	if (m_initialized || m_shutdown || hMainWindow == NULL || !::IsWindow(hMainWindow))
		return false;
	m_hMainWindow = hMainWindow;
	m_notifier->Attach(hMainWindow);

	const relayclient::RelayClientConfig config = RelayConfigFromPreferences();
	const relay::RelayStatus configured = m_manager->Configure(config);
	// Keep the shell alive even when an opted-in profile is temporarily
	// incomplete; a later local reconfiguration can recover without restart.
	m_initialized = true;
	if (configured == relay::RelayStatus::Ok) {
		m_appliedEnabled = config.enabled;
		m_appliedKillSwitch = config.kill_switch;
	}
	if (configured == relay::RelayStatus::Ok && config.enabled && !config.kill_switch) {
		m_tlsRuntimeInUse.store(true, std::memory_order_release);
		(void)m_manager->Start(KrpMonotonicMilliseconds());
	}
	UpdateStatusCache();
	ScheduleMainThreadWake();
	return configured == relay::RelayStatus::Ok;
}

bool CRelayClient::ApplyPreferences() noexcept
{
	if (!m_initialized || m_shutdown)
		return false;

	const bool enabled = thePrefs.GetKrpRelayEnabled();
	const bool killSwitch = thePrefs.GetKrpRelayKillSwitch();
	if (enabled == m_appliedEnabled && killSwitch == m_appliedKillSwitch)
		return true;

	if (!enabled || killSwitch) {
		const relay::RelayStatus status = killSwitch
			? m_manager->SetKillSwitch(true)
			: m_manager->Disable();
		if (status != relay::RelayStatus::Ok)
			return false;
		m_appliedEnabled = enabled;
		m_appliedKillSwitch = killSwitch;
		m_tlsRuntimeInUse.store(false, std::memory_order_release);
		UpdateStatusCache();
		return true;
	}

	(void)m_manager->SetKillSwitch(false);
	(void)m_manager->Disable();
	const relayclient::RelayClientConfig config = RelayConfigFromPreferences();
	if (m_manager->Configure(config) != relay::RelayStatus::Ok) {
		UpdateStatusCache();
		return false;
	}
	m_appliedEnabled = true;
	m_appliedKillSwitch = false;
	m_tlsRuntimeInUse.store(true, std::memory_order_release);
	const bool started =
		m_manager->Start(KrpMonotonicMilliseconds()) == relay::RelayStatus::Ok;
	UpdateStatusCache();
	ScheduleMainThreadWake();
	return started;
}

void CRelayClient::ProcessMainThreadEvents() noexcept
{
	if (!m_initialized || m_shutdown)
		return;
	(void)ApplyPreferences();
	(void)m_manager->Tick(KrpMonotonicMilliseconds());
	if (m_relayHighIdObserved) {
		const relayclient::RelayClientSnapshot& state = m_manager->Snapshot();
		(void)m_manager->ApplyEd2kRelayEvidence(true,
			state.endpoint == relayclient::RelayEndpointState::Reachable,
			m_relayHighIdSelectedServer);
	}
	UpdateStatusCache();
	ScheduleMainThreadWake();
}

bool CRelayClient::IsTcpDataPlaneEnabled() const noexcept
{
	return m_initialized && !m_shutdown && thePrefs.GetKrpRelayEnabled() &&
		thePrefs.GetKrpRelayExperimentalTcp() && !thePrefs.GetKrpRelayKillSwitch();
}

bool CRelayClient::IsTcpDataPlaneReady() const noexcept
{
	return IsTcpDataPlaneEnabled() && m_transport->DataPlaneReady();
}

bool CRelayClient::PrepareEd2kServerRoute(LPCTSTR numericAddress,
	uint16 serverPort, uint16& loopbackProxyPort) noexcept
{
	loopbackProxyPort = 0;
	if (!IsTcpDataPlaneReady() || numericAddress == NULL)
		return false;
	const CStringA address(numericAddress);
	return m_transport->PrepareEd2kServerRoute(address.GetString(),
		serverPort, loopbackProxyPort);
}

uint16 CRelayClient::GetAdvertisedTcpPort(uint16 directPort) const noexcept
{
	if (!IsTcpDataPlaneReady())
		return directPort;
	const uint16 relayPort = m_transport->PublicTcpPort();
	return relayPort != 0 ? relayPort : directPort;
}

void CRelayClient::OnEd2kIdChange(uint32 clientId,
	bool currentServerIsSelected) noexcept
{
	if (!IsTcpDataPlaneEnabled())
		return;
	m_relayHighIdObserved = clientId != 0 && !::IsLowID(clientId);
	m_relayHighIdSelectedServer = currentServerIsSelected;
	if (!m_relayHighIdObserved)
		return;
	const relayclient::RelayClientSnapshot& state = m_manager->Snapshot();
	(void)m_manager->ApplyEd2kRelayEvidence(true,
		state.endpoint == relayclient::RelayEndpointState::Reachable,
		currentServerIsSelected);
	UpdateStatusCache();
}

void CRelayClient::ScheduleMainThreadWake() noexcept
{
	if (m_hMainWindow == NULL)
		return;
	::KillTimer(m_hMainWindow, kKrpRetryTimerId);
	const relayclient::RelayClientSnapshot& state = m_manager->Snapshot();
	if (state.carrier != relayclient::RelayCarrierState::Backoff)
		return;
	const uint64 now = KrpMonotonicMilliseconds();
	const uint64 remaining = state.next_retry_ms > now ? state.next_retry_ms - now : 1;
	const UINT delay = static_cast<UINT>((std::min)(remaining,
		static_cast<uint64>((std::numeric_limits<UINT>::max)())));
	::SetTimer(m_hMainWindow, kKrpRetryTimerId, (std::max)(delay, 1u), KrpRetryTimerProc);
}

void CRelayClient::Shutdown() noexcept
{
	if (m_shutdown)
		return;
	m_shutdown = true;
	if (m_hMainWindow != NULL)
		::KillTimer(m_hMainWindow, kKrpRetryTimerId);
	m_notifier->Attach(NULL);
	(void)m_manager->Shutdown();
	m_tlsRuntimeInUse.store(false, std::memory_order_release);
	UpdateStatusCache();
	m_hMainWindow = NULL;
}

void CRelayClient::UpdateStatusCache() noexcept
{
	const relayclient::RelayClientSnapshot& state = m_manager->Snapshot();
	const relayclient::RelayClientMetrics metrics = m_manager->Metrics();
	const char* display = "Low ID";
	if (state.ed2k == relayclient::RelayEd2kState::RelayHighId)
		display = "High ID by relay";
	else if (state.ed2k == relayclient::RelayEd2kState::RelayDegraded ||
		state.endpoint == relayclient::RelayEndpointState::Degraded)
		display = "relay endpoint degraded";
	else if (state.ed2k == relayclient::RelayEd2kState::RelayPending)
		display = "Low ID (relay pending)";

	CStringA json;
	const uint16 publicTcpPort = m_transport->PublicTcpPort();
	json.Format(
		"{\"enabled\":%s,\"kill_switch\":%s,\"display\":\"%s\","
		"\"carrier\":\"%s\",\"session\":\"%s\",\"lease\":\"%s\","
		"\"ed2k\":\"%s\",\"endpoint\":\"%s\",\"kad\":\"%s\","
		"\"route\":\"%s\",\"reason\":\"%s\",\"public_tcp_port\":%u,\"generation\":%I64u,"
		"\"next_retry_ms\":%I64u,\"metrics\":{\"starts\":%I64u,"
		"\"reconnects\":%I64u,\"events\":%I64u,\"stale_events\":%I64u,"
		"\"invalid_transitions\":%I64u,\"disconnects\":%I64u,\"queue_drops\":%I64u}}",
		state.configured_enabled ? "true" : "false",
		state.kill_switch ? "true" : "false", display,
		ShortStateName(relayclient::RelayCarrierStateName(state.carrier)),
		ShortStateName(relayclient::RelaySessionStateName(state.session)),
		ShortStateName(relayclient::RelayLeaseStateName(state.lease)),
		ShortStateName(relayclient::RelayEd2kStateName(state.ed2k)),
		ShortStateName(relayclient::RelayEndpointStateName(state.endpoint)),
		ShortStateName(relayclient::RelayKadStateName(state.kad)),
		ShortStateName(relayclient::RelayRouteStateName(state.route)),
		ShortStateName(relayclient::RelayReasonName(state.reason)),
		static_cast<unsigned>(publicTcpPort), state.generation, state.next_retry_ms,
		metrics.transport_starts, metrics.reconnects_scheduled,
		metrics.events_processed, metrics.stale_events,
		metrics.invalid_transitions, metrics.disconnects, metrics.queue_drops);
	std::lock_guard<std::mutex> lock(m_cacheMutex);
	m_statusJson.assign(json.GetString(), static_cast<std::size_t>(json.GetLength()));
}

void CRelayClient::GetStatusJson(CStringA& json) const
{
	std::lock_guard<std::mutex> lock(m_cacheMutex);
	json = m_statusJson.c_str();
}
