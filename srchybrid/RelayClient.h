// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once

#include <memory>
#include <atomic>
#include <mutex>
#include <string>

namespace relayclient {
class RelayClientManager;
class RelayWssTransport;
}
namespace relay { class INodeIdentitySigner; }

// MFC-facing shell for the MFC-free P3 client. The worker is deliberately
// hidden behind the relayclient queue and never receives an eMule object.
class CRelayClient
{
public:
	CRelayClient();
	~CRelayClient();

	CRelayClient(const CRelayClient&) = delete;
	CRelayClient& operator=(const CRelayClient&) = delete;

	bool Initialize(HWND hMainWindow) noexcept;
	void ProcessMainThreadEvents() noexcept;
	void Shutdown() noexcept;
	void GetStatusJson(CStringA& json) const;
	bool IsTlsRuntimeInUse() const noexcept { return m_tlsRuntimeInUse.load(std::memory_order_acquire); }
	bool IsTcpDataPlaneEnabled() const noexcept;
	bool IsTcpDataPlaneReady() const noexcept;
	bool PrepareEd2kServerRoute(LPCTSTR numericAddress, uint16 serverPort,
		uint16& loopbackProxyPort) noexcept;
	uint16 GetAdvertisedTcpPort(uint16 directPort) const noexcept;
	void OnEd2kIdChange(uint32 clientId, bool currentServerIsSelected) noexcept;

private:
	class CWindowNotifier;
	void UpdateStatusCache() noexcept;
	void ScheduleMainThreadWake() noexcept;

	std::unique_ptr<CWindowNotifier> m_notifier;
	std::unique_ptr<relay::INodeIdentitySigner> m_identitySigner;
	std::unique_ptr<relayclient::RelayWssTransport> m_transport;
	std::unique_ptr<relayclient::RelayClientManager> m_manager;
	mutable std::mutex m_cacheMutex;
	std::string m_statusJson;
	HWND m_hMainWindow;
	bool m_initialized;
	bool m_shutdown;
	std::atomic<bool> m_tlsRuntimeInUse;
	bool m_relayHighIdObserved;
	bool m_relayHighIdSelectedServer;
};
