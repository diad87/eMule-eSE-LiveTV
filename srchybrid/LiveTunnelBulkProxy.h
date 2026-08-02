// this file is part of eMule eSE - LT7 bulk/proxy state owner
#pragma once
#include "LiveTunnelBulkStatePort.h"
#include "M2ABindingPort.h"
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <vector>

namespace eSELive {

class LiveTunnelBulkTransportAdapter;

class LiveTunnelBulkProxy final {
public:
  explicit LiveTunnelBulkProxy(const M2AParentPort &) noexcept;
  LiveTunnelBulkProxy(const LiveTunnelBulkProxy &) = delete;
  LiveTunnelBulkProxy &operator=(const LiveTunnelBulkProxy &) = delete;

  LiveTunnelBulkTransportAdapter *Adapter() noexcept;
  const LiveTunnelBulkTransportAdapter *Adapter() const noexcept;
  bool AcceptReplay(std::uint32_t circuitId, std::uint64_t nonceSequence) noexcept;
  bool AcceptFragment(const std::string&,std::uint16_t,std::uint16_t,std::uint32_t,const std::uint8_t*,std::uint32_t,std::uint32_t,DWORD) noexcept;
  void Clear() noexcept;
  std::size_t RemoveCircuitReassembly(std::uint32_t circuitId) noexcept;
  std::size_t SweepRelayReassembly(DWORD now, DWORD ttl) noexcept;

private:
  std::map<std::string, BulkReasmEntry> m_bulkReasm;
  std::map<std::uint32_t, Bulk::BulkReplayWindow> m_bulkReplay;
  mutable std::mutex m_proxyIngestLock;
  std::set<std::string> m_proxyKeys;
  std::map<std::string, ProxyFrag> m_proxyFragReasm;
  std::deque<std::vector<std::uint8_t>> m_proxyReady;
  std::map<std::string, std::vector<BulkSub>> m_bulkSubs;
  std::deque<ProxyRecentRec> m_proxyRecent;
  std::map<std::string, ProxyStreamCtl> m_proxyCtl;
  std::map<std::uint64_t, ReassemblyEntry> m_reassembly;
  std::map<std::string, ExitStreamProxy> m_exitLiveSubs;

  M2AModuleHandle m_m2a_binding_cac245f7e7;

  friend LiveTunnelBulkStatePort M2A_LT7_StateBridge(M2AModuleHandle &) noexcept;
  friend bool M2A_LT7_AcceptReplayBridge(M2AModuleHandle &, std::uint32_t, std::uint64_t) noexcept;
  friend bool M2A_LT7_BulkReplayBridge(void *, std::uint32_t, std::uint64_t) noexcept;
  friend bool RunLiveTunnelBulkProxyCharacterizationSelfTest();
};

M2AModuleHandle M2A_BIND_LT7_9EA638E856(const M2AParentPort &);
LiveTunnelBulkProxy *ResolveLiveTunnelBulkProxy(M2AModuleHandle &) noexcept;
const LiveTunnelBulkProxy *ResolveLiveTunnelBulkProxy(const M2AModuleHandle &) noexcept;
bool RunLiveTunnelBulkProxyCharacterizationSelfTest();

} // namespace eSELive
