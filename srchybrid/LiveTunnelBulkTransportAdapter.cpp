// this file is part of eMule eSE - LT7 bulk transport boundary
#include "stdafx.h"
#include "LiveTunnelBulkTransportAdapter.h"

namespace eSELive {

bool M2A_LT7_BulkReplayBridge(void *, std::uint32_t, std::uint64_t) noexcept;

LiveTunnelBulkTransportAdapter::LiveTunnelBulkTransportAdapter(const M2AParentPort &parent) noexcept : m_owner(parent.context) {}
bool LiveTunnelBulkTransportAdapter::AcceptReplay(std::uint32_t circuitId, std::uint64_t nonceSequence) noexcept { return M2A_LT7_BulkReplayBridge(m_owner, circuitId, nonceSequence); }
bool AcceptLiveTunnelBulkTransportReplay(LiveTunnelBulkTransportAdapter *adapter, std::uint32_t circuitId, std::uint64_t nonceSequence) noexcept { return adapter && adapter->AcceptReplay(circuitId, nonceSequence); }
M2AModuleHandle M2A_BIND_LT7_CAC245F7E7(const M2AParentPort &parent) { return MakeM2AModuleHandle(new LiveTunnelBulkTransportAdapter(parent)); }
LiveTunnelBulkTransportAdapter *ResolveLiveTunnelBulkTransportAdapter(M2AModuleHandle &handle) noexcept { return static_cast<LiveTunnelBulkTransportAdapter *>(handle.Get()); }
const LiveTunnelBulkTransportAdapter *ResolveLiveTunnelBulkTransportAdapter(const M2AModuleHandle &handle) noexcept { return static_cast<const LiveTunnelBulkTransportAdapter *>(handle.Get()); }
bool RunLiveTunnelBulkTransportAdapterCharacterizationSelfTest(LiveTunnelBulkTransportAdapter *adapter) {
  if (!adapter || !adapter->AcceptReplay(7, 100) || adapter->AcceptReplay(7, 100) || !adapter->AcceptReplay(7, 102) || !adapter->AcceptReplay(7, 101)) return false;
  for (std::uint64_t sequence = 200; sequence < 500; ++sequence)
    if (!adapter->AcceptReplay(7, sequence)) return false;
  return !adapter->AcceptReplay(7, 100);
}

} // namespace eSELive
