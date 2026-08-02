// this file is part of eMule eSE - LT7 bulk transport boundary
#pragma once

#include "M2ABindingPort.h"
#include <cstdint>

namespace eSELive {

class LiveTunnelBulkTransportAdapter final {
public:
  explicit LiveTunnelBulkTransportAdapter(const M2AParentPort &parent) noexcept;
  LiveTunnelBulkTransportAdapter(const LiveTunnelBulkTransportAdapter &) = delete;
  LiveTunnelBulkTransportAdapter &operator=(const LiveTunnelBulkTransportAdapter &) = delete;

  bool AcceptReplay(std::uint32_t circuitId, std::uint64_t nonceSequence) noexcept;

private:
  void *m_owner = nullptr;
};

M2AModuleHandle M2A_BIND_LT7_CAC245F7E7(const M2AParentPort &);
LiveTunnelBulkTransportAdapter *ResolveLiveTunnelBulkTransportAdapter(M2AModuleHandle &) noexcept;
const LiveTunnelBulkTransportAdapter *ResolveLiveTunnelBulkTransportAdapter(const M2AModuleHandle &) noexcept;
bool RunLiveTunnelBulkTransportAdapterCharacterizationSelfTest(LiveTunnelBulkTransportAdapter *);

} // namespace eSELive
