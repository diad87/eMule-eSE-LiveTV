// SPDX-License-Identifier: MIT
#pragma once

#include "edge/edge_daemon.h"
#include "edge/wss_carrier.h"

#include <cstdint>

namespace relayedge {

struct KrpTcpSessionStats {
    std::uint64_t authenticated = 0;
    std::uint64_t leases = 0;
    std::uint64_t server_flows = 0;
    std::uint64_t inbound_flows = 0;
    std::uint64_t bytes_to_client = 0;
    std::uint64_t bytes_from_client = 0;
};

relay::RelayStatus RunKrpTcpSession(EdgeDaemon& daemon,
                                    TlsTcpCarrier& tls,
                                    WssH1Carrier& wss,
                                    const EdgeConfig& config,
                                    KrpTcpSessionStats& stats) noexcept;

} // namespace relayedge
