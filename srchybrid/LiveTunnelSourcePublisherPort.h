// this file is part of eMule eSE - value-only LT4 parent/owner boundary
#pragma once

#include "kad6/kad6_gateway.h"
#include "kad6/kad6_publish.h"
#include "kad6/kad6_search.h"
#include "kad6/kad6_store.h"
#include <cstdint>
#include <string>

namespace eSELive {

struct LiveTunnelPublishRuntime {
    kad6::K6Publish request;
    std::uint64_t publish_lease_id = 0;
    std::uint64_t source_lease_id = 0;
    std::uint64_t expires_at = 0;
    kad6::K6PublishStatus status = kad6::K6PublishStatus::Queued;
    std::uint8_t published_networks = 0;
    std::uint16_t replicas = 0;
    std::uint8_t max_load = 0;
    std::uint64_t primary_publish_lease_id = 0;
    std::uint64_t next_refresh_at = 0;
    std::uint64_t next_native_refresh_at = 0;
    std::uint64_t visibility_probe_at = 0;
    std::uint64_t visibility_probe_deadline = 0;
    std::uint32_t refresh_backoff_s = 60;
    std::uint32_t native_backoff_s = 60;
    bool kad2_queued = false;
    bool kad2_search_active = false;
    bool visibility_probe_started = false;
    bool auto_refresh = false;
    bool refresh_enabled = true;
};

struct LiveTunnelAuthorizedTarget {
    std::uint32_t circ_id = 0;
    std::uint32_t source_request_id = 0;
    kad6::Hash16 result_id{};
    kad6::Hash16 object_hash{};
    kad6::Hash32 digest{};
    kad6::K6Endpoint endpoint;
    std::uint8_t network_origin = kad6::kK6NetOriginKad2;
    std::uint64_t expires_at = 0;
};

struct LiveTunnelUsedTicket {
    std::uint16_t used = 0;
    std::uint64_t expires_at = 0;
};

enum class LiveTunnelPublishActionKind : std::uint8_t {
    StopServing,
    RemoveCoalesced,
    RefreshShadow,
    RefreshNative,
    ProbeVisibility,
};

struct LiveTunnelPublishAction {
    LiveTunnelPublishActionKind kind =
        LiveTunnelPublishActionKind::RemoveCoalesced;
    std::uint64_t publish_lease_id = 0;
    std::uint64_t source_lease_id = 0;
};

enum class LiveTunnelPublishMutation : std::uint8_t {
    Created,
    DuplicatePublish,
    CapacityRejected,
    DuplicateUnpublish,
    LateAckIgnored,
    Updated,
};

} // namespace eSELive
