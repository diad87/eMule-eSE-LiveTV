// this file is part of eMule eSE - value types for the LT5 stream boundary
#pragma once
#include "kad6/kad6_gateway.h"
#include "kad6/kad6_hints.h"
#include "kad6/kad6_search.h"
#include "kad6/kad6_ticket.h"
#include "kad6/kad6_vep.h"
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <set>
#include <vector>
class CUpDownClient;
namespace eSELive {
class CKad6ExitSocket; class CKad6OriginSocket; class CLiveCircuit;
struct LiveTunnelExitStreamRuntime {
    std::uint32_t circ_id=0,dial_request_id=0; std::uint64_t generation=0;
    std::weak_ptr<CLiveCircuit> circuit;
    kad6::K6TargetTicket ticket; kad6::K6Endpoint apparent;
    CKad6ExitSocket* socket=nullptr; CUpDownClient* client=nullptr;
    kad6::K6StreamFlowState flow; std::vector<std::uint8_t> initial_data;
    std::uint64_t created_at=0,last_activity=0,connect_deadline=0,idle_deadline=0;
    std::uint32_t idle_timeout_ms=0;
    std::uint64_t stream_max_bytes=0,tx_sequence=0,pex_sequence=0,quota_allocation_id=0;
    std::uint8_t network_origin=kad6::kK6NetOriginKad2;
    bool connected=false,inbound=false,kill_switch_close=false;
    std::deque<std::vector<std::uint8_t>> pending_credit_frames;
    std::size_t pending_credit_bytes=0; std::uint64_t credit_stall_since_ms=0;
};
struct LiveTunnelQueuedOriginFrame {
    std::uint32_t request_id=0; std::uint64_t sequence=0;
    std::size_t data_bytes=0; std::vector<std::uint8_t> wire;
};
struct LiveTunnelOriginStreamRuntime {
    std::uint32_t circ_id=0; std::uint64_t generation=0; kad6::K6DialResult dial;
    CKad6OriginSocket* socket=nullptr; CUpDownClient* client=nullptr;
    kad6::K6StreamFlowState flow; kad6::K6VirtualIdentityEndpoint vep;
    bool has_vep=false,initial_data_sent=false;
    std::uint64_t next_tx_sequence=0,queued_tx_bytes=0;
    std::deque<kad6::K6SourceHints> hints;
    std::deque<std::vector<std::uint8_t>> pending_frames;
    std::size_t pending_frame_bytes=0;
    std::uint64_t last_activity=0,idle_deadline=0;
    std::deque<LiveTunnelQueuedOriginFrame> pending_credit_frames;
    std::size_t pending_credit_bytes=0; std::uint64_t credit_stall_since_ms=0;
};
using K6ExitStreamRuntime=LiveTunnelExitStreamRuntime;
using K6QueuedOriginFrame=LiveTunnelQueuedOriginFrame;
using K6OriginStreamRuntime=LiveTunnelOriginStreamRuntime;
using LiveTunnelExitStreams=std::map<std::uint64_t,LiveTunnelExitStreamRuntime>;
using LiveTunnelOriginStreams=std::map<std::uint64_t,LiveTunnelOriginStreamRuntime>;
using LiveTunnelSendCredits=std::map<std::uint32_t,kad6::K6SendCreditLedger>;
using LiveTunnelReceiveCredits=std::map<std::uint32_t,kad6::K6ReceiveCreditWindow>;
using LiveTunnelFlowStreamsByCircuit=std::map<std::uint32_t,std::set<std::uint64_t>>;
struct LT5StreamStateBinding { LiveTunnelExitStreams* exit_streams=nullptr; LiveTunnelOriginStreams* origin_streams=nullptr; LiveTunnelSendCredits* send_credits=nullptr; LiveTunnelReceiveCredits* receive_credits=nullptr; LiveTunnelFlowStreamsByCircuit* streams_by_circuit=nullptr; std::uint64_t* next_generation=nullptr; };
} // namespace eSELive
