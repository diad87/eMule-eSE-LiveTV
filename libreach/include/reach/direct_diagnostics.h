// SPDX-License-Identifier: MIT
#pragma once
#include "reach/direct_coordinator.h"
#include <memory>
#include <mutex>
#include <string>
#include <tuple>
#include <stdexcept>
#include <algorithm>

namespace reach {
enum class DirectProgressBlocker : std::uint8_t { Unspecified, Preparing, Recovering, Terminal, RemoteQueue, LocalPause, None };
inline const char* DirectBlockerName(DirectProgressBlocker blocker) noexcept {
    switch(blocker) {
    case DirectProgressBlocker::Unspecified:return "UNSPECIFIED";
    case DirectProgressBlocker::Preparing:return "PREPARING";
    case DirectProgressBlocker::Recovering:return "RECOVERING";
    case DirectProgressBlocker::Terminal:return "TERMINAL";
    case DirectProgressBlocker::RemoteQueue:return "REMOTE_QUEUE";
    case DirectProgressBlocker::LocalPause:return "LOCAL_PAUSE";
    case DirectProgressBlocker::None:return "NONE";
    }
    return "UNSPECIFIED";
}
// Diagnostic-only projection. Never contains a peer key, endpoint, subscriber,
// auth token or route permission. MX01 remains a separate, unchanged contract.
struct DirectDiagnosticV2 {
    std::uint64_t snapshot_sequence=0, topology_generation=0, session_epoch=0;
    std::uint64_t accepted_unique_bytes=0, fallback_count=0;
    std::uint64_t session_id=0;
    DirectSessionState state=DirectSessionState::Gathering;
    DirectReason terminal_reason=DirectReason::None;
    DirectProgressBlocker progress_blocker=DirectProgressBlocker::Unspecified;
    bool authenticated=false, transfer_verified=false, fallback_count_available=false;
    std::uint8_t candidate_count=0;
    std::uint8_t transport=0;
    // Zero means no winner; otherwise DirectKind + 1 (not a route ID).
    std::uint8_t route_kind=0;
};
inline bool ValidDirectDiagnostic(const DirectDiagnosticV2& value) noexcept {
    return value.state<=DirectSessionState::Cancelled && value.terminal_reason<=DirectReason::UnsupportedRemote &&
        value.progress_blocker<=DirectProgressBlocker::None &&
        value.candidate_count<=kDirectMaxCandidates && value.route_kind<=8 &&
        (!value.transport || value.transport==DirectTcp || value.transport==DirectUtp || value.transport==DirectQuic) &&
        (bool(value.route_kind)==bool(value.transport)) &&
        (!value.authenticated || (value.session_epoch && value.route_kind));
}
inline const char* DirectDiagnosticState(DirectSessionState state) noexcept {
    switch(state) {
    case DirectSessionState::Gathering:return "PREPARING";
    case DirectSessionState::Connecting:return "CONNECTING";
    case DirectSessionState::Authenticating:return "AUTHENTICATING";
    case DirectSessionState::Ready:return "DIRECT";
    case DirectSessionState::Transferring:return "TRANSFERRING";
    case DirectSessionState::Recovering:return "RECOVERING";
    case DirectSessionState::Failed:return "DIRECT_UNREACHABLE";
    case DirectSessionState::Cancelled:return "CANCELLED";
    }
    return "UNAVAILABLE";
}
inline DirectDiagnosticV2 ProjectDirectDiagnostic(const DirectCoordinatorSnapshot& source,
    const std::vector<DirectSessionRoute>& routes={}) noexcept {
    DirectDiagnosticV2 result;
    result.topology_generation=source.topology_generation; result.session_epoch=source.epoch;
    result.accepted_unique_bytes=source.useful_bytes; result.state=source.state;
    result.terminal_reason=source.reason; result.transfer_verified=source.transfer_verified;
    result.fallback_count=source.fallback_count; result.fallback_count_available=true;
    result.progress_blocker=source.state==DirectSessionState::Gathering ? DirectProgressBlocker::Preparing :
        source.state==DirectSessionState::Recovering ? DirectProgressBlocker::Recovering :
        source.state==DirectSessionState::Failed || source.state==DirectSessionState::Cancelled ? DirectProgressBlocker::Terminal : DirectProgressBlocker::Unspecified;
    result.authenticated=source.winner!=0 && source.epoch!=0 &&
        (source.state==DirectSessionState::Ready || source.state==DirectSessionState::Transferring);
    result.candidate_count=static_cast<std::uint8_t>((std::min)(routes.size(),kDirectMaxCandidates));
    for(const auto& route:routes) if(route.id==source.winner) {
        result.route_kind=static_cast<std::uint8_t>(route.candidate.kind)+1; result.transport=route.transport;
    }
    // Missing local route evidence must not export an authenticated winner.
    if(!result.route_kind) result.authenticated=false;
    return result;
}
inline std::string DirectDiagnosticJson(const DirectDiagnosticV2& value) {
    if(!ValidDirectDiagnostic(value)) throw std::invalid_argument("Invalid direct diagnostic projection");
    // Every uint64 is ALWAYS a canonical decimal string, including zero.
    return "{\"schema_version\":2,\"snapshot_sequence\":\""+std::to_string(value.snapshot_sequence)+
        "\",\"topology_generation\":\""+std::to_string(value.topology_generation)+
        "\",\"session_epoch\":\""+std::to_string(value.session_epoch)+
        "\",\"accepted_unique_bytes\":\""+std::to_string(value.accepted_unique_bytes)+
        "\",\"fallback_count\":\""+std::to_string(value.fallback_count)+
        "\",\"fallback_count_available\":"+(value.fallback_count_available ? "true" : "false")+
        ",\"session_id\":\"d"+std::to_string(value.session_id)+
        "\",\"state\":\""+DirectDiagnosticState(value.state)+"\""+
        ",\"route_kind\":"+std::to_string(value.route_kind)+
        ",\"transport\":\""+(value.transport==DirectTcp ? "TCP" : value.transport==DirectUtp ? "UTP" : value.transport==DirectQuic ? "QUIC" : "NONE")+"\""+
        ",\"terminal_reason\":"+std::to_string(static_cast<unsigned>(value.terminal_reason))+
        ",\"auth_status\":\""+(value.authenticated ? "AUTHENTICATED" : "UNVERIFIED")+
        "\",\"transfer_verified\":"+(value.transfer_verified ? "true" : "false")+
        ",\"progress_blocker\":\""+DirectBlockerName(value.progress_blocker)+
        "\",\"limits\":{\"attempts\":256,\"subscribers\":16,\"candidates\":16,\"routes\":8,"
        "\"tx_bytes\":\"4194304\",\"rx_bytes\":\"4194304\",\"global_bytes\":\"134217728\"},"
        "\"candidate_summary\":{\"count\":"+std::to_string(value.candidate_count)+"}}";
}
// Owner thread publishes; GUI and web workers share this immutable value.
// Logical transitions bypass counter throttling. Failed publication is atomic.
class DirectDiagnosticPublisher {
public:
    bool Publish(DirectDiagnosticV2 next,std::uint64_t now) {
        std::lock_guard<std::mutex> lock(mutex_);
        if(!ValidDirectDiagnostic(next)) return false;
        if(current_ && now<last_clock_) return false;
        if(current_) {
            const auto& old=*current_;
            const bool transition=std::tie(next.state,next.terminal_reason,next.topology_generation,
                next.session_epoch,next.authenticated,next.transfer_verified,next.candidate_count,next.session_id,next.route_kind,next.transport,next.fallback_count_available,next.progress_blocker)!=
                std::tie(old.state,old.terminal_reason,old.topology_generation,
                old.session_epoch,old.authenticated,old.transfer_verified,old.candidate_count,old.session_id,old.route_kind,old.transport,old.fallback_count_available,old.progress_blocker);
            const bool counters=next.accepted_unique_bytes!=old.accepted_unique_bytes || next.fallback_count!=old.fallback_count;
            if(!transition && (!counters || now-last_publication_<1000)) { last_clock_=now; return false; }
            if(old.snapshot_sequence==(std::numeric_limits<std::uint64_t>::max)()) return false;
            next.snapshot_sequence=old.snapshot_sequence+1;
        } else next.snapshot_sequence=1;
        auto replacement=std::make_shared<const DirectDiagnosticV2>(next);
        current_=std::move(replacement); last_publication_=now; last_clock_=now;
        return true;
    }
    std::shared_ptr<const DirectDiagnosticV2> Read() const {
        std::lock_guard<std::mutex> lock(mutex_); return current_;
    }
private:
    mutable std::mutex mutex_;
    std::shared_ptr<const DirectDiagnosticV2> current_;
    std::uint64_t last_publication_=0,last_clock_=0;
};
}
