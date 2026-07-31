// this file is part of eMule eSE - LT6 value-only origin service boundary
#pragma once
#include <array>
#include <cstdint>
#include <functional>
#include <set>
#include <string>
#include <vector>
namespace eSELive {
struct LiveTunnelOriginSourceLookup{
    std::array<std::uint8_t,16> file_hash{};std::uint32_t circuit_id=0,deadline_tick=0;std::uint16_t received=0;};
struct LiveTunnelOriginDownloadActivation{
    std::uintptr_t client_token=0;std::uint32_t circuit_id=0,deadline_tick=0;};
struct LiveTunnelOriginTargetRoute{
    std::uint32_t circuit_id=0,source_request_id=0;std::uint64_t expires_at=0;};
struct LiveTunnelOriginAdvertiseReservation{
    bool accepted=false;std::uint64_t generation=0,epoch=0,previous_source_lease_id=0,previous_publish_lease_id=0;};
struct LiveTunnelOriginAdvertiseCompletion{
    bool success=false;std::uint64_t source_lease_id=0,publish_lease_id=0;std::uint32_t refresh_after=0;std::uint64_t now=0;};
enum class LiveTunnelOriginActionKind : std::uint8_t {
    SourceLookupExpired,
    DownloadActivationExpired,
    LeaseRouteRemoved,
    AdvertiseRollback
};
struct LiveTunnelOriginAction{
    LiveTunnelOriginActionKind kind=LiveTunnelOriginActionKind::SourceLookupExpired;
    std::uint32_t request_id=0;std::uintptr_t client_token=0;std::uint64_t lease_id=0;};
struct LiveTunnelOriginSweepResult{std::vector<LiveTunnelOriginAction> actions;bool timer_coalesced=false;};
using LiveTunnelOriginWorkerTask = std::function<void()>;
enum class LiveTunnelOriginOperation : std::uint8_t {
    AddSourceLookup, BindSourceLookup, NoteSourceLookupResult, TakeSourceLookup,
    AddDownloadActivation, TakeDownloadActivation, RemoveDownloadActivation,
    RemoveDownloadActivationsByClient, AddSourceRoute, FindSourceRoute,
    TakeSourceRoute, AddPublishRoute, TakePublishRoute, ReserveAdvertise,
    FinishAdvertise, SubmitAdvertise, AddTargetRoute, FindTargetRoute,
    AddLiveRoute, FindLiveRoute, Sweep, Cancel, Join
};
} // namespace eSELive
