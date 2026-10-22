#pragma once
namespace ese { namespace discovery {
enum class DiscoveryOutcome { Idle, Pending, SourceReady, BootstrapRequired, DiscoveryUnavailable };
inline const char* DiscoveryOutcomeName(DiscoveryOutcome state) noexcept {
    switch(state) {
    case DiscoveryOutcome::Pending: return "DISCOVERY_PENDING";
    case DiscoveryOutcome::SourceReady: return "SOURCE_READY";
    case DiscoveryOutcome::BootstrapRequired: return "BOOTSTRAP_REQUIRED";
    case DiscoveryOutcome::DiscoveryUnavailable: return "DISCOVERY_UNAVAILABLE";
    default: return "IDLE";
    }
}
// Local diagnostic of the last admitted lookup; neither a source, a route,
// an identity proof nor a replacement for the bounded per-file cooldown.
class DiscoveryStatus {
public:
    void MissingBootstrap() noexcept { state_=DiscoveryOutcome::BootstrapRequired; }
    void Started() noexcept { state_=DiscoveryOutcome::Pending; }
    void Resolved() noexcept { state_=DiscoveryOutcome::SourceReady; }
    void Expired() noexcept { if(state_==DiscoveryOutcome::Pending) state_=DiscoveryOutcome::DiscoveryUnavailable; }
    void Cancelled() noexcept { if(state_==DiscoveryOutcome::Pending || state_==DiscoveryOutcome::SourceReady) state_=DiscoveryOutcome::Idle; }
    DiscoveryOutcome State() const noexcept { return state_; }
private:
    DiscoveryOutcome state_=DiscoveryOutcome::Idle;
};
} }
