#pragma once
namespace ese { namespace classic {
enum class CallbackAvailability { Available, NoRoute, LegacyCallbackUnavailable };
inline CallbackAvailability EvaluateCallback(bool featureEnabled,bool currentProof,bool kadConnected,bool kadOpen) noexcept {
    if(featureEnabled && !currentProof) return CallbackAvailability::NoRoute;
    if(!kadConnected || !kadOpen) return CallbackAvailability::LegacyCallbackUnavailable;
    return CallbackAvailability::Available;
}
inline const char* CallbackAvailabilityName(CallbackAvailability state) noexcept {
    switch(state) {
    case CallbackAvailability::Available: return "AVAILABLE";
    case CallbackAvailability::NoRoute: return "NO_ROUTE";
    default: return "LEGACY_CALLBACK_UNAVAILABLE";
    }
}
} }
