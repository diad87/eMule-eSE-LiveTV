#include "natmap/pcp_mapping_identity.h"

#include <algorithm>

namespace natmap {
namespace {

bool IsSupportedTransport(Transport transport) noexcept {
    return transport == Transport::Tcp || transport == Transport::Udp;
}

bool IsZeroNonce(
    const std::array<std::uint8_t, 12>& nonce) noexcept {
    return std::all_of(
        nonce.begin(), nonce.end(),
        [](std::uint8_t byte) { return byte == 0; });
}

} // namespace

bool PcpMappingIdentity::IsEmpty() const noexcept {
    return static_cast<std::uint8_t>(transport) == 0
        && internal_port == 0 && IsZeroNonce(nonce);
}

bool PcpMappingIdentity::IsValid() const noexcept {
    return IsSupportedTransport(transport)
        && internal_port != 0 && !IsZeroNonce(nonce);
}

bool PcpMappingIdentity::Matches(
    Transport expected_transport,
    std::uint16_t expected_internal_port) const noexcept {
    return IsValid()
        && transport == expected_transport
        && internal_port == expected_internal_port;
}

void PcpMappingIdentity::Clear() noexcept {
    *this = PcpMappingIdentity{};
}

PcpIdentityStatus InitializePcpMappingIdentity(
    PcpMappingIdentity& identity,
    Transport transport,
    std::uint16_t internal_port,
    const std::array<std::uint8_t, 12>& nonce) noexcept {
    if (!identity.IsEmpty())
        return PcpIdentityStatus::CorruptIdentity;
    if (!IsSupportedTransport(transport))
        return PcpIdentityStatus::InvalidTransport;
    if (internal_port == 0)
        return PcpIdentityStatus::InvalidPort;
    if (IsZeroNonce(nonce))
        return PcpIdentityStatus::ZeroNonce;
    identity.transport = transport;
    identity.internal_port = internal_port;
    identity.nonce = nonce;
    return PcpIdentityStatus::Valid;
}

PcpIdentityStatus ValidatePcpMappingIdentity(
    const PcpMappingIdentity& identity,
    Transport expected_transport,
    std::uint16_t expected_internal_port) noexcept {
    if (!IsSupportedTransport(expected_transport))
        return PcpIdentityStatus::InvalidTransport;
    if (expected_internal_port == 0)
        return PcpIdentityStatus::InvalidPort;
    if (identity.IsEmpty())
        return PcpIdentityStatus::Empty;
    if (!identity.IsValid())
        return PcpIdentityStatus::CorruptIdentity;
    return identity.Matches(expected_transport, expected_internal_port)
        ? PcpIdentityStatus::Valid
        : PcpIdentityStatus::IdentityMismatch;
}

} // namespace natmap
