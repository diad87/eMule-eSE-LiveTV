// this file is part of eMule eSE - stateless LT4 ticket validation policy
#include "LiveTunnelTicketPolicy.h"

#include <algorithm>

namespace eSELive {

LiveTunnelTicketPolicy::LiveTunnelTicketPolicy(const M2AParentPort&) noexcept {}

bool LiveTunnelTicketPolicy::AllowTarget(
    kad6::Byte service,
    const kad6::K6Endpoint& endpoint,
    std::uint16_t applicationPort,
    std::uint16_t webPort) noexcept
{
    if (service != static_cast<kad6::Byte>(kad6::K6TicketService::Ed2kTcp) ||
        endpoint.tcp_port == 0 || endpoint.tcp_port == applicationPort ||
        endpoint.tcp_port == webPort)
        return false;
    static const std::uint16_t denied[] = {
        22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445, 1433,
        2375, 3306, 3389, 5432, 5900, 5985, 6379, 8080, 9200, 11211,
    };
    return std::find(std::begin(denied), std::end(denied),
                     endpoint.tcp_port) == std::end(denied);
}

bool LiveTunnelTicketPolicy::ValidateTicketEnvelope(
    const kad6::K6TargetTicket& ticket,
    std::uint64_t now) noexcept
{
    return ticket.service ==
            static_cast<kad6::Byte>(kad6::K6TicketService::Ed2kTcp) &&
        ticket.lease_id != 0 && ticket.max_connections != 0 &&
        ticket.max_bytes != 0 && ticket.issued_at <= now &&
        ticket.expires_at > now &&
        ticket.expires_at - ticket.issued_at <= kad6::kK6TicketMaxTtlSeconds &&
        ticket.target_endpoint.tcp_port != 0;
}

std::string LiveTunnelTicketPolicy::ReplayKey(
    const kad6::K6TargetTicket& ticket)
{
    std::string key(
        reinterpret_cast<const char*>(ticket.nonce.data()),
        ticket.nonce.size());
    for (int shift = 0; shift < 8; ++shift)
        key.push_back(static_cast<char>(ticket.lease_id >> (8 * shift)));
    return key;
}

M2AModuleHandle M2A_BIND_LT4_15F4A995EA(const M2AParentPort& parent){
    return MakeM2AModuleHandle(new LiveTunnelTicketPolicy(parent));
}

} // namespace eSELive
