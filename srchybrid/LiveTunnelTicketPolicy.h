// this file is part of eMule eSE - stateless LT4 ticket validation policy
#pragma once

#include "M2ABindingPort.h"
#include "kad6/kad6_ticket.h"

#include <cstdint>
#include <string>

namespace eSELive {

class LiveTunnelTicketPolicy final {
public:
    explicit LiveTunnelTicketPolicy(const M2AParentPort&) noexcept;

    static bool AllowTarget(
        kad6::Byte service,
        const kad6::K6Endpoint& endpoint,
        std::uint16_t applicationPort,
        std::uint16_t webPort) noexcept;
    static bool ValidateTicketEnvelope(
        const kad6::K6TargetTicket& ticket,
        std::uint64_t now) noexcept;
    static std::string ReplayKey(const kad6::K6TargetTicket& ticket);
};

M2AModuleHandle M2A_BIND_LT4_15F4A995EA(const M2AParentPort&);

} // namespace eSELive
