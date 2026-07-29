// this file is part of eMule eSE - narrow relay/exit value boundary
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>

namespace eSELive {

class CLiveCircuit;

// Immutable-for-the-duration-of-dispatch view of a fully validated relay
// request. `body` is borrowed only for the synchronous handler call. Handlers
// that continue asynchronously must copy the bytes they need.
struct LiveTunnelRequestCtx {
    std::shared_ptr<CLiveCircuit> circ;
    std::uint8_t sub_cmd = 0;
    std::uint32_t req_id = 0;
    const std::uint8_t* body = nullptr;
    std::size_t bodyLen = 0;
};

using LiveTunnelOpHandler =
    std::function<void(const LiveTunnelRequestCtx&)>;

} // namespace eSELive
