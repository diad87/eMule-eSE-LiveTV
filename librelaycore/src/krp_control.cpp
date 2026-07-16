// SPDX-License-Identifier: MIT
#include "relay/krp_control.h"

#include "relay/relay_bytes.h"

#include <limits>
#include <utility>

namespace relay {

bool IsReservedKrpMessageType(std::uint64_t type) noexcept {
    switch (static_cast<KrpMessageType>(type)) {
        case KrpMessageType::KRP_HELLO:
        case KrpMessageType::KRP_WELCOME:
        case KrpMessageType::KRP_AUTH_CHALLENGE:
        case KrpMessageType::KRP_AUTH_RESPONSE:
        case KrpMessageType::KRP_AUTH_OK:
        case KrpMessageType::KRP_CAPABILITIES:
        case KrpMessageType::KRP_SETTINGS:
        case KrpMessageType::KRP_RESUME_PROBE:
        case KrpMessageType::KRP_RESUME_COMMIT:
        case KrpMessageType::KRP_RESUME_RESULT:
        case KrpMessageType::KRP_PRIORITY_GRANT:
        case KrpMessageType::KRP_LEASE_REQUEST:
        case KrpMessageType::KRP_LEASE_GRANTED:
        case KrpMessageType::KRP_LEASE_RENEW:
        case KrpMessageType::KRP_LEASE_STATUS:
        case KrpMessageType::KRP_LEASE_RELEASE:
        case KrpMessageType::KRP_LEASE_REVOKED:
        case KrpMessageType::KRP_FLOW_OPEN:
        case KrpMessageType::KRP_FLOW_ACCEPT:
        case KrpMessageType::KRP_FLOW_REJECT:
        case KrpMessageType::KRP_FLOW_CLOSE:
        case KrpMessageType::KRP_FLOW_RESET:
        case KrpMessageType::KRP_FLOW_PRESSURE:
        case KrpMessageType::KRP_FLOW_DATA:
        case KrpMessageType::KRP_SERVER_BIND:
        case KrpMessageType::KRP_SERVER_STATUS:
        case KrpMessageType::KRP_LEGACY_ENDPOINT_UPDATE:
        case KrpMessageType::KRP_CLASSIC_REACHABILITY:
        case KrpMessageType::KRP_PEER_PROBE_CHALLENGE:
        case KrpMessageType::KRP_PEER_PROBE_RESPONSE:
        case KrpMessageType::KRP_REACHABILITY_STATUS:
        case KrpMessageType::KRP_SERVER_CANDIDATE_SET:
        case KrpMessageType::KRP_PING:
        case KrpMessageType::KRP_PONG:
        case KrpMessageType::KRP_STATS:
        case KrpMessageType::KRP_GOAWAY:
        case KrpMessageType::KRP_ERROR:
            return true;
    }
    return false;
}

RelayStatus EncodeKrpControlFrame(const KrpControlFrame& frame,
                                  std::vector<Byte>& output) {
    if (!IsReservedKrpMessageType(frame.type))
        return RelayStatus::UnsupportedMessage;
    if ((frame.flags & ~kKrpKnownControlFlags) != 0)
        return RelayStatus::UnsupportedOption;
    if (frame.payload.size() > kKrpMaxControlPayload)
        return RelayStatus::TooLarge;

    std::vector<Byte> encoded;
    encoded.reserve(frame.payload.size() + 12u);
    RelayByteWriter writer(encoded);
    writer.WriteVarint(frame.type);
    writer.WriteVarint(frame.flags);
    writer.WriteVarint(static_cast<std::uint64_t>(frame.payload.size()));
    const RelayStatus write_status =
        writer.WriteBytes(frame.payload.data(), frame.payload.size());
    if (write_status != RelayStatus::Ok)
        return write_status;

    output.swap(encoded);
    return RelayStatus::Ok;
}

RelayStatus DecodeKrpControlFrame(const Byte* input,
                                  std::size_t input_size,
                                  KrpControlFrame& frame,
                                  std::size_t& consumed) {
    frame = KrpControlFrame{};
    consumed = 0;
    RelayByteReader reader(input, input_size);
    if (!reader.ok())
        return reader.status();

    std::uint64_t type = 0;
    std::uint64_t flags = 0;
    std::uint64_t payload_size = 0;
    RelayStatus status = reader.ReadVarint(type);
    if (status != RelayStatus::Ok)
        return status;
    status = reader.ReadVarint(flags);
    if (status != RelayStatus::Ok)
        return status;
    status = reader.ReadVarint(payload_size);
    if (status != RelayStatus::Ok)
        return status;

    if (!IsReservedKrpMessageType(type))
        return RelayStatus::UnsupportedMessage;
    if ((flags & ~kKrpKnownControlFlags) != 0)
        return RelayStatus::UnsupportedOption;
    if (payload_size > static_cast<std::uint64_t>(kKrpMaxControlPayload))
        return RelayStatus::TooLarge;
    if (payload_size > static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)()))
        return RelayStatus::TooLarge;

    const std::size_t payload_length = static_cast<std::size_t>(payload_size);
    const Byte* payload = reader.Take(payload_length);
    if (payload == nullptr && payload_length != 0)
        return reader.status();

    KrpControlFrame decoded;
    decoded.type = type;
    decoded.flags = flags;
    if (payload_length != 0)
        decoded.payload.assign(payload, payload + payload_length);

    consumed = reader.position();
    frame = std::move(decoded);
    return RelayStatus::Ok;
}

} // namespace relay
