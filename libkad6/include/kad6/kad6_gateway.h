// SPDX-License-Identifier: MIT
// Kad6 K6-4 gateway control and stream wire objects (spec sections 14-15).
#pragma once

#include "kad6/kad6_endpoint.h"
#include "kad6/kad6_ticket.h"

#include <cstdint>
#include <vector>

namespace kad6 {

constexpr Byte kK6MsgTargetTicketReq = 0x28;
constexpr Byte kK6MsgTargetTicket    = 0x29;
constexpr Byte kK6MsgSourceHints     = 0x2A;
constexpr Byte kK6MsgVep             = 0x2B;
constexpr Byte kK6MsgDial            = 0x30;
constexpr Byte kK6MsgDialOk          = 0x31;
constexpr Byte kK6MsgAccept          = 0x32;
constexpr Byte kK6MsgStreamData      = 0x33;
constexpr Byte kK6MsgStreamHalfClose = 0x34;
constexpr Byte kK6MsgStreamClose     = 0x35;

constexpr std::size_t kK6DialMaxInitialData = 64u * 1024u;
constexpr std::size_t kK6StreamMaxFrameData = 256u * 1024u;
constexpr std::uint32_t kK6DialMinConnectTimeoutMs = 1000;
constexpr std::uint32_t kK6DialMaxConnectTimeoutMs = 30000;
constexpr std::uint32_t kK6DialMinIdleTimeoutMs = 10000;
constexpr std::uint32_t kK6DialMaxIdleTimeoutMs = 30u * 60u * 1000u;

enum class K6GatewayTransport : Byte { TcpEd2k = 1, UdpEd2k = 2, UdpKad2 = 3 };
enum class K6TargetTicketStatus : Byte {
    Ok = 0, NotFound = 1, PolicyDenied = 2, Expired = 3, Overloaded = 4, BadRequest = 5
};
enum class K6DialStatus : Byte {
    Ok = 0, TicketRejected = 1, PolicyDenied = 2, ConnectFailed = 3,
    Timeout = 4, Overloaded = 5, Unsupported = 6, BadInitialData = 7
};

struct K6TargetTicketRequest {
    std::uint32_t source_request_id = 0;
    Hash16 result_id{};
    Byte service = static_cast<Byte>(K6TicketService::Ed2kTcp);
    Hash16 object_hash{};
    std::uint64_t requested_max_bytes = 0;
};

// The response wrapper makes denial explicit and keeps a malformed/empty ticket
// from being confused with an authorization. A successful response contains
// exactly one canonical K6TargetTicketV1.
struct K6TargetTicketResponse {
    K6TargetTicketStatus status = K6TargetTicketStatus::BadRequest;
    std::vector<Byte> ticket;
};

struct K6Dial {
    std::vector<Byte> ticket;
    K6GatewayTransport protocol = K6GatewayTransport::TcpEd2k;
    std::uint32_t connect_timeout_ms = 10000;
    std::uint32_t idle_timeout_ms = 120000;
    std::vector<Byte> initial_data;
};

struct K6DialResult {
    std::uint64_t stream_id = 0;
    K6DialStatus status = K6DialStatus::ConnectFailed;
    K6GatewayTransport transport = K6GatewayTransport::TcpEd2k;
    std::uint16_t flags = 0;
    K6Endpoint apparent_local_endpoint;
    K6Endpoint remote_endpoint;
    std::uint64_t max_bytes = 0;
    std::uint32_t idle_timeout_ms = 0;
};

struct K6StreamData {
    std::uint64_t stream_id = 0;
    std::uint64_t sequence = 0;
    Byte direction = 0; // 0=A->X->remote, 1=remote->X->A
    Byte flags = 0;
    std::vector<Byte> data;
};

struct K6StreamHalfClose {
    std::uint64_t stream_id = 0;
    Byte direction = 0;
    Byte reason = 0;
    std::uint64_t last_sequence = 0;
};

struct K6StreamClose {
    std::uint64_t stream_id = 0;
    std::uint16_t reason_code = 0;
    std::uint16_t flags = 0;
    std::uint64_t last_tx_sequence = 0;
    std::uint64_t last_rx_sequence = 0;
    std::uint64_t total_tx_bytes = 0;
    std::uint64_t total_rx_bytes = 0;
};

Kad6Status EncodeK6TargetTicketRequest(const K6TargetTicketRequest&, std::vector<Byte>&);
Kad6Status DecodeK6TargetTicketRequest(const Byte*, std::size_t, K6TargetTicketRequest&,
                                        std::size_t* consumed = nullptr) noexcept;
Kad6Status EncodeK6TargetTicketResponse(const K6TargetTicketResponse&, std::vector<Byte>&);
Kad6Status DecodeK6TargetTicketResponse(const Byte*, std::size_t, K6TargetTicketResponse&,
                                         std::size_t* consumed = nullptr) noexcept;
Kad6Status EncodeK6Dial(const K6Dial&, std::vector<Byte>&);
Kad6Status DecodeK6Dial(const Byte*, std::size_t, K6Dial&,
                         std::size_t* consumed = nullptr) noexcept;
Kad6Status EncodeK6DialResult(const K6DialResult&, std::vector<Byte>&);
Kad6Status DecodeK6DialResult(const Byte*, std::size_t, K6DialResult&,
                               std::size_t* consumed = nullptr) noexcept;
Kad6Status EncodeK6StreamData(const K6StreamData&, std::vector<Byte>&);
Kad6Status DecodeK6StreamData(const Byte*, std::size_t, K6StreamData&,
                               std::size_t* consumed = nullptr) noexcept;
Kad6Status EncodeK6StreamHalfClose(const K6StreamHalfClose&, std::vector<Byte>&);
Kad6Status DecodeK6StreamHalfClose(const Byte*, std::size_t, K6StreamHalfClose&,
                                    std::size_t* consumed = nullptr) noexcept;
Kad6Status EncodeK6StreamClose(const K6StreamClose&, std::vector<Byte>&);
Kad6Status DecodeK6StreamClose(const Byte*, std::size_t, K6StreamClose&,
                                std::size_t* consumed = nullptr) noexcept;

// Side-effect-free sequence/quota state used by both tunnel endpoints. Data is
// accepted only in exact order, before half-close, and while byte quotas fit.
class K6StreamFlowState {
public:
    explicit K6StreamFlowState(std::uint64_t maxBytes = 0) : max_bytes_(maxBytes) {}
    Kad6Status Accept(const K6StreamData& data) noexcept;
    Kad6Status AcceptFrame(Byte direction, std::uint64_t sequence,
                           std::size_t dataBytes) noexcept;
    Kad6Status HalfClose(const K6StreamHalfClose& close) noexcept;
    Kad6Status Close(const K6StreamClose& close) noexcept;
    std::uint64_t next_sequence(Byte direction) const noexcept;
    std::uint64_t total_bytes(Byte direction) const noexcept;
    bool half_closed(Byte direction) const noexcept;
    bool closed() const noexcept { return closed_; }
private:
    std::uint64_t next_[2] = {0, 0};
    std::uint64_t total_[2] = {0, 0};
    bool half_[2] = {false, false};
    bool closed_ = false;
    std::uint64_t max_bytes_ = 0;
};

} // namespace kad6
