// SPDX-License-Identifier: MIT
// Kad6 K6-4 gateway control and stream wire objects (spec sections 14-15).
#pragma once

#include "kad6/kad6_endpoint.h"
#include "kad6/kad6_ticket.h"

#include <array>
#include <cstdint>
#include <map>
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
constexpr Byte kK6MsgMaxStreamData   = 0x3C;
constexpr Byte kK6MsgMaxData         = 0x3D;

constexpr std::size_t kK6DialMaxInitialData = 64u * 1024u;
constexpr std::size_t kK6StreamMaxFrameData = 256u * 1024u;
constexpr std::uint32_t kK6DialMinConnectTimeoutMs = 1000;
constexpr std::uint32_t kK6DialMaxConnectTimeoutMs = 30000;
constexpr std::uint32_t kK6DialMinIdleTimeoutMs = 10000;
constexpr std::uint32_t kK6DialMaxIdleTimeoutMs = 30u * 60u * 1000u;
constexpr std::uint64_t kK6DefaultReceiveBuffer = 2u * 1024u * 1024u;
// Initial credit ends exactly at the 75% high watermark. A stalled receiver
// therefore stops the sender before the final quarter of bounded headroom.
constexpr std::uint64_t kK6DefaultStreamCredit =
    kK6DefaultReceiveBuffer * 3u / 4u;
constexpr std::uint64_t kK6DefaultCircuitCredit =
    kK6DefaultReceiveBuffer * 3u / 4u;
constexpr std::uint64_t kK6ReservedControlBytes = 64u * 1024u;
constexpr std::uint64_t kK6CreditStallDeadlineMs = 30u * 1000u;

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

// Authenticated by the enclosing onion/circuit frame.  Offsets are absolute
// and monotonic, so replay cannot create additional credit.
struct K6MaxStreamData {
    std::uint64_t stream_id = 0;
    Byte direction = 0;
    std::uint64_t absolute_offset = 0;
};

struct K6MaxData {
    Byte direction = 0;
    std::uint64_t absolute_offset = 0;
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
Kad6Status EncodeK6MaxStreamData(const K6MaxStreamData&, std::vector<Byte>&);
Kad6Status DecodeK6MaxStreamData(const Byte*, std::size_t, K6MaxStreamData&,
                                  std::size_t* consumed = nullptr) noexcept;
Kad6Status EncodeK6MaxData(const K6MaxData&, std::vector<Byte>&);
Kad6Status DecodeK6MaxData(const Byte*, std::size_t, K6MaxData&,
                            std::size_t* consumed = nullptr) noexcept;

// Side-effect-free sequence/quota state used by both tunnel endpoints. Data is
// accepted only in exact order, before half-close, and while byte quotas fit.
class K6StreamFlowState {
public:
    explicit K6StreamFlowState(std::uint64_t maxBytes = 0) : max_bytes_(maxBytes) {}
    Kad6Status CanAccept(const K6StreamData& data) const noexcept;
    Kad6Status CanAcceptFrame(Byte direction, std::uint64_t sequence,
                              std::size_t dataBytes) const noexcept;
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

// Sender-side credit ledger.  One instance is scoped to one circuit and may
// contain many streams.  CommitSend succeeds only when stream credit, circuit
// credit, ticket quota, scheduler allocation and local queue headroom all fit.
class K6SendCreditLedger {
public:
    Kad6Status RegisterStream(std::uint64_t streamId);
    void RemoveStream(std::uint64_t streamId);
    Kad6Status Grant(const K6MaxStreamData& credit) noexcept;
    Kad6Status Grant(const K6MaxData& credit) noexcept;
    std::uint64_t Available(std::uint64_t streamId, Byte direction,
                            std::uint64_t ticketRemaining,
                            std::uint64_t schedulerCredit,
                            std::uint64_t queueHeadroom) const noexcept;
    Kad6Status CommitSend(std::uint64_t streamId, Byte direction,
                          std::uint64_t bytes, std::uint64_t ticketRemaining,
                          std::uint64_t schedulerCredit,
                          std::uint64_t queueHeadroom) noexcept;
    std::uint64_t stream_sent(std::uint64_t streamId, Byte direction) const noexcept;
    std::uint64_t circuit_sent(Byte direction) const noexcept;
private:
    struct StreamState {
        std::uint64_t limit[2] = {0, 0};
        std::uint64_t sent[2] = {0, 0};
    };
    std::map<std::uint64_t, StreamState> streams_;
    std::uint64_t circuit_limit_[2] = {0, 0};
    std::uint64_t circuit_sent_[2] = {0, 0};
};

// Receiver-side sliding window.  Credit advances only through Consume(),
// which the host calls after bytes leave the downstream socket/application
// queue.  The 75/25 percent hysteresis is exposed as reads_paused().
class K6ReceiveCreditWindow {
public:
    explicit K6ReceiveCreditWindow(
        std::uint64_t streamWindow = kK6DefaultStreamCredit,
        std::uint64_t circuitWindow = kK6DefaultCircuitCredit,
        std::uint64_t maxBuffered = kK6DefaultReceiveBuffer);
    Kad6Status RegisterStream(std::uint64_t streamId);
    void RemoveStream(std::uint64_t streamId);
    Kad6Status InitialCredit(std::uint64_t streamId, Byte direction,
                             K6MaxStreamData& streamCredit,
                             K6MaxData& circuitCredit) const noexcept;
    Kad6Status CanAccept(std::uint64_t streamId, Byte direction,
                         std::uint64_t bytes) const noexcept;
    Kad6Status Accept(std::uint64_t streamId, Byte direction,
                      std::uint64_t bytes, std::uint64_t nowMs) noexcept;
    Kad6Status Consume(std::uint64_t streamId, Byte direction,
                       std::uint64_t bytes, std::uint64_t nowMs,
                       K6MaxStreamData& streamCredit,
                       K6MaxData& circuitCredit) noexcept;
    bool reads_paused() const noexcept { return reads_paused_; }
    bool stalled(std::uint64_t nowMs,
                 std::uint64_t deadlineMs = kK6CreditStallDeadlineMs) const noexcept;
    std::uint64_t buffered_bytes() const noexcept { return buffered_bytes_; }
    std::uint64_t max_buffered_bytes() const noexcept { return max_buffered_; }
private:
    struct StreamState {
        std::uint64_t received[2] = {0, 0};
        std::uint64_t consumed[2] = {0, 0};
        std::uint64_t advertised[2] = {0, 0};
    };
    void UpdateWatermark(std::uint64_t nowMs) noexcept;
    std::map<std::uint64_t, StreamState> streams_;
    std::uint64_t circuit_received_[2] = {0, 0};
    std::uint64_t circuit_consumed_[2] = {0, 0};
    std::uint64_t circuit_advertised_[2] = {0, 0};
    std::uint64_t stream_window_ = 0;
    std::uint64_t circuit_window_ = 0;
    std::uint64_t max_buffered_ = 0;
    std::uint64_t buffered_bytes_ = 0;
    std::uint64_t paused_since_ms_ = 0;
    bool reads_paused_ = false;
};

// Data cannot consume the reserved control lane.  MAX_*, CLOSE and DESTROY
// may therefore make progress even when the ordinary data queue is full.
class K6GatewayQueueBudget {
public:
    explicit K6GatewayQueueBudget(std::uint64_t dataBytes,
        std::uint64_t controlBytes = kK6ReservedControlBytes)
        : data_capacity_(dataBytes), control_capacity_(controlBytes) {}
    bool ReserveData(std::uint64_t bytes) noexcept;
    bool ReserveControl(std::uint64_t bytes) noexcept;
    void ReleaseData(std::uint64_t bytes) noexcept;
    void ReleaseControl(std::uint64_t bytes) noexcept;
    std::uint64_t data_used() const noexcept { return data_used_; }
    std::uint64_t control_used() const noexcept { return control_used_; }
private:
    std::uint64_t data_capacity_ = 0, control_capacity_ = 0;
    std::uint64_t data_used_ = 0, control_used_ = 0;
};

} // namespace kad6
