// SPDX-License-Identifier: MIT
#include "kad6/kad6_gateway.h"

#include <algorithm>
#include <limits>

namespace kad6 {
namespace {

bool ValidTransport(K6GatewayTransport v) noexcept {
    const Byte b = static_cast<Byte>(v);
    return b >= static_cast<Byte>(K6GatewayTransport::TcpEd2k) &&
           b <= static_cast<Byte>(K6GatewayTransport::UdpKad2);
}
bool ValidTicketStatus(K6TargetTicketStatus v) noexcept {
    return static_cast<Byte>(v) <= static_cast<Byte>(K6TargetTicketStatus::BadRequest);
}
bool ValidDialStatus(K6DialStatus v) noexcept {
    return static_cast<Byte>(v) <= static_cast<Byte>(K6DialStatus::BadInitialData);
}
Kad6Status Finish(const ByteReader& r, std::size_t len, std::size_t* consumed) noexcept {
    if (!r.ok()) return Kad6Status::Truncated;
    if (r.pos() != len) return Kad6Status::Malformed;
    if (consumed) *consumed = len;
    return Kad6Status::Ok;
}
bool AddOverflows(std::uint64_t a, std::uint64_t b) noexcept {
    return b > (std::numeric_limits<std::uint64_t>::max)() - a;
}

} // namespace

Kad6Status EncodeK6TargetTicketRequest(const K6TargetTicketRequest& v, std::vector<Byte>& out) {
    out.clear();
    if (v.source_request_id == 0 ||
        v.service < static_cast<Byte>(K6TicketService::Kad2Udp) ||
        v.service > static_cast<Byte>(K6TicketService::Ed2kUdp) ||
        v.requested_max_bytes == 0)
        return Kad6Status::BadValue;
    ByteWriter w(out); w.u32le(v.source_request_id); w.bytes(v.result_id.data(), 16);
    w.u8(v.service); w.bytes(v.object_hash.data(), 16); w.u64le(v.requested_max_bytes);
    return Kad6Status::Ok;
}

Kad6Status DecodeK6TargetTicketRequest(const Byte* in, std::size_t len,
        K6TargetTicketRequest& out, std::size_t* consumed) noexcept {
    out = K6TargetTicketRequest{}; if (consumed) *consumed = 0;
    if (!in && len) return Kad6Status::NullArgument;
    ByteReader r(in, len); out.source_request_id = r.u32le();
    r.bytes(out.result_id.data(), 16); out.service = r.u8();
    r.bytes(out.object_hash.data(), 16); out.requested_max_bytes = r.u64le();
    Kad6Status s = Finish(r, len, consumed); if (s != Kad6Status::Ok) { out={}; return s; }
    if (out.source_request_id == 0 || out.service < 1 || out.service > 3 ||
        out.requested_max_bytes == 0) { out={}; return Kad6Status::BadValue; }
    return Kad6Status::Ok;
}

Kad6Status EncodeK6TargetTicketResponse(const K6TargetTicketResponse& v, std::vector<Byte>& out) {
    out.clear();
    if (!ValidTicketStatus(v.status) || v.ticket.size() > 0xffffu ||
        (v.status == K6TargetTicketStatus::Ok) != !v.ticket.empty())
        return Kad6Status::BadValue;
    if (!v.ticket.empty()) {
        K6TargetTicket t; std::size_t used = 0;
        if (DecodeK6TargetTicket(v.ticket.data(), v.ticket.size(), t, &used) != Kad6Status::Ok ||
            used != v.ticket.size()) return Kad6Status::Malformed;
    }
    ByteWriter w(out); w.u8(static_cast<Byte>(v.status)); w.u8(0);
    w.u16le(static_cast<std::uint16_t>(v.ticket.size())); w.bytes(v.ticket.data(), v.ticket.size());
    return Kad6Status::Ok;
}

Kad6Status DecodeK6TargetTicketResponse(const Byte* in, std::size_t len,
        K6TargetTicketResponse& out, std::size_t* consumed) noexcept {
    out = K6TargetTicketResponse{}; if (consumed) *consumed = 0;
    if (!in && len) return Kad6Status::NullArgument;
    ByteReader r(in, len); out.status = static_cast<K6TargetTicketStatus>(r.u8());
    const Byte reserved = r.u8(); const std::uint16_t n = r.u16le(); const Byte* p = r.take(n);
    if (!r.ok()) return Kad6Status::Truncated;
    if (!ValidTicketStatus(out.status) || reserved != 0 ||
        (out.status == K6TargetTicketStatus::Ok) != (n != 0)) { out={}; return Kad6Status::Malformed; }
    out.ticket.assign(p, p + n);
    if (n) { K6TargetTicket t; std::size_t used=0;
        if (DecodeK6TargetTicket(p,n,t,&used)!=Kad6Status::Ok || used!=n) { out={}; return Kad6Status::Malformed; } }
    Kad6Status s=Finish(r,len,consumed); if(s!=Kad6Status::Ok) out={}; return s;
}

Kad6Status EncodeK6Dial(const K6Dial& v, std::vector<Byte>& out) {
    out.clear();
    if (v.ticket.empty() || v.ticket.size() > 0xffffu || !ValidTransport(v.protocol) ||
        v.connect_timeout_ms < kK6DialMinConnectTimeoutMs ||
        v.connect_timeout_ms > kK6DialMaxConnectTimeoutMs ||
        v.idle_timeout_ms < kK6DialMinIdleTimeoutMs || v.idle_timeout_ms > kK6DialMaxIdleTimeoutMs ||
        v.initial_data.size() > kK6DialMaxInitialData) return Kad6Status::BadValue;
    K6TargetTicket t; std::size_t used=0;
    if (DecodeK6TargetTicket(v.ticket.data(),v.ticket.size(),t,&used)!=Kad6Status::Ok || used!=v.ticket.size())
        return Kad6Status::Malformed;
    ByteWriter w(out); w.u16le(static_cast<std::uint16_t>(v.ticket.size()));
    w.bytes(v.ticket.data(),v.ticket.size()); w.u8(static_cast<Byte>(v.protocol));
    w.u32le(v.connect_timeout_ms); w.u32le(v.idle_timeout_ms);
    w.u32le(static_cast<std::uint32_t>(v.initial_data.size()));
    w.bytes(v.initial_data.data(),v.initial_data.size()); return Kad6Status::Ok;
}

Kad6Status DecodeK6Dial(const Byte* in, std::size_t len, K6Dial& out,
        std::size_t* consumed) noexcept {
    out=K6Dial{}; if(consumed)*consumed=0; if(!in&&len)return Kad6Status::NullArgument;
    ByteReader r(in,len); const std::uint16_t tn=r.u16le(); const Byte* tp=r.take(tn);
    if(!r.ok())return Kad6Status::Truncated; out.ticket.assign(tp,tp+tn);
    out.protocol=static_cast<K6GatewayTransport>(r.u8()); out.connect_timeout_ms=r.u32le();
    out.idle_timeout_ms=r.u32le(); const std::uint32_t dn=r.u32le();
    if(dn>kK6DialMaxInitialData){out={};return Kad6Status::TooLarge;} const Byte* dp=r.take(dn);
    if(!r.ok()){out={};return Kad6Status::Truncated;} out.initial_data.assign(dp,dp+dn);
    Kad6Status s=Finish(r,len,consumed); if(s!=Kad6Status::Ok){out={};return s;}
    if(tn==0||!ValidTransport(out.protocol)||out.connect_timeout_ms<kK6DialMinConnectTimeoutMs||
       out.connect_timeout_ms>kK6DialMaxConnectTimeoutMs||out.idle_timeout_ms<kK6DialMinIdleTimeoutMs||
       out.idle_timeout_ms>kK6DialMaxIdleTimeoutMs){out={};return Kad6Status::BadValue;}
    K6TargetTicket t;std::size_t used=0;if(DecodeK6TargetTicket(tp,tn,t,&used)!=Kad6Status::Ok||used!=tn){out={};return Kad6Status::Malformed;}
    return Kad6Status::Ok;
}

Kad6Status EncodeK6DialResult(const K6DialResult& v,std::vector<Byte>& out){
    out.clear();if(!ValidDialStatus(v.status)||!ValidTransport(v.transport)||v.stream_id==0||
       (v.flags&0xfff0u)!=0)return Kad6Status::BadValue;
    std::vector<Byte>a,b;if(EncodeK6Endpoint(v.apparent_local_endpoint,a)!=Kad6Status::Ok||
       EncodeK6Endpoint(v.remote_endpoint,b)!=Kad6Status::Ok)return Kad6Status::BadValue;
    ByteWriter w(out);w.u64le(v.stream_id);w.u8(static_cast<Byte>(v.status));w.u8(static_cast<Byte>(v.transport));
    w.u16le(v.flags);w.bytes(a.data(),a.size());w.bytes(b.data(),b.size());w.u64le(v.max_bytes);w.u32le(v.idle_timeout_ms);return Kad6Status::Ok;
}

Kad6Status DecodeK6DialResult(const Byte*in,std::size_t len,K6DialResult&out,std::size_t*consumed)noexcept{
    out=K6DialResult{};if(consumed)*consumed=0;if(!in&&len)return Kad6Status::NullArgument;ByteReader r(in,len);
    out.stream_id=r.u64le();out.status=static_cast<K6DialStatus>(r.u8());out.transport=static_cast<K6GatewayTransport>(r.u8());out.flags=r.u16le();
    if(!r.ok())return Kad6Status::Truncated;std::size_t n=0;Kad6Status s=DecodeK6Endpoint(in+r.pos(),r.remaining(),out.apparent_local_endpoint,&n);
    if(s!=Kad6Status::Ok){out={};return s;}r.take(n);s=DecodeK6Endpoint(in+r.pos(),r.remaining(),out.remote_endpoint,&n);
    if(s!=Kad6Status::Ok){out={};return s;}r.take(n);out.max_bytes=r.u64le();out.idle_timeout_ms=r.u32le();s=Finish(r,len,consumed);
    if(s!=Kad6Status::Ok){out={};return s;}if(out.stream_id==0||!ValidDialStatus(out.status)||!ValidTransport(out.transport)||(out.flags&0xfff0u)!=0){out={};return Kad6Status::BadValue;}return Kad6Status::Ok;
}

Kad6Status EncodeK6StreamData(const K6StreamData&v,std::vector<Byte>&out){out.clear();if(v.stream_id==0||v.direction>1||(v.flags&0xf8u)||v.data.size()>kK6StreamMaxFrameData)return Kad6Status::BadValue;ByteWriter w(out);w.u64le(v.stream_id);w.u64le(v.sequence);w.u8(v.direction);w.u8(v.flags);w.u16le(0);w.u32le(static_cast<std::uint32_t>(v.data.size()));w.bytes(v.data.data(),v.data.size());return Kad6Status::Ok;}
Kad6Status DecodeK6StreamData(const Byte*in,std::size_t len,K6StreamData&out,std::size_t*consumed)noexcept{out={};if(consumed)*consumed=0;if(!in&&len)return Kad6Status::NullArgument;ByteReader r(in,len);out.stream_id=r.u64le();out.sequence=r.u64le();out.direction=r.u8();out.flags=r.u8();const auto z=r.u16le();const auto n=r.u32le();if(n>kK6StreamMaxFrameData){out={};return Kad6Status::TooLarge;}const Byte*p=r.take(n);if(!r.ok()){out={};return Kad6Status::Truncated;}out.data.assign(p,p+n);Kad6Status s=Finish(r,len,consumed);if(s!=Kad6Status::Ok){out={};return s;}if(out.stream_id==0||out.direction>1||(out.flags&0xf8u)||z){out={};return Kad6Status::Malformed;}return Kad6Status::Ok;}
Kad6Status EncodeK6StreamHalfClose(const K6StreamHalfClose&v,std::vector<Byte>&out){out.clear();if(v.stream_id==0||v.direction>1)return Kad6Status::BadValue;ByteWriter w(out);w.u64le(v.stream_id);w.u8(v.direction);w.u8(v.reason);w.u16le(0);w.u64le(v.last_sequence);return Kad6Status::Ok;}
Kad6Status DecodeK6StreamHalfClose(const Byte*in,std::size_t len,K6StreamHalfClose&out,std::size_t*consumed)noexcept{out={};if(consumed)*consumed=0;if(!in&&len)return Kad6Status::NullArgument;ByteReader r(in,len);out.stream_id=r.u64le();out.direction=r.u8();out.reason=r.u8();const auto z=r.u16le();out.last_sequence=r.u64le();Kad6Status s=Finish(r,len,consumed);if(s!=Kad6Status::Ok){out={};return s;}if(!out.stream_id||out.direction>1||z){out={};return Kad6Status::Malformed;}return Kad6Status::Ok;}
Kad6Status EncodeK6StreamClose(const K6StreamClose&v,std::vector<Byte>&out){out.clear();if(v.stream_id==0)return Kad6Status::BadValue;ByteWriter w(out);w.u64le(v.stream_id);w.u16le(v.reason_code);w.u16le(v.flags);w.u64le(v.last_tx_sequence);w.u64le(v.last_rx_sequence);w.u64le(v.total_tx_bytes);w.u64le(v.total_rx_bytes);return Kad6Status::Ok;}
Kad6Status DecodeK6StreamClose(const Byte*in,std::size_t len,K6StreamClose&out,std::size_t*consumed)noexcept{out={};if(consumed)*consumed=0;if(!in&&len)return Kad6Status::NullArgument;ByteReader r(in,len);out.stream_id=r.u64le();out.reason_code=r.u16le();out.flags=r.u16le();out.last_tx_sequence=r.u64le();out.last_rx_sequence=r.u64le();out.total_tx_bytes=r.u64le();out.total_rx_bytes=r.u64le();Kad6Status s=Finish(r,len,consumed);if(s!=Kad6Status::Ok){out={};return s;}if(!out.stream_id){out={};return Kad6Status::BadValue;}return Kad6Status::Ok;}

Kad6Status EncodeK6MaxStreamData(const K6MaxStreamData& v, std::vector<Byte>& out) {
    out.clear();
    if (v.stream_id == 0 || v.direction > 1 || v.absolute_offset == 0)
        return Kad6Status::BadValue;
    ByteWriter w(out); w.u64le(v.stream_id); w.u8(v.direction); w.u8(0); w.u16le(0);
    w.u64le(v.absolute_offset); return Kad6Status::Ok;
}
Kad6Status DecodeK6MaxStreamData(const Byte* in, std::size_t len,
        K6MaxStreamData& out, std::size_t* consumed) noexcept {
    out = {}; if (consumed) *consumed = 0; if (!in && len) return Kad6Status::NullArgument;
    ByteReader r(in, len); out.stream_id = r.u64le(); out.direction = r.u8();
    const Byte z8 = r.u8(); const std::uint16_t z16 = r.u16le();
    out.absolute_offset = r.u64le();
    const Kad6Status status = Finish(r, len, consumed);
    if (status != Kad6Status::Ok) { out = {}; return status; }
    if (!out.stream_id || out.direction > 1 || !out.absolute_offset || z8 || z16) {
        out = {}; return Kad6Status::Malformed;
    }
    return Kad6Status::Ok;
}
Kad6Status EncodeK6MaxData(const K6MaxData& v, std::vector<Byte>& out) {
    out.clear();
    if (v.direction > 1 || v.absolute_offset == 0) return Kad6Status::BadValue;
    ByteWriter w(out); w.u8(v.direction); w.u8(0); w.u16le(0);
    w.u64le(v.absolute_offset); return Kad6Status::Ok;
}
Kad6Status DecodeK6MaxData(const Byte* in, std::size_t len, K6MaxData& out,
        std::size_t* consumed) noexcept {
    out = {}; if (consumed) *consumed = 0; if (!in && len) return Kad6Status::NullArgument;
    ByteReader r(in, len); out.direction = r.u8(); const Byte z8 = r.u8();
    const std::uint16_t z16 = r.u16le(); out.absolute_offset = r.u64le();
    const Kad6Status status = Finish(r, len, consumed);
    if (status != Kad6Status::Ok) { out = {}; return status; }
    if (out.direction > 1 || !out.absolute_offset || z8 || z16) {
        out = {}; return Kad6Status::Malformed;
    }
    return Kad6Status::Ok;
}

Kad6Status K6StreamFlowState::CanAccept(const K6StreamData&d)const noexcept{return CanAcceptFrame(d.direction,d.sequence,d.data.size());}
Kad6Status K6StreamFlowState::CanAcceptFrame(Byte direction,std::uint64_t sequence,std::size_t dataBytes)const noexcept{if(closed_||direction>1||sequence!=next_[direction]||half_[direction])return Kad6Status::StaleEpoch;if(next_[direction]==(std::numeric_limits<std::uint64_t>::max)()||dataBytes>kK6StreamMaxFrameData||AddOverflows(total_[direction],dataBytes)||AddOverflows(total_[0],total_[1])||AddOverflows(total_[0]+total_[1],dataBytes))return Kad6Status::TooLarge;if(max_bytes_&&total_[0]+total_[1]+dataBytes>max_bytes_)return Kad6Status::TooLarge;return Kad6Status::Ok;}
Kad6Status K6StreamFlowState::Accept(const K6StreamData&d)noexcept{return AcceptFrame(d.direction,d.sequence,d.data.size());}
Kad6Status K6StreamFlowState::AcceptFrame(Byte direction,std::uint64_t sequence,std::size_t dataBytes)noexcept{const Kad6Status status=CanAcceptFrame(direction,sequence,dataBytes);if(status!=Kad6Status::Ok)return status;total_[direction]+=dataBytes;++next_[direction];return Kad6Status::Ok;}
Kad6Status K6StreamFlowState::HalfClose(const K6StreamHalfClose&c)noexcept{if(closed_||c.direction>1||half_[c.direction]||c.last_sequence!=(next_[c.direction]?next_[c.direction]-1:0))return Kad6Status::StaleEpoch;half_[c.direction]=true;return Kad6Status::Ok;}
Kad6Status K6StreamFlowState::Close(const K6StreamClose&c)noexcept{if(closed_)return Kad6Status::StaleEpoch;if(c.last_tx_sequence!=(next_[0]?next_[0]-1:0)||c.last_rx_sequence!=(next_[1]?next_[1]-1:0)||c.total_tx_bytes!=total_[0]||c.total_rx_bytes!=total_[1])return Kad6Status::BadValue;closed_=true;return Kad6Status::Ok;}
std::uint64_t K6StreamFlowState::next_sequence(Byte d)const noexcept{return d<2?next_[d]:0;}
std::uint64_t K6StreamFlowState::total_bytes(Byte d)const noexcept{return d<2?total_[d]:0;}
bool K6StreamFlowState::half_closed(Byte d)const noexcept{return d<2?half_[d]:true;}

Kad6Status K6SendCreditLedger::RegisterStream(std::uint64_t streamId) {
    if (!streamId || streams_.find(streamId) != streams_.end())
        return Kad6Status::BadValue;
    streams_.emplace(streamId, StreamState{});
    return Kad6Status::Ok;
}
void K6SendCreditLedger::RemoveStream(std::uint64_t streamId) { streams_.erase(streamId); }
Kad6Status K6SendCreditLedger::Grant(const K6MaxStreamData& credit) noexcept {
    if (!credit.stream_id || credit.direction > 1 || !credit.absolute_offset)
        return Kad6Status::BadValue;
    auto stream = streams_.find(credit.stream_id);
    if (stream == streams_.end()) return Kad6Status::BadValue;
    const Byte d = credit.direction;
    if (credit.absolute_offset < stream->second.limit[d] ||
        credit.absolute_offset < stream->second.sent[d])
        return Kad6Status::StaleEpoch;
    stream->second.limit[d] = credit.absolute_offset;
    return Kad6Status::Ok;
}
Kad6Status K6SendCreditLedger::Grant(const K6MaxData& credit) noexcept {
    if (credit.direction > 1 || !credit.absolute_offset) return Kad6Status::BadValue;
    const Byte d = credit.direction;
    if (credit.absolute_offset < circuit_limit_[d] ||
        credit.absolute_offset < circuit_sent_[d])
        return Kad6Status::StaleEpoch;
    circuit_limit_[d] = credit.absolute_offset;
    return Kad6Status::Ok;
}
std::uint64_t K6SendCreditLedger::Available(std::uint64_t streamId, Byte direction,
        std::uint64_t ticketRemaining, std::uint64_t schedulerCredit,
        std::uint64_t queueHeadroom) const noexcept {
    if (direction > 1) return 0;
    const auto stream = streams_.find(streamId);
    if (stream == streams_.end() || stream->second.sent[direction] >
            stream->second.limit[direction] || circuit_sent_[direction] >
            circuit_limit_[direction]) return 0;
    const std::uint64_t streamCredit = stream->second.limit[direction] -
        stream->second.sent[direction];
    const std::uint64_t circuitCredit = circuit_limit_[direction] -
        circuit_sent_[direction];
    return (std::min)((std::min)((std::min)(streamCredit, circuitCredit),
        (std::min)(ticketRemaining, schedulerCredit)), queueHeadroom);
}
Kad6Status K6SendCreditLedger::CommitSend(std::uint64_t streamId, Byte direction,
        std::uint64_t bytes, std::uint64_t ticketRemaining,
        std::uint64_t schedulerCredit, std::uint64_t queueHeadroom) noexcept {
    if (!bytes || direction > 1) return Kad6Status::BadValue;
    if (Available(streamId, direction, ticketRemaining, schedulerCredit,
            queueHeadroom) < bytes) return Kad6Status::TooLarge;
    StreamState& stream = streams_.find(streamId)->second;
    stream.sent[direction] += bytes;
    circuit_sent_[direction] += bytes;
    return Kad6Status::Ok;
}
std::uint64_t K6SendCreditLedger::stream_sent(std::uint64_t streamId,
        Byte direction) const noexcept {
    const auto stream = streams_.find(streamId);
    return direction < 2 && stream != streams_.end() ? stream->second.sent[direction] : 0;
}
std::uint64_t K6SendCreditLedger::circuit_sent(Byte direction) const noexcept {
    return direction < 2 ? circuit_sent_[direction] : 0;
}

K6ReceiveCreditWindow::K6ReceiveCreditWindow(std::uint64_t streamWindow,
        std::uint64_t circuitWindow, std::uint64_t maxBuffered)
    : stream_window_(streamWindow), circuit_window_(circuitWindow),
      max_buffered_(maxBuffered) {
    circuit_advertised_[0] = circuitWindow;
    circuit_advertised_[1] = circuitWindow;
}
Kad6Status K6ReceiveCreditWindow::RegisterStream(std::uint64_t streamId) {
    if (!streamId || !stream_window_ || !circuit_window_ || !max_buffered_ ||
        streams_.find(streamId) != streams_.end()) return Kad6Status::BadValue;
    StreamState state;
    state.advertised[0] = stream_window_; state.advertised[1] = stream_window_;
    streams_.emplace(streamId, state);
    return Kad6Status::Ok;
}
void K6ReceiveCreditWindow::RemoveStream(std::uint64_t streamId) {
    const auto stream = streams_.find(streamId);
    if (stream == streams_.end()) return;
    for (Byte direction = 0; direction < 2; ++direction) {
        const std::uint64_t pending = stream->second.received[direction] -
            stream->second.consumed[direction];
        buffered_bytes_ -= (std::min)(buffered_bytes_, pending);
    }
    streams_.erase(stream);
    UpdateWatermark(0);
}
Kad6Status K6ReceiveCreditWindow::InitialCredit(std::uint64_t streamId, Byte direction,
        K6MaxStreamData& streamCredit, K6MaxData& circuitCredit) const noexcept {
    const auto stream = streams_.find(streamId);
    if (direction > 1 || stream == streams_.end()) return Kad6Status::BadValue;
    streamCredit.stream_id = streamId; streamCredit.direction = direction;
    streamCredit.absolute_offset = stream->second.advertised[direction];
    circuitCredit.direction = direction;
    circuitCredit.absolute_offset = circuit_advertised_[direction];
    return Kad6Status::Ok;
}
Kad6Status K6ReceiveCreditWindow::CanAccept(std::uint64_t streamId, Byte direction,
        std::uint64_t bytes) const noexcept {
    const auto stream = streams_.find(streamId);
    if (!bytes || direction > 1 || stream == streams_.end()) return Kad6Status::BadValue;
    const StreamState& state = stream->second;
    if (state.received[direction] > state.advertised[direction] ||
        bytes > state.advertised[direction] - state.received[direction] ||
        circuit_received_[direction] > circuit_advertised_[direction] ||
        bytes > circuit_advertised_[direction] - circuit_received_[direction] ||
        buffered_bytes_ > max_buffered_ || bytes > max_buffered_ - buffered_bytes_)
        return Kad6Status::TooLarge;
    return Kad6Status::Ok;
}
Kad6Status K6ReceiveCreditWindow::Accept(std::uint64_t streamId, Byte direction,
        std::uint64_t bytes, std::uint64_t nowMs) noexcept {
    auto stream = streams_.find(streamId);
    const Kad6Status status = CanAccept(streamId, direction, bytes);
    if (status != Kad6Status::Ok) return status;
    StreamState& state = stream->second;
    state.received[direction] += bytes;
    circuit_received_[direction] += bytes;
    buffered_bytes_ += bytes;
    UpdateWatermark(nowMs);
    return Kad6Status::Ok;
}
Kad6Status K6ReceiveCreditWindow::Consume(std::uint64_t streamId, Byte direction,
        std::uint64_t bytes, std::uint64_t nowMs, K6MaxStreamData& streamCredit,
        K6MaxData& circuitCredit) noexcept {
    auto stream = streams_.find(streamId);
    if (!bytes || direction > 1 || stream == streams_.end()) return Kad6Status::BadValue;
    StreamState& state = stream->second;
    if (state.consumed[direction] > state.received[direction] ||
        bytes > state.received[direction] - state.consumed[direction] ||
        circuit_consumed_[direction] > circuit_received_[direction] ||
        bytes > circuit_received_[direction] - circuit_consumed_[direction] ||
        bytes > buffered_bytes_ ||
        state.consumed[direction] > (std::numeric_limits<std::uint64_t>::max)() - bytes ||
        circuit_consumed_[direction] > (std::numeric_limits<std::uint64_t>::max)() - bytes ||
        state.consumed[direction] + bytes >
            (std::numeric_limits<std::uint64_t>::max)() - stream_window_ ||
        circuit_consumed_[direction] + bytes >
            (std::numeric_limits<std::uint64_t>::max)() - circuit_window_)
        return Kad6Status::BadValue;
    state.consumed[direction] += bytes;
    circuit_consumed_[direction] += bytes;
    buffered_bytes_ -= bytes;
    state.advertised[direction] = state.consumed[direction] + stream_window_;
    circuit_advertised_[direction] = circuit_consumed_[direction] + circuit_window_;
    streamCredit.stream_id = streamId; streamCredit.direction = direction;
    streamCredit.absolute_offset = state.advertised[direction];
    circuitCredit.direction = direction;
    circuitCredit.absolute_offset = circuit_advertised_[direction];
    UpdateWatermark(nowMs);
    return Kad6Status::Ok;
}
void K6ReceiveCreditWindow::UpdateWatermark(std::uint64_t nowMs) noexcept {
    const std::uint64_t high = max_buffered_ - max_buffered_ / 4;
    const std::uint64_t low = max_buffered_ / 4;
    if (!reads_paused_ && buffered_bytes_ >= high) {
        reads_paused_ = true; paused_since_ms_ = nowMs;
    } else if (reads_paused_ && buffered_bytes_ <= low) {
        reads_paused_ = false; paused_since_ms_ = 0;
    }
}
bool K6ReceiveCreditWindow::stalled(std::uint64_t nowMs,
        std::uint64_t deadlineMs) const noexcept {
    return reads_paused_ && nowMs >= paused_since_ms_ &&
        nowMs - paused_since_ms_ >= deadlineMs;
}

bool K6GatewayQueueBudget::ReserveData(std::uint64_t bytes) noexcept {
    if (!bytes || data_used_ > data_capacity_ || bytes > data_capacity_ - data_used_)
        return false;
    data_used_ += bytes; return true;
}
bool K6GatewayQueueBudget::ReserveControl(std::uint64_t bytes) noexcept {
    if (!bytes || control_used_ > control_capacity_ ||
        bytes > control_capacity_ - control_used_) return false;
    control_used_ += bytes; return true;
}
void K6GatewayQueueBudget::ReleaseData(std::uint64_t bytes) noexcept {
    data_used_ -= (std::min)(data_used_, bytes);
}
void K6GatewayQueueBudget::ReleaseControl(std::uint64_t bytes) noexcept {
    control_used_ -= (std::min)(control_used_, bytes);
}

} // namespace kad6
