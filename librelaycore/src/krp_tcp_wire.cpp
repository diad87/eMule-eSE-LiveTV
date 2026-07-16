// SPDX-License-Identifier: MIT
#include "relay/krp_tcp_wire.h"

#include "relay/relay_bytes.h"

#include <algorithm>
#include <limits>

namespace relay {
namespace {

template <typename Array>
RelayStatus WriteArray(RelayByteWriter& writer, const Array& value) {
    return writer.WriteBytes(value.data(), value.size());
}

template <typename Array>
RelayStatus ReadArray(RelayByteReader& reader, Array& value) noexcept {
    const Byte* const bytes = reader.Take(value.size());
    if (bytes == nullptr)
        return reader.status();
    std::copy(bytes, bytes + value.size(), value.begin());
    return RelayStatus::Ok;
}

RelayStatus Finish(RelayByteReader& reader) noexcept {
    return reader.status() == RelayStatus::Ok && reader.remaining() == 0
        ? RelayStatus::Ok : (reader.status() == RelayStatus::Ok
            ? RelayStatus::Malformed : reader.status());
}

RelayStatus WriteU16(RelayByteWriter& writer, std::uint16_t value) {
    writer.WriteVarint(value);
    return RelayStatus::Ok;
}

RelayStatus ReadU16(RelayByteReader& reader, std::uint16_t& value) noexcept {
    std::uint64_t parsed = 0;
    const RelayStatus status = reader.ReadVarint(parsed);
    if (status != RelayStatus::Ok)
        return status;
    if (parsed > (std::numeric_limits<std::uint16_t>::max)())
        return RelayStatus::Malformed;
    value = static_cast<std::uint16_t>(parsed);
    return RelayStatus::Ok;
}

RelayStatus ReadStatus(RelayByteReader& reader, RelayStatus& value) noexcept {
    Byte raw = 0;
    const RelayStatus status = reader.ReadByte(raw);
    if (status != RelayStatus::Ok)
        return status;
    if (raw > static_cast<Byte>(RelayStatus::Expired))
        return RelayStatus::Malformed;
    value = static_cast<RelayStatus>(raw);
    return RelayStatus::Ok;
}

bool ValidAddress(EprAddressFamily family, const EprAddressBytes& address) noexcept {
    if (family != EprAddressFamily::IPv4 && family != EprAddressFamily::IPv6)
        return false;
    if (family == EprAddressFamily::IPv4) {
        for (std::size_t index = 4; index < address.size(); ++index) {
            if (address[index] != 0)
                return false;
        }
    }
    return true;
}

} // namespace

RelayStatus EncodeKrpHello(const KrpHelloPayload& value, std::vector<Byte>& out) {
    if (value.version_major == 0)
        return RelayStatus::InvalidArgument;
    std::vector<Byte> encoded;
    RelayByteWriter writer(encoded);
    WriteU16(writer, value.version_major); WriteU16(writer, value.version_minor);
    WriteArray(writer, value.node_id); WriteArray(writer, value.client_nonce);
    out.swap(encoded); return RelayStatus::Ok;
}

RelayStatus DecodeKrpHello(const Byte* data, std::size_t size, KrpHelloPayload& value) noexcept {
    value = {}; RelayByteReader r(data, size);
    if (ReadU16(r, value.version_major) != RelayStatus::Ok ||
        ReadU16(r, value.version_minor) != RelayStatus::Ok ||
        ReadArray(r, value.node_id) != RelayStatus::Ok ||
        ReadArray(r, value.client_nonce) != RelayStatus::Ok)
        return r.status() == RelayStatus::Ok ? RelayStatus::Malformed : r.status();
    return Finish(r);
}

RelayStatus EncodeKrpAuthChallenge(const KrpAuthChallengePayload& value, std::vector<Byte>& out) {
    if (value.timestamp == 0) return RelayStatus::InvalidArgument;
    std::vector<Byte> e; RelayByteWriter w(e); WriteArray(w, value.relay_id);
    WriteArray(w, value.relay_nonce); w.WriteVarint(value.timestamp); WriteArray(w, value.settings_hash);
    out.swap(e); return RelayStatus::Ok;
}

RelayStatus DecodeKrpAuthChallenge(const Byte* data, std::size_t size, KrpAuthChallengePayload& value) noexcept {
    value = {}; RelayByteReader r(data, size);
    if (ReadArray(r, value.relay_id) != RelayStatus::Ok || ReadArray(r, value.relay_nonce) != RelayStatus::Ok ||
        r.ReadVarint(value.timestamp) != RelayStatus::Ok || ReadArray(r, value.settings_hash) != RelayStatus::Ok)
        return r.status();
    return Finish(r);
}

RelayStatus EncodeKrpAuthResponsePayload(const KrpAuthResponsePayload& value, std::vector<Byte>& out) {
    std::vector<Byte> e; RelayByteWriter w(e); WriteArray(w, value.response.node_id);
    WriteArray(w, value.response.signature); WriteArray(w, value.token_proof); out.swap(e); return RelayStatus::Ok;
}

RelayStatus DecodeKrpAuthResponsePayload(const Byte* data, std::size_t size, KrpAuthResponsePayload& value) noexcept {
    value = {}; RelayByteReader r(data, size);
    if (ReadArray(r, value.response.node_id) != RelayStatus::Ok ||
        ReadArray(r, value.response.signature) != RelayStatus::Ok || ReadArray(r, value.token_proof) != RelayStatus::Ok)
        return r.status();
    return Finish(r);
}

RelayStatus EncodeKrpAuthOk(const KrpAuthOkPayload& value, std::vector<Byte>& out) {
    if (value.session_epoch == 0 || value.route_generation == 0) return RelayStatus::InvalidArgument;
    std::vector<Byte> e; RelayByteWriter w(e); WriteArray(w, value.session_id);
    w.WriteVarint(value.session_epoch); w.WriteVarint(value.route_generation); out.swap(e); return RelayStatus::Ok;
}

RelayStatus DecodeKrpAuthOk(const Byte* data, std::size_t size, KrpAuthOkPayload& value) noexcept {
    value = {}; RelayByteReader r(data, size);
    if (ReadArray(r, value.session_id) != RelayStatus::Ok || r.ReadVarint(value.session_epoch) != RelayStatus::Ok ||
        r.ReadVarint(value.route_generation) != RelayStatus::Ok) return r.status();
    return Finish(r);
}

RelayStatus EncodeKrpLeaseRequest(const KrpLeaseRequestPayload& value, std::vector<Byte>& out) {
    if (value.session_epoch == 0 || value.requested_lease_id == 0) return RelayStatus::InvalidArgument;
    std::vector<Byte> e; RelayByteWriter w(e); w.WriteVarint(value.session_epoch);
    w.WriteVarint(value.requested_lease_id); out.swap(e); return RelayStatus::Ok;
}

RelayStatus DecodeKrpLeaseRequest(const Byte* data, std::size_t size, KrpLeaseRequestPayload& value) noexcept {
    value = {}; RelayByteReader r(data, size);
    if (r.ReadVarint(value.session_epoch) != RelayStatus::Ok || r.ReadVarint(value.requested_lease_id) != RelayStatus::Ok)
        return r.status();
    return Finish(r);
}

RelayStatus EncodeKrpLeaseGranted(const KrpLeaseGrantedPayload& value, std::vector<Byte>& out) {
    if (value.session_epoch == 0 || value.lease_id == 0 || value.lease_generation == 0 || value.tcp_port == 0)
        return RelayStatus::InvalidArgument;
    std::vector<Byte> e; RelayByteWriter w(e); w.WriteVarint(value.session_epoch); w.WriteVarint(value.lease_id);
    w.WriteVarint(value.lease_generation); WriteArray(w, value.public_ipv4); WriteU16(w, value.tcp_port);
    out.swap(e); return RelayStatus::Ok;
}

RelayStatus DecodeKrpLeaseGranted(const Byte* data, std::size_t size, KrpLeaseGrantedPayload& value) noexcept {
    value = {}; RelayByteReader r(data, size);
    if (r.ReadVarint(value.session_epoch) != RelayStatus::Ok || r.ReadVarint(value.lease_id) != RelayStatus::Ok ||
        r.ReadVarint(value.lease_generation) != RelayStatus::Ok || ReadArray(r, value.public_ipv4) != RelayStatus::Ok ||
        ReadU16(r, value.tcp_port) != RelayStatus::Ok) return r.status() == RelayStatus::Ok ? RelayStatus::Malformed : r.status();
    return Finish(r);
}

RelayStatus EncodeKrpServerBind(const KrpServerBindPayload& value, std::vector<Byte>& out) {
    if (value.session_epoch == 0 || value.route_generation == 0 || value.lease_id == 0 ||
        value.lease_generation == 0 || value.flow_id == 0 || value.target_port == 0 ||
        !ValidAddress(value.target_family, value.target_address)) return RelayStatus::InvalidArgument;
    std::vector<Byte> e; RelayByteWriter w(e); w.WriteVarint(value.session_epoch); w.WriteVarint(value.route_generation);
    w.WriteVarint(value.lease_id); w.WriteVarint(value.lease_generation); w.WriteVarint(value.flow_id);
    w.WriteByte(static_cast<Byte>(value.target_family)); WriteArray(w, value.target_address); WriteU16(w, value.target_port);
    out.swap(e); return RelayStatus::Ok;
}

RelayStatus DecodeKrpServerBind(const Byte* data, std::size_t size, KrpServerBindPayload& value) noexcept {
    value = {}; RelayByteReader r(data, size); Byte family = 0;
    if (r.ReadVarint(value.session_epoch) != RelayStatus::Ok || r.ReadVarint(value.route_generation) != RelayStatus::Ok ||
        r.ReadVarint(value.lease_id) != RelayStatus::Ok || r.ReadVarint(value.lease_generation) != RelayStatus::Ok ||
        r.ReadVarint(value.flow_id) != RelayStatus::Ok || r.ReadByte(family) != RelayStatus::Ok ||
        ReadArray(r, value.target_address) != RelayStatus::Ok || ReadU16(r, value.target_port) != RelayStatus::Ok)
        return r.status() == RelayStatus::Ok ? RelayStatus::Malformed : r.status();
    value.target_family = static_cast<EprAddressFamily>(family);
    return ValidAddress(value.target_family, value.target_address) ? Finish(r) : RelayStatus::Malformed;
}

RelayStatus EncodeKrpServerStatus(const KrpServerStatusPayload& value, std::vector<Byte>& out) {
    if (value.flow_id == 0) return RelayStatus::InvalidArgument;
    std::vector<Byte> e; RelayByteWriter w(e); w.WriteVarint(value.flow_id); w.WriteByte(static_cast<Byte>(value.status));
    out.swap(e); return RelayStatus::Ok;
}

RelayStatus DecodeKrpServerStatus(const Byte* data, std::size_t size, KrpServerStatusPayload& value) noexcept {
    value = {}; RelayByteReader r(data, size);
    if (r.ReadVarint(value.flow_id) != RelayStatus::Ok || ReadStatus(r, value.status) != RelayStatus::Ok)
        return r.status() == RelayStatus::Ok ? RelayStatus::Malformed : r.status();
    return Finish(r);
}

RelayStatus EncodeKrpFlowOpen(const KrpFlowOpenPayload& value, std::vector<Byte>& out) {
    if (value.session_epoch == 0 || value.route_generation == 0 || value.lease_id == 0 ||
        value.lease_generation == 0 || value.flow_id == 0 || value.remote_port == 0 ||
        value.kind != KrpClassicFlowKind::LegacyTcpInbound || !ValidAddress(value.remote_family, value.remote_address))
        return RelayStatus::InvalidArgument;
    std::vector<Byte> e; RelayByteWriter w(e); w.WriteVarint(value.session_epoch); w.WriteVarint(value.route_generation);
    w.WriteVarint(value.lease_id); w.WriteVarint(value.lease_generation); w.WriteVarint(value.flow_id);
    w.WriteByte(static_cast<Byte>(value.kind)); w.WriteByte(static_cast<Byte>(value.remote_family));
    WriteArray(w, value.remote_address); WriteU16(w, value.remote_port); out.swap(e); return RelayStatus::Ok;
}

RelayStatus DecodeKrpFlowOpen(const Byte* data, std::size_t size, KrpFlowOpenPayload& value) noexcept {
    value = {}; RelayByteReader r(data, size); Byte kind = 0, family = 0;
    if (r.ReadVarint(value.session_epoch) != RelayStatus::Ok || r.ReadVarint(value.route_generation) != RelayStatus::Ok ||
        r.ReadVarint(value.lease_id) != RelayStatus::Ok || r.ReadVarint(value.lease_generation) != RelayStatus::Ok ||
        r.ReadVarint(value.flow_id) != RelayStatus::Ok || r.ReadByte(kind) != RelayStatus::Ok || r.ReadByte(family) != RelayStatus::Ok ||
        ReadArray(r, value.remote_address) != RelayStatus::Ok || ReadU16(r, value.remote_port) != RelayStatus::Ok)
        return r.status() == RelayStatus::Ok ? RelayStatus::Malformed : r.status();
    value.kind = static_cast<KrpClassicFlowKind>(kind); value.remote_family = static_cast<EprAddressFamily>(family);
    return value.kind == KrpClassicFlowKind::LegacyTcpInbound && ValidAddress(value.remote_family, value.remote_address)
        ? Finish(r) : RelayStatus::Malformed;
}

RelayStatus EncodeKrpFlowData(const KrpFlowDataPayload& value, std::vector<Byte>& out) {
    if (value.flow_id == 0 || value.bytes.empty() || value.bytes.size() > kKrpMaxFlowDataBytes)
        return RelayStatus::InvalidArgument;
    std::vector<Byte> e; RelayByteWriter w(e); w.WriteVarint(value.flow_id); w.WriteVarint(value.sequence);
    w.WriteBytes(value.bytes.data(), value.bytes.size()); out.swap(e); return RelayStatus::Ok;
}

RelayStatus DecodeKrpFlowData(const Byte* data, std::size_t size, KrpFlowDataPayload& value) {
    value = {}; RelayByteReader r(data, size);
    if (r.ReadVarint(value.flow_id) != RelayStatus::Ok || r.ReadVarint(value.sequence) != RelayStatus::Ok)
        return r.status();
    const std::size_t byte_count = r.remaining();
    if (byte_count == 0 || byte_count > kKrpMaxFlowDataBytes)
        return byte_count == 0 ? RelayStatus::Malformed : RelayStatus::TooLarge;
    const Byte* const bytes = r.Take(byte_count);
    value.bytes.assign(bytes, bytes + byte_count);
    if (value.bytes.empty()) return RelayStatus::Malformed;
    return Finish(r);
}

RelayStatus EncodeKrpFlowTerminal(const KrpFlowTerminalPayload& value, std::vector<Byte>& out) {
    if (value.flow_id == 0) return RelayStatus::InvalidArgument;
    std::vector<Byte> e; RelayByteWriter w(e); w.WriteVarint(value.flow_id); w.WriteByte(static_cast<Byte>(value.reason));
    out.swap(e); return RelayStatus::Ok;
}

RelayStatus DecodeKrpFlowTerminal(const Byte* data, std::size_t size, KrpFlowTerminalPayload& value) noexcept {
    value = {}; RelayByteReader r(data, size);
    if (r.ReadVarint(value.flow_id) != RelayStatus::Ok || ReadStatus(r, value.reason) != RelayStatus::Ok)
        return r.status() == RelayStatus::Ok ? RelayStatus::Malformed : r.status();
    return Finish(r);
}

} // namespace relay
