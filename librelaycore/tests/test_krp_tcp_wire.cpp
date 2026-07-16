// SPDX-License-Identifier: MIT
#include "relay/krp_tcp_wire.h"

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <vector>

namespace {
std::uint64_t checks = 0;
void Check(bool value, const char* expression, int line) {
    ++checks;
    if (!value) {
        std::cerr << "CHECK failed at line " << line << ": " << expression << '\n';
        std::exit(1);
    }
}
#define CHECK(value) Check((value), #value, __LINE__)

template <typename Decoder, typename Value>
void CheckTruncation(const std::vector<relay::Byte>& wire,
                     Decoder decode, Value& value) {
    for (std::size_t size = 0; size < wire.size(); ++size)
        CHECK(decode(wire.data(), size, value) != relay::RelayStatus::Ok);
}
} // namespace

int main() {
    std::vector<relay::Byte> wire;
    relay::KrpHelloPayload hello;
    hello.node_id.fill(0x11); hello.client_nonce.fill(0x22);
    CHECK(relay::EncodeKrpHello(hello, wire) == relay::RelayStatus::Ok);
    relay::KrpHelloPayload hello_out;
    CHECK(relay::DecodeKrpHello(wire.data(), wire.size(), hello_out) == relay::RelayStatus::Ok);
    CHECK(hello_out.node_id == hello.node_id && hello_out.client_nonce == hello.client_nonce);
    CheckTruncation(wire, relay::DecodeKrpHello, hello_out);

    relay::KrpAuthChallengePayload challenge;
    challenge.relay_id.fill(1); challenge.relay_nonce.fill(2);
    challenge.timestamp = 1234; challenge.settings_hash.fill(3);
    CHECK(relay::EncodeKrpAuthChallenge(challenge, wire) == relay::RelayStatus::Ok);
    relay::KrpAuthChallengePayload challenge_out;
    CHECK(relay::DecodeKrpAuthChallenge(wire.data(), wire.size(), challenge_out) == relay::RelayStatus::Ok);
    CheckTruncation(wire, relay::DecodeKrpAuthChallenge, challenge_out);

    relay::KrpAuthResponsePayload response;
    response.response.node_id.fill(4); response.response.signature.fill(5);
    response.token_proof.fill(6);
    CHECK(relay::EncodeKrpAuthResponsePayload(response, wire) == relay::RelayStatus::Ok);
    relay::KrpAuthResponsePayload response_out;
    CHECK(relay::DecodeKrpAuthResponsePayload(wire.data(), wire.size(), response_out) == relay::RelayStatus::Ok);
    CheckTruncation(wire, relay::DecodeKrpAuthResponsePayload, response_out);

    relay::KrpLeaseGrantedPayload lease;
    lease.session_epoch = 7; lease.lease_id = 8; lease.lease_generation = 9;
    lease.public_ipv4 = {1, 2, 3, 4}; lease.tcp_port = 4662;
    CHECK(relay::EncodeKrpLeaseGranted(lease, wire) == relay::RelayStatus::Ok);
    relay::KrpLeaseGrantedPayload lease_out;
    CHECK(relay::DecodeKrpLeaseGranted(wire.data(), wire.size(), lease_out) == relay::RelayStatus::Ok);
    CHECK(lease_out.tcp_port == 4662 && lease_out.public_ipv4 == lease.public_ipv4);
    CheckTruncation(wire, relay::DecodeKrpLeaseGranted, lease_out);

    relay::KrpServerBindPayload bind;
    bind.session_epoch = 7; bind.route_generation = 1; bind.lease_id = 8;
    bind.lease_generation = 9; bind.flow_id = 11;
    bind.target_family = relay::EprAddressFamily::IPv4;
    bind.target_address[0] = 8; bind.target_address[1] = 8;
    bind.target_address[2] = 8; bind.target_address[3] = 8; bind.target_port = 4661;
    CHECK(relay::EncodeKrpServerBind(bind, wire) == relay::RelayStatus::Ok);
    relay::KrpServerBindPayload bind_out;
    CHECK(relay::DecodeKrpServerBind(wire.data(), wire.size(), bind_out) == relay::RelayStatus::Ok);
    CHECK(bind_out.flow_id == bind.flow_id && bind_out.target_address == bind.target_address);
    CheckTruncation(wire, relay::DecodeKrpServerBind, bind_out);
    bind.target_address[15] = 1;
    CHECK(relay::EncodeKrpServerBind(bind, wire) == relay::RelayStatus::InvalidArgument);

    std::uint64_t state = 0xA5A5A5A55A5A5A5Aull;
    for (std::uint64_t sequence = 0; sequence < 10000; ++sequence) {
        state ^= state << 13; state ^= state >> 7; state ^= state << 17;
        relay::KrpFlowDataPayload data;
        data.flow_id = 12; data.sequence = sequence;
        const std::size_t size = static_cast<std::size_t>(state % 4096u) + 1;
        data.bytes.resize(size);
        for (std::size_t i = 0; i < size; ++i)
            data.bytes[i] = static_cast<relay::Byte>(state + i);
        CHECK(relay::EncodeKrpFlowData(data, wire) == relay::RelayStatus::Ok);
        relay::KrpFlowDataPayload decoded;
        CHECK(relay::DecodeKrpFlowData(wire.data(), wire.size(), decoded) == relay::RelayStatus::Ok);
        CHECK(decoded.flow_id == data.flow_id && decoded.sequence == sequence && decoded.bytes == data.bytes);
    }
    relay::KrpFlowDataPayload oversized;
    oversized.flow_id = 1; oversized.bytes.resize(relay::kKrpMaxFlowDataBytes + 1);
    CHECK(relay::EncodeKrpFlowData(oversized, wire) == relay::RelayStatus::InvalidArgument);

    for (std::uint64_t type = 0; type <= 0x61; ++type) {
        const bool expected = type == 0x0A || type == 0x26 ||
            (type >= 0x40 && type <= 0x47) || type == 0x52;
        if (expected) CHECK(relay::IsReservedKrpMessageType(type));
    }
    std::cout << "test_krp_tcp_wire: " << checks
              << " passed, 10000 bounded data round trips\n";
    return 0;
}
