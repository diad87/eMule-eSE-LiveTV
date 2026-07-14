// SPDX-License-Identifier: MIT
//
// libkad6 — kad6_endpoint.cpp: K6EndpointV1 codec (ticket K6-0.6 support piece).
#include "kad6/kad6_endpoint.h"

namespace kad6 {

std::size_t K6EndpointEncodedSize(const K6Endpoint& e) noexcept {
    return Kad6AddressEncodedSize(e.addr) + kK6EndpointTailSize;
}

Kad6Status EncodeK6Endpoint(const K6Endpoint& e, std::vector<Byte>& out) {
    out.clear();
    std::vector<Byte> a;
    const Kad6Status s = EncodeKad6Address(e.addr, a); // validates family
    if (s != Kad6Status::Ok)
        return s;
    ByteWriter w(out);
    w.bytes(a.data(), a.size());
    w.u16le(e.udp_port);
    w.u16le(e.tcp_port);
    w.u16le(e.transport_flags);
    w.u8(e.priority);
    w.u8(e.observed);
    w.u64le(e.valid_until);
    return Kad6Status::Ok;
}

Kad6Status DecodeK6Endpoint(const Byte* in, std::size_t len, K6Endpoint& out,
                            std::size_t* consumed) noexcept {
    out = K6Endpoint{};
    if (consumed)
        *consumed = 0;

    std::size_t addrConsumed = 0;
    const Kad6Status s = DecodeKad6Address(in, len, out.addr, &addrConsumed);
    if (s != Kad6Status::Ok) {
        out = K6Endpoint{};
        return s;
    }

    // The address decoder guarantees addrConsumed <= len on success.
    ByteReader r(in + addrConsumed, len - addrConsumed);
    out.udp_port        = r.u16le();
    out.tcp_port        = r.u16le();
    out.transport_flags = r.u16le();
    out.priority        = r.u8();
    out.observed        = r.u8();
    out.valid_until     = r.u64le();
    if (!r.ok()) {
        out = K6Endpoint{};
        return Kad6Status::Truncated;
    }
    if (consumed)
        *consumed = addrConsumed + kK6EndpointTailSize;
    return Kad6Status::Ok;
}

} // namespace kad6
