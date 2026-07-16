// SPDX-License-Identifier: MIT
//
// libkad6 — kad6_address.cpp: implementation of the Kad6 address codec
// (ticket K6-0.3). New code, MIT-licensed; see kad6_address.h for the wire
// layout and the three valid (family, addr_len) combinations.
#include "kad6/kad6_address.h"
#include "kad6/kad6_bytes.h"

namespace kad6 {

namespace {

// Maps a Family to its wire address length (0, 4, or 16). Returns false for
// any value that is not one of the three recognized enumerators, leaving
// `lenOut` at 0 so callers can safely use it as a "nothing to do" length.
bool addrLenForFamily(Kad6Address::Family f, std::size_t& lenOut) noexcept {
    switch (f) {
        case Kad6Address::Family::None: lenOut = 0;  return true;
        case Kad6Address::Family::IPv4: lenOut = 4;  return true;
        case Kad6Address::Family::IPv6: lenOut = 16; return true;
    }
    lenOut = 0;
    return false;
}

} // namespace

std::size_t Kad6AddressEncodedSize(const Kad6Address& a) noexcept {
    std::size_t len = 0;
    addrLenForFamily(a.family, len); // unrecognized family: len stays 0 (header-only size)
    return kKad6AddressHeaderSize + len;
}

Kad6Status EncodeKad6Address(const Kad6Address& a, Byte* out, std::size_t cap,
                              std::size_t* written) noexcept {
    if (written != nullptr)
        *written = 0;

    // ── Producer validation (strict) ──────────────────────────────────────
    std::size_t addrLen = 0;
    if (!addrLenForFamily(a.family, addrLen))
        return Kad6Status::Malformed;

    const std::size_t need = kKad6AddressHeaderSize + addrLen;

    if (out == nullptr) {
        // Even the smallest valid address needs 2 bytes, so a null buffer
        // never succeeds here; cap==0 reports "too small", cap>0 with a null
        // pointer is a caller bug. (A true size probe is
        // Kad6AddressEncodedSize, not this call with cap==0.)
        if (cap == 0)
            return Kad6Status::TooLarge;
        return Kad6Status::NullArgument;
    }
    if (cap < need)
        return Kad6Status::TooLarge;

    out[0] = static_cast<Byte>(static_cast<int>(a.family));
    out[1] = static_cast<Byte>(addrLen);
    for (std::size_t i = 0; i < addrLen; ++i)
        out[kKad6AddressHeaderSize + i] = a.addr[i];

    if (written != nullptr)
        *written = need;
    return Kad6Status::Ok;
}

Kad6Status EncodeKad6Address(const Kad6Address& a, std::vector<Byte>& out) {
    out.clear();

    std::size_t addrLen = 0;
    if (!addrLenForFamily(a.family, addrLen))
        return Kad6Status::Malformed;

    const std::size_t need = kKad6AddressHeaderSize + addrLen;
    out.resize(need);
    std::size_t written = 0;
    const Kad6Status st = EncodeKad6Address(a, out.data(), out.size(), &written);
    if (st != Kad6Status::Ok)
        out.clear();
    return st;
}

Kad6Status DecodeKad6Address(const Byte* in, std::size_t len, Kad6Address& out,
                              std::size_t* consumed) noexcept {
    if (consumed != nullptr)
        *consumed = 0;
    out = Kad6Address{};

    ByteReader r(in, len);
    if (r.null_arg())
        return Kad6Status::NullArgument;

    const Byte familyByte = r.u8();
    const Byte addrLenByte = r.u8();
    if (!r.ok())
        return Kad6Status::Truncated; // fewer than the 2 header bytes present

    // Validate the (family, addr_len) pair BEFORE reading any address bytes:
    // reject a structurally bad header before touching more of the buffer.
    Kad6Address::Family fam;
    std::size_t expectAddrLen;
    switch (familyByte) {
        case 0: fam = Kad6Address::Family::None; expectAddrLen = 0;  break;
        case 4: fam = Kad6Address::Family::IPv4; expectAddrLen = 4;  break;
        case 6: fam = Kad6Address::Family::IPv6; expectAddrLen = 16; break;
        default:
            return Kad6Status::Malformed;
    }
    if (addrLenByte != expectAddrLen)
        return Kad6Status::Malformed;

    Byte addrBuf[16] = {};
    if (expectAddrLen != 0 && !r.bytes(addrBuf, expectAddrLen))
        return Kad6Status::Truncated; // header promised addrLen bytes; buffer too short

    out.family = fam;
    out.addr.fill(0);
    for (std::size_t i = 0; i < expectAddrLen; ++i)
        out.addr[i] = addrBuf[i];

    if (consumed != nullptr)
        *consumed = r.pos(); // 2, 6, or 18
    return Kad6Status::Ok;
}

void Kad6AddressNormalize(Kad6Address& a) noexcept {
    if (a.family == Kad6Address::Family::IPv6) {
        // IPv4-mapped IPv6: ::ffff:a.b.c.d -> first 10 bytes 0, bytes 10-11
        // = 0xFF 0xFF, trailing 4 bytes are the IPv4 address.
        bool mapped = (a.addr[10] == 0xFF && a.addr[11] == 0xFF);
        for (std::size_t i = 0; mapped && i < 10; ++i)
            if (a.addr[i] != 0)
                mapped = false;
        if (mapped) {
            const Byte v4[4] = { a.addr[12], a.addr[13], a.addr[14], a.addr[15] };
            a.family = Kad6Address::Family::IPv4;
            a.addr.fill(0);
            a.addr[0] = v4[0];
            a.addr[1] = v4[1];
            a.addr[2] = v4[2];
            a.addr[3] = v4[3];
        }
    }

    // Zero the unused tail for every recognized family so the normalized
    // form is byte-deterministic regardless of what the caller left there.
    // An unrecognized family has no defined normal form; leave it alone.
    std::size_t len = 0;
    if (addrLenForFamily(a.family, len))
        for (std::size_t i = len; i < a.addr.size(); ++i)
            a.addr[i] = 0;
}

Kad6Address Kad6AddressSubnet(const Kad6Address& a, int prefixBits) noexcept {
    Kad6Address r = a;
    Kad6AddressNormalize(r); // fold IPv4-mapped IPv6 to IPv4 before masking

    std::size_t len = 0;
    if (!addrLenForFamily(r.family, len) || len == 0)
        return r; // None, or an unrecognized family: no address bits to mask

    const int maxBits = static_cast<int>(len) * 8;
    int bits = prefixBits;
    if (bits < 0) bits = 0;
    if (bits > maxBits) bits = maxBits;

    for (std::size_t i = 0; i < len; ++i) {
        const int bitPosStart = static_cast<int>(i) * 8;
        if (bitPosStart + 8 <= bits)
            continue; // fully inside the network prefix: keep as-is
        if (bitPosStart >= bits) {
            r.addr[i] = 0; // fully inside the host part: clear
            continue;
        }
        // Straddles the boundary: keep the top `keepBits` bits of this byte.
        const int keepBits = bits - bitPosStart; // 1..7 here
        const Byte mask = static_cast<Byte>(0xFF00u >> keepBits);
        r.addr[i] = static_cast<Byte>(r.addr[i] & mask);
    }
    return r;
}

bool Kad6AddressInSameSubnet(const Kad6Address& a, const Kad6Address& b,
                              int prefixBits) noexcept {
    return Kad6AddressSubnet(a, prefixBits) == Kad6AddressSubnet(b, prefixBits);
}

bool operator==(const Kad6Address& a, const Kad6Address& b) noexcept {
    Kad6Address na = a;
    Kad6Address nb = b;
    Kad6AddressNormalize(na);
    Kad6AddressNormalize(nb);
    if (na.family != nb.family)
        return false;
    std::size_t len = 0;
    if (!addrLenForFamily(na.family, len))
        return false; // invalid/manual families are never valid identity keys
    return Kad6CtEqual(na.addr.data(), nb.addr.data(), len);
}

} // namespace kad6
