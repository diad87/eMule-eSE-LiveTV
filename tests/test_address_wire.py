#!/usr/bin/env python3
# tests/test_address_wire.py — IPv6 Sprint 1 spec regression.
#
# Locks down the CAddress wire format (see docs/IPV6_PLAN.md §5.1) by
# replicating the byte layout, HashKey/subnet/synthetic-uint32 logic in
# Python and asserting against fixed test vectors. The eventual C++ unit
# test (--tool=test-address, planned for Sprint 10 hardening) MUST agree
# with these vectors byte-for-byte; any drift is a regression.
#
# Run: python tests/test_address_wire.py
# Exit 0 = all pass, 1 = at least one mismatch, 2 = tool error.

import struct
import sys


# Family codes match CAddress::EAF in C++.
NONE = 0
IPV4 = 4
IPV6 = 6


def ipv4_bytes(s):
    return bytes(int(x) for x in s.split('.'))


def ipv6_bytes(s):
    # Minimal inet_pton(AF_INET6) — supports `::` elision but not zone ids.
    if '::' in s:
        left, _, right = s.partition('::')
        lparts = left.split(':') if left else []
        rparts = right.split(':') if right else []
        mid = 8 - (len(lparts) + len(rparts))
        parts = lparts + ['0'] * mid + rparts
    else:
        parts = s.split(':')
    if len(parts) != 8:
        raise ValueError(s)
    out = bytearray()
    for p in parts:
        out.extend(struct.pack('>H', int(p, 16) if p else 0))
    return bytes(out)


class Address:
    """Python replica of C++ CAddress for spec validation."""

    def __init__(self, family=NONE, raw=None):
        self.family = family
        if raw is None:
            self.raw = bytearray(16)
        else:
            if family == IPV4 and len(raw) == 4:
                self.raw = bytearray(raw) + bytearray(12)
            elif family == IPV6 and len(raw) == 16:
                self.raw = bytearray(raw)
            elif family == NONE:
                self.raw = bytearray(16)
            else:
                raise ValueError("bad family/raw")

    @classmethod
    def v4(cls, s):
        return cls(IPV4, ipv4_bytes(s))

    @classmethod
    def v6(cls, s):
        return cls(IPV6, ipv6_bytes(s))

    # -------- wire format (matches CAddress::WriteToBuffer / ReadFromBuffer) --
    def to_wire(self):
        if self.family == NONE:
            return bytes([0, 0])
        if self.family == IPV4:
            return bytes([4, 4]) + bytes(self.raw[:4])
        if self.family == IPV6:
            return bytes([6, 16]) + bytes(self.raw[:16])
        raise ValueError(self.family)

    @classmethod
    def from_wire(cls, b):
        if len(b) < 2:
            return None, 0
        fam, length = b[0], b[1]
        if fam == 0 and length == 0:
            return cls(NONE), 2
        if fam == 4 and length == 4 and len(b) >= 6:
            return cls(IPV4, bytes(b[2:6])), 6
        if fam == 6 and length == 16 and len(b) >= 18:
            return cls(IPV6, bytes(b[2:18])), 18
        return None, 0

    # -------- HashKey (matches FNV-1a 32-bit) ---------------------------------
    def hash_key(self):
        h = 2166136261
        h ^= self.family
        h = (h * 16777619) & 0xFFFFFFFF
        for b in self.raw:
            h ^= b
            h = (h * 16777619) & 0xFFFFFFFF
        return h

    # -------- GetSubnet -------------------------------------------------------
    def get_subnet(self, prefix_bits):
        if self.family == NONE or prefix_bits <= 0:
            return Address(self.family)
        max_bits = 32 if self.family == IPV4 else 128
        if prefix_bits >= max_bits:
            return Address(self.family, bytes(self.raw[:4 if self.family == IPV4 else 16]))
        out = Address(self.family, bytes(self.raw[:4 if self.family == IPV4 else 16]))
        byte_count = prefix_bits // 8
        leftover = prefix_bits % 8
        total = 4 if self.family == IPV4 else 16
        if leftover == 0:
            for i in range(byte_count, total):
                out.raw[i] = 0
        else:
            mask = (0xFF << (8 - leftover)) & 0xFF
            out.raw[byte_count] = out.raw[byte_count] & mask
            for i in range(byte_count + 1, total):
                out.raw[i] = 0
        return out

    def in_same_subnet(self, other, prefix_bits):
        if self.family != other.family:
            return False
        if self.family == NONE:
            return True
        return bytes(self.get_subnet(prefix_bits).raw) == bytes(other.get_subnet(prefix_bits).raw)

    # -------- ToSyntheticUInt32 -----------------------------------------------
    def to_synthetic_uint32(self):
        if self.family == IPV4:
            # Same as ToUInt32(bReverse=false): network-order bytes packed.
            return int.from_bytes(self.raw[:4], 'little')
        if self.family == NONE:
            return 0
        h = 2166136261
        for b in self.raw:
            h ^= b
            h = (h * 16777619) & 0xFFFFFFFF
        return (h & 0x00FFFFFF) | 0xFE000000


# ──────────────────────────── tests ────────────────────────────


def test_roundtrip():
    # None / IPv4 / IPv6 all roundtrip through wire.
    cases = [
        Address(NONE),
        Address.v4("0.0.0.0"),
        Address.v4("1.2.3.4"),
        Address.v4("192.168.1.1"),
        Address.v4("255.255.255.255"),
        Address.v6("::"),
        Address.v6("::1"),
        Address.v6("fe80::1"),
        Address.v6("2001:db8::1"),
        Address.v6("2001:db8:1234:5678:90ab:cdef:1234:5678"),
        Address.v6("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
    ]
    for c in cases:
        wire = c.to_wire()
        # Wire lengths per spec.
        expected_len = {NONE: 2, IPV4: 6, IPV6: 18}[c.family]
        assert len(wire) == expected_len, f"wrong len for {c.family}: {len(wire)}"
        back, consumed = Address.from_wire(wire)
        assert consumed == expected_len
        assert back.family == c.family
        assert bytes(back.raw) == bytes(c.raw)


def test_wire_byte_layout():
    # Pin the exact byte layout so a C++ implementation drift is caught.
    # IPv6 = 16 raw bytes. "2001:db8::1" = 20 01 0d b8 + 10 zero bytes + 00 01.
    cases = [
        (Address(NONE),              b'\x00\x00'),
        (Address.v4("1.2.3.4"),      b'\x04\x04\x01\x02\x03\x04'),
        (Address.v4("127.0.0.1"),    b'\x04\x04\x7f\x00\x00\x01'),
        (Address.v6("::1"),          b'\x06\x10' + b'\x00'*15 + b'\x01'),
        (Address.v6("2001:db8::1"),  b'\x06\x10\x20\x01\x0d\xb8' + b'\x00'*10 + b'\x00\x01'),
    ]
    for addr, expected in cases:
        got = addr.to_wire()
        assert got == expected, f"layout mismatch: got={got.hex()} want={expected.hex()}"


def test_malformed_wire():
    # Reader rejects bad combos.
    bad = [
        b'',                            # empty
        b'\x04',                        # truncated prefix
        b'\x04\x04',                    # missing addr bytes
        b'\x04\x04\x01\x02\x03',        # short addr
        b'\x04\x10' + b'\x00'*16,       # v4 with v6 length
        b'\x06\x04' + b'\x00'*4,        # v6 with v4 length
        b'\x07\x04\x01\x02\x03\x04',    # unknown family
        b'\xff\x00',                    # bogus
    ]
    for b in bad:
        addr, consumed = Address.from_wire(b)
        assert addr is None, f"reader accepted bad input: {b.hex()}"


def test_hash_distribution():
    # Same content -> same hash. Different content -> different (high prob).
    a = Address.v4("1.2.3.4")
    b = Address.v4("1.2.3.4")
    c = Address.v4("1.2.3.5")
    d = Address.v6("2001:db8::1")
    assert a.hash_key() == b.hash_key()
    assert a.hash_key() != c.hash_key()
    assert a.hash_key() != d.hash_key()
    # IPv4-mapped-as-v6 should NOT collide with the v4 representation:
    # different family byte feeds into FNV.
    v6mapped = Address.v6("::ffff:1.2.3.4") if False else None  # not testing mapped here
    # Loose distribution check: hash 1000 distinct addresses, expect < 1% collision.
    import random
    random.seed(42)
    seen = set()
    coll = 0
    for _ in range(1000):
        ip = ".".join(str(random.randrange(0, 256)) for _ in range(4))
        h = Address.v4(ip).hash_key()
        if h in seen:
            coll += 1
        seen.add(h)
    assert coll < 10, f"hash distribution poor: {coll}/1000 collisions"


def test_subnet():
    # IPv4 /24
    a = Address.v4("192.168.1.50")
    b = Address.v4("192.168.1.99")
    c = Address.v4("192.168.2.50")
    assert a.in_same_subnet(b, 24)
    assert not a.in_same_subnet(c, 24)
    assert a.in_same_subnet(c, 16)

    # IPv6 /64
    p = Address.v6("2001:db8:1::100")
    q = Address.v6("2001:db8:1::200")
    r = Address.v6("2001:db8:2::100")
    assert p.in_same_subnet(q, 64)
    assert not p.in_same_subnet(r, 64)
    assert p.in_same_subnet(r, 32)

    # GetSubnet zero-fills past prefix
    s = a.get_subnet(24)
    assert bytes(s.raw[:4]) == bytes([192, 168, 1, 0])

    # Cross-family never same subnet
    assert not a.in_same_subnet(p, 24)


def test_synthetic_uint32():
    # IPv4 → preserves the raw uint32 in host order.
    assert Address.v4("1.2.3.4").to_synthetic_uint32() == int.from_bytes(b'\x01\x02\x03\x04', 'little')
    # None → 0
    assert Address(NONE).to_synthetic_uint32() == 0
    # IPv6 → top byte forced to 0xFE
    s1 = Address.v6("2001:db8::1").to_synthetic_uint32()
    s2 = Address.v6("2001:db8::2").to_synthetic_uint32()
    assert (s1 & 0xFF000000) == 0xFE000000
    assert (s2 & 0xFF000000) == 0xFE000000
    assert s1 != s2


def run():
    tests = [
        ("roundtrip", test_roundtrip),
        ("wire byte layout", test_wire_byte_layout),
        ("malformed wire rejected", test_malformed_wire),
        ("hash distribution", test_hash_distribution),
        ("subnet ops", test_subnet),
        ("synthetic uint32", test_synthetic_uint32),
    ]
    fails = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS: {name}")
        except AssertionError as e:
            print(f"FAIL: {name}: {e}")
            fails += 1
        except Exception as e:
            print(f"ERR : {name}: {type(e).__name__}: {e}")
            fails += 1
    print(f"\nTOTAL: {len(tests)-fails}/{len(tests)} passed")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(run())
