#!/usr/bin/env python3
"""Wire regression tests for server UDP OP_FOUNDSOURCES_V6."""

import struct
import sys

from test_address_wire import Address, IPV6


OP_EMULEPROT = 0xC5
OP_FOUNDSOURCES_V6 = 0xE2
ENTRY_SIZE = 20


def encode(file_hash, sources):
    if len(file_hash) != 16 or len(sources) > 255:
        raise ValueError("invalid source response")
    out = bytearray([OP_EMULEPROT, OP_FOUNDSOURCES_V6])
    out.extend(file_hash)
    out.append(len(sources))
    for address, port in sources:
        if address.family != IPV6 or not 0 < port <= 0xFFFF:
            raise ValueError("IPv6 address and non-zero uint16 port required")
        out.extend(address.to_wire())
        out.extend(struct.pack("<H", port))
    return bytes(out)


def decode(packet):
    if len(packet) < 19:
        raise ValueError("truncated header")
    if packet[:2] != bytes([OP_EMULEPROT, OP_FOUNDSOURCES_V6]):
        raise ValueError("wrong protocol/opcode")
    file_hash = packet[2:18]
    count = packet[18]
    if len(packet) != 19 + count * ENTRY_SIZE:
        raise ValueError("wrong packet length")
    offset = 19
    sources = []
    for _ in range(count):
        address, consumed = Address.from_wire(packet[offset:])
        if address is None or address.family != IPV6 or consumed != 18:
            raise ValueError("invalid CAddress")
        offset += consumed
        port = struct.unpack_from("<H", packet, offset)[0]
        if port == 0:
            raise ValueError("zero port")
        offset += 2
        sources.append((address, port))
    return file_hash, sources


def test_exact_layout():
    file_hash = bytes(range(16))
    address = Address.v6("2001:4860:4860::8888")
    packet = encode(file_hash, [(address, 4662)])
    expected = (
        b"\xc5\xe2"
        + file_hash
        + b"\x01"
        + b"\x06\x10"
        + bytes.fromhex("20014860486000000000000000008888")
        + b"\x36\x12"
    )
    assert packet == expected


def test_roundtrip_and_count():
    file_hash = b"\xaa" * 16
    original = [
        (Address.v6("2001:4860:4860::8888"), 4662),
        (Address.v6("2606:4700:4700::1111"), 65535),
    ]
    packet = encode(file_hash, original)
    parsed_hash, parsed = decode(packet)
    assert parsed_hash == file_hash
    assert len(parsed) == len(original)
    for (actual_address, actual_port), (wanted_address, wanted_port) in zip(parsed, original):
        assert actual_address.to_wire() == wanted_address.to_wire()
        assert actual_port == wanted_port


def test_empty_response():
    file_hash = b"\x10" * 16
    assert decode(encode(file_hash, [])) == (file_hash, [])


def test_rejects_old_jemule_collision_and_raw_address():
    file_hash = b"\xbb" * 16
    raw_address = bytes.fromhex("20014860486000000000000000008888")
    old_packet = b"\xe3\x9c" + file_hash + b"\x01" + raw_address + b"\x36\x12"
    raw_c5_packet = b"\xc5\xe2" + file_hash + b"\x01" + raw_address + b"\x36\x12"
    for packet in (old_packet, raw_c5_packet):
        try:
            decode(packet)
        except ValueError:
            pass
        else:
            raise AssertionError(f"accepted invalid packet: {packet.hex()}")


def test_rejects_truncation_and_zero_port():
    file_hash = b"\xcc" * 16
    valid = encode(file_hash, [(Address.v6("2001:4860:4860::8888"), 4662)])
    invalid = [
        valid[:-1],
        valid + b"\x00",
        valid[:18],
        valid[:18] + b"\x02" + valid[19:],
        valid[:-2] + b"\x00\x00",
    ]
    for packet in invalid:
        try:
            decode(packet)
        except ValueError:
            pass
        else:
            raise AssertionError(f"accepted invalid packet: {packet.hex()}")


def run():
    tests = [
        ("exact layout", test_exact_layout),
        ("roundtrip and count", test_roundtrip_and_count),
        ("empty response", test_empty_response),
        ("legacy collision/raw address rejected", test_rejects_old_jemule_collision_and_raw_address),
        ("truncation/zero port rejected", test_rejects_truncation_and_zero_port),
    ]
    failures = 0
    for name, test in tests:
        try:
            test()
            print(f"PASS: {name}")
        except Exception as exc:
            failures += 1
            print(f"FAIL: {name}: {exc}")
    print(f"\nTOTAL: {len(tests) - failures}/{len(tests)} passed")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(run())
