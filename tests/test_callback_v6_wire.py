#!/usr/bin/env python3
"""Wire regression tests for the additive OP_CALLBACK_V6 payload."""

import struct
import sys

from test_address_wire import Address, IPV6


OP_CALLBACK_V6 = 0xE1
CHECK_SIZE = 16
FILE_ID_SIZE = 16


def encode(check, file_id, address, port):
    if len(check) != CHECK_SIZE or len(file_id) != FILE_ID_SIZE:
        raise ValueError("hashes must be 16 bytes")
    if address.family != IPV6 or not 0 < port <= 0xFFFF:
        raise ValueError("native IPv6 address and non-zero port required")
    return check + file_id + address.to_wire() + struct.pack("<H", port)


def decode(payload):
    if len(payload) < CHECK_SIZE + FILE_ID_SIZE + 18 + 2:
        raise ValueError("truncated callback")
    check = payload[:CHECK_SIZE]
    file_id = payload[CHECK_SIZE:CHECK_SIZE + FILE_ID_SIZE]
    address, consumed = Address.from_wire(payload[32:])
    if address is None or address.family != IPV6 or consumed != 18:
        raise ValueError("callback endpoint is not a native CAddress")
    offset = 32 + consumed
    port = struct.unpack_from("<H", payload, offset)[0]
    if port == 0 or len(payload) != offset + 2:
        raise ValueError("invalid callback port or trailing data")
    return check, file_id, address, port


def test_layout_and_roundtrip():
    check = bytes(range(16))
    file_id = b"\xA5" * 16
    address = Address.v6("2001:4860:4860::8888")
    payload = encode(check, file_id, address, 4662)
    parsed = decode(payload)
    assert parsed[0] == check
    assert parsed[1] == file_id
    assert parsed[2].to_wire() == address.to_wire()
    assert parsed[3] == 4662


def test_rejects_ipv4_raw_and_zero_port():
    check = b"\x01" * 16
    file_id = b"\x02" * 16
    raw_v4 = b"\x04\x04\x7f\x00\x00\x01"
    for payload in (
        check + file_id + raw_v4 + b"\x36\x12",
        encode(check, file_id, Address.v6("2001:db8::1"), 4662)[:-2] + b"\x00\x00",
        encode(check, file_id, Address.v6("2001:db8::1"), 4662) + b"\x00",
    ):
        try:
            decode(payload)
        except ValueError:
            pass
        else:
            raise AssertionError("accepted invalid callback payload")


def run():
    tests = [
        ("layout and roundtrip", test_layout_and_roundtrip),
        ("IPv4/zero/trailing rejected", test_rejects_ipv4_raw_and_zero_port),
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
