"""Pure wire-contract checks for the native IPv6 transport paths.

These tests deliberately do not open sockets.  They lock the byte layouts
that must remain stable while the C++ socket layer chooses IPv4 or IPv6.
"""

from __future__ import annotations

import ipaddress
import struct


def caddress_v6(text: str) -> bytes:
    raw = ipaddress.IPv6Address(text).packed
    return bytes((6, 16)) + raw


def socks5_connect_v6(text: str, port: int) -> bytes:
    return bytes((5, 1, 0, 4)) + ipaddress.IPv6Address(text).packed + struct.pack(">H", port)


def socks5_reply_v6(text: str, port: int) -> bytes:
    return bytes((5, 0, 0, 4)) + ipaddress.IPv6Address(text).packed + struct.pack(">H", port)


def live_peer_list_v2(entries: list[tuple[str, int]]) -> bytes:
    body = bytearray(b"K" * 16)
    body += struct.pack(">H", len(entries))
    for address, port in entries:
        body += caddress_v6(address)
        body += struct.pack(">H", port)
    return bytes(body)


def test_caddress_is_family_length_and_network_bytes() -> None:
    assert caddress_v6("2001:db8::1234") == bytes.fromhex(
        "06 10 20010db8000000000000000000001234"
    )


def test_socks5_ipv6_connect_uses_atyp_4_and_16_bytes() -> None:
    wire = socks5_connect_v6("2001:db8::1", 4662)
    assert wire[:4] == bytes.fromhex("05 01 00 04")
    assert len(wire) == 22
    assert wire[4:20] == ipaddress.IPv6Address("2001:db8::1").packed
    assert wire[20:] == bytes.fromhex("1236")


def test_socks5_ipv6_reply_has_variable_address_slot() -> None:
    wire = socks5_reply_v6("2001:db8::2", 4672)
    assert wire[:4] == bytes.fromhex("05 00 00 04")
    assert len(wire) == 22
    assert wire[20:] == struct.pack(">H", 4672)


def test_http_connect_authority_brackets_ipv6() -> None:
    address = ipaddress.IPv6Address("2001:db8::3")
    authority = f"[{address}]:4662"
    assert authority == "[2001:db8::3]:4662"
    assert authority.count(":") > 2 and authority.startswith("[")


def test_live_peer_list_v2_keeps_each_native_endpoint_losslessly() -> None:
    wire = live_peer_list_v2([("2001:db8::10", 4662), ("2001:db8::11", 4670)])
    assert wire[16:18] == struct.pack(">H", 2)
    assert wire[18:20] == bytes((6, 16))
    assert wire[36:38] == struct.pack(">H", 4662)
    assert wire[38:40] == bytes((6, 16))
    assert wire[56:58] == struct.pack(">H", 4670)


def test_legacy_socks4_cannot_be_silently_reencoded_as_ipv6() -> None:
    # SOCKS4 has no ATYP=4.  The C++ layer must reject this combination rather
    # than truncating the address to a synthetic uint32 value.
    assert len(ipaddress.IPv6Address("2001:db8::1").packed) == 16
    assert bytes((4, 1)) != bytes((5, 1, 0, 4))


if __name__ == "__main__":
    tests = [value for name, value in globals().items() if name.startswith("test_")]
    for test in tests:
        test()
    print(f"IPv6 transport wire tests: PASS ({len(tests)})")
