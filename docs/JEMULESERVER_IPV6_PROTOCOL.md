# JEmuleServer ↔ eMule eSE IPv6 source discovery

This document defines the interoperable IPv6 source response implemented by
eMule eSE. It replaces JEmuleServer's experimental `0xE3:0x9C` packet, whose
opcode collides with the standard eD2K `OP_GLOBCALLBACKREQ`.

## Capability negotiation

When IPv6 is enabled, eMule eSE adds this numeric tag to `OP_LOGINREQUEST`:

| Field | Value |
|---|---:|
| Tag ID | `CT_FORK_CAPABILITIES` (`0xF0`) |
| Tag type | unsigned integer |
| Value bit | `CAP_FORK_IPV6_WIRE` (`0x00000001`) |

An unmodified server may ignore the unknown additive tag. JEmuleServer should
remember the capability on the logged-in client and send the IPv6 response only
when the UDP requester can be associated with a session carrying that bit. If
no capable session can be identified, it must send only the legacy response.

## UDP response

The IPv6 response is a separate UDP datagram:

```text
0xC5 0xE2
file_hash[16]
source_count[u8]
repeat source_count times:
    address_family[u8] = 0x06
    address_length[u8] = 0x10
    address[16]        = IPv6 bytes in network order
    tcp_port[u16_le]
```

The first byte is `OP_EMULEPROT` (`0xC5`) and the second is
`OP_FOUNDSOURCES_V6` (`0xE2`). The payload after those two bytes is therefore:

```text
<HASH 16><count 1>(<CAddress 18><PORT 2>)[count]
```

`CAddress` is eMule eSE's family-neutral wire representation. This packet
requires `family=6` and `length=16`; IPv4 and IPv4-mapped entries belong in the
legacy response. The TCP port uses little-endian order.

The maximum encoded count is 255. Senders should include only global, usable
IPv6 addresses and non-zero TCP ports.

Multiple logical responses may be concatenated in one datagram by inserting
another `0xC5 0xE2` before the following file hash. Sending one datagram per
file is also valid and simpler.

## Backward compatibility

JEmuleServer must continue sending the usual IPv4 response independently:

```text
0xE3 0x9B <HASH 16><count 1>(<IPv4/ID 4><PORT 2>)[count]
```

A capable client can therefore receive both responses for the same hash.
Legacy clients receive only `0xE3:0x9B`. The IPv6 packet does not replace,
extend, or append data to the legacy packet.

Do not use any of these alternatives:

- `0xE3:0x9C`: collides with `OP_GLOBCALLBACKREQ`.
- `0xE3:0xE2`: the numeric opcode is allocated in the `0xC5` namespace.
- Raw `<IPv6 16><port 2>` entries: each address must carry the `0x06 0x10`
  `CAddress` prefix.

## JEmuleServer migration checklist

1. Parse numeric login tag `0xF0` and retain its unsigned 32-bit value.
2. Keep the existing `0xE3:0x9B` IPv4 response.
3. Replace the experimental `0xE3:0x9C` datagram with `0xC5:0xE2`.
4. Prefix every 16-byte IPv6 address with `0x06 0x10`.
5. Emit the new datagram only for clients advertising bit `0x00000001`.
6. Add tests covering mixed IPv4/IPv6 sources and a legacy login without the
   capability tag.
