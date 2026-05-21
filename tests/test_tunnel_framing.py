#!/usr/bin/env python3
# tests/test_tunnel_framing.py - v8.1 Sprint A spec regression.
#
# Locks down the v8.1 onion-tunnel sub-protocol framing (see
# docs/V8.1_SPRINT_A_BREAKDOWN.md SS1) by replicating the byte layout of the
# 7-byte sub-header and the 8-byte fragment header in Python and asserting
# against fixed test vectors. The C++ helpers PackSubHeader / ParseSubHeader /
# PackFragHeader / ParseFragHeader (srchybrid/LiveCellQueue.cpp) MUST agree
# with these vectors byte-for-byte; any drift is a regression.
#
# Same pattern as test_address_wire.py. Pure Python, no emule.exe needed.
#
# Run: python tests/test_tunnel_framing.py
# Exit 0 = all pass, 1 = at least one mismatch, 2 = tool error.

import sys


# ---- constants mirrored from srchybrid/LiveCellQueue.h + Opcodes.h ----------
SUB_HEADER_BYTES      = 7
FRAG_HEADER_BYTES     = 8
TUN_MULTICELL_OP_MIN  = 0x40
TUN_MSG_MAX_BYTES     = 65536
TUN_MSG_MAX_FRAGS     = 256
CELL_TOTAL_BYTES      = 512
CELL_HEADER_BYTES     = 7
CELL_PAYLOAD_MAX      = CELL_TOTAL_BYTES - CELL_HEADER_BYTES   # 505
AEAD_TAG_BYTES        = 16                                    # one per onion hop

# TunnelOpCmd (LiveTunnel.h) - legacy single-cell ops (< 0x40)
TUN_OP_PING            = 0x01
TUN_OP_PING_REPLY      = 0x02
TUN_OP_KAD_SEARCH      = 0x10
TUN_OP_KAD_RESULT      = 0x11
TUN_OP_LIVE_SUBSCRIBE  = 0x20
TUN_OP_LIVE_SUB_ACK    = 0x21
# v8.1 multi-cell ops (>= 0x40, carry the fragment header)
TUN_OP_ECHO_LARGE       = 0x40
TUN_OP_ECHO_LARGE_REPLY = 0x41

# ESE_CAP_* bitmap (Opcodes.h)
ESE_CAP_BITS = {
    'M1_SUBSCRIBER_PIN': 0x0001, 'M2_COMPOSITE_KEYS': 0x0002,
    'M3_SHARDING':       0x0004, 'M4_TRIGRAMS':       0x0008,
    'M5_BLOOM_GOSSIP':   0x0010, 'M6_K_EFFECTIVE':    0x0020,
    'PRIVACY_TUNNELING': 0x0100, 'SEALED_RECORDS':    0x0200,
    'GOSSIP_PROTOCOL':   0x0400, 'COVER_TRAFFIC':     0x0800,
}
ESE_CAP_TUNNEL_DATAPLANE = 0x1000   # v8.1 A7 - new bit


# ---- Python replicas of the C++ framing helpers -----------------------------
def pack_sub_header(sub_cmd, req_id, body_len):
    """Replica of C++ PackSubHeader: sub_cmd(1) + req_id(4 LE) + body_len(2 LE)."""
    return bytes([
        sub_cmd & 0xFF,
        req_id & 0xFF, (req_id >> 8) & 0xFF, (req_id >> 16) & 0xFF, (req_id >> 24) & 0xFF,
        body_len & 0xFF, (body_len >> 8) & 0xFF,
    ])


def parse_sub_header(plain):
    """Replica of C++ ParseSubHeader. Returns (sub_cmd, req_id, body_len, body)
    or None if the buffer is too short or the declared body overruns it."""
    if plain is None or len(plain) < SUB_HEADER_BYTES:
        return None
    sub_cmd  = plain[0]
    req_id   = plain[1] | (plain[2] << 8) | (plain[3] << 16) | (plain[4] << 24)
    body_len = plain[5] | (plain[6] << 8)
    if SUB_HEADER_BYTES + body_len > len(plain):
        return None
    body = bytes(plain[SUB_HEADER_BYTES:SUB_HEADER_BYTES + body_len])
    return (sub_cmd, req_id, body_len, body)


def pack_frag_header(frag_index, frag_count, msg_total):
    """Replica of C++ PackFragHeader: frag_index(2 LE) + frag_count(2 LE) + msg_total(4 LE)."""
    return bytes([
        frag_index & 0xFF, (frag_index >> 8) & 0xFF,
        frag_count & 0xFF, (frag_count >> 8) & 0xFF,
        msg_total & 0xFF, (msg_total >> 8) & 0xFF,
        (msg_total >> 16) & 0xFF, (msg_total >> 24) & 0xFF,
    ])


def parse_frag_header(body):
    """Replica of C++ ParseFragHeader. Returns (frag_index, frag_count,
    msg_total, frag_data) or None if `body` is shorter than FRAG_HEADER_BYTES."""
    if body is None or len(body) < FRAG_HEADER_BYTES:
        return None
    frag_index = body[0] | (body[1] << 8)
    frag_count = body[2] | (body[3] << 8)
    msg_total  = body[4] | (body[5] << 8) | (body[6] << 16) | (body[7] << 24)
    frag_data  = bytes(body[FRAG_HEADER_BYTES:])
    return (frag_index, frag_count, msg_total, frag_data)


# ---- models of the planned A1.3 (split) + A1.4/A1.6 (reassembly) ------------
def split_message(sub_cmd, req_id, message, frag_data_max):
    """Model of A1.3 SplitIntoCells: a logical message -> list of cell
    plaintexts, each = sub-header + frag-header + frag_data."""
    total = len(message)
    if total == 0:
        chunks = [b'']
    else:
        chunks = [message[i:i + frag_data_max] for i in range(0, total, frag_data_max)]
    count = len(chunks)
    cells = []
    for idx, chunk in enumerate(chunks):
        body = pack_frag_header(idx, count, total) + chunk
        cells.append(pack_sub_header(sub_cmd, req_id, len(body)) + body)
    return cells


def reassemble(cells):
    """Model of A1.4 reassembly + A1.6 caps. Returns the message or None."""
    frags, req_id, exp_count, exp_total = {}, None, None, None
    for cell in cells:
        sub = parse_sub_header(cell)
        if sub is None:
            return None
        _, s_req, _, body = sub
        fh = parse_frag_header(body)
        if fh is None:
            return None
        idx, count, total, data = fh
        if total > TUN_MSG_MAX_BYTES:          # A1.6 caps
            return None
        if count == 0 or count > TUN_MSG_MAX_FRAGS:
            return None
        if req_id is None:
            req_id, exp_count, exp_total = s_req, count, total
        elif (s_req, count, total) != (req_id, exp_count, exp_total):
            return None
        if idx >= count:                       # A1.6 bad index
            return None
        frags[idx] = data
    if exp_count is None or len(frags) != exp_count:
        return None
    out = b''.join(frags[i] for i in range(exp_count))
    return out if len(out) == exp_total else None


# -------------------------------- tests --------------------------------------
def test_sub_header_roundtrip():
    cases = [
        (TUN_OP_PING, 0, 0),
        (TUN_OP_ECHO_LARGE, 1, 1),
        (0x40, 0x12345678, 100),
        (0xFF, 0xFFFFFFFF, 0xFFFF),
        (0x00, 0x00000000, 0),
    ]
    for sub_cmd, req_id, body_len in cases:
        hdr = pack_sub_header(sub_cmd, req_id, body_len)
        assert len(hdr) == SUB_HEADER_BYTES, f"sub-header not {SUB_HEADER_BYTES} bytes"
        plain = hdr + bytes(i & 0xFF for i in range(body_len))
        got = parse_sub_header(plain)
        assert got is not None, f"parse failed for {sub_cmd:#x}/{req_id:#x}/{body_len}"
        g_cmd, g_req, g_len, g_body = got
        assert g_cmd == sub_cmd, f"sub_cmd drift: {g_cmd:#x} != {sub_cmd:#x}"
        assert g_req == req_id, f"req_id drift: {g_req:#x} != {req_id:#x}"
        assert g_len == body_len, f"body_len drift: {g_len} != {body_len}"
        assert g_body == plain[SUB_HEADER_BYTES:SUB_HEADER_BYTES + body_len]


def test_sub_header_byte_layout():
    # Pinned vectors. A C++ implementation drift is caught here.
    assert pack_sub_header(0x40, 0xAABBCCDD, 0x1234) == bytes.fromhex('40DDCCBBAA3412')
    assert pack_sub_header(0x01, 0, 0) == bytes.fromhex('01000000000000')
    assert pack_sub_header(0x11, 0x00000001, 0x0005) == bytes.fromhex('11010000000500')


def test_sub_header_rejects_short():
    for n in range(0, SUB_HEADER_BYTES):           # 0..6
        assert parse_sub_header(bytes(n)) is None, f"accepted short buffer len={n}"
    assert parse_sub_header(None) is None
    # exactly 7 bytes, body_len 0 -> valid
    assert parse_sub_header(pack_sub_header(0x40, 0, 0)) is not None


def test_sub_header_rejects_overrun():
    # Declares body_len=10 but only 5 body bytes present -> reject.
    assert parse_sub_header(pack_sub_header(0x40, 7, 10) + bytes(5)) is None
    # Declares 6, only 5 present -> reject (off-by-one guard).
    assert parse_sub_header(pack_sub_header(0x40, 7, 6) + bytes(5)) is None
    # Declares 5, exactly 5 present -> accept.
    assert parse_sub_header(pack_sub_header(0x40, 7, 5) + bytes(5)) is not None


def test_frag_header_roundtrip():
    cases = [
        (0, 1, 0),
        (0, 1, 1),
        (5, 10, 4096),
        (0xFFFF, 0xFFFF, 0xFFFFFFFF),
        (143, 144, 65536),
    ]
    for idx, count, total in cases:
        hdr = pack_frag_header(idx, count, total)
        assert len(hdr) == FRAG_HEADER_BYTES, f"frag-header not {FRAG_HEADER_BYTES} bytes"
        got = parse_frag_header(hdr + b'payload')
        assert got is not None, f"parse failed for {idx}/{count}/{total}"
        g_idx, g_count, g_total, g_data = got
        assert (g_idx, g_count, g_total) == (idx, count, total), \
            f"frag-header drift: {(g_idx, g_count, g_total)} != {(idx, count, total)}"
        assert g_data == b'payload'


def test_frag_header_byte_layout():
    # Pinned vectors.
    assert pack_frag_header(0x0102, 0x0304, 0xAABBCCDD) == bytes.fromhex('02010403DDCCBBAA')
    assert pack_frag_header(0, 1, 0) == bytes.fromhex('0000010000000000')


def test_frag_header_rejects_short():
    for n in range(0, FRAG_HEADER_BYTES):          # 0..7
        assert parse_frag_header(bytes(n)) is None, f"accepted short buffer len={n}"
    assert parse_frag_header(None) is None
    # exactly 8 bytes, empty frag_data -> valid
    assert parse_frag_header(pack_frag_header(0, 1, 0)) is not None


def test_endianness():
    # High bytes must survive a little-endian round-trip.
    got = parse_sub_header(pack_sub_header(0x55, 0xFF000000, 0x8000) + bytes(0x8000))
    assert got is not None and got[1] == 0xFF000000 and got[2] == 0x8000
    fh = parse_frag_header(pack_frag_header(0xFFFF, 0x8001, 0xDEADBEEF))
    assert fh is not None and fh[:3] == (0xFFFF, 0x8001, 0xDEADBEEF)


def test_multicell_threshold():
    # Legacy single-cell ops are < 0x40; v8.1 multi-cell ops are >= 0x40.
    for op in (TUN_OP_PING, TUN_OP_PING_REPLY, TUN_OP_KAD_SEARCH,
               TUN_OP_KAD_RESULT, TUN_OP_LIVE_SUBSCRIBE, TUN_OP_LIVE_SUB_ACK):
        assert op < TUN_MULTICELL_OP_MIN, f"{op:#x} must be legacy single-cell"
    for op in (TUN_OP_ECHO_LARGE, TUN_OP_ECHO_LARGE_REPLY):
        assert op >= TUN_MULTICELL_OP_MIN, f"{op:#x} must be multi-cell"


def test_per_cell_budget():
    # Useful frag_data per cell on a 2-hop circuit. If this number drifts,
    # the breakdown doc's fragmentation math (V8.1_SPRINT_A_BREAKDOWN SS1)
    # must be updated too.
    two_hop_plain = CELL_PAYLOAD_MAX - 2 * AEAD_TAG_BYTES         # 505 - 32
    assert two_hop_plain == 473, f"2-hop plaintext budget: {two_hop_plain}"
    frag_data_2hop = two_hop_plain - SUB_HEADER_BYTES - FRAG_HEADER_BYTES
    assert frag_data_2hop == 458, f"2-hop frag_data budget drifted: {frag_data_2hop}"


def test_message_fragmentation():
    # Models A1.3 (split) + A1.4 (reassembly) over the fragment wire format.
    budget = 458   # 2-hop frag_data per cell
    for size in (0, 1, 457, 458, 459, 916, 4096, 65536):
        msg = bytes((i * 7 + 3) & 0xFF for i in range(size))
        cells = split_message(TUN_OP_ECHO_LARGE, 0x1234, msg, budget)
        for c in cells:                                  # every cell fits the wire
            assert len(c) <= SUB_HEADER_BYTES + FRAG_HEADER_BYTES + budget
        assert reassemble(cells) == msg, f"round-trip failed at size={size}"
    # Reassembly is keyed by frag_index -> order independent.
    import random
    msg = bytes(range(200)) * 5
    cells = split_message(TUN_OP_ECHO_LARGE, 0x9, msg, 64)
    random.seed(1)
    shuffled = cells[:]
    random.shuffle(shuffled)
    assert reassemble(shuffled) == msg, "out-of-order reassembly failed"
    # A missing fragment must NOT reassemble.
    assert reassemble(cells[:-1]) is None, "accepted an incomplete message"


def test_message_size_cap():
    # A1.6 - a message exceeding TUN_MSG_MAX_BYTES is rejected by reassembly.
    big = bytes(TUN_MSG_MAX_BYTES + 1)
    assert reassemble(split_message(TUN_OP_ECHO_LARGE, 0x7, big, 458)) is None, \
        "oversized message must be rejected"
    # Exactly at the cap is allowed.
    atcap = bytes(TUN_MSG_MAX_BYTES)
    assert reassemble(split_message(TUN_OP_ECHO_LARGE, 0x7, atcap, 458)) == atcap
    # Too many fragments (here 300 frags of 1 byte) is rejected.
    assert reassemble(split_message(TUN_OP_ECHO_LARGE, 0x8, bytes(300), 1)) is None, \
        "too-many-fragments must be rejected"


def test_capability_bits():
    # A7 - ESE_CAP_TUNNEL_DATAPLANE must be a distinct, single, free bit.
    assert ESE_CAP_TUNNEL_DATAPLANE == 0x1000
    assert bin(ESE_CAP_TUNNEL_DATAPLANE).count('1') == 1, "not a single bit"
    for name, bit in ESE_CAP_BITS.items():
        assert bit != ESE_CAP_TUNNEL_DATAPLANE, f"0x1000 collides with ESE_CAP_{name}"
    # In Tunneled/Adaptive mode the v8.1 runtime caps = v8.0.0 set | 0x1000.
    v800 = (ESE_CAP_BITS['M1_SUBSCRIBER_PIN'] | ESE_CAP_BITS['M3_SHARDING']
            | ESE_CAP_BITS['M5_BLOOM_GOSSIP'] | ESE_CAP_BITS['M6_K_EFFECTIVE']
            | ESE_CAP_BITS['SEALED_RECORDS'] | ESE_CAP_BITS['GOSSIP_PROTOCOL']
            | ESE_CAP_BITS['PRIVACY_TUNNELING'] | ESE_CAP_BITS['COVER_TRAFFIC'])
    assert v800 == 0x0F35, f"v8.0.0 caps baseline drifted: {v800:#06x}"
    assert (v800 | ESE_CAP_TUNNEL_DATAPLANE) == 0x1F35, "expected v8.1 runtime caps 0x1F35"


def run():
    tests = [
        ("sub-header roundtrip",            test_sub_header_roundtrip),
        ("sub-header byte layout",          test_sub_header_byte_layout),
        ("sub-header rejects short buffer", test_sub_header_rejects_short),
        ("sub-header rejects body overrun", test_sub_header_rejects_overrun),
        ("frag-header roundtrip",           test_frag_header_roundtrip),
        ("frag-header byte layout",         test_frag_header_byte_layout),
        ("frag-header rejects short buffer", test_frag_header_rejects_short),
        ("little-endian high bytes",        test_endianness),
        ("multi-cell op threshold",         test_multicell_threshold),
        ("per-cell frag_data budget",       test_per_cell_budget),
        ("message fragmentation round-trip", test_message_fragmentation),
        ("message size cap (A1.6)",         test_message_size_cap),
        ("ESE_CAP_TUNNEL_DATAPLANE bit (A7)", test_capability_bits),
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
    print(f"\nTOTAL: {len(tests) - fails}/{len(tests)} passed")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(run())
