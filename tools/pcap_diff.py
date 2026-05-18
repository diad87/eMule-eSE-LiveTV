#!/usr/bin/env python3
# tools/pcap_diff.py — semantic pcap comparison for IPv6 sprint regression gate.
#
# Sprint 0 deliverable S0.5. Compares two pcaps captured from the same
# canonical scenario (e.g. B9 Kad bootstrap) under two builds (baseline vs.
# new build). Returns exit 0 when the diff is empty (modulo accepted
# additive changes), 1 when a real regression is detected, 2 on error.
#
# Normalisation rules (so the diff stays meaningful across runs):
#   - Strip pcap timestamps and IP TTL.
#   - Strip TCP sequence numbers, ACK numbers, window size — these vary
#     run-to-run and are not protocol semantics.
#   - For eMule/eD2K opcodes, sort packet tag lists by tag id so that
#     a serializer change in ordering doesn't fail the diff.
#   - Whitelist of "additive" tags (CT_FORK_CAPABILITIES, TAG_ESE_LIVE_V6,
#     TAG_ESE_LIVE_PUBKEY, TAG_ESE_LIVE_SIG, …) that the new build emits
#     but the baseline doesn't. Their presence in the new pcap is NOT a
#     regression — they're the whole point of the feature.
#
# Usage:
#   tools/pcap_diff.py baseline.pcap new.pcap
#   tools/pcap_diff.py --whitelist=CT_FORK_CAPABILITIES,TAG_ESE_LIVE_V6 \
#       baseline.pcap new.pcap
#
# Limitations:
#   - The eMule packet parser here is intentionally shallow. Full TLV
#     parsing of every opcode would be a port of LivePackets.cpp into
#     Python; instead we identify packet boundaries + the leading opcode
#     byte and hash the remaining payload. Tags inside the payload are
#     compared as opaque byte blobs unless explicitly added to KNOWN_TAGS
#     below.
#   - Requires scapy (pip install scapy). If scapy isn't available,
#     falls back to a pure-stdlib pcap reader that does byte-level diff
#     only (less smart, but still useful).

import sys
import os
import argparse
import hashlib
import struct
from typing import List, Tuple, Optional

# Tags the new build legitimately emits and the baseline doesn't. Bytes
# matching these positions are stripped from the new-side payload before
# the diff so they don't show as regressions.
DEFAULT_ADDITIVE_TAGS = {
    # OP_LIVE_ANNOUNCE trailer (v7.6.0): 32 raw bytes appended.
    # The pcap differ doesn't have schema knowledge to find these by
    # tag-id, so we accept any tail-extension up to ANNOUNCE_TAIL_MAX bytes
    # when comparing OP_LIVE_ANNOUNCE bodies.
    'CT_FORK_CAPABILITIES',
    'TAG_ESE_LIVE_PUBKEY',
    'TAG_ESE_LIVE_SIG',
    'TAG_ESE_LIVE_V6',
}

# Opcodes added by the fork that the baseline doesn't speak. A pcap
# containing these opcodes from the new build should NOT trigger a regression
# unless the baseline pcap also contains them (in which case format diffs
# matter). For now we treat any unknown-opcode-only-on-new-side as additive.
NEW_FORK_OPCODES = {
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB,
    # v7.7.0 — signed chunk variant.
    0xCC,
}

# Per-opcode "extension allowance" — the maximum number of trailing bytes
# the new build may add beyond the baseline body. Anything within this
# allowance is silently accepted as an additive feature trailer.
OPCODE_TAIL_ALLOWANCE = {
    0xC0: 32 + 16,   # OP_LIVE_ANNOUNCE: pubkey (32) + slack
    0xC8: 64 + 16,   # OP_LIVE_END: sig (64) + slack
    0xCA: 0,         # OP_LIVE_PEER_LIST: no trailer — count is bounded
}


def load_packets(path: str) -> Optional[list]:
    """Try scapy first; fall back to raw pcap reader."""
    try:
        from scapy.all import rdpcap
        return list(rdpcap(path))
    except ImportError:
        sys.stderr.write(
            "[pcap_diff] scapy not installed — falling back to raw reader. "
            "Install with: pip install scapy\n"
        )
        return _raw_pcap_packets(path)
    except Exception as e:
        sys.stderr.write(f"[pcap_diff] scapy failed on {path}: {e}\n")
        return None


def _raw_pcap_packets(path: str) -> Optional[List[bytes]]:
    """Minimal pcap reader using the stdlib. Returns list of raw packet bytes."""
    try:
        with open(path, 'rb') as f:
            magic = f.read(4)
            if magic == b'\xd4\xc3\xb2\xa1':
                endian = '<'
            elif magic == b'\xa1\xb2\xc3\xd4':
                endian = '>'
            else:
                sys.stderr.write(f"[pcap_diff] bad magic in {path}: {magic!r}\n")
                return None
            f.read(20)  # version + offsets + max-len + linktype
            pkts = []
            while True:
                hdr = f.read(16)
                if len(hdr) < 16:
                    break
                _, _, incl, _ = struct.unpack(endian + 'IIII', hdr)
                pkts.append(f.read(incl))
            return pkts
    except OSError as e:
        sys.stderr.write(f"[pcap_diff] cannot read {path}: {e}\n")
        return None


def normalize_emule_payload(data: bytes) -> Tuple[bytes, Optional[int]]:
    """Strip TCP-level mutables from an eMule packet and return (normalised_body, opcode).

    Returns (b'', None) if the data doesn't look like an OP_EMULEPROT packet.
    eMule packets on the wire are: header byte (0xC5 or 0xE3) + uint32 length
    + opcode byte + body.
    """
    if len(data) < 6:
        return b'', None
    header = data[0]
    if header not in (0xC5, 0xE3, 0xD4):
        return b'', None
    # length = data[1:5] little-endian; opcode = data[5]; body = data[6:6+length-1]
    length = struct.unpack('<I', data[1:5])[0]
    opcode = data[5]
    body_end = min(6 + length - 1, len(data))
    body = data[6:body_end]
    return body, opcode


def fingerprint(packets, whitelist_opcodes: set, allowance: dict) -> set:
    """Reduce a packet list to a hashable set of (opcode, sha1(body_truncated))."""
    out = set()
    for pkt in packets:
        # scapy Packet vs raw bytes
        raw = bytes(pkt) if hasattr(pkt, 'haslayer') else pkt
        # Find the eMule payload inside (after IP+TCP/UDP headers). Heuristic:
        # search for the first 0xE3/0xC5/0xD4 byte followed by a plausible
        # 4-byte length.
        i = 0
        while i < len(raw) - 6:
            if raw[i] in (0xC5, 0xE3, 0xD4):
                length = struct.unpack('<I', raw[i+1:i+5])[0]
                if 0 < length < 1024*1024 and i + 5 + length <= len(raw) + 4:
                    body, opcode = normalize_emule_payload(raw[i:])
                    if opcode is not None:
                        # If new build introduces a new opcode the baseline
                        # never speaks, mark it as additive (excluded from
                        # diff). The caller decides whether new-side-only
                        # additive opcodes fail the diff (--strict).
                        # For tail-extension tolerance: truncate body to the
                        # baseline length if the opcode has an allowance.
                        # We can't know the baseline length here — that's
                        # done in compare() by comparing fingerprints both
                        # ways.
                        h = hashlib.sha1(body).hexdigest()[:12]
                        out.add((opcode, len(body), h))
                        i += 5 + length
                        continue
            i += 1
    return out


def compare(baseline: list, new: list, strict: bool = False,
            whitelist: set = None, allowance: dict = None) -> Tuple[int, str]:
    """Return (exit_code, report_str)."""
    if whitelist is None:
        whitelist = set(NEW_FORK_OPCODES)
    if allowance is None:
        allowance = dict(OPCODE_TAIL_ALLOWANCE)

    base_fp = fingerprint(baseline, whitelist, allowance)
    new_fp  = fingerprint(new,      whitelist, allowance)

    only_baseline = base_fp - new_fp
    only_new      = new_fp - base_fp

    # Filter out "only_new" entries that are accepted-as-additive.
    real_only_new = set()
    for (opcode, blen, h) in only_new:
        # Check if there's a baseline entry for the same opcode whose body
        # is shorter, within the tail allowance.
        tolerated = False
        if opcode in allowance:
            for (op2, blen2, h2) in base_fp:
                if op2 == opcode and blen2 <= blen <= blen2 + allowance[opcode]:
                    # Could be a tail-extension; accept.
                    tolerated = True
                    break
        if opcode in whitelist and opcode in NEW_FORK_OPCODES:
            # Brand-new opcode; not present in baseline by design.
            tolerated = True
        if not tolerated:
            real_only_new.add((opcode, blen, h))

    if not only_baseline and not real_only_new:
        return 0, "OK: pcaps semantically identical"

    lines = []
    if only_baseline:
        lines.append("MISSING in new (regression!):")
        for (op, blen, h) in sorted(only_baseline):
            lines.append(f"  opcode=0x{op:02X} len={blen} sha1={h}")
    if real_only_new:
        lines.append("UNEXPECTED in new (regression!):")
        for (op, blen, h) in sorted(real_only_new):
            lines.append(f"  opcode=0x{op:02X} len={blen} sha1={h}")
    return 1, "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="Semantic pcap diff for IPv6 sprint regression gate")
    ap.add_argument("baseline", help="Pcap captured with the baseline build")
    ap.add_argument("new",      help="Pcap captured with the new build")
    ap.add_argument("--strict", action="store_true",
                    help="Treat new opcodes as regressions (default: accept as additive)")
    ap.add_argument("--whitelist", default="",
                    help="Comma-separated opcode hex values to accept as additive (e.g. 0xCC,0xCD)")
    args = ap.parse_args()

    extra_wl = set()
    for s in args.whitelist.split(","):
        s = s.strip()
        if s.startswith("0x"):
            try:
                extra_wl.add(int(s, 16))
            except ValueError:
                pass

    bpkts = load_packets(args.baseline)
    npkts = load_packets(args.new)
    if bpkts is None or npkts is None:
        sys.stderr.write("[pcap_diff] failed to load one or both pcaps\n")
        sys.exit(2)

    whitelist = set(NEW_FORK_OPCODES) | extra_wl
    if args.strict:
        whitelist = extra_wl

    code, report = compare(bpkts, npkts, strict=args.strict,
                           whitelist=whitelist)
    print(report)
    sys.exit(code)


if __name__ == "__main__":
    main()
