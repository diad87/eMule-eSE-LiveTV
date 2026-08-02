#!/usr/bin/env python3
"""V91-K02 physical Kad2/Kad6 plane-isolation phase probe."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import signal
import socket
import struct
import subprocess
import time
from collections import Counter
from pathlib import Path

import v91_s01_collision_probe as S01


OP_KAD2_HEADER = 0xE4
OP_KAD2_BOOTSTRAP_REQ = 0x01
OP_KAD2_BOOTSTRAP_RES = 0x09
OP_KAD6_HEADER = 0xE6
OP_KAD6_BOOTSTRAP_REQ = 0x02
OP_KAD6_BOOTSTRAP_RES = 0x0A
OP_KAD6_HELLO_REQ = 0x12
OP_KAD6_HELLO_RES = 0x1A


def start_capture(
    interface: str,
    source_v4: str,
    target_v4: str,
    source_v6: str,
    target_v6: str,
    port: int,
    output: Path,
) -> subprocess.Popen[str]:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.unlink(missing_ok=True)
    expression = (
        f"udp and port {port} and ("
        f"(host {source_v4} and host {target_v4}) or "
        f"(host {source_v6} and host {target_v6}))"
    )
    process = subprocess.Popen(
        (
            "tcpdump", "-U", "-i", interface, "-s", "0",
            "-w", str(output), expression,
        ),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    time.sleep(0.75)
    if process.poll() is not None:
        stderr = process.stderr.read() if process.stderr is not None else ""
        raise RuntimeError(f"tcpdump did not arm: {stderr.strip()}")
    return process


def stop_capture(process: subprocess.Popen[str]) -> str:
    if process.poll() is None:
        process.send_signal(signal.SIGINT)
    try:
        _, stderr = process.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        _, stderr = process.communicate(timeout=5)
    if process.returncode not in (0, -signal.SIGINT):
        raise RuntimeError(
            f"tcpdump stopped with {process.returncode}: {stderr.strip()}"
        )
    return stderr


def parse_pcap(path: Path) -> list[dict[str, object]]:
    raw = path.read_bytes()
    if len(raw) < 24:
        raise RuntimeError("pcap has no global header")
    if raw[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif raw[:4] in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        raise RuntimeError("unsupported pcap magic")
    if struct.unpack_from(f"{endian}I", raw, 20)[0] != 1:
        raise RuntimeError("pcap is not Ethernet")
    frames: list[dict[str, object]] = []
    offset = 24
    while offset < len(raw):
        seconds, fraction, captured, original = struct.unpack_from(
            f"{endian}IIII", raw, offset
        )
        offset += 16
        frame = raw[offset:offset + captured]
        offset += captured
        if len(frame) < 14:
            continue
        network = 14
        ether_type = struct.unpack_from("!H", frame, 12)[0]
        while ether_type in (0x8100, 0x88A8):
            ether_type = struct.unpack_from("!H", frame, network + 2)[0]
            network += 4
        family = ""
        if ether_type == 0x0800 and len(frame) >= network + 28:
            if frame[network] >> 4 != 4:
                continue
            ihl = (frame[network] & 0x0F) * 4
            if ihl < 20 or frame[network + 9] != socket.IPPROTO_UDP:
                continue
            udp = network + ihl
            source_address = str(ipaddress.IPv4Address(
                frame[network + 12:network + 16]
            ))
            target_address = str(ipaddress.IPv4Address(
                frame[network + 16:network + 20]
            ))
            family = "IPv4"
        elif ether_type == 0x86DD and len(frame) >= network + 48:
            if frame[network] >> 4 != 6 or (
                frame[network + 6] != socket.IPPROTO_UDP
            ):
                continue
            udp = network + 40
            source_address = str(ipaddress.IPv6Address(
                frame[network + 8:network + 24]
            ))
            target_address = str(ipaddress.IPv6Address(
                frame[network + 24:network + 40]
            ))
            family = "IPv6"
        else:
            continue
        source_port, target_port, udp_length = struct.unpack_from(
            "!HHH", frame, udp
        )
        if udp_length < 8 or udp + udp_length > len(frame):
            continue
        payload = frame[udp + 8:udp + udp_length]
        frames.append({
            "timestamp_seconds": seconds,
            "timestamp_fraction": fraction,
            "captured_bytes": captured,
            "original_bytes": original,
            "family": family,
            "source_mac": ":".join(f"{b:02x}" for b in frame[6:12]),
            "target_mac": ":".join(f"{b:02x}" for b in frame[0:6]),
            "source_address": source_address,
            "target_address": target_address,
            "source_port": source_port,
            "target_port": target_port,
            "payload_bytes": len(payload),
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
            "header": payload[0] if payload else None,
            "opcode": payload[1] if len(payload) >= 2 else None,
        })
    return frames


def packet_event(
    direction: str,
    family: str,
    packet: bytes,
    source: str,
    source_port: int,
    target: str,
    target_port: int,
    kind: str,
) -> dict[str, object]:
    return {
        "direction": direction,
        "family": family,
        "kind": kind,
        "source_address": source,
        "source_port": source_port,
        "target_address": target,
        "target_port": target_port,
        "header": packet[0] if packet else None,
        "opcode": packet[1] if len(packet) >= 2 else None,
        "bytes": len(packet),
        "sha256": hashlib.sha256(packet).hexdigest(),
    }


def run_phase(
    phase: str,
    expect_kad2: bool,
    expect_kad6: bool,
    source_v4: str,
    target_v4: str,
    source_v6: str,
    target_v6: str,
    target_port: int,
    timeout_seconds: float,
) -> dict[str, object]:
    events: list[dict[str, object]] = []
    v4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    v6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        v4.bind((source_v4, 0))
        v6.bind((source_v6, 0))
        v4.setblocking(False)
        v6.setblocking(False)
        v4_port = v4.getsockname()[1]
        v6_port = v6.getsockname()[1]

        kad2_request = bytes((OP_KAD2_HEADER, OP_KAD2_BOOTSTRAP_REQ))
        v4.sendto(kad2_request, (target_v4, target_port))
        events.append(packet_event(
            "probe_to_candidate", "IPv4", kad2_request,
            source_v4, v4_port, target_v4, target_port, "kad2_bootstrap_req",
        ))
        kad2_response = False
        kad2_deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < kad2_deadline:
            try:
                packet, peer = v4.recvfrom(4096)
            except BlockingIOError:
                time.sleep(0.025)
                continue
            events.append(packet_event(
                "candidate_to_probe", "IPv4", packet,
                peer[0], peer[1], source_v4, v4_port, "kad2_response",
            ))
            if (
                len(packet) >= 2
                and packet[0] == OP_KAD2_HEADER
                and packet[1] == OP_KAD2_BOOTSTRAP_RES
            ):
                kad2_response = True
                break

        identity = S01.make_identity(source_v6, v6_port, 0)
        txid = int.from_bytes(hashlib.sha256(
            b"eSE-V91-K02-v1" + phase.encode("ascii")
        ).digest()[:4], "little") or 1
        kad6_request = (
            bytes((OP_KAD6_HEADER, OP_KAD6_BOOTSTRAP_REQ))
            + S01.make_header(identity, txid)
        )
        v6.sendto(kad6_request, (target_v6, target_port))
        events.append(packet_event(
            "probe_to_candidate", "IPv6", kad6_request,
            source_v6, v6_port, target_v6, target_port, "kad6_bootstrap_req",
        ))
        kad6_challenge = False
        kad6_response = False
        semantic_before_challenge = False
        kad6_deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < kad6_deadline and not kad6_response:
            try:
                packet, peer = v6.recvfrom(4096)
            except BlockingIOError:
                time.sleep(0.025)
                continue
            events.append(packet_event(
                "candidate_to_probe", "IPv6", packet,
                peer[0], peer[1], source_v6, v6_port, "kad6_response",
            ))
            opcode = packet[1] if len(packet) >= 2 else None
            packet_txid = (
                int.from_bytes(packet[6:10], "little")
                if len(packet) >= 10
                else None
            )
            if opcode == OP_KAD6_BOOTSTRAP_RES and packet_txid == txid:
                semantic_before_challenge = not kad6_challenge
                kad6_response = True
                continue
            if opcode != OP_KAD6_HELLO_REQ or packet_txid is None:
                continue
            kad6_challenge = True
            hello = (
                bytes((OP_KAD6_HEADER, OP_KAD6_HELLO_RES))
                + S01.make_header(identity, packet_txid)
            )
            v6.sendto(hello, (target_v6, target_port))
            events.append(packet_event(
                "probe_to_candidate", "IPv6", hello,
                source_v6, v6_port, target_v6, target_port,
                "kad6_challenge_response",
            ))
        return {
            "phase": phase,
            "expect_kad2": expect_kad2,
            "expect_kad6": expect_kad6,
            "kad2_bootstrap_response": kad2_response,
            "kad6_challenge": kad6_challenge,
            "kad6_bootstrap_response": kad6_response,
            "kad6_semantic_before_challenge": semantic_before_challenge,
            "wire_expectations_met": (
                kad2_response == expect_kad2
                and kad6_challenge == expect_kad6
                and kad6_response == expect_kad6
                and not semantic_before_challenge
            ),
            "events": events,
        }
    finally:
        v4.close()
        v6.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", required=True)
    parser.add_argument("--expect-kad2", type=int, choices=(0, 1), required=True)
    parser.add_argument("--expect-kad6", type=int, choices=(0, 1), required=True)
    parser.add_argument("--source-v4", required=True)
    parser.add_argument("--target-v4", required=True)
    parser.add_argument("--source-v6", required=True)
    parser.add_argument("--target-v6", required=True)
    parser.add_argument("--target-port", type=int, required=True)
    parser.add_argument("--physical-ipv4", required=True)
    parser.add_argument("--pcap-output", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--timeout-seconds", type=float, default=2.0)
    args = parser.parse_args()

    source_v4 = str(ipaddress.IPv4Address(args.source_v4))
    target_v4 = str(ipaddress.IPv4Address(args.target_v4))
    source_v6 = str(ipaddress.IPv6Address(args.source_v6))
    target_v6 = str(ipaddress.IPv6Address(args.target_v6))
    interface = S01.S03.find_interface_for_ipv4(args.physical_ipv4)
    S01.S03.configure_source_ula(interface, source_v6)
    subprocess.run(
        ("ip", "-6", "route", "replace", f"{target_v6}/128",
         "dev", interface),
        check=True,
    )
    capture_path = Path(args.pcap_output)
    started = time.time()
    capture = None
    capture_stderr = ""
    try:
        capture = start_capture(
            interface, source_v4, target_v4, source_v6, target_v6,
            args.target_port, capture_path,
        )
        try:
            phase = run_phase(
                args.phase,
                bool(args.expect_kad2),
                bool(args.expect_kad6),
                source_v4,
                target_v4,
                source_v6,
                target_v6,
                args.target_port,
                args.timeout_seconds,
            )
        finally:
            # tcpdump may have accepted the last frames into its capture
            # buffer while the protocol probe was finishing. Give it time
            # to flush them before SIGINT so the PCAP remains authoritative.
            time.sleep(3.0)
            capture_stderr = stop_capture(capture)
    finally:
        subprocess.run(
            ("ip", "-6", "route", "del", f"{target_v6}/128",
             "dev", interface),
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        S01.S03.cleanup_source_ula(interface, source_v6)

    frames = parse_pcap(capture_path)
    event_hashes = Counter(event["sha256"] for event in phase["events"])
    missing = event_hashes.copy()
    enabled_background: list[dict[str, object]] = []
    unexpected: list[dict[str, object]] = []
    for frame in frames:
        payload_hash = frame["payload_sha256"]
        if missing[payload_hash] > 0:
            missing[payload_hash] -= 1
            continue
        candidate_to_probe = (
            (
                frame["source_address"] == target_v4
                and frame["target_address"] == source_v4
            )
            or (
                frame["source_address"] == target_v6
                and frame["target_address"] == source_v6
            )
        )
        enabled_plane = (
            frame["header"] == OP_KAD2_HEADER and bool(args.expect_kad2)
        ) or (
            frame["header"] == OP_KAD6_HEADER and bool(args.expect_kad6)
        )
        if candidate_to_probe and enabled_plane:
            enabled_background.append(frame)
        else:
            unexpected.append(frame)
    missing_event_count = sum(missing.values())
    capture_pass = (
        not unexpected
        and missing_event_count == 0
    )
    passed = phase["wire_expectations_met"] and capture_pass
    text_path = capture_path.with_suffix(".txt")
    decoded = subprocess.run(
        ("tcpdump", "-nn", "-e", "-vvv", "-XX", "-r", str(capture_path)),
        check=False,
        capture_output=True,
        text=True,
    )
    text_path.write_text(decoded.stdout, encoding="utf-8")
    result = {
        "schema": "ese.v91.k02-plane-probe/v1",
        "case_id": "V91-K02",
        "status": "PASS" if passed else "FAIL",
        "started_at_utc": time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(started)
        ),
        "completed_at_utc": time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
        ),
        "topology": {
            "profile": "T1",
            "interface": interface,
            "source_v4": source_v4,
            "target_v4": target_v4,
            "source_v6": source_v6,
            "target_v6": target_v6,
            "target_port": args.target_port,
            "overlay_data_route_used": False,
        },
        "probe": phase,
        "capture": {
            "backend": "tcpdump",
            "status": "PASS" if capture_pass else "FAIL",
            "pcap_file": capture_path.name,
            "pcap_bytes": capture_path.stat().st_size,
            "pcap_sha256": hashlib.sha256(
                capture_path.read_bytes()
            ).hexdigest(),
            "text_file": text_path.name,
            "text_bytes": text_path.stat().st_size,
            "frame_count": len(frames),
            "frames": frames,
            "declared_event_frame_count": len(phase["events"]),
            "missing_declared_event_count": missing_event_count,
            "enabled_plane_background_frame_count": len(enabled_background),
            "enabled_plane_background_frames": enabled_background,
            "unexpected_frame_count": len(unexpected),
            "stderr": capture_stderr.strip(),
        },
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(result, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result, indent=2, sort_keys=False))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
