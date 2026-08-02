#!/usr/bin/env python3
"""V91-S03 unverified Kad6 anti-amplification network probe."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import signal
import socket
import struct
import subprocess
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


OP_KAD6HEADER = 0xE6
OP_BOOTSTRAP_REQ = 0x02
OP_BOOTSTRAP_RES = 0x0A
OP_HELLO_REQ = 0x12
OP_FIND_NODE_REQ = 0x23
OP_FIND_NODE_RES = 0x2A
OP_FIND_SOURCE_REQ = 0x48
OP_FIND_SOURCE_RES = 0x49

ROUTER_DOMAIN = b"eSE-Kad6-RouterRecord-v1"
REQUESTS = (
    ("BOOTSTRAP_REQ", OP_BOOTSTRAP_REQ),
    ("REQ", OP_FIND_NODE_REQ),
    ("FIND_SOURCE_REQ", OP_FIND_SOURCE_REQ),
)
AMPLIFIED_OPCODES = {
    OP_BOOTSTRAP_RES,
    OP_FIND_NODE_RES,
    OP_FIND_SOURCE_RES,
}


def start_capture(
    interface: str,
    source: str,
    target: str,
    output: Path,
) -> subprocess.Popen[str]:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.unlink(missing_ok=True)
    expression = (
        f"ip6 and udp and ((src host {source} and dst host {target}) or "
        f"(src host {target} and dst host {source}))"
    )
    process = subprocess.Popen(
        (
            "tcpdump",
            "-U",
            "-i",
            interface,
            "-s",
            "0",
            "-w",
            str(output),
            expression,
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


def read_pcap_udp(path: Path) -> list[dict[str, object]]:
    raw = path.read_bytes()
    if len(raw) < 24:
        raise RuntimeError("pcap has no global header")
    magic = raw[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        raise RuntimeError("pcap magic is unsupported")
    link_type = struct.unpack_from(f"{endian}I", raw, 20)[0]
    if link_type != 1:
        raise RuntimeError(f"pcap link type is not Ethernet: {link_type}")

    frames: list[dict[str, object]] = []
    offset = 24
    while offset < len(raw):
        if offset + 16 > len(raw):
            raise RuntimeError("pcap record header is truncated")
        seconds, fraction, captured, original = struct.unpack_from(
            f"{endian}IIII", raw, offset
        )
        offset += 16
        if offset + captured > len(raw):
            raise RuntimeError("pcap record data is truncated")
        frame = raw[offset : offset + captured]
        offset += captured
        if len(frame) < 14:
            continue
        ethernet_offset = 14
        ether_type = struct.unpack_from("!H", frame, 12)[0]
        while ether_type in (0x8100, 0x88A8):
            if len(frame) < ethernet_offset + 4:
                break
            ether_type = struct.unpack_from("!H", frame, ethernet_offset + 2)[0]
            ethernet_offset += 4
        if ether_type != 0x86DD or len(frame) < ethernet_offset + 48:
            continue
        ipv6 = ethernet_offset
        if frame[ipv6] >> 4 != 6 or frame[ipv6 + 6] != socket.IPPROTO_UDP:
            continue
        udp = ipv6 + 40
        source_port, target_port, udp_length = struct.unpack_from(
            "!HHH", frame, udp
        )
        if udp_length < 8 or udp + udp_length > len(frame):
            continue
        payload = frame[udp + 8 : udp + udp_length]
        frames.append(
            {
                "timestamp_seconds": seconds,
                "timestamp_fraction": fraction,
                "captured_bytes": captured,
                "original_bytes": original,
                "source_mac": ":".join(f"{byte:02x}" for byte in frame[6:12]),
                "target_mac": ":".join(f"{byte:02x}" for byte in frame[0:6]),
                "source_ipv6": str(
                    ipaddress.IPv6Address(frame[ipv6 + 8 : ipv6 + 24])
                ),
                "target_ipv6": str(
                    ipaddress.IPv6Address(frame[ipv6 + 24 : ipv6 + 40])
                ),
                "source_port": source_port,
                "target_port": target_port,
                "payload_bytes": len(payload),
                "payload_sha256": hashlib.sha256(payload).hexdigest(),
                "opcode": payload[1] if len(payload) >= 2 else None,
            }
        )
    return frames


def adjudicate_capture(
    path: Path,
    interface: str,
    cases: list[dict[str, object]],
) -> dict[str, object]:
    frames = read_pcap_udp(path)
    expected_hashes: list[str] = []
    checks: list[dict[str, object]] = []
    for case in cases:
        hashes = [str(case["request_sha256"])]
        hashes.extend(str(item["sha256"]) for item in case["responses"])
        expected_hashes.extend(hashes)
        frame_counts = {
            payload_hash: sum(
                1
                for frame in frames
                if frame["payload_sha256"] == payload_hash
            )
            for payload_hash in hashes
        }
        checks.append(
            {
                "name": case["name"],
                "payload_frame_counts": frame_counts,
                "status": (
                    "PASS"
                    if all(count == 1 for count in frame_counts.values())
                    else "FAIL"
                ),
            }
        )
    unexpected = [
        frame
        for frame in frames
        if frame["payload_sha256"] not in expected_hashes
    ]
    passed = (
        len(frames) == len(expected_hashes)
        and not unexpected
        and all(check["status"] == "PASS" for check in checks)
    )
    text_path = path.with_suffix(".txt")
    text_result = subprocess.run(
        (
            "tcpdump",
            "-nn",
            "-e",
            "-vvv",
            "-XX",
            "-r",
            str(path),
        ),
        check=False,
        capture_output=True,
        text=True,
    )
    text_path.write_text(text_result.stdout, encoding="utf-8")
    return {
        "backend": "tcpdump",
        "status": "PASS" if passed else "FAIL",
        "interface": interface,
        "interface_mac": Path(
            f"/sys/class/net/{interface}/address"
        ).read_text(encoding="ascii").strip(),
        "pcap_file": path.name,
        "pcap_bytes": path.stat().st_size,
        "pcap_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "text_file": text_path.name,
        "text_bytes": text_path.stat().st_size,
        "frames": frames,
        "checks": checks,
        "unexpected_frame_count": len(unexpected),
    }


def u16(value: int) -> bytes:
    return struct.pack("<H", value)


def u32(value: int) -> bytes:
    return struct.pack("<I", value)


def u64(value: int) -> bytes:
    return struct.pack("<Q", value)


def make_endpoint(address: str, udp_port: int, valid_until: int) -> bytes:
    packed = ipaddress.IPv6Address(address).packed
    return (
        b"\x06\x10"
        + packed
        + u16(udp_port)
        + u16(0)
        + u16(1)
        + b"\x00\x00"
        + u64(valid_until)
    )


def make_route_header(
    address: str,
    udp_port: int,
    case_name: str,
    txid_override: int | None = None,
) -> tuple[bytes, dict[str, object]]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        Encoding.Raw,
        PublicFormat.Raw,
    )
    kad_id = hashlib.sha256(
        b"eSE-V91-S03-KadId-v1" + public_key + case_name.encode("ascii")
    ).digest()[:16]
    now = int(time.time())
    epoch = now
    valid_from = now - 5
    valid_until = now + 600
    endpoint = make_endpoint(address, udp_port, valid_until)

    record_body = (
        b"\x01\x00\x01\x00"
        + kad_id
        + public_key
        + u64(epoch)
        + u64(0)
        + u64(valid_from)
        + u64(valid_until)
        + endpoint
    )
    signature = private_key.sign(ROUTER_DOMAIN + record_body)
    public_key_obj = Ed25519PublicKey.from_public_bytes(public_key)
    public_key_obj.verify(signature, ROUTER_DOMAIN + record_body)
    record = record_body + signature

    txid = (
        txid_override
        if txid_override is not None
        else int.from_bytes(os.urandom(4), "little") or 1
    )
    header = (
        b"\x02\x00\x00\x00"
        + u32(txid)
        + kad_id
        + u64(0)
        + u64(epoch)
        + endpoint
        + u16(len(record))
        + record
    )
    return header, {
        "txid": txid,
        "kad_id": kad_id.hex(),
        "node_pub": public_key.hex(),
        "epoch": epoch,
        "valid_from": valid_from,
        "valid_until": valid_until,
        "advertised_udp_port": udp_port,
    }


def make_request(case_name: str, opcode: int, header: bytes) -> bytes:
    body = header
    if opcode == OP_FIND_NODE_REQ:
        target = hashlib.sha256(
            b"eSE-V91-S03-FindNode-v1" + case_name.encode("ascii")
        ).digest()[:16]
        body += target + b"\x0a\x00\x00\x00"
    elif opcode == OP_FIND_SOURCE_REQ:
        target = hashlib.sha256(
            b"eSE-V91-S03-FindSource-v1" + case_name.encode("ascii")
        ).digest()[:16]
        body += target + b"\x08\x00\x00\x00"
    return bytes((OP_KAD6HEADER, opcode)) + body


def verify_challenge(packet: bytes) -> dict[str, object]:
    detail: dict[str, object] = {
        "valid_envelope": False,
        "valid_signature": False,
    }
    if len(packet) < 2 or packet[0] != OP_KAD6HEADER:
        return detail
    detail["opcode"] = packet[1]
    if packet[1] != OP_HELLO_REQ:
        return detail
    payload = packet[2:]
    if len(payload) < 76 or payload[0] != 2:
        return detail

    endpoint_family = payload[40]
    endpoint_length = payload[41]
    if endpoint_family != 6 or endpoint_length != 16:
        return detail
    endpoint_end = 40 + 2 + endpoint_length + 16
    if endpoint_end + 2 > len(payload):
        return detail
    record_length = struct.unpack_from("<H", payload, endpoint_end)[0]
    record_start = endpoint_end + 2
    record_end = record_start + record_length
    if record_end != len(payload) or record_length < 64 + 84:
        return detail
    record = payload[record_start:record_end]
    record_body = record[:-64]
    signature = record[-64:]
    if len(record_body) < 52:
        return detail
    public_key = record_body[20:52]
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature,
            ROUTER_DOMAIN + record_body,
        )
    except Exception as exc:  # noqa: BLE001 - evidence captures exact class.
        detail["signature_error"] = type(exc).__name__
        return detail
    detail["valid_envelope"] = True
    detail["valid_signature"] = True
    detail["challenge_txid"] = struct.unpack_from("<I", payload, 4)[0]
    detail["record_length"] = record_length
    return detail


def run_case(
    source: str,
    target: str,
    target_port: int,
    case_name: str,
    opcode: int,
    timeout_seconds: float,
) -> dict[str, object]:
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        sock.bind((source, 0))
        sock.settimeout(0.25)
        source_port = sock.getsockname()[1]
        header, identity = make_route_header(source, source_port, case_name)
        request = make_request(case_name, opcode, header)
        started = time.monotonic()
        sock.sendto(request, (target, target_port))
        packets: list[dict[str, object]] = []
        while time.monotonic() - started < timeout_seconds:
            try:
                packet, peer = sock.recvfrom(4096)
            except socket.timeout:
                continue
            verification = verify_challenge(packet)
            packets.append(
                {
                    "bytes": len(packet),
                    "sha256": hashlib.sha256(packet).hexdigest(),
                    "source_ipv6": peer[0],
                    "source_port": peer[1],
                    "opcode": packet[1] if len(packet) >= 2 else None,
                    "bounded": len(packet) <= len(request),
                    "challenge": verification,
                }
            )

        challenge_count = sum(
            1
            for packet in packets
            if packet["opcode"] == OP_HELLO_REQ
            and packet["bounded"]
            and packet["challenge"]["valid_envelope"]
            and packet["challenge"]["valid_signature"]
        )
        amplified_count = sum(
            1 for packet in packets if packet["opcode"] in AMPLIFIED_OPCODES
        )
        unexpected_count = sum(
            1 for packet in packets if packet["opcode"] != OP_HELLO_REQ
        )
        passed = (
            challenge_count == 1
            and amplified_count == 0
            and unexpected_count == 0
            and len(packets) == 1
        )
        return {
            "name": case_name,
            "request_opcode": opcode,
            "request_txid": identity["txid"],
            "request_bytes": len(request),
            "request_sha256": hashlib.sha256(request).hexdigest(),
            "source_ipv6": source,
            "source_port": source_port,
            "target_ipv6": target,
            "target_port": target_port,
            "identity": identity,
            "responses": packets,
            "challenge_count": challenge_count,
            "amplified_count": amplified_count,
            "unexpected_count": unexpected_count,
            "status": "PASS" if passed else "FAIL",
        }
    finally:
        sock.close()


def find_interface_for_ipv4(address: str) -> str:
    output = subprocess.check_output(
        ("ip", "-o", "-4", "addr", "show"),
        text=True,
    )
    expected = f"{address}/"
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[2] == "inet" and fields[3].startswith(
            expected
        ):
            return fields[1]
    raise RuntimeError(f"physical IPv4 interface not found: {address}")


def configure_source_ula(interface: str, address: str) -> None:
    network = ipaddress.IPv6Network(f"{address}/64", strict=False)
    subprocess.run(
        ("ip", "-6", "addr", "replace", f"{address}/64", "dev", interface),
        check=True,
    )
    for _ in range(50):
        state = subprocess.check_output(
            ("ip", "-6", "addr", "show", "dev", interface),
            text=True,
        )
        matching_lines = [
            line
            for line in state.splitlines()
            if f"inet6 {address}/64" in line
        ]
        if matching_lines and all(
            "tentative" not in line and "dadfailed" not in line
            for line in matching_lines
        ):
            break
        time.sleep(0.1)
    else:
        raise RuntimeError(f"source ULA did not become usable: {address}")
    subprocess.run(
        (
            "ip",
            "-6",
            "route",
            "replace",
            str(network),
            "dev",
            interface,
        ),
        check=True,
    )


def cleanup_source_ula(interface: str, address: str) -> None:
    network = ipaddress.IPv6Network(f"{address}/64", strict=False)
    subprocess.run(
        ("ip", "-6", "addr", "del", f"{address}/64", "dev", interface),
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        ("ip", "-6", "route", "del", str(network), "dev", interface),
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--target-port", type=int, required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--timeout-seconds", type=float, default=4.0)
    parser.add_argument("--physical-ipv4")
    parser.add_argument("--pcap-output")
    parser.add_argument(
        "--only",
        choices=tuple(name for name, _ in REQUESTS),
        help="Run exactly one request kind against a fresh candidate.",
    )
    args = parser.parse_args()

    source = str(ipaddress.IPv6Address(args.source))
    target = str(ipaddress.IPv6Address(args.target))
    source_interface = None
    if args.physical_ipv4:
        source_interface = find_interface_for_ipv4(args.physical_ipv4)
        configure_source_ula(source_interface, source)
    started = time.time()
    capture_process = None
    capture_stderr = ""
    capture_path = Path(args.pcap_output) if args.pcap_output else None
    try:
        if capture_path is not None:
            if source_interface is None:
                raise RuntimeError("--pcap-output requires --physical-ipv4")
            capture_process = start_capture(
                source_interface,
                source,
                target,
                capture_path,
            )
        selected_requests = (
            tuple(item for item in REQUESTS if item[0] == args.only)
            if args.only
            else REQUESTS
        )
        cases = [
            run_case(
                source,
                target,
                args.target_port,
                name,
                opcode,
                args.timeout_seconds,
            )
            for name, opcode in selected_requests
        ]
    finally:
        if capture_process is not None:
            capture_stderr = stop_capture(capture_process)
        if source_interface is not None:
            cleanup_source_ula(source_interface, source)
    capture = None
    if capture_path is not None:
        capture = adjudicate_capture(
            capture_path,
            str(source_interface),
            cases,
        )
        capture["stderr"] = capture_stderr.strip()
    passed = all(case["status"] == "PASS" for case in cases) and (
        capture is None or capture["status"] == "PASS"
    )
    result = {
        "schema": "ese.v91.s03-probe/v1",
        "case_id": "V91-S03",
        "status": "PASS" if passed else "FAIL",
        "started_at_utc": time.strftime(
            "%Y-%m-%dT%H:%M:%SZ",
            time.gmtime(started),
        ),
        "completed_at_utc": time.strftime(
            "%Y-%m-%dT%H:%M:%SZ",
            time.gmtime(),
        ),
        "topology": {
            "profile": "T1",
            "ipv4_route_used": False,
            "overlay_used": False,
            "source": source,
            "target": target,
            "source_interface": source_interface,
            "source_physical_ipv4": args.physical_ipv4,
        },
        "cases": cases,
        "capture": capture,
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
