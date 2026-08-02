#!/usr/bin/env python3
"""V91-S01 physical Kad6 IPv6-collision qualification probe."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import ipaddress
import json
import signal
import socket
import struct
import subprocess
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


OP_KAD6HEADER = 0xE6
OP_BOOTSTRAP_REQ = 0x02
OP_BOOTSTRAP_RES = 0x0A
OP_HELLO_REQ = 0x12
OP_HELLO_RES = 0x1A
ROUTER_DOMAIN = b"eSE-Kad6-RouterRecord-v1"


def load_s03():
    path = Path(__file__).with_name("v91_s03_kad6_probe.py")
    spec = importlib.util.spec_from_file_location("v91_s03_probe", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load the shared Kad6 probe")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


S03 = load_s03()


def u16(value: int) -> bytes:
    return struct.pack("<H", value)


def u32(value: int) -> bytes:
    return struct.pack("<I", value)


def u64(value: int) -> bytes:
    return struct.pack("<Q", value)


def make_endpoint(address: str, udp_port: int, valid_until: int) -> bytes:
    return (
        b"\x06\x10"
        + ipaddress.IPv6Address(address).packed
        + u16(udp_port)
        + u16(0)
        + u16(1)
        + b"\x00\x00"
        + u64(valid_until)
    )


def make_identity(
    address: str,
    udp_port: int,
    required_first_bit: int,
) -> dict[str, object]:
    attempt = 0
    while True:
        attempt += 1
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key().public_bytes(
            Encoding.Raw,
            PublicFormat.Raw,
        )
        kad_id = hashlib.sha256(
            b"eSE-V91-S01-KadId-v1" + public_key
        ).digest()[:16]
        if kad_id[0] >> 7 == required_first_bit:
            break
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
    record = record_body + private_key.sign(ROUTER_DOMAIN + record_body)
    return {
        "address": address,
        "port": udp_port,
        "kad_id": kad_id,
        "kad_id_hex": kad_id.hex(),
        "node_pub": public_key.hex(),
        "epoch": epoch,
        "valid_from": valid_from,
        "valid_until": valid_until,
        "endpoint": endpoint,
        "record": record,
        "generation_attempts": attempt,
    }


def make_header(identity: dict[str, object], txid: int) -> bytes:
    record = identity["record"]
    if not isinstance(record, bytes):
        raise TypeError("record")
    kad_id = identity["kad_id"]
    endpoint = identity["endpoint"]
    if not isinstance(kad_id, bytes) or not isinstance(endpoint, bytes):
        raise TypeError("identity")
    return (
        b"\x02\x00\x00\x00"
        + u32(txid)
        + kad_id
        + u64(0)
        + u64(int(identity["epoch"]))
        + endpoint
        + u16(len(record))
        + record
    )


def start_capture(
    interface: str,
    sources: list[str],
    target: str,
    output: Path,
) -> subprocess.Popen[str]:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.unlink(missing_ok=True)
    source_clause = " or ".join(f"host {item}" for item in sources)
    expression = f"ip6 and udp and host {target} and ({source_clause})"
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


def run_probe(
    sources: list[str],
    target: str,
    target_port: int,
    timeout_seconds: float,
) -> dict[str, object]:
    sockets: list[socket.socket] = []
    identities: list[dict[str, object]] = []
    events: list[dict[str, object]] = []
    try:
        for index, address in enumerate(sources):
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            sock.bind((address, 0))
            sock.setblocking(False)
            sockets.append(sock)
            identities.append(
                make_identity(address, sock.getsockname()[1], index)
            )

        challenged: set[str] = set()
        completed: set[str] = set()

        def poll_packets() -> bool:
            progressed = False
            for sock, identity in zip(sockets, identities):
                try:
                    packet, peer = sock.recvfrom(4096)
                except BlockingIOError:
                    continue
                progressed = True
                opcode = packet[1] if len(packet) >= 2 else None
                txid = (
                    struct.unpack_from("<I", packet, 6)[0]
                    if len(packet) >= 10
                    else None
                )
                events.append({
                    "direction": "candidate_to_probe",
                    "source_ipv6": peer[0],
                    "source_port": peer[1],
                    "target_ipv6": identity["address"],
                    "target_port": identity["port"],
                    "opcode": opcode,
                    "txid": txid,
                    "bytes": len(packet),
                    "sha256": hashlib.sha256(packet).hexdigest(),
                })
                if opcode == OP_BOOTSTRAP_RES:
                    completed.add(str(identity["address"]))
                if opcode != OP_HELLO_REQ or txid is None:
                    continue
                response = (
                    bytes((OP_KAD6HEADER, OP_HELLO_RES))
                    + make_header(identity, txid)
                )
                sock.sendto(response, (target, target_port))
                events.append({
                    "direction": "probe_to_candidate",
                    "kind": "challenge_response",
                    "source_ipv6": identity["address"],
                    "source_port": identity["port"],
                    "opcode": OP_HELLO_RES,
                    "txid": txid,
                    "bytes": len(response),
                    "sha256": hashlib.sha256(response).hexdigest(),
                })
                challenged.add(str(identity["address"]))
            return progressed

        deadline = time.monotonic() + timeout_seconds
        for identity_index, (sock, identity) in enumerate(
            zip(sockets, identities)
        ):
            txid = int.from_bytes(hashlib.sha256(
                b"eSE-V91-S01-initial-v1"
                + str(identity["address"]).encode("ascii")
            ).digest()[:4], "little") or 1
            packet = bytes((OP_KAD6HEADER, OP_BOOTSTRAP_REQ)) + make_header(
                identity,
                txid,
            )
            sock.sendto(packet, (target, target_port))
            events.append({
                "direction": "probe_to_candidate",
                "kind": "initial_bootstrap_req",
                "source_ipv6": identity["address"],
                "source_port": identity["port"],
                "opcode": OP_BOOTSTRAP_REQ,
                "txid": txid,
                "bytes": len(packet),
                "sha256": hashlib.sha256(packet).hexdigest(),
            })
            while (
                str(identity["address"]) not in completed
                and time.monotonic() < deadline
            ):
                if not poll_packets():
                    time.sleep(0.05)
            if str(identity["address"]) not in completed:
                break
            if identity_index + 1 < len(identities):
                time.sleep(1.0)

        grace_deadline = min(deadline, time.monotonic() + 1.0)
        while time.monotonic() < grace_deadline:
            if not poll_packets():
                time.sleep(0.05)
        return {
            "identities": [
                {
                    key: value
                    for key, value in identity.items()
                    if key not in {"kad_id", "endpoint", "record"}
                }
                for identity in identities
            ],
            "events": events,
            "challenged_addresses": sorted(challenged),
            "completed_addresses": sorted(completed),
            "all_challenges_answered": len(challenged) == len(sources),
            "all_bootstraps_completed": len(completed) == len(sources),
        }
    finally:
        for sock in sockets:
            sock.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", action="append", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--target-port", type=int, required=True)
    parser.add_argument("--physical-ipv4", required=True)
    parser.add_argument("--pcap-output", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--timeout-seconds", type=float, default=18.0)
    args = parser.parse_args()

    sources = [str(ipaddress.IPv6Address(item)) for item in args.source]
    if len(sources) != 2 or len(set(sources)) != 2:
        raise ValueError("exactly two distinct --source addresses are required")
    target = str(ipaddress.IPv6Address(args.target))
    packed = [ipaddress.IPv6Address(item).packed for item in sources]
    if packed[0][-4:] != packed[1][-4:] or packed[0] == packed[1]:
        raise ValueError("sources must be distinct and share the low 32 bits")

    interface = S03.find_interface_for_ipv4(args.physical_ipv4)
    for source in sources:
        S03.configure_source_ula(interface, source)
    subprocess.run(
        ("ip", "-6", "route", "replace", f"{target}/128", "dev", interface),
        check=True,
    )
    capture_path = Path(args.pcap_output)
    capture = None
    capture_stderr = ""
    started = time.time()
    try:
        capture_process = start_capture(
            interface,
            sources,
            target,
            capture_path,
        )
        try:
            probe = run_probe(
                sources,
                target,
                args.target_port,
                args.timeout_seconds,
            )
        finally:
            capture_stderr = stop_capture(capture_process)
    finally:
        subprocess.run(
            ("ip", "-6", "route", "del", f"{target}/128", "dev", interface),
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        for source in sources:
            S03.cleanup_source_ula(interface, source)

    frames = S03.read_pcap_udp(capture_path)
    expected_hashes = {
        event["sha256"]
        for event in probe["events"]
        if event["direction"] in {
            "probe_to_candidate",
            "candidate_to_probe",
        }
    }
    unexpected = [
        frame
        for frame in frames
        if frame["payload_sha256"] not in expected_hashes
    ]
    candidate_challenges = [
        event
        for event in probe["events"]
        if event["direction"] == "candidate_to_probe"
        and event["opcode"] == OP_HELLO_REQ
    ]
    challenge_responses = [
        event
        for event in probe["events"]
        if event.get("kind") == "challenge_response"
    ]
    capture_pass = (
        not unexpected
        and len(frames) == len(probe["events"])
        and all(
            sum(
                1
                for frame in frames
                if frame["payload_sha256"] == event["sha256"]
            ) == 1
            for event in probe["events"]
        )
    )
    passed = (
        probe["all_challenges_answered"]
        and probe["all_bootstraps_completed"]
        and len(candidate_challenges) == 2
        and len(challenge_responses) == 2
        and capture_pass
    )
    text_path = capture_path.with_suffix(".txt")
    text = subprocess.run(
        ("tcpdump", "-nn", "-e", "-vvv", "-XX", "-r", str(capture_path)),
        check=False,
        capture_output=True,
        text=True,
    )
    text_path.write_text(text.stdout, encoding="utf-8")
    result = {
        "schema": "ese.v91.s01-probe/v1",
        "case_id": "V91-S01",
        "status": "PASS" if passed else "FAIL",
        "started_at_utc": time.strftime(
            "%Y-%m-%dT%H:%M:%SZ",
            time.gmtime(started),
        ),
        "completed_at_utc": time.strftime(
            "%Y-%m-%dT%H:%M:%SZ",
            time.gmtime(),
        ),
        "collision": {
            "projection": "low-32-bits",
            "value_hex": packed[0][-4:].hex(),
            "source_ipv6s": sources,
            "distinct_128_bit_addresses": packed[0] != packed[1],
        },
        "topology": {
            "profile": "T1",
            "physical_ipv4": args.physical_ipv4,
            "interface": interface,
            "target_ipv6": target,
            "target_port": args.target_port,
            "ipv4_data_route_used": False,
            "overlay_data_route_used": False,
        },
        "probe": probe,
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
