#!/usr/bin/env python3
"""V91-S02 physical Kad6 temporal-IPv6-reuse qualification probe."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import ipaddress
import json
import signal
import socket
import subprocess
import time
from collections import Counter
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


OP_KAD6HEADER = 0xE6
OP_BOOTSTRAP_REQ = 0x02
OP_BOOTSTRAP_RES = 0x0A
OP_HELLO_REQ = 0x12
OP_HELLO_RES = 0x1A
ROUTER_DOMAIN = b"eSE-Kad6-RouterRecord-v1"


def load_s01():
    path = Path(__file__).with_name("v91_s01_collision_probe.py")
    spec = importlib.util.spec_from_file_location("v91_s01_probe", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load the shared Kad6 collision probe")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


S01 = load_s01()
S03 = S01.S03


def make_identity(
    address: str,
    udp_port: int,
    label: bytes,
    epoch: int,
    valid_from: int,
    valid_until: int,
) -> dict[str, object]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        Encoding.Raw,
        PublicFormat.Raw,
    )
    kad_id = hashlib.sha256(
        b"eSE-V91-S02-KadId-v1" + label + public_key
    ).digest()[:16]
    endpoint = S01.make_endpoint(address, udp_port, valid_until)
    record_body = (
        b"\x01\x00\x01\x00"
        + kad_id
        + public_key
        + S01.u64(epoch)
        + S01.u64(0)
        + S01.u64(valid_from)
        + S01.u64(valid_until)
        + endpoint
    )
    record = record_body + private_key.sign(ROUTER_DOMAIN + record_body)
    return {
        "label": label.decode("ascii"),
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
    }


def event_for_packet(
    direction: str,
    packet: bytes,
    source_ipv6: str,
    source_port: int,
    target_ipv6: str,
    target_port: int,
    phase: str,
    kind: str = "",
) -> dict[str, object]:
    event: dict[str, object] = {
        "direction": direction,
        "phase": phase,
        "source_ipv6": source_ipv6,
        "source_port": source_port,
        "target_ipv6": target_ipv6,
        "target_port": target_port,
        "opcode": packet[1] if len(packet) >= 2 else None,
        "txid": (
            int.from_bytes(packet[6:10], "little")
            if len(packet) >= 10
            else None
        ),
        "bytes": len(packet),
        "sha256": hashlib.sha256(packet).hexdigest(),
    }
    if kind:
        event["kind"] = kind
    return event


def receive_one(
    sock: socket.socket,
    source: str,
    target: str,
    target_port: int,
    phase: str,
    events: list[dict[str, object]],
) -> tuple[bytes, tuple[str, int]] | None:
    try:
        packet, peer = sock.recvfrom(4096)
    except BlockingIOError:
        return None
    events.append(event_for_packet(
        "candidate_to_probe",
        packet,
        peer[0],
        peer[1],
        source,
        sock.getsockname()[1],
        phase,
    ))
    return packet, (peer[0], peer[1])


def run_probe(
    source: str,
    target: str,
    target_port: int,
    timeout_seconds: float,
    old_lifetime_seconds: int,
    expiry_grace_seconds: float,
    replay_observation_seconds: float,
) -> dict[str, object]:
    events: list[dict[str, object]] = []
    phases: list[dict[str, object]] = []
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        sock.bind((source, 0))
        sock.setblocking(False)
        source_port = sock.getsockname()[1]
        created = int(time.time())
        identity_a = make_identity(
            source,
            source_port,
            b"A",
            created,
            created - 5,
            created + old_lifetime_seconds,
        )
        identity_b = make_identity(
            source,
            source_port,
            b"B",
            created + 1,
            created - 5,
            created + 600,
        )
        identities = (identity_a, identity_b)

        def send_bootstrap(
            identity: dict[str, object],
            txid: int,
            phase: str,
            kind: str,
        ) -> bytes:
            packet = (
                bytes((OP_KAD6HEADER, OP_BOOTSTRAP_REQ))
                + S01.make_header(identity, txid)
            )
            sock.sendto(packet, (target, target_port))
            events.append(event_for_packet(
                "probe_to_candidate",
                packet,
                source,
                source_port,
                target,
                target_port,
                phase,
                kind,
            ))
            return packet

        def verify(
            identity: dict[str, object],
            txid: int,
            phase: str,
        ) -> tuple[bool, bool, bool]:
            challenged = False
            completed = False
            semantic_before_challenge = False
            deadline = time.monotonic() + timeout_seconds
            while time.monotonic() < deadline and not completed:
                received = receive_one(
                    sock,
                    source,
                    target,
                    target_port,
                    phase,
                    events,
                )
                if received is None:
                    time.sleep(0.05)
                    continue
                packet, _ = received
                opcode = packet[1] if len(packet) >= 2 else None
                packet_txid = (
                    int.from_bytes(packet[6:10], "little")
                    if len(packet) >= 10
                    else None
                )
                if opcode == OP_BOOTSTRAP_RES and packet_txid == txid:
                    semantic_before_challenge = not challenged
                    completed = True
                    continue
                if opcode != OP_HELLO_REQ or packet_txid is None:
                    continue
                challenged = True
                response = (
                    bytes((OP_KAD6HEADER, OP_HELLO_RES))
                    + S01.make_header(identity, packet_txid)
                )
                sock.sendto(response, (target, target_port))
                events.append(event_for_packet(
                    "probe_to_candidate",
                    response,
                    source,
                    source_port,
                    target,
                    target_port,
                    phase,
                    "challenge_response",
                ))
            return challenged, completed, semantic_before_challenge

        txid_a = 0x52020001
        old_packet = send_bootstrap(
            identity_a,
            txid_a,
            "identity_a",
            "initial_old_identity",
        )
        a_challenged, a_completed, a_early = verify(
            identity_a,
            txid_a,
            "identity_a",
        )
        phases.append({
            "name": "identity_a",
            "completed_at_utc": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ",
                time.gmtime(),
            ),
            "challenged": a_challenged,
            "bootstrap_completed": a_completed,
            "semantic_before_challenge": a_early,
        })

        expiry_target = (
            int(identity_a["valid_until"]) + expiry_grace_seconds
        )
        while time.time() < expiry_target:
            receive_one(
                sock,
                source,
                target,
                target_port,
                "expiry_wait",
                events,
            )
            time.sleep(0.05)
        phases.append({
            "name": "old_record_expired",
            "completed_at_utc": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ",
                time.gmtime(),
            ),
            "old_valid_until": identity_a["valid_until"],
            "expiry_grace_seconds": expiry_grace_seconds,
        })

        txid_b = 0x52020002
        send_bootstrap(
            identity_b,
            txid_b,
            "identity_b",
            "reused_address_new_identity",
        )
        b_challenged, b_completed, b_early = verify(
            identity_b,
            txid_b,
            "identity_b",
        )
        phases.append({
            "name": "identity_b",
            "completed_at_utc": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ",
                time.gmtime(),
            ),
            "challenged": b_challenged,
            "bootstrap_completed": b_completed,
            "semantic_before_challenge": b_early,
        })

        replay_started = time.monotonic()
        sock.sendto(old_packet, (target, target_port))
        events.append(event_for_packet(
            "probe_to_candidate",
            old_packet,
            source,
            source_port,
            target,
            target_port,
            "stale_replay",
            "expired_old_record_replay",
        ))
        replay_challenges = 0
        replay_semantic = 0
        deadline = replay_started + replay_observation_seconds
        while time.monotonic() < deadline:
            received = receive_one(
                sock,
                source,
                target,
                target_port,
                "stale_replay",
                events,
            )
            if received is None:
                time.sleep(0.05)
                continue
            packet, _ = received
            opcode = packet[1] if len(packet) >= 2 else None
            if opcode == OP_HELLO_REQ:
                replay_challenges += 1
            elif opcode == OP_BOOTSTRAP_RES:
                replay_semantic += 1
        phases.append({
            "name": "stale_replay",
            "completed_at_utc": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ",
                time.gmtime(),
            ),
            "observation_seconds": replay_observation_seconds,
            "challenge_count": replay_challenges,
            "semantic_response_count": replay_semantic,
        })

        return {
            "identities": [
                {
                    key: value
                    for key, value in identity.items()
                    if key not in {"kad_id", "endpoint", "record"}
                }
                for identity in identities
            ],
            "same_ipv6": identity_a["address"] == identity_b["address"],
            "same_udp_port": identity_a["port"] == identity_b["port"],
            "distinct_node_ids": (
                identity_a["kad_id"] != identity_b["kad_id"]
            ),
            "strictly_increasing_epoch": (
                int(identity_b["epoch"]) > int(identity_a["epoch"])
            ),
            "identity_a_challenged": a_challenged,
            "identity_a_completed": a_completed,
            "identity_b_challenged": b_challenged,
            "identity_b_completed": b_completed,
            "identity_b_inherited_credit": b_early,
            "stale_replay_challenge_count": replay_challenges,
            "stale_replay_semantic_response_count": replay_semantic,
            "phases": phases,
            "events": events,
        }
    finally:
        sock.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--target-port", type=int, required=True)
    parser.add_argument("--physical-ipv4", required=True)
    parser.add_argument("--pcap-output", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--timeout-seconds", type=float, default=15.0)
    parser.add_argument("--old-lifetime-seconds", type=int, default=8)
    parser.add_argument("--expiry-grace-seconds", type=float, default=2.5)
    parser.add_argument("--replay-observation-seconds", type=float, default=3.0)
    args = parser.parse_args()

    source = str(ipaddress.IPv6Address(args.source))
    target = str(ipaddress.IPv6Address(args.target))
    interface = S03.find_interface_for_ipv4(args.physical_ipv4)
    S03.configure_source_ula(interface, source)
    subprocess.run(
        ("ip", "-6", "route", "replace", f"{target}/128", "dev", interface),
        check=True,
    )
    capture_path = Path(args.pcap_output)
    capture_process = None
    capture_stderr = ""
    started = time.time()
    try:
        capture_process = S01.start_capture(
            interface,
            [source],
            target,
            capture_path,
        )
        try:
            probe = run_probe(
                source,
                target,
                args.target_port,
                args.timeout_seconds,
                args.old_lifetime_seconds,
                args.expiry_grace_seconds,
                args.replay_observation_seconds,
            )
        finally:
            capture_stderr = S01.stop_capture(capture_process)
    finally:
        subprocess.run(
            ("ip", "-6", "route", "del", f"{target}/128", "dev", interface),
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
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
    capture_pass = (
        not unexpected
        and len(frames) == len(probe["events"])
        and Counter(
            frame["payload_sha256"] for frame in frames
        ) == Counter(
            event["sha256"] for event in probe["events"]
        )
    )
    passed = (
        probe["same_ipv6"]
        and probe["same_udp_port"]
        and probe["distinct_node_ids"]
        and probe["strictly_increasing_epoch"]
        and probe["identity_a_challenged"]
        and probe["identity_a_completed"]
        and probe["identity_b_challenged"]
        and probe["identity_b_completed"]
        and not probe["identity_b_inherited_credit"]
        and probe["stale_replay_challenge_count"] == 0
        and probe["stale_replay_semantic_response_count"] == 0
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
        "schema": "ese.v91.s02-probe/v1",
        "case_id": "V91-S02",
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
            "physical_ipv4": args.physical_ipv4,
            "interface": interface,
            "source_ipv6": source,
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
