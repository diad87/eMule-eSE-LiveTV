"""Independent TLS1.3 client for the initial reference server loopback."""

from __future__ import annotations

import datetime
import hashlib
import hmac
import pathlib
import re
import socket
import struct
import subprocess
import sys
import tempfile
import time

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from OpenSSL import SSL


def require(condition, description):
    if not condition:
        raise RuntimeError(description)


def frame(kind, body=b"", request=bytes(16), flags=0):
    return struct.pack("!4sIHH16s", b"ESES", len(body), kind, flags, request) + body


def read_exact(connection, length):
    received = bytearray()
    while len(received) < length:
        data = connection.recv(length - len(received))
        require(data, "unexpected TLS end of stream")
        received.extend(data)
    return bytes(received)


def read_frame(connection):
    magic, count, kind, flags, request = struct.unpack("!4sIHH16s", read_exact(connection, 28))
    require(magic == b"ESES" and count <= 65508, "bad reference response framing")
    return kind, flags, request, read_exact(connection, count)


def wrapped(opcode, body=b""):
    return struct.pack("!BBI", 0xE3, opcode, len(body)) + body


def pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def write_identity(directory):
    tls_key = ed25519.Ed25519PrivateKey.generate()
    server_key = ed25519.Ed25519PrivateKey.generate()
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    certificate = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(tls_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(minutes=20))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(tls_key, algorithm=None)
    )
    files = [directory / name for name in ("certificate.pem", "tls-key.pem", "node-key.pem")]
    for path, data in zip(files, (certificate.public_bytes(serialization.Encoding.PEM), pem(tls_key), pem(server_key))):
        path.write_bytes(data)
    return files, certificate.public_bytes(serialization.Encoding.PEM), server_key.public_key()


def authenticate(connection, server_pub, mode=0, generation_expected=1, client_key=None, rdv=None):
    client_key = client_key or ed25519.Ed25519PrivateKey.generate()
    user_hash = bytes([0x37] * 16)
    client_node = client_key.public_key().public_bytes_raw()
    nonce = bytes(byte ^ generation_expected for byte in range(32))
    expected_caps = 0x15 if rdv is not None else 0x11
    if rdv is not None and rdv.get("pairing"):
        expected_caps |= 0x08
    client_hello = struct.pack("!32s32s16sII16sB", nonce, client_node,
                               user_hash, 0x80000000 | expected_caps, 65536, bytes([0x4A] * 16), mode)
    wire = frame(0x01, client_hello)
    for offset in range(0, len(wire), 7):
        connection.sendall(wire[offset:offset + 7])
    kind, flags, request, server_hello = read_frame(connection)
    require((kind, flags, request) == (0x02, 0, bytes(16)), "canonical SERVER_HELLO")
    nonce, node, epoch, session, generation, chosen, maximum, lease = struct.unpack("!32s32s16s16sQIII", server_hello)
    require((node, generation, chosen, maximum, lease) == (server_pub.public_bytes_raw(), generation_expected, expected_caps, 65536, 600)
            and all(any(value) for value in (nonce, epoch, session)), "expected descriptor and selected capabilities")
    digest = hashlib.sha256(client_hello + server_hello).digest()
    exporter = connection.export_keying_material(b"EXPORTER-eSE-server-v1", 32, digest)
    transcript = b"ESE-SERVER-AUTH/1\x00" + exporter + digest
    kind, flags, request, proof = read_frame(connection)
    require((kind, flags, request) == (0x03, 0, bytes(16)), "SERVER_PROOF precedes CLIENT_PROOF")
    server_pub.verify(proof, transcript + b"\x02")
    connection.sendall(frame(0x04, client_key.sign(transcript + b"\x01")))
    require(read_frame(connection) == (0x05, 0, bytes(16), struct.pack("!I", 600)), "ordered AUTH_OK")
    if rdv is not None:
        rdv.update(epoch=epoch, session=session, generation=generation,
                   key=connection.export_keying_material(b"EXPORTER-eSE-rdv2-v1", 32, digest))
    return user_hash, client_node


def operation(connection, request, opcode, body=b""):
    wire = frame(0x10, wrapped(opcode, body), request)
    connection.sendall(wire)
    first = read_frame(connection)
    require(first[2] == request, "correlated response")
    if first[1] == 3:
        return [first]
    require(first[1] == 1, "first fragment response flags")
    last = read_frame(connection)
    require(last[1:3] == (3, request), "final fragment response flags")
    return [first, last]


def login_command(user_hash):
    name = b"Mule ref"
    tags = struct.pack("<BHBH", 2, 1, 1, len(name)) + name
    tags += b"".join(struct.pack("<BHBI", 3, 1, tag, value) for tag, value in ((0x11, 0x3C), (0x20, 0x10), (0xFB, 0x46)))
    return struct.pack("<16sIHI", user_hash, 0, 4662, 4) + tags


def exercise_operations(connection, user_hash, port):
    login = login_command(user_hash)
    request = bytes([1] * 16)
    wrong = bytes([0x38]) + login[1:]
    require(operation(connection, request, 1, wrong) == [(0xFF, 3, request, struct.pack("!HI", 1, 0))],
            "authenticated client cannot claim a different login user hash")
    request = bytes([2] * 16)
    accepted = operation(connection, request, 1, login)
    require(len(accepted) == 2 and accepted[0] == (0x11, 1, request, wrapped(0x40, struct.pack("<I", 1)))
            and accepted[1][0:3] == (0x11, 3, request) and accepted[1][3][0:2] == bytes([0xE3, 0x41])
            and accepted[1][3][22:32] == struct.pack("<4sHI", socket.inet_aton("127.0.0.1"), port, 0),
            "reference LOGIN emits bounded classic IDCHANGE and SERVERIDENT")
    require(operation(connection, request, 1, login) == accepted, "same login request ID replays identical events")
    require(operation(connection, request, 1, wrong) == [(0xFF, 3, request, struct.pack("!HI", 10, 0))],
            "conflicting payload cannot reuse a completed login request")
    duplicate = bytes([3] * 16)
    require(operation(connection, duplicate, 1, login) == [(0xFF, 3, duplicate, struct.pack("!HI", 13, 0))],
            "another request cannot perform a second logical login")
    listing = bytes([4] * 16)
    require(operation(connection, listing, 0x14) == [(0x11, 3, listing, wrapped(0x32, b"\x00"))],
            "classic empty server list")
    legacy_upload = bytes([0x31] * 16)
    require(operation(connection, legacy_upload, 0x15) == [(0xFF, 3, legacy_upload, struct.pack("!HI", 2, 0))],
            "secure channel cannot bypass atomic publication with OFFERFILES")
    unknown = bytes([5] * 16)
    ping = bytes([6] * 16)
    nonce = bytes(range(16))
    connection.sendall(frame(0x7777, request=unknown) + frame(0xFE, nonce, ping))
    require(read_frame(connection) == (0xFF, 3, unknown, struct.pack("!HI", 2, 0))
            and read_frame(connection) == (0xFD, 3, ping, nonce), "unknown request is recoverable and does not desynchronize")
    exercise_publication(connection)


def disconnect_client(connection):
    disconnect = bytes([7] * 16)
    require(operation(connection, disconnect, 0x18) == [(0x12, 3, disconnect, b"\x00\x00")],
            "owned reconnect fixture disconnects cleanly")


def publish_operation(connection, sequence, kind, body, expected_kind, expected_body):
    request = sequence.to_bytes(16, byteorder="big")
    connection.sendall(frame(kind, body, request))
    require(read_frame(connection) == (expected_kind, 3, request, expected_body),
            f"publication type {kind} exact response for operation {sequence}")


def exercise_publication(connection):
    name = "Málaga eSE".encode("utf-8")
    record = bytes([0xA1] * 16) + struct.pack("!QH", 4294967400, len(name)) + name + b"\x02"
    digest = hashlib.sha256(record).digest()
    previous = struct.pack("!QI", 0, 0) + hashlib.sha256(b"").digest()
    proposed = struct.pack("!QI32s", 1, 1, digest)
    chunk = struct.pack("!QIH", 1, 0, 1) + record
    commit = struct.pack("!Q32s", 1, digest)
    ack = b"\x00\x00"
    publish_operation(connection, 20, 0x23, b"", 0x24, previous)
    publish_operation(connection, 21, 0x20, proposed, 0x12, ack)
    publish_operation(connection, 22, 0x21, chunk[:-1], 0xFF, struct.pack("!HI", 1, 0))
    publish_operation(connection, 23, 0x21, chunk, 0x12, ack)
    publish_operation(connection, 24, 0x21, chunk, 0x12, ack)
    publish_operation(connection, 25, 0x23, b"", 0x24, previous)
    publish_operation(connection, 26, 0x22, commit, 0x12, ack)
    publish_operation(connection, 27, 0x22, commit, 0x12, ack)
    publish_operation(connection, 28, 0x23, b"", 0x24, proposed)

    new_state = struct.pack("!QI32s", 2, 1, digest)
    new_chunk = struct.pack("!QIH", 2, 0, 1) + record
    publish_operation(connection, 29, 0x20, new_state, 0x12, ack)
    publish_operation(connection, 30, 0x21, new_chunk, 0x12, ack)
    publish_operation(connection, 31, 0x21, new_chunk[:-1] + b"\x01", 0xFF, struct.pack("!HI", 10, 0))
    publish_operation(connection, 32, 0x22, struct.pack("!Q32s", 2, digest), 0xFF, struct.pack("!HI", 13, 0))
    publish_operation(connection, 33, 0x23, b"", 0x24, proposed)

def connect_reference(port, files, expected_certificate, callback, host="127.0.0.1"):
    context = SSL.Context(SSL.TLS_CLIENT_METHOD)
    context.set_min_proto_version(SSL.TLS1_3_VERSION)
    context.set_max_proto_version(SSL.TLS1_3_VERSION)
    context.set_alpn_protos([b"ese-server/1"])
    context.load_verify_locations(str(files[0]))
    context.set_verify(SSL.VERIFY_PEER, lambda _conn, _cert, _error, _depth, ok: ok)
    with socket.create_connection((host, port), timeout=5) as sock:
        # PyOpenSSL talks directly to the socket. Blocking mode lets
        # OpenSSL perform I/O without a Python-side poll loop.
        sock.setblocking(True)
        connection = SSL.Connection(context, sock)
        connection.set_connect_state()
        connection.set_tlsext_host_name(b"localhost")
        connection.do_handshake()
        require(connection.get_alpn_proto_negotiated() == b"ese-server/1"
                and connection.get_peer_certificate().to_cryptography().public_bytes(serialization.Encoding.PEM) == expected_certificate,
                "independently trusted reference cert and ALPN")
        callback(connection)


def rdv_packet(context, kind, sequence, nonce, cookie=bytes(32), family=4):
    prefix = struct.pack("!8sBBH16s16sQQ16s32s", b"ESERDV2\0", kind, family, 0, context["epoch"],
                         context["session"], context["generation"], sequence, nonce, cookie)
    return prefix + hmac.digest(context["key"], prefix, "sha256")


def ping(connection, sequence):
    token = sequence.to_bytes(16, "big")
    connection.sendall(frame(0xFE, token, token))
    require(read_frame(connection) == (0xFD, 3, token, token), "no unexpected TLS notification before PONG")


def no_datagram(udp):
    try:
        udp.recvfrom(512)
    except TimeoutError:
        return
    raise RuntimeError("unexpected UDP reply")


def verify_prelogin_silent(context, endpoint):
    nonce = bytes(range(1, 17))
    ipv6 = endpoint[0] == "::1"
    request = rdv_packet(context, 1, 1, nonce, family=6 if ipv6 else 4)
    with socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_DGRAM) as owned:
        owned.bind((endpoint[0], 0))
        owned.settimeout(0.08)
        owned.sendto(request, endpoint)
        no_datagram(owned)  # AUTH completed, but the application has not logged in.


def established_udp(connection, context, endpoint, owned):
    socket_family = owned.family
    wire_family = 6 if socket_family == socket.AF_INET6 else 4
    with socket.socket(socket_family, socket.SOCK_DGRAM) as wrong:
        for udp in (owned, wrong):
            udp.bind((endpoint[0], 0))
            udp.settimeout(0.08)
        nonce = bytes(range(1, 17))
        request = rdv_packet(context, 1, 1, nonce, family=wire_family)
        bad = request[:-1] + bytes([request[-1] ^ 1])
        for rejected in (request[:-1], request + b"\0", bad):
            owned.sendto(rejected, endpoint)
        no_datagram(owned)
        ping(connection, 140)
        owned.sendto(request, endpoint)
        owned.settimeout(2)
        challenge, sender = owned.recvfrom(512)
        require(sender[:2] == endpoint[:2] and len(challenge) == 140 and challenge[8] == 2
                and challenge[:8] == b"ESERDV2\0" and challenge[9:76] == request[9:76]
                and any(challenge[76:108]) and hmac.compare_digest(challenge[108:], hmac.digest(context["key"], challenge[:108], "sha256")),
                "exact authenticated one-to-one RDV2 challenge")
        ping(connection, 141)
        echo = rdv_packet(context, 3, 2, nonce, challenge[76:108], wire_family)
        wrong.sendto(echo, endpoint)
        no_datagram(wrong)
        ping(connection, 142)  # no REG_STATUS from the other local port
        owned.sendto(echo, endpoint)
        first = read_frame(connection)
        expected = struct.pack("!BB", wire_family, wire_family) + socket.inet_pton(socket_family, endpoint[0])
        expected += struct.pack("!H", owned.getsockname()[1])
        offset = len(expected)
        require(first[:3] == (0x36, 0, bytes(16)) and len(first[3]) == offset + 4 and first[3][:offset] == expected,
                "same-port ECHO reports observed endpoint over TLS only")
        first_ttl = struct.unpack("!I", first[3][offset:])[0]
        require(55000 < first_ttl <= 60000, "bounded UDP lease")
        time.sleep(0.12)
        owned.sendto(echo, endpoint)
        second = read_frame(connection)
        require(second[:3] == first[:3] and second[3][:offset] == expected and
                0 < struct.unpack("!I", second[3][offset:])[0] < first_ttl, "duplicate ECHO does not refresh TTL")
        return nonce


def exercise_pairing(requester, target, requester_node, target_node, requester_socket, target_socket, retire_target,
                     before_consent=None):
    file = bytes([0xA1] * 16) + struct.pack("!Q", 4294967400)
    token_id = (250).to_bytes(16, "big")
    issue = frame(0x30, target_node + file + b"\x01", token_id)
    requester.sendall(issue)
    voucher = read_frame(requester)
    require(voucher[:3] == (0x31, 3, token_id) and len(voucher[3]) == 68 and voucher[3][32:64] == target_node,
            "voucher contains target identity and no endpoint")
    voucher_token = voucher[3][:32]
    require(any(voucher_token) and 0 < struct.unpack("!I", voucher[3][64:])[0] <= 30000, "voucher bounded expiry")
    requester.sendall(issue)
    repeated = read_frame(requester)
    require(repeated[:3] == voucher[:3] and repeated[3][:64] == voucher[3][:64], "same request reuses one voucher")
    requester.sendall(frame(0xFE, token_id, token_id))
    require(read_frame(requester) == (0xFF, 3, token_id, struct.pack("!HI", 10, 0)),
            "control and ordinary request IDs cannot be reused across operation types")
    attempt = bytes([0x11] * 16)
    nonce = bytes([0x22] * 16)
    generation = 81
    pair_body = voucher_token + attempt + struct.pack("!Q", generation) + nonce
    pair_request = (251).to_bytes(16, "big")
    wrong_id = (252).to_bytes(16, "big")
    target.sendall(frame(0x32, pair_body, wrong_id))
    require(read_frame(target) == (0xFF, 3, wrong_id, struct.pack("!HI", 11, 0)),
            "other TLS session cannot redeem copied voucher")
    pairing = frame(0x32, pair_body, pair_request)
    requester.sendall(pairing + pairing)
    query = read_frame(target)
    require(query[:3] == (0x33, 0, bytes(16)) and len(query[3]) == 77 and
            query[3][16:73] == requester_node + file + b"\x01" and
            0 < struct.unpack("!I", query[3][73:])[0] <= 10000, "one consent query omits endpoint")
    transaction = query[3][:16]
    ping(target, 253)
    if before_consent:
        before_consent()
    target_attempt = bytes([0x33] * 16)
    target_generation = 19
    consent_request = (254).to_bytes(16, "big")
    target.sendall(frame(0x34, transaction + b"\x01" + target_attempt + struct.pack("!Q", target_generation), consent_request))
    require(read_frame(target) == (0x12, 3, consent_request, bytes(2)), "target receives exactly one consent ACK")

    def result(connection, expected_flags, request_id, expected_attempt, expected_generation, peer, endpoint):
        response = read_frame(connection)
        prefix = transaction + expected_attempt + struct.pack("!Q", expected_generation) + peer
        host, port, *_ = endpoint.getsockname()
        family = 6 if endpoint.family == socket.AF_INET6 else 4
        address = bytes([1, family]) + socket.inet_pton(endpoint.family, host) + struct.pack("!H", port)
        require(response[:3] == (0x35, expected_flags, request_id) and response[3][:72] == prefix
                and 0 < struct.unpack("!I", response[3][72:76])[0] <= 10000 and response[3][76:] == address,
                "paired response carries only the proved other endpoint and local attempt/generation")

    result(requester, 3, pair_request, attempt, generation, target_node, target_socket)
    result(target, 0, bytes(16), target_attempt, target_generation, requester_node, requester_socket)
    requester.sendall(pairing)
    result(requester, 3, pair_request, attempt, generation, target_node, target_socket)
    ping(target, 255)
    replay_id = (256).to_bytes(16, "big")
    requester.sendall(frame(0x32, pair_body, replay_id))
    require(read_frame(requester) == (0xFF, 3, replay_id, struct.pack("!HI", 6, 0)),
            "new request cannot consume used voucher a second time")

    denied_issue = (257).to_bytes(16, "big")
    requester.sendall(frame(0x30, target_node + file + b"\x01", denied_issue))
    denied_voucher = read_frame(requester)
    require(denied_voucher[:3] == (0x31, 3, denied_issue), "independent voucher for denial")
    denied_pair = (258).to_bytes(16, "big")
    requester.sendall(frame(0x32, denied_voucher[3][:32] + pair_body[32:], denied_pair))
    denied_query = read_frame(target)
    require(denied_query[:3] == (0x33, 0, bytes(16)) and denied_query[3][:16] != transaction, "fresh consent transaction")
    denied_consent = (259).to_bytes(16, "big")
    target.sendall(frame(0x34, denied_query[3][:16] + bytes(25), denied_consent))
    require(read_frame(target) == (0x12, 3, denied_consent, bytes(2))
            and read_frame(requester) == (0xFF, 3, denied_pair, struct.pack("!HI", 7, 0)),
            "explicit denial releases no endpoints")
    ping(target, 260)

    def start_additional(issuance, pairing_id):
        request_id = issuance.to_bytes(16, "big")
        requester.sendall(frame(0x30, target_node + file + b"\x01", request_id))
        token = read_frame(requester)
        require(token[:3] == (0x31, 3, request_id), "eligible publisher issues requested voucher")
        pair_id = pairing_id.to_bytes(16, "big")
        requester.sendall(frame(0x32, token[3][:32] + pair_body[32:], pair_id))
        require(read_frame(target)[:3] == (0x33, 0, bytes(16)), "one further prompt")
        return pair_id

    expired = start_additional(261, 262)
    before = time.monotonic()
    require(read_frame(requester) == (0xFF, 3, expired, struct.pack("!HI", 5, 0))
            and 9 < time.monotonic() - before < 12, "no consent expires without releasing endpoints")
    withdrawn = start_additional(263, 264)
    retire_target()
    require(read_frame(requester) == (0xFF, 3, withdrawn, struct.pack("!HI", 11, 0)),
            "withdrawing target invalidates pending pairing before endpoint disclosure")


def main():
    require(len(sys.argv) in (2, 3), "usage: test_reference_server.py <ese-server-ref.exe> [ipv6]")
    ipv6 = len(sys.argv) == 3 and sys.argv[2] == "ipv6"
    family = socket.AF_INET6 if ipv6 else socket.AF_INET
    host = "::1" if ipv6 else "127.0.0.1"
    with tempfile.TemporaryDirectory(prefix="ese-server-ref-") as scratch:
        files, ca, server_pub = write_identity(pathlib.Path(scratch))
        child = subprocess.Popen([sys.argv[1], "0", *map(str, files), "3", "0"],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                 creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        try:
            match = re.fullmatch(r"LISTENING (\d+) RDV (\d+)\n", child.stdout.readline())
            require(match is not None, "reference server ready on an owned port")
            port = int(match.group(1))
            rdv_endpoint = (host, int(match.group(2)))
            primary_key = ed25519.Ed25519PrivateKey.generate()

            def exercise_primary(primary):
                user_hash, primary_node = authenticate(primary, server_pub, client_key=primary_key)
                exercise_operations(primary, user_hash, port)

                def exercise_auxiliary(auxiliary):
                    auxiliary_rdv = {"pairing": True}
                    auxiliary_hash, auxiliary_node = authenticate(auxiliary, server_pub, mode=1, generation_expected=2,
                                                                  rdv=auxiliary_rdv)
                    request = bytes([1] * 16)
                    require(len(operation(auxiliary, request, 1, login_command(auxiliary_hash))) == 2,
                            "auxiliary performs restricted authenticated login")
                    publish_operation(auxiliary, 21, 0x23, b"", 0xFF, struct.pack("!HI", 13, 0))
                    key = bytes([0xA1] * 16) + struct.pack("!Q", 4294967400)
                    publish_operation(auxiliary, 22, 0x14, key, 0x15, b"\x00\x01" + primary_node + user_hash)

                    def replace_primary(replacement):
                        rdv_context = {"pairing": True}
                        replacement_hash, replacement_node = authenticate(
                            replacement, server_pub, generation_expected=3, client_key=primary_key, rdv=rdv_context)
                        verify_prelogin_silent(rdv_context, rdv_endpoint)
                        require(replacement_node == primary_node and replacement_hash == user_hash
                                and len(operation(replacement, request, 1, login_command(replacement_hash))) == 2,
                                "same verified node reconnects with new primary generation")
                        publish_operation(primary, 24, 0x23, b"", 0xFF, struct.pack("!HI", 13, 0))
                        publish_operation(auxiliary, 23, 0x14, key, 0x15, b"\x00\x01" + primary_node + user_hash)
                        with socket.socket(family, socket.SOCK_DGRAM) as requester_udp, \
                                socket.socket(family, socket.SOCK_DGRAM) as target_udp, \
                                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as second_family:
                            established_udp(auxiliary, auxiliary_rdv, rdv_endpoint, requester_udp)
                            target_nonce = established_udp(replacement, rdv_context, rdv_endpoint, target_udp)
                            if ipv6:
                                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as same_port_other_family:
                                    same_port_other_family.bind(("127.0.0.1", target_udp.getsockname()[1]))
                                    same_port_other_family.settimeout(0.08)
                                    same_port_other_family.sendto(rdv_packet(rdv_context, 1, 3, target_nonce, family=6),
                                                                  ("127.0.0.1", rdv_endpoint[1]))
                                    no_datagram(same_port_other_family)
                                    ping(replacement, 148)

                            def register_other_family():
                                established_udp(replacement, rdv_context, ("127.0.0.1", rdv_endpoint[1]), second_family)

                            exercise_pairing(auxiliary, replacement, auxiliary_node, replacement_node,
                                             requester_udp, target_udp, lambda: disconnect_client(replacement),
                                             register_other_family if ipv6 else None)
                            target_udp.settimeout(0.08)
                            target_udp.sendto(rdv_packet(rdv_context, 1, 3, target_nonce, family=6 if ipv6 else 4), rdv_endpoint)
                            no_datagram(target_udp)
                        publish_operation(auxiliary, 24, 0x14, key, 0x15, b"\x00\x00")

                    connect_reference(port, files, ca, replace_primary, host)
                    disconnect_client(auxiliary)

                connect_reference(port, files, ca, exercise_auxiliary, host)

            connect_reference(port, files, ca, exercise_primary)
            stdout, stderr = child.communicate(timeout=5)
            require(child.returncode == 0 and stdout.strip() == "LOGIN_SESSIONS 3" and not stderr,
                    "three authenticated sessions reported by reference server")
        finally:
            if child.poll() is None:
                child.kill()
                child.communicate()
    print(f"Reference server IPv{6 if ipv6 else 4} TLS1.3, publication, UDP return proof and consent PASS")


if __name__ == "__main__":
    main()
