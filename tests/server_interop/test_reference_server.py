"""Independent TLS1.3 client for the initial reference server loopback."""

from __future__ import annotations

import datetime
import hashlib
import pathlib
import re
import socket
import struct
import subprocess
import sys
import tempfile

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


def authenticate(connection, server_pub):
    client_key = ed25519.Ed25519PrivateKey.generate()
    user_hash = bytes([0x37] * 16)
    client_hello = struct.pack("!32s32s16sII16sB", bytes(range(32)), client_key.public_key().public_bytes_raw(),
                               user_hash, 0x80000011, 65536, bytes([0x4A] * 16), 0)
    wire = frame(0x01, client_hello)
    for offset in range(0, len(wire), 7):
        connection.sendall(wire[offset:offset + 7])
    kind, flags, request, server_hello = read_frame(connection)
    require((kind, flags, request) == (0x02, 0, bytes(16)), "canonical SERVER_HELLO")
    nonce, node, epoch, session, generation, chosen, maximum, lease = struct.unpack("!32s32s16s16sQIII", server_hello)
    require((node, generation, chosen, maximum, lease) == (server_pub.public_bytes_raw(), 1, 0x11, 65536, 600)
            and all(any(value) for value in (nonce, epoch, session)), "expected descriptor and selected capabilities")
    digest = hashlib.sha256(client_hello + server_hello).digest()
    exporter = connection.export_keying_material(b"EXPORTER-eSE-server-v1", 32, digest)
    transcript = b"ESE-SERVER-AUTH/1\x00" + exporter + digest
    kind, flags, request, proof = read_frame(connection)
    require((kind, flags, request) == (0x03, 0, bytes(16)), "SERVER_PROOF precedes CLIENT_PROOF")
    server_pub.verify(proof, transcript + b"\x02")
    connection.sendall(frame(0x04, client_key.sign(transcript + b"\x01")))
    require(read_frame(connection) == (0x05, 0, bytes(16), struct.pack("!I", 600)), "ordered AUTH_OK")
    return user_hash


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


def exercise_operations(connection, user_hash, port):
    name = b"Mule ref"
    tags = struct.pack("<BHBH", 2, 1, 1, len(name)) + name
    tags += b"".join(struct.pack("<BHBI", 3, 1, tag, value) for tag, value in ((0x11, 0x3C), (0x20, 0x10), (0xFB, 0x46)))
    login = struct.pack("<16sIHI", user_hash, 0, 4662, 4) + tags
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
    disconnect = bytes([7] * 16)
    require(operation(connection, disconnect, 0x18) == [(0x12, 3, disconnect, b"\x00\x00")],
            "owned reconnect fixture disconnects cleanly")


def main():
    require(len(sys.argv) == 2, "usage: test_reference_server.py <ese-server-ref.exe>")
    with tempfile.TemporaryDirectory(prefix="ese-server-ref-") as scratch:
        files, ca, server_pub = write_identity(pathlib.Path(scratch))
        child = subprocess.Popen([sys.argv[1], "0", *map(str, files), "1"],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                 creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        try:
            match = re.fullmatch(r"LISTENING (\d+)\n", child.stdout.readline())
            require(match is not None, "reference server ready on an owned port")
            port = int(match.group(1))
            context = SSL.Context(SSL.TLS_CLIENT_METHOD)
            context.set_min_proto_version(SSL.TLS1_3_VERSION)
            context.set_max_proto_version(SSL.TLS1_3_VERSION)
            context.set_alpn_protos([b"ese-server/1"])
            context.load_verify_locations(str(files[0]))
            context.set_verify(SSL.VERIFY_PEER, lambda _conn, _cert, _error, _depth, ok: ok)
            with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
                # PyOpenSSL talks directly to the socket. Blocking mode lets
                # OpenSSL perform I/O without a Python-side poll loop.
                sock.setblocking(True)
                connection = SSL.Connection(context, sock)
                connection.set_connect_state()
                connection.set_tlsext_host_name(b"localhost")
                connection.do_handshake()
                require(connection.get_alpn_proto_negotiated() == b"ese-server/1"
                        and connection.get_peer_certificate().to_cryptography().public_bytes(serialization.Encoding.PEM) == ca,
                        "independently trusted reference cert and ALPN")
                exercise_operations(connection, authenticate(connection, server_pub), port)
            stdout, stderr = child.communicate(timeout=5)
            require(child.returncode == 0 and stdout.strip() == "LOGIN_SESSIONS 1" and not stderr,
                    "one authenticated session reported by reference server")
        finally:
            if child.poll() is None:
                child.kill()
                child.communicate()
    print("Reference server TLS1.3, proof, initial eD2K login and idempotency PASS")


if __name__ == "__main__":
    main()
