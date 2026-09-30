#!/usr/bin/env python3
"""Structural gate for the observational external interoperability catalog."""

from __future__ import annotations

import csv
import hashlib
import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
CATALOG = ROOT / "docs" / "protocol" / "EXTERNAL_INTEROP_CATALOG.csv"
LAB = ROOT / "docs" / "SERVER_CONFORMANCE_LAB.md"
V98 = ROOT / "docs" / "V9.8_ECOSYSTEM_INTEROP_ENVELOPE.md"
ROADMAP = ROOT / "docs" / "EMULEAI_INTEGRATED_RELEASE_ROADMAP.md"
REGISTRY = ROOT / "docs" / "protocol" / "PROTOCOL_REGISTRY.md"
INDEX = ROOT / "docs" / "INDEX.md"
V9_SPEC = ROOT / "docs" / "V9_RELEASE_SPECIFICATION.md"
V94_PLAN = ROOT / "docs" / "V9.4_DEVELOPMENT_AND_TEST_PLAN.md"
ADR93 = ROOT / "docs" / "adr" / "ADR-0001-tesis-vs-especificacion-9.3.md"
REGISTRY_CHECKER = ROOT / "tools" / "check_protocol_registry.py"
OWNED_REGISTRIES = (
    ROOT / "docs" / "protocol" / "OPCODES.csv",
    ROOT / "docs" / "protocol" / "TAGS.csv",
    ROOT / "docs" / "protocol" / "CAPABILITIES.csv",
)

EXPECTED_FIELDS = [
    "id",
    "implementation",
    "reference_version",
    "reference_commit",
    "namespace",
    "value",
    "symbol",
    "direction",
    "wire_shape",
    "classification",
    "local_relation",
    "target",
    "send_policy",
    "security_status",
    "sources",
]
# Full-row fingerprint: freezes classification, provenance, target, emission
# policy and security verdict in addition to the byte contracts below.
EXPECTED_CATALOG_SHA256 = "b942dbdfd00ff1d674ef74f080235aafae8afd50f419e3bde5fae82a3d3888b2"
ALLOWED_CLASSIFICATIONS = {
    "compatible-candidate",
    "dialect-different",
    "hint-only",
    "needs-byte-comparison",
    "partial-implementation",
    "unsafe-as-is",
    "watch-only",
    "exact-alias",
    "numeric-collision",
}
ALLOWED_TARGETS = {"9.7", "9.8", "watch"}
ALLOWED_SEND_POLICIES = {
    "receiver-first",
    "never-send-v1",
    "do-not-send",
    "defer-to-v9.8",
}

NAT_V1_SYMBOLS = {
    "PR_NAT",
    "ST_NAT_PORT",
    "SRV_TCPFLG_NAT_RENDEZVOUS",
    "OP_NAT_REGISTER",
    "OP_NAT_KEEPALIVE",
    "OP_NAT_SYNC2",
    "OP_NAT_REGISTER_IPV6",
    "OP_NAT_SYNC_IPV6",
    "OP_NAT_REGISTER_EX",
    "OP_NAT_PING",
    "OP_NAT_SYNC",
    "OP_NAT_SYNC_EX",
    "OP_NAT_FAILED",
}

NAMESPACE_EQUIVALENTS = {
    "SERVER-LOGIN-TAG": "TAG-ED2K",
    "SERVER-IDENT-TAG": "TAG-ED2K",
}

CANONICAL_CONTRACTS = {
    "CT_MOD_MISCOPTIONS": (
        "TAG-ED2K",
        "0xAA",
        "client<->client",
        "old tag; UINT32 capability bits",
    ),
    "CT_MOD_IP_V6": (
        "TAG-ED2K",
        "0xAE",
        "client<->client",
        "old tag in peer hello; HASH16 network-order IPv6",
    ),
    "SRVCAP_IPV6": (
        "SERVER-LOGIN-FLAG",
        "0x1000",
        "client->server",
        "bit in CT_SERVER_FLAGS 0x20",
    ),
    "IPV6_SOURCE_SENTINEL": (
        "SERVER-SOURCE-RECORD",
        "0xFFFFFFFF",
        "server->client",
        "ClientID 0xFFFFFFFF u32_le + port u16_le; in *_OBFU only: "
        "cryptFlags u8 + userHash[16] iff bit 0x80; if sentinel: IPv6[16] "
        "network-order ALWAYS LAST",
    ),
    "OP_CALLBACKREQUESTED_IPV6": (
        "ED2K-SERVER-TCP",
        "0x26",
        "server->client",
        "IPv6[16] + TCP port u16 little-endian",
    ),
    "CT_MOD_SVR_IP_V6": (
        "TAG-ED2K",
        "0xAF",
        "server->client",
        "OP_SERVERIDENT old/new tag; HASH16",
    ),
    "CT_MOD_YOUR_IP": (
        "TAG-ED2K",
        "0xAD",
        "client<->client",
        "peer hello tag; UINT32 IPv4 or HASH16 IPv6 depending on type",
    ),
    "ST_IPV6_STATUS": (
        "TAG-ED2K",
        "0xAB",
        "server->client",
        "integer bitfield: IPV6ST_HAVE=0x01; IPV6ST_REACHABLE=0x02; "
        "IPV6ST_PROBED=0x04; sender SHOULD use UINT8; receiver accepts "
        "UINT8/16/32/64",
    ),
    "PR_NAT": (
        "UDP-PROTOCOL",
        "0xF1",
        "client<->server",
        "[0xF1][size u32_le = payloadLen+1][opcode u8][payload]; every "
        "endpoint IP and port inside payload is big-endian",
    ),
    "ST_NAT_PORT": (
        "TAG-ED2K",
        "0x9D",
        "server->client",
        "OP_SERVERIDENT UINT16 NAT rendezvous UDP port",
    ),
    "OP_GETSOURCES_IPV6": (
        "ED2K-SERVER-TCP",
        "0x24",
        "client->server",
        "tag-block source request",
    ),
    "OP_FOUNDSOURCES_IPV6": (
        "ED2K-SERVER-TCP",
        "0x25",
        "server->client",
        "tag-block source answer",
    ),
    "OP_GLOBGETSOURCES_IPV6": (
        "ED2K-SERVER-UDP",
        "0xA5",
        "client->server",
        "UDP tag-block source request",
    ),
    "OP_GLOBFOUNDSOURCES_IPV6": (
        "ED2K-SERVER-UDP",
        "0xA6",
        "server->client",
        "UDP tag-block source answer",
    ),
    "TAG_IPV6": (
        "KAD-TAG",
        "ip6",
        "Kad-index->client",
        "STRING with 32 hexadecimal characters",
    ),
    "CLIENT-UDP-KEY-V6": (
        "UDP-OBFUSCATION",
        "IPv6-v1",
        "client<->client",
        "RC4 key = MD5(userHash[16] || IPv6[16] || 0x5B || "
        "randomKeyPart u16_le); 35-byte key material, 16-byte digest; "
        "magic at material offset 32",
    ),
    "SRV_TCPFLG_IPV6": (
        "SERVER-TCP-FLAG",
        "0x00004000",
        "server->client",
        "bit in OP_IDCHANGE optional TCP flags word",
    ),
    "SRV_UDPFLG_IPV6": (
        "SERVER-UDP-FLAG",
        "0x00004000",
        "server->client",
        "bit in OP_GLOBSERVSTATRES UDP flags word",
    ),
    "SRV_TCPFLG_NAT_RENDEZVOUS": (
        "SERVER-TCP-FLAG",
        "0x00008000",
        "server->client",
        "bit in OP_IDCHANGE optional TCP flags word",
    ),
    "OP_NAT_REGISTER": (
        "PR-NAT-OPCODE",
        "0xE4",
        "client<->server",
        "request userHash[16] [+ legacy stats ignored]; v4 ack port u16_be + "
        "IPv4[4]",
    ),
    "OP_NAT_KEEPALIVE": (
        "PR-NAT-OPCODE",
        "0xE6",
        "client->server",
        "empty payload inside PR_NAT envelope",
    ),
    "OP_NAT_SYNC2": (
        "PR-NAT-OPCODE",
        "0xE9",
        "client->server",
        "srcHash[16] + connAck[4] opaque + dstHash[16]",
    ),
    "OP_NAT_REGISTER_IPV6": (
        "PR-NAT-OPCODE",
        "0xEC",
        "server->client",
        "server port u16_be + server IPv6[16] network-order",
    ),
    "OP_NAT_SYNC_IPV6": (
        "PR-NAT-OPCODE",
        "0xED",
        "server->client",
        "peer IPv6[16] + peer port u16_be + peerHash[16] + connAck[4] opaque "
        "+ peerVersion u8",
    ),
    "MODMISC_EXTXS": (
        "CT-MOD-MISCOPTIONS-BIT",
        "0x00000001",
        "client<->client",
        "bit 0 of CT_MOD_MISCOPTIONS 0xAA",
    ),
    "MODMISC_IPV6": (
        "CT-MOD-MISCOPTIONS-BIT",
        "0x00000004",
        "client<->client",
        "bit 2 of CT_MOD_MISCOPTIONS 0xAA",
    ),
    "MODMISC_EXTXS_SKIPTAGS": (
        "CT-MOD-MISCOPTIONS-BIT",
        "0x00000020",
        "client<->client",
        "bit 5 of CT_MOD_MISCOPTIONS 0xAA",
    ),
    "SOURCEEXCHANGEEXT_VERSION": (
        "SOURCE-EXCHANGE-VERSION",
        "0x01",
        "client<->client",
        "immutable ExtSX version byte 1; version >1 re-enables ambiguous "
        "legacy tail",
    ),
    "OP_REQUESTSOURCES2": (
        "EMULEPROT-CC",
        "0x83",
        "client->client",
        "version u8=1 + options u16_le=0 + fileHash[16]",
    ),
    "OP_ANSWERSOURCES2": (
        "EMULEPROT-CC",
        "0x84",
        "client->client",
        "version u8=1 + fileHash[16] + sourceCount u16_le + ExtSX v1 records",
    ),
    "EXTSX_V1_RECORD": (
        "SOURCE-EXCHANGE-RECORD",
        "v1",
        "client<->client",
        "clientID = htonl(userIDHybrid) serialized by u32_le writer (hybrid "
        "0x0A000001 -> wire 0a 00 00 01) + tcpPort u16_le + tagCount u8 + "
        "new-format tags; 0xAE HASH16; 0xBA serverIPv4 + 0xBB serverPort; "
        "0xBC userHash and 0xBE conopts only after bit 0x20",
    ),
    "CT_EMULE_SERVINGBUDDYIPV6": (
        "TAG-ED2K",
        "0xA0",
        "client<->client",
        "old hello tag; HASH16 serving-buddy IPv6",
    ),
    "OP_CHANGE_CLIENT_IP": (
        "ED2K-CLIENT-TCP",
        "0xAC",
        "client<->client",
        "IPv6[16] network-order under OP_EDONKEYPROT 0xE3",
    ),
    "OP_REASKCALLBACKTCP_V6_SENTINEL": (
        "EMULEPROT-CC",
        "0x9A",
        "buddy->client",
        "0xFFFFFFFF u32 + requester IPv6[16] + requester UDP port u16_le + "
        "fileHash[16] + unchanged tail",
    ),
    "OP_SERVERLIST_IPV6_TRAILING": (
        "ED2K-SERVER-TCP",
        "0x32",
        "server->client",
        "v4count u8 + v4 records; optional v6count u8 + v6count*(IPv6[16] + "
        "port u16_le); absent means zero block and emits no byte",
    ),
    "TAG_SERVINGBUDDYIPV6": (
        "KAD-TAG",
        "bi6",
        "Kad-index->client",
        "STRING with 32 hexadecimal characters for serving-buddy IPv6",
    ),
    "CT_MOD_IP_V6_SERVER_LOGIN": (
        "SERVER-LOGIN-TAG",
        "0xAE",
        "client->server",
        "old tag in OP_LOGINREQUEST; HASH16 network-order IPv6",
    ),
    "OP_NAT_REGISTER_EX": (
        "PR-NAT-OPCODE",
        "0xE3",
        "client->server",
        "userHash[16] + clientVersion u8",
    ),
    "OP_NAT_PING": (
        "PR-NAT-OPCODE",
        "0xE2",
        "server->client",
        "empty payload inside PR_NAT envelope",
    ),
    "OP_NAT_SYNC": (
        "PR-NAT-OPCODE",
        "0xE1",
        "server->client",
        "peerIPv4[4] big-endian + peerPort u16_be + peerHash[16] + "
        "connAck[4] opaque",
    ),
    "OP_NAT_SYNC_EX": (
        "PR-NAT-OPCODE",
        "0xE7",
        "server->client",
        "peerIPv4[4] big-endian + peerPort u16_be + peerHash[16] + "
        "connAck[4] opaque + peerVersion u8",
    ),
    "OP_NAT_FAILED": (
        "PR-NAT-OPCODE",
        "0xE5",
        "server->client",
        "reason u8 + targetHash[16]",
    ),
    "CT_MOD_YOUR_IP_SERVER_IDENT": (
        "SERVER-IDENT-TAG",
        "0xAD",
        "server->client",
        "OP_SERVERIDENT HASH16 IPv6 only; server emits only on a session that "
        "arrived over IPv6 with a global-unicast peer address",
    ),
}

EXPECTED_PROVENANCE = {
    "CT_MOD_IP_V6": (
        "eMuleQt",
        "v0.3.0",
        "0638dcc272d2ccc52b42018de26661541558f7e3",
    ),
    "CT_MOD_IP_V6_SERVER_LOGIN": (
        "eMuleQt+eNode",
        "v0.3.0+snapshot",
        "0638dcc272d2ccc52b42018de26661541558f7e3+"
        "e901b44bd0f17ca880828a52a9d7e39c4dde21d0",
    ),
    "CT_MOD_YOUR_IP": (
        "eMuleQt",
        "v0.3.0",
        "0638dcc272d2ccc52b42018de26661541558f7e3",
    ),
    "CT_MOD_YOUR_IP_SERVER_IDENT": (
        "eMuleQt+eNode",
        "v0.3.0+snapshot",
        "0638dcc272d2ccc52b42018de26661541558f7e3+"
        "e901b44bd0f17ca880828a52a9d7e39c4dde21d0",
    ),
    "PR_NAT": (
        "eNode",
        "snapshot",
        "e901b44bd0f17ca880828a52a9d7e39c4dde21d0",
    ),
}

FROZEN_SNAPSHOTS = {
    "eMuleQt": (
        "v0.3.0",
        "0638dcc272d2ccc52b42018de26661541558f7e3",
    ),
    "eNode": (
        "snapshot",
        "e901b44bd0f17ca880828a52a9d7e39c4dde21d0",
    ),
    "eMuleQt+eNode": (
        "v0.3.0+snapshot",
        "0638dcc272d2ccc52b42018de26661541558f7e3+"
        "e901b44bd0f17ca880828a52a9d7e39c4dde21d0",
    ),
    "eNode+eMuleQt": (
        "snapshot+v0.3.0",
        "e901b44bd0f17ca880828a52a9d7e39c4dde21d0+"
        "0638dcc272d2ccc52b42018de26661541558f7e3",
    ),
}

SOURCE_PREFIX_BY_COMMIT = {
    "0638dcc272d2ccc52b42018de26661541558f7e3": (
        "https://github.com/ModderMule/emule-qt/blob/"
        "0638dcc272d2ccc52b42018de26661541558f7e3/"
    ),
    "e901b44bd0f17ca880828a52a9d7e39c4dde21d0": (
        "https://github.com/ModderMule/eNode-go/blob/"
        "e901b44bd0f17ca880828a52a9d7e39c4dde21d0/"
    ),
}

REQUIRED_SECURITY_MARKERS = {
    "IPV6_SOURCE_SENTINEL": (
        "select crypt tail by opcode not remaining bytes",
        "never chained before a second E3/9B block",
    ),
    "CT_MOD_YOUR_IP_SERVER_IDENT": (
        "receiver accepts only HASH16 on that IPv6 session",
        "global-unicast plus assigned to a local interface",
        "reject UINT32",
    ),
    "ST_IPV6_STATUS": (
        "reject non-integer tag types",
        "absent/0 means no verdict",
        "suppress IPv6 announcement only when PROBED=1 and REACHABLE=0",
        "ignore unknown bits",
    ),
    "PR_NAT": ("not session/hash bound",),
    "MODMISC_EXTXS_SKIPTAGS": ("required before emitting 0xBC userHash",),
    "EXTSX_V1_RECORD": ("hybrid-ID transform",),
    "CLIENT-UDP-KEY-V6": ("golden vectors and negative control",),
    "CT_MOD_IP_V6_SERVER_LOGIN": ("9.7 may parse fixtures but never emits",),
}


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def normalized_contract_key(namespace: str, value: str) -> tuple[str, str]:
    normalized_namespace = NAMESPACE_EQUIVALENTS.get(namespace, namespace)
    try:
        normalized_value = hex(int(value, 0))
    except ValueError:
        normalized_value = value.lower()
    return normalized_namespace, normalized_value


def main() -> int:
    with CATALOG.open(encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames != EXPECTED_FIELDS:
            fail(f"catalog schema mismatch: {reader.fieldnames}")
        rows = list(reader)

    canonical_catalog = "\n".join(
        "\x1f".join(row[field] for field in EXPECTED_FIELDS) for row in rows
    )
    catalog_digest = hashlib.sha256(canonical_catalog.encode("utf-8")).hexdigest()
    if catalog_digest != EXPECTED_CATALOG_SHA256:
        fail(
            "frozen external catalog rows drifted: "
            f"expected={EXPECTED_CATALOG_SHA256}, actual={catalog_digest}"
        )

    expected_ids = [f"EXT-{number:03d}" for number in range(1, 44)]
    ids = [row["id"] for row in rows]
    if ids != expected_ids:
        fail(f"catalog ID coverage/order mismatch: {ids}")

    owned_names: set[str] = set()
    owned_contracts: dict[tuple[str, str], set[str]] = {}
    for path in OWNED_REGISTRIES:
        with path.open(encoding="utf-8", newline="") as stream:
            for owned_row in csv.DictReader(stream):
                owned_names.add(owned_row["name"])
                key = normalized_contract_key(
                    owned_row["namespace"], owned_row["value"]
                )
                owned_contracts.setdefault(key, set()).add(owned_row["name"])

    seen_contracts: set[tuple[str, str, str, str]] = set()
    for row in rows:
        missing = [field for field in EXPECTED_FIELDS if not row[field].strip()]
        if missing:
            fail(f"{row['id']} has empty fields: {missing}")
        if row["classification"] not in ALLOWED_CLASSIFICATIONS:
            fail(f"{row['id']} has invalid classification")
        if row["target"] not in ALLOWED_TARGETS:
            fail(f"{row['id']} has invalid target")
        if row["send_policy"] not in ALLOWED_SEND_POLICIES:
            fail(f"{row['id']} has invalid send policy")
        frozen_snapshot = FROZEN_SNAPSHOTS.get(row["implementation"])
        if frozen_snapshot is None:
            fail(f"{row['id']} uses an unapproved external implementation set")
        if (row["reference_version"], row["reference_commit"]) != frozen_snapshot:
            fail(
                f"{row['id']} drifted from the frozen snapshot: "
                f"expected={frozen_snapshot!r}"
            )
        commits = row["reference_commit"].split("+")
        if any(not re.fullmatch(r"[0-9a-f]{40}", commit) for commit in commits):
            fail(f"{row['id']} does not pin full commit SHA(s)")
        sources = row["sources"].split(";")
        if any(not source.startswith("https://github.com/") for source in sources):
            fail(f"{row['id']} has a source that is not a GitHub reference")
        missing_pins = [
            commit
            for commit in commits
            if not any(
                source.startswith(SOURCE_PREFIX_BY_COMMIT[commit])
                for source in sources
            )
        ]
        if missing_pins:
            fail(f"{row['id']} sources do not pin commits: {missing_pins}")
        if row["symbol"] in owned_names:
            fail(
                f"{row['id']} external symbol was added to an eSE-owned registry: "
                f"{row['symbol']}"
            )
        numeric_key = normalized_contract_key(row["namespace"], row["value"])
        if numeric_key in owned_contracts:
            verdict = row["classification"]
            if verdict not in {"exact-alias", "dialect-different", "numeric-collision"}:
                fail(
                    f"{row['id']} collides with {sorted(owned_contracts[numeric_key])} "
                    "without an explicit alias/dialect/collision verdict"
                )
            if verdict != "exact-alias" and row["send_policy"] not in {
                "do-not-send",
                "never-send-v1",
            }:
                fail(
                    f"{row['id']} has an unresolved local numeric collision "
                    "but does not block emission"
                )
        key = (
            row["implementation"],
            row["namespace"],
            row["value"],
            row["symbol"],
        )
        if key in seen_contracts:
            fail(f"duplicate external contract: {key}")
        seen_contracts.add(key)

    required_symbols = set(CANONICAL_CONTRACTS)
    actual_symbols = {row["symbol"] for row in rows}
    missing_symbols = sorted(required_symbols - actual_symbols)
    if missing_symbols:
        fail(f"required external contracts missing: {missing_symbols}")

    by_symbol = {row["symbol"]: row for row in rows}
    if len(by_symbol) != len(rows):
        fail("external symbols must be unique in the observational catalog")
    for symbol, expected_contract in CANONICAL_CONTRACTS.items():
        row = by_symbol[symbol]
        actual_contract = tuple(
            row[field] for field in ("namespace", "value", "direction", "wire_shape")
        )
        if actual_contract != expected_contract:
            fail(
                f"{symbol} byte contract drifted: "
                f"expected={expected_contract!r}, actual={actual_contract!r}"
            )
    for symbol, expected_provenance in EXPECTED_PROVENANCE.items():
        row = by_symbol[symbol]
        actual_provenance = tuple(
            row[field]
            for field in ("implementation", "reference_version", "reference_commit")
        )
        if actual_provenance != expected_provenance:
            fail(
                f"{symbol} provenance drifted: "
                f"expected={expected_provenance!r}, actual={actual_provenance!r}"
            )
    for symbol, markers in REQUIRED_SECURITY_MARKERS.items():
        security_status = by_symbol[symbol]["security_status"]
        for marker in markers:
            if marker not in security_status:
                fail(f"{symbol} lost security invariant {marker!r}")

    for row in rows:
        if row["target"] == "9.7" and row["send_policy"] != "receiver-first":
            fail(f"{row['symbol']} lost the v9.7 receiver-first policy")
        if (
            row["classification"] == "unsafe-as-is"
            and row["send_policy"] != "never-send-v1"
        ):
            fail(f"{row['symbol']} is unsafe-as-is but can be emitted")
        if (
            row["classification"] == "partial-implementation"
            and row["send_policy"] != "do-not-send"
        ):
            fail(f"{row['symbol']} is partial but can be emitted")
        if row["symbol"] in NAT_V1_SYMBOLS and row["send_policy"] != "never-send-v1":
            fail(f"{row['symbol']} would enable the unauthenticated v1 NAT path")

    for symbol in ("SRVCAP_IPV6", "CT_MOD_IP_V6_SERVER_LOGIN"):
        row = by_symbol[symbol]
        if row["target"] != "9.8" or row["send_policy"] != "defer-to-v9.8":
            fail(f"{symbol} must remain outside v9.7 active server interop")

    pr_nat = by_symbol["PR_NAT"]
    if (
        pr_nat["classification"] != "unsafe-as-is"
        or pr_nat["target"] != "9.8"
        or pr_nat["send_policy"] != "never-send-v1"
    ):
        fail("PR_NAT v1 must remain unsafe-as-is and non-emitting")
    for symbol in (
        "OP_GETSOURCES_IPV6",
        "OP_FOUNDSOURCES_IPV6",
        "OP_GLOBGETSOURCES_IPV6",
        "OP_GLOBFOUNDSOURCES_IPV6",
    ):
        if by_symbol[symbol]["send_policy"] != "do-not-send":
            fail(f"{symbol} is not interoperable in the frozen client snapshot")

    lab = LAB.read_text(encoding="utf-8")
    for marker in (
        "cero emisión nueva",
        "SCL-G1-RX",
        "0xFFFFFFFF",
        "SRV_TCPFLG_IPV6/SRV_UDPFLG_IPV6 0x4000",
        "MODMISC_EXTXS_SKIPTAGS 0x20",
        "`ip6`/`bi6`",
        "OP_CHANGE_CLIENT_IP 0xAC",
        "OP_REASKCALLBACKTCP 0x9A",
        "UINT8/16/32/64",
        "HAVE=0x01",
        "`0x00/01/02/03/04/05/06/07`",
        "solo `PROBED=1 && REACHABLE=0`",
        "0x0A000001 → 0a 00 00 01",
        "`0xE1`/`0xE7`/`0xED`",
        "`0xE8/0xEA/0xEB/0xEF`",
        "REG-DEBT-001",
        "permanecen en 9.8",
        "PR_NAT v1",
        "RendezvousV2",
    ):
        if marker not in lab:
            fail(f"server conformance lab is missing invariant {marker!r}")

    v98 = V98.read_text(encoding="utf-8")
    v98_flat = " ".join(v98.split())
    exact_status = re.findall(
        r"^Estado: \*\*PROPOSED / NOT AUTHORIZED\*\*\s*$", v98, re.MULTILINE
    )
    if len(exact_status) != 1:
        fail("v9.8 must have one exact PROPOSED / NOT AUTHORIZED status line")
    status_lines = re.findall(r"^Estado:.*$", v98, re.MULTILINE)
    if len(status_lines) != 1:
        fail(f"v9.8 has ambiguous status lines: {status_lines}")
    if re.search(r"^Estado:\s*\*\*(?:ACTIVE|READY|IN_PROGRESS)\b", v98, re.MULTILINE):
        fail("v9.8 contains an operational status")
    if re.search(r"^\s*program_status\s*:", v98, re.MULTILINE | re.IGNORECASE):
        fail("v9.8 contains an operational program_status field")
    for marker in (
        "Este documento no es un plan normativo de desarrollo",
        "no puede seleccionar una tarjeta activa",
        "G98-RX",
        "G98-RDV2",
        "channel_binding",
        "el binding de canal nunca sustituye la autenticación de identidad",
        "`user_hash` solo correlaciona y nunca autentica",
        "no funciona como bearer token reutilizable",
        "nuevo canal TLS con ese hash pero sin su clave privada",
        "QUIC → TLS/TCP → TCP clásico",
        "no se convierte en autoridad de rutas",
    ):
        if " ".join(marker.split()) not in v98_flat:
            fail(f"v9.8 envelope is missing invariant {marker!r}")

    registry = REGISTRY.read_text(encoding="utf-8")
    roadmap = ROADMAP.read_text(encoding="utf-8")
    index = INDEX.read_text(encoding="utf-8")
    v9_spec = V9_SPEC.read_text(encoding="utf-8")
    v94_plan = V94_PLAN.read_text(encoding="utf-8")
    adr93 = ADR93.read_text(encoding="utf-8")
    registry_checker = REGISTRY_CHECKER.read_text(encoding="utf-8")
    if "REG-DEBT-001" not in registry or "blocks every\nexternal emitter gate" not in registry:
        fail("REG-DEBT-001 is not an explicit registry-level emitter blocker")
    if "REG-DEBT-001" not in roadmap or "antes de cualquier emisión externa" not in roadmap:
        fail("the v9.7 roadmap does not block emitters on REG-DEBT-001")
    for marker in (
        "9.7 no emite `CT_MOD_IP_V6 0xAE` ni `SRVCAP_IPV6`",
        "no incluye login o dial IPv6 activo de servidor",
    ):
        if marker not in roadmap:
            fail(f"v9.7 active-server exclusion is missing {marker!r}")

    roadmap_v98_rows = re.findall(
        r"^\| 9\.8 \| `PROPOSED / NOT AUTHORIZED` \|[^\n]+\|$",
        roadmap,
        re.MULTILINE,
    )
    if len(roadmap_v98_rows) != 1:
        fail("roadmap v9.8 status row is not exactly proposed/not authorized")
    for document_name, document in (("roadmap", roadmap), ("index", index)):
        if re.search(
            r"9\.8[^\n]*(?:\bACTIVE\b|\bREADY\b|\bIN_PROGRESS\b|"
            r"(?<!NOT )\bAUTHORIZED\b)",
            document,
            re.IGNORECASE,
        ):
            fail(f"{document_name} contains an operational v9.8 status")
    for marker in ("9.8 remains unapproved", "explicitly `NOT AUTHORIZED`"):
        if marker not in index:
            fail(f"index lost the v9.8 non-authorization marker {marker!r}")
    for marker in (
        "after `G92-93-DEV`, only",
        "until `G-N0=PASS` with an accepted reconciliation",
        "proposes replacing the former KRP",
    ):
        if marker not in index:
            fail(f"index lost release-authority invariant {marker!r}")
    if "supersedes the former KRP" in index:
        fail("index incorrectly elevates the blocked v9.4 plan over the root spec")

    authority_markers = (
        "`G92-93-DEV=PASS` solo permite WP93-0 documental",
        "No autoriza editar código funcional. Ese trabajo exige `G-N0=PASS`",
        "`BLOCKED_BY_SPEC_RECONCILIATION`",
    )
    for marker in authority_markers:
        if marker not in roadmap:
            fail(f"roadmap lost authority invariant {marker!r}")
    if "| Estado | **PROPUESTO** — no aprobado; no levanta N0 por sí solo |" not in adr93:
        fail("ADR-0001 is no longer explicitly proposed/non-authoritative")
    for marker in (
        "La sección 10 conserva autoridad íntegra",
        "mientras siga `PROPUESTO`, manda íntegramente esta sección",
    ):
        if marker not in v9_spec:
            fail(f"root v9 specification lost proposed-ADR precedence: {marker!r}")
    for marker in (
        "Estado: `BLOCKED_BY_SPEC_RECONCILIATION`",
        "propone sustituir íntegramente el plan v9.4 anterior",
        "pasaría a ser, si se acepta esa reconciliación",
        "Las consecuencias propuestas son:",
    ):
        if marker not in v94_plan:
            fail(f"v9.4 plan lost subordinate/proposed wording: {marker!r}")
    for forbidden in (
        "Este documento sustituye íntegramente el plan v9.4 anterior",
        "La entrega v9.4 pasa a ser una plataforma",
        "Las consecuencias normativas son:",
    ):
        if forbidden in v94_plan:
            fail(f"v9.4 plan improperly claims root authority: {forbidden!r}")
    if not re.search(
        r'"CT_FORK_CAPABILITIES":\s*\(\s*0xF0\s*,', registry_checker
    ) or "DEBT-DRIFT" not in registry_checker:
        fail("REG-DEBT-001 checker no longer pins CT_FORK_CAPABILITIES to 0xF0")
    for marker in (
        "server login",
        "peer HELLO",
        "IPV6_WIRE 0x01",
        "IPV6_KAD 0x02",
        "IPV6_DUALSTACK 0x04",
        "ED25519 0x08",
    ):
        if marker not in registry:
            fail(f"REG-DEBT-001 lost context/bit inventory {marker!r}")

    print(
        "external interop catalog: PASS "
        f"({len(rows)} pinned contracts, receiver-first lab, v9.8 not authorized)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
