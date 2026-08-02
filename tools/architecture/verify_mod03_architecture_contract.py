#!/usr/bin/env python3
"""Verify the MOD-0.3 ownership/layering contract against MOD-0.1.

The negative fixtures mutate only deep copies in memory. This gate does not
scan hypothetical extracted modules; MOD-0.4 will enforce those source-level
limits. MOD-0.3 freezes the contract which that later gate must consume.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
CONTRACT = ROOT / "docs" / "architecture" / "mod03_ownership_layering_contract_v1.json"
INVENTORY = ROOT / "docs" / "architecture" / "mod01_architecture_inventory_v1.json"
MATRIX = ROOT / "docs" / "architecture" / "mod02_characterization_matrix_v1.json"

EXPECTED_OWNERS = {"CLiveTunnel", "CWebServer", "CLiveStreamManager"}
EXPECTED_CONTRACT_ID = "urn:emule:architecture:mod-0.3:ownership-layering:v1"
EXPECTED_TOP_LEVEL_KEYS = {
    "schema", "contract_id", "status", "scope", "baselines", "non_goals",
    "layer_model", "global_rules", "coordinators",
    "global_stop_conditions", "approval",
}
EXPECTED_BASELINE_KEYS = {"inventory", "characterization"}
EXPECTED_INVENTORY_BASELINE = {
    "path": "docs/architecture/mod01_architecture_inventory_v1.json",
    "inventory_id": "urn:emule:architecture-inventory:mod-0.1:v1",
    "baseline_commit": "b875d3dd61a2d675b2138d61161f0a8fec9d9888",
    "sha256": "56d9b3c26add68bdf9e490e2ea98a6078775d8f6e56c27ebd09475fd74b1cff8",
}
EXPECTED_CHARACTERIZATION_BASELINE = {
    "matrix_path": "docs/architecture/mod02_characterization_matrix_v1.json",
    "matrix_id": "urn:emule:architecture:mod-0.2:characterization:v1",
    "required_status": "PASS",
}
EXPECTED_SCOPE = (
    "architecture contract only; no extraction and no production behavior change"
)
EXPECTED_NON_GOALS = {
    "wire_change": False,
    "persistence_change": False,
    "behavior_change": False,
    "coordinator_extraction_started": False,
}
EXPECTED_LAYERS = [
    "composition", "facade", "application", "domain_state", "ports",
    "adapters", "foundation",
]
EXPECTED_LAYER_MODEL_KEYS = {
    "layers", "edge_policy", "acyclic", "allowed_edges", "forbidden_edges",
}
EXPECTED_GLOBAL_RULE_KEYS = {
    "ownership", "lock_order", "lock_rule", "external_callbacks",
    "marshaling", "composition", "includes",
}
EXPECTED_COORDINATOR_KEYS = {
    "name", "owner", "files", "inventory_projection", "record_ownership",
    "planned_modules", "lock_contract", "thread_affinity",
    "external_callback_contracts", "composition", "include_rules",
    "inventory_stop_conditions",
}
EXPECTED_INVENTORY_PROJECTION_KEYS = {
    "mutable_fields", "state_records", "thread_entrypoints",
    "external_async_callback_edges", "direct_includes",
}
EXPECTED_PROJECTION_VALUE_KEYS = {"count", "sha256"}
EXPECTED_RECORD_OWNERSHIP_KEYS = {
    "record", "record_owner", "contained_by_owner", "contained_by_fields",
}
EXPECTED_STOP_CONDITION_KEYS = {"id", "condition"}
EXPECTED_LAYER_EDGES = [
    ("composition", "facade"),
    ("composition", "adapters"),
    ("facade", "application"),
    ("facade", "ports"),
    ("application", "domain_state"),
    ("application", "ports"),
    ("adapters", "ports"),
    ("adapters", "foundation"),
    ("domain_state", "foundation"),
    ("ports", "foundation"),
]
EXPECTED_GLOBAL_RULES_SHA256 = (
    "9e029de2a4822a4b561e4df07281a4dafab3a1a70028b81de0b059b32fe013ae"
)
EXPECTED_DOMAIN_RANKS = {
    "registry": 10,
    "pending": 20,
    "queue": 30,
    "timer_or_leaf": 40,
}
EXPECTED_LOCK_DOMAINS = {
    "CLiveTunnel": {
        "m_lock": "registry",
        "m_pendingLock": "pending",
        "m_mtLock": "queue",
        "m_k6ReleaseLock": "timer_or_leaf",
        "m_peersCacheLock": "timer_or_leaf",
        "m_proxyIngestLock": "timer_or_leaf",
    },
    "CWebServer": {},
    "CLiveStreamManager": {
        "m_lock": "registry",
        "s_liveRequestRateLock": "timer_or_leaf",
    },
}
TRANSFER_RULE = "only after atomic ownership transfer in its approved slice"


def planned(
    owner: str, module: str, layer: str, responsibility: str
) -> dict[str, Any]:
    return {
        "module": module,
        "layer": layer,
        "responsibility": responsibility,
        "owner_before": owner,
        "owner_after": module,
        "transfer_rule": TRANSFER_RULE,
    }


EXPECTED_PLANNED_MODULES = {
    "CLiveTunnel": [
        planned("CLiveTunnel", "LiveTunnelFraming", "foundation", "headers, fragmentation and reassembly"),
        planned("CLiveTunnel", "LiveHandshakeWire", "ports", "byte-exact CREATE, CREATED, EXTEND and EXTENDED transcript and cell serialization"),
        planned("CLiveTunnel", "LiveTunnelPending", "domain_state", "pending requests, deadlines, retry and single completion"),
        planned("CLiveTunnel", "LiveCircuitRegistry", "domain_state", "circuit identity, state and lookup"),
        planned("CLiveTunnel", "LiveCircuitHandshake", "application", "CREATE, CREATED, EXTEND and EXTENDED orchestration"),
        planned("CLiveTunnel", "LiveRelayDispatcher", "application", "sub-opcode validation and dispatch"),
        planned("CLiveTunnel", "LiveExitServices", "application", "exit handler registry and lifecycle"),
        planned("CLiveTunnel", "LiveTunnelScheduler", "application", "ticks, timers, shaping and deferred work"),
        planned("CLiveTunnel", "LiveTunnelPeerState", "domain_state", "disconnect, cooldown, penalty and peer selection"),
        planned("CLiveTunnel", "LiveTunnelKadBridge", "adapters", "explicit Kad2/Kad6 to tunnel boundary"),
        planned("CLiveTunnel", "LiveTunnelMetrics", "application", "immutable snapshots and counters"),
    ],
    "CWebServer": [
        planned("CWebServer", "WebRequestParser", "application", "request line, headers, limits and normalization"),
        planned("CWebServer", "WebAuthPolicy", "application", "session, CSRF, permissions and rate limiting"),
        planned("CWebServer", "WebRouteTable", "application", "method and route to handler dispatch"),
        planned("CWebServer", "WebApiSerializer", "application", "escaped JSON, XML, HTML and response models"),
        planned("CWebServer", "WebTransferController", "application", "download and upload actions"),
        planned("CWebServer", "WebSearchController", "application", "search and result projection"),
        planned("CWebServer", "WebSharedController", "application", "shared catalog projection"),
        planned("CWebServer", "WebStaticAssets", "application", "static resources, MIME, cache and ranges"),
        planned("CWebServer", "WebSocketResponse", "adapters", "socket backpressure, streaming and close"),
        planned("CWebServer", "WebDiagnostics", "application", "sanitized status without secrets or private paths"),
    ],
    "CLiveStreamManager": [
        planned("CLiveStreamManager", "LiveBroadcastSession", "domain_state", "broadcaster start, stop and state"),
        planned("CLiveStreamManager", "LiveViewerSession", "domain_state", "viewer join, leave and lifecycle"),
        planned("CLiveStreamManager", "LivePeerSet", "domain_state", "peer selection, replacement, limits and diversity"),
        planned("CLiveStreamManager", "LiveChunkWindow", "domain_state", "chunk ingest, order, expiry and availability"),
        planned("CLiveStreamManager", "LiveStreamSecurity", "domain_state", "signature, pinning, replay and trust"),
        planned("CLiveStreamManager", "LiveStreamFanout", "application", "queues, backpressure and child delivery"),
        planned("CLiveStreamManager", "LiveStreamRecovery", "application", "NACK, FEC, replenishment and emergency"),
        planned("CLiveStreamManager", "LiveStreamAnnouncer", "adapters", "announces and wire compatibility"),
        planned("CLiveStreamManager", "LiveStreamSnapshot", "application", "immutable observability snapshots"),
    ],
}
EXPECTED_SECTION_DIGESTS = {
    "CLiveTunnel": {
        "thread_affinity": "bcb11b58e7f42584e0a9032cb7f4c49bd94c3eb754b567e554e270cb0d2fc5fa",
        "external_callback_contracts": "dabc3e5ed263a2fa8c0486a070ffaf2e79525a9965f99c3082baa89082240385",
        "include_rules": "a895902f0f3e25db84ef45ea69082ed8f2def18b7e746c6c39c7903abb815a1f",
        "lock_contract": "f95614179c17e7c2089f4b0a7ec71b34f67d6842a8457169429324e2a115dd02",
        "composition": "c5396a641b0888d76fb98f51f627cd9584e0f9babe6f15c2304520689e119288",
    },
    "CWebServer": {
        "thread_affinity": "e45715253167b83792898933f771c760dde8574b4b4608e034a906de6739f60e",
        "external_callback_contracts": "d9afb6ba157de759669a21d7e3835ef5e361ffd3f2ed10fb421c5a42d100efcf",
        "include_rules": "38163ca4936637c92c58b38158753cfd1a15ce0c8bd192381ed6a9341f8ea063",
        "lock_contract": "b9868702485ac27dadc35b687d714d3f82970a284bfdbca5171bc2ee5bb149a3",
        "composition": "760357f7b02f35c51b7c427c4b701953cfa160c1b776278d6abcf15c5b3cf1e2",
    },
    "CLiveStreamManager": {
        "thread_affinity": "0c2f2fc2f3e3856f714e28f5a8bcaf26e5c3c6632a403fa7b389a9d296e4f077",
        "external_callback_contracts": "16ed3cc016c6e2fc137c009236203e9133dc0ebcafc00fc143621f7d5ba2f515",
        "include_rules": "1a52483619171a78a3d23ce6e7d4731d4366fb02637d06af1287bffa387b5a59",
        "lock_contract": "8baef21f9397daa180e16542fe96dfd3e52bbff36cc2b945b6985f5d4238be7f",
        "composition": "8e72a68d1967c1b8ca86051e2a81b5973af8a6f491ff1f3df71e27cf9494ff06",
    },
}
EXPECTED_STOP_CONDITIONS_SHA256 = (
    "4faddfa0aaf1b10df454e891d4be98992452c7d7f420c8505b8205b710169526"
)
EXPECTED_APPROVAL = {
    "mod03_status": "PASS",
    "extraction_authorized_before_pass": False,
    "next_gate": "MOD-0.4",
    "review_policy": "implementation Sol/high plus independent Sol/high review",
}
EXPECTED_NEGATIVE_FIXTURE_COUNT = 25


class ContractError(ValueError):
    """A stable, actionable contract violation."""


def canonical_digest(value: Any) -> str:
    payload = json.dumps(
        value, separators=(",", ":"), sort_keys=True, ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def assert_exact_keys(value: Any, expected: set[str], path: str) -> None:
    if not isinstance(value, dict):
        raise ContractError(f"{path} must be an object")
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        details = []
        if missing:
            details.append(f"missing={missing}")
        if extra:
            details.append(f"extra={extra}")
        raise ContractError(f"{path} keys drift: {', '.join(details)}")


def projections(record: dict[str, Any]) -> dict[str, tuple[int, str]]:
    mutable = sorted((item["name"], item["owner"]) for item in record["mutable_fields"])
    states = sorted(
        (item["owner"], tuple(sorted(item["contained_by_fields"])))
        for item in record["state_records"]
    )
    threads = sorted(
        (
            item["evidence_kind"], item["file"], item["line"],
            tuple(item["markers"]),
        )
        for item in record["thread_task_callback_entrypoints"]
    )
    async_edges = sorted(
        (
            item["edge"], item["thread_contract"], item["callback"],
            item["definition"]["file"], item["definition"]["line"],
            item["target"]["file"], item["target"]["function"],
            item["target"]["line"],
        )
        for item in record["external_async_callback_edges"]
    )
    includes = sorted(
        (source, item["target"], item["scope"])
        for source, items in record["direct_includes"].items()
        for item in items
    )
    return {
        "mutable_fields": (len(mutable), canonical_digest(mutable)),
        "state_records": (len(states), canonical_digest(states)),
        "thread_entrypoints": (len(threads), canonical_digest(threads)),
        "external_async_callback_edges": (
            len(async_edges), canonical_digest(async_edges)
        ),
        "direct_includes": (len(includes), canonical_digest(includes)),
    }


def assert_acyclic(layers: list[str], edges: set[tuple[str, str]]) -> None:
    outgoing = {layer: set() for layer in layers}
    indegree = {layer: 0 for layer in layers}
    for source, target in edges:
        if source not in outgoing or target not in outgoing:
            raise ContractError(f"layer violation: unknown edge {source}->{target}")
        if target not in outgoing[source]:
            outgoing[source].add(target)
            indegree[target] += 1
    ready = sorted(layer for layer, count in indegree.items() if count == 0)
    visited = 0
    while ready:
        layer = ready.pop(0)
        visited += 1
        for target in sorted(outgoing[layer]):
            indegree[target] -= 1
            if indegree[target] == 0:
                ready.append(target)
    if visited != len(layers):
        raise ContractError("layer cycle detected")


def assert_edge_list(name: str, edges: Any) -> list[tuple[str, str]]:
    if not isinstance(edges, list):
        raise ContractError(f"{name} layer edges must be an ordered list")
    normalized: list[tuple[str, str]] = []
    for index, edge in enumerate(edges):
        if (
            not isinstance(edge, list)
            or len(edge) != 2
            or not all(isinstance(item, str) and item for item in edge)
        ):
            raise ContractError(f"{name} layer edge {index} must contain two layer names")
        normalized.append((edge[0], edge[1]))
    if len(normalized) != len(set(normalized)):
        raise ContractError(f"duplicate {name} layer edge")
    return normalized


def assert_no_empty_text(value: Any, path: str) -> None:
    if isinstance(value, str):
        if not value.strip():
            raise ContractError(f"{path} contains an empty value")
    elif isinstance(value, list):
        if not value:
            raise ContractError(f"{path} must not be empty")
        for index, item in enumerate(value):
            assert_no_empty_text(item, f"{path}[{index}]")
    elif isinstance(value, dict):
        if not value:
            raise ContractError(f"{path} must not be empty")
        for key, item in value.items():
            assert_no_empty_text(item, f"{path}.{key}")


def validate(contract: dict[str, Any], inventory: dict[str, Any], matrix: dict[str, Any]) -> None:
    assert_exact_keys(contract, EXPECTED_TOP_LEVEL_KEYS, "top-level contract")
    if contract.get("schema") != "ese.mod03.ownership-layering-contract/v1":
        raise ContractError("schema mismatch")
    if contract.get("contract_id") != EXPECTED_CONTRACT_ID:
        raise ContractError("contract_id drift")
    if contract.get("status") != "PASS":
        raise ContractError("MOD-0.3 status is not PASS")
    if contract.get("scope") != EXPECTED_SCOPE:
        raise ContractError("MOD-0.3 scope drift")
    if contract.get("non_goals") != EXPECTED_NON_GOALS:
        raise ContractError("MOD-0.3 non-goals drift")

    assert_exact_keys(contract["baselines"], EXPECTED_BASELINE_KEYS, "baselines")
    baseline = contract["baselines"]["inventory"]
    characterization = contract["baselines"]["characterization"]
    assert_exact_keys(
        baseline, set(EXPECTED_INVENTORY_BASELINE), "baselines.inventory"
    )
    assert_exact_keys(
        characterization,
        set(EXPECTED_CHARACTERIZATION_BASELINE),
        "baselines.characterization",
    )
    if baseline != EXPECTED_INVENTORY_BASELINE:
        raise ContractError("inventory baseline object drift")
    if characterization != EXPECTED_CHARACTERIZATION_BASELINE:
        raise ContractError("characterization baseline object drift")
    if baseline["inventory_id"] != inventory["inventory_id"]:
        raise ContractError("inventory id drift")
    if baseline["baseline_commit"] != inventory["baseline_commit"]:
        raise ContractError("inventory baseline commit drift")
    if baseline["sha256"] != hashlib.sha256(INVENTORY.read_bytes()).hexdigest():
        raise ContractError("inventory hash drift")
    if characterization["matrix_id"] != matrix["matrix_id"]:
        raise ContractError("MOD-0.2 matrix id drift")
    if matrix["runtime_gate"]["status"] != characterization["required_status"]:
        raise ContractError("MOD-0.2 is not PASS")

    layer_model = contract["layer_model"]
    assert_exact_keys(layer_model, EXPECTED_LAYER_MODEL_KEYS, "layer_model")
    layers = layer_model["layers"]
    if layers != EXPECTED_LAYERS:
        raise ContractError("ordered layer list drift")
    allowed_ordered = assert_edge_list("allowed", layer_model["allowed_edges"])
    forbidden_ordered = assert_edge_list("forbidden", layer_model["forbidden_edges"])
    allowed = set(allowed_ordered)
    forbidden = set(forbidden_ordered)
    assert_acyclic(layers, allowed)
    overlap = allowed & forbidden
    if overlap:
        source, target = sorted(overlap)[0]
        raise ContractError(f"layer violation: forbidden edge {source}->{target}")
    if allowed_ordered != EXPECTED_LAYER_EDGES or layer_model["edge_policy"] != "deny_unlisted":
        raise ContractError("layer allowlist drift")
    expected_forbidden = [
        (source, target)
        for source in EXPECTED_LAYERS
        for target in EXPECTED_LAYERS
        if source != target and (source, target) not in EXPECTED_LAYER_EDGES
    ]
    if forbidden_ordered != expected_forbidden:
        raise ContractError("forbidden layer edges are not the exhaustive ordered complement")
    if layer_model["acyclic"] is not True:
        raise ContractError("acyclic layer policy disabled")

    assert_exact_keys(
        contract["global_rules"], EXPECTED_GLOBAL_RULE_KEYS, "global_rules"
    )
    if canonical_digest(contract["global_rules"]) != EXPECTED_GLOBAL_RULES_SHA256:
        raise ContractError("complete global rules drift")

    inventory_by_owner = {item["owner"]: item for item in inventory["monoliths"]}
    for index, coordinator in enumerate(contract["coordinators"]):
        assert_exact_keys(
            coordinator,
            EXPECTED_COORDINATOR_KEYS,
            f"coordinators[{index}]",
        )
    contract_by_owner = {item["owner"]: item for item in contract["coordinators"]}
    if set(inventory_by_owner) != EXPECTED_OWNERS or set(contract_by_owner) != EXPECTED_OWNERS:
        raise ContractError("coordinator owners differ from MOD-0.1")
    if len(contract["coordinators"]) != len(contract_by_owner):
        raise ContractError("duplicate coordinator owner")

    for owner in sorted(EXPECTED_OWNERS):
        source = inventory_by_owner[owner]
        target = contract_by_owner[owner]
        if target["name"] != source["name"]:
            raise ContractError(f"{owner}: coordinator name drift")
        if target["files"] != [item["path"] for item in source["files"]]:
            raise ContractError(f"{owner}: source file mapping drift")

        actual_projection = projections(source)
        assert_exact_keys(
            target["inventory_projection"],
            EXPECTED_INVENTORY_PROJECTION_KEYS,
            f"{owner}: inventory_projection",
        )
        for key, (count, digest) in actual_projection.items():
            frozen = target["inventory_projection"][key]
            assert_exact_keys(
                frozen,
                EXPECTED_PROJECTION_VALUE_KEYS,
                f"{owner}: inventory_projection.{key}",
            )
            if frozen != {"count": count, "sha256": digest}:
                raise ContractError(f"{owner}: {key} projection drift")

        assignments = target["record_ownership"]
        if not isinstance(assignments, list):
            raise ContractError(f"{owner}: record_ownership must be an ordered list")
        for index, assignment in enumerate(assignments):
            assert_exact_keys(
                assignment,
                EXPECTED_RECORD_OWNERSHIP_KEYS,
                f"{owner}: record_ownership[{index}]",
            )
        record_names = [item["record"] for item in assignments]
        if len(record_names) != len(set(record_names)):
            raise ContractError(f"{owner}: duplicate state record owner assignment")
        expected_records = Counter(
            (
                item["owner"], item["owner"], owner,
                tuple(sorted(item["contained_by_fields"])),
            )
            for item in source["state_records"]
        )
        actual_records = Counter(
            (
                item["record"], item["record_owner"], item["contained_by_owner"],
                tuple(sorted(item["contained_by_fields"])),
            )
            for item in assignments
        )
        if actual_records != expected_records:
            raise ContractError(f"{owner}: state record ownership differs from MOD-0.1")

        planned_modules = target["planned_modules"]
        if not isinstance(planned_modules, list):
            raise ContractError(f"{owner}: planned modules must be an ordered list")
        if not all(isinstance(item, dict) for item in planned_modules):
            raise ContractError(f"{owner}: planned module entries must be objects")
        module_names = [item.get("module") for item in planned_modules]
        if len(module_names) != len(set(module_names)):
            raise ContractError(f"{owner}: duplicate planned module")
        expected_modules = EXPECTED_PLANNED_MODULES[owner]
        if len(planned_modules) != len(expected_modules):
            raise ContractError(f"{owner}: planned module count/order drift")
        for index, (module, expected_module) in enumerate(
            zip(planned_modules, expected_modules)
        ):
            if set(module) != set(expected_module):
                raise ContractError(
                    f"{owner}: planned module keys drift at index {index}"
                )
            for field, expected_value in expected_module.items():
                if module[field] != expected_value:
                    raise ContractError(
                        f"{owner}: planned module {field} drift: "
                        f"{module.get('module', index)}"
                    )
            if "fields" in module or "records" in module:
                raise ContractError(
                    f"{owner}: MOD-0.3 must not preassign state: {module['module']}"
                )

        lock_contract = target["lock_contract"]
        expected_member = sorted(item["name"] for item in source["locks"]["member_fields"])
        expected_local = sorted(item["name"] for item in source["locks"]["local_definitions"])
        if sorted(lock_contract["inventory_member_locks"]) != expected_member:
            raise ContractError(f"{owner}: member lock inventory drift")
        if sorted(lock_contract["inventory_local_locks"]) != expected_local:
            raise ContractError(f"{owner}: local lock inventory drift")
        lock_domains: dict[str, str] = {}
        ranks: dict[str, int] = {}
        for domain in lock_contract["domains"]:
            name, rank = domain["domain"], domain["rank"]
            if EXPECTED_DOMAIN_RANKS.get(name) != rank:
                raise ContractError(f"{owner}: lock domain rank drift")
            if name in ranks:
                raise ContractError(f"{owner}: duplicate lock domain")
            ranks[name] = rank
            for lock in domain["locks"]:
                if lock in lock_domains:
                    raise ContractError(f"{owner}: lock has duplicate domain: {lock}")
                lock_domains[lock] = name
        if lock_domains != EXPECTED_LOCK_DOMAINS[owner]:
            raise ContractError(f"{owner}: lock-domain ownership drift")
        for before, after in map(tuple, lock_contract["permitted_nested_edges"]):
            if before not in ranks or after not in ranks or ranks[before] >= ranks[after]:
                raise ContractError(f"{owner}: lock inversion {before}->{after}")
        if canonical_digest(lock_contract) != EXPECTED_SECTION_DIGESTS[owner]["lock_contract"]:
            raise ContractError(f"{owner}: complete lock contract drift")

        thread_affinity = target.get("thread_affinity")
        callbacks = target.get("external_callback_contracts")
        include_rules = target.get("include_rules")
        if not isinstance(thread_affinity, list) or not thread_affinity:
            raise ContractError(f"{owner}: missing thread-affinity contract")
        if not isinstance(callbacks, list) or not callbacks:
            raise ContractError(f"{owner}: missing external callback contract")
        if not isinstance(include_rules, dict) or not include_rules:
            raise ContractError(f"{owner}: missing include rules contract")
        for callback in callbacks:
            if not isinstance(callback, dict):
                raise ContractError(f"{owner}: callback contract entry must be an object")
            if callback.get("under_internal_lock") is not False:
                raise ContractError(
                    f"{owner}: external callback under lock or missing lock policy: "
                    f"{callback.get('boundary', '<missing boundary>')}"
                )
        for section in (
            "thread_affinity", "external_callback_contracts", "include_rules"
        ):
            assert_no_empty_text(target[section], f"{owner}.{section}")
            if canonical_digest(target[section]) != EXPECTED_SECTION_DIGESTS[owner][section]:
                raise ContractError(f"{owner}: complete {section} contract drift")
        composition = target["composition"]
        if composition["composition_root"] != owner or composition["lifetime_owner"] != owner:
            raise ContractError(f"{owner}: invented composition/lifetime owner")
        if composition["service_locator_in_extracted_modules"] is not False:
            raise ContractError(f"{owner}: extracted service locator enabled")
        if canonical_digest(composition) != EXPECTED_SECTION_DIGESTS[owner]["composition"]:
            raise ContractError(f"{owner}: complete composition contract drift")
        if target["include_rules"]["coordinator_header_in_extracted_module"] != "forbidden":
            raise ContractError(f"{owner}: reverse coordinator include allowed")
        if target["inventory_stop_conditions"] != source["stop_conditions"]:
            raise ContractError(f"{owner}: inventory stop conditions drift")

    for index, stop in enumerate(contract["global_stop_conditions"]):
        assert_exact_keys(
            stop, EXPECTED_STOP_CONDITION_KEYS, f"global_stop_conditions[{index}]"
        )
    if canonical_digest(contract["global_stop_conditions"]) != EXPECTED_STOP_CONDITIONS_SHA256:
        raise ContractError("complete ordered global stop conditions drift")
    assert_exact_keys(
        contract["approval"], set(EXPECTED_APPROVAL), "approval"
    )
    if contract["approval"] != EXPECTED_APPROVAL:
        raise ContractError("complete MOD-0.3 approval policy drift")


def verify_negative_fixtures(
    contract: dict[str, Any], inventory: dict[str, Any], matrix: dict[str, Any]
) -> int:
    fixtures: list[tuple[str, str, Any]] = []

    cyclic = copy.deepcopy(contract)
    cyclic["layer_model"]["allowed_edges"].append(["foundation", "composition"])
    fixtures.append(("cycle", "layer cycle", cyclic))

    layer = copy.deepcopy(contract)
    layer["layer_model"]["allowed_edges"].append(["application", "adapters"])
    fixtures.append(("layer violation", "layer violation", layer))

    duplicate_owner = copy.deepcopy(contract)
    duplicate_owner["coordinators"][0]["record_ownership"].append(
        copy.deepcopy(duplicate_owner["coordinators"][0]["record_ownership"][0])
    )
    fixtures.append(("duplicate owner", "duplicate state record owner", duplicate_owner))

    inversion = copy.deepcopy(contract)
    inversion["coordinators"][0]["lock_contract"]["permitted_nested_edges"].append(
        ["pending", "registry"]
    )
    fixtures.append(("lock inversion", "lock inversion", inversion))

    callback = copy.deepcopy(contract)
    callback["coordinators"][0]["external_callback_contracts"][0][
        "under_internal_lock"
    ] = True
    fixtures.append(("callback under lock", "external callback under lock", callback))

    planned_layer = copy.deepcopy(contract)
    planned_layer["coordinators"][0]["planned_modules"][0]["layer"] = "application"
    fixtures.append(("planned layer", "planned module layer drift", planned_layer))

    planned_responsibility = copy.deepcopy(contract)
    planned_responsibility["coordinators"][0]["planned_modules"][0][
        "responsibility"
    ] = "different responsibility"
    fixtures.append((
        "planned responsibility",
        "planned module responsibility drift",
        planned_responsibility,
    ))

    thread_missing = copy.deepcopy(contract)
    thread_missing["coordinators"][0]["thread_affinity"].pop()
    fixtures.append((
        "thread entry missing",
        "complete thread_affinity contract drift",
        thread_missing,
    ))

    thread_empty = copy.deepcopy(contract)
    thread_empty["coordinators"][0]["thread_affinity"][0]["marshal"] = ""
    fixtures.append((
        "thread marshal empty",
        "thread_affinity[0].marshal contains an empty value",
        thread_empty,
    ))

    thread_marshal = copy.deepcopy(contract)
    thread_marshal["coordinators"][0]["thread_affinity"][0][
        "marshal"
    ] = "direct mutation"
    fixtures.append((
        "thread marshal drift",
        "complete thread_affinity contract drift",
        thread_marshal,
    ))

    callback_rule = copy.deepcopy(contract)
    callback_rule["coordinators"][0]["external_callback_contracts"][0][
        "rule"
    ] = "invoke_under_lock"
    fixtures.append((
        "callback rule",
        "complete external_callback_contracts contract drift",
        callback_rule,
    ))

    include_rule = copy.deepcopy(contract)
    del include_rule["coordinators"][0]["include_rules"][
        "sibling_coordinator_header"
    ]
    fixtures.append((
        "include rule missing",
        "complete include_rules contract drift",
        include_rule,
    ))

    extra_layer = copy.deepcopy(contract)
    extra_layer["layer_model"]["layers"].append("utility")
    fixtures.append(("extra layer", "ordered layer list drift", extra_layer))

    forbidden_empty = copy.deepcopy(contract)
    forbidden_empty["layer_model"]["forbidden_edges"] = []
    fixtures.append((
        "forbidden edges empty",
        "forbidden layer edges are not the exhaustive ordered complement",
        forbidden_empty,
    ))

    forbidden_duplicate = copy.deepcopy(contract)
    forbidden_duplicate["layer_model"]["forbidden_edges"].append(
        copy.deepcopy(forbidden_duplicate["layer_model"]["forbidden_edges"][0])
    )
    fixtures.append((
        "forbidden edge duplicate",
        "duplicate forbidden layer edge",
        forbidden_duplicate,
    ))

    lock_edge_missing = copy.deepcopy(contract)
    lock_edge_missing["coordinators"][0]["lock_contract"][
        "permitted_nested_edges"
    ].pop()
    fixtures.append((
        "lock edge missing",
        "complete lock contract drift",
        lock_edge_missing,
    ))

    stop_text = copy.deepcopy(contract)
    stop_text["global_stop_conditions"][0]["condition"] += " altered"
    fixtures.append((
        "stop text",
        "complete ordered global stop conditions drift",
        stop_text,
    ))

    scope = copy.deepcopy(contract)
    scope["scope"] = "architecture contract"
    fixtures.append(("scope", "MOD-0.3 scope drift", scope))

    global_rule = copy.deepcopy(contract)
    global_rule["global_rules"]["ownership"] += " altered"
    fixtures.append(("global rule", "complete global rules drift", global_rule))

    next_gate = copy.deepcopy(contract)
    next_gate["approval"]["next_gate"] = "MOD-1"
    fixtures.append((
        "approval next gate",
        "complete MOD-0.3 approval policy drift",
        next_gate,
    ))

    contract_id = copy.deepcopy(contract)
    contract_id["contract_id"] += ":drift"
    fixtures.append(("contract id", "contract_id drift", contract_id))

    matrix_path = copy.deepcopy(contract)
    matrix_path["baselines"]["characterization"]["matrix_path"] = "wrong.json"
    fixtures.append((
        "matrix path",
        "characterization baseline object drift",
        matrix_path,
    ))

    record_extra = copy.deepcopy(contract)
    record_extra["coordinators"][0]["record_ownership"][0][
        "owner_after"
    ] = "invented"
    fixtures.append((
        "record ownership extra key",
        "record_ownership[0] keys drift",
        record_extra,
    ))

    top_extra = copy.deepcopy(contract)
    top_extra["unexpected"] = True
    fixtures.append((
        "top-level extra key",
        "top-level contract keys drift",
        top_extra,
    ))

    coordinator_extra = copy.deepcopy(contract)
    coordinator_extra["coordinators"][0]["unexpected"] = True
    fixtures.append((
        "coordinator extra key",
        "coordinators[0] keys drift",
        coordinator_extra,
    ))

    if len(fixtures) != EXPECTED_NEGATIVE_FIXTURE_COUNT:
        raise ContractError(
            "internal negative fixture count drift: "
            f"{len(fixtures)} != {EXPECTED_NEGATIVE_FIXTURE_COUNT}"
        )
    for name, expected, mutated in fixtures:
        try:
            validate(mutated, inventory, matrix)
        except ContractError as error:
            if expected not in str(error):
                raise ContractError(
                    f"negative {name} failed for the wrong reason: {error}"
                ) from error
        else:
            raise ContractError(f"negative {name} fixture was accepted")
    return len(fixtures)


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--verify", action="store_true")
    mode.add_argument("--negative-fixtures", action="store_true")
    args = parser.parse_args()
    try:
        contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))
        matrix = json.loads(MATRIX.read_text(encoding="utf-8"))
        negative_count = 0
        if args.verify:
            validate(contract, inventory, matrix)
        else:
            validate(contract, inventory, matrix)
            negative_count = verify_negative_fixtures(contract, inventory, matrix)
    except (OSError, json.JSONDecodeError, ContractError, KeyError, TypeError) as error:
        print(f"MOD-0.3 FAIL: {error}")
        return 1
    suffix = (
        f" ({negative_count} negative fixtures)"
        if negative_count else ""
    )
    print(f"MOD-0.3 ownership/layering contract PASS{suffix}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
