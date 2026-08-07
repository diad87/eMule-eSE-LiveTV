"""M2A-W7 immutable inventory and regression contract for the Live API."""

from __future__ import annotations

import copy
import json
import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
GOLDEN = ROOT / "tests" / "goldens" / "v92_m2a_w7_live_api_inventory_v1.json"
ROUTES = ROOT / "srchybrid" / "WebRouteTable.cpp"
ROUTE_HEADER = ROOT / "srchybrid" / "WebRouteTable.h"
AUTH = ROOT / "srchybrid" / "WebAuthPolicy.cpp"
WEB = ROOT / "srchybrid" / "WebServer.cpp"
PARSER_HEADER = ROOT / "srchybrid" / "WebRequestParser.h"
INVENTORY = json.loads(GOLDEN.read_text(encoding="utf-8"))

EXPECTED_IDS = {
    "ApiNetworkConnect", "ApiDebugSourceResolutions", "ApiStatus",
    "ApiLiveJoin", "ApiLiveLeave", "ApiLivePlayerAlive",
    "ApiLiveBroadcastStart", "ApiLiveBroadcastStop", "LegacyHls",
    "Dashboard", "ApiHolePunchRendezvousTest", "ApiKeepaliveStart",
    "ApiKeepaliveStop", "ApiEseV9", "ApiEseNetlabReport",
    "ApiEseNetlabIpv6Echo", "ApiKrpStatus",
    "ApiRelayAccept", "ApiRelayEgress", "ApiRelaySelector",
    "ApiRelayConnect", "ApiHolePunchTest", "ApiLivePreflight",
    "ApiLivePrivacySubscriptions", "ApiLivePrivacyTunnelSearch",
    "ApiLivePrivacyTunnelEcho", "ApiLivePrivacyTunnelPing",
    "ApiLivePrivacyCircuits", "ApiLivePrivacyPeers",
    "ApiLivePrivacyTestCircuit", "ApiLivePrivacyKad6Release",
    "ApiLivePrivacyKad6Hardening", "ApiLivePrivacy", "ApiLiveMetrics",
    "ApiLiveLog", "ApiLiveDiagnose", "ApiLiveDirectJoin",
    "ApiLiveChannels", "ApiLiveMesh", "ApiLiveKadStreams",
    "ApiLiveEdgeSabotage", "ApiLiveDebug", "ApiLiveStream",
    "LiveIndex", "LivePlayer",
}
POST_W7_GOVERNED_IDS = {"ApiReachStatus"}
EXPECTED_QUERY_KEYS = {
    "add", "add_sensitive", "admission_attempts", "admission_ppm", "after",
    "audit_sha256", "bitrate", "buddy_ip", "buddy_port", "bytes",
    "category", "challenge", "confirm", "delay", "direct", "drain_seconds",
    "ed2k", "enabled", "fallback", "field_sha256", "file", "gate_mask",
    "headroom_bps", "hops", "ip", "kad", "key", "keyword", "language",
    "link", "mode", "n", "name", "nonce", "observed_from", "observed_to", "on",
    "port", "rdv_ip", "rdv_udp_port", "remove", "rm_sensitive", "service",
    "source", "spread", "stream", "target", "target_ip", "target_udp_port",
    "tcp_port", "text", "timeout_ms", "title", "udp_port", "valid_until",
}
GUEST_IDS = {
    "ApiStatus", "ApiLiveJoin", "ApiLiveLeave", "ApiLivePlayerAlive",
    "ApiLiveMetrics", "ApiLiveChannels", "ApiLiveMesh", "ApiLiveKadStreams",
    "ApiLiveStream", "Dashboard", "LegacyHls", "LiveIndex", "LivePlayer",
}
READ_ONLY_IDS = {
    "ApiStatus", "ApiLiveMetrics", "ApiLiveChannels", "ApiLiveMesh",
    "ApiLiveKadStreams", "ApiLiveStream", "Dashboard", "LegacyHls",
    "LiveIndex", "LivePlayer",
}
OWNER_WAVES = {
    "WebLiveApiStreamController": "W8",
    "WebLiveApiStatusController": "W8",
    "WebLiveApiTransferController": "W9",
    "WebLiveApiSearchController": "W9",
    "WebLiveApiSettingsController": "W10",
    "WebLiveApiDiagnosticsController": "W10",
    "WebLiveApiLegacyController": "W11",
}
OWNER_FAMILIES = {
    "WebLiveApiStreamController": "stream",
    "WebLiveApiStatusController": "status",
    "WebLiveApiTransferController": "transfer",
    "WebLiveApiSearchController": "search",
    "WebLiveApiSettingsController": "settings",
    "WebLiveApiDiagnosticsController": "diagnostics",
    "WebLiveApiLegacyController": "legacy",
}
EXPECTED_ASSIGNMENTS = {
    "ApiLiveJoin": "WebLiveApiStreamController",
    "ApiLiveLeave": "WebLiveApiStreamController",
    "ApiLivePlayerAlive": "WebLiveApiStreamController",
    "ApiLiveBroadcastStart": "WebLiveApiStreamController",
    "ApiLiveBroadcastStop": "WebLiveApiStreamController",
    "ApiLiveDirectJoin": "WebLiveApiStreamController",
    "ApiLiveStream": "WebLiveApiStreamController",
    "ApiStatus": "WebLiveApiStatusController",
    "ApiLiveChannels": "WebLiveApiStatusController",
    "ApiLiveMesh": "WebLiveApiStatusController",
    "ApiNetworkConnect": "WebLiveApiTransferController",
    "ApiHolePunchRendezvousTest": "WebLiveApiTransferController",
    "ApiKeepaliveStart": "WebLiveApiTransferController",
    "ApiKeepaliveStop": "WebLiveApiTransferController",
    "ApiRelayAccept": "WebLiveApiTransferController",
    "ApiRelayEgress": "WebLiveApiTransferController",
    "ApiRelaySelector": "WebLiveApiTransferController",
    "ApiRelayConnect": "WebLiveApiTransferController",
    "ApiHolePunchTest": "WebLiveApiTransferController",
    "ApiDebugSourceResolutions": "WebLiveApiSearchController",
    "ApiLivePrivacySubscriptions": "WebLiveApiSearchController",
    "ApiLivePrivacyTunnelSearch": "WebLiveApiSearchController",
    "ApiLiveDiagnose": "WebLiveApiSearchController",
    "ApiLiveKadStreams": "WebLiveApiSearchController",
    "ApiEseV9": "WebLiveApiSettingsController",
    "ApiLivePrivacy": "WebLiveApiSettingsController",
    "ApiLiveEdgeSabotage": "WebLiveApiSettingsController",
    "ApiLivePreflight": "WebLiveApiDiagnosticsController",
    "ApiEseNetlabIpv6Echo": "WebLiveApiDiagnosticsController",
    "ApiKrpStatus": "WebLiveApiDiagnosticsController",
    "ApiLiveMetrics": "WebLiveApiDiagnosticsController",
    "ApiLiveLog": "WebLiveApiDiagnosticsController",
    "ApiLiveDebug": "WebLiveApiDiagnosticsController",
    "LegacyHls": "WebLiveApiLegacyController",
    "Dashboard": "WebLiveApiLegacyController",
    "ApiEseNetlabReport": "WebLiveApiLegacyController",
    "ApiLivePrivacyTunnelEcho": "WebLiveApiLegacyController",
    "ApiLivePrivacyTunnelPing": "WebLiveApiLegacyController",
    "ApiLivePrivacyCircuits": "WebLiveApiLegacyController",
    "ApiLivePrivacyPeers": "WebLiveApiLegacyController",
    "ApiLivePrivacyTestCircuit": "WebLiveApiLegacyController",
    "ApiLivePrivacyKad6Release": "WebLiveApiLegacyController",
    "ApiLivePrivacyKad6Hardening": "WebLiveApiLegacyController",
    "LiveIndex": "WebLiveApiLegacyController",
    "LivePlayer": "WebLiveApiLegacyController",
}
EXPECTED_DYNAMIC = {
    "LegacyHls": ["/hls/{hls_resource}"],
    "LivePlayer": ["/live/{stream_hash}"],
    "ApiLiveStream": ["/api/live/{stream_hash}/{hls_resource}"],
}
EXPECTED_INPUTS = {
    "ApiNetworkConnect": {"ed2k", "kad"},
    "ApiDebugSourceResolutions": {"after"},
    "ApiStatus": set(),
    "ApiLiveJoin": {"key", "title"},
    "ApiLiveLeave": {"key"},
    "ApiLivePlayerAlive": {"key"},
    "ApiLiveBroadcastStart": {
        "source", "title", "category", "language", "bitrate", "file", "direct",
    },
    "ApiLiveBroadcastStop": set(),
    "LegacyHls": {"hls_resource"},
    "Dashboard": set(),
    "ApiHolePunchRendezvousTest": {
        "target_ip", "target_udp_port", "rdv_ip", "rdv_udp_port",
    },
    "ApiKeepaliveStart": set(),
    "ApiKeepaliveStop": set(),
    "ApiEseV9": {"on"},
    "ApiEseNetlabReport": set(),
    "ApiEseNetlabIpv6Echo": {
        "target", "tcp_port", "udp_port", "nonce", "timeout_ms",
    },
    "ApiKrpStatus": set(),
    "ApiRelayAccept": {"on"},
    "ApiRelayEgress": {"on"},
    "ApiRelaySelector": {"on"},
    "ApiRelayConnect": {"on", "stream", "buddy_ip", "buddy_port"},
    "ApiHolePunchTest": {"ip", "udp_port", "spread"},
    "ApiLivePreflight": set(),
    "ApiLivePrivacySubscriptions": {"add", "remove", "name"},
    "ApiLivePrivacyTunnelSearch": {"keyword"},
    "ApiLivePrivacyTunnelEcho": {"bytes"},
    "ApiLivePrivacyTunnelPing": {"text"},
    "ApiLivePrivacyCircuits": set(),
    "ApiLivePrivacyPeers": set(),
    "ApiLivePrivacyTestCircuit": {"hops"},
    "ApiLivePrivacyKad6Release": {
        "enabled", "challenge", "confirm", "field_sha256", "audit_sha256",
        "observed_from", "observed_to", "admission_attempts", "admission_ppm",
        "headroom_bps", "gate_mask", "valid_until", "drain_seconds",
    },
    "ApiLivePrivacyKad6Hardening": {"service", "enabled", "drain_seconds"},
    "ApiLivePrivacy": {"mode", "fallback", "add_sensitive", "rm_sensitive"},
    "ApiLiveMetrics": set(),
    "ApiLiveLog": {"n"},
    "ApiLiveDiagnose": {"key"},
    "ApiLiveDirectJoin": {"link", "key", "ip", "port", "title"},
    "ApiLiveChannels": set(),
    "ApiLiveMesh": set(),
    "ApiLiveKadStreams": set(),
    "ApiLiveEdgeSabotage": {"on", "mode", "delay"},
    "ApiLiveDebug": set(),
    "ApiLiveStream": {"stream_hash", "hls_resource"},
    "LiveIndex": set(),
    "LivePlayer": {"stream_hash"},
}
ALLOWED_STATE_OWNERS = {
    "CWebServer", "CPreferences", "CStatistics", "CDownloadQueue",
    "CServerConnect", "CKademlia", "CKadKeepalive", "CLiveStreamManager",
    "CLiveTunnel", "CLiveBuddyRelay", "CLiveSubscriptionStore",
    "KRPClient", "GUI", "RTMPIngest", "HLSFilesystem", "EmbeddedWebUI",
    "TestHooks",
}
ALLOWED_MUTABLE_STATE = {
    "connectivity_runtime", "resolution_event_cursor", "stream_session",
    "player_watchdog_tick", "broadcast_session", "legacy_hls_watchdog_tick",
    "rendezvous_attempt", "keepalive_runtime_command", "relay_preferences",
    "relay_session", "holepunch_attempt", "subscription_store",
    "tunnel_search_request", "diagnostic_directory_refresh",
    "netlab_preferences", "privacy_preferences", "test_sabotage_globals",
    "kad6_release_policy", "kad6_hardening_policy", "test_circuit_request",
}
ALLOWED_EFFECT_KINDS = {
    "none", "snapshot", "main_thread_command", "atomic_tick", "filesystem_read",
    "network_request", "preference_update", "persistence_write",
    "directory_refresh", "test_hook_update",
}
OPERATION_KEYS = {
    "id", "family", "routes", "route_kind", "methods", "inputs", "role",
    "mutation", "csrf",
    "state_owner", "mutable_state", "future_wave", "future_owner", "effects",
    "response", "redactions", "vectors", "security_notes",
}
INPUT_KEYS = {
    "name", "source", "type", "required", "default", "bounds", "sensitivity",
}
REDACTION_KEYS = {"field", "surface", "mode"}
VECTOR_KEYS = {"positive", "negative"}
FINDING_KEYS = {
    "id", "severity", "asset", "route", "configuration", "observed",
    "intended", "vector", "disposition",
}


def _array_strings(text: str, name: str) -> set[str]:
    match = re.search(
        rf"{re.escape(name)}\[\]\s*=\s*\{{(.*?)\}};",
        text,
        re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"missing production array {name}")
    return set(re.findall(r'"([^"]+)"', match.group(1)))


def _exact_routes() -> dict[str, list[str]]:
    text = ROUTES.read_text(encoding="utf-8")
    block = text.split("constexpr RouteDefinition kExactRoutes[] = {", 1)[1]
    block = block.split("};", 1)[0]
    result: dict[str, list[str]] = {}
    for path, route_id in re.findall(
        r'\{"([^"]+)",\s*WebRouteId::([A-Za-z0-9_]+)\}', block
    ):
        result.setdefault(route_id, []).append(path)
    return result


def _route_enum_ids() -> set[str]:
    text = ROUTE_HEADER.read_text(encoding="utf-8")
    body = re.search(r"enum class WebRouteId[^\{]*\{(.*?)\};", text, re.DOTALL)
    if body is None:
        raise AssertionError("WebRouteId enum missing")
    names = set(re.findall(r"^\s*([A-Za-z][A-Za-z0-9_]*)", body.group(1), re.MULTILINE))
    return names - {"None", "ClassicPage", "StaticAsset"}


def _live_sources() -> str:
    text = WEB.read_text(encoding="utf-8")
    body = text.split("void CWebServer::_ProcessLiveAPI", 1)[1]
    body = body.split("void CWebServer::_ProcessFileReq", 1)[0]
    sources = [body]
    sources.extend(path.read_text(encoding="utf-8") for path in sorted((ROOT / "srchybrid").glob("WebLiveApi*Controller.cpp")))
    return "\n".join(sources)


def _handled_route_ids() -> set[str]:
    return set(re.findall(r"WebRouteId::([A-Za-z0-9_]+)", _live_sources()))


def validate_inventory(document: dict) -> None:
    assert set(document) == {
        "schema", "source_contract", "route_contract", "auth_contract",
        "future_owners", "query_keys_baseline", "path_parameters",
        "known_findings", "operations",
    }
    assert document["schema"] == "ese.m2a.w7.live-api-inventory/v1"
    assert document["source_contract"] == {
        "baseline_commit": "b5e8336adaddc91f7180d049b6ef88dc02f50273",
        "handler_surface": [
            "srchybrid/WebServer.cpp", "srchybrid/WebLiveApi*Controller.cpp",
        ],
        "route_resolver": "srchybrid/WebRouteTable.cpp",
        "auth_policy": "srchybrid/WebAuthPolicy.cpp",
        "scope": "inventory_and_regression_only",
        "excluded": ["CWebServer::_ProcessFileReq"],
    }
    route_contract = document["route_contract"]
    assert set(route_contract) == {
        "exact_path_count", "exact_route_id_count", "dynamic_family_count",
        "session_prefix", "method_policy", "parser_limits", "vectors",
    }
    assert (
        route_contract["exact_path_count"],
        route_contract["exact_route_id_count"],
        route_contract["dynamic_family_count"],
    ) == (44, 42, 3)
    assert route_contract["session_prefix"] == {
        "pattern": "/s/{session_token}",
        "bounds": "positive decimal <= INT_MAX; one prefix; LiveApi handlers only",
        "invalid": "403 before dispatch",
        "sensitivity": "credential",
    }
    assert route_contract["method_policy"] == {
        "GET": "dispatch", "OPTIONS": "CorsPreflight 204",
        "POST": "MethodNotAllowed 405", "unknown": "NotFound then fallback 404",
    }
    assert route_contract["parser_limits"] == {
        "target_bytes": 8192, "query_fields": 128, "value_bytes": 65536,
    }
    assert set(route_contract["vectors"]) == {"positive", "negative"}
    assert len(route_contract["vectors"]["positive"]) >= 3
    assert {
        item["id"] for item in route_contract["vectors"]["negative"]
    } == {
        "unknown_route", "post_method", "expired_session_prefix",
        "hostile_dynamic_path", "csrf_failure",
    }
    auth_contract = document["auth_contract"]
    assert set(auth_contract) == {
        "guest_ids", "read_only_ids", "session_browser_mutation",
        "session_non_browser_mutation", "loopback_without_session",
        "unknown_api_role", "unknown_api_mutation", "failure_status",
    }
    assert set(auth_contract["guest_ids"]) == GUEST_IDS
    assert set(auth_contract["read_only_ids"]) == READ_ONLY_IDS
    assert auth_contract["session_browser_mutation"] == (
        "exact valid 64-hex CSRF token required"
    )
    assert auth_contract["session_non_browser_mutation"] == (
        "supplied token must validate; empty accepted only for empty, "
        "same-origin, same-site, or none fetch-site"
    )
    assert auth_contract["loopback_without_session"] == (
        "loopback IP plus local Host plus non-cross-site plus empty/local Origin"
    )
    assert auth_contract["unknown_api_role"] == "admin"
    assert auth_contract["unknown_api_mutation"] is True
    assert auth_contract["failure_status"] == 403
    assert document["query_keys_baseline"] == sorted(EXPECTED_QUERY_KEYS)
    assert document["path_parameters"] == [
        "hls_resource", "session_token", "stream_hash",
    ]
    findings = document["known_findings"]
    assert all(set(item) == FINDING_KEYS for item in findings)
    assert findings == [
        {
            "id": "W7-SEC-01", "severity": "P1",
            "asset": "test-only mutation endpoint",
            "route": "ApiLiveEdgeSabotage", "configuration": "ESE_TEST_HOOKS",
            "observed": (
                "A remote admin token with valid CSRF can reach the "
                "ESE_TEST_HOOKS handler because token auth bypasses the "
                "physical-loopback branch."
            ),
            "intended": "loopback_only",
            "vector": "remote admin token must receive 403 and leave hooks unchanged",
            "disposition": "fix_before_W10_close",
        },
        {
            "id": "W7-SEC-02", "severity": "P1",
            "asset": "session_prefix", "route": "*",
            "configuration": "all builds",
            "observed": (
                "The raw session id is a credential embedded in /s/{id}/ "
                "URLs and can leak through the explicit invalid-token security "
                "log, browser history, copied URLs, and Referer headers."
            ),
            "intended": (
                "non_replayable_or_non_url_session_transport_with_"
                "referrer_suppression"
            ),
            "vector": "bad token canary must not appear in logs or outbound Referer",
            "disposition": "fix_before_W12_close",
        },
    ]
    owners = document["future_owners"]
    assert len(owners) == 7
    assert {
        item["owner"]: item["wave"] for item in owners
    } == OWNER_WAVES
    assert {
        item["owner"]: item["family"] for item in owners
    } == OWNER_FAMILIES
    assert all(
        set(item) == {
            "owner", "wave", "family", "responsibility", "baseline_span_loc",
        }
        and item["responsibility"]
        and isinstance(item["baseline_span_loc"], int)
        and item["baseline_span_loc"] > 0
        for item in owners
    )
    operations = document["operations"]
    assert len(operations) == 45
    ids = [item["id"] for item in operations]
    assert len(ids) == len(set(ids))
    assert set(ids) == EXPECTED_IDS
    assert _route_enum_ids() == EXPECTED_IDS | POST_W7_GOVERNED_IDS
    assert EXPECTED_IDS <= _handled_route_ids()

    exact = _exact_routes()
    assert sum(len(paths) for paths in exact.values()) == 45
    assert len(exact) == 43
    live_sources = _live_sources()
    assert set(re.findall(r'_ParseURL\(\s*Data\.sURL,\s*_T\("([^"]+)"\)\)', live_sources)) == EXPECTED_QUERY_KEYS
    parser_text = PARSER_HEADER.read_text(encoding="utf-8")
    assert all(marker in parser_text for marker in ("kMaxTargetBytes = 8u * 1024u", "kMaxQueryFields = 128u", "kMaxQueryValueBytes = 64u * 1024u"))
    auth_text = AUTH.read_text(encoding="utf-8")
    guest_paths = _array_strings(auth_text, "guestPaths")
    read_only_paths = _array_strings(auth_text, "readOnlyPaths")
    query_seen: set[str] = set()
    mutable_owner: dict[str, str] = {}
    by_id = {item["id"]: item for item in operations}
    assert {
        item_id: item["future_owner"] for item_id, item in by_id.items()
    } == EXPECTED_ASSIGNMENTS

    for item in operations:
        assert set(item) == OPERATION_KEYS
        assert item["family"] == OWNER_FAMILIES[item["future_owner"]]
        assert item["methods"] == ["GET"]
        assert item["route_kind"] in {"exact", "dynamic"}
        assert item["routes"] and len(item["routes"]) == len(set(item["routes"]))
        if item["route_kind"] == "exact":
            assert item["routes"] == exact[item["id"]]
        else:
            assert item["routes"] == EXPECTED_DYNAMIC[item["id"]]
        assert item["role"] == ("guest" if item["id"] in GUEST_IDS else "admin")
        assert item["mutation"] == (item["id"] not in READ_ONLY_IDS)
        expected_csrf = (
            "read_only"
            if item["id"] in READ_ONLY_IDS
            else "session_browser_token_or_trusted_loopback"
        )
        assert item["csrf"] == expected_csrf
        assert OWNER_WAVES[item["future_owner"]] == item["future_wave"]
        assert item["state_owner"] and set(item["state_owner"]) <= ALLOWED_STATE_OWNERS
        assert set(item["mutable_state"]) <= ALLOWED_MUTABLE_STATE
        assert item["effects"] and all(
            set(effect) == {"kind", "target"}
            and effect["kind"] in ALLOWED_EFFECT_KINDS
            and effect["target"] in ALLOWED_STATE_OWNERS
            for effect in item["effects"]
        )
        assert set(item["vectors"]) == VECTOR_KEYS
        assert all(isinstance(item["vectors"][kind], str) and len(item["vectors"][kind]) >= 16 for kind in VECTOR_KEYS) and item["vectors"]["positive"] != item["vectors"]["negative"]
        assert isinstance(item["security_notes"], list) and item["security_notes"] and all(isinstance(note, str) and note for note in item["security_notes"])
        assert all(
            set(rule) == REDACTION_KEYS
            and rule["field"] and rule["surface"]
            and rule["mode"] in {
                "omit", "hash", "escape", "local_only", "intentional_echo",
                "no_log", "aggregate", "bucket", "none",
            }
            for rule in item["redactions"]
        )
        response = item["response"]
        assert set(response) == {"statuses", "content_type", "observable"}
        assert response["statuses"] and all(
            isinstance(value, int) and 100 <= value <= 599
            for value in response["statuses"]
        )
        assert isinstance(response["content_type"], str) and isinstance(response["observable"], str) and len(response["content_type"]) >= 3 and len(response["observable"]) >= 16
        for component in item["mutable_state"]:
            prior = mutable_owner.setdefault(component, item["future_owner"])
            assert prior == item["future_owner"]
        input_names = [input_item["name"] for input_item in item["inputs"]]
        assert len(input_names) == len(set(input_names))
        assert set(input_names) == EXPECTED_INPUTS[item["id"]]
        redacted_fields = {rule["field"] for rule in item["redactions"]}
        for input_item in item["inputs"]:
            assert set(input_item) == INPUT_KEYS
            assert input_item["source"] in {"query", "path"}
            assert isinstance(input_item["required"], bool)
            assert isinstance(input_item["type"], str) and isinstance(input_item["bounds"], str) and len(input_item["type"]) >= 3 and len(input_item["bounds"]) >= 8
            if input_item["required"]:
                assert input_item["default"] is None
            assert input_item["sensitivity"] in {
                "none", "identifier", "network", "user_content",
                "filesystem", "operator_evidence",
            }
            if input_item["source"] == "query":
                query_seen.add(input_item["name"])
            if input_item["sensitivity"] != "none":
                assert input_item["name"] in redacted_fields
                assert any(rule["field"] == input_item["name"] and rule["mode"] != "none" for rule in item["redactions"])
    assert query_seen == EXPECTED_QUERY_KEYS
    assert set(EXPECTED_DYNAMIC) == {
        item["id"] for item in operations if item["route_kind"] == "dynamic"
    }
    assert guest_paths == {
        "/api/status", "/api/live/join", "/api/live/leave",
        "/api/live/player-alive", "/api/live/metrics", "/api/live/channels",
        "/api/live/mesh", "/api/live/kad/streams",
    }
    assert read_only_paths == {
        "/api/status", "/api/live/metrics", "/api/live/channels",
        "/api/live/mesh", "/api/live/kad/streams", "/api/reach/status",
    }
    serialized = json.dumps(document, sort_keys=True)
    for forbidden in (
        r"(?<![A-Za-z0-9_])[0-9a-fA-F]{32}(?![A-Za-z0-9_])",
        r"(?<![A-Za-z0-9_])[0-9a-fA-F]{64}(?![A-Za-z0-9_])",
        r"/s/[1-9][0-9]+/", r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
    ):
        assert re.search(forbidden, serialized) is None


class W7LiveApiInventoryTest(unittest.TestCase):
    def test_m2a_a97059cc2bdf2c42(self):
        self.assertEqual(INVENTORY["schema"], "ese.m2a.w7.live-api-inventory/v1")
        validate_inventory(INVENTORY)

    def test_route_and_auth_fail_closed_contract_is_present(self):
        route_text = ROUTES.read_text(encoding="utf-8")
        auth_text = AUTH.read_text(encoding="utf-8")
        web_text = WEB.read_text(encoding="utf-8")
        for required in (
            "WebRouteMethod::Options", "WebHandler::CorsPreflight",
            "WebRouteStatus::MethodNotAllowed", "retained session credential in HLS path",
            "accepted unknown route",
        ):
            self.assertIn(required, route_text)
        self.assertIn("Fail closed for every API endpoint", auth_text)
        self.assertIn("Unknown APIs are treated as mutations", auth_text)
        self.assertIn("trusted origin or session CSRF required", web_text)
        self.assertIn("HTTP/1.1 404 Not Found", web_text)

    def test_dynamic_patterns_remain_narrow_and_token_prefix_is_bounded(self):
        route_text = ROUTES.read_text(encoding="utf-8")
        for required in (
            'path.compare(0, 5, "/hls/")',
            "IsSafeLeaf(resource, 64)",
            'path.size() == 38',
            'path.compare(0, 6, "/live/")',
            'path.compare(0, 10, "/api/live/")',
            "IsSafeHlsResource(path.substr(43))",
            "ParseSessionPrefix(path, suffix)",
            "token >",
            "static_cast<std::uint64_t>(INT_MAX)",
        ):
            self.assertIn(required, route_text)

    def test_known_security_deltas_are_visible_and_actionable(self):
        findings = {
            item["id"]: item for item in INVENTORY["known_findings"]
        }
        self.assertEqual(findings["W7-SEC-01"]["route"], "ApiLiveEdgeSabotage")
        self.assertIn("remote admin token", findings["W7-SEC-01"]["observed"])
        self.assertEqual(findings["W7-SEC-01"]["intended"], "loopback_only")
        self.assertEqual(findings["W7-SEC-01"]["disposition"], "fix_before_W10_close")
        self.assertEqual(findings["W7-SEC-02"]["asset"], "session_prefix")
        self.assertIn("raw session id", findings["W7-SEC-02"]["observed"])
        self.assertEqual(findings["W7-SEC-02"]["disposition"], "fix_before_W12_close")

    def test_negative_inventory_mutations_are_rejected(self):
        mutations = []
        missing = copy.deepcopy(INVENTORY)
        missing["operations"].pop()
        mutations.append(missing)
        duplicate = copy.deepcopy(INVENTORY)
        duplicate["operations"].append(copy.deepcopy(duplicate["operations"][0]))
        mutations.append(duplicate)
        invented = copy.deepcopy(INVENTORY)
        invented["operations"][0]["id"] = "ApiFutureUnsafe"
        mutations.append(invented)
        widened = copy.deepcopy(INVENTORY)
        widened["operations"][0]["routes"].append("/api/network/connect/*")
        mutations.append(widened)
        degraded_role = copy.deepcopy(INVENTORY)
        next(
            item for item in degraded_role["operations"]
            if item["id"] == "ApiRelayConnect"
        )["role"] = "guest"
        mutations.append(degraded_role)
        degraded_csrf = copy.deepcopy(INVENTORY)
        next(
            item for item in degraded_csrf["operations"]
            if item["id"] == "ApiLiveJoin"
        )["csrf"] = "read_only"
        mutations.append(degraded_csrf)
        moved_family = copy.deepcopy(INVENTORY)
        next(
            item for item in moved_family["operations"]
            if item["id"] == "ApiLiveJoin"
        )["future_owner"] = "WebLiveApiLegacyController"
        mutations.append(moved_family)
        unredacted = copy.deepcopy(INVENTORY)
        next(
            item for item in unredacted["operations"]
            if item["id"] == "ApiLiveDirectJoin"
        )["redactions"] = []
        mutations.append(unredacted)
        no_vector = copy.deepcopy(INVENTORY)
        no_vector["operations"][0]["vectors"] = []
        mutations.append(no_vector)
        conflict = copy.deepcopy(INVENTORY)
        next(item for item in conflict["operations"] if item["id"] == "ApiNetworkConnect")["mutable_state"] = ["stream_session"]
        mutations.append(conflict)
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index):
                with self.assertRaises((AssertionError, KeyError)):
                    validate_inventory(mutation)


if __name__ == "__main__":
    unittest.main()
