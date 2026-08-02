"""M2A-W11 production-bound evidence for the final Live API extraction."""
from __future__ import annotations

import ast
import hashlib
import json
import pathlib
import re
import subprocess
import unittest

from tools.architecture import generate_mod01_architecture_inventory as mod01


ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "srchybrid"
WEB = SRC / "WebServer.cpp"
HEADER = SRC / "WebLiveApiLegacyController.h"
MODULE = SRC / "WebLiveApiLegacyController.cpp"
PROJECT = SRC / "emule.vcxproj"
MATRIX = ROOT / "docs" / "architecture" / "mod52_migration_matrix_v1.json"
OVERLAYS = ROOT / "docs" / "architecture" / "mod01_approved_overlays_v1.json"
W7 = ROOT / "tests" / "goldens" / "v92_m2a_w7_live_api_inventory_v1.json"
BASE = "236f33515fd30379593a56db7a7552ed8fe753ed"
EVIDENCE_PATH = "tests/test_v92_m2a_w11_live_api_legacy.py"
CARD_NEW_PATHS = (
    "srchybrid/WebLiveApiLegacyController.cpp",
    "srchybrid/WebLiveApiLegacyController.h",
    EVIDENCE_PATH,
)
ROUTES = {
    "LegacyHls": "Hls",
    "Dashboard": "Dashboard",
    "ApiEseNetlabReport": "NetlabReport",
    "ApiLivePrivacyTunnelEcho": "TunnelEcho",
    "ApiLivePrivacyTunnelPing": "TunnelPing",
    "ApiLivePrivacyCircuits": "Circuits",
    "ApiLivePrivacyPeers": "Peers",
    "ApiLivePrivacyTestCircuit": "TestCircuit",
    "ApiLivePrivacyKad6Release": "Kad6Release",
    "ApiLivePrivacyKad6Hardening": "Kad6Hardening",
    "LiveIndex": "LiveIndex",
    "LivePlayer": "LivePlayer",
}


def section(source: str, start: str, end: str) -> str:
    return source.split(start, 1)[1].split(end, 1)[0]


def cxx_string_literals(source: str) -> str:
    """Decode adjacent ordinary C++ literals without executing the module."""
    tokens = re.findall(r'"(?:[^"\\]|\\.)*"', source)
    return "".join(ast.literal_eval(token) for token in tokens)


def substitute_player_hash(template: str, stream_hash: str) -> str:
    output: list[str] = []
    index = 0
    while index < len(template):
        if template[index] != "%":
            output.append(template[index])
            index += 1
            continue
        index += 1
        marker = template[index]
        output.append("%" if marker == "%" else stream_hash if marker == "s" else "%" + marker)
        index += 1
    return "".join(output)


def changed(*paths: str) -> tuple[int, int]:
    """Card churn, including an uncommitted candidate during implementation."""
    commits = subprocess.check_output(
        ["git", "log", "--format=%H", "--diff-filter=A", f"{BASE}..HEAD", "--", EVIDENCE_PATH],
        cwd=ROOT, text=True,
    ).splitlines()
    if len(commits) > 1:
        raise AssertionError("W11 evidence has more than one introduction commit")
    command = ["git", "diff", "--numstat", BASE]
    if commits:
        command.append(commits[0])
    command.extend(["--", *paths])
    rows = [line.split("\t") for line in subprocess.check_output(command, cwd=ROOT, text=True).splitlines()]
    assert all(len(row) >= 3 and row[0].isdigit() and row[1].isdigit() for row in rows)
    added = sum(int(row[0]) for row in rows)
    deleted = sum(int(row[1]) for row in rows)
    selected = set(paths) if paths else set(CARD_NEW_PATHS)
    for relative in CARD_NEW_PATHS:
        if relative not in selected:
            continue
        if subprocess.run(["git", "ls-files", "--error-unmatch", relative], cwd=ROOT,
                          capture_output=True).returncode != 0:
            added += len((ROOT / relative).read_text(encoding="utf-8").splitlines())
    return added, deleted


class W11LiveApiLegacyEvidence(unittest.TestCase):
    def test_m2a_3043db2505195477(self) -> None:
        # The frozen W7 family is complete and remains the sole W11 API scope.
        self.assertIn('"future_wave":"W11"', W7.read_text(encoding="utf-8"))
        inventory = json.loads(W7.read_text(encoding="utf-8"))
        owned = [item for item in inventory["operations"] if item["future_wave"] == "W11"]
        self.assertEqual(len(owned), 12)
        self.assertEqual({item["future_owner"] for item in owned}, {"WebLiveApiLegacyController"})
        self.assertEqual({item["id"] for item in owned}, set(ROUTES))
        matrix = json.loads(MATRIX.read_text(encoding="utf-8"))
        module = next(item for item in matrix["additional_modules"] if item["name"] == "WebLiveApiLegacyController")
        self.assertEqual((module["card"], module["parent"], module["dependencies"]), ("W11", "CWebServer", []))
        self.assertEqual(module["budget"], {"module_loc": 1100, "add": 1300, "delete": 850, "net": 250})
        self.assertEqual(matrix["card_budgets"]["W11"], {
            "add": 1300, "delete": 850, "net": 250, "coordinator": "WebServer",
            "facade_add_max": 80, "reduction_required": True,
        })
        overlays = json.loads(OVERLAYS.read_text(encoding="utf-8"))["overlays"]
        web_overlay = next(item for item in overlays if item["path"] == "srchybrid/WebServer.cpp")
        normalized_web = WEB.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        self.assertEqual(web_overlay["overlay_sha256"], hashlib.sha256(normalized_web).hexdigest())
        self.assertIn("MOD-5.2A/W1..W11", web_overlay["task"])
        self.assertIn("W11 transfers", web_overlay["reason"])

    def test_m2a_f7b8ef8211b01002(self) -> None:
        # The module is portable and its own self-test covers every operation.
        self.assertIn("M2A_BIND_W11_55908BF94D", HEADER.read_text(encoding="utf-8"))
        header, source = HEADER.read_text(encoding="utf-8"), MODULE.read_text(encoding="utf-8")
        combined = header + source
        self.assertLessEqual(len(combined.splitlines()), 1100)
        self.assertIn('#include "M2ABindingPort.h"', header)
        self.assertIn("M2A_BIND_W11_55908BF94D", combined)
        self.assertIn("MakeM2AModuleHandle(new WebLiveApiLegacyController", source)
        for forbidden in (
            "WebServer.h", "theApp", "thePrefs", "WebAuthPolicy", "CWebSocket", "SendMessage",
            "CLiveTunnel", "CKad", "CString", "windows.h", "afx", "SendFileResponse", "SendData",
        ):
            self.assertNotIn(forbidden, combined)
        selftest = section(source, "bool RunW11LiveLegacyCharacterizationSelfTest", "} } // namespace ese::web")
        for route, operation in ROUTES.items():
            self.assertIn("W11LegacyOperation::" + operation, selftest, route)
        for negative in (
            "../secret.ts", "not-a-stream", "local_only", "challenge_required_or_expired",
            "confirmation_required", "incomplete_or_bad_evidence", "bad_service_or_enabled",
        ):
            self.assertIn(negative, selftest)
        self.assertIn("release response byte-exact", selftest)
        self.assertIn("hardening response byte-exact", selftest)

        # Frozen literal goldens prevent circular page and legacy-header checks.
        source = MODULE.read_text(encoding="utf-8")
        dashboard = cxx_string_literals(section(
            source, "static const char* DashboardHtml() { return", "\n}\nstatic const char* LiveIndexHtml",
        ))
        index = cxx_string_literals(section(
            source, "static const char* LiveIndexHtml() { return", "\n}\nstd::string SubstitutePlayerHash",
        ))
        player = cxx_string_literals(section(
            source, "static std::string LivePlayerHtml(const std::string& hash) { static const char* const format =",
            "; return SubstitutePlayerHash",
        ))
        rendered_player = substitute_player_hash(player, "0123456789abcdef0123456789abcdef")
        self.assertEqual(hashlib.sha256(dashboard.encode()).hexdigest(),
                         "d8f5cc8064f0783f5bc5bd39bff4d61bfddb911c068c15da0e4994eb3811ffc6")
        self.assertEqual(len(dashboard.encode()), 7805)
        self.assertEqual(hashlib.sha256(index.encode()).hexdigest(),
                         "48364b9bf51f5575804fe2f7b971168c5fb801d6a188ed0d2f161dc39314eef4")
        self.assertEqual(hashlib.sha256(rendered_player.encode()).hexdigest(),
                         "e6cdaf371348626bfff95fa2caf8ce558e4d0d8d7ff3e3173907f6188c9a9105")
        self.assertEqual(rendered_player.count("0123456789abcdef0123456789abcdef"), 3)
        self.assertIn(
            'Content-Type: application/json\\r\\nCache-Control: no-store\\r\\nContent-Length: ', source,
        )
        for begin, end in (("bool Netlab", "bool Echo"), ("bool Circuits", "bool Peers")):
            self.assertIn("o.imbue(std::locale::classic())", section(source, begin, end))

    def test_m2a_1832a7b52536b9b3(self) -> None:
        # Every W11 route reaches production dispatch once, after the common gate.
        self.assertIn("M2A_BIND_W11_55908BF94D(M2AParentPort{this})", WEB.read_text(encoding="utf-8"))
        facade = WEB.read_text(encoding="utf-8", errors="replace")
        self.assertNotIn('#include "WebLiveApiLegacyController.h"', facade)
        self.assertNotIn("WebLiveApiLegacyController final", facade)
        self.assertIn("M2A_BIND_W11_55908BF94D(M2AParentPort{this})", facade)
        self.assertIn("M2A_UNBIND_W11_55908BF94D(M2AParentPort{this})", facade)
        self.assertIn("RunW11LiveLegacyCharacterizationSelfTest", facade)
        self.assertIn("WebLiveApiLegacyController.cpp", PROJECT.read_text(encoding="utf-8"))
        self.assertIn("WebLiveApiLegacyController.h", PROJECT.read_text(encoding="utf-8"))
        for relative in ("tools/architecture/verify_mod02_characterization.py", "tools/architecture/run_mod02_stream_selftest.ps1"):
            self.assertIn("WebLiveApiLegacyController.cpp", (ROOT / relative).read_text(encoding="utf-8"))
        body = section(facade, "void CWebServer::_ProcessLiveAPI", "void CWebServer::_ProcessFileReq")
        dispatch = re.findall(r"\bRunW11LiveLegacyApi\s*\(", body)
        self.assertEqual(len(dispatch), 1, "W11 must have one productive dispatch, not a self-test-only binding")
        self.assertLess(body.index("AuthorizeLiveRequest"), body.index("RunW11LiveLegacyApi"))
        self.assertLess(body.index("RequiredRoleForLivePath"), body.index("RunW11LiveLegacyApi"))
        for route in ROUTES:
            self.assertEqual(len(re.findall(r"WebRouteId::" + re.escape(route) + r"\b", body)), 1, route)
        for inline in (
            "TunnelEchoLarge", "CLiveTunnel::Get().TunnelPing", "GetCircuitsSnapshot", "GetPeersSnapshot",
            "RequestTestCircuit", "RequestK6PublicRelease", "RequestK6ServiceSwitch",
            "GetK6ReleaseSnapshot", "GetK6HardeningSnapshot", "const char* dashHtml",
            "Loading channels...", "hls.js@latest",
        ):
            self.assertNotIn(inline, body, inline)
        adapter = section(facade, "struct W11LegacyContext", "static void SendW11Response")
        release_adapter = section(adapter, "static bool ReadRelease", "static bool Hardening")
        hardening_adapter = section(adapter, "static bool ReadHardening", "static ese::web::W11LegacyPort Port")
        self.assertGreaterEqual(release_adapter.count("try{"), 2, "release state and challenge reads must fail independently")
        self.assertGreaterEqual(hardening_adapter.count("try{"), 2, "hardening and exit-notice reads must fail independently")

    def test_m2a_5e591905a00ae160(self) -> None:
        # Churn is a genuine coordinator reduction, including static-file dispatch.
        self.assertIn("void CWebServer::_ProcessLiveAPI", WEB.read_text(encoding="utf-8"))
        self.assertEqual(
            mod01.strip_comments('value = "http://127.0.0.1"; // trailing'),
            'value = "http://127.0.0.1"; ',
        )
        self.assertEqual(
            mod01.strip_comments(r'value = "escaped\"//still literal"; // trailing'),
            r'value = "escaped\"//still literal"; ',
        )
        self.assertEqual(mod01.strip_comments("char slash = '/'; // trailing"), "char slash = '/'; ")
        self.assertEqual(mod01.strip_comments("int slash = '//'; // trailing"), "int slash = '//'; ")
        self.assertEqual(mod01.strip_comments("auto n = 1'000; // trailing"), "auto n = 1'000; ")
        self.assertEqual(
            mod01.strip_comments('auto raw = R"tag(a"//host/{x})tag"; // trailing'),
            'auto raw = R"tag(a"//host/{x})tag"; ',
        )
        live_lengths = [item["length_approx"] for item in mod01.functions(
            WEB.read_text(encoding="utf-8", errors="replace").splitlines(),
            "CWebServer", "srchybrid/WebServer.cpp",
        ) if item["name"] == "CWebServer::_ProcessLiveAPI"]
        self.assertEqual(len(live_lengths), 1)
        self.assertLessEqual(live_lengths[0], 150)
        file_body = section(WEB.read_text(encoding="utf-8", errors="replace"),
                            "void CWebServer::_ProcessFileReq", "CString CWebServer::_GetWebImageNameForFileType")
        self.assertRegex(file_body, r"\bRunW11LiveLegacy\w*\s*\(")
        for inline in ("thePrefs", "SendFileResponse", "WebFileResponseOptions", "filename.Replace"):
            self.assertNotIn(inline, file_body, inline)
        added, deleted = changed()
        facade_added, facade_deleted = changed("srchybrid/WebServer.cpp", "srchybrid/WebServer.h")
        self.assertLessEqual(added, 1300)
        self.assertGreaterEqual(deleted, 850)
        self.assertLessEqual(added - deleted, 250)
        self.assertLessEqual(facade_added, 80)
        self.assertGreater(facade_deleted, facade_added)


if __name__ == "__main__":
    unittest.main()
