"""M2A-W10 source-bound evidence for settings and diagnostics extraction."""
from __future__ import annotations

import json
import pathlib
import re
import subprocess
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "srchybrid"
WEB = SRC / "WebServer.cpp"
PROJECT = SRC / "emule.vcxproj"
MATRIX = ROOT / "docs" / "architecture" / "mod52_migration_matrix_v1.json"
W7 = ROOT / "tests" / "goldens" / "v92_m2a_w7_live_api_inventory_v1.json"
MOD27 = ROOT / "docs" / "architecture" / "mod27_web_diagnostics_contract_v1.json"
BASE = "1a4993b27be9fb3af4ec67200a63f00965b634f7"
EVIDENCE_PATH = "tests/test_v92_m2a_w10_live_api_settings_diagnostics.py"
MODULES = {
    "WebLiveApiSettingsController": (
        650,
        "M2A_BIND_W10_E9722EA045",
        {"ApiEseV9", "ApiLivePrivacy", "ApiLiveEdgeSabotage"},
        {"EseV9", "Privacy", "EdgeSabotage"},
    ),
    "WebLiveApiDiagnosticsController": (
        650,
        "M2A_BIND_W10_47570D3256",
        {"ApiKrpStatus", "ApiLivePreflight", "ApiLiveMetrics", "ApiLiveLog", "ApiLiveDebug"},
        {"KrpStatus", "Preflight", "Metrics", "Log", "Debug"},
    ),
}
ODR_TYPES = {
    "WebLiveApiSettingsController.h": (
        "W10SettingsOperation", "W10SettingsRequest", "W10NetlabSnapshot",
        "W10PrivacySnapshot", "W10SettingsResponse", "W10SettingsPort",
    ),
    "WebLiveApiDiagnosticsController.h": (
        "W10DiagnosticsOperation", "W10DiagnosticsRequest", "W10PreflightSnapshot",
        "W10MetricsSnapshot", "W10DebugPeer", "W10DebugSnapshot",
        "W10DiagnosticsResponse", "W10DiagnosticsPort",
    ),
}
CARD_NEW_PATHS = tuple(
    f"srchybrid/{name}{suffix}" for name in MODULES for suffix in (".cpp", ".h")
) + (EVIDENCE_PATH,)


def text(name: str, suffix: str) -> str:
    return (SRC / (name + suffix)).read_text(encoding="utf-8")


def live_body() -> str:
    source = WEB.read_text(encoding="utf-8", errors="replace")
    return source.split("void CWebServer::_ProcessLiveAPI", 1)[1].split(
        "void CWebServer::_ProcessFileReq", 1
    )[0]


def changed(*paths: str) -> tuple[int, int]:
    commits = subprocess.check_output(
        ["git", "log", "--format=%H", "--diff-filter=A", f"{BASE}..HEAD", "--", EVIDENCE_PATH],
        cwd=ROOT, text=True,
    ).splitlines()
    if len(commits) > 1:
        raise AssertionError("W10 evidence has more than one introduction commit")
    target = commits[0] if commits else None
    command = ["git", "diff", "--numstat", BASE]
    if target is not None:
        command.append(target)
    command.extend(["--", *paths])
    rows = [line.split("\t") for line in subprocess.check_output(command, cwd=ROOT, text=True).splitlines()]
    assert all(len(row) >= 3 and row[0].isdigit() and row[1].isdigit() for row in rows)
    added = sum(int(row[0]) for row in rows)
    deleted = sum(int(row[1]) for row in rows)
    if target is None:
        selected = set(paths) if paths else set(CARD_NEW_PATHS)
        for relative in CARD_NEW_PATHS:
            if relative in selected and subprocess.run(
                ["git", "ls-files", "--error-unmatch", relative], cwd=ROOT,
                capture_output=True,
            ).returncode != 0:
                added += len((ROOT / relative).read_text(encoding="utf-8").splitlines())
    return added, deleted


def declaration(source: str, name: str) -> str:
    match = re.search(r"\b(?:enum\s+class|class|struct)\s+" + re.escape(name) + r"\b", source)
    if match is None:
        raise AssertionError(f"missing type definition: {name}")
    opening = source.find("{", match.end())
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                value = source[match.start():index + 1]
                return re.sub(r"\s+", "", re.sub(r"/\*.*?\*/|//[^\r\n]*", "", value, flags=re.S))
    raise AssertionError(f"unbalanced type definition: {name}")


class W10LiveApiEvidence(unittest.TestCase):
    def test_m2a_7a5ab5e8946a21b4(self) -> None:
        self.assertTrue(WEB.is_file() and PROJECT.is_file())
        added, deleted = changed()
        facade_added, facade_deleted = changed("srchybrid/WebServer.cpp", "srchybrid/WebServer.h")
        self.assertLessEqual(added, 1100)
        self.assertGreaterEqual(deleted, 800)
        self.assertLessEqual(added - deleted, 300)
        self.assertLessEqual(facade_added, 80)
        self.assertGreater(facade_deleted, facade_added)
        inventory = json.loads(W7.read_text(encoding="utf-8"))
        owned = [item for item in inventory["operations"] if item["future_wave"] == "W10"]
        self.assertEqual(len(owned), 8)
        self.assertEqual({item["future_owner"] for item in owned}, set(MODULES))
        self.assertEqual(
            next(item for item in inventory["known_findings"] if item["id"] == "W7-SEC-01")["disposition"],
            "fix_before_W10_close",
        )
        facade = WEB.read_text(encoding="utf-8", errors="replace")
        for header_name, names in ODR_TYPES.items():
            header = (SRC / header_name).read_text(encoding="utf-8")
            for name in names:
                self.assertEqual(declaration(facade, name), declaration(header, name), name)
        body = live_body()
        routes = set().union(*(item[2] for item in MODULES.values()))
        self.assertTrue(all(len(re.findall(r"WebRouteId::" + re.escape(route) + r"\b", body)) == 1 for route in routes))
        first_route = min(body.index("WebRouteId::" + route) for route in routes)
        self.assertIn("AuthorizeLiveRequest", body[:first_route])
        self.assertIn("RequiredRoleForLivePath", body[:first_route])
        for moved in (
            "ApplyEseNetLabPreferenceState", "GetStatusJson", "FindFFmpeg",
            "GetK6PrometheusMetrics", "CLiveDebugLog::Get", "WebDiagnostics::Serialize(debug)",
        ):
            self.assertNotIn(moved, body)
        settings = text("WebLiveApiSettingsController", ".cpp")
        remote_start = settings.index("!request.loopback")
        remote = settings[remote_start:settings.index("W10SettingsOperation::EseV9", remote_start)]
        forbidden_return = remote.index("return true")
        self.assertLess(remote.index("response.status = 403"), forbidden_return)
        self.assertNotIn("set_edge_sabotage", remote[:forbidden_return])
        self.assertIn("#ifdef ESE_TEST_HOOKS", body)
        self.assertEqual(json.loads(MOD27.read_text(encoding="utf-8"))["module"]["routes"], ["/api/status", "/api/live/mesh"])
        self.assertNotIn("W10DebugSnapshot", (SRC / "WebDiagnostics.h").read_text(encoding="utf-8"))

    def test_m2a_06b807893f0f86e0(self) -> None:
        self.assertTrue((SRC / "WebLiveApiSettingsController.cpp").is_file())
        self._module_contract("WebLiveApiSettingsController")
        source = text("WebLiveApiSettingsController", ".cpp")
        self.assertIn("explicit_consent_required", source)
        self.assertIn("invalid_on_value", source)
        self.assertIn("persist_failed", source)
        self.assertIn("loopback required", source)
        self.assertIn("Content-Type: text/html\\r\\n", source)
        self.assertLess(source.index("port.post_krp_event"), source.index("W10NetlabSnapshot snapshot"))

    def test_m2a_d690a30c862dfafd(self) -> None:
        self.assertEqual(text("WebLiveApiSettingsController", ".cpp").count("M2A_BIND_W10_E9722EA045"), 1)
        self._binding_contract("WebLiveApiSettingsController")
        body = live_body()
        compact = re.sub(r"\s+", "", body)
        self.assertIn("RunW10LiveSettingsApi(settings,port,response)", compact)
        self.assertIn("settings.loopback=Data.inadr.S_un.S_addr==htonl(INADDR_LOOPBACK)", compact)
        self.assertIn('settings.add_sensitive=W8Utf8(_ParseURL(Data.sURL,_T("add_sensitive")))', compact)
        self.assertIn('settings.rm_sensitive=W8Utf8(_ParseURL(Data.sURL,_T("rm_sensitive")))', compact)

    def test_m2a_4cee5b0a0dc6b39a(self) -> None:
        self.assertTrue((SRC / "WebLiveApiDiagnosticsController.cpp").is_file())
        self._module_contract("WebLiveApiDiagnosticsController")
        source = text("WebLiveApiDiagnosticsController", ".cpp")
        for token in (
            "Content-Type: text/plain; version=0.0.4; charset=utf-8",
            "Content-Type: text/html\\r\\n", "DebugUnavailable", "Age(",
            "count>16u", "q.log_n<=0?100:q.log_n>500?500:q.log_n",
            "available debug response remains byte-exact",
            "unavailable debug response remains byte-exact",
        ):
            self.assertIn(token, source)
        metrics = source[source.index("W10DiagnosticsOperation::Metrics"):source.index("W10DiagnosticsOperation::Log")]
        self.assertLess(metrics.index("read_metrics"), metrics.index("read_percentiles"))
        self.assertLess(metrics.index("read_percentiles"), metrics.index("read_latency_mean"))
        self.assertLess(metrics.index("read_latency_mean"), metrics.index("read_latency_samples"))
        self.assertLess(metrics.index("read_latency_samples"), metrics.index("read_kad6_metrics"))

    def test_m2a_d150ba5bebc220bb(self) -> None:
        self.assertEqual(text("WebLiveApiDiagnosticsController", ".cpp").count("M2A_BIND_W10_47570D3256"), 1)
        self._binding_contract("WebLiveApiDiagnosticsController")
        compact = re.sub(r"\s+", "", WEB.read_text(encoding="utf-8", errors="replace"))
        self.assertIn("RunW10LiveDiagnosticsApi(diagnostics,port,response)", compact)
        debug = next(line for line in WEB.read_text(encoding="utf-8", errors="replace").splitlines() if line.startswith("bool W10DiagnosticsContext::Debug"))
        self.assertEqual(debug.count("BuildDebugSnapshot()"), 1)
        self.assertLess(debug.index("BuildDebugSnapshot()"), debug.index("GetTickCount()"))

    def _module_contract(self, name: str) -> None:
        limit, binding, _routes, operations = MODULES[name]
        header, source = text(name, ".h"), text(name, ".cpp")
        combined = header + source
        self.assertLessEqual(len(combined.splitlines()), limit)
        self.assertTrue(all(operation in combined for operation in operations))
        self.assertIn('#include "M2ABindingPort.h"', header)
        self.assertNotIn("WebRoute", combined)
        self.assertRegex(header, rf"\bexplicit\s+{name}\s*\(\s*const\s+M2AParentPort\s*&")
        self.assertRegex(source, rf"M2AModuleHandle\s+{binding}\s*\(\s*const\s+M2AParentPort\s*&\s*parent\s*\)")
        self.assertIn("MakeM2AModuleHandle(new " + name, source)
        self.assertNotRegex(combined, r"\b(?:WebAuthPolicy|Authorize\w*|Validate(?:Csrf|CSRF|Session|Token)\w*|IsAdmin)\b")
        for forbidden in ("WebServer.h", "WebApiSerializer", "WebDiagnostics", "windows.h", "afx", "CString", "theApp", "thePrefs"):
            self.assertNotIn(forbidden, combined)
        row = next(item for item in json.loads(MATRIX.read_text(encoding="utf-8"))["additional_modules"] if item["name"] == name)
        self.assertEqual((row["card"], row["dependencies"]), ("W10", []))
        node = re.search(r'<ClCompile Include="' + name + r'\.cpp">(.*?)</ClCompile>', PROJECT.read_text(encoding="utf-8"), re.S)
        self.assertIsNotNone(node)
        for setting in ("<PrecompiledHeader>NotUsing</PrecompiledHeader>", "<WarningLevel>Level4</WarningLevel>", "<TreatWarningAsError>true</TreatWarningAsError>", "<LanguageStandard>stdcpp17</LanguageStandard>"):
            self.assertIn(setting, node.group(1))
        self.assertIn("CharacterizationSelfTest", source)
        for relative in ("tools/architecture/verify_mod02_characterization.py", "tools/architecture/run_mod02_stream_selftest.ps1"):
            self.assertIn(name + ".cpp", (ROOT / relative).read_text(encoding="utf-8"))

    def _binding_contract(self, name: str) -> None:
        _limit, binding, routes, _operations = MODULES[name]
        facade = WEB.read_text(encoding="utf-8", errors="replace")
        source = text(name, ".cpp")
        self.assertEqual(facade.count(binding), 2)
        self.assertIn("MakeM2AModuleHandle(new " + name, source)
        self.assertNotIn(name, facade)
        self.assertRegex(facade, rf"M2AModuleHandle\s+\w+\s*=\s*{binding}\(M2AParentPort\{{this\}}\);\s*if\s*\(!\w+\)\s*return;")
        self.assertIn(binding.replace("BIND", "UNBIND") + "(M2AParentPort{this})", facade)
        body = live_body()
        self.assertTrue(all(len(re.findall(r"WebRouteId::" + re.escape(route) + r"\b", body)) == 1 for route in routes))
        self.assertIn("CharacterizationSelfTest", source)
        self.assertIn(
            "RunW10Live" + ("Settings" if "Settings" in name else "Diagnostics") + "CharacterizationSelfTest",
            facade.split("bool CWebServer::RunCharacterizationSelfTest", 1)[1].split("CString CWebServer::_SpecialChars", 1)[0],
        )


if __name__ == "__main__":
    unittest.main()
