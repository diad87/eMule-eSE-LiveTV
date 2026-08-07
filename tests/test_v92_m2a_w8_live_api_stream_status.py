"""M2A-W8 source-bound evidence for the Live API stream/status split."""
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
MODULES = {
    "WebLiveApiStreamController": (700, "M2A_BIND_W8_4974C0F316", {
        "ApiLiveJoin", "ApiLiveLeave", "ApiLivePlayerAlive",
        "ApiLiveBroadcastStart", "ApiLiveBroadcastStop", "ApiLiveDirectJoin",
        "ApiLiveStream",
    }, {"Join", "Leave", "PlayerAlive", "BroadcastStart", "BroadcastStop", "DirectJoin", "StreamFile"}),
    "WebLiveApiStatusController": (650, "M2A_BIND_W8_E988965D5A", {
        "ApiStatus", "ApiLiveChannels", "ApiLiveMesh",
    }, {"Status", "Channels", "Mesh"}),
}
BASE = "6e1406ab8bedc924fd4ae3a178230eaced00fd1a"
EVIDENCE_PATH = "tests/test_v92_m2a_w8_live_api_stream_status.py"
CARD_NEW_PATHS = tuple(
    f"srchybrid/{name}{suffix}"
    for name in MODULES
    for suffix in (".cpp", ".h")
) + (EVIDENCE_PATH,)
MOVED_LEGACY = {
    "WebNetworkStatusDiagnostics", "LiveChannelSnapshot",
    "WebLiveMeshDiagnostics", "LiveWebLeaveReq", "UM_LIVE_WEB_LEAVE",
    "LiveWebBroadcastReq", "UM_LIVE_WEB_BROADCAST", "LiveWebJoinReq",
    "UM_LIVE_WEB_JOIN",
}
ODR_TYPES = {
    "WebLiveApiStreamController.h": (
        "W8LiveStreamOperation", "W8LiveStreamRequest", "W8LiveStreamAddress",
        "W8LiveStreamResponse", "W8LiveBroadcastRequest", "W8LiveStreamPort",
    ),
    "WebLiveApiStatusController.h": (
        "W8LiveStatusOperation", "W8LiveStatusSnapshot", "W8LiveChannelSnapshot",
        "W8LiveMeshSnapshot", "W8LiveStatusPort", "W8LiveStatusResponse",
    ),
}


def text(name: str, suffix: str) -> str:
    return (SRC / (name + suffix)).read_text(encoding="utf-8")


def live_body() -> str:
    source = WEB.read_text(encoding="utf-8")
    return source.split("void CWebServer::_ProcessLiveAPI", 1)[1].split(
        "void CWebServer::_ProcessFileReq", 1
    )[0]


def changed(*paths: str) -> tuple[int, int]:
    commits = subprocess.check_output(
        [
            "git", "log", "--format=%H", "--diff-filter=A",
            f"{BASE}..HEAD", "--", EVIDENCE_PATH,
        ],
        cwd=ROOT,
        text=True,
    ).splitlines()
    if len(commits) > 1:
        raise AssertionError("W8 evidence has more than one introduction commit")
    target = commits[0] if commits else None
    command = ["git", "diff", "--numstat", BASE]
    if target is not None:
        command.append(target)
    command.extend(["--", *paths])
    output = subprocess.check_output(
        command, cwd=ROOT, text=True
    )
    rows = [line.split("\t") for line in output.splitlines()]
    assert all(len(row) >= 3 and row[0].isdigit() and row[1].isdigit() for row in rows)
    added = sum(int(row[0]) for row in rows)
    deleted = sum(int(row[1]) for row in rows)
    if target is None:
        selected = set(paths) if paths else set(CARD_NEW_PATHS)
        for relative in CARD_NEW_PATHS:
            if relative not in selected:
                continue
            tracked = subprocess.run(
                ["git", "ls-files", "--error-unmatch", relative],
                cwd=ROOT,
                capture_output=True,
                check=False,
            )
            if tracked.returncode != 0:
                added += len((ROOT / relative).read_text(encoding="utf-8").splitlines())
    return added, deleted


def declaration(source: str, name: str) -> str:
    """Return a named type definition with comments/whitespace removed."""
    match = re.search(r"\b(?:enum\s+class|class|struct)\s+" + re.escape(name) + r"\b", source)
    if match is None:
        raise AssertionError(f"missing type definition: {name}")
    opening = source.find("{", match.end())
    if opening < 0:
        raise AssertionError(f"incomplete type definition: {name}")
    depth = 0
    closing = -1
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                closing = index
                break
    if closing < 0:
        raise AssertionError(f"unbalanced type definition: {name}")
    value = source[match.start():closing + 1]
    value = re.sub(r"/\*.*?\*/|//[^\r\n]*", "", value, flags=re.S)
    return re.sub(r"\s+", "", value)


class W8LiveApiEvidence(unittest.TestCase):
    def test_card_churn_budget_is_activation_bound(self):
        added, deleted = changed()
        facade_added, facade_deleted = changed(
            "srchybrid/WebServer.cpp", "srchybrid/WebServer.h"
        )
        self.assertLessEqual(added, 1100)
        self.assertGreaterEqual(deleted, 800)
        self.assertLessEqual(added - deleted, 300)
        self.assertLessEqual(facade_added, 80)
        self.assertGreater(facade_deleted, facade_added)

    def test_m2a_1920352fa03db0c5(self):
        self.assertTrue(all((SRC / (name + ".cpp")).is_file() for name in MODULES))
        inventory = json.loads(W7.read_text(encoding="utf-8"))
        self.assertEqual(len(inventory["operations"]), 45)
        self.assertEqual(
            {item["id"] for item in inventory["operations"] if item["future_wave"] == "W8"},
            set().union(*(item[2] for item in MODULES.values())),
        )
        sources = live_body() + "\n" + "\n".join(
            text(name, ".cpp") for name in MODULES
        )
        self.assertEqual(
            set(re.findall(r'_ParseURL\(\s*Data\.sURL,\s*_T\("([^"]+)"\)', sources)),
            set(inventory["query_keys_baseline"]),
        )
        facade = WEB.read_text(encoding="utf-8")
        for header_name, names in ODR_TYPES.items():
            header = (SRC / header_name).read_text(encoding="utf-8")
            for name in names:
                self.assertEqual(declaration(facade, name), declaration(header, name), name)

    def test_m2a_b1be3e80702fbf7d(self):
        self.assertTrue((SRC / "WebLiveApiStreamController.cpp").is_file())
        self._module_contract("WebLiveApiStreamController")

    def test_m2a_5110d5c4a70e577c(self):
        self.assertIn(MODULES["WebLiveApiStreamController"][1], WEB.read_text(encoding="utf-8"))
        self._binding_contract("WebLiveApiStreamController")

    def test_m2a_35f29c8a21cf7b8b(self):
        self.assertTrue((SRC / "WebLiveApiStatusController.cpp").is_file())
        self._module_contract("WebLiveApiStatusController")

    def test_m2a_a8abad19e464e861(self):
        self.assertIn(MODULES["WebLiveApiStatusController"][1], WEB.read_text(encoding="utf-8"))
        self._binding_contract("WebLiveApiStatusController")

    def _module_contract(self, name: str) -> None:
        limit, _binding, _routes, operations = MODULES[name]
        header, source = text(name, ".h"), text(name, ".cpp")
        combined = header + source
        self.assertLessEqual(len(combined.splitlines()), limit)
        self.assertIn("RunW8Live", combined)
        self.assertTrue(all(operation in combined for operation in operations))
        self.assertNotIn("WebRoute", combined)
        self.assertIn('#include "M2ABindingPort.h"', header)
        self.assertRegex(header, rf"\bexplicit\s+{name}\s*\(\s*const\s+M2AParentPort\s*&")
        self.assertIn(_binding, source); self.assertIn("MakeM2AModuleHandle(new " + name + "(parent))", source)
        self.assertNotRegex(combined, r"\b(?:WebAuthPolicy|Authorize\w*|Validate(?:Csrf|CSRF|Session|Token)\w*|IsAdmin|(?:Guest|Admin)Role|Session(?:Gate|Policy|Token)?)\b")
        if name.endswith("StatusController"):
            self.assertIn("Authorization, X-CSRF-Token, Content-Type", source)
        for forbidden in ("WebServer.h", "WebApiSerializer", "WebDiagnostics", "LiveStreamManager", "windows.h", "afx"):
            self.assertNotIn(forbidden, combined)
        matrix = json.loads(MATRIX.read_text(encoding="utf-8"))
        row = next(item for item in matrix["additional_modules"] if item["name"] == name)
        self.assertEqual((row["card"], row["dependencies"]), ("W8", []))
        node = re.search(r'<ClCompile Include="' + name + r'\.cpp">(.*?)</ClCompile>', PROJECT.read_text(encoding="utf-8"), re.S)
        self.assertIsNotNone(node)
        for setting in ("<PrecompiledHeader>NotUsing</PrecompiledHeader>", "<WarningLevel>Level4</WarningLevel>", "<TreatWarningAsError>true</TreatWarningAsError>", "<LanguageStandard>stdcpp17</LanguageStandard>"):
            self.assertIn(setting, node.group(1))

    def _binding_contract(self, name: str) -> None:
        _limit, binding, routes, _operations = MODULES[name]
        facade, source = WEB.read_text(encoding="utf-8"), text(name, ".cpp")
        self.assertIn(binding, source); self.assertIn(binding, facade)
        other = next(value[1] for key, value in MODULES.items() if key != name)
        self.assertNotEqual(binding, other); self.assertNotIn(other, source)
        selftest = "RunW8Live" + ("Stream" if "Stream" in name else "Status") + "CharacterizationSelfTest"
        self.assertIn(selftest, source); self.assertIn(selftest, facade.split("bool CWebServer::RunCharacterizationSelfTest", 1)[1].split("CString CWebServer::_SpecialChars", 1)[0])
        self.assertNotIn(name, facade)
        body = live_body()
        self.assertTrue(all(body.count("WebRouteId::" + route) == 1 for route in routes))
        self.assertTrue(all(marker not in body for marker in MOVED_LEGACY))
        if name.endswith("StatusController"):
            adapter = declaration(facade, "W8StatusContext")
            for method in ("ReadStatus", "ReadChannel", "ReadMesh", "Send"):
                self.assertIn("static", adapter); self.assertIn(method, adapter)
            self.assertNotRegex(facade, r"\b(?:bool|void)\s+W8(?:ReadStatus|ReadChannel|ReadMesh|Send)\b")
            channel = facade.split("bool W8StatusContext::ReadChannel", 1)[1].split("bool W8StatusContext::ReadMesh", 1)[0]
            mesh = facade.split("bool W8StatusContext::ReadMesh", 1)[1].split("void W8StatusContext::Send", 1)[0]
            self.assertEqual(channel.count("GetChannelSnapshot()"), 1)
            self.assertEqual(mesh.count("BuildDebugSnapshot()"), 1)
            self.assertIn("out.title=W8Legacy(snapshot.title)", re.sub(r"\s+", "", channel))
            self.assertIn("W8StatusContext::Send(Data.pSocket,response.header,response.body)", re.sub(r"\s+", "", body))
        else:
            compact = re.sub(r"\s+", "", body)
            self.assertIn("StrToUtf8(text)", facade)
            self.assertIn("OptUtf8ToStr(text.data(),static_cast<int>(text.size()))", re.sub(r"\s+", "", facade))
            self.assertIn(r'_T("\x0416")', facade)
            self.assertIn("W8Legacy(text)", facade)
            self.assertIn("EncodeURLQueryParam(text)", facade)
            self.assertIn("W8BuildLiveStreamHeader(response)", compact)
            self.assertIn("W8BuildLiveStreamHeader", source)
            self.assertIn('options.corsOrigin="http://127.0.0.1";', compact)
            self.assertIn(
                "SendFileResponse(path,resource,Data.sRange,options,"
                "20ull*1024ull*1024ull,true,false)", compact,
            )
        for relative in ("tools/architecture/verify_mod02_characterization.py", "tools/architecture/run_mod02_stream_selftest.ps1"):
            self.assertIn(name + ".cpp", (ROOT / relative).read_text(encoding="utf-8"))

if __name__ == "__main__":
    unittest.main()
