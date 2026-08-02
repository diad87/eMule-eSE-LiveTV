"""M2A-W9 source-bound evidence for the Live API transfer/search split."""
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
BASE = "3fd02e53fa97fa8b9d1f2a6c5e9e9fec06c5e890"
EVIDENCE_PATH = "tests/test_v92_m2a_w9_live_api_transfer_search.py"
MODULES = {
    "WebLiveApiTransferController": (700, "M2A_BIND_W9_52CC9DEBDD", {
        "ApiNetworkConnect", "ApiHolePunchRendezvousTest", "ApiKeepaliveStart",
        "ApiKeepaliveStop", "ApiRelayAccept", "ApiRelayEgress", "ApiRelaySelector",
        "ApiRelayConnect", "ApiHolePunchTest",
    }, {"NetworkConnect", "Rendezvous", "KeepaliveStart", "KeepaliveStop",
        "RelayAccept", "RelayEgress", "RelaySelector", "RelayConnect", "HolePunch"}),
    "WebLiveApiSearchController": (650, "M2A_BIND_W9_3B359EBB1A", {
        "ApiDebugSourceResolutions", "ApiLivePrivacySubscriptions",
        "ApiLivePrivacyTunnelSearch", "ApiLiveDiagnose", "ApiLiveKadStreams",
    }, {"SourceResolutions", "PrivacySubscriptions", "TunnelSearch", "Diagnose", "KadStreams"}),
}
CARD_NEW_PATHS = tuple(
    f"srchybrid/{name}{suffix}" for name in MODULES for suffix in (".cpp", ".h")
) + (EVIDENCE_PATH,)
ODR_TYPES = {
    "WebLiveApiTransferController.h": (
        "W9LiveTransferOperation", "W9LiveTransferRate", "W9LiveRelayToggle",
        "W9LiveTransferGuard", "W9LiveTransferRequest", "W9LiveTransferRateDecision",
        "W9LiveHolePunchResult", "W9LiveTransferSnapshot", "W9LiveTransferResponse",
        "W9LiveTransferPort",
    ),
    "WebLiveApiSearchController.h": (
        "W9SearchOperation", "W9SearchRequest", "W9SourceCandidate", "W9SourceEvent",
        "W9Subscription", "W9DirectoryEntry", "W9DiagnoseSnapshot", "W9KadStream",
        "W9SearchPort", "W9SearchResponse",
    ),
}
MOVED_LEGACY = {
    "WEBGUIIA_CONNECTTOSERVER", "WEBGUIIA_KAD_START", "InitiateKad3Rendezvous",
    "SetEseRelayAccept", "SetEseRelayEgress", "SetEseReachSelector",
    "GetSourceResolutionEvents", "AddSubscription", "RemoveSubscription", "SearchStreams",
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
        ["git", "log", "--format=%H", "--diff-filter=A", f"{BASE}..HEAD", "--", EVIDENCE_PATH],
        cwd=ROOT, text=True,
    ).splitlines()
    if len(commits) > 1:
        raise AssertionError("W9 evidence has more than one introduction commit")
    target = commits[0] if commits else None
    command = ["git", "diff", "--numstat", BASE]
    if target is not None:
        command.append(target)
    command.extend(["--", *paths])
    rows = [line.split("\t") for line in subprocess.check_output(command, cwd=ROOT, text=True).splitlines()]
    assert all(len(row) >= 3 and row[0].isdigit() and row[1].isdigit() for row in rows)
    added, deleted = sum(int(row[0]) for row in rows), sum(int(row[1]) for row in rows)
    if target is None:
        selected = set(paths) if paths else set(CARD_NEW_PATHS)
        for relative in CARD_NEW_PATHS:
            if relative not in selected:
                continue
            tracked = subprocess.run(["git", "ls-files", "--error-unmatch", relative], cwd=ROOT, capture_output=True)
            if tracked.returncode != 0:
                added += len((ROOT / relative).read_text(encoding="utf-8").splitlines())
    return added, deleted


def declaration(source: str, name: str) -> str:
    match = re.search(r"\b(?:enum\s+class|class|struct)\s+" + re.escape(name) + r"\b", source)
    if match is None:
        raise AssertionError(f"missing type definition: {name}")
    opening, depth = source.find("{", match.end()), 0
    if opening < 0:
        raise AssertionError(f"incomplete type definition: {name}")
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                value = source[match.start():index + 1]
                return re.sub(r"\s+", "", re.sub(r"/\*.*?\*/|//[^\r\n]*", "", value, flags=re.S))
    raise AssertionError(f"unbalanced type definition: {name}")


class W9LiveApiEvidence(unittest.TestCase):
    def test_m2a_2b2afbc3a905edc4(self):
        self.assertTrue(WEB.is_file() and PROJECT.is_file())
        added, deleted = changed()
        facade_added, facade_deleted = changed("srchybrid/WebServer.cpp", "srchybrid/WebServer.h")
        self.assertLessEqual(added, 1100); self.assertGreaterEqual(deleted, 800)
        self.assertLessEqual(added - deleted, 300); self.assertLessEqual(facade_added, 80)
        self.assertGreater(facade_deleted, facade_added)
        inventory = json.loads(W7.read_text(encoding="utf-8"))
        owned = [item for item in inventory["operations"] if item["future_wave"] == "W9"]
        self.assertEqual(len(owned), 14)
        self.assertEqual({item["future_owner"] for item in owned}, set(MODULES))
        for name, (_limit, _binding, routes, _operations) in MODULES.items():
            self.assertEqual(len(routes), len(_operations))
            self.assertEqual({item["id"] for item in owned if item["future_owner"] == name}, routes)
        facade = WEB.read_text(encoding="utf-8")
        for header_name, names in ODR_TYPES.items():
            header = (SRC / header_name).read_text(encoding="utf-8")
            for name in names:
                self.assertEqual(declaration(facade, name), declaration(header, name), name)

    def test_m2a_fb7c489f61e1695a(self):
        self.assertTrue((SRC / "WebLiveApiTransferController.cpp").is_file())
        self._module_contract("WebLiveApiTransferController")

    def test_m2a_34fd80050a39b243(self):
        self.assertTrue((SRC / "WebLiveApiTransferController.cpp").is_file())
        self._binding_contract("WebLiveApiTransferController")

    def test_m2a_a0e04e6e6f67962a(self):
        self.assertTrue((SRC / "WebLiveApiSearchController.cpp").is_file())
        self._module_contract("WebLiveApiSearchController")

    def test_m2a_ff70e69f56f3d107(self):
        self.assertTrue((SRC / "WebLiveApiSearchController.cpp").is_file())
        self._binding_contract("WebLiveApiSearchController")

    def _module_contract(self, name: str) -> None:
        limit, binding, _routes, operations = MODULES[name]
        header, source = text(name, ".h"), text(name, ".cpp")
        combined = header + source
        self.assertLessEqual(len(combined.splitlines()), limit)
        self.assertIn("RunW9Live", combined); self.assertTrue(all(item in combined for item in operations))
        self.assertNotIn("WebRoute", combined); self.assertIn('#include "M2ABindingPort.h"', header)
        self.assertRegex(header, rf"\bexplicit\s+{name}\s*\(\s*const\s+M2AParentPort\s*&")
        self.assertIn(binding, source)
        self.assertRegex(source, r"MakeM2AModuleHandle\(new\s+" + re.escape(name) + r"\s*\(")
        self.assertNotRegex(combined, r"\b(?:WebAuthPolicy|Authorize\w*|Validate(?:Csrf|CSRF|Session|Token)\w*|IsAdmin|Session(?:Gate|Policy|Token)?)\b")
        for forbidden in ("WebServer.h", "WebApiSerializer", "WebDiagnostics", "windows.h", "afx", "CString", "CArray", "theApp", "thePrefs"):
            self.assertNotIn(forbidden, combined)
        matrix = json.loads(MATRIX.read_text(encoding="utf-8"))
        row = next(item for item in matrix["additional_modules"] if item["name"] == name)
        self.assertEqual((row["card"], row["dependencies"]), ("W9", []))
        self.assertRegex(source, rf"M2AModuleHandle\s+{binding}\s*\(\s*const\s+M2AParentPort\s*&\s*parent\s*\)")
        self.assertRegex(source, r"MakeM2AModuleHandle\(new\s+" + re.escape(name) + r"\s*\(\s*parent\s*\)\s*\)")
        node = re.search(r'<ClCompile Include="' + name + r'\.cpp">(.*?)</ClCompile>', PROJECT.read_text(encoding="utf-8"), re.S)
        self.assertIsNotNone(node)
        for setting in ("<PrecompiledHeader>NotUsing</PrecompiledHeader>", "<WarningLevel>Level4</WarningLevel>", "<TreatWarningAsError>true</TreatWarningAsError>", "<LanguageStandard>stdcpp17</LanguageStandard>"):
            self.assertIn(setting, node.group(1))

    def _binding_contract(self, name: str) -> None:
        _limit, binding, routes, _operations = MODULES[name]
        facade, source, body = WEB.read_text(encoding="utf-8"), text(name, ".cpp"), live_body()
        other = next(value[1] for key, value in MODULES.items() if key != name)
        self.assertEqual(source.count(binding), 1); self.assertEqual(facade.count(binding), 2)
        self.assertNotEqual(binding, other); self.assertNotIn(other, source); self.assertNotIn(name, facade)
        self.assertIn("MakeM2AModuleHandle(new " + name, source)
        first_route = min(body.index("WebRouteId::" + route) for route in routes)
        auth_prefix = body[:first_route]
        self.assertIn("AuthorizeLiveRequest", auth_prefix); self.assertIn("RequiredRoleForLivePath", auth_prefix)
        self.assertTrue(all(body.count("WebRouteId::" + route) == 1 for route in routes))
        self.assertTrue(all(marker not in body for marker in MOVED_LEGACY))
        selftest = "RunW9Live" + ("Transfer" if "Transfer" in name else "Search") + "CharacterizationSelfTest"
        self.assertIn(selftest, source)
        self.assertIn(selftest, facade.split("bool CWebServer::RunCharacterizationSelfTest", 1)[1].split("CString CWebServer::_SpecialChars", 1)[0])
        if name == "WebLiveApiTransferController":
            compact = re.sub(r"\s+", "", facade)
            self.assertIn("InitiateKad3Rendezvous(ntohl(rdv),rdvPort,ntohl(target),targetPort)", compact)
            self.assertIn("RequestViewerConnect(key.data(),ip,port)", compact)
            self.assertIn("SendEseHolePunchReqSpray(ntohl(ip),port,result.spread,true,context.target)", compact)
            self.assertIn("thePrefs.GetEseHolePunchPortPredict()?static_cast<std::uint16_t>(thePrefs.GetEseHolePunchPortSpread()):0", compact)
        for relative in ("tools/architecture/verify_mod02_characterization.py", "tools/architecture/run_mod02_stream_selftest.ps1"):
            runner = (ROOT / relative).read_text(encoding="utf-8")
            self.assertIn(name + ".cpp", runner); self.assertIn(name + ".h", runner)


if __name__ == "__main__":
    unittest.main()
