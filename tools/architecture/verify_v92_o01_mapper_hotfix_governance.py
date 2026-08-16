from __future__ import annotations

import argparse
import datetime
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOC = "docs/architecture/v92_o01_mapper_hotfix_governance_v1.json"
DOC_PATH = ROOT / DOC
PRED_G = "cfeba8b67234c47a052e3d976acbb233868160f4"
PRED_A = "37057fcb58e25fc9cec6ebba67fc294343936a1a"
PRED_A_TREE = "969abbd1df19afc12d49cee22e45b6a698de21b7"
PRED_H = "c9a81244ba8f2171aed6610aaea10a5898ac6acb"
PRED_H_TREE = "ea5a4b52d13fcd070db87dcd2bf686cdb3df2af0"
MOD02_IDENTITY = "b9c3c25fece8a80d71eee340e61d8cd5088b95f8b12e221278d9d249f6d29c9d"
MOD02_MARKER_SHA = "17d7cbca262c94f802d59255d0ec41137bd85c12037a393cc5198abd40373cae"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")

GOV = [
    DOC,
    "tools/architecture/verify_v92_o01_mapper_hotfix_governance.py",
    "tools/architecture/test_verify_v92_o01_mapper_hotfix_governance.py",
]
FUNCTIONAL = [
    "libnatmap/src/pcp_pair_transaction.cpp",
    "libnatmap/tests/test_legacy_mapper_projection.cpp",
    "libnatmap/tests/test_pcp_pair_transaction.cpp",
    "srchybrid/UPnPImplNATPMP.cpp",
    "srchybrid/UPnPImplPCP.cpp",
    "srchybrid/UPnPImplPCP.h",
    "tests/test_v92_l02_pcp_ownership.py",
    "tests/test_v92_l03_natpmp_ownership.py",
]
RELEASE_METADATA = [
    "docs/RELEASE_NOTES_v9.2.0-rc.1.md",
    "docs/V92_RC1_EXECUTION.md",
    "srchybrid/Version.h",
    "srchybrid/eSE/package-lock.json",
    "srchybrid/eSE/package.json",
]
RELEASE_METADATA_SHA256 = {
    "docs/RELEASE_NOTES_v9.2.0-rc.1.md": "7092ec87998b5f03e9913049f0d3849b25204af498f4d8e319a241420560a030",
    "docs/V92_RC1_EXECUTION.md": "6b765d83cedefc986790f1e79fc83d26ac6889c4535b96fdc1c5429de4a29340",
    "srchybrid/Version.h": "3405f993e97de02fa3af16d813fa99727472dc9bd417df3a38b817a6bbc43bd7",
    "srchybrid/eSE/package-lock.json": "534eced571e12188a7e9af83e0caf9e34c957876b6b0904effa04c52a41ac5cd",
    "srchybrid/eSE/package.json": "ea8c8bb89164f4ab897993f25f71a40aee584e8b38f072ac17cceb157d4b164f",
}
BUILD_GATE = [
    "libkad6/make_crypto_vectors.bat",
    "tests/test_v92_m2a_lt1_release_gate.py",
]
BUILD_GATE_SHA256 = {
    "libkad6/make_crypto_vectors.bat": "ac724e18a50f647974297423aae4a87a1ae1b624ec774d6abfef2088db9c35fb",
    "tests/test_v92_m2a_lt1_release_gate.py": "7df1085d5fd6d8fa2818666e497279754a020e6fe5224da13f263ce1e7dd627f",
}
PACKAGE_DOCUMENTATION = [
    "CHANGES_FROM_EMULE_0.70b.md",
    "GUIA-RAPIDA.md",
    "README.md",
    "THIRD_PARTY_LICENSES.md",
    "docs/INDEX.md",
    "docs/USER_GUIDE.md",
]
PACKAGE_DOCUMENTATION_SHA256 = {
    "CHANGES_FROM_EMULE_0.70b.md": "0d8a8d68ef84f194f4c717660bd04f593c115aef3169cb84fa43780c69fccff7",
    "GUIA-RAPIDA.md": "1788f7060733fa369f9365a8051f48e98cc7f1dcad3d3adb727fee8f9d3dcd13",
    "README.md": "28eabaf5be34b1d3b818dcf384387d405394dcbc48a1b5c3f230c8d80e368409",
    "THIRD_PARTY_LICENSES.md": "7ab529f988f46b5903038951ec9f55735ded2496ebb5d437ab04065ba5c44eb7",
    "docs/INDEX.md": "921abe47ca6367b113281d9f4daa1f73eac1d2168d37ded1e9f4eefdcf4cff10",
    "docs/USER_GUIDE.md": "95729dd9d7ff7fbb679ebfb3da0a436c57485f50d67eb2ad5fb0f99895e4f6f1",
}
MOD02_RESEAL = [
    "srchybrid/Mod02BuildIdentity.h",
    "srchybrid/eSE/test/live_tv_regression.test.js",
]
MOD02_RESEAL_SHA256 = {
    "srchybrid/Mod02BuildIdentity.h": "760f2564e6b99aaceb8ba2e70c5aaf4283545b7d867509cd07228d6b835bf8af",
    "srchybrid/eSE/test/live_tv_regression.test.js": "adb46a0b326e1668558ec390087bc04d2913c1f9fbdd66d41e111398bdbf8166",
}
A_PATHS = sorted(
    FUNCTIONAL + RELEASE_METADATA + BUILD_GATE
    + PACKAGE_DOCUMENTATION + MOD02_RESEAL
)
MAPPER_BUDGET = (8, 203, 10, 193)
RELEASE_METADATA_BUDGET = (5, 151, 6, 145)
BUILD_GATE_BUDGET = (2, 19, 1, 18)
PACKAGE_DOCUMENTATION_BUDGET = (6, 42, 44, -2)
MOD02_RESEAL_BUDGET = (2, 2, 2, 0)
BUDGET = (23, 417, 63, 354)
M_MANIFEST = "docs/architecture/mod02_build_manifest_v1.json"
M_MATRIX = "docs/architecture/mod02_characterization_matrix_v1.json"
RELEASE_TAG = "v0.70b-eSE9.2.0-rc.1"
H_PATHS = [
    "artifacts/v92-o01-governance/activation.json",
    "artifacts/v92-o01-governance/offline-summary.json",
    "artifacts/v92-o01-governance/review-sol.json",
    "artifacts/v92-o01-governance/review-terra.json",
]
S_PATHS = [
    "artifacts/v92-o01-governance/nonrelease-smoke-raw.json",
    "artifacts/v92-o01-governance/nonrelease-smoke-summary.json",
]
REVIEWS = [
    "Terra APPROVE with findings=[]",
    "Sol APPROVE with findings=[]",
]
GATES = [
    "Node 22 complete nat_gateway suite",
    "formal controller/validator/host/RPC focal suite",
    "PowerShell parser for every changed ps1/psm1",
    "product formal-soak mock",
    "VM session rollback mock",
    "formal RPC pump mock",
    "formal runner source/mock gate",
    "PCP and NAT-PMP ownership host contracts",
    "libnatmap complete native suite",
    "Release x64 build",
    "MOD02 verifier and runtime reseal",
    "git diff --check",
]
OFFLINE = [
    (GATES[0], "npm.cmd test", "O01_NODE_SUITE_PASS"),
    (GATES[1], "node --test test/v92_o01_formal_controller.test.js test/v92_o01_validate_formal.test.js test/v92_o01_formal_host.test.js test/v92_o01_formal_rpc.test.js", "O01_FORMAL_FOCAL_PASS"),
    (GATES[2], "powershell parser changed ps1/psm1", "O01_POWERSHELL_PARSE_PASS"),
    (GATES[3], "powershell -File tools/lab/handoff93/test_product_mapper_formal_soak_mock.ps1", "O01_PRODUCT_MOCK_PASS"),
    (GATES[4], "powershell -File tools/lab/test_v92_o01_vm_session_mock.ps1", "O01_SESSION_MOCK_PASS"),
    (GATES[5], "powershell -File tools/lab/test_v92_o01_formal_rpc_pump_mock.ps1", "O01_RPC_MOCK_PASS"),
    (GATES[6], "powershell -File tools/lab/test_v92_o01_formal_runner_mock.ps1", "O01_RUNNER_MOCK_PASS"),
    (GATES[7], "cmd /d /c \"python -B tests\\test_v92_l02_pcp_ownership.py && python -B tests\\test_v92_l03_natpmp_ownership.py && python -B tests\\test_v92_l07_hostile_corpus.py && python -B tests\\test_v92_m02_double_nat.py && python -B tests\\test_v92_mx03_pcp_upstream.py\"", "O01_MAPPER_OWNERSHIP_PASS"),
    (GATES[8], "cmd /d /c libnatmap\\make.bat", "O01_LIBNATMAP_PASS"),
    (GATES[9], "powershell -File tools/build_all.ps1 -ReleaseTag v0.70b-eSE9.2.0-rc.1", "O01_RELEASE_BUILD_PASS"),
    (GATES[10], "verify M36 MOD02 artifacts", "O01_MOD02_RESEAL_PASS"),
    (GATES[11], "git diff --check", "O01_DIFF_CHECK_PASS"),
]
STOPS = [
    "candidate path 24 or any path outside the closed allowlist",
    "budget differs by one line",
    "project file, product binary, MOD02 critical source outside mod02_reseal_paths or unrelated production source changes",
    "PCP ownership without exact TCP and UDP identities or one public address",
    "PCP or NAT-PMP result without the protocol gateway port",
    "M lacks a clean Release build receipt and MOD02 runtime PASS bound to A and the rebuilt executable",
    "source, Node, package or evidence binding changes during a run",
    "a packaged document identifies the candidate as 9.1 stable, or a candidate-facing entrypoint (README, GUIA-RAPIDA, docs/INDEX or docs/USER_GUIDE) omits the 9.2.0-rc.1 NO_GO boundary",
    "P0, P1, P2 or nonempty review finding",
    "release_gate=true before independent validation and exact baseline restoration",
]
MOD02_REQUIRED = [
    "build_manifest_sha256",
    "source_identity_sha256",
    "source_tree_clean",
    "executable_sha256",
    "marker_sha256",
    "termination_confirmed",
]

_legacy_spec = importlib.util.spec_from_file_location(
    "o01_legacy_governance",
    Path(__file__).with_name("verify_v92_o01_governance_amendment.py"),
)
LEGACY = importlib.util.module_from_spec(_legacy_spec)
assert _legacy_spec.loader is not None
_legacy_spec.loader.exec_module(LEGACY)


class GateError(RuntimeError):
    pass


def sh(*args: str) -> str:
    return subprocess.run(
        args,
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout.decode().strip()


def git(*args: str) -> str:
    return sh("git", *args)


def exact(value: object, keys: set[str], where: str) -> dict:
    if not isinstance(value, dict) or set(value) != keys:
        raise GateError(f"{where} schema")
    return value


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def mod02_markers() -> list[str]:
    return [
        "BEGIN CUPnPImplMiniLib deferred reaper",
        "PASS CUPnPImplMiniLib deferred reaper",
        f"SOURCE {MOD02_IDENTITY}",
        "BEGIN CLiveTunnel", "PASS CLiveTunnel",
        "BEGIN CWebServer", "PASS CWebServer",
        "BEGIN CLiveStreamManager", "PASS CLiveStreamManager",
    ]


def mod02_marker_sha256() -> str:
    return sha(("\n".join(mod02_markers()) + "\n").encode())


def validate_package_documentation(raw: dict[str, bytes], where: str) -> None:
    if set(raw) != set(PACKAGE_DOCUMENTATION):
        raise GateError(f"{where} package documentation set")
    try:
        text = {path: value.decode("utf-8") for path, value in raw.items()}
    except UnicodeDecodeError as exc:
        raise GateError(f"{where} package documentation encoding") from exc
    required = {
        "README.md": ["eSE 9.2.0-rc.1 for Windows x64", "**NO_GO**", "latest published stable release remains `9.1.0`"],
        "GUIA-RAPIDA.md": ["eMule eSE 9.2.0-rc.1", "**NO_GO**", "última versión estable sigue siendo `9.1.0`"],
        "CHANGES_FROM_EMULE_0.70b.md": ["through eMule eSE 9.2.0-rc.1", "remains disabled in 9.2.0-rc.1"],
        "THIRD_PARTY_LICENSES.md": ["Third-party notices for eMule eSE 9.2.0-rc.1", "revalidated against the 9.2.0-rc.1 source"],
        "docs/INDEX.md": ["RELEASE_NOTES_v9.2.0-rc.1.md", "V92_RC1_EXECUTION.md", "`NO_GO`"],
        "docs/USER_GUIDE.md": ["9.2.0-rc.1 release notes", "**NO_GO**", "not treat it as a"],
    }
    forbidden = {
        "README.md": ["This source tree builds the final `9.1.0`"],
        "GUIA-RAPIDA.md": ["Esta versión estable", "Descarga el paquete `9.1.0`"],
        "CHANGES_FROM_EMULE_0.70b.md": ["differences shipped in eMule eSE 9.1.0"],
        "THIRD_PARTY_LICENSES.md": ["Third-party notices for eMule eSE 9.1.0"],
        "docs/INDEX.md": ["## User documentation\n\n- [eSE 9.1.0 release notes"],
        "docs/USER_GUIDE.md": ["Download the `9.1.0` portable ZIP"],
    }
    if any(marker not in text[path] for path, markers in required.items() for marker in markers):
        raise GateError(f"{where} package documentation identity")
    if any(marker in text[path] for path, markers in forbidden.items() for marker in markers):
        raise GateError(f"{where} package documentation stale identity")


def parse_utc(
    value: object,
    where: str,
    allow_timezone_offset: bool = False,
) -> datetime.datetime:
    if not isinstance(value, str):
        raise GateError(where)
    try:
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise GateError(where) from exc
    if parsed.tzinfo is None or (
        not allow_timezone_offset
        and parsed.utcoffset() != datetime.timedelta(0)
    ):
        raise GateError(where)
    return parsed.astimezone(datetime.timezone.utc)


def release_source_fingerprint() -> str:
    command = (
        ". .\\tools\\release_fingerprint.ps1; "
        "Get-ReleaseSourceFingerprint -RepoRoot . -Component emule"
    )
    lines = sh(
        "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-Command", command,
    ).splitlines()
    value = lines[-1].strip() if lines else ""
    if re.fullmatch(r"[0-9A-F]{64}", value) is None:
        raise GateError("Release source fingerprint")
    return value


def blob(commit: str, path: str) -> bytes:
    return subprocess.run(
        ["git", "show", f"{commit}:{path}"],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout


def load_bytes(data: bytes) -> object:
    return json.loads(data.decode("utf-8"))


def load() -> dict:
    return json.loads(DOC_PATH.read_text(encoding="utf-8"))


def parents(commit: str) -> list[str]:
    return git("show", "-s", "--format=%P", commit).split()


def changed(parent: str, commit: str) -> list[str]:
    return sorted(filter(None, git("diff", "--name-only", parent, commit, "--").splitlines()))


def require_single_parent(commit: str, parent: str, label: str) -> None:
    if parents(commit) != [parent]:
        raise GateError(f"{label} parent")


def verify_predecessor() -> None:
    legacy_document = load_bytes(blob(PRED_G, LEGACY.DOC))
    LEGACY.validate(legacy_document)
    if parents(PRED_G) != [LEGACY.BASE] or parents(PRED_A) != [PRED_G] or parents(PRED_H) != [PRED_A]:
        raise GateError("predecessor topology")
    if git("rev-parse", f"{PRED_A}^{{tree}}") != PRED_A_TREE or git("rev-parse", f"{PRED_H}^{{tree}}") != PRED_H_TREE:
        raise GateError("predecessor tree")
    if changed(PRED_A, PRED_H) != H_PATHS:
        raise GateError("predecessor H delta")
    if changed(LEGACY.BASE, PRED_G) != sorted(LEGACY.GOV) or changed(PRED_G, PRED_A) != LEGACY.functional_paths():
        raise GateError("predecessor functional delta")
    LEGACY.commit_budget(PRED_G, PRED_A)
    LEGACY.verify_h(PRED_H, PRED_A, PRED_G)


def budget(parent: str, commit: str) -> None:
    rows: dict[str, tuple[int, int]] = {}
    for line in git("diff", "--numstat", parent, commit, "--").splitlines():
        added, deleted, path = line.split("\t", 2)
        if not added.isdigit() or not deleted.isdigit():
            raise GateError("A binary payload")
        rows[path] = (int(added), int(deleted))
    validate_budget_slices(rows, "A")


def observed_budget(stats: dict[str, tuple[int, int]], paths: list[str]) -> tuple[int, int, int, int]:
    rows = [stats[path] for path in paths]
    return (
        len(rows),
        sum(row[0] for row in rows),
        sum(row[1] for row in rows),
        sum(row[0] - row[1] for row in rows),
    )


def validate_budget_slices(stats: dict[str, tuple[int, int]], where: str) -> None:
    if sorted(stats) != A_PATHS:
        raise GateError(f"{where} allowlist")
    if observed_budget(stats, A_PATHS) != BUDGET:
        raise GateError(f"{where} budget")
    if observed_budget(stats, FUNCTIONAL) != MAPPER_BUDGET:
        raise GateError(f"{where} mapper budget")
    if observed_budget(stats, RELEASE_METADATA) != RELEASE_METADATA_BUDGET:
        raise GateError(f"{where} release metadata budget")
    if observed_budget(stats, BUILD_GATE) != BUILD_GATE_BUDGET:
        raise GateError(f"{where} build gate budget")
    if observed_budget(stats, PACKAGE_DOCUMENTATION) != PACKAGE_DOCUMENTATION_BUDGET:
        raise GateError(f"{where} package documentation budget")
    if observed_budget(stats, MOD02_RESEAL) != MOD02_RESEAL_BUDGET:
        raise GateError(f"{where} MOD02 reseal budget")


def release_receipt_path(a_commit: str) -> str:
    return f"artifacts/v92-o01-release-build-{a_commit[:8]}/emule-release-build.json"


def m_paths(a_commit: str) -> list[str]:
    return sorted([
        M_MANIFEST,
        M_MATRIX,
        f"artifacts/mod02-runtime-v92-{a_commit[:8]}/summary.json",
        release_receipt_path(a_commit),
    ])


def cumulative_paths() -> list[str]:
    return sorted(LEGACY.functional_paths() + FUNCTIONAL)


def candidate_paths() -> list[str]:
    return sorted(
        cumulative_paths() + RELEASE_METADATA + BUILD_GATE
        + PACKAGE_DOCUMENTATION + MOD02_RESEAL
    )


def validate(value: dict) -> bool:
    exact(value, {
        "schema", "status", "predecessor", "historical_contract", "scope", "topology",
        "phase_contract", "governance_paths", "functional_paths",
        "release_metadata_paths", "release_metadata_sha256", "build_gate_paths",
        "build_gate_sha256", "package_documentation_paths",
        "package_documentation_sha256", "mod02_reseal_paths", "mod02_reseal_sha256",
        "carrier_paths", "budget", "mapper_budget", "release_metadata_budget",
        "build_gate_budget", "package_documentation_budget", "mod02_reseal_budget",
        "required_reviews", "offline_gates",
        "physical_policy", "stop_conditions", "activation_state",
    }, "root")
    if MOD02_MARKER_SHA != mod02_marker_sha256():
        raise GateError("MOD02 marker identity")
    if value["schema"] != "ese.v92.o01-mapper-hotfix-governance/v1" or value["status"] != "DRAFT_PRE_G8":
        raise GateError("identity")
    if value["predecessor"] != {
        "g_commit": PRED_G,
        "a_commit": PRED_A,
        "a_tree": PRED_A_TREE,
        "h_commit": PRED_H,
        "h_tree": PRED_H_TREE,
    }:
        raise GateError("predecessor")
    if value["historical_contract"] != {
        "verifier": "tools/architecture/verify_v92_o01_governance_amendment.py",
        "historical_path_count": 36,
        "historical_add_exact": 1237,
        "historical_delete_exact": 63,
        "historical_net_exact": 1174,
        "cumulative_path_count": 44,
        "cumulative_add_exact": 1440,
        "cumulative_delete_exact": 73,
        "cumulative_net_exact": 1367,
        "candidate_path_count": 59,
        "candidate_add_exact": 1654,
        "candidate_delete_exact": 126,
        "candidate_net_exact": 1528,
    }:
        raise GateError("historical contract")
    if value["scope"] != "V92-O01 rc.1 candidate only: reject incoherent PCP pairs, publish route-bound PCP ownership, complete PCP and NAT-PMP gateway endpoints, add exact regression coverage, repair the exact libkad6 standalone release-gate link, bind the exact 9.2.0-rc.1 metadata and release documents, make the six packaged release documents candidate-honest, and reseal the exact MOD02 identity after the version ratchet update; the predecessor O01 controller and physical contract remain immutable.":
        raise GateError("scope")
    topology = {
        "G": "direct child of predecessor H; this amendment, verifier and verifier test only",
        "A": "direct child of G; exactly functional_paths plus release_metadata_paths plus build_gate_paths plus package_documentation_paths plus mod02_reseal_paths and their exact separate budgets",
        "M": "direct child of A; exact Release build receipt plus MOD02 manifest, matrix and runtime summary reseal only",
        "H": "direct child of M; exact four governance carriers, reviews bind A and activation binds M",
        "S": "optional direct child of H; one NON_RELEASE physical preflight only",
        "R": "direct child of H or S; exact formal eight-hour evidence sourced from A and using the executable validated by M",
    }
    phases = {
        "schema": "ese.v92.o01-mapper-hotfix-phases/v1",
        "merge_policy": "Every G/A/M/H/S/R commit has exactly one parent; merges and intermediate commits are rejected.",
        "G": {"parent": "predecessor_h", "delta": "governance_paths"},
        "A": {"parent": "G", "delta": "functional_paths_plus_release_metadata_paths_plus_build_gate_paths_plus_package_documentation_paths_plus_mod02_reseal_paths"},
        "M": {"parent": "A", "delta": "mod02_carrier_paths"},
        "H": {"parent": "M", "delta": "h_carrier_paths"},
        "S": {"optional": True, "parent": "H", "delta": "s_carrier_paths", "release_gate": False},
        "R": {"parent": "H_or_S", "source": "A", "governance": "H_and_optional_S", "executable": "exact_M_manifest_executable_sha256", "release_gate": True},
    }
    carriers = {
        "M": {
            "fixed": [M_MANIFEST, M_MATRIX],
            "summary_pattern": "artifacts/mod02-runtime-v92-<A[0:8]>/summary.json",
            "release_build_receipt_pattern": "artifacts/v92-o01-release-build-<A[0:8]>/emule-release-build.json",
            "file_count": 4,
        },
        "H": H_PATHS,
        "S": S_PATHS,
        "R": {
            "directory": "artifacts/v92-o01-formal",
            "checkpoint_pattern": "checkpoint-(01..95).json",
            "fixed": ["controller-result.json", "formal-run-result.json", "formal-validation.json"],
            "file_count": 98,
        },
    }
    if value["topology"] != topology or value["phase_contract"] != phases:
        raise GateError("topology")
    if value["governance_paths"] != GOV or value["functional_paths"] != FUNCTIONAL or value["release_metadata_paths"] != RELEASE_METADATA or value["release_metadata_sha256"] != RELEASE_METADATA_SHA256 or value["build_gate_paths"] != BUILD_GATE or value["build_gate_sha256"] != BUILD_GATE_SHA256 or value["package_documentation_paths"] != PACKAGE_DOCUMENTATION or value["package_documentation_sha256"] != PACKAGE_DOCUMENTATION_SHA256 or value["mod02_reseal_paths"] != MOD02_RESEAL or value["mod02_reseal_sha256"] != MOD02_RESEAL_SHA256 or value["carrier_paths"] != carriers:
        raise GateError("closed paths")
    if value["budget"] != {"path_count": 23, "add_exact": 417, "delete_exact": 63, "net_exact": 354, "headroom": 0}:
        raise GateError("budget")
    if value["mapper_budget"] != {"path_count": 8, "add_exact": 203, "delete_exact": 10, "net_exact": 193, "headroom": 0}:
        raise GateError("mapper budget")
    if value["release_metadata_budget"] != {"path_count": 5, "add_exact": 151, "delete_exact": 6, "net_exact": 145, "headroom": 0}:
        raise GateError("release metadata budget")
    if value["build_gate_budget"] != {"path_count": 2, "add_exact": 19, "delete_exact": 1, "net_exact": 18, "headroom": 0}:
        raise GateError("build gate budget")
    if value["package_documentation_budget"] != {"path_count": 6, "add_exact": 42, "delete_exact": 44, "net_exact": -2, "headroom": 0}:
        raise GateError("package documentation budget")
    if value["mod02_reseal_budget"] != {"path_count": 2, "add_exact": 2, "delete_exact": 2, "net_exact": 0, "headroom": 0}:
        raise GateError("MOD02 reseal budget")
    if value["required_reviews"] != REVIEWS or value["offline_gates"] != GATES or value["stop_conditions"] != STOPS:
        raise GateError("normative lists")
    if value["physical_policy"] != {
        "short_preflight": "One NON_RELEASE physical preflight after H is permitted; it must restore the exact baseline and can never award release PASS.",
        "formal": "Exactly 28800000 monotonic milliseconds, no duration override, no resume, no skip-cleanup, Node 22 and clean A source.",
        "claim_rule": "Only independently validated R evidence with exact cleanup and baseline restoration may award V92-O01 PASS.",
    }:
        raise GateError("physical policy")
    if value["activation_state"] != {
        "G": None, "A": None, "M": None, "H": None, "S": None, "R": None,
        "rule": "The document never stores its own commit; phase identities are derived from exact Git parentage and later carriers.",
    }:
        raise GateError("self reference")
    return True


def worktree_stats() -> bool:
    if git("rev-parse", "HEAD") != PRED_H:
        raise GateError("worktree base")
    stats: dict[str, tuple[int, int]] = {}
    for line in git("diff", "HEAD", "--numstat", "--").splitlines():
        added, deleted, path = line.split("\t", 2)
        if not added.isdigit() or not deleted.isdigit():
            raise GateError("binary payload")
        if path not in GOV:
            stats[path] = (int(added), int(deleted))
    for path in git("ls-files", "--others", "--exclude-standard").splitlines():
        if path in GOV:
            continue
        data = (ROOT / path).read_bytes()
        stats[path] = (data.count(b"\n") + int(bool(data) and not data.endswith(b"\n")), 0)
    validate_budget_slices(stats, "worktree")
    if {path: sha((ROOT / path).read_bytes()) for path in RELEASE_METADATA} != RELEASE_METADATA_SHA256:
        raise GateError("worktree release metadata content")
    if {path: sha((ROOT / path).read_bytes()) for path in BUILD_GATE} != BUILD_GATE_SHA256:
        raise GateError("worktree build gate content")
    package_documentation = {
        path: (ROOT / path).read_bytes() for path in PACKAGE_DOCUMENTATION
    }
    if {path: sha(raw) for path, raw in package_documentation.items()} != PACKAGE_DOCUMENTATION_SHA256:
        raise GateError("worktree package documentation content")
    validate_package_documentation(package_documentation, "worktree")
    if {path: sha((ROOT / path).read_bytes()) for path in MOD02_RESEAL} != MOD02_RESEAL_SHA256:
        raise GateError("worktree MOD02 reseal content")
    return True


def validate_review(raw: bytes, role: str, a_commit: str, a_tree: str) -> None:
    value = exact(load_bytes(raw), {
        "schema", "role", "reviewed_commit", "reviewed_tree", "verdict", "findings",
    }, "review")
    if value != {
        "schema": "ese.v92.o01-review/v1",
        "role": role,
        "reviewed_commit": a_commit,
        "reviewed_tree": a_tree,
        "verdict": "APPROVE",
        "findings": [],
    }:
        raise GateError("review content")


def verify_g(g_commit: str, document: dict) -> None:
    require_single_parent(g_commit, PRED_H, "G")
    if changed(PRED_H, g_commit) != sorted(GOV):
        raise GateError("G delta")
    if load_bytes(blob(g_commit, DOC)) != document:
        raise GateError("G document")


def verify_a(a_commit: str, g_commit: str) -> None:
    require_single_parent(a_commit, g_commit, "A")
    if changed(g_commit, a_commit) != A_PATHS:
        raise GateError("A delta")
    budget(g_commit, a_commit)
    if {path: sha(blob(a_commit, path)) for path in RELEASE_METADATA} != RELEASE_METADATA_SHA256:
        raise GateError("A release metadata content")
    if {path: sha(blob(a_commit, path)) for path in BUILD_GATE} != BUILD_GATE_SHA256:
        raise GateError("A build gate content")
    package_documentation = {
        path: blob(a_commit, path) for path in PACKAGE_DOCUMENTATION
    }
    if {path: sha(raw) for path, raw in package_documentation.items()} != PACKAGE_DOCUMENTATION_SHA256:
        raise GateError("A package documentation content")
    validate_package_documentation(package_documentation, "A")
    if {path: sha(blob(a_commit, path)) for path in MOD02_RESEAL} != MOD02_RESEAL_SHA256:
        raise GateError("A MOD02 reseal content")


def verify_m(m_commit: str, a_commit: str) -> None:
    require_single_parent(m_commit, a_commit, "M")
    paths = m_paths(a_commit)
    if changed(a_commit, m_commit) != paths:
        raise GateError("M delta")
    manifest_raw = blob(m_commit, M_MANIFEST)
    manifest = exact(load_bytes(manifest_raw), {
        "schema", "source_commit", "source_identity_sha256", "executable_sha256",
    }, "MOD02 manifest")
    if manifest["schema"] != "ese.mod02.build-manifest/v1" or manifest["source_commit"] != a_commit or manifest["source_identity_sha256"] != MOD02_IDENTITY or not isinstance(manifest["executable_sha256"], str) or not HEX64.fullmatch(manifest["executable_sha256"]):
        raise GateError("MOD02 manifest")

    receipt_path = release_receipt_path(a_commit)
    receipt_raw = blob(m_commit, receipt_path)
    receipt = exact(json.loads(receipt_raw.decode("utf-8-sig")), {
        "schema", "component", "releaseTag", "commit", "sourceFingerprint",
        "binarySha256", "binaryLength", "builtAtUtc",
    }, "Release build receipt")
    a_tree = git("rev-parse", f"{a_commit}^{{tree}}")
    receipt_built_at = parse_utc(receipt["builtAtUtc"], "Release build timestamp")
    commit_time = parse_utc(
        git("show", "-s", "--format=%cI", a_commit),
        "Release source commit timestamp",
        allow_timezone_offset=True,
    )
    if (
        type(receipt["schema"]) is not int
        or receipt["schema"] != 1
        or receipt["component"] != "emule"
        or receipt["releaseTag"] != RELEASE_TAG
        or receipt["commit"] != a_commit
        or receipt["sourceFingerprint"] != release_source_fingerprint()
        or receipt["binarySha256"] != manifest["executable_sha256"].upper()
        or type(receipt["binaryLength"]) is not int
        or not 1 <= receipt["binaryLength"] <= 100 * 1024 * 1024
        or receipt_built_at < commit_time
    ):
        raise GateError("Release build receipt")

    summary_path = f"artifacts/mod02-runtime-v92-{a_commit[:8]}/summary.json"
    summary_raw = blob(m_commit, summary_path)
    if summary_raw.startswith(b"\xef\xbb\xbf") or b"\r" in summary_raw or not summary_raw.endswith(b"\n"):
        raise GateError("MOD02 summary encoding")
    summary = exact(load_bytes(summary_raw), {
        "schema", "build_manifest_sha256", "source_commit", "source_identity_sha256",
        "source_tree_clean", "executable_sha256", "executable_write_utc",
        "latest_critical_source_write_utc", "timeout_seconds", "timed_out",
        "taskkill_started", "taskkill_finished", "taskkill_exit_code",
        "termination_confirmed", "exit_code", "expected_markers",
        "observed_markers_sanitized", "markers_verified", "marker_sha256",
        "verdict", "command", "isolation",
    }, "MOD02 summary")
    expected_markers = mod02_markers()
    if summary["schema"] != "ese.mod02.stream-selftest/v1" or summary["build_manifest_sha256"] != sha(manifest_raw) or summary["source_commit"] != a_commit or summary["source_identity_sha256"] != MOD02_IDENTITY or summary["source_tree_clean"] is not True or summary["executable_sha256"] != manifest["executable_sha256"]:
        raise GateError("MOD02 summary binding")
    if summary["timeout_seconds"] != 180 or summary["timed_out"] is not False or summary["taskkill_started"] is not False or summary["taskkill_finished"] is not True or summary["taskkill_exit_code"] is not None or summary["termination_confirmed"] is not True or type(summary["exit_code"]) is not int or summary["exit_code"] != 0:
        raise GateError("MOD02 termination")
    if summary["expected_markers"] != expected_markers or summary["observed_markers_sanitized"] != expected_markers or summary["markers_verified"] is not True or summary["marker_sha256"] != MOD02_MARKER_SHA:
        raise GateError("MOD02 markers")
    if summary["verdict"] != "PASS" or summary["command"] != "--portable --ignoreinstances --selftest" or summary["isolation"] != "portable unique output root; no UI":
        raise GateError("MOD02 verdict")
    parsed_times = []
    for field in ("latest_critical_source_write_utc", "executable_write_utc"):
        parsed_times.append(parse_utc(summary[field], "MOD02 timestamp"))
    if (
        parsed_times[1] < parsed_times[0]
        or parsed_times[1] < commit_time
        or receipt_built_at < parsed_times[1]
    ):
        raise GateError("MOD02 build ordering")

    matrix = load_bytes(blob(m_commit, M_MATRIX))
    prior_matrix = load_bytes(blob(a_commit, M_MATRIX))
    if not isinstance(matrix, dict) or set(matrix) != set(prior_matrix):
        raise GateError("MOD02 matrix schema")
    if {key: value for key, value in matrix.items() if key != "runtime_gate"} != {key: value for key, value in prior_matrix.items() if key != "runtime_gate"}:
        raise GateError("MOD02 matrix drift")
    gate = exact(matrix["runtime_gate"], {
        "runner", "build_manifest", "summary", "status", "required_summary",
        "acceptance", "evidence", "release_build_receipt",
    }, "MOD02 gate")
    receipt_binding = exact(gate["release_build_receipt"], {
        "path", "sha256", "source_tree",
    }, "Release build receipt binding")
    evidence = exact(gate["evidence"], {
        "source_commit", "source_identity_sha256", "executable_sha256",
        "build_manifest_sha256", "summary_sha256", "marker_sha256",
        "timeout_seconds", "timed_out", "termination_confirmed", "exit_code",
        "source_tree_clean", "markers_verified",
    }, "MOD02 evidence")
    expected_evidence = {
        field: summary[field] for field in (
            "source_commit", "source_identity_sha256", "executable_sha256",
            "build_manifest_sha256", "marker_sha256", "timeout_seconds",
            "timed_out", "termination_confirmed", "exit_code",
            "source_tree_clean", "markers_verified",
        )
    }
    expected_evidence["summary_sha256"] = sha(summary_raw)
    if gate["runner"] != "tools/architecture/run_mod02_stream_selftest.ps1" or gate["build_manifest"] != M_MANIFEST or gate["summary"] != summary_path or gate["status"] != "PASS" or gate["required_summary"] != MOD02_REQUIRED or gate["acceptance"] != prior_matrix["runtime_gate"]["acceptance"] or receipt_binding != {"path": receipt_path, "sha256": sha(receipt_raw), "source_tree": a_tree} or evidence != expected_evidence:
        raise GateError("MOD02 matrix binding")


def verify_h(h_commit: str, m_commit: str, a_commit: str, g_commit: str) -> None:
    require_single_parent(h_commit, m_commit, "H")
    if changed(m_commit, h_commit) != H_PATHS:
        raise GateError("H delta")
    a_tree = git("rev-parse", f"{a_commit}^{{tree}}")
    m_tree = git("rev-parse", f"{m_commit}^{{tree}}")
    amendment_sha = sha(blob(g_commit, DOC))
    activation = exact(load_bytes(blob(h_commit, H_PATHS[0])), {
        "schema", "predecessor_h_commit", "g_commit", "a_commit", "a_tree",
        "m_commit", "m_tree", "amendment_sha256",
        "historical_functional_paths_sha256", "hotfix_functional_paths_sha256",
        "cumulative_functional_paths_sha256", "release_metadata_paths_sha256",
        "build_gate_paths_sha256", "package_documentation_paths_sha256",
        "mod02_reseal_paths_sha256",
        "candidate_paths_sha256", "artifact_sha256",
    }, "activation")
    artifact_hashes = {path: sha(blob(h_commit, path)) for path in H_PATHS[1:]}
    if activation != {
        "schema": "ese.v92.o01-hotfix-activation/v1",
        "predecessor_h_commit": PRED_H,
        "g_commit": g_commit,
        "a_commit": a_commit,
        "a_tree": a_tree,
        "m_commit": m_commit,
        "m_tree": m_tree,
        "amendment_sha256": amendment_sha,
        "historical_functional_paths_sha256": sha(canonical(LEGACY.functional_paths())),
        "hotfix_functional_paths_sha256": sha(canonical(FUNCTIONAL)),
        "cumulative_functional_paths_sha256": sha(canonical(cumulative_paths())),
        "release_metadata_paths_sha256": sha(canonical(RELEASE_METADATA)),
        "build_gate_paths_sha256": sha(canonical(BUILD_GATE)),
        "package_documentation_paths_sha256": sha(canonical(PACKAGE_DOCUMENTATION)),
        "mod02_reseal_paths_sha256": sha(canonical(MOD02_RESEAL)),
        "candidate_paths_sha256": sha(canonical(candidate_paths())),
        "artifact_sha256": artifact_hashes,
    }:
        raise GateError("activation content")
    validate_review(blob(h_commit, H_PATHS[2]), "Sol", a_commit, a_tree)
    validate_review(blob(h_commit, H_PATHS[3]), "Terra", a_commit, a_tree)
    offline = exact(load_bytes(blob(h_commit, H_PATHS[1])), {
        "schema", "source_commit", "source_tree", "m_commit", "m_tree",
        "amendment_sha256", "gates",
    }, "offline")
    if offline["schema"] != "ese.v92.o01-hotfix-offline-summary/v1" or offline["source_commit"] != a_commit or offline["source_tree"] != a_tree or offline["m_commit"] != m_commit or offline["m_tree"] != m_tree or offline["amendment_sha256"] != amendment_sha or not isinstance(offline["gates"], list) or len(offline["gates"]) != len(OFFLINE):
        raise GateError("offline content")
    for item, (name, command, marker) in zip(offline["gates"], OFFLINE):
        exact(item, {"name", "command", "exit_code", "marker", "body", "body_sha256"}, "offline gate")
        if item["name"] != name or item["command"] != command or type(item["exit_code"]) is not int or item["exit_code"] != 0 or item["marker"] != marker or item["body"] != [marker] or item["body_sha256"] != sha(canonical(item["body"])):
            raise GateError("offline gate")


def verify_r_hotfix(
    r_commit: str,
    parent_commit: str,
    a_commit: str,
    h_commit: str,
    s_commit: str | None,
    m_commit: str,
) -> None:
    LEGACY.verify_r(r_commit, parent_commit, a_commit, h_commit, s_commit)
    manifest = exact(load_bytes(blob(m_commit, M_MANIFEST)), {
        "schema", "source_commit", "source_identity_sha256", "executable_sha256",
    }, "MOD02 manifest")
    run = load_bytes(blob(
        r_commit,
        "artifacts/v92-o01-formal/formal-run-result.json",
    ))
    if (
        manifest["schema"] != "ese.mod02.build-manifest/v1"
        or manifest["source_commit"] != a_commit
        or manifest["source_identity_sha256"] != MOD02_IDENTITY
        or not isinstance(run, dict)
        or run.get("executable_sha256") != manifest["executable_sha256"]
    ):
        raise GateError("formal executable binding")


def autodetect(document: dict) -> str:
    head = git("rev-parse", "HEAD")
    if head == PRED_H:
        worktree_stats()
        return "DRAFT_WORKTREE"
    chain = []
    current = head
    while current != PRED_H and len(chain) < 7:
        chain.append(current)
        current_parents = parents(current)
        if len(current_parents) != 1:
            raise GateError("merge topology")
        current = current_parents[0]
    if current != PRED_H:
        raise GateError("predecessor ancestry")
    chain.reverse()
    g_commit = chain[0]
    verify_g(g_commit, document)
    if len(chain) == 1:
        return "G"
    a_commit = chain[1]
    verify_a(a_commit, g_commit)
    if len(chain) == 2:
        return "A"
    m_commit = chain[2]
    verify_m(m_commit, a_commit)
    if len(chain) == 3:
        return "M"
    h_commit = chain[3]
    verify_h(h_commit, m_commit, a_commit, g_commit)
    if len(chain) == 4:
        return "H"
    next_commit = chain[4]
    if changed(h_commit, next_commit) == S_PATHS:
        LEGACY.verify_s(next_commit, h_commit, a_commit)
        if len(chain) == 5:
            return "S"
        if len(chain) != 6:
            raise GateError("intermediate after S")
        verify_r_hotfix(
            chain[5], next_commit, a_commit, h_commit, next_commit, m_commit
        )
        return "R"
    if len(chain) != 5:
        raise GateError("intermediate before R")
    verify_r_hotfix(
        next_commit, h_commit, a_commit, h_commit, None, m_commit
    )
    return "R"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check-worktree", action="store_true")
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    try:
        document = load()
        validate(document)
        verify_predecessor()
        if args.verify and git("status", "--porcelain", "--untracked-files=all"):
            raise GateError("verification worktree dirty")
        state = autodetect(document) if args.verify else (
            "DRAFT_WORKTREE" if args.check_worktree and worktree_stats() else "DOCUMENT"
        )
    except Exception as exc:
        if not isinstance(exc, (GateError, ValueError, OSError, subprocess.SubprocessError)):
            raise
        print(f"V92_O01_HOTFIX_GOVERNANCE_FAIL {exc}", file=sys.stderr)
        return 1
    print("V92_O01_HOTFIX_GOVERNANCE_PASS "
          f"state={state} paths={BUDGET[0]} add={BUDGET[1]} "
          f"delete={BUDGET[2]} net={BUDGET[3]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
