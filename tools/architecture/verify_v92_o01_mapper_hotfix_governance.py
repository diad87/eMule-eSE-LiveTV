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

H32 = "c9a81244ba8f2171aed6610aaea10a5898ac6acb"
G8 = "487f43bd95cc841b91311dd7166a863ecdd7bf8e"
G8_TREE = "f0b5f1587a836d30e668dfa377eab6c0c218a073"
A36 = "3d19e260c1bdf24f1b03a181869ae0602e795179"
A36_TREE = "01f1646d7f384a91c3e5b623cf0de95ddbc615c1"
M36 = "9c9e9b517bac1f9175c4b68623b40281f8fc9b28"
M36_TREE = "63f96e67f4d2b581c8ae04075426dda7e6e13ed1"
PRED_H = "db2ddfd42768ae9f7311ca5f8f0c618a3484f5a3"
PRED_H_TREE = "c381830c43f2a2d7b94dea1bd0afa125959aface"

GOV = [
    DOC,
    "tools/architecture/verify_v92_o01_mapper_hotfix_governance.py",
    "tools/architecture/test_verify_v92_o01_mapper_hotfix_governance.py",
]
HISTORICAL_GOV_SHA256 = {
    GOV[0]: "8978e30d6817bcdadb6072844dde8395c4277da33f77a004fa3d9e1cacc1b677",
    GOV[1]: "bd5eb197828b889831afa3a67489a2299f5ce01a4ab5df8ac0244cec5e47f28d",
    GOV[2]: "8fb0550d7c99705bc47248ab2eb93539652ab73d0908781265fffb05cd4bed20",
}

FORMAL_RUNTIME_FIX = [
    "tools/lab/nat_gateway/v92_o01_t8_daemon.js",
    "tools/lab/nat_gateway/test/v92_o01_t8_daemon.test.js",
    "tools/lab/t8_hyperv.ps1",
    "tools/lab/test_t8_hyperv_plan.ps1",
    "tools/lab/run_v92_o01_formal.ps1",
    "tools/lab/test_v92_o01_formal_runner_mock.ps1",
]
FORMAL_RUNTIME_FIX_SHA256 = {
    FORMAL_RUNTIME_FIX[0]: "525865a3477f2cc250ae30c2cbaf7ca84c900f471234ffc277f390609584731f",
    FORMAL_RUNTIME_FIX[1]: "041e1de8f4ac514b7f680aeaf23e56b72d8c4bc12cf79cdeba4771782993db8a",
    FORMAL_RUNTIME_FIX[2]: "9972724ad8c18830b5bb256ad419bc05bd1c9c7c7c62e3567532438c3d678138",
    FORMAL_RUNTIME_FIX[3]: "2c63431330fe9428002141eb24ff68679e40c6f4296c55493212522b6d48a8a7",
    FORMAL_RUNTIME_FIX[4]: "7e634561fce9fa5d0df527b2f595b1b6a56efba655a32d436a08a87805eb3762",
    FORMAL_RUNTIME_FIX[5]: "0400589f453b92adc5710d7d7b7212a75b2353c4dc3016b7a276a6a95972fa87",
}
MOD02_TEST_RATCHET = ["tests/test_v92_mod02_characterization.py"]
MOD02_TEST_RATCHET_SHA256 = {
    MOD02_TEST_RATCHET[0]: "7129060dcd2811bbda9ad0a9c56c15c946e39bcf96adcf14bfec44ff84e0b346",
}
HISTORICAL_OVERLAP = [
    FORMAL_RUNTIME_FIX[0],
    FORMAL_RUNTIME_FIX[1],
    FORMAL_RUNTIME_FIX[4],
    FORMAL_RUNTIME_FIX[5],
]
NEW_CANDIDATE = [
    FORMAL_RUNTIME_FIX[2], FORMAL_RUNTIME_FIX[3], MOD02_TEST_RATCHET[0],
]
A_PATHS = sorted(FORMAL_RUNTIME_FIX + MOD02_TEST_RATCHET)
PATH_BUDGET = {
    FORMAL_RUNTIME_FIX[0]: (10, 2),
    FORMAL_RUNTIME_FIX[1]: (9, 2),
    FORMAL_RUNTIME_FIX[2]: (2, 2),
    FORMAL_RUNTIME_FIX[3]: (23, 0),
    FORMAL_RUNTIME_FIX[4]: (2, 2),
    FORMAL_RUNTIME_FIX[5]: (1, 1),
    MOD02_TEST_RATCHET[0]: (1, 1),
}
BUDGET = (7, 48, 10, 38)
FORMAL_RUNTIME_FIX_BUDGET = (6, 47, 9, 38)
MOD02_TEST_RATCHET_BUDGET = (1, 1, 1, 0)
CANDIDATE_BUDGET = (62, 1702, 136, 1566)

HISTORICAL_CANDIDATE = sorted([
    "CHANGES_FROM_EMULE_0.70b.md",
    "GUIA-RAPIDA.md",
    "README.md",
    "THIRD_PARTY_LICENSES.md",
    "docs/INDEX.md",
    "docs/RELEASE_NOTES_v9.2.0-rc.1.md",
    "docs/USER_GUIDE.md",
    "docs/V92_RC1_EXECUTION.md",
    "libkad6/make_crypto_vectors.bat",
    "libnatmap/src/pcp_pair_transaction.cpp",
    "libnatmap/tests/test_legacy_mapper_projection.cpp",
    "libnatmap/tests/test_pcp_pair_transaction.cpp",
    "srchybrid/Mod02BuildIdentity.h",
    "srchybrid/UPnPImplNATPMP.cpp",
    "srchybrid/UPnPImplPCP.cpp",
    "srchybrid/UPnPImplPCP.h",
    "srchybrid/Version.h",
    "srchybrid/eSE/package-lock.json",
    "srchybrid/eSE/package.json",
    "srchybrid/eSE/test/live_tv_regression.test.js",
    "tests/test_v92_l02_pcp_ownership.py",
    "tests/test_v92_l03_natpmp_ownership.py",
    "tests/test_v92_m2a_lt1_release_gate.py",
    "tools/lab/handoff93/run_product_mapper_cycle.ps1",
    "tools/lab/handoff93/test_product_mapper_formal_soak_mock.ps1",
    "tools/lab/nat_gateway/test/v92_o01_bridge_protocol.test.js",
    "tools/lab/nat_gateway/test/v92_o01_formal_controller.test.js",
    "tools/lab/nat_gateway/test/v92_o01_formal_host.test.js",
    "tools/lab/nat_gateway/test/v92_o01_formal_rpc.test.js",
    "tools/lab/nat_gateway/test/v92_o01_formal_rpc_peer_mock.js",
    "tools/lab/nat_gateway/test/v92_o01_product_stream.test.js",
    "tools/lab/nat_gateway/test/v92_o01_soak.test.js",
    "tools/lab/nat_gateway/test/v92_o01_t8_child.test.js",
    "tools/lab/nat_gateway/test/v92_o01_t8_daemon.test.js",
    "tools/lab/nat_gateway/test/v92_o01_t8_fault_controller.test.js",
    "tools/lab/nat_gateway/test/v92_o01_t8_gateway_adapter.test.js",
    "tools/lab/nat_gateway/test/v92_o01_t8_network_adapter.test.js",
    "tools/lab/nat_gateway/test/v92_o01_t8_udp_mux.test.js",
    "tools/lab/nat_gateway/test/v92_o01_validate_formal.test.js",
    "tools/lab/nat_gateway/v92_o01_bridge_protocol.js",
    "tools/lab/nat_gateway/v92_o01_formal_controller.js",
    "tools/lab/nat_gateway/v92_o01_formal_host.js",
    "tools/lab/nat_gateway/v92_o01_formal_rpc.js",
    "tools/lab/nat_gateway/v92_o01_product_stream.js",
    "tools/lab/nat_gateway/v92_o01_scenario.json",
    "tools/lab/nat_gateway/v92_o01_soak.js",
    "tools/lab/nat_gateway/v92_o01_t8_child.js",
    "tools/lab/nat_gateway/v92_o01_t8_daemon.js",
    "tools/lab/nat_gateway/v92_o01_t8_fault_controller.js",
    "tools/lab/nat_gateway/v92_o01_t8_gateway_adapter.js",
    "tools/lab/nat_gateway/v92_o01_t8_network_adapter.js",
    "tools/lab/nat_gateway/v92_o01_t8_udp_mux.js",
    "tools/lab/nat_gateway/v92_o01_validate_formal.js",
    "tools/lab/run_v92_o01_formal.ps1",
    "tools/lab/test_v92_o01_formal_rpc_pump_mock.ps1",
    "tools/lab/test_v92_o01_formal_runner_mock.ps1",
    "tools/lab/test_v92_o01_vm_session_mock.ps1",
    "tools/lab/test_v92_o01_vm_t8_smoke.ps1",
    "tools/lab/v92_o01_vm_session.psm1",
])
HISTORICAL_CANDIDATE_SHA256 = "9abb0acf0ed94ca4b93ead443c6a7510c1d8d1a893a9340e6143bd483eee05c9"
CANDIDATE_SHA256 = "140557b8694f61af9f660dc990082b2696a0ee1ae6fb46a679f5d2d25e06e828"

M_MANIFEST = "docs/architecture/mod02_build_manifest_v1.json"
M_MATRIX = "docs/architecture/mod02_characterization_matrix_v1.json"
H_PATHS = [
    "artifacts/v92-o01-governance/activation.json",
    "artifacts/v92-o01-governance/offline-summary.json",
    "artifacts/v92-o01-governance/review-sol.json",
    "artifacts/v92-o01-governance/review-terra.json",
]
RELEASE_TAG = "v0.70b-eSE9.2.0-rc.1"
RELEASE_FINGERPRINT = "3E1B51DCE2A83DF5DDA10697385FD8C7F05D8C81EB391B967D30E0CD6761ED23"
MOD02_IDENTITY = "b9c3c25fece8a80d71eee340e61d8cd5088b95f8b12e221278d9d249f6d29c9d"
MOD02_MARKER_SHA = "17d7cbca262c94f802d59255d0ec41137bd85c12037a393cc5198abd40373cae"
SCENARIO = "tools/lab/nat_gateway/v92_o01_scenario.json"
SCENARIO_SHA256 = "3462299984b058685ad051ffc20f76e9d21772f629b7d3c2abd05b8f48693028"
HEX64 = re.compile(r"^[0-9a-f]{64}$")

REVIEWS = [
    "Terra APPROVE with findings=[]",
    "Sol APPROVE with findings=[]",
]
GATES = [
    "Node 22 complete nat_gateway suite",
    "PowerShell parser for every changed ps1",
    "T8 Hyper-V plan regression",
    "formal runner mock",
    "MOD02 characterization identity ratchet",
    "G9 hostile governance suite",
    "official full Release x64 rebuild from clean A37",
    "M37 MOD02 verifier and runtime reseal",
    "git diff --check",
]
OFFLINE = [
    (GATES[0], "npm.cmd test", "O01_NODE_SUITE_PASS"),
    (GATES[1], "powershell parser changed ps1", "O01_POWERSHELL_PARSE_PASS"),
    (GATES[2], "powershell -File tools/lab/test_t8_hyperv_plan.ps1", "O01_T8_PLAN_PASS"),
    (GATES[3], "powershell -File tools/lab/test_v92_o01_formal_runner_mock.ps1", "O01_RUNNER_MOCK_PASS"),
    (GATES[4], "python -B tests/test_v92_mod02_characterization.py", "O01_MOD02_CHARACTERIZATION_PASS"),
    (GATES[5], "python -B tools/architecture/test_verify_v92_o01_mapper_hotfix_governance.py", "O01_G9_GOVERNANCE_PASS"),
    (GATES[6], "powershell -File tools/build_all.ps1 -ReleaseTag v0.70b-eSE9.2.0-rc.1", "O01_RELEASE_BUILD_PASS"),
    (GATES[7], "verify M37 MOD02 artifacts", "O01_MOD02_RESEAL_PASS"),
    (GATES[8], "git diff --check", "O01_DIFF_CHECK_PASS"),
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
        args, cwd=ROOT, check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
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


def load_bytes(data: bytes) -> object:
    return json.loads(data.decode("utf-8"))


def load() -> dict:
    return json.loads(DOC_PATH.read_text(encoding="utf-8"))


def blob(commit: str, path: str) -> bytes:
    return subprocess.run(
        ["git", "show", f"{commit}:{path}"], cwd=ROOT, check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    ).stdout


def parents(commit: str) -> list[str]:
    return git("show", "-s", "--format=%P", commit).split()


def changed(parent: str, commit: str) -> list[str]:
    return sorted(filter(None, git("diff", "--name-only", parent, commit, "--").splitlines()))


def require_single_parent(commit: str, parent: str, label: str) -> None:
    if parents(commit) != [parent]:
        raise GateError(f"{label} parent")


def parse_utc(
    value: object, where: str, allow_timezone_offset: bool = False,
) -> datetime.datetime:
    if not isinstance(value, str):
        raise GateError(where)
    try:
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise GateError(where) from exc
    if parsed.tzinfo is None or (
        not allow_timezone_offset and parsed.utcoffset() != datetime.timedelta(0)
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


def candidate_paths() -> list[str]:
    return sorted(set(HISTORICAL_CANDIDATE) | set(A_PATHS))


def release_receipt_path(a_commit: str) -> str:
    return f"artifacts/v92-o01-release-build-{a_commit[:8]}/emule-release-build.json"


def m_paths(a_commit: str) -> list[str]:
    return sorted([
        M_MANIFEST,
        M_MATRIX,
        f"artifacts/mod02-runtime-v92-{a_commit[:8]}/summary.json",
        release_receipt_path(a_commit),
    ])


def expected_document() -> dict:
    topology = {
        "G9": "direct child of H36; exactly this amendment, verifier and verifier test",
        "A37": "direct child of G9; exactly formal_runtime_fix_paths plus mod02_test_ratchet_paths at their exact separate budgets and byte identities",
        "M37": "direct child of A37; exact official Release receipt plus MOD02 manifest, matrix and runtime summary",
        "H37": "direct child of M37; exact four governance carriers with two independent empty-finding approvals",
        "R": "direct child of H37; exact formal eight-hour evidence sourced from A37 and using the executable validated by M37",
    }
    phases = {
        "schema": "ese.v92.o01-runtime-fix-phases/v1",
        "merge_policy": "Every G9/A37/M37/H37/R commit has exactly one parent; merges, S, intermediate commits and reused build metadata are rejected.",
        "G9": {"parent": "H36", "delta": "governance_paths"},
        "A37": {"parent": "G9", "delta": "formal_runtime_fix_paths_plus_mod02_test_ratchet_paths"},
        "M37": {"parent": "A37", "delta": "m_carrier_paths", "build": "official full Release rebuild from clean A37"},
        "H37": {"parent": "M37", "delta": "h_carrier_paths"},
        "R": {"parent": "H37", "source": "A37", "governance": "H37", "executable": "exact_M37_manifest_executable_sha256", "release_gate": True},
    }
    carriers = {
        "M37": {
            "fixed": [M_MANIFEST, M_MATRIX],
            "summary_pattern": "artifacts/mod02-runtime-v92-<A37[0:8]>/summary.json",
            "release_build_receipt_pattern": "artifacts/v92-o01-release-build-<A37[0:8]>/emule-release-build.json",
            "file_count": 4,
        },
        "H37": H_PATHS,
        "R": {
            "directory": "artifacts/v92-o01-formal",
            "checkpoint_pattern": "checkpoint-(01..95).json",
            "fixed": ["controller-result.json", "formal-run-result.json", "formal-validation.json"],
            "file_count": 98,
        },
    }
    return {
        "schema": "ese.v92.o01-runtime-fix-governance/v1",
        "status": "DRAFT_PRE_G9",
        "predecessor": {
            "g8_commit": G8, "g8_tree": G8_TREE,
            "a36_commit": A36, "a36_tree": A36_TREE,
            "m36_commit": M36, "m36_tree": M36_TREE,
            "h36_commit": PRED_H, "h36_tree": PRED_H_TREE,
        },
        "historical_contract": {
            "governance_document_sha256": HISTORICAL_GOV_SHA256[GOV[0]],
            "governance_verifier_sha256": HISTORICAL_GOV_SHA256[GOV[1]],
            "governance_test_sha256": HISTORICAL_GOV_SHA256[GOV[2]],
            "candidate_path_count": 59,
            "candidate_add_exact": 1654,
            "candidate_delete_exact": 126,
            "candidate_net_exact": 1528,
            "candidate_paths_sha256": HISTORICAL_CANDIDATE_SHA256,
        },
        "scope": "V92-O01 rc.1 only: repair the controller resource accounting and formal terminal propagation exposed by the first A36 physical run, ratchet the remaining MOD02 characterization test to the sealed identity, keep the H36 release candidate contract immutable, rebuild the official Release executable from A37, reseal MOD02 in M37, and permit release only through a direct independently validated R after H37.",
        "topology": topology,
        "phase_contract": phases,
        "governance_paths": GOV,
        "formal_runtime_fix_paths": FORMAL_RUNTIME_FIX,
        "formal_runtime_fix_sha256": FORMAL_RUNTIME_FIX_SHA256,
        "mod02_test_ratchet_paths": MOD02_TEST_RATCHET,
        "mod02_test_ratchet_sha256": MOD02_TEST_RATCHET_SHA256,
        "path_budget": {
            path: {"add_exact": row[0], "delete_exact": row[1]}
            for path, row in PATH_BUDGET.items()
        },
        "historical_overlap_paths": HISTORICAL_OVERLAP,
        "new_candidate_paths": NEW_CANDIDATE,
        "budget": {"path_count": 7, "add_exact": 48, "delete_exact": 10, "net_exact": 38, "headroom": 0},
        "formal_runtime_fix_budget": {"path_count": 6, "add_exact": 47, "delete_exact": 9, "net_exact": 38, "headroom": 0},
        "mod02_test_ratchet_budget": {"path_count": 1, "add_exact": 1, "delete_exact": 1, "net_exact": 0, "headroom": 0},
        "cumulative_candidate_budget": {"path_count": 62, "add_exact": 1702, "delete_exact": 136, "net_exact": 1566},
        "cumulative_candidate_paths_sha256": CANDIDATE_SHA256,
        "release_contract": {
            "release_tag": RELEASE_TAG,
            "source_fingerprint": RELEASE_FINGERPRINT,
            "mod02_identity_sha256": MOD02_IDENTITY,
            "mod02_marker_sha256": MOD02_MARKER_SHA,
            "scenario_sha256": SCENARIO_SHA256,
            "scenario_socket_limit": 2,
            "build_policy": "M37 must contain a new official full Release x64 build receipt bound to A37; M36 binary or metadata reuse is forbidden.",
        },
        "carrier_paths": carriers,
        "required_reviews": REVIEWS,
        "offline_gates": GATES,
        "physical_policy": {
            "formal": "Exactly 28800000 monotonic milliseconds, no duration override, no resume, no skip-cleanup, Node 22, clean A37 source and the M37 executable.",
            "claim_rule": "Only independently validated direct-R evidence with exact cleanup and baseline restoration may award V92-O01 PASS.",
            "preflight": "No S phase exists in G9; diagnostic runs are external NON_RELEASE evidence and cannot enter the release ancestry.",
        },
        "stop_conditions": [
            "A37 path 8 or any path outside the two closed A37 slices",
            "A37 budget differs by one line or is preserved only by a compensated rebalance",
            "an A37 byte identity differs from its pinned SHA-256",
            "historical overlap differs from exactly four named paths or cumulative candidate union differs from 62 paths",
            "scenario limits.sockets differs from integer 2 or the scenario blob changes",
            "daemon counts controller stdio as gateway sockets or does not retain exactly two data-plane UDP sockets",
            "T8 plan or teardown terminates the caller, or the formal runner can report success after a failed nested phase",
            "M37 is not a fresh clean official Release build bound to A37 and the exact MOD02 identity",
            "source, Node, package or evidence binding changes during a run",
            "P0, P1, P2 or nonempty review finding",
            "release_gate=true before independent validation and exact baseline restoration",
        ],
        "activation_state": {
            "G9": None, "A37": None, "M37": None, "H37": None, "R": None,
            "rule": "The document never stores its own commit; phase identities are derived from exact Git parentage and later carriers.",
        },
    }


def validate(value: dict) -> bool:
    exact(value, set(expected_document()), "root")
    if value != expected_document():
        raise GateError("document exact contract")
    if len(HISTORICAL_CANDIDATE) != 59 or len(set(HISTORICAL_CANDIDATE)) != 59:
        raise GateError("historical candidate set")
    if sha(canonical(HISTORICAL_CANDIDATE)) != HISTORICAL_CANDIDATE_SHA256:
        raise GateError("historical candidate identity")
    if set(FORMAL_RUNTIME_FIX) & set(HISTORICAL_CANDIDATE) != set(HISTORICAL_OVERLAP):
        raise GateError("historical overlap")
    if set(MOD02_TEST_RATCHET) & set(HISTORICAL_CANDIDATE):
        raise GateError("ratchet historical overlap")
    if set(A_PATHS) - set(HISTORICAL_CANDIDATE) != set(NEW_CANDIDATE):
        raise GateError("new candidate set")
    if len(candidate_paths()) != CANDIDATE_BUDGET[0] or sha(canonical(candidate_paths())) != CANDIDATE_SHA256:
        raise GateError("candidate union")
    if MOD02_MARKER_SHA != mod02_marker_sha256():
        raise GateError("MOD02 marker identity")
    return True


def verify_scenario(raw: bytes, where: str) -> None:
    if sha(raw) != SCENARIO_SHA256:
        raise GateError(f"{where} scenario identity")
    value = load_bytes(raw)
    if not isinstance(value, dict) or not isinstance(value.get("limits"), dict):
        raise GateError(f"{where} scenario schema")
    sockets = value["limits"].get("sockets")
    if type(sockets) is not int or sockets != 2:
        raise GateError(f"{where} scenario socket limit")


def verify_predecessor() -> None:
    expected_parents = {
        G8: H32,
        A36: G8,
        M36: A36,
        PRED_H: M36,
    }
    for commit, parent in expected_parents.items():
        require_single_parent(commit, parent, "predecessor")
    expected_trees = {
        G8: G8_TREE, A36: A36_TREE, M36: M36_TREE, PRED_H: PRED_H_TREE,
    }
    for commit, tree in expected_trees.items():
        if git("rev-parse", f"{commit}^{{tree}}") != tree:
            raise GateError("predecessor tree")
    if changed(H32, G8) != sorted(GOV):
        raise GateError("predecessor G8 delta")
    if changed(A36, M36) != m_paths(A36):
        raise GateError("predecessor M36 delta")
    if changed(M36, PRED_H) != H_PATHS:
        raise GateError("predecessor H36 delta")
    observed = {path: sha(blob(PRED_H, path)) for path in GOV}
    if observed != HISTORICAL_GOV_SHA256:
        raise GateError("predecessor governance identity")
    activation = load_bytes(blob(PRED_H, H_PATHS[0]))
    if not isinstance(activation, dict) or activation.get("candidate_paths_sha256") != HISTORICAL_CANDIDATE_SHA256:
        raise GateError("predecessor candidate identity")
    verify_scenario(blob(PRED_H, SCENARIO), "predecessor")


def observed_budget(
    stats: dict[str, tuple[int, int]], paths: list[str] | None = None,
) -> tuple[int, int, int, int]:
    selected = stats if paths is None else {path: stats[path] for path in paths}
    return (
        len(selected),
        sum(row[0] for row in selected.values()),
        sum(row[1] for row in selected.values()),
        sum(row[0] - row[1] for row in selected.values()),
    )


def validate_budget(stats: dict[str, tuple[int, int]], where: str) -> None:
    if sorted(stats) != A_PATHS:
        raise GateError(f"{where} allowlist")
    if observed_budget(stats) != BUDGET:
        raise GateError(f"{where} budget")
    if stats != PATH_BUDGET:
        raise GateError(f"{where} path budget")
    if observed_budget(stats, FORMAL_RUNTIME_FIX) != FORMAL_RUNTIME_FIX_BUDGET:
        raise GateError(f"{where} formal runtime fix budget")
    if observed_budget(stats, MOD02_TEST_RATCHET) != MOD02_TEST_RATCHET_BUDGET:
        raise GateError(f"{where} MOD02 test ratchet budget")
    if set(FORMAL_RUNTIME_FIX) & set(HISTORICAL_CANDIDATE) != set(HISTORICAL_OVERLAP):
        raise GateError(f"{where} overlap")


def commit_budget(parent: str, commit: str) -> None:
    stats: dict[str, tuple[int, int]] = {}
    for line in git("diff", "--numstat", parent, commit, "--").splitlines():
        added, deleted, path = line.split("\t", 2)
        if not added.isdigit() or not deleted.isdigit():
            raise GateError("A binary payload")
        stats[path] = (int(added), int(deleted))
    validate_budget(stats, "A")


def verify_fix_hashes(reader, where: str) -> None:
    runtime = {path: sha(reader(path)) for path in FORMAL_RUNTIME_FIX}
    ratchet = {path: sha(reader(path)) for path in MOD02_TEST_RATCHET}
    if runtime != FORMAL_RUNTIME_FIX_SHA256:
        raise GateError(f"{where} formal runtime fix identity")
    if ratchet != MOD02_TEST_RATCHET_SHA256:
        raise GateError(f"{where} MOD02 test ratchet identity")


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
        stats[path] = (
            data.count(b"\n") + int(bool(data) and not data.endswith(b"\n")), 0,
        )
    validate_budget(stats, "worktree")
    verify_fix_hashes(lambda path: (ROOT / path).read_bytes(), "worktree")
    verify_scenario((ROOT / SCENARIO).read_bytes(), "worktree")
    return True


def verify_g(g_commit: str, document: dict) -> None:
    require_single_parent(g_commit, PRED_H, "G9")
    if changed(PRED_H, g_commit) != sorted(GOV):
        raise GateError("G9 delta")
    if load_bytes(blob(g_commit, DOC)) != document:
        raise GateError("G9 document")


def verify_a(a_commit: str, g_commit: str) -> None:
    require_single_parent(a_commit, g_commit, "A37")
    if changed(g_commit, a_commit) != A_PATHS:
        raise GateError("A37 delta")
    commit_budget(g_commit, a_commit)
    verify_fix_hashes(lambda path: blob(a_commit, path), "A37")
    verify_scenario(blob(a_commit, SCENARIO), "A37")


def verify_m(m_commit: str, a_commit: str) -> None:
    require_single_parent(m_commit, a_commit, "M37")
    paths = m_paths(a_commit)
    if changed(a_commit, m_commit) != paths:
        raise GateError("M37 delta")
    manifest_raw = blob(m_commit, M_MANIFEST)
    manifest = exact(load_bytes(manifest_raw), {
        "schema", "source_commit", "source_identity_sha256", "executable_sha256",
    }, "MOD02 manifest")
    if (
        manifest["schema"] != "ese.mod02.build-manifest/v1"
        or manifest["source_commit"] != a_commit
        or manifest["source_identity_sha256"] != MOD02_IDENTITY
        or not isinstance(manifest["executable_sha256"], str)
        or not HEX64.fullmatch(manifest["executable_sha256"])
    ):
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
        "Release source commit timestamp", allow_timezone_offset=True,
    )
    if (
        type(receipt["schema"]) is not int or receipt["schema"] != 1
        or receipt["component"] != "emule"
        or receipt["releaseTag"] != RELEASE_TAG
        or receipt["commit"] != a_commit
        or receipt["sourceFingerprint"] != RELEASE_FINGERPRINT
        or release_source_fingerprint() != RELEASE_FINGERPRINT
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
    if (
        summary["schema"] != "ese.mod02.stream-selftest/v1"
        or summary["build_manifest_sha256"] != sha(manifest_raw)
        or summary["source_commit"] != a_commit
        or summary["source_identity_sha256"] != MOD02_IDENTITY
        or summary["source_tree_clean"] is not True
        or summary["executable_sha256"] != manifest["executable_sha256"]
    ):
        raise GateError("MOD02 summary binding")
    if (
        summary["timeout_seconds"] != 180 or summary["timed_out"] is not False
        or summary["taskkill_started"] is not False
        or summary["taskkill_finished"] is not True
        or summary["taskkill_exit_code"] is not None
        or summary["termination_confirmed"] is not True
        or type(summary["exit_code"]) is not int or summary["exit_code"] != 0
    ):
        raise GateError("MOD02 termination")
    if (
        summary["expected_markers"] != expected_markers
        or summary["observed_markers_sanitized"] != expected_markers
        or summary["markers_verified"] is not True
        or summary["marker_sha256"] != MOD02_MARKER_SHA
    ):
        raise GateError("MOD02 markers")
    if (
        summary["verdict"] != "PASS"
        or summary["command"] != "--portable --ignoreinstances --selftest"
        or summary["isolation"] != "portable unique output root; no UI"
    ):
        raise GateError("MOD02 verdict")
    source_time = parse_utc(summary["latest_critical_source_write_utc"], "MOD02 timestamp")
    executable_time = parse_utc(summary["executable_write_utc"], "MOD02 timestamp")
    if executable_time < source_time or executable_time < commit_time or receipt_built_at < executable_time:
        raise GateError("MOD02 build ordering")

    matrix = load_bytes(blob(m_commit, M_MATRIX))
    prior_matrix = load_bytes(blob(a_commit, M_MATRIX))
    if not isinstance(matrix, dict) or not isinstance(prior_matrix, dict) or set(matrix) != set(prior_matrix):
        raise GateError("MOD02 matrix schema")
    if (
        {key: value for key, value in matrix.items() if key != "runtime_gate"}
        != {key: value for key, value in prior_matrix.items() if key != "runtime_gate"}
    ):
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
    if (
        gate["runner"] != "tools/architecture/run_mod02_stream_selftest.ps1"
        or gate["build_manifest"] != M_MANIFEST
        or gate["summary"] != summary_path
        or gate["status"] != "PASS"
        or gate["required_summary"] != MOD02_REQUIRED
        or gate["acceptance"] != prior_matrix["runtime_gate"]["acceptance"]
        or receipt_binding != {
            "path": receipt_path, "sha256": sha(receipt_raw), "source_tree": a_tree,
        }
        or evidence != expected_evidence
    ):
        raise GateError("MOD02 matrix binding")


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


def verify_h(h_commit: str, m_commit: str, a_commit: str, g_commit: str) -> None:
    require_single_parent(h_commit, m_commit, "H37")
    if changed(m_commit, h_commit) != H_PATHS:
        raise GateError("H37 delta")
    a_tree = git("rev-parse", f"{a_commit}^{{tree}}")
    m_tree = git("rev-parse", f"{m_commit}^{{tree}}")
    amendment_sha = sha(blob(g_commit, DOC))
    children = {path: blob(h_commit, path) for path in H_PATHS[1:]}
    activation = exact(load_bytes(blob(h_commit, H_PATHS[0])), {
        "schema", "predecessor_h_commit", "g_commit", "a_commit", "a_tree",
        "m_commit", "m_tree", "amendment_sha256",
        "historical_candidate_paths_sha256", "formal_runtime_fix_paths_sha256",
        "mod02_test_ratchet_paths_sha256",
        "historical_overlap_paths_sha256", "new_candidate_paths_sha256",
        "candidate_paths_sha256", "artifact_sha256",
    }, "activation")
    expected_activation = {
        "schema": "ese.v92.o01-runtime-fix-activation/v1",
        "predecessor_h_commit": PRED_H,
        "g_commit": g_commit,
        "a_commit": a_commit,
        "a_tree": a_tree,
        "m_commit": m_commit,
        "m_tree": m_tree,
        "amendment_sha256": amendment_sha,
        "historical_candidate_paths_sha256": HISTORICAL_CANDIDATE_SHA256,
        "formal_runtime_fix_paths_sha256": sha(canonical(FORMAL_RUNTIME_FIX)),
        "mod02_test_ratchet_paths_sha256": sha(canonical(MOD02_TEST_RATCHET)),
        "historical_overlap_paths_sha256": sha(canonical(HISTORICAL_OVERLAP)),
        "new_candidate_paths_sha256": sha(canonical(NEW_CANDIDATE)),
        "candidate_paths_sha256": CANDIDATE_SHA256,
        "artifact_sha256": {path: sha(raw) for path, raw in children.items()},
    }
    if activation != expected_activation:
        raise GateError("activation content")
    validate_review(children[H_PATHS[2]], "Sol", a_commit, a_tree)
    validate_review(children[H_PATHS[3]], "Terra", a_commit, a_tree)
    offline = exact(load_bytes(children[H_PATHS[1]]), {
        "schema", "source_commit", "source_tree", "m_commit", "m_tree",
        "amendment_sha256", "gates",
    }, "offline")
    if (
        offline["schema"] != "ese.v92.o01-runtime-fix-offline-summary/v1"
        or offline["source_commit"] != a_commit
        or offline["source_tree"] != a_tree
        or offline["m_commit"] != m_commit
        or offline["m_tree"] != m_tree
        or offline["amendment_sha256"] != amendment_sha
        or not isinstance(offline["gates"], list)
        or len(offline["gates"]) != len(OFFLINE)
    ):
        raise GateError("offline content")
    for item, (name, command, marker) in zip(offline["gates"], OFFLINE):
        exact(item, {"name", "command", "exit_code", "marker", "body", "body_sha256"}, "offline gate")
        if (
            item["name"] != name or item["command"] != command
            or type(item["exit_code"]) is not int or item["exit_code"] != 0
            or item["marker"] != marker or item["body"] != [marker]
            or item["body_sha256"] != sha(canonical(item["body"]))
        ):
            raise GateError("offline gate")


def verify_r(
    r_commit: str, h_commit: str, a_commit: str, m_commit: str,
) -> None:
    require_single_parent(r_commit, h_commit, "R")
    LEGACY.verify_r(r_commit, h_commit, a_commit, h_commit, None)
    manifest = exact(load_bytes(blob(m_commit, M_MANIFEST)), {
        "schema", "source_commit", "source_identity_sha256", "executable_sha256",
    }, "MOD02 manifest")
    run = load_bytes(blob(r_commit, "artifacts/v92-o01-formal/formal-run-result.json"))
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
    chain: list[str] = []
    current = head
    while current != PRED_H and len(chain) < 6:
        chain.append(current)
        current_parents = parents(current)
        if len(current_parents) != 1:
            raise GateError("merge topology")
        current = current_parents[0]
    if current != PRED_H:
        raise GateError("predecessor ancestry")
    chain.reverse()
    if not chain:
        raise GateError("missing G9")
    g_commit = chain[0]
    verify_g(g_commit, document)
    if len(chain) == 1:
        return "G9"
    a_commit = chain[1]
    verify_a(a_commit, g_commit)
    if len(chain) == 2:
        return "A37"
    m_commit = chain[2]
    verify_m(m_commit, a_commit)
    if len(chain) == 3:
        return "M37"
    h_commit = chain[3]
    verify_h(h_commit, m_commit, a_commit, g_commit)
    if len(chain) == 4:
        return "H37"
    if len(chain) != 5:
        raise GateError("intermediate before R")
    verify_r(chain[4], h_commit, a_commit, m_commit)
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
        print(f"V92_O01_RUNTIME_FIX_GOVERNANCE_FAIL {exc}", file=sys.stderr)
        return 1
    print(
        "V92_O01_RUNTIME_FIX_GOVERNANCE_PASS "
        f"state={state} paths={BUDGET[0]} add={BUDGET[1]} "
        f"delete={BUDGET[2]} net={BUDGET[3]} candidate_paths={CANDIDATE_BUDGET[0]}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
