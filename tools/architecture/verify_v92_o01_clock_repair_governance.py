#!/usr/bin/env python3
"""Fail-closed governance for the V92-O01 A63 clock classification repair."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys


class GateError(RuntimeError):
    pass


ROOT = Path(__file__).resolve().parents[2]
DOC = "docs/architecture/v92_o01_clock_repair_governance_v1.json"
DOC_PATH = ROOT / DOC
GOV = sorted([
    DOC,
    "tools/architecture/verify_v92_o01_clock_repair_governance.py",
    "tools/architecture/test_verify_v92_o01_clock_repair_governance.py",
])

H37 = "e3ff85f2f710f25dbd98d8f9be059a5b2aee955d"
H37_TREE = "999b81fa83ee7e13caee4c65146b599e0c9c0c4c"
G10 = "3f18b71855b2d5341e8805f09d3c3e9e58901a13"
G10_TREE = "2423eac425740f5bfc64d3ffbfce3b030f115d20"
A38 = "ff52e777dd96de346328bf7825d1906499980615"
A38_TREE = "ecb70c0dd588632a0bf099ac73ad9256a854e9e2"
M38 = "cf9abf0103fb855f3fa7df41d89fb9b28897c23c"
M38_TREE = "4b649a93b62849a906852ecba190dbfe39ef32ce"
H38 = "c033d65f17df7dacade2b3518eade7da3349f956"
H38_TREE = "61b3133b9378a0a613050b35676a325b043dc9b1"
H62 = "4d1d157e48349b685c2e6d1ee1a8929a2d3a2589"
H62_TREE = "72a0e5d1ca37615d3a42c59d47bce26ded74705b"

OLD_VERIFIER = "tools/architecture/verify_v92_o01_physical_repair_governance.py"
HISTORICAL_GOV_SHA256 = {
    "docs/architecture/v92_o01_governance_amendment_v1.json": "f60a99763774cfdabe988b7e53f1d0d1722e31195f567fd1fc00372c4f8a5bd7",
    "tools/architecture/verify_v92_o01_governance_amendment.py": "dc7c114a2a31cb465c190392087f5fad3e10064723cd8633e167ed711849eb4e",
    "tools/architecture/test_verify_v92_o01_governance_amendment.py": "832b16df9f1c47e57676ce5ac19d0f2423809a27a4fc500e64317a6936406f7d",
    "docs/architecture/v92_o01_mapper_hotfix_governance_v1.json": "f74ac5518135593e1bb8f9dea42f301112310ec02cf7546efbb5156fc8808c8d",
    "tools/architecture/verify_v92_o01_mapper_hotfix_governance.py": "5ad3350ab9a973ff575e837332a54f68fa98bf305e25813cffa6deb5f7d85343",
    "tools/architecture/test_verify_v92_o01_mapper_hotfix_governance.py": "0f9ea17a7fe1ebbeb0f66915e35c68a456fd67cfe1b4b27bbed2b636d4f1f0d3",
    "docs/architecture/v92_o01_physical_repair_governance_v1.json": "ea14ac3bb18fbefac240ce74431ffa5f5adc152914779b27b7892e6ea558781a",
    OLD_VERIFIER: "83c6e7f8c134f6ede26328ef1a491cbb55746fdfa84372dfe9ecb9b8cbecd717",
    "tools/architecture/test_verify_v92_o01_physical_repair_governance.py": "bd1b2d2f84cd6fd1d61cd117ae8b9a74f5fc54d44013a4695b4e3387e286fb73",
}

DIAGNOSTIC_COMMITS = [
    "a39ab58bc933136539c643b179856fb4ea4071db", "715f5363103c0c92fb7cb7a34c25c7899a6e1856",
    "a1c60a636d32621a7ec97398bc2d90d34b59c7b5", "43c23a8d2016a57a0d22ef441358a013edcf5d7a",
    "28ac1b4c7b0f124eaa4fce5e63a8fb1a6c3d3a81", "2b45f0bea8190883685013d331ca36a6a6d37070",
    "61daaee9a7437b617da91bcfeccd292b523e2564", "be4ee6e3069c6fb01b8e9a572712adf93c374396",
    "35cc1d7997521686aff82a5a66c85ccb9e40406c", "761cae24ecd34b6d43b6ad51c9d7d4dba27a3dc5",
    "1afbc985edd4a7bf24f9845c400ba80f8eaa5e24", "930ba2b4581313a1bc679bd59f9411883e95ac76",
    "a885529137e4a6f4548e2482e8c50ad9d846293f", "a2b207250120004b239d77629dc2b3d632460b47",
    "a23982bd849380880f6ed691c4ee3c9fd2da0507", "ee686b8769922c4e423b5ec917a9a337335af8d5",
    "873774f38777a6f2c39ad59c5a9b0097b6112410", "7ee5ea029a219a6777e2f40589bd0d6216077b75",
    "0b1272b52bfea9cb5005270528e48178c3ab5d97", "2bf0641957f35f971f0d461f8c8c70d8e769fef9",
    "258c84dc05c44341b32601805fd1646b49688c56", "60f91a1cc6b0ce75788c13d1c3d4786cf1fe2a04",
    "8ddf0751ce13a82ed82a18fbe41ed10a89b9555c", "c6538ac2afd9ca0bdb90c265d276e4cf5e2aba52",
    "63dd44ca3d8a7496f38dcb0ab895fd741302ecd5", "8fa3caca46444367dd751e6dc4a8f98bbcfed999",
    "0e300ab08655178be44253d7d9a62f81582cc628", "e78c0adb2198b178b130f54945e882e2f51cbfa2",
    "49321b0621d92b5058db18d8664cf0331a5df337", "611107374944ac546cfdd7170e04a1990b1c581d",
    "832f50f4e5c6f704665c6584189796e22ff721ba", "79cfffd5406ab30b349ff1568def95fdaec5b5f1",
    "816515f52b897169dda8808eb43440b2782c19af", "14ef412b4c49be9e92ee69451812e907679049ae",
    "976004dc339920556cb157785948f5795822ffbc", "061cce166a1b60dcf9caef290be259b85cd3e083",
    "c1d195b25d0d11cf0a30c7fc4ebbf3b725c2887f", "e9090e2ac6bf7cef046c554e1719c4f8d4a1a5f0",
    "b293ce5d385aa97e567257c27a6e3f8eda60c980", "bd2d95890d06331a5bd1bef0d24593496daebf8b",
    "82d7c299d67329ffbb93abbb316b5ba96712b12f", "b609ae5cf5c04414e96618bda824d764d7fa9b5e",
    "6b2863d735cb5feef00a0de44065093c2d4bdb18", "7f30a550e11637edbc84ecc6796b7e3eee34c9bf",
    "09936aecaccc08450f32529aa5fd2d2242a77087", "621aff2b6515315ebb3e2b6940108964cfb28cf5",
    H62,
]
DIAGNOSTIC_COMMIT_LIST_SHA256 = "9c05fd97c0fd975bf7f076c3ac49d305436b360687e5900dcd1a78ecad852a27"
DIAGNOSTIC_ALIASES = {
    "A39": "a39ab58bc933136539c643b179856fb4ea4071db", "A40": "a1c60a636d32621a7ec97398bc2d90d34b59c7b5",
    "A41": "28ac1b4c7b0f124eaa4fce5e63a8fb1a6c3d3a81", "A42": "61daaee9a7437b617da91bcfeccd292b523e2564",
    "A43": "35cc1d7997521686aff82a5a66c85ccb9e40406c", "A44": "1afbc985edd4a7bf24f9845c400ba80f8eaa5e24",
    "A45": "a885529137e4a6f4548e2482e8c50ad9d846293f", "A46": "a23982bd849380880f6ed691c4ee3c9fd2da0507",
    "A47": "873774f38777a6f2c39ad59c5a9b0097b6112410", "A48": "0b1272b52bfea9cb5005270528e48178c3ab5d97",
    "A49": "258c84dc05c44341b32601805fd1646b49688c56", "A50": "8ddf0751ce13a82ed82a18fbe41ed10a89b9555c",
    "A51": "63dd44ca3d8a7496f38dcb0ab895fd741302ecd5", "A52": "0e300ab08655178be44253d7d9a62f81582cc628",
    "A53": "49321b0621d92b5058db18d8664cf0331a5df337", "A54": "832f50f4e5c6f704665c6584189796e22ff721ba",
    "A55": "816515f52b897169dda8808eb43440b2782c19af", "A56": "976004dc339920556cb157785948f5795822ffbc",
    "A57": "c1d195b25d0d11cf0a30c7fc4ebbf3b725c2887f", "A58": "b293ce5d385aa97e567257c27a6e3f8eda60c980",
    "A59": "bd2d95890d06331a5bd1bef0d24593496daebf8b", "A60": "b609ae5cf5c04414e96618bda824d764d7fa9b5e",
    "A61": "7f30a550e11637edbc84ecc6796b7e3eee34c9bf", "A62": "621aff2b6515315ebb3e2b6940108964cfb28cf5",
}
DIAGNOSTIC_PATH_SHA256 = {
    "tools/lab/assert_data_route.ps1": "7b1e968c96bbb10abc72a75e24b01782f63ad848bbbd110a13e9f9a04d76b570",
    "tools/lab/handoff93/run_product_mapper_cycle.ps1": "46699855502138f8a39cf30bfd0f3f4827a9e02febc79b317218a34924c99027",
    "tools/lab/nat_gateway/test/v92_o01_formal_controller.test.js": "1b18bf47e1f4b2c8ec28636cb0a7612017bda2c649705d67215f1e36acdc7132",
    "tools/lab/nat_gateway/test/v92_o01_t8_daemon.test.js": "18676c00987597a83572d1a919dcc9d05eba352aba33decfbffb35635b1d7d5d",
    "tools/lab/nat_gateway/test/v92_o01_t8_upnp_edge.test.js": "6261096830512e57de87d6503e6b0574a4e0fa053815c2e998f7492d06d3e7a6",
    "tools/lab/nat_gateway/test/v92_o01_validate_formal.test.js": "4c9825afc36184038fd75cde4793e483f9a0512ffeca5149465da3a9e8e09436",
    "tools/lab/nat_gateway/v92_o01_formal_controller.js": "04b323ee22dbc5fa74c7a2c5265c8fd436d00c281ff149881758901897fb199f",
    "tools/lab/nat_gateway/v92_o01_scenario.json": "602874173a0ad69df7da4020f9a8db6ed6f726585c1f3ff983eadd187f74df5d",
    "tools/lab/nat_gateway/v92_o01_soak.js": "dd7474c8135e735a482ab978931318ceb3e5810865cca2693f774da03d756567",
    "tools/lab/nat_gateway/v92_o01_t8_daemon.js": "1daccd7fe0a0c35ccf4e30da9dbd111b3fed2270281c53250940efcd25cfa921",
    "tools/lab/nat_gateway/v92_o01_t8_upnp_edge.js": "61fc600d80865b9a75894cd76929b0dd1261cfab2e0258d37aa5b81d981f2457",
    "tools/lab/nat_gateway/v92_o01_validate_formal.js": "dba5cdc5332ea66959038d81690cccc7b16560c48eea5274aa79f2bd676c41dd",
    "tools/lab/run_v92_o01_formal.ps1": "7a5747433b79ffeec3f370cb041aab3f53920753301b8798758e5c5c606eff38",
    "tools/lab/test_v92_o01_formal_rpc_pump_mock.ps1": "b1202452bec0d6f565d1715e43b9b426929e3e4e71dfd3b79fd068b2f2cda970",
    "tools/lab/test_v92_o01_formal_runner_mock.ps1": "17b537a087c1e833c9bc7ff8ebf0d42979eedc4d4afb2b26202c79f9b670112b",
    "tools/lab/test_v92_o01_vm_session_mock.ps1": "58a4f342caa7df61f189e3a69b62cfcf20605405b3caccc3763f93f46d4c8b9a",
    "tools/lab/v92_o01_vm_session.psm1": "62f264fe0c06e6983539c2594a3c62642ebf650bf75b82dd5c8fb4f5b91b33f8",
}
DIAGNOSTIC_DELTA_MANIFEST_SHA256 = "8dc25e8c8db251cd05f7df67c9fcd78d914a466082772cd727174f0f0cb8a03f"
DIAGNOSTIC_BUDGET = (17, 188, 58, 130)

A_RUNTIME_PATHS = sorted([
    "tools/lab/nat_gateway/v92_o01_formal_controller.js",
    "tools/lab/nat_gateway/v92_o01_formal_host.js",
    "tools/lab/v92_o01_vm_session.psm1",
])
A_TEST_PATHS = sorted([
    "tools/lab/nat_gateway/test/v92_o01_formal_controller.test.js",
    "tools/lab/nat_gateway/test/v92_o01_formal_host.test.js",
    "tools/lab/test_v92_o01_formal_rpc_pump_mock.ps1",
    "tools/lab/test_v92_o01_vm_session_mock.ps1",
])
A_PATHS = sorted(A_RUNTIME_PATHS + A_TEST_PATHS)
A_SHA256 = {
    "tools/lab/nat_gateway/test/v92_o01_formal_controller.test.js": "9ccc8add9081d3623fe48fa3d80aca1b7b5958ca46b1a2048311fee5033f90c0",
    "tools/lab/nat_gateway/test/v92_o01_formal_host.test.js": "17ca5bc0d562d4438bf44b3219b6d942c751545297a0b7f46a2675d564fd05a7",
    "tools/lab/nat_gateway/v92_o01_formal_controller.js": "ce6bb5cb52cf269574c512879fa0bda2db0d1bc8550eff9235662d11ae72c7be",
    "tools/lab/nat_gateway/v92_o01_formal_host.js": "2d2916c5b8cff0bd5ad871b18912f6b9701f420274cf1c43932e78edc29b5e02",
    "tools/lab/test_v92_o01_formal_rpc_pump_mock.ps1": "28bc551c3f1dfe0a8563feffb53e7614b380750e0fe5237a7881a30f83d89153",
    "tools/lab/test_v92_o01_vm_session_mock.ps1": "275e7cff2f1120e3d12278d963af95eb1dba76280ec619fccc912959b1238c28",
    "tools/lab/v92_o01_vm_session.psm1": "1fc8d05581b35a36ed022906b4cb80f4ddca2e07676c0190e158463ac6d73934",
}
PATH_BUDGET = {
    "tools/lab/nat_gateway/test/v92_o01_formal_controller.test.js": (10, 2),
    "tools/lab/nat_gateway/test/v92_o01_formal_host.test.js": (4, 1),
    "tools/lab/nat_gateway/v92_o01_formal_controller.js": (77, 16),
    "tools/lab/nat_gateway/v92_o01_formal_host.js": (19, 2),
    "tools/lab/test_v92_o01_formal_rpc_pump_mock.ps1": (1, 1),
    "tools/lab/test_v92_o01_vm_session_mock.ps1": (1, 1),
    "tools/lab/v92_o01_vm_session.psm1": (2, 2),
}
BUDGET = (7, 114, 25, 89)
RUNTIME_BUDGET = (3, 98, 20, 78)
TEST_BUDGET = (4, 16, 5, 11)

SCENARIO = "tools/lab/nat_gateway/v92_o01_scenario.json"
SCENARIO_SHA256 = "602874173a0ad69df7da4020f9a8db6ed6f726585c1f3ff983eadd187f74df5d"
SCENARIO_BLOB = "720a1359ebdab210f7a670963fb721fc2b8b878f"
PRODUCT_MAPPER = "tools/lab/handoff93/run_product_mapper_cycle.ps1"
PRODUCT_MAPPER_SHA256 = "46699855502138f8a39cf30bfd0f3f4827a9e02febc79b317218a34924c99027"
PRODUCT_MAPPER_BLOB = "bf2494f1b61a27ca0e2af5e4d0197d2137cb06d6"
MAPPER_THRESHOLD_GUARD = b"[int64]$scenario.limits.checkpoint_max_gap_ms -ne 370000"
BOUND_FILES = [
    "tools/lab/handoff93/run_product_mapper_cycle.ps1",
    "tools/lab/nat_gateway/v92_o01_product_stream.js",
    "tools/lab/nat_gateway/v92_o01_formal_controller.js",
    "tools/lab/nat_gateway/v92_o01_validate_formal.js",
    "tools/lab/nat_gateway/v92_o01_scenario.json",
    "tools/lab/nat_gateway/v92_o01_soak.js",
    "tools/lab/nat_gateway/v92_o01_t8_child.js",
    "tools/lab/nat_gateway/v92_o01_t8_daemon.js",
    "tools/lab/nat_gateway/v92_o01_bridge_protocol.js",
    "tools/lab/nat_gateway/v92_o01_t8_network_adapter.js",
    "tools/lab/nat_gateway/v92_o01_t8_gateway_adapter.js",
    "tools/lab/nat_gateway/v92_o01_t8_udp_mux.js",
    "tools/lab/nat_gateway/v92_o01_t8_upnp_edge.js",
    "tools/lab/nat_gateway/v92_o01_t8_fault_controller.js",
    "tools/lab/nat_gateway/v92_o01_formal_host.js",
    "tools/lab/nat_gateway/v92_o01_formal_rpc.js",
    "tools/lab/run_v92_o01_formal.ps1",
    "tools/lab/v92_o01_vm_session.psm1",
    "tools/lab/t8_hyperv.ps1",
    "tools/lab/common.ps1",
    "tools/lab/v91_r01_upnp.ps1",
]

H_PATHS = [
    "artifacts/v92-o01-governance/activation.json",
    "artifacts/v92-o01-governance/offline-summary.json",
    "artifacts/v92-o01-governance/review-sol.json",
    "artifacts/v92-o01-governance/review-terra.json",
]
OFFLINE = [
    ("Node 22 complete nat_gateway suite", "npm.cmd test", "O01_A63_NODE_SUITE_PASS"),
    ("A63 controller and host focal suite", "node --test A63 controller and host tests", "O01_A63_FOCAL_PASS"),
    ("PowerShell parser for changed ps1 and psm1", "powershell parser A63 PowerShell paths", "O01_A63_POWERSHELL_PARSE_PASS"),
    ("formal RPC VM session and runner mocks", "powershell A63 formal mocks", "O01_A63_FORMAL_MOCKS_PASS"),
    ("G11 hostile governance suite", "python -B tools/architecture/test_verify_v92_o01_clock_repair_governance.py", "O01_G11_GOVERNANCE_PASS"),
    ("exact A63 byte and budget verifier", "python -B tools/architecture/verify_v92_o01_clock_repair_governance.py --verify", "O01_A63_BINDING_PASS"),
    ("official full Release x64 rebuild from clean A63", "powershell -File tools/build_all.ps1 -ReleaseTag v0.70b-eSE9.2.0-rc.1", "O01_A63_RELEASE_BUILD_PASS"),
    ("M63 MOD02 verifier and runtime reseal", "verify M63 MOD02 artifacts", "O01_M63_MOD02_RESEAL_PASS"),
    ("git diff --check", "git diff --check", "O01_A63_DIFF_CHECK_PASS"),
]
RELEASE_TAG = "v0.70b-eSE9.2.0-rc.1"
RELEASE_FINGERPRINT = "3E1B51DCE2A83DF5DDA10697385FD8C7F05D8C81EB391B967D30E0CD6761ED23"
MOD02_IDENTITY = "b9c3c25fece8a80d71eee340e61d8cd5088b95f8b12e221278d9d249f6d29c9d"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def sh(*args: str) -> str:
    return subprocess.run(
        args, cwd=ROOT, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    ).stdout.decode().strip()


def git(*args: str) -> str:
    return sh("git", *args)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def load_bytes(data: bytes) -> object:
    return json.loads(data.decode("utf-8-sig"))


def load() -> dict:
    return json.loads(DOC_PATH.read_text(encoding="utf-8"))


def exact(value: object, keys: set[str], where: str) -> dict:
    if not isinstance(value, dict) or set(value) != keys:
        raise GateError(f"{where} schema")
    return value


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


def observed_budget(stats: dict[str, tuple[int, int]], paths: list[str] | None = None) -> tuple[int, int, int, int]:
    selected = paths if paths is not None else sorted(stats)
    additions = sum(stats[path][0] for path in selected)
    deletions = sum(stats[path][1] for path in selected)
    return len(selected), additions, deletions, additions - deletions


def path_budget_document() -> dict[str, dict[str, int]]:
    return {
        path: {"add": values[0], "delete": values[1], "net": values[0] - values[1]}
        for path, values in sorted(PATH_BUDGET.items())
    }


def a_paths_sha256() -> str:
    return sha(canonical(A_PATHS))


def a_bytes_sha256() -> str:
    return sha(canonical(A_SHA256))


def a_budget_sha256() -> str:
    return sha(canonical(path_budget_document()))


def m_paths(a_commit: str) -> list[str]:
    return sorted([
        "docs/architecture/mod02_build_manifest_v1.json",
        "docs/architecture/mod02_characterization_matrix_v1.json",
        f"artifacts/mod02-runtime-v92-{a_commit[:8]}/summary.json",
        f"artifacts/v92-o01-release-build-{a_commit[:8]}/emule-release-build.json",
    ])


def r_paths() -> list[str]:
    return sorted([
        *[f"artifacts/v92-o01-formal/checkpoint-{index:02d}.json" for index in range(1, 96)],
        "artifacts/v92-o01-formal/controller-result.json",
        "artifacts/v92-o01-formal/formal-run-result.json",
        "artifacts/v92-o01-formal/formal-validation.json",
    ])


def expected_document() -> dict:
    return {
        "schema": "ese.v92.o01-clock-repair-governance/v1",
        "status": "DRAFT_PRE_G11",
        "base": {
            "h37_commit": H37, "h37_tree": H37_TREE,
            "g10_commit": G10, "g10_tree": G10_TREE,
            "a38_commit": A38, "a38_tree": A38_TREE,
            "m38_commit": M38, "m38_tree": M38_TREE,
            "h38_commit": H38, "h38_tree": H38_TREE,
            "h62_commit": H62, "h62_tree": H62_TREE,
        },
        "historical_contract": {
            "governance_sha256": HISTORICAL_GOV_SHA256,
            "verified_at_commits": [H38, H62],
            "rule": "G10/A38/M38/H38 and every historical governance blob remain byte-exact; G11 does not amend them.",
        },
        "diagnostic_epoch": {
            "classification": "NON_RELEASE_DIAGNOSTIC_ONLY",
            "release_gate": False,
            "evidence_reuse": "FORBIDDEN",
            "candidate_aliases": DIAGNOSTIC_ALIASES,
            "first_parent_commits": DIAGNOSTIC_COMMITS,
            "commit_count": len(DIAGNOSTIC_COMMITS),
            "commit_list_sha256": DIAGNOSTIC_COMMIT_LIST_SHA256,
            "cumulative_paths": sorted(DIAGNOSTIC_PATH_SHA256),
            "cumulative_path_sha256": DIAGNOSTIC_PATH_SHA256,
            "cumulative_delta_manifest_sha256": DIAGNOSTIC_DELTA_MANIFEST_SHA256,
            "cumulative_budget": {
                "path_count": DIAGNOSTIC_BUDGET[0], "add_exact": DIAGNOSTIC_BUDGET[1],
                "delete_exact": DIAGNOSTIC_BUDGET[2], "net_exact": DIAGNOSTIC_BUDGET[3],
            },
            "rule": "A39 through A62, their authorization commits, partial checkpoints and failures are diagnostics only and can never enter R63.",
        },
        "scope": "V92-O01 rc.1 only: classify clock failures without weakening the frozen 70000 ms scheduling bound, persist one closed diagnostic artifact on failure, align the RPC watchdog to 140000 ms, rebuild from A63, reseal MOD02, and admit release only through a new uninterrupted direct-R63 PASS.",
        "topology": {
            "G11": "direct child of H62; exactly this amendment, verifier and hostile verifier test",
            "A63": "direct child of G11; exactly seven frozen functional paths at exact byte and per-path numstat identities",
            "M63": "direct child of A63; exactly four carriers from one fresh official full Release build and MOD02 reseal",
            "H63": "direct child of M63; exactly four governance carriers with two independent empty-finding approvals",
            "R63": "direct child of H63; exactly 98 PASS artifacts from one uninterrupted eight-hour run sourced from A63 and the M63 executable",
        },
        "phase_contract": {
            "schema": "ese.v92.o01-clock-repair-phases/v1",
            "merge_policy": "Every G11/A63/M63/H63/R63 commit has exactly one parent; merges, squash/rebase substitution, intermediate commits, S, resume and reused evidence are rejected.",
            "G11": {"parent": "H62", "delta": "governance_paths"},
            "A63": {"parent": "G11", "delta": "functional_paths"},
            "M63": {"parent": "A63", "delta": "m_carrier_paths", "build": "fresh official full Release rebuild from clean A63"},
            "H63": {"parent": "M63", "delta": "h_carrier_paths"},
            "R63": {"parent": "H63", "source": "A63", "governance": "H63", "executable": "exact_M63_manifest_executable_sha256", "release_gate": True},
        },
        "governance_paths": GOV,
        "functional_paths": {
            "runtime": A_RUNTIME_PATHS,
            "tests": A_TEST_PATHS,
            "all": A_PATHS,
            "path_count": len(A_PATHS),
            "sha256": A_SHA256,
            "paths_sha256": a_paths_sha256(),
            "byte_identity_sha256": a_bytes_sha256(),
        },
        "immutable_contract": {
            "scenario_path": SCENARIO,
            "scenario_blob": SCENARIO_BLOB,
            "scenario_sha256": SCENARIO_SHA256,
            "product_mapper_path": PRODUCT_MAPPER,
            "product_mapper_blob": PRODUCT_MAPPER_BLOB,
            "product_mapper_sha256": PRODUCT_MAPPER_SHA256,
            "formal_duration_ms": 28800000,
            "tick_ms": 10000,
            "checkpoint_ms": 300000,
            "checkpoint_max_gap_ms": 370000,
            "controller_schedule_jitter_ms": 70000,
            "product_stream_max_gap_ms": 70000,
            "subsequent_rpc_watchdog_ms": 140000,
            "bound_files_count": 21,
            "clock_codes": [
                "O01_CONTROLLER_CLOCK_INVALID", "O01_CONTROLLER_CLOCK_NONMONOTONIC",
                "O01_CONTROLLER_CLOCK_CHECKPOINT_GAP", "O01_CONTROLLER_CLOCK_INTERTICK_GAP",
            ],
            "early_wake_rule": "sleep again until the same absolute target; never turn an early wake into PASS evidence or a false failure",
            "failure_artifact": "clock-failure.json is exclusive, structured, integer-only diagnostic evidence and is forbidden from PASS/R63",
        },
        "budget": {
            "path_count": BUDGET[0], "add_exact": BUDGET[1], "delete_exact": BUDGET[2],
            "net_exact": BUDGET[3], "headroom": 0,
            "runtime": {"path_count": RUNTIME_BUDGET[0], "add_exact": RUNTIME_BUDGET[1], "delete_exact": RUNTIME_BUDGET[2], "net_exact": RUNTIME_BUDGET[3]},
            "tests": {"path_count": TEST_BUDGET[0], "add_exact": TEST_BUDGET[1], "delete_exact": TEST_BUDGET[2], "net_exact": TEST_BUDGET[3]},
            "path_budget": path_budget_document(),
            "path_budget_sha256": a_budget_sha256(),
        },
        "carrier_paths": {
            "M63": {
                "fixed": ["docs/architecture/mod02_build_manifest_v1.json", "docs/architecture/mod02_characterization_matrix_v1.json"],
                "summary_pattern": "artifacts/mod02-runtime-v92-<A63[0:8]>/summary.json",
                "release_build_receipt_pattern": "artifacts/v92-o01-release-build-<A63[0:8]>/emule-release-build.json",
                "file_count": 4,
            },
            "H63": H_PATHS,
            "R63": {
                "directory": "artifacts/v92-o01-formal",
                "checkpoint_pattern": "checkpoint-(01..95).json",
                "fixed": ["controller-result.json", "formal-run-result.json", "formal-validation.json"],
                "forbidden": ["clock-failure.json", "failure.json"],
                "file_count": 98,
            },
        },
        "required_reviews": ["Terra APPROVE with findings=[]", "Sol APPROVE with findings=[]"],
        "offline_gates": [name for name, _, _ in OFFLINE],
        "physical_policy": {
            "formal": "Exactly 28800000 monotonic milliseconds, 2880 ten-second ticks, 96 five-minute fault slots, 480 product samples and 95 checkpoints; no duration override, resume, skip-cleanup or threshold increase.",
            "failure": "Any clock subcode remains release_gate=false; its structured clock-failure artifact is diagnostic only and the next attempt starts from a new empty evidence root.",
            "claim_rule": "Only independently validated direct-R63 evidence with exact cleanup and baseline restoration may award V92-O01 PASS.",
        },
        "stop_conditions": [
            "any A63 path outside the exact seven-path slice",
            "any A63 byte identity or per-path numstat differs by one byte or line",
            "scenario, mapper, 370000 ms checkpoint gap, derived 70000 ms scheduler bound or 21 bound_files changes",
            "the 90000 ms watchdog is retained, 140000 ms becomes configurable in the formal path, or any watchdog is unbounded",
            "clock-failure.json is overwritten, contains an open/free-form field, appears on PASS, or enters R63",
            "any A39-A62 artifact, checkpoint or failure is reused for M63, H63 or R63",
            "G11 is not the direct child of H62 or the frozen H38-H62 first-parent chain differs",
            "M63 is not one fresh clean official full Release build bound to A63 and exact MOD02 identity",
            "source, Node, package, M63/H63 binding or evidence root changes during the run",
            "P0, P1, P2 or any nonempty review finding",
            "release_gate=true before independent validation and exact baseline restoration",
        ],
        "activation_state": {
            "G11": None, "A63": None, "M63": None, "H63": None, "R63": None,
            "rule": "The document never stores its own commit; later carriers derive phase identities from exact Git parentage.",
        },
    }


def validate_document(value: dict) -> bool:
    exact(value, set(expected_document()), "root")
    if value != expected_document():
        raise GateError("document exact contract")
    if len(GOV) != 3 or len(A_PATHS) != 7 or set(A_RUNTIME_PATHS) & set(A_TEST_PATHS):
        raise GateError("closed slices")
    if set(A_SHA256) != set(A_PATHS) or set(PATH_BUDGET) != set(A_PATHS):
        raise GateError("A63 pin coverage")
    if observed_budget(PATH_BUDGET) != BUDGET or observed_budget(PATH_BUDGET, A_RUNTIME_PATHS) != RUNTIME_BUDGET or observed_budget(PATH_BUDGET, A_TEST_PATHS) != TEST_BUDGET:
        raise GateError("A63 frozen budget")
    if len(DIAGNOSTIC_COMMITS) != 47 or DIAGNOSTIC_COMMITS[-1] != H62:
        raise GateError("diagnostic commit set")
    if sha(("\n".join(DIAGNOSTIC_COMMITS) + "\n").encode()) != DIAGNOSTIC_COMMIT_LIST_SHA256:
        raise GateError("diagnostic commit-list identity")
    return True


def import_old_verifier():
    path = ROOT / OLD_VERIFIER
    spec = importlib.util.spec_from_file_location("o01_historical_g10", path)
    if spec is None or spec.loader is None:
        raise GateError("historical verifier import")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify_historical_h38() -> None:
    topology = [(H37, None, H37_TREE), (G10, H37, G10_TREE), (A38, G10, A38_TREE), (M38, A38, M38_TREE), (H38, M38, H38_TREE)]
    for commit, parent, tree in topology:
        if parent is not None:
            require_single_parent(commit, parent, "historical H38")
        if git("rev-parse", f"{commit}^{{tree}}") != tree:
            raise GateError("historical H38 tree")
    if git("rev-parse", f"{H62}^{{tree}}") != H62_TREE:
        raise GateError("H62 tree")
    for at in (H38, H62):
        observed = {path: sha(blob(at, path)) for path in HISTORICAL_GOV_SHA256}
        if observed != HISTORICAL_GOV_SHA256:
            raise GateError(f"historical governance identity at {at[:8]}")
    current = {path: sha((ROOT / path).read_bytes()) for path in HISTORICAL_GOV_SHA256}
    if current != HISTORICAL_GOV_SHA256:
        raise GateError("historical governance worktree identity")
    old = import_old_verifier()
    old.verify_predecessor()
    document = load_bytes(blob(G10, old.DOC))
    old.validate(document)
    if changed(old.PRED_H, G10) != sorted(old.GOV) or changed(G10, A38) != old.A_PATHS:
        raise GateError("historical G10/A38 delta")
    if changed(A38, M38) != old.m_paths(A38) or changed(M38, H38) != sorted(old.H_PATHS):
        raise GateError("historical M38/H38 delta")
    old.verify_a_hashes(lambda path: blob(A38, path), "historical A38")
    old.verify_scenario(blob(A38, old.SCENARIO), "historical A38")
    old.verify_product_mapper(blob(A38, old.PRODUCT_MAPPER), "historical A38")
    manifest = load_bytes(blob(M38, old.M_MANIFEST))
    if not isinstance(manifest, dict) or manifest.get("source_commit") != A38 or manifest.get("source_identity_sha256") != MOD02_IDENTITY or not HEX64.fullmatch(str(manifest.get("executable_sha256", ""))):
        raise GateError("historical M38 manifest")
    executable = manifest["executable_sha256"]
    receipt = load_bytes(blob(M38, old.release_receipt_path(A38)))
    if not isinstance(receipt, dict) or receipt.get("commit") != A38 or receipt.get("releaseTag") != RELEASE_TAG or receipt.get("sourceFingerprint") != RELEASE_FINGERPRINT or receipt.get("binarySha256") != executable.upper():
        raise GateError("historical M38 receipt")
    activation = load_bytes(blob(H38, old.H_PATHS[0]))
    if not isinstance(activation, dict) or activation.get("g_commit") != G10 or activation.get("a_commit") != A38 or activation.get("m_commit") != M38:
        raise GateError("historical H38 activation")
    for role, path in (("Sol", old.H_PATHS[2]), ("Terra", old.H_PATHS[3])):
        review = load_bytes(blob(H38, path))
        if not isinstance(review, dict) or review.get("role") != role or review.get("reviewed_commit") != A38 or review.get("verdict") != "APPROVE" or review.get("findings") != []:
            raise GateError("historical H38 review")


def diagnostic_manifest() -> list[dict[str, object]]:
    stats: dict[str, tuple[int, int]] = {}
    for line in git("diff", "--numstat", H38, H62, "--").splitlines():
        added, deleted, path = line.split("\t", 2)
        if not added.isdigit() or not deleted.isdigit():
            raise GateError("diagnostic binary delta")
        stats[path] = (int(added), int(deleted))
    records = []
    for path in sorted(stats):
        raw = blob(H62, path)
        records.append({
            "path": path, "add": stats[path][0], "delete": stats[path][1],
            "h38_blob": git("rev-parse", f"{H38}:{path}"),
            "h62_blob": git("rev-parse", f"{H62}:{path}"),
            "h62_sha256": sha(raw),
        })
    return records


def verify_scenario(raw: bytes, where: str, expected_sha: str = SCENARIO_SHA256) -> None:
    if sha(raw) != expected_sha:
        raise GateError(f"{where} scenario identity")
    value = load_bytes(raw)
    exact_values = {
        "formal_duration_ms": 28800000, "tick_ms": 10000, "fault_slot_ms": 300000,
        "lease_ms": 120000, "late_delay_ms": 8000, "checkpoint_ms": 300000,
        "sample_ms": 60000, "node_major": 22,
    }
    if not isinstance(value, dict) or any(type(value.get(key)) is not int or value[key] != expected for key, expected in exact_values.items()):
        raise GateError(f"{where} scenario timing")
    limits = value.get("limits")
    if not isinstance(limits, dict) or type(limits.get("checkpoint_max_gap_ms")) is not int or limits["checkpoint_max_gap_ms"] != 370000 or type(limits.get("sockets")) is not int or limits["sockets"] != 2:
        raise GateError(f"{where} scenario limits")
    if value.get("bound_files") != BOUND_FILES or len(value["bound_files"]) != 21:
        raise GateError(f"{where} scenario bound files")
    if limits["checkpoint_max_gap_ms"] - value["checkpoint_ms"] != 70000:
        raise GateError(f"{where} scheduler bound")


def verify_mapper(raw: bytes, where: str, expected_sha: str = PRODUCT_MAPPER_SHA256) -> None:
    if sha(raw) != expected_sha:
        raise GateError(f"{where} mapper identity")
    if raw.count(MAPPER_THRESHOLD_GUARD) != 1:
        raise GateError(f"{where} mapper threshold")


def verify_diagnostic_epoch() -> None:
    commits = git("rev-list", "--first-parent", "--reverse", f"{H38}..{H62}").splitlines()
    if commits != DIAGNOSTIC_COMMITS:
        raise GateError("diagnostic first-parent chain")
    previous = H38
    for commit in commits:
        require_single_parent(commit, previous, "diagnostic chain")
        previous = commit
    if sha(("\n".join(commits) + "\n").encode()) != DIAGNOSTIC_COMMIT_LIST_SHA256:
        raise GateError("diagnostic commit-list hash")
    manifest = diagnostic_manifest()
    if sorted(record["path"] for record in manifest) != sorted(DIAGNOSTIC_PATH_SHA256):
        raise GateError("diagnostic path set")
    if observed_budget({record["path"]: (record["add"], record["delete"]) for record in manifest}) != DIAGNOSTIC_BUDGET:
        raise GateError("diagnostic cumulative budget")
    if sha(canonical(manifest)) != DIAGNOSTIC_DELTA_MANIFEST_SHA256:
        raise GateError("diagnostic delta identity")
    observed_sha = {record["path"]: record["h62_sha256"] for record in manifest}
    if observed_sha != DIAGNOSTIC_PATH_SHA256:
        raise GateError("diagnostic path identity")
    if any(commit not in commits for commit in DIAGNOSTIC_ALIASES.values()):
        raise GateError("diagnostic alias identity")
    scenario = blob(H62, SCENARIO)
    mapper = blob(H62, PRODUCT_MAPPER)
    if git("rev-parse", f"{H62}:{SCENARIO}") != SCENARIO_BLOB or git("rev-parse", f"{H62}:{PRODUCT_MAPPER}") != PRODUCT_MAPPER_BLOB:
        raise GateError("immutable blob identity")
    verify_scenario(scenario, "H62")
    verify_mapper(mapper, "H62")


def validate_budget(stats: dict[str, tuple[int, int]], where: str) -> None:
    if sorted(stats) != A_PATHS:
        raise GateError(f"{where} allowlist")
    if stats != PATH_BUDGET or observed_budget(stats) != BUDGET:
        raise GateError(f"{where} path budget")
    if observed_budget(stats, A_RUNTIME_PATHS) != RUNTIME_BUDGET or observed_budget(stats, A_TEST_PATHS) != TEST_BUDGET:
        raise GateError(f"{where} slice budget")


def verify_a_hashes(reader, where: str) -> None:
    observed = {path: sha(reader(path)) for path in A_PATHS}
    if observed != A_SHA256:
        raise GateError(f"{where} byte identity")


def commit_stats(parent: str, commit: str) -> dict[str, tuple[int, int]]:
    stats = {}
    for line in git("diff", "--numstat", parent, commit, "--").splitlines():
        added, deleted, path = line.split("\t", 2)
        if not added.isdigit() or not deleted.isdigit():
            raise GateError("A63 binary payload")
        stats[path] = (int(added), int(deleted))
    return stats


def collect_worktree_stats() -> tuple[dict[str, tuple[int, int]], list[str]]:
    stats = {}
    for line in git("diff", "HEAD", "--numstat", "--").splitlines():
        added, deleted, path = line.split("\t", 2)
        if not added.isdigit() or not deleted.isdigit():
            raise GateError("worktree binary payload")
        if path not in GOV:
            stats[path] = (int(added), int(deleted))
    other_untracked = []
    for path in filter(None, git("ls-files", "--others", "--exclude-standard").splitlines()):
        if path in GOV:
            continue
        other_untracked.append(path)
        raw = (ROOT / path).read_bytes()
        stats[path] = (raw.count(b"\n") + int(bool(raw) and not raw.endswith(b"\n")), 0)
    return stats, sorted(other_untracked)


def worktree_stats() -> bool:
    if git("rev-parse", "HEAD") != H62:
        raise GateError("worktree base")
    stats, _ = collect_worktree_stats()
    validate_budget(stats, "worktree")
    verify_a_hashes(lambda path: (ROOT / path).read_bytes(), "worktree A63")
    verify_scenario((ROOT / SCENARIO).read_bytes(), "worktree")
    verify_mapper((ROOT / PRODUCT_MAPPER).read_bytes(), "worktree")
    return True


def verify_g(g_commit: str, document: dict) -> None:
    require_single_parent(g_commit, H62, "G11")
    if changed(H62, g_commit) != GOV:
        raise GateError("G11 delta")
    if load_bytes(blob(g_commit, DOC)) != document:
        raise GateError("G11 document")
    for path in GOV:
        if blob(g_commit, path) != (ROOT / path).read_bytes():
            raise GateError("G11 governance identity")


def verify_a(a_commit: str, g_commit: str) -> None:
    require_single_parent(a_commit, g_commit, "A63")
    if changed(g_commit, a_commit) != A_PATHS:
        raise GateError("A63 delta")
    validate_budget(commit_stats(g_commit, a_commit), "A63")
    verify_a_hashes(lambda path: blob(a_commit, path), "A63")
    verify_scenario(blob(a_commit, SCENARIO), "A63")
    verify_mapper(blob(a_commit, PRODUCT_MAPPER), "A63")


def verify_m(m_commit: str, a_commit: str) -> None:
    require_single_parent(m_commit, a_commit, "M63")
    if changed(a_commit, m_commit) != m_paths(a_commit):
        raise GateError("M63 delta")
    old = import_old_verifier()
    old.verify_m(m_commit, a_commit)


def validate_review(raw: bytes, role: str, a_commit: str, a_tree: str) -> None:
    value = exact(load_bytes(raw), {"schema", "role", "reviewed_commit", "reviewed_tree", "verdict", "findings"}, f"{role} review")
    if value != {
        "schema": "ese.v92.o01-review/v1", "role": role,
        "reviewed_commit": a_commit, "reviewed_tree": a_tree,
        "verdict": "APPROVE", "findings": [],
    }:
        raise GateError(f"{role} review")


def expected_gate_records() -> list[dict[str, object]]:
    records = []
    for name, command, marker in OFFLINE:
        body = [marker]
        records.append({
            "name": name, "command": command, "exit_code": 0, "marker": marker,
            "body": body, "body_sha256": sha(canonical(body)),
        })
    return records


def verify_h(h_commit: str, m_commit: str, a_commit: str, g_commit: str) -> None:
    require_single_parent(h_commit, m_commit, "H63")
    if changed(m_commit, h_commit) != sorted(H_PATHS):
        raise GateError("H63 delta")
    a_tree = git("rev-parse", f"{a_commit}^{{tree}}")
    m_tree = git("rev-parse", f"{m_commit}^{{tree}}")
    reviews = {
        "Sol": blob(h_commit, H_PATHS[2]),
        "Terra": blob(h_commit, H_PATHS[3]),
    }
    for role, raw in reviews.items():
        validate_review(raw, role, a_commit, a_tree)
    offline_raw = blob(h_commit, H_PATHS[1])
    offline = exact(load_bytes(offline_raw), {
        "schema", "source_commit", "source_tree", "m_commit", "m_tree",
        "amendment_sha256", "gates",
    }, "H63 offline summary")
    amendment_sha = sha(blob(g_commit, DOC))
    if offline != {
        "schema": "ese.v92.o01-clock-repair-offline-summary/v1",
        "source_commit": a_commit, "source_tree": a_tree,
        "m_commit": m_commit, "m_tree": m_tree,
        "amendment_sha256": amendment_sha,
        "gates": expected_gate_records(),
    }:
        raise GateError("H63 offline summary")
    activation = exact(load_bytes(blob(h_commit, H_PATHS[0])), {
        "schema", "predecessor_h_commit", "historical_h38_commit", "g_commit",
        "a_commit", "a_tree", "m_commit", "m_tree", "amendment_sha256",
        "diagnostic_commit_list_sha256", "diagnostic_delta_manifest_sha256",
        "a63_paths_sha256", "a63_byte_identity_sha256", "a63_budget_sha256",
        "scenario_sha256", "product_mapper_sha256", "artifact_sha256",
    }, "H63 activation")
    artifact_hashes = {
        H_PATHS[1]: sha(offline_raw), H_PATHS[2]: sha(reviews["Sol"]), H_PATHS[3]: sha(reviews["Terra"]),
    }
    expected_activation = {
        "schema": "ese.v92.o01-clock-repair-activation/v1",
        "predecessor_h_commit": H62, "historical_h38_commit": H38,
        "g_commit": g_commit, "a_commit": a_commit, "a_tree": a_tree,
        "m_commit": m_commit, "m_tree": m_tree, "amendment_sha256": amendment_sha,
        "diagnostic_commit_list_sha256": DIAGNOSTIC_COMMIT_LIST_SHA256,
        "diagnostic_delta_manifest_sha256": DIAGNOSTIC_DELTA_MANIFEST_SHA256,
        "a63_paths_sha256": a_paths_sha256(), "a63_byte_identity_sha256": a_bytes_sha256(),
        "a63_budget_sha256": a_budget_sha256(), "scenario_sha256": SCENARIO_SHA256,
        "product_mapper_sha256": PRODUCT_MAPPER_SHA256, "artifact_sha256": artifact_hashes,
    }
    if activation != expected_activation:
        raise GateError("H63 activation")


def verify_r(r_commit: str, h_commit: str, a_commit: str, m_commit: str) -> None:
    require_single_parent(r_commit, h_commit, "R63")
    observed = changed(h_commit, r_commit)
    if observed != r_paths() or any(path.endswith("clock-failure.json") or path.endswith("failure.json") for path in observed):
        raise GateError("R63 artifact set")
    old = import_old_verifier()
    old.verify_r(r_commit, h_commit, a_commit, m_commit)


def autodetect(document: dict) -> str:
    head = git("rev-parse", "HEAD")
    if head == H62:
        worktree_stats()
        return "DRAFT_WORKTREE"
    chain = []
    current = head
    while current != H62 and len(chain) < 7:
        chain.append(current)
        current_parents = parents(current)
        if len(current_parents) != 1:
            raise GateError("merge topology")
        current = current_parents[0]
    if current != H62:
        raise GateError("H62 ancestry")
    chain.reverse()
    if not chain:
        raise GateError("missing G11")
    g_commit = chain[0]
    verify_g(g_commit, document)
    if len(chain) == 1:
        return "G11"
    a_commit = chain[1]
    verify_a(a_commit, g_commit)
    if len(chain) == 2:
        return "A63"
    m_commit = chain[2]
    verify_m(m_commit, a_commit)
    if len(chain) == 3:
        return "M63"
    h_commit = chain[3]
    verify_h(h_commit, m_commit, a_commit, g_commit)
    if len(chain) == 4:
        return "H63"
    if len(chain) != 5:
        raise GateError("intermediate before R63")
    verify_r(chain[4], h_commit, a_commit, m_commit)
    return "R63"


def main() -> int:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--check-worktree", action="store_true")
    group.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    try:
        document = load()
        validate_document(document)
        verify_historical_h38()
        verify_diagnostic_epoch()
        if args.verify and git("status", "--porcelain", "--untracked-files=all"):
            raise GateError("verification worktree dirty")
        if args.verify:
            state = autodetect(document)
        elif args.check_worktree:
            worktree_stats()
            state = "DRAFT_WORKTREE"
        else:
            state = "DOCUMENT"
    except Exception as exc:
        if not isinstance(exc, (GateError, ValueError, OSError, subprocess.SubprocessError, json.JSONDecodeError)):
            raise
        print(f"V92_O01_CLOCK_REPAIR_GOVERNANCE_FAIL {exc}", file=sys.stderr)
        return 1
    print(
        "V92_O01_CLOCK_REPAIR_GOVERNANCE_PASS "
        f"state={state} paths={BUDGET[0]} add={BUDGET[1]} delete={BUDGET[2]} net={BUDGET[3]} "
        f"diagnostic_commits={len(DIAGNOSTIC_COMMITS)} diagnostic_paths={DIAGNOSTIC_BUDGET[0]}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
