from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DOC = "docs/architecture/v92_o01_physical_repair_governance_v1.json"
DOC_PATH = ROOT / DOC

H36 = "db2ddfd42768ae9f7311ca5f8f0c618a3484f5a3"
H36_TREE = "c381830c43f2a2d7b94dea1bd0afa125959aface"
G9 = "baa6f59198a96c4c801451e4fcb8052489345724"
G9_TREE = "58ce07f127f589843cba13c7361e434dcc1dae6f"
A37 = "480b0c58a48fda23d979313715de1e0605d6ba16"
A37_TREE = "682e3bdd5dc68751f2e4325c96c7eb697e6d6d89"
M37 = "dbf99e6a5837e12bf3fa506d42778b76c4162e90"
M37_TREE = "568cceb6e3e6221943be705bf76bc27947ca5f84"
PRED_H = "e3ff85f2f710f25dbd98d8f9be059a5b2aee955d"
PRED_H_TREE = "999b81fa83ee7e13caee4c65146b599e0c9c0c4c"

GOV = [
    DOC,
    "tools/architecture/verify_v92_o01_physical_repair_governance.py",
    "tools/architecture/test_verify_v92_o01_physical_repair_governance.py",
]
HISTORICAL_GOV = [
    "docs/architecture/v92_o01_mapper_hotfix_governance_v1.json",
    "tools/architecture/verify_v92_o01_mapper_hotfix_governance.py",
    "tools/architecture/test_verify_v92_o01_mapper_hotfix_governance.py",
]
HISTORICAL_GOV_SHA256 = {
    HISTORICAL_GOV[0]: "f74ac5518135593e1bb8f9dea42f301112310ec02cf7546efbb5156fc8808c8d",
    HISTORICAL_GOV[1]: "5ad3350ab9a973ff575e837332a54f68fa98bf305e25813cffa6deb5f7d85343",
    HISTORICAL_GOV[2]: "0f9ea17a7fe1ebbeb0f66915e35c68a456fd67cfe1b4b27bbed2b636d4f1f0d3",
}

RUNTIME_PATHS = [
    "tools/lab/handoff93/run_product_mapper_cycle.ps1",
    "tools/lab/nat_gateway/v92_o01_bridge_protocol.js",
    "tools/lab/nat_gateway/v92_o01_formal_controller.js",
    "tools/lab/nat_gateway/v92_o01_scenario.json",
    "tools/lab/nat_gateway/v92_o01_soak.js",
    "tools/lab/nat_gateway/v92_o01_t8_daemon.js",
    "tools/lab/nat_gateway/v92_o01_t8_child.js",
    "tools/lab/nat_gateway/v92_o01_t8_fault_controller.js",
    "tools/lab/nat_gateway/v92_o01_t8_gateway_adapter.js",
    "tools/lab/nat_gateway/v92_o01_t8_network_adapter.js",
    "tools/lab/nat_gateway/v92_o01_t8_udp_mux.js",
    "tools/lab/nat_gateway/v92_o01_validate_formal.js",
    "tools/lab/run_v92_o01_formal.ps1",
    "tools/lab/v92_o01_vm_session.psm1",
]
TEST_PATHS = [
    "tools/lab/handoff93/test_product_mapper_formal_soak_mock.ps1",
    "tools/lab/nat_gateway/test/v92_o01_bridge_protocol.test.js",
    "tools/lab/nat_gateway/test/v92_o01_formal_controller.test.js",
    "tools/lab/nat_gateway/test/v92_o01_soak.test.js",
    "tools/lab/nat_gateway/test/v92_o01_t8_daemon.test.js",
    "tools/lab/nat_gateway/test/v92_o01_t8_child.test.js",
    "tools/lab/nat_gateway/test/v92_o01_t8_fault_controller.test.js",
    "tools/lab/nat_gateway/test/v92_o01_t8_gateway_adapter.test.js",
    "tools/lab/nat_gateway/test/v92_o01_t8_network_adapter.test.js",
    "tools/lab/nat_gateway/test/v92_o01_t8_udp_mux.test.js",
    "tools/lab/nat_gateway/test/v92_o01_validate_formal.test.js",
    "tools/lab/test_v92_o01_formal_runner_mock.ps1",
    "tools/lab/test_v92_o01_formal_rpc_pump_mock.ps1",
    "tools/lab/test_v92_o01_vm_session_mock.ps1",
]
DOC_PATHS = [
    "docs/RELEASE_NOTES_v9.2.0-rc.1.md",
    "docs/V92_RC1_EXECUTION.md",
]
A_PATHS = sorted(RUNTIME_PATHS + TEST_PATHS + DOC_PATHS)

# These pins are regenerated only after the A38 payload is frozen.  They are
# deliberately byte identities, not semantic hashes.
A_SHA256 = {
    "tools/lab/handoff93/run_product_mapper_cycle.ps1": "700b62b79ab48e34e46ff5b0a7fcde9cf5751925cdee373c3e2784c9a76726fb",
    "tools/lab/handoff93/test_product_mapper_formal_soak_mock.ps1": "cbc17ba067160bbef96d9ea089dadc2fc1351a8aae195539167f5873e6c6b0d1",
    "tools/lab/nat_gateway/test/v92_o01_t8_child.test.js": "916a31e03ded40cc5520296d3fc97e5a00113bb849e700a6b95eb7291e491035",
    "tools/lab/nat_gateway/v92_o01_t8_child.js": "a808b70c7a84b7c141c67d6438b1efd83ea2dc4174377aa0d09ad10521a40ea0",
    "tools/lab/test_v92_o01_formal_rpc_pump_mock.ps1": "3a34302cd77354e8d4efbd5f11f474331bfd8e8868132bf0a0643c89f7fd2645",
    "tools/lab/test_v92_o01_vm_session_mock.ps1": "c1dd12cfb23925a7aeb8c984e0a446dd6c3402fae868883a121fe208699abb6e",
    "docs/RELEASE_NOTES_v9.2.0-rc.1.md": "7e147faa992f515ef8cbfb8e5ed650c3c45c2c3a8727d23f8557d94bbcf410e2",
    "docs/V92_RC1_EXECUTION.md": "b0ac7e9d0933af69c5ac6bc387a147acd481e333c07bb32f3a4a56debbd6eef3",
    "tools/lab/nat_gateway/test/v92_o01_bridge_protocol.test.js": "6968c0b0c464f17370caf7c733933b88c26110b748308ee6c0ab072add61ba2a",
    "tools/lab/nat_gateway/test/v92_o01_formal_controller.test.js": "bdddf52cf794b51df99db593e01dff10bb988acaa4e8525d32d67dc802bcb2bf",
    "tools/lab/nat_gateway/test/v92_o01_soak.test.js": "aa81fc2c951385e30fbdf2dfbaee926ee63d37c9a2dbdeada0ecb53f2e09c25c",
    "tools/lab/nat_gateway/test/v92_o01_t8_daemon.test.js": "b35c986ff68903ef9cceb614e229bac84caa8e0e1cf8206670ccef39df5d019d",
    "tools/lab/nat_gateway/test/v92_o01_t8_fault_controller.test.js": "925a5d098f51ade4575d080703821acf5bebd77bf2768ae93c44c7d8201d6bc1",
    "tools/lab/nat_gateway/test/v92_o01_t8_gateway_adapter.test.js": "ab5bd1785e1f469615516157aba9b37b76581ec68ba054397466d6666b684beb",
    "tools/lab/nat_gateway/test/v92_o01_t8_network_adapter.test.js": "88eebfb570e201dc9b8becda6186cd022453e5fd9298083e227d5a8106194e23",
    "tools/lab/nat_gateway/test/v92_o01_t8_udp_mux.test.js": "194c36754f6911ae9976bb14ffa1eda6e74a8f75aaac0602dd838a6a2ce60f10",
    "tools/lab/nat_gateway/test/v92_o01_validate_formal.test.js": "7ae90c6c36feb4e1a3418362ff74dbe70bb6eaf586d8b883f1bfd54fbe69bc7a",
    "tools/lab/nat_gateway/v92_o01_bridge_protocol.js": "f77aea1a2355642d6e74548177b62e3f7f6120e1ff854e068e0775de725e5973",
    "tools/lab/nat_gateway/v92_o01_formal_controller.js": "7b9ddac2301cbc064a09e3f2a641bf5a987f6f19747f95ca257487919e544324",
    "tools/lab/nat_gateway/v92_o01_scenario.json": "4c83b0de5afa4576c8e4c14fb146b3b7179a54b8988a3322e3a75a5f70a9cbde",
    "tools/lab/nat_gateway/v92_o01_soak.js": "aace145bf4698b8648ca4d77b27ea58cab80d81c75e6cd64ba28de8933765452",
    "tools/lab/nat_gateway/v92_o01_t8_daemon.js": "33193a1a535d5caf593b08e0eb48d5e6b369ad1fa7051cc6f56075e0d297465a",
    "tools/lab/nat_gateway/v92_o01_t8_fault_controller.js": "8c0b89ace441e44e5c23ddad4c9d376719302769e42e67482fdaa60551421185",
    "tools/lab/nat_gateway/v92_o01_t8_gateway_adapter.js": "0c15c84833cf03a27c270e72e88674a5edd390edc2d94933951d1936774de207",
    "tools/lab/nat_gateway/v92_o01_t8_network_adapter.js": "8149b8fd19fc119c2174e62a9fca8ed832856e9df8bcb3bbb93435c7e68875dc",
    "tools/lab/nat_gateway/v92_o01_t8_udp_mux.js": "a073ba65b00f9054a67527f5695ec30c5abf72fdb235411e8346d7753f5ae243",
    "tools/lab/nat_gateway/v92_o01_validate_formal.js": "bb797cf7e52c111c2c8a8944400b20cd9ded37cc6a06ce5352377fbc8ee87640",
    "tools/lab/run_v92_o01_formal.ps1": "e42f9a6b62e2fd34f982a97664ef008dac9ff0abd90b3d057cc523ebbd99173b",
    "tools/lab/test_v92_o01_formal_runner_mock.ps1": "f26d44b55665f00d3190e73e61af3d848dab8c20f3777d9252d751341a174db5",
    "tools/lab/v92_o01_vm_session.psm1": "7df6e0ef1b4e6c20be139c31fa334be31ef9156c4e3202811b8e592f8f6be3eb",
}

PATH_BUDGET = {
    "tools/lab/handoff93/run_product_mapper_cycle.ps1": (62, 6),
    "tools/lab/handoff93/test_product_mapper_formal_soak_mock.ps1": (10, 7),
    "tools/lab/nat_gateway/test/v92_o01_t8_child.test.js": (1, 1),
    "tools/lab/nat_gateway/v92_o01_t8_child.js": (1, 1),
    "tools/lab/test_v92_o01_formal_rpc_pump_mock.ps1": (1, 0),
    "tools/lab/test_v92_o01_vm_session_mock.ps1": (1, 1),
    "docs/RELEASE_NOTES_v9.2.0-rc.1.md": (5, 2),
    "docs/V92_RC1_EXECUTION.md": (3, 1),
    "tools/lab/nat_gateway/test/v92_o01_bridge_protocol.test.js": (1, 1),
    "tools/lab/nat_gateway/test/v92_o01_formal_controller.test.js": (20, 65),
    "tools/lab/nat_gateway/test/v92_o01_soak.test.js": (2, 2),
    "tools/lab/nat_gateway/test/v92_o01_t8_daemon.test.js": (1, 1),
    "tools/lab/nat_gateway/test/v92_o01_t8_fault_controller.test.js": (68, 10),
    "tools/lab/nat_gateway/test/v92_o01_t8_gateway_adapter.test.js": (174, 1),
    "tools/lab/nat_gateway/test/v92_o01_t8_network_adapter.test.js": (4, 3),
    "tools/lab/nat_gateway/test/v92_o01_t8_udp_mux.test.js": (49, 11),
    "tools/lab/nat_gateway/test/v92_o01_validate_formal.test.js": (34, 72),
    "tools/lab/nat_gateway/v92_o01_bridge_protocol.js": (2, 2),
    "tools/lab/nat_gateway/v92_o01_formal_controller.js": (65, 24),
    "tools/lab/nat_gateway/v92_o01_scenario.json": (4, 2),
    "tools/lab/nat_gateway/v92_o01_soak.js": (3, 3),
    "tools/lab/nat_gateway/v92_o01_t8_daemon.js": (8, 3),
    "tools/lab/nat_gateway/v92_o01_t8_fault_controller.js": (218, 26),
    "tools/lab/nat_gateway/v92_o01_t8_gateway_adapter.js": (110, 29),
    "tools/lab/nat_gateway/v92_o01_t8_network_adapter.js": (21, 7),
    "tools/lab/nat_gateway/v92_o01_t8_udp_mux.js": (20, 12),
    "tools/lab/nat_gateway/v92_o01_validate_formal.js": (92, 14),
    "tools/lab/run_v92_o01_formal.ps1": (6, 5),
    "tools/lab/test_v92_o01_formal_runner_mock.ps1": (2, 1),
    "tools/lab/v92_o01_vm_session.psm1": (4, 3),
}
BUDGET = (30, 992, 316, 676)
RUNTIME_BUDGET = (14, 616, 137, 479)
TEST_BUDGET = (14, 368, 176, 192)
DOC_BUDGET = (2, 8, 3, 5)
HISTORICAL_BUDGET = (62, 1702, 136, 1566)
CUMULATIVE_BUDGET = (62, 2694, 452, 2242)

HISTORICAL_CANDIDATE = [
    "CHANGES_FROM_EMULE_0.70b.md", "GUIA-RAPIDA.md", "README.md",
    "THIRD_PARTY_LICENSES.md", "docs/INDEX.md",
    "docs/RELEASE_NOTES_v9.2.0-rc.1.md", "docs/USER_GUIDE.md",
    "docs/V92_RC1_EXECUTION.md", "libkad6/make_crypto_vectors.bat",
    "libnatmap/src/pcp_pair_transaction.cpp",
    "libnatmap/tests/test_legacy_mapper_projection.cpp",
    "libnatmap/tests/test_pcp_pair_transaction.cpp",
    "srchybrid/Mod02BuildIdentity.h", "srchybrid/UPnPImplNATPMP.cpp",
    "srchybrid/UPnPImplPCP.cpp", "srchybrid/UPnPImplPCP.h",
    "srchybrid/Version.h", "srchybrid/eSE/package-lock.json",
    "srchybrid/eSE/package.json", "srchybrid/eSE/test/live_tv_regression.test.js",
    "tests/test_v92_l02_pcp_ownership.py", "tests/test_v92_l03_natpmp_ownership.py",
    "tests/test_v92_m2a_lt1_release_gate.py", "tests/test_v92_mod02_characterization.py",
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
    "tools/lab/run_v92_o01_formal.ps1", "tools/lab/t8_hyperv.ps1",
    "tools/lab/test_t8_hyperv_plan.ps1",
    "tools/lab/test_v92_o01_formal_rpc_pump_mock.ps1",
    "tools/lab/test_v92_o01_formal_runner_mock.ps1",
    "tools/lab/test_v92_o01_vm_session_mock.ps1",
    "tools/lab/test_v92_o01_vm_t8_smoke.ps1", "tools/lab/v92_o01_vm_session.psm1",
]
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
SCENARIO_SHA256 = A_SHA256[SCENARIO]
PRODUCT_MAPPER = "tools/lab/handoff93/run_product_mapper_cycle.ps1"
PREDECESSOR_PRODUCT_MAPPER_BLOB = "24c6384371b7b50ab16fefeb2aecc0c9f00fe946"
PREDECESSOR_PRODUCT_MAPPER_SHA256 = "262d11aaa40c5beb6b49e9e9ceb8b48be900afff9bd993d28876b0613caace3c"
PRODUCT_MAPPER_BLOB = "ad4ab8518229f638e610ed08b0e9745595ad4147"
PRODUCT_MAPPER_SHA256 = "700b62b79ab48e34e46ff5b0a7fcde9cf5751925cdee373c3e2784c9a76726fb"
BOUND_FILES = [
    PRODUCT_MAPPER, "tools/lab/nat_gateway/v92_o01_product_stream.js",
    "tools/lab/nat_gateway/v92_o01_formal_controller.js",
    "tools/lab/nat_gateway/v92_o01_validate_formal.js", SCENARIO,
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
    "tools/lab/run_v92_o01_formal.ps1", "tools/lab/v92_o01_vm_session.psm1",
    "tools/lab/t8_hyperv.ps1", "tools/lab/common.ps1", "tools/lab/v91_r01_upnp.ps1",
]
HEX64 = re.compile(r"^[0-9a-f]{64}$")

REVIEWS = ["Terra APPROVE with findings=[]", "Sol APPROVE with findings=[]"]
GATES = [
    "Node 22 complete nat_gateway suite",
    "PowerShell parser for every changed ps1/psm1",
    "formal runner source/mock gate",
    "G10 hostile governance suite",
    "exact A38 byte and budget verifier",
    "official full Release x64 rebuild from clean A38",
    "M38 MOD02 verifier and runtime reseal",
    "git diff --check",
]
OFFLINE = [
    (GATES[0], "npm.cmd test", "O01_NODE_SUITE_PASS"),
    (GATES[1], "powershell parser changed ps1/psm1", "O01_POWERSHELL_PARSE_PASS"),
    (GATES[2], "powershell -File tools/lab/test_v92_o01_formal_runner_mock.ps1", "O01_RUNNER_MOCK_PASS"),
    (GATES[3], "python -B tools/architecture/test_verify_v92_o01_physical_repair_governance.py", "O01_G10_GOVERNANCE_PASS"),
    (GATES[4], "python -B tools/architecture/verify_v92_o01_physical_repair_governance.py --verify", "O01_A38_BINDING_PASS"),
    (GATES[5], "powershell -File tools/build_all.ps1 -ReleaseTag v0.70b-eSE9.2.0-rc.1", "O01_RELEASE_BUILD_PASS"),
    (GATES[6], "verify M38 MOD02 artifacts", "O01_MOD02_RESEAL_PASS"),
    (GATES[7], "git diff --check", "O01_DIFF_CHECK_PASS"),
]
MOD02_REQUIRED = [
    "build_manifest_sha256", "source_identity_sha256", "source_tree_clean",
    "executable_sha256", "marker_sha256", "termination_confirmed",
]


class GateError(RuntimeError):
    pass


def sh(*args: str) -> str:
    return subprocess.run(
        args, cwd=ROOT, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    ).stdout.decode().strip()


def git(*args: str) -> str:
    return sh("git", *args)


def exact(value: object, keys: set[str], where: str) -> dict:
    if not isinstance(value, dict) or set(value) != keys:
        raise GateError(f"{where} schema")
    return value


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


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


def parse_utc(value: object, where: str, allow_timezone_offset: bool = False) -> datetime.datetime:
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
    command = ". .\\tools\\release_fingerprint.ps1; Get-ReleaseSourceFingerprint -RepoRoot . -Component emule"
    lines = sh(
        "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command,
    ).splitlines()
    value = lines[-1].strip() if lines else ""
    if re.fullmatch(r"[0-9A-F]{64}", value) is None:
        raise GateError("Release source fingerprint")
    return value


def mod02_markers() -> list[str]:
    return [
        "BEGIN CUPnPImplMiniLib deferred reaper", "PASS CUPnPImplMiniLib deferred reaper",
        f"SOURCE {MOD02_IDENTITY}", "BEGIN CLiveTunnel", "PASS CLiveTunnel",
        "BEGIN CWebServer", "PASS CWebServer", "BEGIN CLiveStreamManager",
        "PASS CLiveStreamManager",
    ]


def mod02_marker_sha256() -> str:
    return sha(("\n".join(mod02_markers()) + "\n").encode())


def observed_budget(stats: dict[str, tuple[int, int]], paths: list[str] | None = None) -> tuple[int, int, int, int]:
    selected = stats if paths is None else {path: stats[path] for path in paths}
    return (
        len(selected), sum(row[0] for row in selected.values()),
        sum(row[1] for row in selected.values()), sum(row[0] - row[1] for row in selected.values()),
    )


def release_receipt_path(a_commit: str) -> str:
    return f"artifacts/v92-o01-release-build-{a_commit[:8]}/emule-release-build.json"


def m_paths(a_commit: str) -> list[str]:
    return sorted([
        M_MANIFEST, M_MATRIX, f"artifacts/mod02-runtime-v92-{a_commit[:8]}/summary.json",
        release_receipt_path(a_commit),
    ])


def r_paths() -> list[str]:
    return sorted([
        f"artifacts/v92-o01-formal/checkpoint-{index:02}.json" for index in range(1, 96)
    ] + [
        "artifacts/v92-o01-formal/controller-result.json",
        "artifacts/v92-o01-formal/formal-run-result.json",
        "artifacts/v92-o01-formal/formal-validation.json",
    ])


def expected_document() -> dict:
    return {
        "schema": "ese.v92.o01-physical-repair-governance/v1",
        "status": "DRAFT_PRE_G10",
        "predecessor": {
            "g9_commit": G9, "g9_tree": G9_TREE, "a37_commit": A37,
            "a37_tree": A37_TREE, "m37_commit": M37, "m37_tree": M37_TREE,
            "h37_commit": PRED_H, "h37_tree": PRED_H_TREE,
        },
        "historical_contract": {
            "governance_sha256": HISTORICAL_GOV_SHA256,
            "candidate_path_count": HISTORICAL_BUDGET[0],
            "candidate_add_exact": HISTORICAL_BUDGET[1],
            "candidate_delete_exact": HISTORICAL_BUDGET[2],
            "candidate_net_exact": HISTORICAL_BUDGET[3],
            "candidate_paths_sha256": CANDIDATE_SHA256,
        },
        "scope": "V92-O01 rc.1 only: repair the real T8 fault-consumption, lease timing, cleanup-port and controller-release contracts exposed by the A37 physical runs, rebuild Release from A38, reseal MOD02 in M38, and permit release only through direct independently validated eight-hour evidence after H38.",
        "topology": {
            "G10": "direct child of H37; exactly this amendment, verifier and verifier test",
            "A38": "direct child of G10; exactly runtime_paths plus test_paths plus documentation_paths at their exact separate budgets and byte identities",
            "M38": "direct child of A38; exactly four carriers from a fresh official full Release build and MOD02 reseal",
            "H38": "direct child of M38; exactly four governance carriers with two independent empty-finding approvals",
            "R": "direct child of H38; exactly 98 formal artifacts from one uninterrupted eight-hour run sourced from A38 and using the executable validated by M38",
        },
        "phase_contract": {
            "schema": "ese.v92.o01-physical-repair-phases/v1",
            "merge_policy": "Every G10/A38/M38/H38/R commit has exactly one parent; merges, S, intermediate commits and reused build metadata are rejected.",
            "G10": {"parent": "H37", "delta": "governance_paths"},
            "A38": {"parent": "G10", "delta": "runtime_paths_plus_test_paths_plus_documentation_paths"},
            "M38": {"parent": "A38", "delta": "m_carrier_paths", "build": "fresh official full Release rebuild from clean A38"},
            "H38": {"parent": "M38", "delta": "h_carrier_paths"},
            "R": {"parent": "H38", "source": "A38", "governance": "H38", "executable": "exact_M38_manifest_executable_sha256", "release_gate": True},
        },
        "governance_paths": GOV,
        "runtime_paths": RUNTIME_PATHS,
        "test_paths": TEST_PATHS,
        "documentation_paths": DOC_PATHS,
        "a38_sha256": A_SHA256,
        "path_budget": {
            path: {"add_exact": row[0], "delete_exact": row[1]}
            for path, row in PATH_BUDGET.items()
        },
        "historical_overlap_paths": A_PATHS,
        "new_candidate_paths": [],
        "budget": {"path_count": 30, "add_exact": 992, "delete_exact": 316, "net_exact": 676, "headroom": 0},
        "runtime_budget": {"path_count": 12, "add_exact": 437, "delete_exact": 103, "net_exact": 334, "headroom": 0},
        "test_budget": {"path_count": 10, "add_exact": 133, "delete_exact": 165, "net_exact": -32, "headroom": 0},
        "documentation_budget": {"path_count": 2, "add_exact": 8, "delete_exact": 3, "net_exact": 5, "headroom": 0},
        "cumulative_candidate_budget": {"path_count": 62, "add_exact": 2694, "delete_exact": 452, "net_exact": 2242},
        "cumulative_candidate_paths_sha256": CANDIDATE_SHA256,
        "release_contract": {
            "release_tag": RELEASE_TAG, "source_fingerprint": RELEASE_FINGERPRINT,
            "mod02_identity_sha256": MOD02_IDENTITY,
            "mod02_marker_sha256": MOD02_MARKER_SHA,
            "scenario_sha256": SCENARIO_SHA256, "scenario_socket_limit": 2,
            "fault_slot_ms": 300000, "lease_ms": 120000, "late_delay_ms": 8000,
            "bound_file_count": 21,
            "product_mapper_cycle": {"path": PRODUCT_MAPPER, "blob": PRODUCT_MAPPER_BLOB, "sha256": PRODUCT_MAPPER_SHA256},
            "build_policy": "M38 must contain a fresh official full Release x64 build receipt bound to clean A38; M37 binary or metadata reuse is forbidden.",
        },
        "carrier_paths": {
            "M38": {
                "fixed": [M_MANIFEST, M_MATRIX],
                "summary_pattern": "artifacts/mod02-runtime-v92-<A38[0:8]>/summary.json",
                "release_build_receipt_pattern": "artifacts/v92-o01-release-build-<A38[0:8]>/emule-release-build.json",
                "file_count": 4,
            },
            "H38": H_PATHS,
            "R": {
                "directory": "artifacts/v92-o01-formal",
                "checkpoint_pattern": "checkpoint-(01..95).json",
                "fixed": ["controller-result.json", "formal-run-result.json", "formal-validation.json"],
                "file_count": 98,
            },
        },
        "required_reviews": REVIEWS,
        "offline_gates": GATES,
        "physical_policy": {
            "formal": "Exactly 28800000 monotonic milliseconds, 96 five-minute fault slots, no duration override, no resume, no skip-cleanup, Node 22, clean A38 source and the M38 executable.",
            "claim_rule": "Only independently validated direct-R evidence with exact cleanup and baseline restoration may award V92-O01 PASS.",
            "preflight": "No S phase exists in G10; diagnostic runs are external NON_RELEASE evidence and cannot enter the release ancestry.",
        },
        "stop_conditions": [
            "A38 path 31 or any path outside the three closed A38 slices",
            "A38 total or slice budget differs by one line or is preserved only by compensated rebalance",
            "an A38 byte identity differs from its pinned SHA-256",
            "historical overlap differs from all 30 A38 paths, new candidate count differs from zero, or the 62-path union hash changes",
            "scenario limits.sockets differs from integer 2, fault_slot_ms differs from 300000, lease_ms differs from 120000, late_delay_ms differs from 8000, or bound_files differs from exactly 21",
            "the production mapper cycle blob or byte SHA-256 changes",
            "M38 is not a fresh clean official full Release build bound to A38 and exact MOD02 identity",
            "source, Node, package or evidence binding changes during a run",
            "P0, P1, P2 or nonempty review finding",
            "release_gate=true before independent validation and exact baseline restoration",
        ],
        "activation_state": {
            "G10": None, "A38": None, "M38": None, "H38": None, "R": None,
            "rule": "The document never stores its own commit; phase identities are derived from exact Git parentage and later carriers.",
        },
    }


def validate(value: dict) -> bool:
    exact(value, set(expected_document()), "root")
    if value != expected_document():
        raise GateError("document exact contract")
    if len(HISTORICAL_CANDIDATE) != 62 or len(set(HISTORICAL_CANDIDATE)) != 62:
        raise GateError("historical candidate set")
    if sha(canonical(sorted(HISTORICAL_CANDIDATE))) != CANDIDATE_SHA256:
        raise GateError("historical candidate identity")
    if set(A_PATHS) - set(HISTORICAL_CANDIDATE) or len(A_PATHS) != 30:
        raise GateError("historical overlap")
    if set(RUNTIME_PATHS) & set(TEST_PATHS) or set(RUNTIME_PATHS) & set(DOC_PATHS) or set(TEST_PATHS) & set(DOC_PATHS):
        raise GateError("slice overlap")
    if set(A_SHA256) != set(A_PATHS) or set(PATH_BUDGET) != set(A_PATHS):
        raise GateError("A38 pin coverage")
    if MOD02_MARKER_SHA != mod02_marker_sha256():
        raise GateError("MOD02 marker identity")
    return True


def verify_product_mapper(raw: bytes, where: str, expected_sha: str = PRODUCT_MAPPER_SHA256,
                          expected_blob: str = PRODUCT_MAPPER_BLOB) -> None:
    if sha(raw) != expected_sha or git_blob_sha(raw) != expected_blob:
        raise GateError(f"{where} product mapper identity")


def verify_scenario(raw: bytes, where: str) -> None:
    if sha(raw) != SCENARIO_SHA256:
        raise GateError(f"{where} scenario identity")
    value = load_bytes(raw)
    exact_fields = {
        "formal_duration_ms": 28800000, "tick_ms": 10000,
        "fault_slot_ms": 300000, "lease_ms": 120000, "late_delay_ms": 8000,
        "checkpoint_ms": 300000, "sample_ms": 60000, "node_major": 22,
    }
    if not isinstance(value, dict) or any(value.get(key) != expected for key, expected in exact_fields.items()):
        raise GateError(f"{where} scenario timing")
    if not isinstance(value.get("limits"), dict) or type(value["limits"].get("sockets")) is not int or value["limits"]["sockets"] != 2:
        raise GateError(f"{where} scenario socket limit")
    if value.get("bound_files") != BOUND_FILES or len(value["bound_files"]) != 21:
        raise GateError(f"{where} scenario bound files")


def verify_predecessor() -> None:
    for commit, parent in ((G9, H36), (A37, G9), (M37, A37), (PRED_H, M37)):
        require_single_parent(commit, parent, "predecessor")
    for commit, expected_tree in (
        (H36, H36_TREE), (G9, G9_TREE), (A37, A37_TREE),
        (M37, M37_TREE), (PRED_H, PRED_H_TREE),
    ):
        if git("rev-parse", f"{commit}^{{tree}}") != expected_tree:
            raise GateError("predecessor tree")
    observed = {path: sha(blob(PRED_H, path)) for path in HISTORICAL_GOV}
    if observed != HISTORICAL_GOV_SHA256:
        raise GateError("predecessor governance identity")
    activation = load_bytes(blob(PRED_H, H_PATHS[0]))
    if not isinstance(activation, dict) or activation.get("candidate_paths_sha256") != CANDIDATE_SHA256:
        raise GateError("predecessor candidate identity")
    verify_product_mapper(blob(PRED_H, PRODUCT_MAPPER), "predecessor",
                          PREDECESSOR_PRODUCT_MAPPER_SHA256, PREDECESSOR_PRODUCT_MAPPER_BLOB)


def validate_budget(stats: dict[str, tuple[int, int]], where: str) -> None:
    if sorted(stats) != A_PATHS:
        raise GateError(f"{where} allowlist")
    if observed_budget(stats) != BUDGET:
        raise GateError(f"{where} budget")
    if stats != PATH_BUDGET:
        raise GateError(f"{where} path budget")
    if observed_budget(stats, RUNTIME_PATHS) != RUNTIME_BUDGET:
        raise GateError(f"{where} runtime budget")
    if observed_budget(stats, TEST_PATHS) != TEST_BUDGET:
        raise GateError(f"{where} test budget")
    if observed_budget(stats, DOC_PATHS) != DOC_BUDGET:
        raise GateError(f"{where} documentation budget")


def commit_budget(parent: str, commit: str) -> None:
    stats: dict[str, tuple[int, int]] = {}
    for line in git("diff", "--numstat", parent, commit, "--").splitlines():
        added, deleted, path = line.split("\t", 2)
        if not added.isdigit() or not deleted.isdigit():
            raise GateError("A38 binary payload")
        stats[path] = (int(added), int(deleted))
    validate_budget(stats, "A38")


def verify_a_hashes(reader, where: str) -> None:
    observed = {path: sha(reader(path)) for path in A_PATHS}
    if observed != A_SHA256:
        raise GateError(f"{where} A38 byte identity")


def worktree_stats() -> bool:
    if git("rev-parse", "HEAD") != PRED_H:
        raise GateError("worktree base")
    stats: dict[str, tuple[int, int]] = {}
    for line in git("diff", "HEAD", "--numstat", "--").splitlines():
        added, deleted, path = line.split("\t", 2)
        if not added.isdigit() or not deleted.isdigit():
            raise GateError("A38 binary payload")
        if path not in GOV:
            stats[path] = (int(added), int(deleted))
    for path in git("ls-files", "--others", "--exclude-standard").splitlines():
        if path in GOV:
            continue
        data = (ROOT / path).read_bytes()
        stats[path] = (data.count(b"\n") + int(bool(data) and not data.endswith(b"\n")), 0)
    validate_budget(stats, "worktree")
    verify_a_hashes(lambda path: (ROOT / path).read_bytes(), "worktree")
    verify_scenario((ROOT / SCENARIO).read_bytes(), "worktree")
    verify_product_mapper((ROOT / PRODUCT_MAPPER).read_bytes(), "worktree")
    return True


def verify_g(g_commit: str, document: dict) -> None:
    require_single_parent(g_commit, PRED_H, "G10")
    if changed(PRED_H, g_commit) != sorted(GOV):
        raise GateError("G10 delta")
    if load_bytes(blob(g_commit, DOC)) != document:
        raise GateError("G10 document")


def verify_a(a_commit: str, g_commit: str) -> None:
    require_single_parent(a_commit, g_commit, "A38")
    if changed(g_commit, a_commit) != A_PATHS:
        raise GateError("A38 delta")
    commit_budget(g_commit, a_commit)
    verify_a_hashes(lambda path: blob(a_commit, path), "A38")
    verify_scenario(blob(a_commit, SCENARIO), "A38")
    verify_product_mapper(blob(a_commit, PRODUCT_MAPPER), "A38")


def verify_m(m_commit: str, a_commit: str) -> None:
    require_single_parent(m_commit, a_commit, "M38")
    if changed(a_commit, m_commit) != m_paths(a_commit):
        raise GateError("M38 delta")
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
    built_at = parse_utc(receipt["builtAtUtc"], "Release build timestamp")
    commit_time = parse_utc(
        git("show", "-s", "--format=%cI", a_commit),
        "Release source commit timestamp", allow_timezone_offset=True,
    )
    if (
        type(receipt["schema"]) is not int or receipt["schema"] != 1
        or receipt["component"] != "emule" or receipt["releaseTag"] != RELEASE_TAG
        or receipt["commit"] != a_commit or receipt["sourceFingerprint"] != RELEASE_FINGERPRINT
        or release_source_fingerprint() != RELEASE_FINGERPRINT
        or receipt["binarySha256"] != manifest["executable_sha256"].upper()
        or type(receipt["binaryLength"]) is not int
        or not 1 <= receipt["binaryLength"] <= 100 * 1024 * 1024
        or built_at < commit_time
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
        or summary["taskkill_started"] is not False or summary["taskkill_finished"] is not True
        or summary["taskkill_exit_code"] is not None or summary["termination_confirmed"] is not True
        or type(summary["exit_code"]) is not int or summary["exit_code"] != 0
    ):
        raise GateError("MOD02 termination")
    markers = mod02_markers()
    if (
        summary["expected_markers"] != markers
        or summary["observed_markers_sanitized"] != markers
        or summary["markers_verified"] is not True
        or summary["marker_sha256"] != MOD02_MARKER_SHA
        or summary["verdict"] != "PASS"
        or summary["command"] != "--portable --ignoreinstances --selftest"
        or summary["isolation"] != "portable unique output root; no UI"
    ):
        raise GateError("MOD02 verdict")
    source_time = parse_utc(summary["latest_critical_source_write_utc"], "MOD02 timestamp")
    executable_time = parse_utc(summary["executable_write_utc"], "MOD02 timestamp")
    if executable_time < source_time or executable_time < commit_time or built_at < executable_time:
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
    receipt_binding = exact(gate["release_build_receipt"], {"path", "sha256", "source_tree"}, "Release build receipt binding")
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
            "timed_out", "termination_confirmed", "exit_code", "source_tree_clean",
            "markers_verified",
        )
    }
    expected_evidence["summary_sha256"] = sha(summary_raw)
    if (
        gate["runner"] != "tools/architecture/run_mod02_stream_selftest.ps1"
        or gate["build_manifest"] != M_MANIFEST or gate["summary"] != summary_path
        or gate["status"] != "PASS" or gate["required_summary"] != MOD02_REQUIRED
        or gate["acceptance"] != prior_matrix["runtime_gate"]["acceptance"]
        or receipt_binding != {"path": receipt_path, "sha256": sha(receipt_raw), "source_tree": a_tree}
        or evidence != expected_evidence
    ):
        raise GateError("MOD02 matrix binding")


def validate_review(raw: bytes, role: str, a_commit: str, a_tree: str) -> None:
    value = exact(load_bytes(raw), {
        "schema", "role", "reviewed_commit", "reviewed_tree", "verdict", "findings",
    }, "review")
    if value != {
        "schema": "ese.v92.o01-review/v1", "role": role,
        "reviewed_commit": a_commit, "reviewed_tree": a_tree,
        "verdict": "APPROVE", "findings": [],
    }:
        raise GateError("review content")


def verify_h(h_commit: str, m_commit: str, a_commit: str, g_commit: str) -> None:
    require_single_parent(h_commit, m_commit, "H38")
    if changed(m_commit, h_commit) != H_PATHS:
        raise GateError("H38 delta")
    a_tree = git("rev-parse", f"{a_commit}^{{tree}}")
    m_tree = git("rev-parse", f"{m_commit}^{{tree}}")
    amendment_sha = sha(blob(g_commit, DOC))
    children = {path: blob(h_commit, path) for path in H_PATHS[1:]}
    activation = exact(load_bytes(blob(h_commit, H_PATHS[0])), {
        "schema", "predecessor_h_commit", "g_commit", "a_commit", "a_tree",
        "m_commit", "m_tree", "amendment_sha256", "candidate_paths_sha256",
        "a38_paths_sha256", "runtime_paths_sha256", "test_paths_sha256",
        "documentation_paths_sha256", "scenario_sha256", "product_mapper_blob",
        "product_mapper_sha256", "artifact_sha256",
    }, "activation")
    expected_activation = {
        "schema": "ese.v92.o01-physical-repair-activation/v1",
        "predecessor_h_commit": PRED_H, "g_commit": g_commit,
        "a_commit": a_commit, "a_tree": a_tree, "m_commit": m_commit,
        "m_tree": m_tree, "amendment_sha256": amendment_sha,
        "candidate_paths_sha256": CANDIDATE_SHA256,
        "a38_paths_sha256": sha(canonical(A_PATHS)),
        "runtime_paths_sha256": sha(canonical(RUNTIME_PATHS)),
        "test_paths_sha256": sha(canonical(TEST_PATHS)),
        "documentation_paths_sha256": sha(canonical(DOC_PATHS)),
        "scenario_sha256": SCENARIO_SHA256, "product_mapper_blob": PRODUCT_MAPPER_BLOB,
        "product_mapper_sha256": PRODUCT_MAPPER_SHA256,
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
        offline["schema"] != "ese.v92.o01-physical-repair-offline-summary/v1"
        or offline["source_commit"] != a_commit or offline["source_tree"] != a_tree
        or offline["m_commit"] != m_commit or offline["m_tree"] != m_tree
        or offline["amendment_sha256"] != amendment_sha
        or not isinstance(offline["gates"], list) or len(offline["gates"]) != len(OFFLINE)
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


def run_product_validator(materialized: Path) -> None:
    script = (
        "const fs=require('fs'),p=require('path'),d=process.argv[1],"
        "v=require(p.join(d,'validator.js')),c=JSON.parse(fs.readFileSync(p.join(d,'scenario.json'))),"
        "r=JSON.parse(fs.readFileSync(p.join(d,'controller-result.json'))),"
        "x=Array.from({length:95},(_,i)=>JSON.parse(fs.readFileSync(p.join(d,'checkpoint-'+String(i+1).padStart(2,'0')+'.json'))));"
        "v._validateFormalEvidenceTest({config:c,checkpoints:x,result:r});process.stdout.write('PASS');"
    )
    output = subprocess.run(
        ["node", "-e", script, str(materialized)], cwd=ROOT, check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120,
    ).stdout
    if output != b"PASS":
        raise GateError("product validator output")


def verify_r(r_commit: str, h_commit: str, a_commit: str, m_commit: str) -> None:
    require_single_parent(r_commit, h_commit, "R")
    if changed(h_commit, r_commit) != r_paths():
        raise GateError("R delta")
    a_tree = git("rev-parse", f"{a_commit}^{{tree}}")
    manifest = exact(load_bytes(blob(m_commit, M_MANIFEST)), {
        "schema", "source_commit", "source_identity_sha256", "executable_sha256",
    }, "MOD02 manifest")
    run_path = "artifacts/v92-o01-formal/formal-run-result.json"
    controller_path = "artifacts/v92-o01-formal/controller-result.json"
    validation_path = "artifacts/v92-o01-formal/formal-validation.json"
    run_raw = blob(r_commit, run_path)
    controller_raw = blob(r_commit, controller_path)
    run = exact(load_bytes(run_raw), {
        "schema", "verdict", "release_gate", "source_commit", "source_tree",
        "governance_h_commit", "governance_s_commit", "executable_sha256",
        "build_info_sha256", "node_sha256", "duration_ms", "product_records",
        "checkpoints", "fault_slots", "baseline_restored", "independent_validation",
    }, "formal run")
    if (
        run["schema"] != "ese.v92.o01-formal-run/v1" or run["verdict"] != "PASS"
        or run["release_gate"] is not True or run["source_commit"] != a_commit
        or run["source_tree"] != a_tree or run["governance_h_commit"] != h_commit
        or run["governance_s_commit"] is not None or run["duration_ms"] != 28800000
        or run["product_records"] != 482 or run["checkpoints"] != 95
        or run["fault_slots"] != 96 or run["baseline_restored"] is not True
        or run["independent_validation"] is not True
        or manifest != {
            "schema": "ese.mod02.build-manifest/v1", "source_commit": a_commit,
            "source_identity_sha256": MOD02_IDENTITY,
            "executable_sha256": run["executable_sha256"],
        }
        or any(not isinstance(run[key], str) or not HEX64.fullmatch(run[key]) for key in (
            "executable_sha256", "build_info_sha256", "node_sha256",
        ))
    ):
        raise GateError("formal run")
    result = load_bytes(controller_raw)
    if (
        not isinstance(result, dict) or result.get("source_commit") != a_commit
        or result.get("source_tree") != a_tree or result.get("verdict") != "PASS"
        or result.get("checkpoint_count") != 95
    ):
        raise GateError("controller result")
    raw = {controller_path: controller_raw, run_path: run_raw}
    checkpoints: list[bytes] = []
    for index in range(1, 96):
        path = f"artifacts/v92-o01-formal/checkpoint-{index:02}.json"
        data = blob(r_commit, path)
        raw[path] = data
        checkpoints.append(data)
    validation = exact(load_bytes(blob(r_commit, validation_path)), {
        "schema", "verdict", "source_commit", "source_tree", "governance_h_commit",
        "governance_s_commit", "validator_sha256", "scenario_sha256",
        "artifacts_sha256", "chain_tip_sha256", "checkpoints", "fault_slots",
        "ticks", "samples",
    }, "formal validation")
    validator_blob = blob(a_commit, "tools/lab/nat_gateway/v92_o01_validate_formal.js")
    scenario_blob = blob(a_commit, SCENARIO)
    expected_validation = {
        "schema": "ese.v92.o01-formal-validation/v2", "verdict": "PASS",
        "source_commit": a_commit, "source_tree": a_tree,
        "governance_h_commit": h_commit, "governance_s_commit": None,
        "validator_sha256": sha(validator_blob), "scenario_sha256": sha(scenario_blob),
        "artifacts_sha256": {path: sha(data) for path, data in sorted(raw.items())},
        "chain_tip_sha256": result.get("chain_tip_sha256"), "checkpoints": 95,
        "fault_slots": 96, "ticks": 2880, "samples": 480,
    }
    if validation != expected_validation:
        raise GateError("formal validation")
    verify_scenario(scenario_blob, "R")
    bound = result.get("bound_files")
    if not isinstance(bound, list) or len(bound) != 21:
        raise GateError("A38 bound paths")
    for index, path in enumerate(BOUND_FILES):
        if bound[index] != {"path": path, "sha256": sha(blob(a_commit, path))}:
            raise GateError("A38 bound hash")
    with tempfile.TemporaryDirectory(prefix="o01-g10-governance-") as temporary:
        root = Path(temporary)
        (root / "validator.js").write_bytes(validator_blob)
        (root / "scenario.json").write_bytes(scenario_blob)
        (root / "controller-result.json").write_bytes(controller_raw)
        for index, data in enumerate(checkpoints, 1):
            (root / f"checkpoint-{index:02}.json").write_bytes(data)
        run_product_validator(root)


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
        raise GateError("missing G10")
    g_commit = chain[0]
    verify_g(g_commit, document)
    if len(chain) == 1:
        return "G10"
    a_commit = chain[1]
    verify_a(a_commit, g_commit)
    if len(chain) == 2:
        return "A38"
    m_commit = chain[2]
    verify_m(m_commit, a_commit)
    if len(chain) == 3:
        return "M38"
    h_commit = chain[3]
    verify_h(h_commit, m_commit, a_commit, g_commit)
    if len(chain) == 4:
        return "H38"
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
        print(f"V92_O01_PHYSICAL_REPAIR_GOVERNANCE_FAIL {exc}", file=sys.stderr)
        return 1
    print(
        "V92_O01_PHYSICAL_REPAIR_GOVERNANCE_PASS "
        f"state={state} paths={BUDGET[0]} add={BUDGET[1]} delete={BUDGET[2]} "
        f"net={BUDGET[3]} candidate_paths={CUMULATIVE_BUDGET[0]}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
