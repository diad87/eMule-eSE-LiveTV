#!/usr/bin/env python3
"""Sealed G12/A64 governance verifier for the V92-O01 RPC repair."""

from __future__ import annotations

import argparse
import hashlib
import json
import locale
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import types
import zipfile
import zlib
from contextlib import ExitStack, contextmanager
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


REPO = Path(__file__).resolve().parents[2]
DOCUMENT = REPO / "docs/architecture/v92_o01_rpc_failure_governance_v1.json"
DOCUMENT_SHA256 = "b5a8a7015424d51dfc9acffc7dcfb478d090e3029d7e25602b2b5b34bbb58f58"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
CLOSED_CODE = re.compile(r"^O01_[A-Z0-9_]{1,60}$")
DOCUMENT_ASSIGNMENT = re.compile(br'(?m)^DOCUMENT_SHA256 = "[0-9a-f]{64}"$')
VERIFIER_NORMALIZATION_RULE = (
    "Replace the unique DOCUMENT_SHA256 assignment value in the verifier by 64 zeroes "
    "before SHA-256; reject zero or multiple assignments."
)
CLOSED_CORE_WHITESPACE = (
    "blank-at-eol,blank-at-eof,space-before-tab,cr-at-eol"
)

BASE = {
    "h62_commit": "4d1d157e48349b685c2e6d1ee1a8929a2d3a2589",
    "h62_tree": "72a0e5d1ca37615d3a42c59d47bce26ded74705b",
    "g11_commit": "4ffaf1f56347798e7f20c676759c1a1ad95f4970",
    "g11_tree": "12673a84e88c8aa686bef91715e516e2ac969d68",
    "a63_commit": "bba779d073a80c43661c6fe0dca4fc25e0e99f3d",
    "a63_tree": "c823e4b9c6e52c426bc51cbc4ecfb20ccc88a591",
    "m63_commit": "9ab458cb39fee88c9bf57b758ccd251b36ebc5dc",
    "m63_tree": "5227fe5d27b6563c962cad107d32a37bf32ab01f",
    "h63_commit": "bdf2c0ffcb43c519eea950e2125f27fa850076dd",
    "h63_tree": "d402269a14ef8cd1682eeb3365cd4bad1258f824",
}

G11_SHA256 = {
    "docs/architecture/v92_o01_clock_repair_governance_v1.json":
        "f94199dcc05c69970078fa65f6d93b7d772e99be040c936222439ee70d79d0d6",
    "tools/architecture/test_verify_v92_o01_clock_repair_governance.py":
        "a1b2952e40ed3051da43ac0fd0bbabdfce8cfe9093af4d85e4fad706dad3a2fb",
    "tools/architecture/verify_v92_o01_clock_repair_governance.py":
        "b4fad8e71dd307c1437b0c7540d5c264f168c82ea55eaa86ca69ad66e55369c7",
}
M63_SHA256 = {
    "artifacts/mod02-runtime-v92-bba779d0/summary.json":
        "d231c109945d6c443e6441bcc584da0516c8c8270d056c0a8546c97f72a6d5d4",
    "artifacts/v92-o01-release-build-bba779d0/emule-release-build.json":
        "abc990429e2286ccf46870e872256f350c79a92024b29475579654fc153a4381",
    "docs/architecture/mod02_build_manifest_v1.json":
        "13a52422f0db3d808e0f0c315a28408532bca56c45595cba9fdbb5375a9d591c",
    "docs/architecture/mod02_characterization_matrix_v1.json":
        "b4985c9341c6aa03fcf49e6e1cb19436a74ffad34ac5093d796dc7125c1636f3",
}
H63_SHA256 = {
    "artifacts/v92-o01-governance/activation.json":
        "0e7bd1beaf33d33562bb74700e0eb28d13f70cc9f5252bbb926686155b7b7ada",
    "artifacts/v92-o01-governance/offline-summary.json":
        "a7be74f7215f4f96e2f6a8eb0bb74e1a4e84b799cbb15d5b8985a8d6f94b9c53",
    "artifacts/v92-o01-governance/review-sol.json":
        "12149bca99002a2380d8d41625135e3d04609c838c2f0978dab490af0423e955",
    "artifacts/v92-o01-governance/review-terra.json":
        "3334c65bb5f8bf15c07fdf155a4c2696bd5087b77e7c8d10192a31fcf4b9cdce",
}
H_PATHS = [
    "artifacts/v92-o01-governance/activation.json",
    "artifacts/v92-o01-governance/offline-summary.json",
    "artifacts/v92-o01-governance/review-sol.json",
    "artifacts/v92-o01-governance/review-terra.json",
]
RELEASE_TAG = "v0.70b-eSE9.2.0-rc.1"
PACKAGE_ZIP_BASENAME = f"eSE-LiveTV-{RELEASE_TAG}-x64.zip"
PACKAGE_ZIP_PATH = f"dist/{RELEASE_TAG}/{PACKAGE_ZIP_BASENAME}"
PACKAGE_ZIP_SIDECAR_PATH = f"{PACKAGE_ZIP_PATH}.sha256"
PINNED_NODE_VERSION = "22.23.2"
PINNED_NODE_SHA256 = "0d0f5e39f9f3d9587bc19f73eab3c2c9c4903fd02d6dbf9c853dd81b3d95fad4"
PINNED_NODE_PATH = Path(r"C:\tmp\node-v22.23.2-win-x64\node.exe")
PINNED_NODE_TREE_FILE_COUNT = 2032
PINNED_NODE_TREE_DIRECTORY_COUNT = 507
PINNED_NODE_TREE_SHA256 = "b36841250caf4e868cf68f616e203abdc8aa82d83eb04acaa92e9750f27cde58"
PINNED_NPM_VERSION = "10.9.8"
PINNED_NPM_CMD_SHA256 = "21b46c69ad6e2f231f02a9e120f4ba6c8e75fef5a45637103002eab99f888ab8"
PINNED_NPM_CLI_SHA256 = "3ce7cba6f5128dd5f54c98b6a5036b0f850496878cc2e21044b675fe3c594e3e"
PINNED_NAT_GATEWAY_MODULE_FILE_COUNT = 528
PINNED_NAT_GATEWAY_MODULE_DIRECTORY_COUNT = 61
PINNED_NAT_GATEWAY_MODULE_IDENTITY_SHA256 = "ded983de6732b386dec8ec71385ed7259da38bf7aede9e66287db402868fb8e5"
PINNED_PKG_NODE_VERSION = "22.23.1"
PINNED_PKG_NODE_BYTES = 57440768
PINNED_PKG_NODE_SHA256 = "588055f6dd40513c16ecf705f9db5e4744eb8b9074e4979246a306b2d7315d1d"
PINNED_FFMPEG_SHA256 = "d1e2a156261ecc675081943197a85f08f2868784a0af499171ede89353edad31"
PINNED_FFPROBE_SHA256 = "70872c3ffbc43d0b2c570f9837f54d6e9a832f4ca25463e9735b6a3ec0621478"
MOD02_PORTABLE_SEED = b"[eMule]\r\n"
MOD02_PORTABLE_SEED_SHA256 = "ce888622784715371dac03b6651a767c98e5a4af93404d70d39043f829c17682"
PINNED_PYTHON_VERSION = "3.12.10"
PINNED_PYTHON_SHA256 = "4d6f5f81a4bca11191c4c7c6b43632694d0a4ce74e068619d8fdc161d469859a"
BUILD_PYTHON_DEPENDENCY_ROOTS = (
    "attr", "attrs", "jsonschema", "jsonschema_specifications", "referencing", "rpds",
)
BUILD_PYTHON_DEPENDENCY_FILES = ("typing_extensions.py",)
PINNED_BUILD_PYTHON_DEPENDENCY_FILE_COUNT = 113
PINNED_BUILD_PYTHON_DEPENDENCY_DIRECTORY_COUNT = 21
PINNED_BUILD_PYTHON_DEPENDENCY_IDENTITY_SHA256 = (
    "71b8a04b2258767d06583ce2652396e7a8e9ce554fe70d60c94141aaa617ee6d"
)
BUILD_PYTHON_DEPENDENCY_IDENTITY_RULE = (
    "SHA-256 of compact ASCII canonical JSON with exact keys directories and files for "
    "the attr, attrs, jsonschema, jsonschema_specifications, referencing and rpds package "
    "roots plus typing_extensions.py; source selection excludes __pycache__ directories "
    "and .pyc files, while the strict projection prohibits every non-admitted entry "
    "including caches and bytecode. All admitted relative paths are ordinal-sorted and "
    "case-insensitive collisions or lexical reparse points are rejected. The exact "
    "projection is copied create-exclusive to a fresh temporary root and both source and "
    "projection are remeasured after BUILD_ALL."
)
BUILD_PYTHON_DEPENDENCY_BOOTSTRAP = (
    "import os,runpy,sys;dependency=sys.argv[1];script=os.path.abspath(sys.argv[2]);"
    "sys.argv=sys.argv[2:];sys.path.insert(0,dependency);"
    "runpy.run_path(script,run_name='__main__')"
)
PINNED_GIT_VERSION = "2.51.0.windows.1"
PINNED_GIT_SHA256 = "34a408843194be320d8a87a3c12cd5c7d2e08d03b24567a41db32e21d12569d2"
PINNED_GIT_CORE_SHA256 = "755d4896d35663d0ff08924f84507f35236b83d240635b512c519bf43cc71a87"
LEGACY_PHYSICAL_VERIFIER_SHA256 = (
    "83c6e7f8c134f6ede26328ef1a491cbb55746fdfa84372dfe9ecb9b8cbecd717"
)
PINNED_POWERSHELL_SHA256 = "7600ffe12da441fe89d035b13801e8e91d064bc544a27b19a5cf49f6ab8b18f5"
PINNED_CMD_SHA256 = "8dd1ebb0b969370c70a5ee7f7ee347949aa7046aa5e1a33fcd7b1e9415b21fc3"
PINNED_MSBUILD_VERSION = "17.14.40.60911"
PINNED_MSBUILD_SHA256 = "0f7daba445ba37b652ae4180270ab3eff27acbbe5d411d3b05dad51aab16404c"
NODE_DISTRIBUTION_IDENTITY_RULE = (
    "SHA-256 of compact ASCII canonical JSON with exact keys directories and files; "
    "directories is the ordinal-sorted list of every relative POSIX directory path "
    "excluding the root, and files is the ordinal path-sorted list of exact objects "
    "{path,bytes,sha256}. Lexical reparse points and case-insensitive collisions across "
    "all relative file and directory paths are rejected."
)
PACKAGE_SNAPSHOT_IDENTITY_RULE = (
    "SHA-256 of compact ASCII canonical JSON with exact keys runtime_bindings and "
    "build_artifact_bindings; BUILD_ALL v3 measures it immediately after the official "
    "build and PACKAGE_AUDIT v2 must independently reproduce the identical value."
)
MAX_PACKAGE_MANIFEST_BYTES = 1024 * 1024
MAX_BUILD_INFO_BYTES = 4096
MAX_ZIP_SIDECAR_BYTES = 4096
MAX_RELEASE_RECEIPT_BYTES = 65536
MAX_PACKAGE_ZIP_BYTES = 1024 * 1024 * 1024
RUNTIME_BINDING_KEYS = [
    "node_version", "node_sha256", "executable_sha256", "build_info_sha256",
    "package_manifest_sha256", "package_manifest_entry_count", "package_file_count",
]
BUILD_ARTIFACT_BINDING_KEYS = [
    "release_tag", "package_zip_path", "package_zip_sha256", "package_zip_bytes",
    "package_zip_entry_count", "package_zip_sidecar_path",
    "package_zip_sidecar_bytes", "package_zip_sidecar_sha256",
]
FORMAL_RUN_KEYS = [
    "schema", "verdict", "release_gate", "source_commit", "source_tree",
    "governance_h_commit", "governance_s_commit", "executable_sha256",
    "build_info_sha256", "package_manifest_sha256", "package_manifest_entry_count",
    "package_file_count", "node_version", "node_sha256", "duration_ms",
    "product_records", "checkpoints", "fault_slots", "baseline_restored",
    "independent_validation",
]
FORMAL_LAUNCH_RECEIPT_KEYS = [
    "schema", "verdict", "release_gate", "source_commit", "source_tree",
    "governance_h_commit", "governance_s_commit", "artifact_count",
    "evidence_set_sha256", "formal_run_sha256", "formal_validation_sha256",
    "plan_sha256", "state_sha256", "raw_streams_retained",
]
MAX_FORMAL_LAUNCH_RECEIPT_BYTES = 65536
OFFLINE_GATES = [
    ("BUILD_ALL", "A64", ("<PINNED_PYTHON>", "-I", "-S", "-B", "tools/architecture/verify_v92_o01_rpc_failure_governance.py", "--build-all", "--node", "<PINNED_NODE>", "--pkg-node", "<PINNED_PKG_NODE>", "--ffmpeg", "<PINNED_FFMPEG>", "--release-tag", RELEASE_TAG), "official full Release build under exact Python/Node/npm/pkg-base/FFmpeg tool bindings PASS"),
    ("NODE22_FULL", "A64", ("<PINNED_PYTHON>", "-I", "-S", "-B", "tools/architecture/verify_v92_o01_rpc_failure_governance.py", "--node-tests", "FULL", "--node", "<PINNED_NODE>"), "pinned npm-ci/bootstrap and Node 22 nat_gateway full PASS"),
    ("A64_FOCAL", "A64", ("<PINNED_PYTHON>", "-I", "-S", "-B", "tools/architecture/verify_v92_o01_rpc_failure_governance.py", "--node-tests", "FOCAL", "--node", "<PINNED_NODE>"), "pinned npm-ci/bootstrap and A64 focal PASS"),
    ("MOD02_RUNTIME", "A64", ("<PINNED_PYTHON>", "-I", "-S", "-B", "tools/architecture/verify_v92_o01_rpc_failure_governance.py", "--powershell-gate", "MOD02_RUNTIME", "--node", "<PINNED_NODE>", "--executable", "<FRESH_A64_WORKTREE>/srchybrid/x64/Release/emule.exe", "--output-root", "<FRESH_MOD02_ROOT>", "--build-manifest", "<FRESH_MOD02_MANIFEST>", "--timeout-seconds", "180"), "MOD02 runtime characterization PASS"),
    ("G12_HOSTILE", "M64", ("<PINNED_PYTHON>", "-I", "-S", "-B", "tools/architecture/test_verify_v92_o01_rpc_failure_governance.py"), "G12 hostile governance PASS"),
    ("G12_VERIFY", "M64", ("<PINNED_PYTHON>", "-I", "-S", "-B", "tools/architecture/verify_v92_o01_rpc_failure_governance.py", "--verify"), "G12 sealed verifier PASS state=M64"),
    ("POWERSHELL_PARSE", "M64", ("<PINNED_PYTHON>", "-I", "-S", "-B", "tools/architecture/verify_v92_o01_rpc_failure_governance.py", "--powershell-parse"), "PowerShell parser 4/4 PASS"),
    ("RPC_PUMP_MOCK", "M64", ("<PINNED_PYTHON>", "-I", "-S", "-B", "tools/architecture/verify_v92_o01_rpc_failure_governance.py", "--powershell-gate", "RPC_PUMP_MOCK", "--node", "<PINNED_NODE>"), "formal RPC pump mock v3 PASS"),
    ("FORMAL_RUNNER_MOCK", "M64", ("<PINNED_PYTHON>", "-I", "-S", "-B", "tools/architecture/verify_v92_o01_rpc_failure_governance.py", "--powershell-gate", "FORMAL_RUNNER_MOCK", "--node", "<PINNED_NODE>"), "formal runner mock v2 PASS"),
    ("VM_SESSION_MOCK", "M64", ("<PINNED_PYTHON>", "-I", "-S", "-B", "tools/architecture/verify_v92_o01_rpc_failure_governance.py", "--powershell-gate", "VM_SESSION_MOCK", "--node", "<PINNED_NODE>"), "VM session mock PASS"),
    ("FORMAL_PRODUCT_MOCK", "M64", ("<PINNED_PYTHON>", "-I", "-S", "-B", "tools/architecture/verify_v92_o01_rpc_failure_governance.py", "--powershell-gate", "FORMAL_PRODUCT_MOCK", "--node", "<PINNED_NODE>"), "formal product mapper mock PASS"),
    ("PACKAGE_AUDIT", "M64", ("<PINNED_PYTHON>", "-I", "-S", "-B", "tools/architecture/verify_v92_o01_rpc_failure_governance.py", "--package-audit", "--package-root", f"<FRESH_A64_WORKTREE>/dist/{RELEASE_TAG}/package", "--zip", f"<FRESH_A64_WORKTREE>/{PACKAGE_ZIP_PATH}", "--node", "<PINNED_NODE>", "--release-tag", RELEASE_TAG), "fresh package and ZIP exact audit PASS"),
    ("DIFF_CHECK", "M64", ("<PINNED_PYTHON>", "-I", "-S", "-B", "tools/architecture/verify_v92_o01_rpc_failure_governance.py", "--diff-check"), "closed Git diff --check H63..M64 PASS"),
]
OLD_GOVERNANCE_VERIFIER = REPO / "tools/architecture/verify_v92_o01_clock_repair_governance.py"

GOVERNANCE_PATHS = [
    "docs/architecture/v92_o01_rpc_failure_governance_v1.json",
    "tools/architecture/test_verify_v92_o01_rpc_failure_governance.py",
    "tools/architecture/verify_v92_o01_rpc_failure_governance.py",
]
A_PATHS = [
    "tools/lab/nat_gateway/test/v92_o01_formal_controller.test.js",
    "tools/lab/nat_gateway/test/v92_o01_product_stream.test.js",
    "tools/lab/nat_gateway/test/v92_o01_t8_daemon.test.js",
    "tools/lab/nat_gateway/test/v92_o01_t8_fault_controller.test.js",
    "tools/lab/nat_gateway/test/v92_o01_validate_formal.test.js",
    "tools/lab/nat_gateway/v92_o01_formal_controller.js",
    "tools/lab/nat_gateway/v92_o01_product_stream.js",
    "tools/lab/nat_gateway/v92_o01_t8_fault_controller.js",
    "tools/lab/nat_gateway/v92_o01_validate_formal.js",
    "tools/lab/run_v92_o01_formal.ps1",
    "tools/lab/test_v92_o01_formal_rpc_pump_mock.ps1",
    "tools/lab/test_v92_o01_formal_runner_mock.ps1",
    "tools/lab/v92_o01_vm_session.psm1",
]
A_RUNTIME_PATHS = [
    "tools/lab/nat_gateway/v92_o01_formal_controller.js",
    "tools/lab/nat_gateway/v92_o01_product_stream.js",
    "tools/lab/nat_gateway/v92_o01_t8_fault_controller.js",
    "tools/lab/nat_gateway/v92_o01_validate_formal.js",
    "tools/lab/run_v92_o01_formal.ps1",
    "tools/lab/v92_o01_vm_session.psm1",
]
A_TEST_PATHS = sorted(set(A_PATHS) - set(A_RUNTIME_PATHS))
A_SHA256 = {
    "tools/lab/nat_gateway/test/v92_o01_formal_controller.test.js": "6582b334a209376bef5affe45d217a777038b0d25d94c0719ce232022fe350f1",
    "tools/lab/nat_gateway/test/v92_o01_product_stream.test.js": "23d8287473b514e483cc34bddd01682f341fc8e9e4af99d85a0b55aba8af0d4a",
    "tools/lab/nat_gateway/test/v92_o01_t8_daemon.test.js": "808883ae44f714c4a784b8ac6bd5b38fa5f6a4787388587e826d2bfb90a25518",
    "tools/lab/nat_gateway/test/v92_o01_t8_fault_controller.test.js": "035497cc96aa020b2a17a94cdc4207aed2e2a9745882eb36037a16505c8bb45e",
    "tools/lab/nat_gateway/test/v92_o01_validate_formal.test.js": "114e36daf1641f7efe7ad76d43a2d1315b1d1f0938f0330b8f5e8eccdb6867ae",
    "tools/lab/nat_gateway/v92_o01_formal_controller.js": "51fd16617074519e9c3e4b5fa6def91b246f0b9168cbc635617e1678be7cecf2",
    "tools/lab/nat_gateway/v92_o01_product_stream.js": "e60901bd560b538de5dee2e9be6e595ee607a6fa302d04c5f9dee27f0e59efb0",
    "tools/lab/nat_gateway/v92_o01_t8_fault_controller.js": "1497d8916f9ad9ed151717e3ab3274a9b518f998f118b2c465a71da3a79b8c3c",
    "tools/lab/nat_gateway/v92_o01_validate_formal.js": "c71d9245a8a8b4d06cf7b9ce0c8f06b0dbcbaf13b1331f736a27ba9c147e5f44",
    "tools/lab/run_v92_o01_formal.ps1": "727f6dbe4603181d973f4fe367eed051e033ea1ce6ec5fe949b0ea93e4e1b88d",
    "tools/lab/test_v92_o01_formal_rpc_pump_mock.ps1": "2796891eefa8e34d5e92be543d47eaf0f25b9fe94a9e83e745b7eb99016985ab",
    "tools/lab/test_v92_o01_formal_runner_mock.ps1": "7b57bc1dfbc682a9104bf508d2b924682a4a746b7f1d7a9b2ff162c696c2ec4e",
    "tools/lab/v92_o01_vm_session.psm1": "ecefa47cedea683ad014b273eca36a0a1b1a6efc2ea8dee7b0febb1925ca4280",
}
PATH_BUDGET = {
    "tools/lab/nat_gateway/test/v92_o01_formal_controller.test.js": (37, 12),
    "tools/lab/nat_gateway/test/v92_o01_product_stream.test.js": (20, 2),
    "tools/lab/nat_gateway/test/v92_o01_t8_daemon.test.js": (2, 1),
    "tools/lab/nat_gateway/test/v92_o01_t8_fault_controller.test.js": (72, 5),
    "tools/lab/nat_gateway/test/v92_o01_validate_formal.test.js": (11, 4),
    "tools/lab/nat_gateway/v92_o01_formal_controller.js": (162, 22),
    "tools/lab/nat_gateway/v92_o01_product_stream.js": (12, 2),
    "tools/lab/nat_gateway/v92_o01_t8_fault_controller.js": (47, 13),
    "tools/lab/nat_gateway/v92_o01_validate_formal.js": (42, 9),
    "tools/lab/run_v92_o01_formal.ps1": (109, 27),
    "tools/lab/test_v92_o01_formal_rpc_pump_mock.ps1": (365, 5),
    "tools/lab/test_v92_o01_formal_runner_mock.ps1": (379, 10),
    "tools/lab/v92_o01_vm_session.psm1": (82, 13),
}
BUDGET = (13, 1340, 125, 1215)
RUNTIME_BUDGET = (6, 454, 86, 368)
TEST_BUDGET = (7, 886, 39, 847)
A_PATHS_SHA256 = "b4eae66756761df10e056a858b1e8fab2fbb9aa684a4a33fb4f3698bb8179471"
A_BYTES_SHA256 = "5374ad9b7edeb335e48f12e714f29bb1c5b13231defc365e80eb3f7e47843a35"
A_NUMSTAT_SHA256 = "bbb993a0d0d30c8c6fcfe8d1de77e562f43e245071ce2d36c6c4967cef369cff"
GOVERNANCE_PATHS_SHA256 = "5296046b68bc18e2ed7be811eac5911d5d62283bbd97ca382f24bf06dc4943ca"

CHECKPOINT_FILE_SHA256 = {
    "checkpoint-01.json": "cf47bf18e9b31e6c8c9474cbbc13c8bbc8bce3e40a5ebde64af947c3358e4ed0",
    "checkpoint-02.json": "660bbdd2cbbe36df947e1522dedeb14e620be150ee1ed5af3d838a09e72059e2",
    "checkpoint-03.json": "f9cb8b581bcc80bda4249b54cc5d95c1b12df8c741e5df6954ce1a4734872026",
    "checkpoint-04.json": "169e6be9ac7a7598de7564a130f1021748f3835c8235d5df4a597fffff1015c7",
    "checkpoint-05.json": "08570d63ceb7a5c940b14888aa01386e59b9e2183078c4d5dcc1e26b01c3cd7c",
    "checkpoint-06.json": "76ceb45c21aee4251f0447e892ef40fe9e38a68dde0db4222c1d9d12887bff73",
}
CHECKPOINT_CHAIN = [
    (1, 300000, 6, "11a762a4a70ecb6ad80fa9a179ba08b0ffbda416a357729ed1b6a79e52a27572",
     "7b866446b1688f5d65deeb14c8895e801e96ec332e944062dddd77b7c8cdf5aa"),
    (2, 600000, 11, "7b866446b1688f5d65deeb14c8895e801e96ec332e944062dddd77b7c8cdf5aa",
     "0819b1243c108de7c78f287674cbb6e8af2159d43d89a2d730796e543e57ed2d"),
    (3, 900000, 16, "0819b1243c108de7c78f287674cbb6e8af2159d43d89a2d730796e543e57ed2d",
     "76c48a002febda9f4700ab9bc76fd7a9c7e55a93cb56c7875b21b93007cb24c0"),
    (4, 1200000, 21, "76c48a002febda9f4700ab9bc76fd7a9c7e55a93cb56c7875b21b93007cb24c0",
     "805806219d9a33221788158e2656ffdb5e78856bb4f2ffe7b3d027b353393211"),
    (5, 1500000, 26, "805806219d9a33221788158e2656ffdb5e78856bb4f2ffe7b3d027b353393211",
     "ec390b4fa1b313198c694358c5f1190344690fa1bdbfbb0ac3ceba48218bf"),
    (6, 1800000, 31, "ec390b4fa1b313198c694358c5f1190344690fa1bdbfbb0ac3ceba48218bf",
     "e8ad8bcbac7a1c7e7d40c6de39053a4a42c5dd4b50af845c6a65354e02683ae5"),
]

RPC_KEYS = [
    "schema", "verdict", "release_gate", "origin", "stage", "failure_code",
    "requests_handled", "next_sequence", "maximum_requests", "host_exit_code",
    "stderr_tail_chars", "stderr_tail_utf8_bytes", "stderr_tail_sha256",
    "last_checkpoint_ordinal", "last_checkpoint_record_sha256",
    "last_checkpoint_file_sha256",
]
RPC_ORIGINS = ["FORMAL_HOST", "LOCAL_PRODUCT", "RPC_PUMP"]
RPC_STAGES = ["HOST_EXIT", "PRODUCT_READ", "REQUEST_WAIT", "REQUEST_PARSE", "RESPONSE_WRITE"]
RPC_ORIGIN_STAGE_PAIRS = [
    "FORMAL_HOST:HOST_EXIT", "LOCAL_PRODUCT:PRODUCT_READ",
    "RPC_PUMP:REQUEST_PARSE", "RPC_PUMP:REQUEST_WAIT", "RPC_PUMP:RESPONSE_WRITE",
]
RPC_PUMP_CODES = {
    "RPC_PUMP:REQUEST_PARSE": ["O01_RPC_HOST_REQUEST_INVALID"],
    "RPC_PUMP:REQUEST_WAIT": ["O01_RPC_HOST_OUTPUT_CLOSED", "O01_RPC_HOST_REQUEST_TIMEOUT"],
    "RPC_PUMP:RESPONSE_WRITE": ["O01_RPC_HOST_WRITE_FAILED"],
}
RPC_LITERAL_COUNTS = {
    "O01RpcHostFailureCodes": 96,
    "O01RpcDependencyFailureCodes": 26,
    "O01RpcProductStreamFailureCodes": 14,
    "O01LocalProductFailureCodes": 17,
}
RPC_TUPLE_COUNTS = {
    "FORMAL_HOST:HOST_EXIT": 137,
    "LOCAL_PRODUCT:PRODUCT_READ": 17,
    "RPC_PUMP:REQUEST_PARSE": 1,
    "RPC_PUMP:REQUEST_WAIT": 2,
    "RPC_PUMP:RESPONSE_WRITE": 1,
}
RPC_CODE_ALLOWLIST_SHA256 = "6d8b980de18f481a7eeeae71e3df1f1b608d72f135bf6f34188daabb69dc3163"
RPC_TUPLE_ALLOWLIST_SHA256 = "b34608e728957967092bc02dbe4bf197d5e642528f94b61685f7a7a54101a5ed"
RPC_CANONICAL_REPRESENTATION = (
    "Deduplicate exact strings, sort with Windows PowerShell Sort-Object under "
    "Spanish_Spain.1252 collation, serialize the resulting array as compact ASCII JSON "
    "without a trailing newline; tuple strings are origin:stage:code."
)
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
FORBIDDEN_RPC_FIELDS = [
    "message", "stack", "stderr", "stdout", "path", "username",
    "hostname", "ip", "command_line", "environment", "secret", "timestamp",
]
THREAT_MODEL = {
    "evidence_root": "Concurrent mutation of EvidenceRoot/controller is adversarial and is guarded during validation by persistent FileShare.Read handles over the exact 98 admitted carrier files, plan.json and state.json, plus guarded root/controller directories and exact-set rechecks.",
    "persistent_inputs": "Persistent tracked-source identity is enforced byte-exactly outside libutp; libutp is recursively bound to its exact gitlink, index and Git-blob contents under fixed core.autocrlf=true, so LF/CRLF-only worktree materializations are intentionally equivalent and every other persistent tracked-source change fails. Persistent build Python dependency projection, Node/npm/pkg-base inputs, host PackageRoot manifest/set, initial guest runtime projection, process inputs and enumerated VM identity/topology/baseline fields fail the forced-worktree, byte-hash, identity, baseline-restoration and binding checks.",
    "distribution_artifact": "The release ZIP is a post-build distribution artifact bound by the M64/H64 package audit and reviews; it is not read by the physical runner and is not claimed as a runtime input.",
    "trusted_host_toolchain": "The Windows kernel/filesystem, System32 PowerShell/cmd, canonical Program Files Git and installed MSVC/Windows SDK targets, plus the native DLLs and standard library of the pinned Python installation, are trusted host TCB. Entry executables are path/hash/version checked and ambient redirection variables/configuration are closed, but G12 does not claim a byte-reproducible attestation of the complete host toolchain.",
    "trusted_lab_fixture": "The pre-provisioned v92-o01-client VM, its initial base-VHD bytes, firmware/configuration, guest OS and credential semantics are trusted lab TCB for the full physical run. The gate fixes the VM name and checks initial Off/Disabled/no-checkpoint state, VMId, one NIC/MAC/switch, one disk path/slot, a fresh differencing child and exact restoration of those enumerated fields; it does not authenticate the initial base VHD or every guest/configuration byte.",
    "out_of_scope": "Any writer capable of altering or controlling the trusted host TCB, trusted lab fixture or validating process itself, and any privileged adaptive writer capable of replacing or controlling the repository, Node runtime or PackageRoot while evading the closed checks, is outside this release gate's threat boundary.",
    "claim_limit": "G12 does not claim universal TOCTOU protection, byte authentication of the initial base VHD or every VM/guest setting; it claims only the explicit handle, hash, clean-worktree, enumerated-baseline and binding guarantees above.",
}
FORMAL_LAUNCH_CONTRACT = {
    "schema": "ese.v92.o01-formal-launch-contract/v1",
    "state": "A64_ONLY_AFTER_VERIFIED_H64",
    "mode": "G12 --formal-run",
    "required_arguments": [
        "--h-commit", "--evidence-root", "--package-root", "--node",
        "--credential-path",
    ],
    "powershell_rule": "Launch only the canonical System32 Windows PowerShell 5.1 executable with its immutable SHA-256, in a new noninteractive no-profile process; the A64 runner rejects every different executable, flag order, VM name, GovernanceS value or parameter tail before operational cmdlets.",
    "argv_rule": "The outer formal CLI requires the five named arguments exactly once in the documented order, without abbreviations or equals-form aliases. The launcher derives ExpectedExeSha256, ExpectedBuildInfoSha256, ExpectedPackageManifestSha256 and ExpectedNodeSha256 from verified H64 activation, fixes VMName=v92-o01-client and omits GovernanceSCommit; caller-supplied expected hashes or free-form runner flags are forbidden.",
    "environment_rule": "The child cwd and profile directories are fresh private temporary directories. The environment is rebuilt case-insensitively with closed SystemRoot/cmd/PATH/PATHEXT/PSModulePath and Git configuration; inherited GIT_, NODE/NODE_*, OPENSSL_*, COR_, COMPLUS_, DOTNET_, MSBuild and PowerShell injection variables are absent.",
    "receipt_exact_keys": FORMAL_LAUNCH_RECEIPT_KEYS,
    "receipt_identity_rule": "The runner emits one compact ASCII JSON receipt with CRLF. evidence_set_sha256 is SHA-256 of compact ASCII canonical JSON {artifacts:[{name,sha256}]} for the 98 ordinal-sorted controller file names and bytes; plan_sha256 and state_sha256 bind the final root metadata; the launcher recomputes and requires exact receipt equality.",
    "stream_rule": "stdout is bounded to 65536 bytes and must be exactly the single receipt plus CRLF; stderr is drained without retention and must be empty. Raw child streams, credential bytes and free-form child errors never enter EvidenceRoot, the gate result or failure reason.",
    "evidence_rule": "EvidenceRoot is fresh and ends with eSE-v9.2-o01-formal-<12 lowercase hex>; its final top level is exactly controller, plan.json and state.json, state phase is TORN_DOWN, controller is exact98, and the receipt, formal schemas, hashes and independent Node validator all agree.",
    "sandwich_rule": "Before PASS, G12 revalidates exact A64 source identity (byte-exact tracked files outside libutp; exact libutp gitlink, index and Git-blob contents under fixed core.autocrlf=true), H64 topology/activation, runner, canonical PowerShell, full pinned Node distribution, PackageRoot manifest/set/bindings, credential source, guarded exact98 and guarded plan/state; one handle epoch remains open from authenticated receipt admission through the final stdout write and flush.",
    "cleanup_rule": "The isolated credential, child runtime/scratch, raw captures and temporary launcher tree must be absent before PASS. Any failure after authenticated ownership marks the exact formal-run and formal-validation handles delete-pending before guard release, applies an identity-checked fallback, and emits no release result.",
    "r64_validator_node_path": str(PINNED_NODE_PATH),
    "direct_runner_invocation": "NON_RELEASE",
}
CAUSAL_CLOSURE = {
    "status": "DETERMINISTIC_REPRODUCERS_REPAIRED_WITHOUT_HISTORICAL_ATTRIBUTION",
    "a163_observation": "a163 proves six linked checkpoints through product sequence 31, then a generic O01_RPC_HOST_FAILED terminal and a clean TORN_DOWN rollback; it does not preserve the exact sample-32 state, exception or a unique underlying root cause.",
    "historical_attribution": "No underlying mechanism is attributed to a163 from the generic fallback alone.",
    "deterministic_reproducers": [
        {
            "id": "PRODUCT_STATE_ENUM_CONTRACT",
            "mechanism": "The formal mapper can emit DISABLED, DISCOVERING, VERIFIED and WITHDRAWN while the product stream previously rejected those legitimate closed states.",
            "repair": "The stream, controller and independent validator now share the closed product-state contract with bounded transient and terminal semantics.",
            "tests": "Node 22 product-stream, controller and rechained-validator hostile tests",
        },
        {
            "id": "REPLAY_EXACT_KEY_TRANSACTION",
            "mechanism": "replay_duplicate previously consumed its armed fault before an exact committed response cache existed and could expose or correlate an uncommitted replay buffer.",
            "repair": "Exact-key replay is primed and promoted only transactionally after pair commit; mismatched keys remain armed and correlated retries are closed over both pair members.",
            "tests": "Node 22 fault-controller and UDP-mux transactional replay tests",
        },
    ],
    "hardening": "Structured rpc-failure evidence, origin-stage-code binding, checkpoint causality, evidence-root handle guards and independent validator tightening are defensive closure and are not retrospective attribution.",
    "release_adjudication": "Only a fresh uninterrupted R64 exact-98 PASS sourced from frozen A64 and the M64 executable may adjudicate release readiness.",
}
SCOPE = (
    "V92-O01 rc.1 only: preserve a closed structured RPC failure observation, "
    "freeze the deterministic reproducers and release-gate hardening without attributing "
    "a unique a163 root cause, rebuild from frozen A64, reseal MOD02 and admit release only through a "
    "fresh uninterrupted direct-R64 PASS."
)
PHASE_MERGE_POLICY = (
    "Every G12/A64/M64/H64/R64 commit has exactly one parent; merges, squash/rebase "
    "substitution, intermediate commits, resume and reused evidence are rejected."
)
FREEZE_PREREQUISITES = [
    "closed structured causal observation or deterministic reproducer",
    "final implementation and hostile tests",
    "stable exact git diff with no unrelated path",
    "independent P0/P1/P2 review",
]
DRAFT_GATES = [
    "<PINNED_PYTHON> -I -S -B tools/architecture/test_verify_v92_o01_rpc_failure_governance.py",
    "<PINNED_PYTHON> -I -S -B tools/architecture/verify_v92_o01_rpc_failure_governance.py --document",
    "<PINNED_PYTHON> -I -S -B tools/architecture/verify_v92_o01_rpc_failure_governance.py --check-worktree",
]
SEALED_GATES = [
    "Node 22 complete nat_gateway suite",
    "A64 focal product stream, fault controller, formal controller, host and RPC suite",
    "PowerShell parser for every changed ps1 and psm1",
    "formal RPC pump, VM session and runner mocks",
    "G12 hostile governance suite",
    "exact A64 byte and zero-headroom budget verifier",
    "official full Release x64 rebuild from clean A64",
    "post-build package manifest and distribution ZIP audit",
    "M64 MOD02 verifier and runtime reseal",
    "H64 independent Sol and Terra empty-finding reviews",
    "git diff --check",
]
STOP_CONDITIONS = [
    "A64 paths, SHA-256, numstat or budget are frozen before causal stabilization",
    "a speculative underlying host fix is claimed from O01_RPC_HOST_FAILED alone",
    "any a163 checkpoint, failure or launcher artifact is reused or enters M64, H64 or R64",
    "rpc-failure.json is overwritten, contains an open or free-form field, appears on PASS or enters R64",
    "failure projection and rpc-failure.json code or byte identity disagree",
    "scenario, mapper, 370000 ms checkpoint gap, derived 70000 ms bounds, 300000 ms initial watchdog, 140000 ms subsequent watchdog or 21 bound files change",
    "G12 is not the direct child of H63, G11 changes, or any phase has a merge or intermediate commit",
    "M64 reuses M63 build evidence or is not one fresh clean official full Release build bound to A64",
    "source, Node, host PackageRoot manifest/set, initial guest runtime projection, M64/H64 binding, enumerated VM identity/topology/baseline fields or evidence root changes during the run",
    "the post-build distribution ZIP identity is absent from the review-attested H64 build-artifact binding",
    "BUILD_ALL and PACKAGE_AUDIT package snapshot identities disagree",
    "the physical runner is invoked directly or without the exact G12 --formal-run argv, environment, receipt, guarded evidence and final sandwich contract",
    "initial base-VHD, guest OS, firmware or unenumerated VM configuration is claimed as byte-authenticated rather than trusted lab TCB",
    "P0, P1, P2 or any nonempty review finding",
    "release_gate=true before independent validation and exact baseline restoration",
]
ACTIVATION_RULE = (
    "This sealed amendment stores no invented future commit identity. The verifier derives "
    "exact direct Git parentage, and H64 activation must bind the complete G12 triad, A64 "
    "path/byte/numstat identities, both RPC allowlist identities, immutable blobs and M64/H64 "
    "carrier identities."
)


class GateError(RuntimeError):
    pass


class GateArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise GateError("command-line arguments")


def require(condition: bool, label: str) -> None:
    if not condition:
        raise GateError(label)


def exact_keys(value: Any, keys: Iterable[str], label: str) -> None:
    require(isinstance(value, dict), f"{label}: object required")
    require(set(value) == set(keys), f"{label}: exact keys")


def require_exact_value(value: Any, expected: Any, label: str) -> None:
    require(canonical(value) == canonical(expected), label)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def ordered_canonical(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def observed_budget(stats: dict[str, tuple[int, int]], paths: Iterable[str] | None = None) -> tuple[int, int, int, int]:
    selected = list(stats) if paths is None else list(paths)
    added = sum(stats[path][0] for path in selected)
    deleted = sum(stats[path][1] for path in selected)
    return len(selected), added, deleted, added - deleted


def budget_document(stats: dict[str, tuple[int, int]]) -> dict[str, dict[str, int]]:
    return {
        path: {"add": stats[path][0], "delete": stats[path][1],
               "net": stats[path][0] - stats[path][1]}
        for path in sorted(stats)
    }


def path_hash_document(values: dict[str, str]) -> dict[str, str]:
    return {path: values[path] for path in sorted(values)}


def _literal_assignment_codes(raw: str, name: str) -> list[str]:
    pattern = re.compile(r"\$script:" + re.escape(name) + r"=@\(([^\r\n]*?)\)")
    matches = pattern.findall(raw)
    require(len(matches) >= 1, f"RPC source assignment: {name}")
    # The first Host assignment is the byte-pinned base list; later assignments are derived unions.
    values = re.findall(r"'([^']+)'", matches[0])
    require(len(values) == len(set(values)), f"RPC source duplicates: {name}")
    return values


def _windows_canonical_sort(values: Iterable[str]) -> list[str]:
    previous = locale.setlocale(locale.LC_COLLATE)
    try:
        locale.setlocale(locale.LC_COLLATE, "Spanish_Spain.1252")
        return sorted(set(values), key=locale.strxfrm)
    except locale.Error as exc:
        raise GateError("Windows canonical collation unavailable") from exc
    finally:
        locale.setlocale(locale.LC_COLLATE, previous)


def derive_rpc_allowlists(raw: bytes | None = None) -> tuple[dict[str, list[str]], list[str], list[str]]:
    if raw is None:
        raw = (REPO / "tools/lab/v92_o01_vm_session.psm1").read_bytes()
    require(sha256(raw) == A_SHA256["tools/lab/v92_o01_vm_session.psm1"],
            "RPC allowlist source identity")
    text = raw.decode("utf-8")
    sources = {name: _literal_assignment_codes(text, name) for name in RPC_LITERAL_COUNTS}
    require({name: len(values) for name, values in sources.items()} == RPC_LITERAL_COUNTS,
            "RPC literal source counts")
    host = _windows_canonical_sort(
        sources["O01RpcHostFailureCodes"]
        + sources["O01RpcDependencyFailureCodes"]
        + sources["O01RpcProductStreamFailureCodes"]
        + ["O01_RPC_HOST_FAILED"]
    )
    local = _windows_canonical_sort(sources["O01LocalProductFailureCodes"])
    tuples = {
        "FORMAL_HOST:HOST_EXIT": host,
        "LOCAL_PRODUCT:PRODUCT_READ": local,
        **{key: list(values) for key, values in RPC_PUMP_CODES.items()},
    }
    require({key: len(values) for key, values in tuples.items()} == RPC_TUPLE_COUNTS,
            "RPC tuple counts")
    tuple_strings = _windows_canonical_sort(
        f"{pair}:{code}" for pair, codes in tuples.items() for code in codes
    )
    unique_codes = _windows_canonical_sort(code for codes in tuples.values() for code in codes)
    require(len(tuple_strings) == 158 and len(unique_codes) == 158, "RPC allowlist cardinality")
    require(sha256(ordered_canonical(unique_codes)) == RPC_CODE_ALLOWLIST_SHA256,
            "RPC code allowlist identity")
    require(sha256(ordered_canonical(tuple_strings)) == RPC_TUPLE_ALLOWLIST_SHA256,
            "RPC tuple allowlist identity")
    return tuples, unique_codes, tuple_strings


def require_sha(value: Any, label: str) -> None:
    require(isinstance(value, str) and HEX64.fullmatch(value) is not None, label)


def require_int(value: Any, low: int, high: int, label: str) -> None:
    require(type(value) is int and low <= value <= high, label)


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise GateError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    require(not raw.startswith(b"\xef\xbb\xbf"), "document BOM")
    require(b"\r" not in raw and raw.endswith(b"\n"), "document encoding")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GateError("document JSON") from exc
    require(isinstance(value, dict), "document object")
    return value, raw


def load_json_bytes(raw: bytes, label: str) -> dict[str, Any]:
    require(raw and not raw.startswith(b"\xef\xbb\xbf") and b"\r" not in raw and
            raw.endswith(b"\n"), f"{label} encoding")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GateError(f"{label} JSON") from exc
    require(isinstance(value, dict), f"{label} object")
    return value


def _normal_path(value: Any, label: str) -> None:
    require(isinstance(value, str) and value != "", label)
    path = PurePosixPath(value)
    require(not path.is_absolute() and ".." not in path.parts and "\\" not in value, label)


def normalized_verifier_sha256(raw: bytes) -> str:
    require(len(DOCUMENT_ASSIGNMENT.findall(raw)) == 1, "verifier document pin cardinality")
    normalized = DOCUMENT_ASSIGNMENT.sub(
        b'DOCUMENT_SHA256 = "' + (b"0" * 64) + b'"', raw,
    )
    return sha256(normalized)


def verify_governance_tool_identity(document: dict[str, Any], reader) -> None:
    identity = document["governance_tool_identity"]
    exact_keys(identity, [
        "verifier_normalization", "verifier_normalized_sha256", "hostile_test_sha256",
    ], "governance tool identity")
    require(identity["verifier_normalization"] == VERIFIER_NORMALIZATION_RULE,
            "verifier normalization rule")
    require_sha(identity["verifier_normalized_sha256"], "normalized verifier SHA-256")
    require_sha(identity["hostile_test_sha256"], "hostile test SHA-256")
    require(normalized_verifier_sha256(reader(GOVERNANCE_PATHS[2])) ==
            identity["verifier_normalized_sha256"], "normalized verifier identity")
    require(sha256(reader(GOVERNANCE_PATHS[1])) == identity["hostile_test_sha256"],
            "hostile test identity")


def validate_document(document: dict[str, Any]) -> None:
    exact_keys(document, [
        "schema", "status", "amendment", "base", "historical_contract",
        "diagnostic_attempt", "scope", "threat_model", "topology", "phase_contract",
        "governance_paths", "governance_paths_sha256", "governance_tool_identity",
        "functional_surface",
        "rpc_failure_contract", "immutable_contract", "carrier_paths",
        "formal_launch_contract",
        "required_reviews", "draft_gates", "sealed_gates", "stop_conditions",
        "gate_attestation_contract", "h64_review_contract",
        "h64_activation_contract", "activation_state",
    ], "document")
    require(document["schema"] == "ese.v92.o01-rpc-failure-governance/v1", "schema")
    require(document["status"] == "SEALED_G12_A64_CAUSAL_FREEZE", "status")
    require(document["amendment"] == "G12", "amendment")
    require_exact_value(document["base"], BASE, "base identities")
    require(document["scope"] == SCOPE, "scope")

    history = document["historical_contract"]
    exact_keys(history, [
        "g11_governance_sha256", "m63_carrier_sha256", "h63_carrier_sha256", "rule",
    ], "historical contract")
    require_exact_value(history["g11_governance_sha256"], G11_SHA256,
                        "G11 byte identities")
    require_exact_value(history["m63_carrier_sha256"], M63_SHA256,
                        "M63 byte identities")
    require_exact_value(history["h63_carrier_sha256"], H63_SHA256,
                        "H63 byte identities")
    require(history["rule"] ==
            "G11, A63, M63, H63 and all their governed carriers remain byte-exact; "
            "G12 is additive and never edits G11.", "historical rule")

    attempt = document["diagnostic_attempt"]
    exact_keys(attempt, [
        "attempt_id", "evidence_id", "classification", "release_gate",
        "evidence_reuse", "source_commit", "source_tree", "governance_h_commit",
        "checkpoint_schema", "checkpoint_count", "checkpoint_ordinals",
        "checkpoint_file_sha256", "checkpoint_chain", "terminal_failure",
        "launcher", "rollback", "rule",
    ], "diagnostic attempt")
    require(attempt["attempt_id"] == "a163", "attempt id")
    require(attempt["evidence_id"] == "eSE-v9.2-o01-formal-bba779d0a163", "evidence id")
    require(attempt["classification"] == "NON_RELEASE_DIAGNOSTIC_ONLY", "classification")
    require(attempt["release_gate"] is False, "diagnostic release gate")
    require(attempt["evidence_reuse"] == "FORBIDDEN", "diagnostic reuse")
    require(attempt["source_commit"] == BASE["a63_commit"], "diagnostic source")
    require(attempt["source_tree"] == BASE["a63_tree"], "diagnostic source tree")
    require(attempt["governance_h_commit"] == BASE["h63_commit"], "diagnostic governance")
    require(attempt["checkpoint_schema"] == "ese.v92.o01-checkpoint/v2", "checkpoint schema")
    require_int(attempt["checkpoint_count"], 6, 6, "checkpoint count")
    require_exact_value(attempt["checkpoint_ordinals"], list(range(1, 7)),
                        "checkpoint ordinals")
    require_exact_value(attempt["checkpoint_file_sha256"], CHECKPOINT_FILE_SHA256,
                        "checkpoint files")
    require(isinstance(attempt["checkpoint_chain"], list) and len(attempt["checkpoint_chain"]) == 6,
            "checkpoint chain count")
    for value, expected in zip(attempt["checkpoint_chain"], CHECKPOINT_CHAIN):
        exact_keys(value, [
            "ordinal", "elapsed_ms", "product_sequence", "previous_sha256", "record_sha256",
        ], "checkpoint record")
        actual = (
            value["ordinal"], value["elapsed_ms"], value["product_sequence"],
            value["previous_sha256"], value["record_sha256"],
        )
        require_exact_value(list(actual), list(expected), "checkpoint chain identity")
    for left, right in zip(attempt["checkpoint_chain"], attempt["checkpoint_chain"][1:]):
        require(right["previous_sha256"] == left["record_sha256"], "checkpoint linkage")

    terminal = attempt["terminal_failure"]
    exact_keys(terminal, [
        "schema", "file_sha256", "verdict", "release_gate", "primary_failure",
        "failure_codes", "error_types", "records_examined", "product_cycle_observation",
    ], "terminal failure")
    require_exact_value(terminal, {
        "schema": "ese.v92.o01-formal-failure/v2",
        "file_sha256": "72dbdcf0f0fe525e39087a98094d6b2177a4958d563b348998ed4b5b9297b8cc",
        "verdict": "FAIL", "release_gate": False,
        "primary_failure": "O01_RPC_HOST_FAILED",
        "failure_codes": ["O01_RPC_HOST_FAILED"],
        "error_types": ["INVALID_OPERATION"], "records_examined": 1,
        "product_cycle_observation": None,
    }, "terminal failure identity")
    require_exact_value(attempt["launcher"], {
        "schema": "ese.v92.o01-formal-launcher/v1",
        "file_sha256": "ee08371000a2cc45cab148c4888804f79fc0137e6f411f4d5c4a4c42960bbdb4",
        "state": "FAILED", "stage": "FORMAL_RECONCILE",
        "code": "O01_FORMAL_FAILURE_EVIDENCE", "exit_code": 1,
    }, "launcher identity")
    require_exact_value(attempt["rollback"], {
        "state_schema": "ese.v92.t8-hyperv-state/v1",
        "state_file_sha256": "79cf24d70d216e276f659b8a1ab7024c157faddde6ea065e3d9956c2dfbb7140",
        "phase": "TORN_DOWN", "completed": True,
        "created_resource_flags": {"switch": False, "gateway_address": False, "nat": False},
        "rollback_failures": [],
    }, "rollback identity")
    require(attempt["rule"] ==
            "The six checkpoints and terminal failure are coherent diagnostic evidence "
            "only; none may be copied, resumed or admitted into M64, H64 or R64.",
            "diagnostic rule")
    require_exact_value(document["threat_model"], THREAT_MODEL, "threat model")

    require_exact_value(document["governance_paths"], GOVERNANCE_PATHS,
                        "governance paths")
    require(document["governance_paths_sha256"] == GOVERNANCE_PATHS_SHA256,
            "governance path identity")
    require(sha256(ordered_canonical(GOVERNANCE_PATHS)) == GOVERNANCE_PATHS_SHA256,
            "governance path canonical identity")
    for path in GOVERNANCE_PATHS:
        _normal_path(path, "governance path")
    identity = document["governance_tool_identity"]
    exact_keys(identity, [
        "verifier_normalization", "verifier_normalized_sha256", "hostile_test_sha256",
    ], "governance tool identity")
    require(identity["verifier_normalization"] == VERIFIER_NORMALIZATION_RULE and
            isinstance(identity["verifier_normalized_sha256"], str) and
            HEX64.fullmatch(identity["verifier_normalized_sha256"]) and
            isinstance(identity["hostile_test_sha256"], str) and
            HEX64.fullmatch(identity["hostile_test_sha256"]),
            "governance tool identity shape")
    topology = document["topology"]
    exact_keys(topology, ["G12", "A64", "M64", "H64", "R64"], "topology")
    for phase, parent in (("G12", "H63"), ("A64", "G12"), ("M64", "A64"),
                          ("H64", "M64"), ("R64", "H64")):
        require(f"direct child of {parent}" in topology[phase], f"{phase} topology")
    require_exact_value(topology, {
        "G12": "direct child of H63; exactly this amendment, verifier and hostile verifier test",
        "A64": "direct child of G12; exact functional paths, bytes and per-path numstat are frozen only after causal stabilization",
        "M64": "direct child of A64; exactly four carriers from one fresh official full Release build and MOD02 reseal",
        "H64": "direct child of M64; exactly four governance carriers with two independent empty-finding approvals",
        "R64": "direct child of H64; exactly 98 PASS artifacts from one uninterrupted eight-hour run sourced from A64 and the M64 executable",
    }, "topology identity")
    phases = document["phase_contract"]
    exact_keys(phases, ["schema", "merge_policy", "G12", "A64", "M64", "H64", "R64"],
               "phase contract")
    require(phases["schema"] == "ese.v92.o01-rpc-repair-phases/v1", "phase schema")
    require(phases["merge_policy"] == PHASE_MERGE_POLICY, "merge policy")
    require_exact_value(phases["G12"], {"parent": "H63", "delta": "governance_paths"},
                        "G12 phase")
    require_exact_value(phases["A64"], {
        "parent": "G12", "delta": "frozen_functional_paths_after_causal_stabilization",
    }, "A64 phase")
    require_exact_value(phases["M64"], {
        "parent": "A64", "delta": "m_carrier_paths",
        "build": "fresh official full Release rebuild from clean A64",
    }, "M64 phase")
    require_exact_value(phases["H64"], {"parent": "M64", "delta": "h_carrier_paths"},
                        "H64 phase")
    require_exact_value(phases["R64"], {
        "parent": "H64", "source": "A64", "governance": "H64",
        "executable": "exact_M64_manifest_executable_sha256", "release_gate": True,
    }, "R64 phase")

    surface = document["functional_surface"]
    exact_keys(surface, [
        "freeze_status", "frozen_paths", "runtime_paths", "test_paths", "path_sha256",
        "paths_sha256", "byte_identity_sha256", "per_path_numstat",
        "numstat_identity_sha256", "budget", "causal_closure", "rule",
    ], "functional surface")
    require(surface["freeze_status"] == "SEALED_EXACT_ZERO_HEADROOM", "freeze status")
    require_exact_value(surface["frozen_paths"], A_PATHS, "A64 paths")
    require(A_PATHS == sorted(set(A_PATHS)), "A64 path constant")
    require_exact_value(surface["runtime_paths"], A_RUNTIME_PATHS, "A64 runtime paths")
    require(A_RUNTIME_PATHS == sorted(set(A_RUNTIME_PATHS)), "A64 runtime path constant")
    require_exact_value(surface["test_paths"], A_TEST_PATHS, "A64 test paths")
    require(A_TEST_PATHS == sorted(set(A_TEST_PATHS)), "A64 test path constant")
    require(set(A_RUNTIME_PATHS).isdisjoint(A_TEST_PATHS) and
            sorted(A_RUNTIME_PATHS + A_TEST_PATHS) == A_PATHS, "A64 slices")
    for path in A_PATHS:
        _normal_path(path, "A64 path")
    require_exact_value(surface["path_sha256"], A_SHA256, "A64 per-path SHA-256")
    require(surface["paths_sha256"] == A_PATHS_SHA256 and
            sha256(ordered_canonical(A_PATHS)) == A_PATHS_SHA256, "A64 path identity")
    require(surface["byte_identity_sha256"] == A_BYTES_SHA256 and
            sha256(ordered_canonical(path_hash_document(A_SHA256))) == A_BYTES_SHA256,
            "A64 byte identity")
    expected_numstat = budget_document(PATH_BUDGET)
    require_exact_value(surface["per_path_numstat"], expected_numstat,
                        "A64 per-path numstat")
    require(surface["numstat_identity_sha256"] == A_NUMSTAT_SHA256 and
            sha256(ordered_canonical(expected_numstat)) == A_NUMSTAT_SHA256,
            "A64 numstat identity")
    require_exact_value(surface["budget"], {
        "all": {"path_count": BUDGET[0], "add_exact": BUDGET[1],
                "delete_exact": BUDGET[2], "net_exact": BUDGET[3],
                "headroom": 0},
        "runtime": {"path_count": RUNTIME_BUDGET[0],
                    "add_exact": RUNTIME_BUDGET[1],
                    "delete_exact": RUNTIME_BUDGET[2],
                    "net_exact": RUNTIME_BUDGET[3], "headroom": 0},
        "tests": {"path_count": TEST_BUDGET[0],
                  "add_exact": TEST_BUDGET[1],
                  "delete_exact": TEST_BUDGET[2],
                  "net_exact": TEST_BUDGET[3], "headroom": 0},
    }, "A64 zero-headroom budget")
    require(observed_budget(PATH_BUDGET) == BUDGET and
            observed_budget(PATH_BUDGET, A_RUNTIME_PATHS) == RUNTIME_BUDGET and
            observed_budget(PATH_BUDGET, A_TEST_PATHS) == TEST_BUDGET,
            "A64 computed budgets")
    require_exact_value(surface["causal_closure"], CAUSAL_CLOSURE,
                        "causal closure exact identity")
    require(surface["rule"] ==
            "A64 is frozen to these exact thirteen paths, bytes and zero-headroom per-path "
            "and slice budgets; compensation, extra paths and byte drift are rejected.",
            "freeze rule")

    rpc = document["rpc_failure_contract"]
    exact_keys(rpc, [
        "status", "path", "schema", "write_policy", "required_exact_keys",
        "origin_enum", "stage_enum", "origin_stage_pairs", "code_policy",
        "code_allowlist", "integer_bounds", "relational_rules", "nullable_fields",
        "sha256_fields", "forbidden_fields", "binding_rule", "pass_rule",
    ], "RPC failure contract")
    require(rpc["status"] == "FROZEN_A64_EXACT", "RPC status")
    require(rpc["path"] == "controller/rpc-failure.json", "RPC path")
    require(rpc["schema"] == "ese.v92.o01-rpc-failure/v1", "RPC schema")
    require_exact_value(rpc["required_exact_keys"], RPC_KEYS, "RPC exact keys")
    require_exact_value(rpc["origin_enum"], RPC_ORIGINS, "RPC origins")
    require_exact_value(rpc["stage_enum"], RPC_STAGES, "RPC stages")
    require_exact_value(rpc["origin_stage_pairs"], RPC_ORIGIN_STAGE_PAIRS,
                        "RPC origin/stage pairs")
    expected_allowlist = {
        "derivation_source": "tools/lab/v92_o01_vm_session.psm1",
        "source_sha256": A_SHA256["tools/lab/v92_o01_vm_session.psm1"],
        "literal_source_counts": RPC_LITERAL_COUNTS,
        "tuple_counts": RPC_TUPLE_COUNTS,
        "pump_codes": RPC_PUMP_CODES,
        "tuple_slot_count": 158,
        "unique_code_count": 158,
        "canonical_representation": RPC_CANONICAL_REPRESENTATION,
        "code_allowlist_sha256": RPC_CODE_ALLOWLIST_SHA256,
        "tuple_allowlist_sha256": RPC_TUPLE_ALLOWLIST_SHA256,
    }
    require_exact_value(rpc["code_allowlist"], expected_allowlist,
                        "RPC code allowlist")
    require_exact_value(rpc["integer_bounds"], {
        "requests_handled": [0, 482], "next_sequence": [1, 483],
        "maximum_requests": [1, 482],
        "host_exit_code_when_present": [-2147483648, 2147483647],
        "stderr_tail_chars": [0, 16384], "stderr_tail_utf8_bytes": [0, 49152],
        "last_checkpoint_ordinal": [0, 95],
    }, "RPC integer bounds")
    require_exact_value(rpc["relational_rules"], [
        "next_sequence equals requests_handled plus one",
        "requests_handled is not greater than maximum_requests",
        "next_sequence is not greater than maximum_requests plus one",
        "FORMAL_HOST requires a nonzero signed-32-bit host_exit_code; LOCAL_PRODUCT requires null; RPC_PUMP permits null or a nonzero signed-32-bit value",
        "LOCAL_PRODUCT requires at least one handled request because its failing response is included before checkpoint causality is evaluated",
        "stderr_tail_utf8_bytes is not less than stderr_tail_chars and zero characters iff zero bytes iff stderr_tail_sha256 equals SHA-256 of the empty string",
        "last_checkpoint_ordinal is at most max(0,floor((effective_requests-1)/5)); effective_requests is requests_handled for FORMAL_HOST and RPC_PUMP and requests_handled minus one for LOCAL_PRODUCT",
        "last_checkpoint_ordinal zero requires both checkpoint hashes null; nonzero requires both lowercase SHA-256 values and the reader revalidates their exact persisted checkpoint chain",
        "the failure/v3 projection binds the exact rpc-failure.json SHA-256, its failure_code as primary_failure and the unique current checkpoint binding",
    ], "RPC relational rules")
    require_exact_value(rpc["nullable_fields"], [
        "host_exit_code", "last_checkpoint_record_sha256", "last_checkpoint_file_sha256",
    ], "RPC nullable fields")
    require_exact_value(rpc["sha256_fields"], [
        "stderr_tail_sha256", "last_checkpoint_record_sha256", "last_checkpoint_file_sha256",
    ], "RPC SHA fields")
    require_exact_value(rpc["forbidden_fields"], FORBIDDEN_RPC_FIELDS,
                        "RPC privacy fields")
    require(rpc["write_policy"] ==
            "create-exclusive and durable; never overwrite, append, resume or reuse",
            "RPC write policy")
    require(rpc["code_policy"] ==
            "Unknown or open FORMAL_HOST messages map to O01_RPC_HOST_FAILED; unknown or "
            "open LOCAL_PRODUCT messages map to O01_PRODUCT_READ_REMOTE; RPC_PUMP admits "
            "only the four exact tuple codes; no free-form message is copied.",
            "RPC code policy")
    require(rpc["binding_rule"] ==
            "The ese.v92.o01-formal-failure/v3 terminal projection rereads and validates "
            "the exclusive rpc-failure.json, binds its exact byte identity in "
            "rpc_failure_sha256, agrees on the unique closed primary failure_code and "
            "revalidates the persisted checkpoint chain named by the sidecar.",
            "RPC binding")
    require(rpc["pass_rule"] ==
            "rpc-failure.json is diagnostic-only, release_gate=false and absent from "
            "every PASS result and R64.", "RPC PASS rule")

    immutable = document["immutable_contract"]
    require_exact_value(immutable, {
        "scenario_path": "tools/lab/nat_gateway/v92_o01_scenario.json",
        "scenario_sha256": "602874173a0ad69df7da4020f9a8db6ed6f726585c1f3ff983eadd187f74df5d",
        "scenario_blob": "720a1359ebdab210f7a670963fb721fc2b8b878f",
        "product_mapper_path": "tools/lab/handoff93/run_product_mapper_cycle.ps1",
        "product_mapper_sha256": "46699855502138f8a39cf30bfd0f3f4827a9e02febc79b317218a34924c99027",
        "product_mapper_blob": "bf2494f1b61a27ca0e2af5e4d0197d2137cb06d6",
        "formal_duration_ms": 28800000, "tick_ms": 10000,
        "checkpoint_ms": 300000, "checkpoint_max_gap_ms": 370000,
        "controller_schedule_jitter_ms": 70000, "product_stream_max_gap_ms": 70000,
        "initial_rpc_watchdog_ms": 300000,
        "subsequent_rpc_watchdog_ms": 140000, "bound_files_count": 21,
        "node_version": PINNED_NODE_VERSION,
        "node_sha256": PINNED_NODE_SHA256,
        "node_distribution_file_count": PINNED_NODE_TREE_FILE_COUNT,
        "node_distribution_directory_count": PINNED_NODE_TREE_DIRECTORY_COUNT,
        "node_distribution_identity_sha256": PINNED_NODE_TREE_SHA256,
        "node_distribution_identity_rule": NODE_DISTRIBUTION_IDENTITY_RULE,
        "npm_version": PINNED_NPM_VERSION,
        "npm_cmd_sha256": PINNED_NPM_CMD_SHA256,
        "npm_cli_sha256": PINNED_NPM_CLI_SHA256,
        "pkg_node_version": PINNED_PKG_NODE_VERSION,
        "pkg_node_bytes": PINNED_PKG_NODE_BYTES,
        "pkg_node_sha256": PINNED_PKG_NODE_SHA256,
        "ajv_version": "8.20.0",
        "package_lock_path": "tools/lab/nat_gateway/package-lock.json",
        "package_lock_sha256": "0d5f46ff0e004c43c7511ce1f31367469d989746c4c1725fc5131b6d04c0eeaf",
        "nat_gateway_node_modules_file_count": PINNED_NAT_GATEWAY_MODULE_FILE_COUNT,
        "nat_gateway_node_modules_directory_count":
            PINNED_NAT_GATEWAY_MODULE_DIRECTORY_COUNT,
        "nat_gateway_node_modules_identity_sha256":
            PINNED_NAT_GATEWAY_MODULE_IDENTITY_SHA256,
        "release_inputs_path": "tools/release_inputs.json",
        "release_inputs_sha256": "6aef8bb28d6633725a4da1f4560e91463db5845d872f55378bf1a52ef76c9d55",
        "release_inputs_blob": "83428e17b40e044c191c5922a9446d6e2c6e8822",
        "nodes_dat_pin_path": "srchybrid/config/nodes.dat.sha256",
        "nodes_dat_pin_sha256": "3a645fc9b5868a6599bbab22b62d85b434bb8ed4591b16ba98dc694d712dc2ef",
        "nodes_dat_pin_blob": "2f665c392e4a16096a1c358a9f1dc1310b1adf46",
        "ffmpeg_sha256": PINNED_FFMPEG_SHA256,
        "ffprobe_sha256": PINNED_FFPROBE_SHA256,
        "python_version": PINNED_PYTHON_VERSION,
        "python_sha256": PINNED_PYTHON_SHA256,
        "build_python_dependency_file_count":
            PINNED_BUILD_PYTHON_DEPENDENCY_FILE_COUNT,
        "build_python_dependency_directory_count":
            PINNED_BUILD_PYTHON_DEPENDENCY_DIRECTORY_COUNT,
        "build_python_dependency_identity_sha256":
            PINNED_BUILD_PYTHON_DEPENDENCY_IDENTITY_SHA256,
        "build_python_dependency_identity_rule":
            BUILD_PYTHON_DEPENDENCY_IDENTITY_RULE,
        "git_version": PINNED_GIT_VERSION,
        "git_sha256": PINNED_GIT_SHA256,
        "git_core_sha256": PINNED_GIT_CORE_SHA256,
        "powershell_sha256": PINNED_POWERSHELL_SHA256,
        "cmd_sha256": PINNED_CMD_SHA256,
        "msbuild_version": PINNED_MSBUILD_VERSION,
        "msbuild_sha256": PINNED_MSBUILD_SHA256,
        "package_snapshot_identity_rule": PACKAGE_SNAPSHOT_IDENTITY_RULE,
        "rule": "No scenario, mapper, timing threshold, 300000 ms initial watchdog, "
                "140000 ms subsequent watchdog, duration override, resume or evidence reuse "
                "is authorized by G12.",
    }, "immutable contract")

    carriers = document["carrier_paths"]
    exact_keys(carriers, ["M64", "H64", "R64"], "carrier paths")
    require_exact_value(carriers["M64"], {
        "fixed": [
            "docs/architecture/mod02_build_manifest_v1.json",
            "docs/architecture/mod02_characterization_matrix_v1.json",
        ],
        "summary_pattern": "artifacts/mod02-runtime-v92-<A64[0:8]>/summary.json",
        "release_build_receipt_pattern":
            "artifacts/v92-o01-release-build-<A64[0:8]>/emule-release-build.json",
        "file_count": 4, "reuse_m63": "FORBIDDEN",
    }, "M64 carriers")
    require_exact_value(carriers["H64"], [
        "artifacts/v92-o01-governance/activation.json",
        "artifacts/v92-o01-governance/offline-summary.json",
        "artifacts/v92-o01-governance/review-sol.json",
        "artifacts/v92-o01-governance/review-terra.json",
    ], "H64 carriers")
    require_exact_value(carriers["R64"], {
        "directory": "artifacts/v92-o01-formal",
        "checkpoint_pattern": "checkpoint-(01..95).json",
        "fixed": ["controller-result.json", "formal-run-result.json", "formal-validation.json"],
        "formal_run_schema": "ese.v92.o01-formal-run/v2",
        "forbidden": ["clock-failure.json", "failure.json", "rpc-failure.json"],
        "file_count": 98,
    }, "R64 carriers")
    require_exact_value(document["formal_launch_contract"], FORMAL_LAUNCH_CONTRACT,
                        "formal launch contract")
    require_exact_value(document["required_reviews"], [
        "Terra v2 APPROVE binds G12/A64/M64, offline summary, gate attestations and runtime/build-artifact identities with findings=[]",
        "Sol v2 APPROVE binds G12/A64/M64, offline summary, gate attestations and runtime/build-artifact identities with findings=[]",
    ], "reviews")
    require_exact_value(document["draft_gates"], DRAFT_GATES, "draft gates")
    require_exact_value(document["sealed_gates"], SEALED_GATES, "sealed gates")
    require_exact_value(document["stop_conditions"], STOP_CONDITIONS,
                        "stop conditions")
    gate_contract = document["gate_attestation_contract"]
    exact_keys(gate_contract, [
        "schema", "record_exact_keys", "evidence_kind", "input_worktree_state",
        "gate_names", "cwd_normalization", "argv_normalization", "result_policy",
        "capture_rule",
    ], "gate attestation contract")
    require_exact_value(gate_contract, {
        "schema": "ese.v92.o01-gate-attestations/v1",
        "record_exact_keys": [
            "evidence_kind", "name", "phase", "source_commit", "source_tree",
            "input_worktree_state", "normalized_cwd", "cwd_sha256",
            "normalized_argv", "argv_sha256", "exit_code", "result",
            "stdout_sha256", "stderr_sha256",
        ],
        "evidence_kind": "REVIEW_ATTESTED_EXECUTION",
        "input_worktree_state": "CLEAN",
        "gate_names": [gate[0] for gate in OFFLINE_GATES],
        "cwd_normalization": "normalized_cwd is exactly <FRESH_A64_WORKTREE> for BUILD_ALL, NODE22_FULL, A64_FOCAL and MOD02_RUNTIME, and <M64_WORKTREE> for every other gate. cwd_sha256 is SHA-256 of compact ASCII JSON of that string.",
        "argv_normalization": "normalized_argv is an ordered string array. Replace only the exact isolated pinned Python executable by <PINNED_PYTHON>, the canonical pinned System32 PowerShell by <PINNED_POWERSHELL>, the canonical pinned Program Files Git entrypoint by <PINNED_GIT>, the absolute clean A64 build-worktree root by <FRESH_A64_WORKTREE>, the pinned Node executable by <PINNED_NODE>, the pinned pkg base Node by <PINNED_PKG_NODE>, the pinned FFmpeg executable by <PINNED_FFMPEG>, the fresh MOD02 output root by <FRESH_MOD02_ROOT>, the fresh temporary A64-bound MOD02 manifest by <FRESH_MOD02_MANIFEST>, and the exact H63-to-M64 commit range by H63..M64; reject every other absolute or unexpanded placeholder. Every Python gate uses -I -S -B. argv_sha256 is SHA-256 of compact ASCII JSON of normalized_argv preserving array order.",
        "result_policy": "result is the exact JSON object emitted by a JSON gate, a closed counter summary parsed from the same captured TAP or unittest stdout, or the exact closed projection of the M64 receipt or MOD02 summary. BUILD_ALL v3 binds isolated Python, the exact 113-file build dependency projection, the exact Node/npm distribution, pkg base Node, entry hashes for the trusted host tools, the fresh receipt and an immediate complete runtime/build-artifact package snapshot. MOD02 binds the compiled executable and the package FFmpeg as the only two loadable binaries in a fresh runtime capsule, plus the exact fixed non-code config/preferences.ini seed that forces portable state into that capsule. PACKAGE_AUDIT v2 independently remeasures that snapshot and must produce the identical canonical package_snapshot_sha256. NODE22_FULL and A64_FOCAL bootstrap the exact lock with pinned npm ci --ignore-scripts and emit the installed dependency-tree identity. No free-form marker is an admitted result.",
        "capture_rule": "Each record binds its normalized cwd, normalized argv and phase to the exact A64 or M64 commit/tree, exit_code=0, a closed parsed PASS result, and SHA-256 of the actual captured stdout and stderr bytes; raw streams are not committed. Python gates require the exact executable/version under -I -S -B. The build wrapper exposes Python only through its temporary python.cmd shim and one in-session python.exe function: ordinary scripts invoke the pinned absolute Python with -E -s -S -B, while the exact test_v92_mx05_handoff.py consumer alone uses -I -S -B with the create-exclusive pinned 113-file dependency projection. MOD02 copies only the authenticated compiled emule.exe and package ffmpeg.exe and creates the exact fixed non-code config/preferences.ini portable seed in a fresh closed initial runtime, preserves the executable build timestamp, executes only that capsule, rejects new loadable code, then remeasures both executable files and their sources before recursively removing the private portable outputs. M64 loads the byte-pinned G11-to-physical legacy verifier chain only from authenticated source bytes; both legacy ambient shells are disabled, Git/blob/parent/delta calls are rebound to G12 closed adapters, and the release fingerprint runs in a new pinned System32 PowerShell process with closed Git and PSModule environment. PowerShell child commands resolve only to the canonical pinned System32 executable under the closed PATH and PSModulePath. Build and Node-test wrappers close Git, Node/npm/pkg, PowerShell-module and MSBuild/user-import environment redirection; use empty npm user/global configuration; reject project npm overrides; force byte-exact tracked files outside libutp and exact libutp gitlink, index and Git-blob contents under fixed core.autocrlf=true against per-worktree temporary indexes; and remeasure inputs after execution. Closed Git fixes core.whitespace=blank-at-eol,blank-at-eof,space-before-tab,cr-at-eol; DIFF_CHECK therefore treats only the CR immediately before LF in the byte-required Release receipt as a line terminator, while blank-at-eol, blank-at-eof and space-before-tab remain errors. Sol and Terra v2 reviews independently compare the actual invocation to the closed normalization, verify the parser or carrier projection against the captured stream or artifact, and bind the canonical identity of the complete record list.",
    }, "gate attestation identity")
    review_contract = document["h64_review_contract"]
    exact_keys(review_contract, ["schema", "required_exact_keys", "rule"],
               "H64 review contract")
    require_exact_value(review_contract, {
        "schema": "ese.v92.o01-review/v2",
        "required_exact_keys": [
            "schema", "role", "g_commit", "g_tree", "a_commit", "a_tree",
            "m_commit", "m_tree", "offline_summary_sha256",
            "gate_attestations_sha256", "runtime_bindings_sha256",
            "build_artifact_bindings_sha256", "verdict", "findings",
        ],
        "rule": "Both independent reviews bind the exact post-build offline summary and canonical gate, runtime and distribution-artifact identities, and must be APPROVE with findings=[].",
    }, "H64 review identity")
    h64_contract = document["h64_activation_contract"]
    exact_keys(h64_contract, [
        "schema", "required_exact_keys", "artifact_sha256_keys",
        "runtime_binding_exact_keys", "build_artifact_binding_exact_keys",
        "runtime_binding_derivation", "build_artifact_binding_derivation", "rule",
    ], "H64 activation contract")
    require(h64_contract["schema"] == "ese.v92.o01-rpc-repair-activation/v1",
            "H64 activation schema")
    require_exact_value(h64_contract["required_exact_keys"], [
        "schema", "predecessor_h_commit", "g_commit", "g_tree",
        "g12_governance_sha256", "g12_governance_identity_sha256", "amendment_sha256",
        "a_commit", "a_tree", "a64_paths_sha256", "a64_byte_identity_sha256",
        "a64_numstat_identity_sha256", "code_allowlist_sha256",
        "tuple_allowlist_sha256", "scenario_sha256", "scenario_blob",
        "product_mapper_sha256", "product_mapper_blob", "m_commit", "m_tree",
        "runtime_bindings", "build_artifact_bindings", "gate_attestations_sha256",
        "artifact_sha256",
    ], "H64 activation exact keys")
    require_exact_value(h64_contract["artifact_sha256_keys"], [
        "artifacts/v92-o01-governance/offline-summary.json",
        "artifacts/v92-o01-governance/review-sol.json",
        "artifacts/v92-o01-governance/review-terra.json",
    ], "H64 artifact keys")
    require_exact_value(h64_contract["runtime_binding_exact_keys"],
                        RUNTIME_BINDING_KEYS, "H64 runtime binding keys")
    require_exact_value(h64_contract["build_artifact_binding_exact_keys"],
                        BUILD_ARTIFACT_BINDING_KEYS,
                        "H64 build artifact binding keys")
    require(h64_contract["runtime_binding_derivation"] ==
            "H64 offline summary records the post-build audit of package/BUILD_INFO.txt bytes, package/SHA256SUMS.txt bytes and exact valid entry count excluding the manifest itself, and the package directory file count including the manifest. A64 runner binds these values to H64, revalidates the full host manifest/set before copy and pre-seal, validates the exact initial guest runtime projection before product start, and emits all runtime bindings in formal-run/v2.",
            "H64 runtime binding derivation")
    require(h64_contract["build_artifact_binding_derivation"] ==
            "PACKAGE_AUDIT derives the exact release tag, ZIP and .sha256 relative paths, ZIP byte length, entry count and SHA-256, and sidecar byte length and SHA-256 from the fresh A64 build; requires sidecar bytes to equal uppercase ZIP_SHA256, two spaces, the ZIP basename and CRLF; rejects any ZIP preamble, suffix, comment, extra field, uncovered local byte or trailing DEFLATE payload; and proves that the ZIP exact file set and every file hash equal the same audited PackageRoot manifest/set. The ZIP is a review-attested distribution artifact, is rehashed before publication, and is not claimed as a runtime input consumed during R64.",
            "H64 build artifact binding derivation")
    require(h64_contract["rule"] ==
            "H64 activation binds predecessor H63; G12 commit/tree, all three governance "
            "bytes and their canonical identity; A64 commit/tree and exact path, byte and "
            "numstat identities; both RPC allowlist identities; immutable scenario and "
            "mapper SHA/blob identities; M64 commit/tree; exact Node, executable, BUILD_INFO "
            "and PackageRoot manifest runtime inputs; the separately classified distribution "
            "ZIP identity; the gate-attestation identity; and exact offline/Sol/Terra carrier "
            "hashes.", "H64 activation rule")
    activation = document["activation_state"]
    exact_keys(activation, ["G12", "A64", "M64", "H64", "R64", "rule"], "activation")
    for phase in ("G12", "A64", "M64", "H64", "R64"):
        require(activation[phase] is None, f"premature activation: {phase}")
    require(activation["rule"] == ACTIVATION_RULE, "activation rule")


def validate_rpc_failure(value: dict[str, Any]) -> None:
    """Validate the frozen closed artifact shape used by hostile tests."""
    exact_keys(value, RPC_KEYS, "rpc-failure")
    require(value["schema"] == "ese.v92.o01-rpc-failure/v1", "rpc schema")
    require(value["verdict"] == "FAIL" and value["release_gate"] is False, "rpc verdict")
    require(value["origin"] in RPC_ORIGINS, "rpc origin")
    require(value["stage"] in RPC_STAGES, "rpc stage")
    pair = f"{value['origin']}:{value['stage']}"
    require(pair in RPC_ORIGIN_STAGE_PAIRS, "rpc origin/stage pair")
    tuples, _, _ = derive_rpc_allowlists()
    require(isinstance(value["failure_code"], str) and
            CLOSED_CODE.fullmatch(value["failure_code"]) is not None and
            value["failure_code"] in tuples[pair], "closed rpc tuple")
    require_int(value["requests_handled"], 0, 482, "requests handled")
    require_int(value["next_sequence"], 1, 483, "next sequence")
    require_int(value["maximum_requests"], 1, 482, "maximum requests")
    require(value["requests_handled"] <= value["maximum_requests"], "request maximum")
    require(value["next_sequence"] == value["requests_handled"] + 1,
            "request sequence relation")
    require(value["next_sequence"] <= value["maximum_requests"] + 1,
            "next sequence maximum")
    if value["origin"] == "FORMAL_HOST":
        require_int(value["host_exit_code"], -2147483648, 2147483647,
                    "host exit code")
        require(value["host_exit_code"] != 0, "formal host exit code")
    elif value["origin"] == "LOCAL_PRODUCT":
        require(value["host_exit_code"] is None, "local product exit code")
    else:
        require(value["host_exit_code"] is None or
                (type(value["host_exit_code"]) is int and
                 -2147483648 <= value["host_exit_code"] <= 2147483647 and
                 value["host_exit_code"] != 0), "RPC pump exit code")
    require_int(value["stderr_tail_chars"], 0, 16384, "stderr tail chars")
    require_int(value["stderr_tail_utf8_bytes"], 0, 49152, "stderr UTF-8 bytes")
    require(value["stderr_tail_utf8_bytes"] >= value["stderr_tail_chars"],
            "stderr byte/character relation")
    require_sha(value["stderr_tail_sha256"], "stderr tail SHA-256")
    empty_tail = value["stderr_tail_chars"] == 0
    require(empty_tail == (value["stderr_tail_utf8_bytes"] == 0),
            "stderr empty count consistency")
    require(empty_tail == (value["stderr_tail_sha256"] == EMPTY_SHA256),
            "stderr empty SHA-256")
    require_int(value["last_checkpoint_ordinal"], 0, 95, "last checkpoint ordinal")
    effective_requests = value["requests_handled"]
    if value["origin"] == "LOCAL_PRODUCT":
        require(effective_requests >= 1, "local product request count")
        effective_requests -= 1
    maximum_checkpoint = max(0, (effective_requests - 1) // 5)
    require(value["last_checkpoint_ordinal"] <= maximum_checkpoint,
            "checkpoint request relation")
    for key in ("last_checkpoint_record_sha256", "last_checkpoint_file_sha256"):
        if value[key] is not None:
            require_sha(value[key], f"{key} SHA-256")
    hashes_are_null = (value["last_checkpoint_record_sha256"] is None and
                       value["last_checkpoint_file_sha256"] is None)
    hashes_are_present = (value["last_checkpoint_record_sha256"] is not None and
                          value["last_checkpoint_file_sha256"] is not None)
    require((value["last_checkpoint_ordinal"] == 0 and hashes_are_null) or
            (value["last_checkpoint_ordinal"] > 0 and hashes_are_present),
            "checkpoint hash consistency")


def validate_r64_paths(paths: Iterable[str]) -> None:
    actual = list(paths)
    expected = [f"checkpoint-{ordinal:02d}.json" for ordinal in range(1, 96)] + [
        "controller-result.json", "formal-run-result.json", "formal-validation.json",
    ]
    require(len(actual) == 98 and set(actual) == set(expected), "R64 exact artifact set")
    require(not ({"clock-failure.json", "failure.json", "rpc-failure.json"} & set(actual)),
            "R64 failure artifact")


def _closed_git_environment(source: dict[str, str] | None = None) -> dict[str, str]:
    environment = dict(os.environ if source is None else source)
    for key in list(environment):
        if key.upper().startswith("GIT_"):
            del environment[key]
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    environment["GIT_CONFIG_GLOBAL"] = "NUL" if os.name == "nt" else "/dev/null"
    environment["GIT_ATTR_NOSYSTEM"] = "1"
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    environment["GIT_TERMINAL_PROMPT"] = "0"
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    return environment


def _set_environment_value_ci(environment: dict[str, str], key: str, value: str) -> None:
    for existing in list(environment):
        if existing.casefold() == key.casefold():
            del environment[existing]
    environment[key] = value


def _git_command(root: Path, *args: str,
                 libutp_checkout: bool = False) -> list[str]:
    require(type(libutp_checkout) is bool, "closed Git checkout policy")
    null_device = "NUL" if os.name == "nt" else "/dev/null"
    autocrlf = "true" if libutp_checkout else "false"
    return [
        str(_git_executable()), "--no-pager", "-c", f"safe.directory={root.as_posix()}",
        "-c", "core.fsmonitor=false", "-c", f"core.excludesFile={null_device}",
        "-c", f"core.attributesFile={null_device}", "-c", f"core.autocrlf={autocrlf}",
        "-c", f"core.worktree={root.as_posix()}", "-c", "core.bare=false",
        "-c", "core.ignoreStat=false", "-c", "core.sparseCheckout=false",
        "-c", "core.sparseCheckoutCone=false", "-c", "index.sparse=false",
        "-c", "extensions.worktreeConfig=false",
        "-c", f"core.whitespace={CLOSED_CORE_WHITESPACE}",
        "-c", f"core.hooksPath={null_device}",
        "-C", str(root), *args,
    ]


def _git_executable() -> Path:
    candidate = shutil.which("git.exe" if os.name == "nt" else "git")
    require(candidate is not None, "pinned Git executable")
    path = _assert_regular_path(Path(candidate), False, "pinned Git executable")
    if os.name == "nt":
        canonical_path = Path(r"C:\Program Files\Git\cmd\git.exe")
        core_path = _assert_regular_path(
            Path(r"C:\Program Files\Git\mingw64\bin\git.exe"), False,
            "pinned Git core executable",
        )
        require(path == canonical_path.resolve(strict=True) and
                _file_sha256(core_path) == PINNED_GIT_CORE_SHA256,
                "pinned Git layout")
    require(_file_sha256(path) == PINNED_GIT_SHA256, "pinned Git SHA-256")
    return path


def _git(*args: str, allow_failure: bool = False) -> bytes:
    process = subprocess.run(
        _git_command(REPO, *args), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=False, env=_closed_git_environment(),
    )
    if process.returncode != 0 and not allow_failure:
        raise GateError(f"git command failed: {args[0] if args else 'unknown'}")
    return process.stdout if process.returncode == 0 else b""


def _git_text(*args: str) -> str:
    return _git(*args).decode("utf-8", "strict").strip()


def _git_succeeds(*args: str) -> bool:
    process = subprocess.run(
        _git_command(REPO, *args), stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, check=False, env=_closed_git_environment(),
    )
    return process.returncode == 0


def _blob(commit: str, path: str) -> bytes:
    return _git("show", f"{commit}:{path}")


def _parents(commit: str) -> list[str]:
    raw = _git("cat-file", "commit", commit)
    header, separator, _ = raw.partition(b"\n\n")
    require(separator == b"\n\n", "commit identity")
    lines = header.splitlines()
    require(lines and re.fullmatch(br"tree [0-9a-f]{40}", lines[0]) is not None,
            "commit identity")
    parents: list[str] = []
    for line in lines[1:]:
        if line.startswith(b"parent "):
            require(re.fullmatch(br"parent [0-9a-f]{40}", line) is not None,
                    "commit identity")
            parents.append(line[7:].decode("ascii"))
    return parents


def verify_history(document: dict[str, Any]) -> None:
    for name in ("h62", "g11", "a63", "m63", "h63"):
        commit = BASE[f"{name}_commit"]
        tree = BASE[f"{name}_tree"]
        require(_git_text("rev-parse", f"{commit}^{{commit}}") == commit, f"{name} commit")
        require(_git_text("rev-parse", f"{commit}^{{tree}}") == tree, f"{name} tree")
    for child, parent in (("g11", "h62"), ("a63", "g11"), ("m63", "a63"), ("h63", "m63")):
        require(_parents(BASE[f"{child}_commit"]) == [BASE[f"{parent}_commit"]],
                f"{child} direct ancestry")
    g11_delta = _git_text(
        "diff-tree", "--no-commit-id", "--name-only", "-r", BASE["g11_commit"],
    ).splitlines()
    require(sorted(g11_delta) == [
        "docs/architecture/v92_o01_clock_repair_governance_v1.json",
        "tools/architecture/test_verify_v92_o01_clock_repair_governance.py",
        "tools/architecture/verify_v92_o01_clock_repair_governance.py",
    ], "G11 delta")
    for commit, identities, label in (
        (BASE["g11_commit"], G11_SHA256, "G11"),
        (BASE["m63_commit"], M63_SHA256, "M63"),
        (BASE["h63_commit"], H63_SHA256, "H63"),
    ):
        for path, expected in identities.items():
            require(sha256(_blob(commit, path)) == expected, f"{label} blob: {path}")
    immutable = document["immutable_contract"]
    require(sha256(_blob(BASE["h63_commit"], immutable["scenario_path"])) ==
            immutable["scenario_sha256"], "scenario identity")
    require(sha256(_blob(BASE["h63_commit"], immutable["product_mapper_path"])) ==
            immutable["product_mapper_sha256"], "mapper identity")
    require(_git_text("rev-parse", f"{BASE['h63_commit']}:{immutable['scenario_path']}") ==
            immutable["scenario_blob"], "scenario blob identity")
    require(_git_text("rev-parse", f"{BASE['h63_commit']}:{immutable['product_mapper_path']}") ==
            immutable["product_mapper_blob"], "mapper blob identity")
    require(sha256(_blob(BASE["h63_commit"], immutable["package_lock_path"])) ==
            immutable["package_lock_sha256"], "package-lock identity")
    require(sha256(_blob(BASE["h63_commit"], immutable["release_inputs_path"])) ==
            immutable["release_inputs_sha256"], "release inputs identity")
    require(_git_text("rev-parse", f"{BASE['h63_commit']}:{immutable['release_inputs_path']}") ==
            immutable["release_inputs_blob"], "release inputs blob identity")
    require(sha256(_blob(BASE["h63_commit"], immutable["nodes_dat_pin_path"])) ==
            immutable["nodes_dat_pin_sha256"], "nodes.dat pin identity")
    require(_git_text("rev-parse", f"{BASE['h63_commit']}:{immutable['nodes_dat_pin_path']}") ==
            immutable["nodes_dat_pin_blob"], "nodes.dat pin blob identity")


def _changed_paths() -> set[str]:
    changed: set[str] = set()
    for arguments in (
        ("diff", "--ignore-submodules=dirty", "--name-only", "HEAD"),
        ("diff", "--cached", "--name-only"),
        ("ls-files", "--others", "--exclude-standard"),
    ):
        changed.update(line for line in _git_text(*arguments).splitlines() if line)
    return changed


def _assert_libutp_checkout(superproject_commit: str, label: str) -> None:
    submodule_commit = _git_text("rev-parse", f"{superproject_commit}:libutp")
    require(re.fullmatch(r"[0-9a-f]{40}", submodule_commit) is not None, label)
    submodule_root = _assert_regular_path(REPO / "libutp", True, label)
    environment = _closed_git_environment()
    process = subprocess.run(
        _git_command(
            submodule_root, "rev-parse", f"{submodule_commit}^{{tree}}",
            libutp_checkout=True,
        ),
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60,
        env=environment,
    )
    try:
        submodule_tree = process.stdout.decode("ascii", "strict").strip()
    except UnicodeDecodeError as exc:
        raise GateError(label) from exc
    require(re.fullmatch(r"[0-9a-f]{40}", submodule_tree) is not None, label)
    _assert_external_checkout(
        submodule_root, submodule_commit, submodule_tree, label,
        reject_untracked_ignored=True, libutp_checkout=True,
    )


def _verify_text_file(path: Path) -> None:
    raw = path.read_bytes()
    require(raw and not raw.startswith(b"\xef\xbb\xbf"), f"encoding: {path.name}")
    require(b"\r" not in raw and raw.endswith(b"\n"), f"line endings: {path.name}")
    require(all(line == line.rstrip(b" \t") for line in raw.splitlines()),
            f"trailing whitespace: {path.name}")


def _numstat(parent: str, child: str | None = None) -> dict[str, tuple[int, int]]:
    arguments = ("diff", "--numstat", parent, child, "--") if child else (
        "diff", "--ignore-submodules=dirty", parent, "--numstat", "--"
    )
    result: dict[str, tuple[int, int]] = {}
    for line in _git_text(*[value for value in arguments if value is not None]).splitlines():
        added, deleted, path = line.split("\t", 2)
        require(added.isdigit() and deleted.isdigit(), "binary numstat forbidden")
        result[path] = (int(added), int(deleted))
    return result


def _verify_a_stats(stats: dict[str, tuple[int, int]], label: str) -> None:
    require(stats == PATH_BUDGET, f"{label} per-path budget")
    require(observed_budget(stats) == BUDGET, f"{label} total budget")
    require(observed_budget(stats, A_RUNTIME_PATHS) == RUNTIME_BUDGET,
            f"{label} runtime budget")
    require(observed_budget(stats, A_TEST_PATHS) == TEST_BUDGET,
            f"{label} test budget")


def _verify_a_bytes(reader, label: str) -> None:
    observed = {path: sha256(reader(path)) for path in A_PATHS}
    require(observed == A_SHA256, f"{label} A64 bytes")
    require(sha256(ordered_canonical(path_hash_document(observed))) == A_BYTES_SHA256,
            f"{label} A64 byte identity")


def verify_check_worktree(document: dict[str, Any], document_raw: bytes) -> None:
    head = _git_text("rev-parse", "HEAD")
    require(sha256(document_raw) == DOCUMENT_SHA256, "sealed document byte identity")
    _assert_libutp_checkout(head, "worktree libutp source")
    changed = _changed_paths()
    require(_git_text("diff", "--cached", "--name-only") == "", "worktree index must be empty")
    verify_governance_tool_identity(document, lambda path: (REPO / path).read_bytes())
    if head == BASE["h63_commit"]:
        require(changed == set(GOVERNANCE_PATHS) | set(A_PATHS), "worktree exact path set")
        for path in GOVERNANCE_PATHS:
            require(not _git_succeeds("cat-file", "-e", f"HEAD:{path}"),
                    f"governance path already tracked: {path}")
            file_path = REPO / path
            require(file_path.is_file() and not file_path.is_symlink(),
                    f"governance regular file: {path}")
            _verify_text_file(file_path)
    else:
        verify_g(head, document)
        require(changed == set(A_PATHS), "post-G12 worktree exact A64 path set")
    require(not (set(G11_SHA256) & changed), "historical G11 path changed")
    require(not (set(M63_SHA256) & changed), "historical M63 carrier changed")
    require(not (set(H63_SHA256) & changed), "historical H63 carrier changed")
    _verify_a_stats(_numstat("HEAD"), "worktree")
    _verify_a_bytes(lambda path: (REPO / path).read_bytes(), "worktree")
    derive_rpc_allowlists((REPO / "tools/lab/v92_o01_vm_session.psm1").read_bytes())
    immutable = document["immutable_contract"]
    require(sha256((REPO / immutable["scenario_path"]).read_bytes()) ==
            immutable["scenario_sha256"], "worktree scenario")
    require(sha256((REPO / immutable["product_mapper_path"]).read_bytes()) ==
            immutable["product_mapper_sha256"], "worktree mapper")
    require(sha256((REPO / immutable["package_lock_path"]).read_bytes()) ==
            immutable["package_lock_sha256"], "worktree package-lock")
    require(sha256((REPO / immutable["release_inputs_path"]).read_bytes()) ==
            immutable["release_inputs_sha256"], "worktree release inputs")
    require(sha256((REPO / immutable["nodes_dat_pin_path"]).read_bytes()) ==
            immutable["nodes_dat_pin_sha256"], "worktree nodes.dat pin")


def _changed_between(parent: str, child: str) -> list[str]:
    return sorted(line for line in _git_text("diff", "--name-only", parent, child, "--").splitlines()
                  if line)


def _require_single_parent(commit: str, parent: str, label: str) -> None:
    require(_parents(commit) == [parent], f"{label} direct parent")


def _governance_sha(reader) -> dict[str, str]:
    return {path: sha256(reader(path)) for path in GOVERNANCE_PATHS}


def verify_g(g_commit: str, document: dict[str, Any]) -> None:
    _require_single_parent(g_commit, BASE["h63_commit"], "G12")
    require(_changed_between(BASE["h63_commit"], g_commit) == GOVERNANCE_PATHS,
            "G12 exact delta")
    require(_blob(g_commit, GOVERNANCE_PATHS[0]) == DOCUMENT.read_bytes(),
            "G12 document identity")
    for path in GOVERNANCE_PATHS:
        require(_blob(g_commit, path) == (REPO / path).read_bytes(),
                f"G12 governance byte identity: {path}")
    require(sha256(_blob(g_commit, GOVERNANCE_PATHS[0])) == DOCUMENT_SHA256,
            "G12 document self identity")
    verify_governance_tool_identity(document, lambda path: _blob(g_commit, path))
    require(document["governance_paths_sha256"] == GOVERNANCE_PATHS_SHA256,
            "G12 path identity")


def verify_a(a_commit: str, g_commit: str, document: dict[str, Any]) -> None:
    _require_single_parent(a_commit, g_commit, "A64")
    require(_changed_between(g_commit, a_commit) == A_PATHS, "A64 exact delta")
    _verify_a_stats(_numstat(g_commit, a_commit), "A64")
    _verify_a_bytes(lambda path: _blob(a_commit, path), "A64")
    derive_rpc_allowlists(_blob(a_commit, "tools/lab/v92_o01_vm_session.psm1"))
    immutable = document["immutable_contract"]
    require(sha256(_blob(a_commit, immutable["scenario_path"])) == immutable["scenario_sha256"],
            "A64 scenario")
    require(sha256(_blob(a_commit, immutable["product_mapper_path"])) ==
            immutable["product_mapper_sha256"], "A64 mapper")
    require(_git_text("rev-parse", f"{a_commit}:{immutable['scenario_path']}") ==
            immutable["scenario_blob"], "A64 scenario blob")
    require(_git_text("rev-parse", f"{a_commit}:{immutable['product_mapper_path']}") ==
            immutable["product_mapper_blob"], "A64 mapper blob")
    require(sha256(_blob(a_commit, immutable["package_lock_path"])) ==
            immutable["package_lock_sha256"], "A64 package-lock")
    require(sha256(_blob(a_commit, immutable["release_inputs_path"])) ==
            immutable["release_inputs_sha256"], "A64 release inputs")
    require(_git_text("rev-parse", f"{a_commit}:{immutable['release_inputs_path']}") ==
            immutable["release_inputs_blob"], "A64 release inputs blob")
    require(sha256(_blob(a_commit, immutable["nodes_dat_pin_path"])) ==
            immutable["nodes_dat_pin_sha256"], "A64 nodes.dat pin")
    require(_git_text("rev-parse", f"{a_commit}:{immutable['nodes_dat_pin_path']}") ==
            immutable["nodes_dat_pin_blob"], "A64 nodes.dat pin blob")


def _load_authenticated_source_module(
        name: str, path: Path, expected_sha256: str, label: str,
):
    path = _assert_regular_path(path, False, label)
    require(0 < path.stat().st_size <= 2 * 1024 * 1024, label)
    raw = path.read_bytes()
    require(_file_sha256(path) == expected_sha256 and
            sha256(raw) == expected_sha256, f"{label} byte identity")
    code = compile(raw, str(path), "exec", dont_inherit=True, optimize=0)
    module = types.ModuleType(name)
    module.__file__ = str(path)
    module.__package__ = None
    exec(code, module.__dict__)
    require(path.read_bytes() == raw and _file_sha256(path) == expected_sha256,
            f"{label} byte identity")
    return module


def _import_old_verifier():
    old_path = _assert_regular_path(OLD_GOVERNANCE_VERIFIER, False,
                                    "legacy verifier path")
    expected = G11_SHA256[
        "tools/architecture/verify_v92_o01_clock_repair_governance.py"
    ]
    require(_file_sha256(old_path) == expected, "legacy verifier byte identity")
    module = _load_authenticated_source_module(
        "g11_verifier_for_g12", old_path, expected, "legacy verifier",
    )
    require(_file_sha256(_assert_regular_path(old_path, False, "legacy verifier path")) ==
            expected, "legacy verifier byte identity")
    return module


def _m_paths(a_commit: str) -> list[str]:
    short = a_commit[:8]
    return sorted([
        f"artifacts/mod02-runtime-v92-{short}/summary.json",
        f"artifacts/v92-o01-release-build-{short}/emule-release-build.json",
        "docs/architecture/mod02_build_manifest_v1.json",
        "docs/architecture/mod02_characterization_matrix_v1.json",
    ])


def _closed_legacy_release_source_fingerprint(a_commit: str) -> str:
    script_relative = "tools/release_fingerprint.ps1"
    script = _assert_regular_path(
        REPO / script_relative, False,
        "legacy release fingerprint script",
    )
    script_raw = script.read_bytes()
    require(script_raw == _blob(a_commit, script_relative),
            "legacy release fingerprint script identity")
    head_before = _git_text("rev-parse", "HEAD")
    git_before = _git_executable()
    powershell = _assert_regular_path(
        Path(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
        False, "legacy release fingerprint PowerShell",
    )
    require(_file_sha256(powershell) == PINNED_POWERSHELL_SHA256,
            "legacy release fingerprint PowerShell identity")
    with tempfile.TemporaryDirectory(prefix="g12-legacy-fingerprint-") as temporary_name:
        environment = _formal_runner_environment(Path(temporary_name))
        for key in list(environment):
            upper = key.upper()
            if (upper == "GIT_CONFIG_COUNT" or
                    upper.startswith("GIT_CONFIG_KEY_") or
                    upper.startswith("GIT_CONFIG_VALUE_")):
                del environment[key]
        null_device = "NUL" if os.name == "nt" else "/dev/null"
        git_config = [
            ("safe.directory", str(REPO)),
            ("safe.directory", str(REPO / "libutp")),
            ("core.fsmonitor", "false"),
            ("core.hooksPath", null_device),
            ("core.excludesFile", null_device),
            ("core.attributesFile", null_device),
            ("core.bare", "false"),
            ("core.ignoreStat", "false"),
            ("core.sparseCheckout", "false"),
            ("core.sparseCheckoutCone", "false"),
            ("index.sparse", "false"),
            ("extensions.worktreeConfig", "false"),
            ("core.autocrlf", "true"),
        ]
        environment["GIT_CONFIG_COUNT"] = str(len(git_config))
        for index, (key, value) in enumerate(git_config):
            environment[f"GIT_CONFIG_KEY_{index}"] = key
            environment[f"GIT_CONFIG_VALUE_{index}"] = value
        command = (
            ". " + _powershell_single_quote(str(script)) +
            "; Get-ReleaseSourceFingerprint -RepoRoot " +
            _powershell_single_quote(str(REPO)) + " -Component emule"
        )
        process = subprocess.run(
            [str(powershell), "-NoLogo", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-Command", command],
            cwd=REPO, env=environment, check=False,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180,
        )
    require(process.returncode == 0 and process.stderr == b"" and
            len(process.stdout) <= 4096,
            "legacy release source fingerprint execution")
    try:
        lines = process.stdout.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise GateError("legacy release source fingerprint encoding") from exc
    require(len(lines) == 1 and re.fullmatch(r"[0-9A-F]{64}", lines[0]) is not None and
            script.read_bytes() == script_raw and
            _git_text("rev-parse", "HEAD") == head_before and
            _blob(a_commit, script_relative) == script_raw and
            _git_executable() == git_before and
            _file_sha256(powershell) == PINNED_POWERSHELL_SHA256,
            "legacy release source fingerprint identity")
    return lines[0]


def _verify_m_with_closed_legacy(m_commit: str, a_commit: str) -> None:
    legacy = _import_old_verifier()
    physical_relative = getattr(legacy, "OLD_VERIFIER", None)
    historical_hashes = getattr(legacy, "HISTORICAL_GOV_SHA256", None)
    require(isinstance(physical_relative, str) and
            isinstance(historical_hashes, dict) and
            historical_hashes.get(physical_relative) ==
                LEGACY_PHYSICAL_VERIFIER_SHA256,
            "legacy physical verifier pin")
    physical_path = _assert_regular_path(
        REPO / physical_relative, False, "legacy physical verifier path",
    )
    require(_file_sha256(physical_path) == LEGACY_PHYSICAL_VERIFIER_SHA256,
            "legacy physical verifier byte identity")
    physical = _load_authenticated_source_module(
        "physical_verifier_closed_for_g12", physical_path,
        LEGACY_PHYSICAL_VERIFIER_SHA256, "legacy physical verifier",
    )
    require(_file_sha256(physical_path) == LEGACY_PHYSICAL_VERIFIER_SHA256,
            "legacy physical verifier byte identity")

    def closed_git(*args: str) -> str:
        return _git_text(*args)

    def closed_blob(commit: str, path: str) -> bytes:
        return _blob(commit, path)

    def closed_parents(commit: str) -> list[str]:
        return _parents(commit)

    def closed_changed(parent: str, child: str) -> list[str]:
        return _changed_between(parent, child)

    def reject_legacy_shell(*_args: str) -> str:
        raise GateError("legacy ambient shell disabled")

    class RejectLegacySubprocess:
        def __getattr__(self, _name: str):
            raise GateError("legacy ambient subprocess disabled")

    for module in (legacy, physical):
        module.subprocess = RejectLegacySubprocess()
        module.sh = reject_legacy_shell
        module.git = closed_git
        module.blob = closed_blob
        module.parents = closed_parents
        module.changed = closed_changed
    physical.release_source_fingerprint = lambda: \
        _closed_legacy_release_source_fingerprint(a_commit)
    legacy.import_old_verifier = lambda: physical
    try:
        legacy.verify_m(m_commit, a_commit)
    except Exception as exc:
        raise GateError("closed legacy M64 verification") from exc
    require(_file_sha256(physical_path) == LEGACY_PHYSICAL_VERIFIER_SHA256 and
            _file_sha256(_assert_regular_path(
                OLD_GOVERNANCE_VERIFIER, False, "legacy verifier path",
            )) == G11_SHA256[
                "tools/architecture/verify_v92_o01_clock_repair_governance.py"
            ], "closed legacy verifier changed")


def verify_m(m_commit: str, a_commit: str) -> None:
    _require_single_parent(m_commit, a_commit, "M64")
    require(_changed_between(a_commit, m_commit) == _m_paths(a_commit), "M64 exact delta")
    _verify_m_with_closed_legacy(m_commit, a_commit)


def _validate_runtime_bindings(value: Any, manifest: dict[str, Any],
                               immutable: dict[str, Any]) -> dict[str, Any]:
    exact_keys(value, RUNTIME_BINDING_KEYS, "H64 runtime bindings")
    require(value["node_version"] == immutable["node_version"] and
            value["node_sha256"] == immutable["node_sha256"] and
            value["executable_sha256"] == manifest["executable_sha256"],
            "H64 pinned runtime identity")
    for key in ("node_sha256", "executable_sha256", "build_info_sha256",
                "package_manifest_sha256"):
        require_sha(value[key], f"H64 {key}")
    require_int(value["package_manifest_entry_count"], 1, 10000,
                "H64 package manifest entries")
    require_int(value["package_file_count"], 2, 10001, "H64 package file count")
    require(value["package_file_count"] == value["package_manifest_entry_count"] + 1,
            "H64 package count relation")
    return value


def _validate_build_artifact_bindings(value: Any,
                                      runtime: dict[str, Any]) -> dict[str, Any]:
    exact_keys(value, BUILD_ARTIFACT_BINDING_KEYS, "H64 build artifact bindings")
    require(value["release_tag"] == RELEASE_TAG and
            value["package_zip_path"] == PACKAGE_ZIP_PATH and
            value["package_zip_sidecar_path"] == PACKAGE_ZIP_SIDECAR_PATH,
            "H64 build artifact paths")
    require_sha(value["package_zip_sha256"], "H64 package ZIP SHA-256")
    require_sha(value["package_zip_sidecar_sha256"], "H64 package ZIP sidecar SHA-256")
    require_int(value["package_zip_bytes"], 22, MAX_PACKAGE_ZIP_BYTES,
                "H64 package ZIP bytes")
    require_int(value["package_zip_entry_count"], 2, 10001,
                "H64 package ZIP entry count")
    require(value["package_zip_entry_count"] == runtime["package_file_count"],
            "H64 package ZIP/file count relation")
    sidecar = (value["package_zip_sha256"].upper() + "  " +
               PACKAGE_ZIP_BASENAME + "\r\n").encode("ascii")
    require_int(value["package_zip_sidecar_bytes"], 1, 4096,
                "H64 package ZIP sidecar bytes")
    require(value["package_zip_sidecar_bytes"] == len(sidecar) and
            value["package_zip_sidecar_sha256"] == sha256(sidecar),
            "H64 package ZIP sidecar identity")
    return value


def _gate_result(name: str, runtime: dict[str, Any], build: dict[str, Any],
                 a_commit: str, a_tree: str, m_commit: str, m_tree: str) -> dict[str, Any]:
    if name == "G12_HOSTILE":
        return {
            "schema": "ese.v92.o01-rpc-failure-governance-hostile-tests/v1",
            "verdict": "PASS", "tests_run": 17, "failures": 0, "errors": 0,
            "a64_freeze": "FROZEN_EXACT13",
        }
    if name == "G12_VERIFY":
        return result("VERIFY", "M64")
    if name == "NODE22_FULL":
        return {"schema": "ese.v92.o01-node-test-summary/v2", "verdict": "PASS",
                "node_version": runtime["node_version"],
                "node_sha256": runtime["node_sha256"], "tests": 436, "passed": 435,
                "failed": 0, "skipped": 1, "npm_version": PINNED_NPM_VERSION,
                "package_lock_sha256": "0d5f46ff0e004c43c7511ce1f31367469d989746c4c1725fc5131b6d04c0eeaf",
                "node_modules_file_count": PINNED_NAT_GATEWAY_MODULE_FILE_COUNT,
                "node_modules_directory_count": PINNED_NAT_GATEWAY_MODULE_DIRECTORY_COUNT,
                "node_modules_identity_sha256": PINNED_NAT_GATEWAY_MODULE_IDENTITY_SHA256,
                "npm_ci_ignore_scripts": True}
    if name == "A64_FOCAL":
        return {"schema": "ese.v92.o01-node-test-summary/v2", "verdict": "PASS",
                "node_version": runtime["node_version"],
                "node_sha256": runtime["node_sha256"], "tests": 67, "passed": 67,
                "failed": 0, "skipped": 0, "npm_version": PINNED_NPM_VERSION,
                "package_lock_sha256": "0d5f46ff0e004c43c7511ce1f31367469d989746c4c1725fc5131b6d04c0eeaf",
                "node_modules_file_count": PINNED_NAT_GATEWAY_MODULE_FILE_COUNT,
                "node_modules_directory_count": PINNED_NAT_GATEWAY_MODULE_DIRECTORY_COUNT,
                "node_modules_identity_sha256": PINNED_NAT_GATEWAY_MODULE_IDENTITY_SHA256,
                "npm_ci_ignore_scripts": True}
    if name == "POWERSHELL_PARSE":
        return {"schema": "ese.v92.o01-powershell-parse/v1", "verdict": "PASS",
                "powershell_version": "5.1", "edition": "Desktop", "parsed_paths": 4}
    if name == "RPC_PUMP_MOCK":
        return {
            "schema": "ese.v92.o01-formal-rpc-pump-mock/v3", "verdict": "PASS",
            "requests": 3, "credential_serialized": False, "closed_host_failure": True,
            "hostile_stderr_bytes": 1048576, "stderr_tail_max": 16384,
            "rpc_failure_atomic": True, "rpc_failure_private": True,
            "failure_v3_bound": True, "checkpoint_chain_bound": True,
            "pump_failures_published": True,
        }
    if name == "FORMAL_RUNNER_MOCK":
        return {
            "schema": "ese.v92.o01-formal-runner-mock/v2", "verdict": "PASS",
            "hyperv_executed": False, "release_gate_emitted": False,
            "rollback_mock": True, "rpc_mock": True, "validated_inputs": 96,
            "sealed_artifacts": 98, "partial_pass_carriers_removed": True,
        }
    if name == "VM_SESSION_MOCK":
        return {"schema": "ese.v92.o01-vm-session-mock/v1", "verdict": "PASS",
                "rollback_phases": 8, "start_failure_points": 10,
                "baseline_always_attempted": True}
    if name == "FORMAL_PRODUCT_MOCK":
        return {"schema": "ese.v92.o01-product-soak-mock/v1", "verdict": "PASS",
                "formal_evidence_emitted": False}
    if name == "BUILD_ALL":
        receipt_path = f"artifacts/v92-o01-release-build-{a_commit[:8]}/emule-release-build.json"
        return _build_result_from_receipt(
            _blob(m_commit, receipt_path), a_commit, a_tree, runtime, build,
        )
    if name == "PACKAGE_AUDIT":
        return {
            "schema": "ese.v92.o01-package-audit/v2", "verdict": "PASS",
            "runtime_bindings": runtime, "build_artifact_bindings": build,
            "package_snapshot_sha256": sha256(canonical({
                "runtime_bindings": runtime, "build_artifact_bindings": build,
            })),
            "manifest_exact_set": True, "manifest_hashes_verified": True,
            "zip_exact_set": True, "zip_hashes_verified": True,
            "sidecar_exact": True,
        }
    if name == "MOD02_RUNTIME":
        summary_path = f"artifacts/mod02-runtime-v92-{a_commit[:8]}/summary.json"
        return {"schema": "ese.v92.o01-mod02-gate/v1", "verdict": "PASS",
                "source_commit": a_commit, "source_tree": a_tree,
                "summary_sha256": sha256(_blob(m_commit, summary_path))}
    require(name == "DIFF_CHECK", "known offline gate")
    return {"schema": "ese.v92.o01-diff-check/v1", "verdict": "PASS",
            "stdout_bytes": 0, "stderr_bytes": 0}


def _gate_cwd(name: str) -> str:
    if name in {"BUILD_ALL", "MOD02_RUNTIME", "NODE22_FULL", "A64_FOCAL"}:
        return "<FRESH_A64_WORKTREE>"
    return "<M64_WORKTREE>"


def _validate_gate_records(value: Any, a_commit: str, a_tree: str,
                           m_commit: str, m_tree: str, runtime: dict[str, Any],
                           build: dict[str, Any]) -> str:
    require(isinstance(value, list) and len(value) == len(OFFLINE_GATES),
            "offline gate count")
    for record, expected in zip(value, OFFLINE_GATES):
        exact_keys(record, [
            "evidence_kind", "name", "phase", "source_commit", "source_tree",
            "input_worktree_state", "normalized_cwd", "cwd_sha256",
            "normalized_argv", "argv_sha256", "exit_code", "result",
            "stdout_sha256", "stderr_sha256",
        ], "offline gate record")
        name, phase, normalized_argv, _ = expected
        expected_commit, expected_tree = ((a_commit, a_tree) if phase == "A64" else
                                          (m_commit, m_tree))
        expected_result = _gate_result(
            name, runtime, build, a_commit, a_tree, m_commit, m_tree,
        )
        require(record["evidence_kind"] == "REVIEW_ATTESTED_EXECUTION" and
                record["name"] == name and record["phase"] == phase and
                record["source_commit"] == expected_commit and
                record["source_tree"] == expected_tree and
                record["input_worktree_state"] == "CLEAN" and
                record["normalized_cwd"] == _gate_cwd(name) and
                record["cwd_sha256"] == sha256(canonical(_gate_cwd(name))) and
                record["normalized_argv"] == list(normalized_argv) and
                record["argv_sha256"] == sha256(canonical(list(normalized_argv))) and
                type(record["exit_code"]) is int and record["exit_code"] == 0 and
                canonical(record["result"]) == canonical(expected_result),
                "offline gate identity")
        for key in ("stdout_sha256", "stderr_sha256"):
            require_sha(record[key], f"offline gate {key}")
        if name in {"G12_HOSTILE", "G12_VERIFY", "NODE22_FULL", "A64_FOCAL",
                    "POWERSHELL_PARSE", "BUILD_ALL", "PACKAGE_AUDIT",
                    "MOD02_RUNTIME", "RPC_PUMP_MOCK", "FORMAL_RUNNER_MOCK",
                    "VM_SESSION_MOCK", "FORMAL_PRODUCT_MOCK", "DIFF_CHECK"}:
            emitted = json.dumps(record["result"], sort_keys=True,
                                 separators=(",", ":")).encode("ascii") + b"\n"
            require(record["stdout_sha256"] == sha256(emitted),
                    "JSON gate stdout identity")
    return sha256(canonical(value))


def _validate_review(raw: bytes, role: str, g_commit: str, g_tree: str,
                     a_commit: str, a_tree: str, m_commit: str, m_tree: str,
                     offline_sha256: str, gate_sha256: str,
                     runtime_sha256: str, build_sha256: str) -> None:
    value = load_json_bytes(raw, f"{role} review")
    exact_keys(value, [
        "schema", "role", "g_commit", "g_tree", "a_commit", "a_tree",
        "m_commit", "m_tree", "offline_summary_sha256",
        "gate_attestations_sha256", "runtime_bindings_sha256",
        "build_artifact_bindings_sha256", "verdict", "findings",
    ], f"{role} review")
    require_exact_value(value, {
        "schema": "ese.v92.o01-review/v2", "role": role,
        "g_commit": g_commit, "g_tree": g_tree,
        "a_commit": a_commit, "a_tree": a_tree,
        "m_commit": m_commit, "m_tree": m_tree,
        "offline_summary_sha256": offline_sha256,
        "gate_attestations_sha256": gate_sha256,
        "runtime_bindings_sha256": runtime_sha256,
        "build_artifact_bindings_sha256": build_sha256,
        "verdict": "APPROVE", "findings": [],
    }, f"{role} review identity")


def verify_h(h_commit: str, m_commit: str, a_commit: str, g_commit: str,
             document: dict[str, Any]) -> None:
    _require_single_parent(h_commit, m_commit, "H64")
    require(_changed_between(m_commit, h_commit) == H_PATHS, "H64 exact delta")
    a_tree = _git_text("rev-parse", f"{a_commit}^{{tree}}")
    g_tree = _git_text("rev-parse", f"{g_commit}^{{tree}}")
    m_tree = _git_text("rev-parse", f"{m_commit}^{{tree}}")
    immutable = document["immutable_contract"]
    triad = _governance_sha(lambda path: _blob(g_commit, path))
    triad_identity = sha256(ordered_canonical(path_hash_document(triad)))
    manifest = load_json_bytes(
        _blob(m_commit, "docs/architecture/mod02_build_manifest_v1.json"),
        "M64 build manifest",
    )
    old = _import_old_verifier()
    exact_keys(manifest, ["schema", "source_commit", "source_identity_sha256",
                          "executable_sha256"], "M64 build manifest")
    require_exact_value(manifest, {
        "schema": "ese.mod02.build-manifest/v1",
        "source_commit": a_commit,
        "source_identity_sha256": old.MOD02_IDENTITY,
        "executable_sha256": manifest["executable_sha256"],
    }, "M64 build manifest identity")
    require_sha(manifest["executable_sha256"], "M64 executable SHA-256")
    offline_raw = _blob(h_commit, H_PATHS[1])
    offline = load_json_bytes(offline_raw, "H64 offline summary")
    exact_keys(offline, [
        "schema", "source_commit", "source_tree", "g_commit", "g_tree", "m_commit", "m_tree",
        "g12_governance_sha256", "a64_paths_sha256", "a64_byte_identity_sha256",
        "a64_numstat_identity_sha256", "code_allowlist_sha256",
        "tuple_allowlist_sha256", "runtime_bindings", "build_artifact_bindings",
        "gates", "gate_attestations_sha256",
    ], "H64 offline summary")
    require(offline["schema"] == "ese.v92.o01-rpc-repair-offline-summary/v1",
            "H64 offline schema")
    require(offline["source_commit"] == a_commit and offline["source_tree"] == a_tree and
            offline["g_commit"] == g_commit and offline["g_tree"] == g_tree and
            offline["m_commit"] == m_commit and offline["m_tree"] == m_tree,
            "H64 offline identities")
    require(offline["g12_governance_sha256"] == triad and
            offline["a64_paths_sha256"] == A_PATHS_SHA256 and
            offline["a64_byte_identity_sha256"] == A_BYTES_SHA256 and
            offline["a64_numstat_identity_sha256"] == A_NUMSTAT_SHA256 and
            offline["code_allowlist_sha256"] == RPC_CODE_ALLOWLIST_SHA256 and
            offline["tuple_allowlist_sha256"] == RPC_TUPLE_ALLOWLIST_SHA256,
            "H64 offline bindings")
    runtime_bindings = _validate_runtime_bindings(offline["runtime_bindings"],
                                                 manifest, immutable)
    build_artifact_bindings = _validate_build_artifact_bindings(
        offline["build_artifact_bindings"], runtime_bindings,
    )
    gate_sha = _validate_gate_records(
        offline["gates"], a_commit, a_tree, m_commit, m_tree,
        runtime_bindings, build_artifact_bindings,
    )
    require(offline["gate_attestations_sha256"] == gate_sha,
            "H64 gate attestation identity")
    runtime_sha = sha256(canonical(runtime_bindings))
    build_sha = sha256(canonical(build_artifact_bindings))
    reviews = {
        "Sol": _blob(h_commit, H_PATHS[2]),
        "Terra": _blob(h_commit, H_PATHS[3]),
    }
    for role, raw in reviews.items():
        _validate_review(
            raw, role, g_commit, g_tree, a_commit, a_tree, m_commit, m_tree,
            sha256(offline_raw), gate_sha, runtime_sha, build_sha,
        )
    artifact_sha = {
        H_PATHS[1]: sha256(offline_raw),
        H_PATHS[2]: sha256(reviews["Sol"]),
        H_PATHS[3]: sha256(reviews["Terra"]),
    }
    activation = load_json_bytes(_blob(h_commit, H_PATHS[0]), "H64 activation")
    exact_keys(activation, document["h64_activation_contract"]["required_exact_keys"],
               "H64 activation")
    require_exact_value(activation, {
        "schema": "ese.v92.o01-rpc-repair-activation/v1",
        "predecessor_h_commit": BASE["h63_commit"],
        "g_commit": g_commit, "g_tree": g_tree,
        "g12_governance_sha256": triad,
        "g12_governance_identity_sha256": triad_identity,
        "amendment_sha256": triad[GOVERNANCE_PATHS[0]],
        "a_commit": a_commit, "a_tree": a_tree,
        "a64_paths_sha256": A_PATHS_SHA256,
        "a64_byte_identity_sha256": A_BYTES_SHA256,
        "a64_numstat_identity_sha256": A_NUMSTAT_SHA256,
        "code_allowlist_sha256": RPC_CODE_ALLOWLIST_SHA256,
        "tuple_allowlist_sha256": RPC_TUPLE_ALLOWLIST_SHA256,
        "scenario_sha256": immutable["scenario_sha256"],
        "scenario_blob": immutable["scenario_blob"],
        "product_mapper_sha256": immutable["product_mapper_sha256"],
        "product_mapper_blob": immutable["product_mapper_blob"],
        "m_commit": m_commit, "m_tree": m_tree,
        "runtime_bindings": runtime_bindings,
        "build_artifact_bindings": build_artifact_bindings,
        "gate_attestations_sha256": gate_sha,
        "artifact_sha256": artifact_sha,
    }, "H64 activation identity")


def _r_paths() -> list[str]:
    root = "artifacts/v92-o01-formal/"
    return sorted(
        [f"{root}checkpoint-{ordinal:02d}.json" for ordinal in range(1, 96)]
        + [f"{root}controller-result.json", f"{root}formal-run-result.json",
           f"{root}formal-validation.json"]
    )


def _validate_formal_run(run: Any, bindings: dict[str, Any], a_commit: str,
                         a_tree: str, h_commit: str) -> None:
    exact_keys(run, FORMAL_RUN_KEYS, "R64 formal run")
    for key, expected in (("duration_ms", 28800000), ("product_records", 482),
                          ("checkpoints", 95), ("fault_slots", 96)):
        require_int(run[key], expected, expected, f"R64 {key}")
    run_bindings = {key: run[key] for key in RUNTIME_BINDING_KEYS}
    require(run["schema"] == "ese.v92.o01-formal-run/v2" and
            run["verdict"] == "PASS" and run["release_gate"] is True and
            run["source_commit"] == a_commit and run["source_tree"] == a_tree and
            run["governance_h_commit"] == h_commit and
            run["governance_s_commit"] is None and
            run["baseline_restored"] is True and
            run["independent_validation"] is True and
            canonical(run_bindings) == canonical(bindings),
            "R64 formal run identity")
    require_int(run["package_manifest_entry_count"], 1, 10000,
                "R64 package manifest entries")
    require_int(run["package_file_count"], 2, 10001, "R64 package files")
    require(run["package_file_count"] == run["package_manifest_entry_count"] + 1,
            "R64 package count relation")


def _assert_isolated_executable_set(
        directory: Path, expected: dict[str, tuple[str, int]], label: str,
) -> dict[str, Path]:
    directory = _assert_regular_path(directory, True, label)
    entries = list(os.scandir(directory))
    expected_folded = {name.casefold(): name for name in expected}
    require(len(expected_folded) == len(expected) and len(entries) == len(expected), label)
    observed: dict[str, Path] = {}
    for entry in entries:
        folded = entry.name.casefold()
        require(folded in expected_folded and folded not in observed, label)
        name = expected_folded[folded]
        path = _assert_regular_path(Path(entry.path), False, label)
        digest, size = expected[name]
        require(path.name == name and path.stat().st_size == size and
                _file_sha256(path) == digest, label)
        observed[folded] = path
    return {name: observed[name.casefold()] for name in expected}


def _assert_mod02_runtime_post(
        directory: Path, expected: dict[str, tuple[str, int]], label: str,
) -> dict[str, Path]:
    directory = _assert_regular_path(directory, True, label)
    expected_folded = {name.casefold(): name for name in expected}
    require(len(expected_folded) == len(expected), label)
    forbidden_suffixes = {
        ".bat", ".cmd", ".com", ".cpl", ".dll", ".exe", ".ocx",
        ".ps1", ".psm1", ".scr", ".sys",
    }
    observed: dict[str, Path] = {}
    stack = [directory]
    total_entries = 0
    while stack:
        current = stack.pop()
        entries = list(os.scandir(current))
        folded_names = [entry.name.casefold() for entry in entries]
        require(len(folded_names) == len(set(folded_names)), label)
        for entry in entries:
            total_entries += 1
            require(total_entries <= 10000, label)
            path = Path(entry.path)
            if entry.is_dir(follow_symlinks=False):
                stack.append(_assert_regular_path(path, True, label))
                continue
            regular = _assert_regular_path(path, False, label)
            if current == directory:
                folded = entry.name.casefold()
                require(folded in expected_folded and folded not in observed, label)
                name = expected_folded[folded]
                digest, size = expected[name]
                require(regular.name == name and regular.stat().st_size == size and
                        _file_sha256(regular) == digest, label)
                observed[folded] = regular
            else:
                require(regular.suffix.casefold() not in forbidden_suffixes, label)
    require(set(observed) == set(expected_folded), label)
    return {name: observed[name.casefold()] for name in expected}


def _assert_mod02_runtime_initial(
        directory: Path, expected: dict[str, tuple[str, int]],
        preference_expected: tuple[str, int], label: str,
) -> dict[str, Path]:
    observed = _assert_mod02_runtime_post(directory, expected, label)
    entries = list(os.scandir(directory))
    require({entry.name for entry in entries} ==
            set(expected) | {"config"}, label)
    config = _assert_regular_path(directory / "config", True, label)
    _assert_isolated_executable_set(
        config, {"preferences.ini": preference_expected}, label,
    )
    return observed


def _assert_isolated_executable(directory: Path, executable: Path,
                                expected_sha256: str, expected_bytes: int,
                                label: str) -> None:
    observed = _assert_isolated_executable_set(
        directory, {executable.name: (expected_sha256, expected_bytes)}, label,
    )
    require(observed[executable.name] == executable.resolve(strict=True), label)


def _copy_isolated_executable(source: Path, directory: Path, name: str,
                              expected_sha256: str, expected_bytes: int,
                              label: str) -> Path:
    source = _assert_regular_path(source, False, label)
    require(source.stat().st_size == expected_bytes and
            _file_sha256(source) == expected_sha256 and
            not os.path.lexists(directory), label)
    directory.mkdir()
    _assert_regular_path(directory, True, label)
    destination = directory / name
    with source.open("rb") as reader, destination.open("xb") as writer:
        shutil.copyfileobj(reader, writer, 1024 * 1024)
        writer.flush()
        os.fsync(writer.fileno())
    _assert_isolated_executable(directory, destination, expected_sha256,
                                expected_bytes, label)
    require(_file_sha256(source) == expected_sha256 and
            source.stat().st_size == expected_bytes, label)
    return destination.resolve(strict=True)


def _copy_isolated_executable_set(
        sources: dict[str, tuple[Path, str]], directory: Path, label: str,
) -> tuple[dict[str, Path], dict[str, tuple[str, int]]]:
    require(sources and len({name.casefold() for name in sources}) == len(sources) and
            not os.path.lexists(directory), label)
    expected: dict[str, tuple[str, int]] = {}
    authenticated: dict[str, Path] = {}
    for name, (source_value, digest) in sources.items():
        source = _assert_regular_path(source_value, False, label)
        size = source.stat().st_size
        require(_file_sha256(source) == digest, label)
        authenticated[name] = source
        expected[name] = (digest, size)
    directory.mkdir()
    _assert_regular_path(directory, True, label)
    for name, source in authenticated.items():
        with source.open("rb") as reader, (directory / name).open("xb") as writer:
            shutil.copyfileobj(reader, writer, 1024 * 1024)
            writer.flush()
            os.fsync(writer.fileno())
    isolated = _assert_isolated_executable_set(directory, expected, label)
    require(all(_file_sha256(authenticated[name]) == expected[name][0] and
                authenticated[name].stat().st_size == expected[name][1]
                for name in authenticated), label)
    return isolated, expected


def _isolated_node_environment(scratch: Path) -> dict[str, str]:
    require(os.name == "nt", "isolated Node Windows runtime")
    scratch = _assert_regular_path(scratch, True, "isolated Node scratch")
    system_root = _assert_regular_path(Path(r"C:\Windows"), True,
                                       "isolated Node SystemRoot")
    command_processor = _assert_regular_path(
        system_root / "System32/cmd.exe", False, "isolated Node command processor",
    )
    require(_file_sha256(command_processor) == PINNED_CMD_SHA256,
            "isolated Node command processor identity")
    return {
        "SystemRoot": str(system_root), "WINDIR": str(system_root),
        "COMSPEC": str(command_processor), "PATH": str(command_processor.parent),
        "PATHEXT": ".COM;.EXE;.BAT;.CMD", "TEMP": str(scratch), "TMP": str(scratch),
    }


def _run_product_validator_pinned(materialized: Path,
                                  bindings: dict[str, Any],
                                  node_source_arg: str | Path | None = None) -> None:
    resolved = shutil.which("node") if node_source_arg is None else str(node_source_arg)
    require(resolved is not None, "R64 Node unavailable")
    node_source = _assert_regular_path(Path(resolved), False, "R64 Node source")
    node_bytes = node_source.stat().st_size
    require(_file_sha256(node_source) == bindings["node_sha256"], "R64 Node SHA-256")
    script = (
        "const fs=require('fs'),p=require('path'),d=process.argv[1],"
        "v=require(p.join(d,'validator.js')),c=JSON.parse(fs.readFileSync(p.join(d,'scenario.json'))),"
        "r=JSON.parse(fs.readFileSync(p.join(d,'controller-result.json'))),"
        "x=Array.from({length:95},(_,i)=>JSON.parse(fs.readFileSync(p.join(d,'checkpoint-'+String(i+1).padStart(2,'0')+'.json'))));"
        "v._validateFormalEvidenceTest({config:c,checkpoints:x,result:r});process.stdout.write('PASS');"
    )
    with tempfile.TemporaryDirectory(prefix="g12-r64-node-") as temporary_name:
        temporary = _assert_regular_path(Path(temporary_name), True,
                                         "R64 isolated Node parent")
        runtime = temporary / "runtime"
        scratch = temporary / "scratch"
        scratch.mkdir()
        node_path = _copy_isolated_executable(
            node_source, runtime, "node.exe", bindings["node_sha256"], node_bytes,
            "R64 isolated Node",
        )
        node_environment = _isolated_node_environment(scratch)
        try:
            version = subprocess.run(
                [str(node_path), "--version"], cwd=runtime, check=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
                env=node_environment,
            )
            require(version.stdout == ("v" + bindings["node_version"] + "\r\n").encode("ascii")
                    and version.stderr == b"", "R64 Node version")
            output = subprocess.run(
                [str(node_path), "-e", script, str(materialized)], cwd=runtime,
                check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=120, env=node_environment,
            )
            require(output.stdout == b"PASS" and output.stderr == b"",
                    "R64 product validator output")
            final_version = subprocess.run(
                [str(node_path), "--version"], cwd=runtime, check=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
                env=node_environment,
            )
            _assert_isolated_executable(runtime, node_path, bindings["node_sha256"],
                                        node_bytes, "R64 isolated Node changed")
            node_source = _assert_regular_path(node_source, False, "R64 Node source")
            require(_file_sha256(node_source) == bindings["node_sha256"] and
                    node_source.stat().st_size == node_bytes and
                    final_version.stdout == version.stdout and final_version.stderr == b"",
                    "R64 Node changed")
        finally:
            _assert_isolated_executable(runtime, node_path, bindings["node_sha256"],
                                        node_bytes, "R64 isolated Node cleanup")
            node_path.unlink()
            require(list(os.scandir(runtime)) == [], "R64 isolated Node cleanup")
            runtime.rmdir()
            require(list(os.scandir(scratch)) == [], "R64 isolated Node scratch cleanup")
            scratch.rmdir()
        require(not os.path.lexists(runtime) and not os.path.lexists(scratch),
                "R64 isolated Node cleanup")


def _validate_formal_evidence(reader, bindings: dict[str, Any], a_commit: str,
                              a_tree: str, h_commit: str,
                              document: dict[str, Any], *,
                              node_source: str | Path | None = None) -> dict[str, Any]:
    old = _import_old_verifier()
    root = "artifacts/v92-o01-formal/"
    run_path = root + "formal-run-result.json"
    controller_path = root + "controller-result.json"
    validation_path = root + "formal-validation.json"
    run_raw = reader("formal-run-result.json")
    controller_raw = reader("controller-result.json")
    run = load_json_bytes(run_raw, "R64 formal run")
    _validate_formal_run(run, bindings, a_commit, a_tree, h_commit)

    result_value = load_json_bytes(controller_raw, "R64 controller result")
    require(result_value.get("source_commit") == a_commit and
            result_value.get("source_tree") == a_tree and
            result_value.get("verdict") == "PASS",
            "R64 controller result identity")
    require_int(result_value.get("checkpoint_count"), 95, 95,
                "R64 controller checkpoint count")
    raw = {controller_path: controller_raw, run_path: run_raw}
    checkpoints: list[bytes] = []
    for index in range(1, 96):
        name = f"checkpoint-{index:02d}.json"
        path = root + name
        data = reader(name)
        raw[path] = data
        checkpoints.append(data)
    validation = load_json_bytes(reader("formal-validation.json"), "R64 validation")
    exact_keys(validation, [
        "schema", "verdict", "source_commit", "source_tree", "governance_h_commit",
        "governance_s_commit", "validator_sha256", "scenario_sha256",
        "artifacts_sha256", "chain_tip_sha256", "checkpoints", "fault_slots",
        "ticks", "samples",
    ], "R64 formal validation")
    validator_blob = _blob(a_commit, "tools/lab/nat_gateway/v92_o01_validate_formal.js")
    scenario_blob = _blob(a_commit, old.SCENARIO)
    expected_validation = {
        "schema": "ese.v92.o01-formal-validation/v2", "verdict": "PASS",
        "source_commit": a_commit, "source_tree": a_tree,
        "governance_h_commit": h_commit, "governance_s_commit": None,
        "validator_sha256": sha256(validator_blob),
        "scenario_sha256": sha256(scenario_blob),
        "artifacts_sha256": {path: sha256(data) for path, data in sorted(raw.items())},
        "chain_tip_sha256": result_value.get("chain_tip_sha256"),
        "checkpoints": 95, "fault_slots": 96, "ticks": 2880, "samples": 480,
    }
    require_exact_value(validation, expected_validation, "R64 formal validation")
    old.verify_scenario(scenario_blob, "R64")
    bound = result_value.get("bound_files")
    require(isinstance(bound, list) and len(bound) == 21, "R64 bound paths")
    for index, path in enumerate(old.BOUND_FILES):
        require_exact_value(
            bound[index], {"path": path, "sha256": sha256(_blob(a_commit, path))},
            "R64 bound file identity",
        )
    with tempfile.TemporaryDirectory(prefix="o01-g12-governance-") as temporary:
        materialized = Path(temporary)
        (materialized / "validator.js").write_bytes(validator_blob)
        (materialized / "scenario.json").write_bytes(scenario_blob)
        (materialized / "controller-result.json").write_bytes(controller_raw)
        for index, data in enumerate(checkpoints, 1):
            (materialized / f"checkpoint-{index:02d}.json").write_bytes(data)
        _run_product_validator_pinned(materialized, bindings, node_source)
    return run


def verify_r(r_commit: str, h_commit: str, a_commit: str, m_commit: str,
             document: dict[str, Any]) -> None:
    _require_single_parent(r_commit, h_commit, "R64")
    observed = _changed_between(h_commit, r_commit)
    require(observed == _r_paths(), "R64 exact delta")
    validate_r64_paths([PurePosixPath(path).name for path in observed])
    old = _import_old_verifier()
    a_tree = _git_text("rev-parse", f"{a_commit}^{{tree}}")
    manifest = load_json_bytes(
        _blob(m_commit, "docs/architecture/mod02_build_manifest_v1.json"),
        "M64 build manifest for R64",
    )
    exact_keys(manifest, [
        "schema", "source_commit", "source_identity_sha256", "executable_sha256",
    ], "M64 build manifest for R64")
    require_exact_value(manifest, {
        "schema": "ese.mod02.build-manifest/v1", "source_commit": a_commit,
        "source_identity_sha256": old.MOD02_IDENTITY,
        "executable_sha256": manifest["executable_sha256"],
    }, "R64 M64 manifest identity")
    require_sha(manifest["executable_sha256"], "R64 executable SHA-256")

    activation = load_json_bytes(_blob(h_commit, H_PATHS[0]), "H64 activation for R64")
    bindings = _validate_runtime_bindings(
        activation.get("runtime_bindings"), manifest, document["immutable_contract"],
    )
    node_binding = _audit_node_distribution(
        PINNED_NODE_PATH, document["immutable_contract"],
    )
    _validate_formal_evidence(
        lambda name: _blob(r_commit, "artifacts/v92-o01-formal/" + name),
        bindings, a_commit, a_tree, h_commit, document,
        node_source=node_binding["node"],
    )


def autodetect(document: dict[str, Any]) -> str:
    head = _git_text("rev-parse", "HEAD")
    chain: list[str] = []
    current = head
    while current != BASE["h63_commit"] and len(chain) < 6:
        chain.append(current)
        parents = _parents(current)
        require(len(parents) == 1, "merge topology")
        current = parents[0]
    require(current == BASE["h63_commit"], "H63 ancestry")
    require(1 <= len(chain) <= 5, "missing G12 or intermediate phase")
    chain.reverse()
    g_commit = chain[0]
    verify_g(g_commit, document)
    if len(chain) == 1:
        return "G12"
    a_commit = chain[1]
    verify_a(a_commit, g_commit, document)
    if len(chain) == 2:
        return "A64"
    m_commit = chain[2]
    verify_m(m_commit, a_commit)
    if len(chain) == 3:
        return "M64"
    h_commit = chain[3]
    verify_h(h_commit, m_commit, a_commit, g_commit, document)
    if len(chain) == 4:
        return "H64"
    require(len(chain) == 5, "intermediate before R64")
    verify_r(chain[4], h_commit, a_commit, m_commit, document)
    return "R64"


def _assert_regular_path(path: Path, expect_directory: bool, label: str) -> Path:
    original = Path(os.path.abspath(path))
    current = original
    while True:
        try:
            stat_value = os.lstat(current)
        except FileNotFoundError:
            stat_value = None
        if stat_value is not None:
            attributes = getattr(stat_value, "st_file_attributes", 0)
            require(not os.path.islink(current) and not (attributes & 0x400),
                    f"{label} reparse")
        if current.parent == current:
            break
        current = current.parent
    resolved = original.resolve(strict=True)
    require(resolved.is_dir() if expect_directory else resolved.is_file(), label)
    return resolved


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_limited(path: Path, maximum: int, label: str) -> bytes:
    path = _assert_regular_path(path, False, label)
    size = path.stat().st_size
    require(type(size) is int and 0 <= size <= maximum, f"{label} length")
    raw = path.read_bytes()
    require(len(raw) == size and path.stat().st_size == size, f"{label} changed while read")
    return raw


def _without_node_injection_environment(source: dict[str, str] | None = None) -> dict[str, str]:
    environment = dict(os.environ if source is None else source)
    for key in list(environment):
        upper = key.upper()
        if upper == "NODE" or upper.startswith("NODE_") or upper.startswith("OPENSSL_"):
            del environment[key]
    return environment


def _assert_python_runtime(immutable: dict[str, Any]) -> tuple[Path, str]:
    executable = _assert_regular_path(Path(sys.executable), False, "Python executable")
    digest = _file_sha256(executable)
    require(digest == immutable["python_sha256"] and
            ".".join(str(value) for value in sys.version_info[:3]) ==
            immutable["python_version"], "pinned Python identity")
    return executable, digest


def _node_distribution_inventory(root: Path) -> tuple[dict[str, Any], str]:
    root = _assert_regular_path(root, True, "Node distribution root")
    directories: list[str] = []
    files: list[dict[str, Any]] = []
    folded_paths: set[str] = set()

    def walk_error(exc: OSError) -> None:
        raise GateError("Node distribution enumeration") from exc

    for directory, child_directories, child_files in os.walk(
        root, followlinks=False, onerror=walk_error,
    ):
        directory_path = _assert_regular_path(
            Path(directory), True, "Node distribution directory",
        )
        if directory_path != root:
            relative_directory = directory_path.relative_to(root).as_posix()
            folded = relative_directory.casefold()
            require(folded not in folded_paths, "Node distribution path collision")
            folded_paths.add(folded)
            directories.append(relative_directory)
        for name in list(child_directories):
            _assert_regular_path(directory_path / name, True,
                                 "Node distribution directory")
        for name in child_files:
            file_path = _assert_regular_path(directory_path / name, False,
                                             "Node distribution file")
            relative = file_path.relative_to(root).as_posix()
            folded = relative.casefold()
            require(folded not in folded_paths, "Node distribution path collision")
            folded_paths.add(folded)
            before_size = file_path.stat().st_size
            digest = _file_sha256(file_path)
            require(file_path.stat().st_size == before_size,
                    "Node distribution file changed")
            files.append({"path": relative, "bytes": before_size, "sha256": digest})
    identity = {
        "directories": sorted(directories),
        "files": sorted(files, key=lambda row: row["path"]),
    }
    return identity, sha256(canonical(identity))


def _build_python_dependency_inventory(
        root: Path, strict_root: bool = False) -> tuple[dict[str, Any], str]:
    root = _assert_regular_path(root, True, "build Python dependency root")
    directories: list[str] = []
    files: list[dict[str, Any]] = []
    folded_paths: set[str] = set()

    def walk_error(exc: OSError) -> None:
        raise GateError("build Python dependency enumeration") from exc

    for package in BUILD_PYTHON_DEPENDENCY_ROOTS:
        package_root = _assert_regular_path(
            root / package, True, "build Python dependency package",
        )
        for directory, child_directories, child_files in os.walk(
            package_root, followlinks=False, onerror=walk_error,
        ):
            directory_path = _assert_regular_path(
                Path(directory), True, "build Python dependency directory",
            )
            child_directories[:] = sorted(
                name for name in child_directories
                if name.casefold() != "__pycache__"
            )
            relative_directory = directory_path.relative_to(root).as_posix()
            folded = relative_directory.casefold()
            require(folded not in folded_paths,
                    "build Python dependency path collision")
            folded_paths.add(folded)
            directories.append(relative_directory)
            for name in child_directories:
                _assert_regular_path(
                    directory_path / name, True,
                    "build Python dependency directory",
                )
            for name in sorted(child_files):
                if name.casefold().endswith(".pyc"):
                    continue
                file_path = _assert_regular_path(
                    directory_path / name, False,
                    "build Python dependency file",
                )
                relative = file_path.relative_to(root).as_posix()
                folded = relative.casefold()
                require(folded not in folded_paths,
                        "build Python dependency path collision")
                folded_paths.add(folded)
                before_size = file_path.stat().st_size
                digest = _file_sha256(file_path)
                require(file_path.stat().st_size == before_size,
                        "build Python dependency file changed")
                files.append({"path": relative, "bytes": before_size,
                              "sha256": digest})
    for relative in BUILD_PYTHON_DEPENDENCY_FILES:
        file_path = _assert_regular_path(
            root / relative, False, "build Python dependency file",
        )
        folded = relative.casefold()
        require(folded not in folded_paths,
                "build Python dependency path collision")
        folded_paths.add(folded)
        before_size = file_path.stat().st_size
        digest = _file_sha256(file_path)
        require(file_path.stat().st_size == before_size,
                "build Python dependency file changed")
        files.append({"path": relative, "bytes": before_size, "sha256": digest})
    identity = {
        "directories": sorted(directories),
        "files": sorted(files, key=lambda row: row["path"]),
    }
    if strict_root:
        actual_directories: list[str] = []
        actual_files: list[str] = []
        actual_folded: set[str] = set()
        for directory, child_directories, child_files in os.walk(
            root, followlinks=False, onerror=walk_error,
        ):
            directory_path = _assert_regular_path(
                Path(directory), True, "build Python projection directory",
            )
            child_directories[:] = sorted(child_directories)
            if directory_path != root:
                relative_directory = directory_path.relative_to(root).as_posix()
                folded = relative_directory.casefold()
                require(folded not in actual_folded,
                        "build Python projection path collision")
                actual_folded.add(folded)
                actual_directories.append(relative_directory)
            for name in child_directories:
                _assert_regular_path(
                    directory_path / name, True,
                    "build Python projection directory",
                )
            for name in sorted(child_files):
                file_path = _assert_regular_path(
                    directory_path / name, False,
                    "build Python projection file",
                )
                relative = file_path.relative_to(root).as_posix()
                folded = relative.casefold()
                require(folded not in actual_folded,
                        "build Python projection path collision")
                actual_folded.add(folded)
                actual_files.append(relative)
        require(sorted(actual_directories) == identity["directories"] and
                sorted(actual_files) == [row["path"] for row in identity["files"]],
                "build Python projection exact set")
    return identity, sha256(canonical(identity))


def _prepare_build_python_dependency(
        python_path: Path, temporary: Path,
        immutable: dict[str, Any]) -> dict[str, Any]:
    source_root = _assert_regular_path(
        python_path.parent / "Lib/site-packages", True,
        "build Python dependency source",
    )
    source_identity, source_sha = _build_python_dependency_inventory(source_root)
    require(len(source_identity["files"]) ==
            immutable["build_python_dependency_file_count"] and
            len(source_identity["directories"]) ==
            immutable["build_python_dependency_directory_count"] and
            source_sha == immutable["build_python_dependency_identity_sha256"],
            "pinned build Python dependency identity")
    projection = temporary / "build-python-dependency"
    require(not os.path.lexists(projection),
            "fresh build Python dependency projection")
    projection.mkdir()
    for relative in source_identity["directories"]:
        (projection / PurePosixPath(relative)).mkdir()
    for row in source_identity["files"]:
        relative = PurePosixPath(row["path"])
        source = _assert_regular_path(
            source_root / relative, False, "build Python dependency source file",
        )
        destination = projection / relative
        require(not os.path.lexists(destination),
                "fresh build Python dependency file")
        with source.open("rb") as source_stream, destination.open("xb") as destination_stream:
            shutil.copyfileobj(source_stream, destination_stream)
        require(destination.stat().st_size == row["bytes"] and
                _file_sha256(destination) == row["sha256"],
                "build Python dependency copy identity")
    projection_identity, projection_sha = \
        _build_python_dependency_inventory(projection, strict_root=True)
    require(canonical(projection_identity) == canonical(source_identity) and
            projection_sha == source_sha,
            "build Python dependency projection identity")
    return {
        "source_root": source_root, "root": projection,
        "identity": source_identity, "identity_sha256": source_sha,
    }


def _audit_node_distribution(node_arg: str | Path,
                             immutable: dict[str, Any]) -> dict[str, Any]:
    node_path = _assert_regular_path(Path(node_arg), False, "Node executable")
    root = _assert_regular_path(node_path.parent, True, "Node distribution root")
    expected_node = _assert_regular_path(root / "node.exe", False, "Node executable")
    require(node_path == expected_node, "Node executable layout")
    npm_cmd = _assert_regular_path(root / "npm.cmd", False, "npm command")
    npm_cli = _assert_regular_path(root / "node_modules/npm/bin/npm-cli.js", False,
                                   "npm CLI")
    identity, identity_sha = _node_distribution_inventory(root)
    require(len(identity["files"]) == immutable["node_distribution_file_count"] and
            len(identity["directories"]) ==
            immutable["node_distribution_directory_count"] and
            identity_sha == immutable["node_distribution_identity_sha256"] and
            _file_sha256(node_path) == immutable["node_sha256"] and
            _file_sha256(npm_cmd) == immutable["npm_cmd_sha256"] and
            _file_sha256(npm_cli) == immutable["npm_cli_sha256"],
            "pinned Node/npm distribution identity")
    return {
        "root": root, "node": node_path, "npm_cmd": npm_cmd, "npm_cli": npm_cli,
        "identity_sha256": identity_sha,
        "file_count": len(identity["files"]),
        "directory_count": len(identity["directories"]),
    }


def _release_input_pins(a_commit: str,
                        immutable: dict[str, Any]) -> tuple[dict[str, Any], str]:
    release_inputs_raw = _blob(a_commit, immutable["release_inputs_path"])
    require(sha256(release_inputs_raw) == immutable["release_inputs_sha256"] and
            _git_text("rev-parse", f"{a_commit}:{immutable['release_inputs_path']}") ==
            immutable["release_inputs_blob"], "release inputs identity")
    try:
        release_inputs = json.loads(
            release_inputs_raw.decode("utf-8"), object_pairs_hook=_no_duplicates,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GateError("release inputs") from exc
    exact_keys(release_inputs, ["ffmpeg", "ffprobe"], "release inputs")
    exact_keys(release_inputs["ffmpeg"], ["version", "sha256"], "FFmpeg input")
    exact_keys(release_inputs["ffprobe"], ["sha256"], "ffprobe input")
    require(isinstance(release_inputs["ffmpeg"]["version"], str) and
            release_inputs["ffmpeg"]["version"] == "8.1-full_build-www.gyan.dev" and
            release_inputs["ffmpeg"]["sha256"] == immutable["ffmpeg_sha256"].upper() and
            release_inputs["ffprobe"]["sha256"] == immutable["ffprobe_sha256"].upper(),
            "release input pins")
    nodes_pin_raw = _blob(a_commit, immutable["nodes_dat_pin_path"])
    require(sha256(nodes_pin_raw) == immutable["nodes_dat_pin_sha256"] and
            _git_text("rev-parse", f"{a_commit}:{immutable['nodes_dat_pin_path']}") ==
            immutable["nodes_dat_pin_blob"], "nodes.dat pin identity")
    try:
        nodes_pin_text = nodes_pin_raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise GateError("nodes.dat pin") from exc
    require(re.fullmatch(r"[0-9a-f]{64}\n", nodes_pin_text) is not None,
            "nodes.dat pin")
    return release_inputs, nodes_pin_text.rstrip("\n")


def _parse_release_receipt(raw: bytes, a_commit: str, release_tag: str,
                           label: str) -> dict[str, Any]:
    require(0 < len(raw) <= MAX_RELEASE_RECEIPT_BYTES, f"{label} length")
    try:
        receipt = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GateError(label) from exc
    exact_keys(receipt, [
        "schema", "component", "releaseTag", "commit", "sourceFingerprint",
        "binarySha256", "binaryLength", "builtAtUtc",
    ], label)
    require(type(receipt["schema"]) is int and receipt["schema"] == 1 and
            receipt["component"] == "emule" and
            receipt["releaseTag"] == release_tag and receipt["commit"] == a_commit and
            isinstance(receipt["sourceFingerprint"], str) and
            re.fullmatch(r"[0-9A-F]{64}", receipt["sourceFingerprint"] or "") and
            isinstance(receipt["binarySha256"], str) and
            re.fullmatch(r"[0-9A-F]{64}", receipt["binarySha256"] or "") and
            type(receipt["binaryLength"]) is int and
            1 <= receipt["binaryLength"] <= 2**63 - 1,
            f"{label} identity")
    _parse_utc(receipt["builtAtUtc"], True, f"{label} timestamp")
    return receipt


def _build_result_from_receipt(raw: bytes, a_commit: str, a_tree: str,
                               runtime: dict[str, Any],
                               build: dict[str, Any]) -> dict[str, Any]:
    receipt = _parse_release_receipt(raw, a_commit, RELEASE_TAG,
                                     "official build receipt")
    return {
        "schema": "ese.v92.o01-release-build-gate/v3", "verdict": "PASS",
        "source_commit": a_commit, "source_tree": a_tree,
        "release_tag": RELEASE_TAG,
        "python_version": PINNED_PYTHON_VERSION,
        "python_sha256": PINNED_PYTHON_SHA256,
        "build_python_dependency_file_count":
            PINNED_BUILD_PYTHON_DEPENDENCY_FILE_COUNT,
        "build_python_dependency_directory_count":
            PINNED_BUILD_PYTHON_DEPENDENCY_DIRECTORY_COUNT,
        "build_python_dependency_identity_sha256":
            PINNED_BUILD_PYTHON_DEPENDENCY_IDENTITY_SHA256,
        "git_version": PINNED_GIT_VERSION,
        "git_sha256": PINNED_GIT_SHA256,
        "git_core_sha256": PINNED_GIT_CORE_SHA256,
        "powershell_sha256": PINNED_POWERSHELL_SHA256,
        "cmd_sha256": PINNED_CMD_SHA256,
        "msbuild_version": PINNED_MSBUILD_VERSION,
        "msbuild_sha256": PINNED_MSBUILD_SHA256,
        "node_version": PINNED_NODE_VERSION,
        "node_sha256": PINNED_NODE_SHA256,
        "node_distribution_file_count": PINNED_NODE_TREE_FILE_COUNT,
        "node_distribution_directory_count": PINNED_NODE_TREE_DIRECTORY_COUNT,
        "node_distribution_identity_sha256": PINNED_NODE_TREE_SHA256,
        "npm_version": PINNED_NPM_VERSION,
        "npm_cmd_sha256": PINNED_NPM_CMD_SHA256,
        "npm_cli_sha256": PINNED_NPM_CLI_SHA256,
        "pkg_node_version": PINNED_PKG_NODE_VERSION,
        "pkg_node_bytes": PINNED_PKG_NODE_BYTES,
        "pkg_node_sha256": PINNED_PKG_NODE_SHA256,
        "ffmpeg_sha256": PINNED_FFMPEG_SHA256,
        "ffprobe_sha256": PINNED_FFPROBE_SHA256,
        "receipt_sha256": sha256(raw),
        "source_fingerprint_sha256": receipt["sourceFingerprint"].lower(),
        "executable_sha256": receipt["binarySha256"].lower(),
        "executable_bytes": receipt["binaryLength"],
        "runtime_bindings": runtime,
        "build_artifact_bindings": build,
        "package_snapshot_sha256": sha256(canonical({
            "runtime_bindings": runtime, "build_artifact_bindings": build,
        })),
    }


def _audit_package_manifest(package_root: Path) -> tuple[dict[str, str], str]:
    manifest_path = _assert_regular_path(package_root / "SHA256SUMS.txt", False,
                                         "package manifest")
    raw = _read_limited(manifest_path, MAX_PACKAGE_MANIFEST_BYTES, "package manifest")
    require(raw and not raw.startswith(b"\xef\xbb\xbf"), "package manifest encoding")
    lines = raw.splitlines(keepends=True)
    require(1 <= len(lines) <= 10000 and b"".join(lines) == raw and
            all(line.endswith(b"\r\n") for line in lines),
            "package manifest CRLF records")
    expected: dict[str, str] = {}
    expected_directories: set[str] = set()
    seen: set[str] = set()
    pattern = re.compile(br"^([0-9A-F]{64})  ([\x20-\x7e]+)\r\n$")
    for line in lines:
        match = pattern.fullmatch(line)
        require(match is not None, "package manifest record")
        relative = match.group(2).decode("ascii")
        path = PurePosixPath(relative)
        folded = relative.casefold()
        require(not path.is_absolute() and relative != "SHA256SUMS.txt" and
                "\\" not in relative and all(part not in ("", ".", "..") for part in path.parts) and
                folded not in seen, "package manifest path")
        seen.add(folded)
        expected[relative] = match.group(1).decode("ascii").lower()
        for parent in list(path.parents)[:-1]:
            expected_directories.add(parent.as_posix())
    actual: dict[str, str] = {}
    actual_seen: set[str] = set()
    actual_directories: set[str] = set()
    actual_directory_seen: set[str] = set()
    def walk_error(exc: OSError) -> None:
        raise GateError("package enumeration") from exc
    for directory, directories, files in os.walk(
        package_root, followlinks=False, onerror=walk_error,
    ):
        directory_path = _assert_regular_path(Path(directory), True, "package directory")
        if directory_path != package_root:
            relative_directory = directory_path.relative_to(package_root).as_posix()
            folded_directory = relative_directory.casefold()
            require(folded_directory not in actual_directory_seen,
                    "package directory case collision")
            actual_directory_seen.add(folded_directory)
            actual_directories.add(relative_directory)
        for name in list(directories):
            _assert_regular_path(directory_path / name, True, "package directory")
        for name in files:
            file_path = _assert_regular_path(directory_path / name, False, "package file")
            relative = file_path.relative_to(package_root).as_posix()
            folded = relative.casefold()
            require(folded not in actual_seen, "package case collision")
            actual_seen.add(folded)
            actual[relative] = _file_sha256(file_path)
    require("SHA256SUMS.txt" in actual and len(actual) == len(expected) + 1 and
            set(actual) - {"SHA256SUMS.txt"} == set(expected), "package exact file set")
    require(all(actual[path] == digest for path, digest in expected.items()),
            "package file hash")
    require(actual_directories == expected_directories, "package exact directory set")
    return expected, sha256(raw)


def _audit_zip(zip_path: Path, package_hashes: dict[str, str],
               package_sizes: dict[str, int]) -> tuple[str, int, int]:
    zip_path = _assert_regular_path(zip_path, False, "package ZIP")
    zip_bytes = zip_path.stat().st_size
    require(22 <= zip_bytes <= MAX_PACKAGE_ZIP_BYTES, "ZIP container length")
    try:
        expected_central_bytes = sum(
            46 + len(path.encode("ascii")) for path in package_hashes
        )
    except UnicodeEncodeError as exc:
        raise GateError("ZIP expected path encoding") from exc
    with zip_path.open("rb") as preflight_stream:
        preflight_stream.seek(zip_bytes - 22)
        preflight_eocd = preflight_stream.read(22)
    require(preflight_eocd[:4] == b"PK\x05\x06" and
            int.from_bytes(preflight_eocd[4:6], "little") == 0 and
            int.from_bytes(preflight_eocd[6:8], "little") == 0 and
            int.from_bytes(preflight_eocd[8:10], "little") == len(package_hashes) and
            int.from_bytes(preflight_eocd[10:12], "little") == len(package_hashes) and
            int.from_bytes(preflight_eocd[12:16], "little") ==
            expected_central_bytes and
            int.from_bytes(preflight_eocd[16:20], "little") +
            expected_central_bytes == zip_bytes - 22 and
            int.from_bytes(preflight_eocd[20:22], "little") == 0,
            "ZIP preflight central directory bounds")
    before = _file_sha256(zip_path)
    observed: dict[str, str] = {}
    seen: set[str] = set()
    with zipfile.ZipFile(zip_path, "r") as archive:
        infos = archive.infolist()
        require(1 <= len(infos) <= 10001 and len(infos) == len(package_hashes),
                "ZIP entry count")
        normalized: dict[int, str] = {}
        for info in infos:
            require(not info.is_dir() and not info.filename.endswith("/"),
                    "ZIP directory entry")
            original = info.orig_filename
            require(isinstance(original, str) and original != "" and
                    not original.startswith(("/", "\\")) and
                    re.match(r"^[A-Za-z]:", original) is None and
                    not ("/" in original and "\\" in original),
                    "ZIP raw entry path")
            relative = original.replace("\\", "/")
            require(info.filename == relative, "ZIP path normalization")
            path = PurePosixPath(relative)
            folded = relative.casefold()
            mode = (info.external_attr >> 16) & 0o170000
            year, month, day, hour, minute, second = info.date_time
            try:
                datetime(year, month, day, hour, minute, second)
            except ValueError as exc:
                raise GateError("ZIP DOS timestamp") from exc
            require(not path.is_absolute() and "\\" not in relative and
                    all(part not in ("", ".", "..") for part in path.parts) and
                    folded not in seen and not (info.flag_bits & 1) and
                    mode in (0, 0o100000) and
                    info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED) and
                    info.create_system == 0 and info.create_version == 20 and
                    info.extract_version == 20 and info.reserved == 0 and
                    info.volume == 0 and info.internal_attr == 0 and
                    info.external_attr == 0 and info.flag_bits == 0 and
                    info.extra == b"" and info.comment == b"" and
                    1980 <= year <= 2107 and second % 2 == 0 and
                    relative in package_sizes and
                    info.file_size == package_sizes[relative] and
                    0 <= info.compress_size <= zip_bytes and
                    0 <= info.header_offset < zip_bytes,
                    "ZIP entry")
            seen.add(folded)
            normalized[info.header_offset] = relative
        require(len(normalized) == len(infos) and
                set(normalized.values()) == set(package_hashes) == set(package_sizes),
                "ZIP exact metadata set")
        local_digests: dict[str, str] = {}
        with zip_path.open("rb") as stream:
            stream.seek(zip_bytes - 22)
            eocd = stream.read(22)
            require(eocd[:4] == b"PK\x05\x06" and
                    int.from_bytes(eocd[4:6], "little") == 0 and
                    int.from_bytes(eocd[6:8], "little") == 0 and
                    int.from_bytes(eocd[8:10], "little") == len(infos) and
                    int.from_bytes(eocd[10:12], "little") == len(infos) and
                    int.from_bytes(eocd[16:20], "little") == archive.start_dir and
                    int.from_bytes(eocd[12:16], "little") + archive.start_dir ==
                    zip_bytes - 22 and int.from_bytes(eocd[20:22], "little") == 0 and
                     archive.comment == b"", "ZIP exact container boundary")
            central_cursor = archive.start_dir
            for info in infos:
                stream.seek(central_cursor)
                central = stream.read(46)
                require(len(central) == 46 and central[:4] == b"PK\x01\x02",
                        "ZIP central header")
                name_length = int.from_bytes(central[28:30], "little")
                extra_length = int.from_bytes(central[30:32], "little")
                comment_length = int.from_bytes(central[32:34], "little")
                raw_name = stream.read(name_length)
                central_extra = stream.read(extra_length)
                central_comment = stream.read(comment_length)
                try:
                    central_name = raw_name.decode("ascii")
                except UnicodeDecodeError as exc:
                    raise GateError("ZIP central name encoding") from exc
                made_by = int.from_bytes(central[4:6], "little")
                require(made_by == ((info.create_system << 8) | info.create_version) and
                        int.from_bytes(central[6:8], "little") == info.extract_version and
                        int.from_bytes(central[8:10], "little") == info.flag_bits and
                        int.from_bytes(central[10:12], "little") == info.compress_type and
                        int.from_bytes(central[16:20], "little") == info.CRC and
                        int.from_bytes(central[20:24], "little") == info.compress_size and
                        int.from_bytes(central[24:28], "little") == info.file_size and
                        int.from_bytes(central[34:36], "little") == info.volume and
                        int.from_bytes(central[36:38], "little") == info.internal_attr and
                        int.from_bytes(central[38:42], "little") == info.external_attr and
                        int.from_bytes(central[42:46], "little") == info.header_offset and
                        central_name == info.orig_filename and central_extra == b"" and
                        central_comment == b"", "ZIP exact central record")
                central_cursor = stream.tell()
            require(central_cursor == zip_bytes - 22, "ZIP central record coverage")
            cursor = 0
            for info in sorted(infos, key=lambda item: item.header_offset):
                require(info.header_offset == cursor, "ZIP local record coverage")
                relative = normalized[info.header_offset]
                expected_size = package_sizes[relative]
                stream.seek(cursor)
                header = stream.read(30)
                require(len(header) == 30 and header[:4] == b"PK\x03\x04",
                        "ZIP local header")
                extract_version = int.from_bytes(header[4:6], "little")
                flag_bits = int.from_bytes(header[6:8], "little")
                compression = int.from_bytes(header[8:10], "little")
                dos_time = int.from_bytes(header[10:12], "little")
                dos_date = int.from_bytes(header[12:14], "little")
                crc = int.from_bytes(header[14:18], "little")
                compressed_size = int.from_bytes(header[18:22], "little")
                uncompressed_size = int.from_bytes(header[22:26], "little")
                name_length = int.from_bytes(header[26:28], "little")
                extra_length = int.from_bytes(header[28:30], "little")
                raw_name = stream.read(name_length)
                local_extra = stream.read(extra_length)
                try:
                    local_name = raw_name.decode("ascii")
                except UnicodeDecodeError as exc:
                    raise GateError("ZIP local name encoding") from exc
                year, month, day, hour, minute, second = info.date_time
                central_dos_time = (hour << 11) | (minute << 5) | (second // 2)
                central_dos_date = ((year - 1980) << 9) | (month << 5) | day
                require(extract_version == info.extract_version and
                        1980 <= year <= 2107 and second % 2 == 0 and
                        dos_time == central_dos_time and dos_date == central_dos_date and
                        info.create_system == 0 and info.create_version == 20 and
                        info.extract_version == 20 and info.reserved == 0 and
                        info.volume == 0 and info.internal_attr == 0 and
                        info.external_attr == 0 and flag_bits == info.flag_bits == 0 and
                        compression in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED) and
                        compression == info.compress_type and crc == info.CRC and
                        compressed_size == info.compress_size and
                        uncompressed_size == info.file_size and extra_length == 0 and
                        local_extra == b"" and info.extra == b"" and info.comment == b"" and
                        local_name == info.orig_filename, "ZIP exact local record")
                digest = hashlib.sha256()
                observed_crc = 0
                observed_size = 0
                decompressor = (zlib.decompressobj(-15)
                                if compression == zipfile.ZIP_DEFLATED else None)
                remaining = compressed_size
                while remaining:
                    chunk = stream.read(min(1024 * 1024, remaining))
                    require(chunk != b"", "ZIP compressed payload length")
                    remaining -= len(chunk)
                    try:
                        if decompressor is None:
                            output = chunk
                        else:
                            budget = expected_size - observed_size
                            require(budget >= 0, "ZIP output bound")
                            output = decompressor.decompress(chunk, budget + 1)
                    except zlib.error as exc:
                        raise GateError("ZIP DEFLATE stream") from exc
                    require(observed_size + len(output) <= expected_size and
                            (decompressor is None or decompressor.unconsumed_tail == b""),
                            "ZIP output bound")
                    digest.update(output)
                    observed_crc = zlib.crc32(output, observed_crc)
                    observed_size += len(output)
                if decompressor is not None:
                    try:
                        budget = expected_size - observed_size
                        require(budget >= 0, "ZIP output bound")
                        output = decompressor.flush(budget + 1)
                    except zlib.error as exc:
                        raise GateError("ZIP DEFLATE stream") from exc
                    require(observed_size + len(output) <= expected_size,
                            "ZIP output bound")
                    digest.update(output)
                    observed_crc = zlib.crc32(output, observed_crc)
                    observed_size += len(output)
                    require(decompressor.eof and decompressor.unused_data == b"" and
                            decompressor.unconsumed_tail == b"",
                            "ZIP exact DEFLATE stream")
                require(observed_size == uncompressed_size and
                        observed_size == expected_size and
                        (observed_crc & 0xffffffff) == crc,
                        "ZIP local payload identity")
                local_digests[relative] = digest.hexdigest()
                cursor = stream.tell()
            require(cursor == archive.start_dir, "ZIP local-to-central coverage")
        observed.update(local_digests)
    require(observed == package_hashes, "ZIP exact file set and hashes")
    require(_file_sha256(zip_path) == before, "ZIP changed during audit")
    return before, zip_bytes, len(observed)


def _parse_build_info(raw: bytes) -> dict[str, str]:
    require(raw and not raw.startswith(b"\xef\xbb\xbf"), "BUILD_INFO encoding")
    lines = raw.splitlines(keepends=True)
    names = [
        "release", "commit", "dirty", "built_utc", "node", "npm", "ffmpeg",
        "ffmpeg_sha256", "ffprobe_sha256", "nodes_dat_sha256",
    ]
    require(len(lines) == len(names) and b"".join(lines) == raw and
            all(line.endswith(b"\r\n") for line in lines), "BUILD_INFO records")
    values: dict[str, str] = {}
    for line, expected_name in zip(lines, names):
        try:
            text = line[:-2].decode("ascii")
        except UnicodeDecodeError as exc:
            raise GateError("BUILD_INFO encoding") from exc
        name, separator, value = text.partition(": ")
        require(separator == ": " and name == expected_name and value != "",
                "BUILD_INFO field")
        values[name] = value
    return values


def _parse_utc(value: Any, fractional: bool, label: str) -> datetime:
    pattern = (r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
               + (r"(?:\.[0-9]{1,7})?Z$" if fractional else r"Z$"))
    require(isinstance(value, str) and re.fullmatch(pattern, value) is not None, label)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise GateError(label) from exc
    require(parsed.tzinfo is not None and parsed.utcoffset() is not None and
            parsed.utcoffset().total_seconds() == 0, label)
    return parsed.astimezone(timezone.utc)


def _audit_release_outputs(build_root: Path, node_arg: str, release_tag: str,
                           a_commit: str, a_tree: str,
                           document: dict[str, Any]) -> tuple[dict[str, Any],
                                                               dict[str, Any], bytes]:
    require(release_tag == RELEASE_TAG, "release output tag")
    build_root = _assert_regular_path(build_root, True, "release build root")
    _assert_external_checkout(build_root, a_commit, a_tree,
                              "release output source identity")
    package_root = _assert_regular_path(
        build_root / "dist" / release_tag / "package", True, "package root",
    )
    require(package_root == (build_root / "dist" / release_tag / "package").resolve(strict=True),
            "package root layout")
    expected, manifest_sha = _audit_package_manifest(package_root)
    actual_hashes = {
        path: _file_sha256(_assert_regular_path(
            package_root / PurePosixPath(path), False, "package file",
        )) for path in expected
    }
    require(actual_hashes == expected, "package changed after manifest audit")
    manifest_path = _assert_regular_path(package_root / "SHA256SUMS.txt", False,
                                         "package manifest")
    package_hashes = dict(actual_hashes)
    package_hashes["SHA256SUMS.txt"] = _file_sha256(manifest_path)
    package_sizes = {
        path: _assert_regular_path(package_root / PurePosixPath(path), False,
                                   "package file").stat().st_size
        for path in package_hashes
    }
    require(manifest_sha == package_hashes["SHA256SUMS.txt"], "manifest hash identity")

    immutable = document["immutable_contract"]
    release_inputs, nodes_pin = _release_input_pins(a_commit, immutable)
    receipt_path = _assert_regular_path(
        build_root / "tools/build_logs/emule-release-build.json.log", False,
        "official build receipt",
    )
    receipt_raw = _read_limited(receipt_path, MAX_RELEASE_RECEIPT_BYTES,
                                "official build receipt")
    receipt = _parse_release_receipt(receipt_raw, a_commit, release_tag,
                                     "official build receipt")
    receipt_built = _parse_utc(receipt["builtAtUtc"], True,
                               "official build receipt timestamp")
    executable = _assert_regular_path(package_root / "emule.exe", False,
                                       "package executable")
    executable_sha = _file_sha256(executable)
    require(receipt["binarySha256"] == executable_sha.upper() and
            receipt["binaryLength"] == executable.stat().st_size,
            "official build executable identity")

    build_info_path = _assert_regular_path(package_root / "BUILD_INFO.txt", False,
                                           "BUILD_INFO")
    build_info_raw = _read_limited(build_info_path, MAX_BUILD_INFO_BYTES, "BUILD_INFO")
    build_info = _parse_build_info(build_info_raw)
    build_built = _parse_utc(build_info["built_utc"], False, "BUILD_INFO timestamp")
    require((build_built - receipt_built).total_seconds() >= 0,
            "BUILD_INFO/receipt chronology")
    ffmpeg_path = _assert_regular_path(package_root / "ffmpeg.exe", False,
                                        "package FFmpeg")
    ffprobe_path = _assert_regular_path(package_root / "ffprobe.exe", False,
                                         "package ffprobe")
    require({"ffmpeg.exe", "ffprobe.exe", "config/nodes.dat"} <= set(actual_hashes),
            "package pinned release inputs present")
    require(actual_hashes["ffmpeg.exe"].upper() == release_inputs["ffmpeg"]["sha256"] and
            actual_hashes["ffprobe.exe"].upper() == release_inputs["ffprobe"]["sha256"] and
            actual_hashes["config/nodes.dat"] == nodes_pin,
            "package pinned release input hashes")
    ffmpeg_process = subprocess.run(
        [str(ffmpeg_path), "-version"], check=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=30, env=_closed_git_environment(),
    )
    try:
        ffmpeg_version_line = ffmpeg_process.stdout.decode("utf-8").splitlines()[0]
    except (UnicodeDecodeError, IndexError) as exc:
        raise GateError("package FFmpeg version") from exc
    require_exact_value(build_info, {
        "release": release_tag, "commit": a_commit, "dirty": "false",
        "built_utc": build_info["built_utc"], "node": "v" + immutable["node_version"],
        "npm": immutable["npm_version"], "ffmpeg": ffmpeg_version_line,
        "ffmpeg_sha256": actual_hashes["ffmpeg.exe"].upper(),
        "ffprobe_sha256": actual_hashes["ffprobe.exe"].upper(),
        "nodes_dat_sha256": actual_hashes["config/nodes.dat"].upper(),
    }, "BUILD_INFO identity")
    require(build_info["ffmpeg"].startswith(
        "ffmpeg version " + release_inputs["ffmpeg"]["version"] + " "
    ), "package pinned release inputs")

    node_binding = _audit_node_distribution(node_arg, immutable)
    node_environment = _without_node_injection_environment()
    node_version = _subprocess_ascii_line(
        [str(node_binding["node"]), "--version"], "package audit Node version",
        cwd=build_root, environment=node_environment,
    )
    require(node_version == "v" + immutable["node_version"] and
            build_info["node"] == node_version, "package audit Node identity")

    zip_path = _assert_regular_path(build_root / PurePosixPath(PACKAGE_ZIP_PATH), False,
                                    "package ZIP")
    zip_sha, zip_bytes, zip_entries = _audit_zip(zip_path, package_hashes, package_sizes)
    sidecar_path = _assert_regular_path(
        build_root / PurePosixPath(PACKAGE_ZIP_SIDECAR_PATH), False,
        "package ZIP sidecar",
    )
    sidecar_bytes = _read_limited(sidecar_path, MAX_ZIP_SIDECAR_BYTES,
                                  "package ZIP sidecar")
    expected_sidecar = (zip_sha.upper() + "  " + PACKAGE_ZIP_BASENAME + "\r\n").encode("ascii")
    require(sidecar_bytes == expected_sidecar, "package ZIP sidecar content")
    runtime = {
        "node_version": immutable["node_version"],
        "node_sha256": immutable["node_sha256"],
        "executable_sha256": executable_sha,
        "build_info_sha256": sha256(build_info_raw),
        "package_manifest_sha256": manifest_sha,
        "package_manifest_entry_count": len(expected),
        "package_file_count": len(expected) + 1,
    }
    build = {
        "release_tag": release_tag, "package_zip_path": PACKAGE_ZIP_PATH,
        "package_zip_sha256": zip_sha, "package_zip_bytes": zip_bytes,
        "package_zip_entry_count": zip_entries,
        "package_zip_sidecar_path": PACKAGE_ZIP_SIDECAR_PATH,
        "package_zip_sidecar_bytes": len(sidecar_bytes),
        "package_zip_sidecar_sha256": sha256(sidecar_bytes),
    }
    _validate_runtime_bindings(runtime, {"executable_sha256": executable_sha}, immutable)
    _validate_build_artifact_bindings(build, runtime)

    final_expected, final_manifest_sha = _audit_package_manifest(package_root)
    final_node = _audit_node_distribution(node_binding["node"], immutable)
    require(final_expected == expected and final_manifest_sha == manifest_sha and
            canonical({key: final_node[key] for key in (
                "identity_sha256", "file_count", "directory_count",
            )}) == canonical({key: node_binding[key] for key in (
                "identity_sha256", "file_count", "directory_count",
            )}) and _read_limited(build_info_path, MAX_BUILD_INFO_BYTES, "BUILD_INFO") ==
            build_info_raw and _read_limited(
                receipt_path, MAX_RELEASE_RECEIPT_BYTES, "official build receipt",
            ) == receipt_raw and _file_sha256(ffmpeg_path) == actual_hashes["ffmpeg.exe"] and
            _file_sha256(ffprobe_path) == actual_hashes["ffprobe.exe"] and
            _read_limited(sidecar_path, MAX_ZIP_SIDECAR_BYTES,
                          "package ZIP sidecar") == sidecar_bytes and
            _file_sha256(zip_path) == zip_sha and zip_path.stat().st_size == zip_bytes,
            "release outputs changed during audit")
    require(_subprocess_ascii_line(
        [str(node_binding["node"]), "--version"], "package audit Node version",
        cwd=build_root, environment=node_environment,
    ) == node_version, "Node changed during release output audit")
    _assert_external_checkout(build_root, a_commit, a_tree,
                              "release output source changed during audit")
    return runtime, build, receipt_raw


def _subprocess_ascii_line(arguments: list[str], label: str, *, cwd: Path,
                            environment: dict[str, str]) -> str:
    process = subprocess.run(
        arguments, cwd=cwd, check=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=60, env=environment,
    )
    require(len(process.stdout) <= 4096 and len(process.stderr) <= 4096, label)
    try:
        lines = process.stdout.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise GateError(label) from exc
    require(len(lines) == 1 and lines[0] != "", label)
    return lines[0].strip()


def _assert_worktree_git_control_files(root: Path, expected_commit: str,
                                       environment: dict[str, str], label: str, *,
                                       libutp_checkout: bool = False) -> None:
    tree_raw = subprocess.run(
        _git_command(root, "ls-tree", "-r", "-z", expected_commit,
                     libutp_checkout=libutp_checkout), check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120, env=environment,
    ).stdout
    expected_controls: dict[str, str] = {}
    submodules: set[str] = set()
    tracked_directories: set[str] = {""}
    entries = tree_raw.split(b"\0")
    require(entries and entries[-1] == b"", label)
    for entry in entries[:-1]:
        header, separator, raw_relative = entry.partition(b"\t")
        fields = header.split(b" ")
        require(separator == b"\t" and len(fields) == 3, label)
        try:
            relative = raw_relative.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise GateError(label) from exc
        parent = PurePosixPath(relative).parent
        while str(parent) != ".":
            tracked_directories.add(parent.as_posix().casefold())
            parent = parent.parent
        if fields[0] == b"160000":
            submodules.add(relative.casefold())
        if PurePosixPath(relative).name.casefold() in {".gitattributes", ".gitmodules"}:
            folded = relative.casefold()
            require(folded not in expected_controls, label)
            expected_controls[folded] = relative

    actual_controls: dict[str, str] = {}

    def walk_error(exc: OSError) -> None:
        raise GateError(label) from exc

    for directory, child_directories, child_files in os.walk(
        root, followlinks=False, onerror=walk_error,
    ):
        directory_path = _assert_regular_path(Path(directory), True, label)
        relative_directory = ("" if directory_path == root else
                              directory_path.relative_to(root).as_posix())
        retained: list[str] = []
        for name in child_directories:
            relative = name if relative_directory == "" else relative_directory + "/" + name
            folded = relative.casefold()
            if (name.casefold() == ".git" or folded in submodules or
                    folded not in tracked_directories):
                continue
            _assert_regular_path(directory_path / name, True, label)
            retained.append(name)
        child_directories[:] = retained
        for name in child_files:
            if name.casefold() not in {".gitattributes", ".gitmodules"}:
                continue
            relative = name if relative_directory == "" else relative_directory + "/" + name
            folded = relative.casefold()
            require(folded not in actual_controls, label)
            _assert_regular_path(directory_path / name, False, label)
            actual_controls[folded] = relative
    require(set(actual_controls) == set(expected_controls), label)
    for folded, relative in expected_controls.items():
        file_path = _assert_regular_path(root / PurePosixPath(actual_controls[folded]),
                                         False, label)
        raw = _read_limited(file_path, 1024 * 1024, label)
        committed_raw = subprocess.run(
            _git_command(root, "show", f"{expected_commit}:{relative}",
                         libutp_checkout=libutp_checkout), check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, env=environment,
        ).stdout
        eol_equivalent = (b"\r" not in committed_raw and
                          raw.count(b"\r") == raw.count(b"\r\n") and
                          raw.replace(b"\r\n", b"\n") == committed_raw)
        require(raw == committed_raw or eol_equivalent, label)


def _assert_git_metadata_files_safe(root: Path, environment: dict[str, str],
                                    label: str, *,
                                    libutp_checkout: bool = False) -> None:
    for git_metadata in ("config.worktree", "info/attributes", "info/grafts", "shallow"):
        metadata_raw = subprocess.run(
            _git_command(root, "rev-parse", "--git-path", git_metadata,
                         libutp_checkout=libutp_checkout), check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60,
            env=environment,
        ).stdout.decode("utf-8", "strict").strip()
        metadata_path = Path(metadata_raw)
        if not metadata_path.is_absolute():
            metadata_path = root / metadata_path
        if git_metadata == "info/attributes":
            require(not os.path.lexists(metadata_path) or
                    (_assert_regular_path(metadata_path, False, label).stat().st_size == 0),
                    label)
        else:
            require(not os.path.lexists(metadata_path), label)


def _assert_external_checkout(root: Path, expected_commit: str,
                              expected_tree: str, label: str,
                              reject_untracked_ignored: bool = False, *,
                              libutp_checkout: bool = False) -> None:
    root = _assert_regular_path(root, True, label)
    environment = _closed_git_environment()

    def git_command(*args: str) -> list[str]:
        return _git_command(root, *args, libutp_checkout=libutp_checkout)

    _assert_plain_git_configuration_safe(
        root, label, libutp_checkout=libutp_checkout,
    )
    _assert_git_metadata_files_safe(
        root, environment, label, libutp_checkout=libutp_checkout,
    )
    head = subprocess.run(
        git_command("rev-parse", "HEAD"), check=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=60, env=environment,
    ).stdout.decode("ascii").strip()
    tree = subprocess.run(
        git_command("rev-parse", "HEAD^{tree}"), check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, env=environment,
    ).stdout.decode("ascii").strip()
    require(head == expected_commit and tree == expected_tree, label)
    _assert_worktree_git_control_files(
        root, expected_commit, environment, label,
        libutp_checkout=libutp_checkout,
    )
    status = subprocess.run(
        git_command("status", "--porcelain=v1", "--untracked-files=all",
                    "--ignore-submodules=dirty"), check=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=60, env=environment,
    ).stdout
    symbolic = subprocess.run(
        git_command("symbolic-ref", "-q", "HEAD"), check=False,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, env=environment,
    )
    tracked = subprocess.run(
        git_command("ls-files", "-v"), check=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=60, env=environment,
    )
    index = subprocess.run(
        git_command("ls-files", "-s", "-z"), check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, env=environment,
    ).stdout
    index_matches_head = subprocess.run(
        git_command("diff-index", "--cached", "--quiet", "HEAD", "--"),
        check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60,
        env=environment,
    )
    if reject_untracked_ignored:
        ordinary_untracked = subprocess.run(
            git_command("ls-files", "--others", "-z", "--exclude-standard"),
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60,
            env=environment,
        ).stdout
        ignored_untracked = subprocess.run(
            git_command("ls-files", "--others", "-z", "--ignored",
                        "--exclude-standard"),
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60,
            env=environment,
        ).stdout
        require(ordinary_untracked == b"" and ignored_untracked == b"", label)
    with tempfile.TemporaryDirectory(prefix="g12-git-index-") as temporary_name:
        forced_environment = dict(environment)
        forced_environment["GIT_INDEX_FILE"] = str(Path(temporary_name) / "index")
        read_tree = subprocess.run(
            git_command("read-tree", expected_commit), check=False,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120,
            env=forced_environment,
        )
        refresh = subprocess.run(
            git_command("update-index", "--really-refresh", "--ignore-submodules"),
            check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300,
            env=forced_environment,
        )
        forced_diff = subprocess.run(
            git_command("diff-files", "--quiet", "--no-ext-diff",
                        "--ignore-submodules=dirty"),
            check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300,
            env=forced_environment,
        )
        require(read_tree.returncode == 0 and refresh.returncode == 0 and
                forced_diff.returncode == 0, label)
    require(status == b"" and
            symbolic.returncode == 1 and symbolic.stdout == b"" and
            index_matches_head.returncode == 0 and
            tracked.stdout != b"" and all(
                line.startswith(b"H ") for line in tracked.stdout.splitlines()
            ), label)
    entries = index.split(b"\0")
    require(entries and entries[-1] == b"", label)
    entries = entries[:-1]
    require(entries, label)
    for entry in entries:
        header, separator, raw_relative = entry.partition(b"\t")
        fields = header.split(b" ")
        require(separator == b"\t" and len(fields) == 3 and fields[2] == b"0" and
                re.fullmatch(br"[0-9a-f]{40}", fields[1]) is not None, label)
        try:
            relative = raw_relative.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise GateError(label) from exc
        require(relative != "" and not PurePosixPath(relative).is_absolute() and
                all(part not in ("", ".", "..") for part in PurePosixPath(relative).parts),
                label)
        worktree_path = root / PurePosixPath(relative)
        mode = fields[0]
        if mode == b"160000":
            require(not libutp_checkout and relative == "libutp", label)
            submodule = _assert_regular_path(worktree_path, True, label)
            sub_commit = fields[1].decode("ascii")
            sub_tree = subprocess.run(
                _git_command(
                    submodule, "rev-parse", "HEAD^{tree}", libutp_checkout=True,
                ),
                check=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60,
                env=environment,
            ).stdout.decode("ascii").strip()
            _assert_external_checkout(submodule, sub_commit, sub_tree, label,
                                      reject_untracked_ignored,
                                      libutp_checkout=True)
            continue
        require(mode in {b"100644", b"100755"}, label)
        _assert_regular_path(worktree_path, False, label)


def _assert_fresh_build_outputs_absent(root: Path) -> None:
    generated = [
        "cryptopp/x64", "Build/x64", "libutp/x64", "libutp/Build/x64",
        "libutp/libutp/x64", "srchybrid/x64", "srchybrid/eSE/node_modules",
        "srchybrid/eSE/ese-server.exe", "srchybrid/lang/x64",
        "tools/lab/nat_gateway/node_modules",
        "dist", "tools/build_logs",
    ]
    require(all(not os.path.lexists(root / PurePosixPath(path)) for path in generated),
            "fresh A64 generated outputs absent")


def _assert_plain_git_configuration_safe(root: Path, label: str, *,
                                         libutp_checkout: bool = False) -> None:
    environment = _closed_git_environment()
    command = [
        str(_git_executable()), "--no-pager", "-c",
        f"safe.directory={root.as_posix()}", "-C", str(root), "config",
        "--show-origin", "--get-regexp",
        r"^(core\.worktree|include\.|includeif\.|filter\.|diff\.external|diff\..*\.(command|textconv))",
    ]
    process = subprocess.run(
        command, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=60, env=environment,
    )
    require(process.returncode in {0, 1} and process.stderr == b"", label)
    if process.returncode == 1:
        require(process.stdout == b"", label)
        return
    try:
        rows = process.stdout.decode("utf-8", "strict").splitlines()
    except UnicodeDecodeError as exc:
        raise GateError(label) from exc
    require(len(rows) == 1, label)
    origin, tab, entry = rows[0].partition("\t")
    key, separator, value = entry.partition(" ")
    require(tab == "\t" and key == "core.worktree" and separator == " " and
            value != "" and origin.startswith("file:"), label)
    config_raw = subprocess.run(
        _git_command(root, "rev-parse", "--git-path", "config",
                     libutp_checkout=libutp_checkout), check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60,
        env=environment,
    ).stdout.decode("utf-8", "strict").strip()
    config_path = Path(config_raw)
    if not config_path.is_absolute():
        config_path = root / config_path
    config_path = _assert_regular_path(config_path, False, label)
    origin_path = _assert_regular_path(Path(origin[5:]), False, label)
    worktree_path = Path(value)
    if not worktree_path.is_absolute():
        worktree_path = config_path.parent / worktree_path
    require(origin_path == config_path and worktree_path.resolve(strict=True) == root,
            label)


def _assert_project_npm_configs_absent(root: Path) -> None:
    for relative in (
        ".npmrc", "npm-shrinkwrap.json", "srchybrid/eSE/.npmrc",
        "srchybrid/eSE/npm-shrinkwrap.json", "tools/lab/nat_gateway/.npmrc",
        "tools/lab/nat_gateway/npm-shrinkwrap.json",
    ):
        require(not os.path.lexists(root / PurePosixPath(relative)),
                "project npm configuration absent")


def _assert_no_external_msbuild_imports(root: Path) -> None:
    cursor = root.parent
    while True:
        for name in ("Directory.Build.props", "Directory.Build.targets",
                     "Directory.Build.rsp", "MSBuild.rsp"):
            require(not os.path.lexists(cursor / name),
                    "external MSBuild import absent")
        if cursor.parent == cursor:
            break
        cursor = cursor.parent


def _assert_command_processor_autorun_absent() -> None:
    require(os.name == "nt", "command processor AutoRun platform")
    import winreg

    access_views = (winreg.KEY_WOW64_32KEY, winreg.KEY_WOW64_64KEY)
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        for view in access_views:
            try:
                key = winreg.OpenKey(
                    hive, r"Software\Microsoft\Command Processor", 0,
                    winreg.KEY_READ | view,
                )
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise GateError("command processor AutoRun") from exc
            try:
                try:
                    value, _ = winreg.QueryValueEx(key, "AutoRun")
                except FileNotFoundError:
                    continue
                require(value is None or (isinstance(value, str) and value.strip() == ""),
                        "command processor AutoRun absent")
            finally:
                winreg.CloseKey(key)


def _build_environment(node_binding: dict[str, Any], pkg_node: Path | None,
                       python_path: Path, temporary: Path,
                       include_build_tools: bool = False) -> dict[str, str]:
    source = dict(os.environ)
    environment: dict[str, str] = {}
    for key, value in source.items():
        if key.upper() in {
            "COMPUTERNAME", "NUMBER_OF_PROCESSORS", "OS",
            "PROCESSOR_ARCHITECTURE", "PROCESSOR_IDENTIFIER",
            "PROCESSOR_LEVEL", "PROCESSOR_REVISION", "USERNAME",
        }:
            _set_environment_value_ci(environment, key.upper(), value)
    environment = _closed_git_environment(environment)
    empty_user = temporary / "npm-user.ini"
    empty_global = temporary / "npm-global.ini"
    empty_user.write_bytes(b"")
    empty_global.write_bytes(b"")
    python_shim = temporary / "python.cmd"
    python_shim.write_bytes(
        ("@echo off\r\n\"" + str(python_path) +
         "\" -E -s -S -B %*\r\nexit /b %errorlevel%\r\n").encode("ascii")
    )
    system_root = Path(r"C:\Windows")
    _set_environment_value_ci(environment, "SystemRoot", str(system_root))
    _set_environment_value_ci(environment, "WINDIR", str(system_root))
    _set_environment_value_ci(environment, "SystemDrive", system_root.drive)
    _set_environment_value_ci(environment, "ProgramFiles", r"C:\Program Files")
    _set_environment_value_ci(environment, "ProgramFiles(x86)", r"C:\Program Files (x86)")
    _set_environment_value_ci(environment, "ProgramData", r"C:\ProgramData")
    _set_environment_value_ci(environment, "ALLUSERSPROFILE", r"C:\ProgramData")
    _set_environment_value_ci(environment, "CommonProgramFiles",
                              r"C:\Program Files\Common Files")
    _set_environment_value_ci(environment, "CommonProgramFiles(x86)",
                              r"C:\Program Files (x86)\Common Files")
    profile = temporary / "profile"
    roaming = profile / "AppData/Roaming"
    local = profile / "AppData/Local"
    roaming.mkdir(parents=True)
    local.mkdir(parents=True)
    _set_environment_value_ci(environment, "TEMP", str(temporary))
    _set_environment_value_ci(environment, "TMP", str(temporary))
    _set_environment_value_ci(environment, "USERPROFILE", str(profile))
    _set_environment_value_ci(environment, "HOME", str(profile))
    _set_environment_value_ci(environment, "HOMEDRIVE", profile.drive)
    _set_environment_value_ci(environment, "HOMEPATH", str(profile)[len(profile.drive):])
    _set_environment_value_ci(environment, "APPDATA", str(roaming))
    _set_environment_value_ci(environment, "LOCALAPPDATA", str(local))
    command_processor = _assert_regular_path(
        system_root / "System32/cmd.exe", False, "command processor",
    )
    require(_file_sha256(command_processor) == PINNED_CMD_SHA256,
            "trusted command processor identity")
    powershell = _assert_regular_path(
        system_root / "System32/WindowsPowerShell/v1.0/powershell.exe",
        False, "trusted Windows PowerShell",
    )
    require(_file_sha256(powershell) == PINNED_POWERSHELL_SHA256,
            "trusted Windows PowerShell identity")
    _set_environment_value_ci(environment, "COMSPEC", str(command_processor))
    _set_environment_value_ci(environment, "PATHEXT", ".COM;.EXE;.BAT;.CMD")
    git_executable = _git_executable()
    git_root = git_executable.parents[1]
    path_parts = [
        str(node_binding["root"]), str(temporary), str(command_processor.parent),
        str(powershell.parent),
        str(git_executable.parent),
        str(git_root / "usr/bin"), str(git_root / "mingw64/bin"),
        str(git_root / "mingw64/libexec/git-core"),
    ]
    if include_build_tools:
        msbuild = _assert_regular_path(
            Path(r"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe"),
            False, "trusted host MSBuild",
        )
        require(_file_sha256(msbuild) == PINNED_MSBUILD_SHA256,
                "trusted host MSBuild identity")
        path_parts.insert(4, str(msbuild.parent))
    _set_environment_value_ci(environment, "PATH", os.pathsep.join(path_parts))
    _set_environment_value_ci(environment, "PYTHONNOUSERSITE", "1")
    _set_environment_value_ci(
        environment, "PSModulePath",
        str(system_root / "System32/WindowsPowerShell/v1.0/Modules"),
    )
    msbuild_user = temporary / "msbuild-user"
    msbuild_user.mkdir()
    _set_environment_value_ci(environment, "MSBuildUserExtensionsPath", str(msbuild_user))
    _set_environment_value_ci(environment, "UserRootDir", str(msbuild_user) + os.sep)
    _set_environment_value_ci(environment, "MSBUILDDISABLENODEREUSE", "1")
    vclib_user = temporary / "disabled-vcpkg-user"
    require(not os.path.lexists(Path(str(vclib_user) + ".props")) and
            not os.path.lexists(Path(str(vclib_user) + ".targets")),
            "disabled vcpkg user imports absent")
    _set_environment_value_ci(environment, "VCLibPackagePath", str(vclib_user))
    _set_environment_value_ci(environment, "VcpkgEnabled", "false")
    _set_environment_value_ci(environment, "EnableVcpkgArtifactsIntegration", "false")
    _set_environment_value_ci(environment, "NPM_CONFIG_USERCONFIG", str(empty_user))
    _set_environment_value_ci(environment, "NPM_CONFIG_GLOBALCONFIG", str(empty_global))
    npm_cache = _assert_regular_path(python_path.parents[3] / "npm-cache", True,
                                     "pinned npm content cache")
    _set_environment_value_ci(environment, "NPM_CONFIG_CACHE", str(npm_cache))
    _set_environment_value_ci(environment, "NPM_CONFIG_PREFIX", str(temporary / "npm-prefix"))
    if pkg_node is not None:
        _set_environment_value_ci(environment, "PKG_NODE_PATH", str(pkg_node))
    empty_hooks = temporary / "git-hooks"
    empty_hooks.mkdir()
    git_config = [
        ("safe.directory", str(REPO)),
        ("safe.directory", str(REPO / "libutp")),
        ("core.fsmonitor", "false"),
        ("core.hooksPath", str(empty_hooks)),
        ("core.excludesFile", "NUL" if os.name == "nt" else "/dev/null"),
        ("core.attributesFile", "NUL" if os.name == "nt" else "/dev/null"),
        ("core.bare", "false"),
        ("core.ignoreStat", "false"),
        ("core.sparseCheckout", "false"),
        ("core.sparseCheckoutCone", "false"),
        ("index.sparse", "false"),
        ("extensions.worktreeConfig", "false"),
        ("core.autocrlf", "true"),
    ]
    environment["GIT_CONFIG_COUNT"] = str(len(git_config))
    for index, (key, value) in enumerate(git_config):
        environment[f"GIT_CONFIG_KEY_{index}"] = key
        environment[f"GIT_CONFIG_VALUE_{index}"] = value
    resolved_node = shutil.which("node.exe", path=environment["PATH"])
    resolved_npm = shutil.which("npm.cmd", path=environment["PATH"])
    resolved_python = shutil.which("python.cmd", path=environment["PATH"])
    resolved_python_default = shutil.which("python", path=environment["PATH"])
    resolved_python_executable = shutil.which("python.exe", path=environment["PATH"])
    resolved_powershell = shutil.which("powershell.exe", path=environment["PATH"])
    resolved_command = shutil.which("cmd.exe", path=environment["PATH"])
    resolved_git = shutil.which("git.exe", path=environment["PATH"])
    require(resolved_node is not None and resolved_npm is not None and
            resolved_python is not None and resolved_python_default is not None and
            resolved_command is not None and resolved_git is not None and
            resolved_powershell is not None and
            resolved_python_executable is None and
            _assert_regular_path(Path(resolved_node), False, "resolved Node") ==
            node_binding["node"] and
            _assert_regular_path(Path(resolved_npm), False, "resolved npm") ==
            node_binding["npm_cmd"] and
            _assert_regular_path(Path(resolved_python), False, "resolved Python shim") ==
            python_shim and
            _assert_regular_path(Path(resolved_python_default), False,
                                 "resolved default Python shim") == python_shim and
            _assert_regular_path(Path(resolved_command), False, "resolved command processor") ==
            command_processor and
            _assert_regular_path(Path(resolved_powershell), False,
                                 "resolved Windows PowerShell") == powershell and
            _assert_regular_path(
                Path(resolved_git), False, "resolved Git",
            ) == git_executable, "build Node/npm/Python/cmd/Git command resolution")
    if include_build_tools:
        resolved_msbuild = shutil.which("MSBuild.exe", path=environment["PATH"])
        require(resolved_msbuild is not None and
                _assert_regular_path(Path(resolved_msbuild), False,
                                     "resolved MSBuild") == msbuild and
                _file_sha256(msbuild) == PINNED_MSBUILD_SHA256,
                "build MSBuild command resolution")
    return environment


def build_all_gate(node_arg: str, ffmpeg_arg: str, pkg_node_arg: str,
                   release_tag: str, document: dict[str, Any]) -> dict[str, Any]:
    require(release_tag == RELEASE_TAG, "official build release tag")
    immutable = document["immutable_contract"]
    python_path, python_sha = _assert_python_runtime(immutable)
    require(sys.flags.isolated == 1 and sys.flags.no_site == 1 and
            sys.flags.dont_write_bytecode == 1, "isolated Python invocation")
    _assert_command_processor_autorun_absent()
    a_commit = _git_text("rev-parse", "HEAD")
    a_tree = _git_text("rev-parse", "HEAD^{tree}")
    _assert_external_checkout(REPO, a_commit, a_tree,
                              "fresh detached A64 source", True)
    _assert_fresh_build_outputs_absent(REPO)
    _assert_project_npm_configs_absent(REPO)
    _assert_no_external_msbuild_imports(REPO)
    _assert_plain_git_configuration_safe(REPO, "official build Git configuration")
    _assert_plain_git_configuration_safe(REPO / "libutp",
                                         "official build submodule Git configuration")

    node_binding = _audit_node_distribution(node_arg, immutable)
    pkg_node = _assert_regular_path(Path(pkg_node_arg), False, "pkg base Node")
    require(pkg_node.stat().st_size == immutable["pkg_node_bytes"] and
            _file_sha256(pkg_node) == immutable["pkg_node_sha256"],
            "pkg base Node identity")
    ffmpeg = _assert_regular_path(Path(ffmpeg_arg), False, "pinned FFmpeg")
    ffprobe = _assert_regular_path(ffmpeg.with_name("ffprobe.exe"), False,
                                   "pinned ffprobe")
    release_inputs, _ = _release_input_pins(a_commit, immutable)
    require(_file_sha256(ffmpeg) == immutable["ffmpeg_sha256"] and
            _file_sha256(ffprobe) == immutable["ffprobe_sha256"] and
            release_inputs["ffmpeg"]["sha256"].lower() == immutable["ffmpeg_sha256"] and
            release_inputs["ffprobe"]["sha256"].lower() == immutable["ffprobe_sha256"],
            "official build FFmpeg identity")

    with tempfile.TemporaryDirectory(prefix="g12-build-gate-") as temporary_name:
        temporary = _assert_regular_path(Path(temporary_name), True,
                                         "official build temporary root")
        isolated_pkg_node = _copy_isolated_executable(
            pkg_node, temporary / "pkg-node-runtime", "node.exe",
            immutable["pkg_node_sha256"], immutable["pkg_node_bytes"],
            "isolated pkg base Node",
        )
        isolated_ffmpeg_set, isolated_ffmpeg_expected = _copy_isolated_executable_set(
            {
                "ffmpeg.exe": (ffmpeg, immutable["ffmpeg_sha256"]),
                "ffprobe.exe": (ffprobe, immutable["ffprobe_sha256"]),
            }, temporary / "ffmpeg-runtime", "isolated FFmpeg tools",
        )
        isolated_ffmpeg = isolated_ffmpeg_set["ffmpeg.exe"]
        isolated_ffprobe = isolated_ffmpeg_set["ffprobe.exe"]
        environment = _build_environment(
            node_binding, isolated_pkg_node, python_path, temporary, True,
        )
        build_python_dependency = _prepare_build_python_dependency(
            python_path, temporary, immutable,
        )
        pkg_probe_environment = dict(environment)
        _set_environment_value_ci(
            pkg_probe_environment, "PKG_EXECPATH", "PKG_INVOKE_NODEJS",
        )
        node_version = _subprocess_ascii_line(
            [str(node_binding["node"]), "--version"], "Node version", cwd=REPO,
            environment=environment,
        )
        npm_version = _subprocess_ascii_line(
            [str(node_binding["node"]), str(node_binding["npm_cli"]), "--version"],
            "npm version", cwd=REPO, environment=environment,
        )
        require(node_version == "v" + immutable["node_version"] and
                npm_version == immutable["npm_version"], "official build Node/npm version")
        pkg_node_version = _subprocess_ascii_line(
            [str(isolated_pkg_node), "--version"], "pkg base Node version",
            cwd=isolated_pkg_node.parent,
            environment=pkg_probe_environment,
        )
        require(pkg_node_version == "v" + immutable["pkg_node_version"],
                "pkg base Node version")
        git_version = _subprocess_ascii_line(
            [str(_git_executable()), "--version"], "Git version", cwd=REPO,
            environment=environment,
        )
        msbuild_path = _assert_regular_path(
            Path(r"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe"),
            False, "trusted host MSBuild",
        )
        msbuild_version = _subprocess_ascii_line(
            [str(msbuild_path), "-version", "-nologo"], "MSBuild version", cwd=REPO,
            environment=environment,
        )
        require(git_version == "git version " + PINNED_GIT_VERSION and
                msbuild_version == PINNED_MSBUILD_VERSION,
                "trusted Git/MSBuild versions")
        powershell = _assert_regular_path(
            Path(r"C:\Windows") /
            "System32/WindowsPowerShell/v1.0/powershell.exe", False,
            "Windows PowerShell 5.1",
        )
        require(_file_sha256(powershell) == PINNED_POWERSHELL_SHA256,
                "trusted Windows PowerShell identity")
        build_script = _assert_regular_path(REPO / "tools/build_all.ps1", False,
                                            "official build script")
        dependency_script = _assert_regular_path(
            REPO / "tests/test_v92_mx05_handoff.py", False,
            "build Python dependency consumer",
        )
        stdout_path = temporary / "build.stdout"
        stderr_path = temporary / "build.stderr"
        command_text = (
            "$ErrorActionPreference='Stop';$env:PSModulePath=" +
            _powershell_single_quote(
                r"C:\Windows\System32\WindowsPowerShell\v1.0\Modules"
            ) + ";function global:python.exe { if($args.Count -eq 1 -and " +
            "[string]::Equals([IO.Path]::GetFullPath([string]$args[0])," +
            _powershell_single_quote(str(dependency_script)) +
            ",[StringComparison]::OrdinalIgnoreCase)){ & " +
            _powershell_single_quote(str(python_path)) + " -I -S -B -c " +
            _powershell_single_quote(BUILD_PYTHON_DEPENDENCY_BOOTSTRAP) + " " +
            _powershell_single_quote(str(build_python_dependency["root"])) +
            " @args } else { & " + _powershell_single_quote(str(python_path)) +
            " -E -s -S -B @args } }; & " + _powershell_single_quote(str(build_script)) +
            " -RepoRoot " + _powershell_single_quote(str(REPO)) +
            " -ReleaseTag " + _powershell_single_quote(release_tag) +
            " -FfmpegPath " + _powershell_single_quote(str(isolated_ffmpeg)) +
            " -MaxCpuCount 0;if($LASTEXITCODE-ne0){exit $LASTEXITCODE}"
        )
        command = [
            str(powershell), "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass",
            "-Command", command_text,
        ]
        with stdout_path.open("wb") as stdout_stream, stderr_path.open("wb") as stderr_stream:
            process = subprocess.run(
                command, cwd=REPO, env=environment, check=False,
                stdout=stdout_stream, stderr=stderr_stream,
            )
        require(type(process.returncode) is int and process.returncode == 0,
                "official build failed")

        final_dependency_source, final_dependency_source_sha = \
            _build_python_dependency_inventory(
                build_python_dependency["source_root"],
            )
        final_dependency_projection, final_dependency_projection_sha = \
            _build_python_dependency_inventory(
                build_python_dependency["root"], strict_root=True,
            )
        require(canonical(final_dependency_source) ==
                canonical(build_python_dependency["identity"]) and
                canonical(final_dependency_projection) ==
                canonical(build_python_dependency["identity"]) and
                final_dependency_source_sha ==
                build_python_dependency["identity_sha256"] and
                final_dependency_projection_sha ==
                build_python_dependency["identity_sha256"],
                "build Python dependency changed during build")

        final_node_binding = _audit_node_distribution(node_binding["node"], immutable)
        require(canonical({key: final_node_binding[key] for key in (
                    "identity_sha256", "file_count", "directory_count",
                )}) == canonical({key: node_binding[key] for key in (
                    "identity_sha256", "file_count", "directory_count",
                )}), "Node distribution changed during build")
        require(_file_sha256(pkg_node) == immutable["pkg_node_sha256"] and
                pkg_node.stat().st_size == immutable["pkg_node_bytes"] and
                _file_sha256(ffmpeg) == immutable["ffmpeg_sha256"] and
                _file_sha256(ffprobe) == immutable["ffprobe_sha256"] and
                _file_sha256(python_path) == python_sha,
                "official build tool changed")
        _assert_isolated_executable(
            isolated_pkg_node.parent, isolated_pkg_node,
            immutable["pkg_node_sha256"], immutable["pkg_node_bytes"],
            "isolated pkg base Node changed",
        )
        _assert_isolated_executable_set(
            isolated_ffmpeg.parent, isolated_ffmpeg_expected,
            "isolated FFmpeg tools changed",
        )
        require(_subprocess_ascii_line(
                    [str(node_binding["node"]), "--version"], "Node version", cwd=REPO,
                    environment=environment,
                ) == node_version and _subprocess_ascii_line(
                    [str(node_binding["node"]), str(node_binding["npm_cli"]), "--version"],
                    "npm version", cwd=REPO, environment=environment,
                ) == npm_version and _subprocess_ascii_line(
                    [str(isolated_pkg_node), "--version"], "pkg base Node version",
                    cwd=isolated_pkg_node.parent,
                    environment=pkg_probe_environment,
                ) == pkg_node_version and _subprocess_ascii_line(
                    [str(_git_executable()), "--version"], "Git version", cwd=REPO,
                    environment=environment,
                ) == git_version and _subprocess_ascii_line(
                    [str(msbuild_path), "-version", "-nologo"], "MSBuild version", cwd=REPO,
                    environment=environment,
                ) == msbuild_version, "build tool versions changed during build")
        require(_file_sha256(powershell) == PINNED_POWERSHELL_SHA256 and
                _file_sha256(Path(r"C:\Windows\System32\cmd.exe")) == PINNED_CMD_SHA256 and
                _file_sha256(Path(r"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe")) == PINNED_MSBUILD_SHA256,
                "trusted host build executables changed")
        _assert_external_checkout(REPO, a_commit, a_tree,
                                  "fresh detached A64 source changed during build")
        _assert_project_npm_configs_absent(REPO)
        _assert_no_external_msbuild_imports(REPO)
        _assert_plain_git_configuration_safe(REPO,
                                             "official build Git configuration changed")
        _assert_plain_git_configuration_safe(
            REPO / "libutp", "official build submodule Git configuration changed",
        )
        _assert_command_processor_autorun_absent()
        isolated_pkg_node.unlink()
        isolated_pkg_node.parent.rmdir()
        isolated_ffmpeg.unlink()
        isolated_ffprobe.unlink()
        isolated_ffmpeg.parent.rmdir()
        require(not os.path.lexists(isolated_pkg_node.parent) and
                not os.path.lexists(isolated_ffmpeg.parent),
                "isolated build tool cleanup")

    runtime, build, receipt_raw = _audit_release_outputs(
        REPO, node_arg, release_tag, a_commit, a_tree, document,
    )
    return _build_result_from_receipt(
        receipt_raw, a_commit, a_tree, runtime, build,
    )


def _tap_summary(raw: bytes, label: str) -> dict[str, int]:
    require(len(raw) <= 64 * 1024 * 1024, f"{label} stdout length")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise GateError(f"{label} stdout encoding") from exc
    values: dict[str, int] = {}
    for key in ("tests", "pass", "fail", "cancelled", "skipped", "todo"):
        matches = re.findall(rf"(?m)^# {key} ([0-9]+)\r?$", text)
        require(len(matches) == 1, f"{label} TAP {key}")
        values[key] = int(matches[0])
    return values


def node_test_gate(suite: str, node_arg: str,
                   document: dict[str, Any]) -> dict[str, Any]:
    require(suite in {"FULL", "FOCAL"}, "Node test suite")
    immutable = document["immutable_contract"]
    _assert_python_runtime(immutable)
    require(sys.flags.isolated == 1 and sys.flags.no_site == 1 and
            sys.flags.ignore_environment == 1 and sys.flags.safe_path == 1 and
            sys.flags.dont_write_bytecode == 1, "isolated Python invocation")
    a_commit = _git_text("rev-parse", "HEAD")
    a_tree = _git_text("rev-parse", "HEAD^{tree}")
    _assert_external_checkout(REPO, a_commit, a_tree, "A64 Node-test source")
    node_binding = _audit_node_distribution(node_arg, immutable)
    package_root = _assert_regular_path(REPO / "tools/lab/nat_gateway", True,
                                        "nat_gateway test root")
    _assert_project_npm_configs_absent(REPO)
    package_lock = _assert_regular_path(package_root / "package-lock.json", False,
                                        "nat_gateway package lock")
    lock_raw = _blob(a_commit, immutable["package_lock_path"])
    require(sha256(lock_raw) == immutable["package_lock_sha256"] and
            package_lock.read_bytes() == lock_raw, "nat_gateway package lock identity")
    with tempfile.TemporaryDirectory(prefix="g12-node-test-") as temporary_name:
        python_path, _ = _assert_python_runtime(immutable)
        environment = _build_environment(
            node_binding, None, python_path, Path(temporary_name),
        )
        node_modules_candidate = package_root / "node_modules"
        if os.path.lexists(node_modules_candidate):
            pre_dependency_identity, pre_dependency_sha = \
                _node_distribution_inventory(node_modules_candidate)
            require(len(pre_dependency_identity["files"]) ==
                    immutable["nat_gateway_node_modules_file_count"] and
                    len(pre_dependency_identity["directories"]) ==
                    immutable["nat_gateway_node_modules_directory_count"] and
                    pre_dependency_sha ==
                    immutable["nat_gateway_node_modules_identity_sha256"],
                    "preexisting nat_gateway dependency identity")
        install = subprocess.run(
            [str(node_binding["node"]), str(node_binding["npm_cli"]), "ci",
             "--ignore-scripts", "--no-audit", "--no-fund", "--offline"],
            cwd=package_root, env=environment, check=False,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=1800,
        )
        require(install.returncode == 0, "pinned npm ci failed")
        node_modules = _assert_regular_path(package_root / "node_modules", True,
                                            "nat_gateway node_modules")
        dependency_identity, dependency_sha = _node_distribution_inventory(node_modules)
        require(len(dependency_identity["files"]) ==
                immutable["nat_gateway_node_modules_file_count"] and
                len(dependency_identity["directories"]) ==
                immutable["nat_gateway_node_modules_directory_count"] and
                dependency_sha == immutable["nat_gateway_node_modules_identity_sha256"],
                "nat_gateway installed dependency identity")
        ajv_package = _assert_regular_path(package_root / "node_modules/ajv/package.json",
                                           False, "installed Ajv package")
        require(ajv_package.stat().st_size <= 1024 * 1024, "installed Ajv package length")
        try:
            ajv = json.loads(ajv_package.read_text(encoding="utf-8"),
                             object_pairs_hook=_no_duplicates)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GateError("installed Ajv package") from exc
        require(isinstance(ajv, dict) and ajv.get("version") == immutable["ajv_version"],
                "installed Ajv version")
        if suite == "FULL":
            arguments = [str(node_binding["node"]), "--test"]
            test_cwd = package_root
            expected_name = "NODE22_FULL"
        else:
            arguments = [str(node_binding["node"]), "--test"] + [
                str(REPO / path) for path in (
                    "tools/lab/nat_gateway/test/v92_o01_formal_controller.test.js",
                    "tools/lab/nat_gateway/test/v92_o01_product_stream.test.js",
                    "tools/lab/nat_gateway/test/v92_o01_t8_fault_controller.test.js",
                    "tools/lab/nat_gateway/test/v92_o01_t8_udp_mux.test.js",
                    "tools/lab/nat_gateway/test/v92_o01_validate_formal.test.js",
                )
            ]
            test_cwd = REPO
            expected_name = "A64_FOCAL"
        tests = subprocess.run(
            arguments, cwd=test_cwd, env=environment, check=False,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600,
        )
        summary = _tap_summary(tests.stdout, expected_name)
        require(tests.returncode == 0 and tests.stderr == b"" and
                summary["fail"] == 0 and summary["cancelled"] == 0 and
                summary["todo"] == 0, f"{expected_name} failed")
        runtime = {"node_version": immutable["node_version"],
                   "node_sha256": immutable["node_sha256"]}
        expected_result = _gate_result(expected_name, runtime, {}, a_commit, a_tree, "", "")
        require(summary["tests"] == expected_result["tests"] and
                summary["pass"] == expected_result["passed"] and
                summary["skipped"] == expected_result["skipped"],
                f"{expected_name} TAP identity")
        final_node = _audit_node_distribution(node_binding["node"], immutable)
        final_dependency_identity, final_dependency_sha = \
            _node_distribution_inventory(node_modules)
        require(final_node["identity_sha256"] == node_binding["identity_sha256"] and
                final_dependency_sha == dependency_sha and
                canonical(final_dependency_identity) == canonical(dependency_identity) and
                package_lock.read_bytes() == lock_raw,
                f"{expected_name} inputs changed")
        _assert_external_checkout(REPO, a_commit, a_tree,
                                  f"{expected_name} source changed")
        _assert_project_npm_configs_absent(REPO)
    return expected_result


def _powershell_single_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _formal_runner_environment(temporary: Path) -> dict[str, str]:
    temporary = _assert_regular_path(temporary, True, "formal launcher temporary root")
    system_root = _assert_regular_path(Path(r"C:\Windows"), True,
                                       "formal launcher SystemRoot")
    command_processor = _assert_regular_path(
        system_root / "System32/cmd.exe", False, "formal launcher command processor",
    )
    require(_file_sha256(command_processor) == PINNED_CMD_SHA256,
            "formal launcher command processor identity")
    git_executable = _git_executable()
    git_root = git_executable.parents[1]
    git_core = _assert_regular_path(
        git_root / "mingw64/bin/git.exe", False, "formal launcher Git core",
    )
    require(_file_sha256(git_core) == PINNED_GIT_CORE_SHA256,
            "formal launcher Git core identity")
    profile = temporary / "profile"
    roaming = profile / "AppData/Roaming"
    local = profile / "AppData/Local"
    launch = temporary / "launch"
    roaming.mkdir(parents=True)
    local.mkdir(parents=True)
    launch.mkdir()
    environment: dict[str, str] = {}
    for key in (
        "COMPUTERNAME", "NUMBER_OF_PROCESSORS", "OS", "PROCESSOR_ARCHITECTURE",
        "PROCESSOR_IDENTIFIER", "PROCESSOR_LEVEL", "PROCESSOR_REVISION", "USERNAME",
    ):
        value = next((value for name, value in os.environ.items()
                      if name.casefold() == key.casefold()), None)
        if value is not None:
            _set_environment_value_ci(environment, key, value)
    _set_environment_value_ci(environment, "SystemRoot", str(system_root))
    _set_environment_value_ci(environment, "WINDIR", str(system_root))
    _set_environment_value_ci(environment, "SystemDrive", system_root.drive)
    _set_environment_value_ci(environment, "ProgramFiles", r"C:\Program Files")
    _set_environment_value_ci(environment, "ProgramFiles(x86)", r"C:\Program Files (x86)")
    _set_environment_value_ci(environment, "ProgramData", r"C:\ProgramData")
    _set_environment_value_ci(environment, "ALLUSERSPROFILE", r"C:\ProgramData")
    _set_environment_value_ci(environment, "CommonProgramFiles",
                              r"C:\Program Files\Common Files")
    _set_environment_value_ci(environment, "CommonProgramFiles(x86)",
                              r"C:\Program Files (x86)\Common Files")
    _set_environment_value_ci(environment, "COMSPEC", str(command_processor))
    _set_environment_value_ci(environment, "PATHEXT", ".COM;.EXE;.BAT;.CMD")
    _set_environment_value_ci(environment, "PATH", os.pathsep.join((
        str(git_executable.parent), str(git_root / "mingw64/bin"),
        str(command_processor.parent), str(system_root),
    )))
    _set_environment_value_ci(
        environment, "PSModulePath",
        str(system_root / "System32/WindowsPowerShell/v1.0/Modules"),
    )
    _set_environment_value_ci(environment, "TEMP", str(launch))
    _set_environment_value_ci(environment, "TMP", str(launch))
    _set_environment_value_ci(environment, "USERPROFILE", str(profile))
    _set_environment_value_ci(environment, "HOME", str(profile))
    _set_environment_value_ci(environment, "HOMEDRIVE", profile.drive)
    _set_environment_value_ci(environment, "HOMEPATH", str(profile)[len(profile.drive):])
    _set_environment_value_ci(environment, "APPDATA", str(roaming))
    _set_environment_value_ci(environment, "LOCALAPPDATA", str(local))
    environment = _closed_git_environment(environment)
    null_device = "NUL"
    git_config = [
        ("safe.directory", str(REPO)), ("core.fsmonitor", "false"),
        ("core.hooksPath", null_device), ("core.excludesFile", null_device),
        ("core.attributesFile", null_device), ("core.worktree", str(REPO)),
        ("core.bare", "false"), ("core.ignoreStat", "false"),
        ("extensions.worktreeConfig", "false"), ("core.autocrlf", "true"),
    ]
    environment["GIT_CONFIG_COUNT"] = str(len(git_config))
    for index, (key, value) in enumerate(git_config):
        environment[f"GIT_CONFIG_KEY_{index}"] = key
        environment[f"GIT_CONFIG_VALUE_{index}"] = value
    require(len(environment) == len({key.casefold() for key in environment}),
            "formal launcher environment key collision")
    resolved_git = shutil.which("git.exe", path=environment["PATH"])
    resolved_command = shutil.which("cmd.exe", path=environment["PATH"])
    require(resolved_git is not None and resolved_command is not None and
            _assert_regular_path(Path(resolved_git), False,
                                 "formal launcher resolved Git") == git_executable and
            _assert_regular_path(Path(resolved_command), False,
                                 "formal launcher resolved command processor") ==
            command_processor, "formal launcher command resolution")
    return environment


def _capture_formal_runner_receipt(argv: list[str], cwd: Path,
                                   environment: dict[str, str]) -> tuple[int, dict[str, Any]]:
    """Capture only the bounded structured launch receipt; never retain child stderr."""
    stdout_data = bytearray()
    stderr_bytes = [0]
    worker_errors: list[BaseException] = []
    stream_ready = threading.Event()
    streams: dict[str, Any] = {"stdout": None, "stderr": None}

    def drain_stdout() -> None:
        try:
            stream_ready.wait()
            stream = streams["stdout"]
            if stream is None:
                return
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    break
                remaining = MAX_FORMAL_LAUNCH_RECEIPT_BYTES + 1 - len(stdout_data)
                if remaining > 0:
                    stdout_data.extend(chunk[:remaining])
        except BaseException as exc:  # fixed projection below; never expose stream data
            worker_errors.append(exc)
        finally:
            if streams["stdout"] is not None:
                streams["stdout"].close()

    def drain_stderr() -> None:
        try:
            stream_ready.wait()
            stream = streams["stderr"]
            if stream is None:
                return
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    break
                stderr_bytes[0] = min(
                    MAX_FORMAL_LAUNCH_RECEIPT_BYTES + 1,
                    stderr_bytes[0] + len(chunk),
                )
        except BaseException as exc:  # fixed projection below; never retain stderr
            worker_errors.append(exc)
        finally:
            if streams["stderr"] is not None:
                streams["stderr"].close()

    stdout_thread = threading.Thread(target=drain_stdout, name="g12-formal-stdout")
    stderr_thread = threading.Thread(target=drain_stderr, name="g12-formal-stderr")
    started: list[threading.Thread] = []
    try:
        stdout_thread.start()
        started.append(stdout_thread)
        stderr_thread.start()
        started.append(stderr_thread)
    except BaseException as exc:
        stream_ready.set()
        for thread in started:
            thread.join()
        raise GateError("formal runner capture workers") from exc
    try:
        process = subprocess.Popen(
            argv, cwd=cwd, env=environment, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, ValueError) as exc:
        stream_ready.set()
        stdout_thread.join()
        stderr_thread.join()
        raise GateError("formal runner process start") from exc
    require(process.stdout is not None and process.stderr is not None,
            "formal runner process streams")
    streams["stdout"] = process.stdout
    streams["stderr"] = process.stderr
    stream_ready.set()
    while True:
        try:
            returncode = process.wait()
            break
        except KeyboardInterrupt:
            # The physical child owns rollback. Defer operator interruption until
            # its bounded lifecycle has completed, then continue the authenticated
            # handoff so no exact98 PASS set is abandoned before admission.
            continue
    stdout_thread.join()
    stderr_thread.join()
    require(not worker_errors and not stdout_thread.is_alive() and
            not stderr_thread.is_alive(), "formal runner process capture")
    require(returncode == 0 and stderr_bytes[0] == 0 and
            0 < len(stdout_data) <= MAX_FORMAL_LAUNCH_RECEIPT_BYTES,
            "formal runner process result")
    raw = bytes(stdout_data)
    require(raw.endswith(b"\r\n") and b"\r" not in raw[:-2] and
            b"\n" not in raw[:-2] and not raw.startswith(b"\xef\xbb\xbf"),
            "formal runner structured receipt framing")
    payload = raw[:-2]
    require(payload and all(0x20 <= byte <= 0x7E for byte in payload),
            "formal runner structured receipt encoding")
    try:
        receipt = json.loads(payload.decode("ascii"), object_pairs_hook=_no_duplicates)
        require(isinstance(receipt, dict) and
                json.dumps(receipt, ensure_ascii=True, separators=(",", ":")).encode(
                    "ascii"
                ) == payload,
                "formal runner structured receipt canonical form")
    except (UnicodeDecodeError, json.JSONDecodeError, GateError, ValueError) as exc:
        raise GateError("formal runner structured receipt") from exc
    return returncode, receipt


def _formal_evidence_set_sha256(cache: dict[str, bytes]) -> str:
    names = sorted(cache)
    require(len(names) == 98, "formal evidence receipt count")
    return sha256(canonical({
        "artifacts": [
            {"name": name, "sha256": sha256(cache[name])} for name in names
        ],
    }))


def _expected_formal_launch_receipt(cache: dict[str, bytes],
                                    root_metadata: dict[str, bytes],
                                    a_commit: str, a_tree: str,
                                    h_commit: str) -> dict[str, Any]:
    require(set(root_metadata) == {"plan.json", "state.json"},
            "formal launch receipt metadata")
    return {
        "schema": "ese.v92.o01-formal-launch-receipt/v1",
        "verdict": "PASS", "release_gate": True,
        "source_commit": a_commit, "source_tree": a_tree,
        "governance_h_commit": h_commit, "governance_s_commit": None,
        "artifact_count": 98,
        "evidence_set_sha256": _formal_evidence_set_sha256(cache),
        "formal_run_sha256": sha256(cache["formal-run-result.json"]),
        "formal_validation_sha256": sha256(cache["formal-validation.json"]),
        "plan_sha256": sha256(root_metadata["plan.json"]),
        "state_sha256": sha256(root_metadata["state.json"]),
        "raw_streams_retained": False,
    }


@contextmanager
def _formal_evidence_read_guard(
        controller: Path,
        failure_disposition: dict[str, Any] | None = None,
):
    """Hold exact98 with Windows FILE_SHARE_READ until every postcheck is complete."""
    require(os.name == "nt", "formal evidence guard platform")
    import ctypes
    import msvcrt

    class FileTime(ctypes.Structure):
        _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_uint32)]

    class FileInformation(ctypes.Structure):
        _fields_ = [
            ("attributes", ctypes.c_uint32), ("creation", FileTime),
            ("access", FileTime), ("write", FileTime),
            ("volume", ctypes.c_uint32), ("size_high", ctypes.c_uint32),
            ("size_low", ctypes.c_uint32), ("links", ctypes.c_uint32),
            ("index_high", ctypes.c_uint32), ("index_low", ctypes.c_uint32),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
        ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
    ]
    create_file.restype = ctypes.c_void_p
    get_information = kernel32.GetFileInformationByHandle
    get_information.argtypes = [ctypes.c_void_p, ctypes.POINTER(FileInformation)]
    get_information.restype = ctypes.c_int
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [ctypes.c_void_p]
    close_handle.restype = ctypes.c_int
    set_file_information = kernel32.SetFileInformationByHandle
    set_file_information.argtypes = [
        ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32,
    ]
    set_file_information.restype = ctypes.c_int

    class FileDispositionInformation(ctypes.Structure):
        _fields_ = [("delete_file", ctypes.c_ubyte)]

    class FileDispositionInformationEx(ctypes.Structure):
        _fields_ = [("flags", ctypes.c_uint32)]

    generic_read = 0x80000000
    delete_access = 0x00010000
    file_share_read = 0x00000001
    open_existing = 3
    file_attribute_normal = 0x00000080
    file_flag_open_reparse_point = 0x00200000
    file_flag_backup_semantics = 0x02000000
    file_attribute_directory = 0x00000010
    file_attribute_reparse = 0x00000400
    file_disposition_information = 4
    file_disposition_information_ex = 21
    file_disposition_delete = 0x00000001
    file_disposition_posix_semantics = 0x00000002
    file_disposition_ignore_readonly = 0x00000010
    invalid_handle = ctypes.c_void_p(-1).value

    def information(handle_value: int, expect_directory: bool = False) -> tuple[int, int, int]:
        row = FileInformation()
        require(bool(get_information(ctypes.c_void_p(handle_value), ctypes.byref(row))),
                "formal evidence guard identity")
        is_directory = bool(row.attributes & file_attribute_directory)
        require(not bool(row.attributes & file_attribute_reparse) and
                is_directory is expect_directory, "formal evidence guard file type")
        size = (int(row.size_high) << 32) | int(row.size_low)
        if not expect_directory:
            require(0 < size <= 8 * 1024 * 1024,
                    "formal evidence guard file size")
        identity = (int(row.volume) << 64) | (int(row.index_high) << 32) | int(row.index_low)
        return identity, size, int(row.attributes)

    controller = _assert_regular_path(controller, True, "formal controller evidence")
    evidence_root = _assert_regular_path(controller.parent, True,
                                         "formal evidence root")
    directory_handles: list[int] = []
    guarded: dict[str, tuple[Any, tuple[int, int, int]]] = {}
    metadata_guarded: dict[str, tuple[Any, tuple[int, int, int]]] = {}
    try:
        for directory in (evidence_root, controller):
            handle = create_file(
                str(directory), generic_read, file_share_read, None, open_existing,
                file_attribute_normal | file_flag_open_reparse_point |
                file_flag_backup_semantics, None,
            )
            require(handle not in (None, invalid_handle),
                    "formal evidence directory guard")
            handle_value = int(handle)
            try:
                information(handle_value, True)
                directory_handles.append(handle_value)
                handle = None
            finally:
                if handle not in (None, invalid_handle):
                    close_handle(ctypes.c_void_p(int(handle)))
        root_entries = {entry.name: entry for entry in os.scandir(evidence_root)}
        require(set(root_entries) == {"controller", "plan.json", "state.json"} and
                root_entries["controller"].is_dir(follow_symlinks=False) and
                not root_entries["controller"].is_symlink() and
                all(not root_entries[name].is_dir(follow_symlinks=False) and
                    not root_entries[name].is_symlink()
                    for name in ("plan.json", "state.json")),
                "formal evidence root exact set")
        for name in ("plan.json", "state.json"):
            path = _assert_regular_path(evidence_root / name, False,
                                        "formal evidence metadata guard path")
            handle = create_file(
                str(path), generic_read, file_share_read, None, open_existing,
                file_attribute_normal | file_flag_open_reparse_point, None,
            )
            require(handle not in (None, invalid_handle),
                    "formal evidence metadata guard open")
            handle_value = int(handle)
            file_descriptor = None
            try:
                identity = information(handle_value)
                file_descriptor = msvcrt.open_osfhandle(
                    handle_value, os.O_RDONLY | getattr(os, "O_BINARY", 0),
                )
                handle = None
                try:
                    stream = os.fdopen(file_descriptor, "rb", buffering=0)
                    file_descriptor = None
                finally:
                    if file_descriptor is not None:
                        os.close(file_descriptor)
            finally:
                if handle not in (None, invalid_handle):
                    close_handle(ctypes.c_void_p(int(handle)))
            metadata_guarded[name] = (stream, identity)
        directory_entries = list(os.scandir(controller))
        names = [entry.name for entry in directory_entries]
        validate_r64_paths(names)
        require(all(not entry.is_dir(follow_symlinks=False) and
                    not entry.is_symlink() for entry in directory_entries),
                "formal exact evidence files")
        names = sorted(names)
        for name in names:
            path = _assert_regular_path(controller / name, False,
                                        "formal evidence guard path")
            handle = create_file(
                str(path), generic_read | (delete_access if name in (
                    "formal-run-result.json", "formal-validation.json",
                ) else 0), file_share_read, None, open_existing,
                file_attribute_normal | file_flag_open_reparse_point, None,
            )
            require(handle not in (None, invalid_handle), "formal evidence guard open")
            handle_value = int(handle)
            file_descriptor: int | None = None
            try:
                identity = information(handle_value)
                file_descriptor = msvcrt.open_osfhandle(
                    handle_value, os.O_RDONLY | getattr(os, "O_BINARY", 0),
                )
                handle = None  # the CRT descriptor now owns the Windows handle
                try:
                    stream = os.fdopen(file_descriptor, "rb", buffering=0)
                    file_descriptor = None  # the Python stream now owns the descriptor
                finally:
                    if file_descriptor is not None:
                        os.close(file_descriptor)
            finally:
                if handle not in (None, invalid_handle):
                    close_handle(ctypes.c_void_p(int(handle)))
            guarded[name] = (stream, identity)
        require(len(guarded) == 98, "formal evidence guard count")
        yield guarded, metadata_guarded
    except BaseException:
        if (failure_disposition is not None and
                failure_disposition.get("claimed") is True):
            delete_failed = False
            for name in ("formal-run-result.json", "formal-validation.json"):
                row = guarded.get(name)
                if row is None:
                    delete_failed = True
                    continue
                stream = row[0]
                try:
                    handle_value = msvcrt.get_osfhandle(stream.fileno())
                    disposition_ex = FileDispositionInformationEx(
                        file_disposition_delete |
                        file_disposition_posix_semantics |
                        file_disposition_ignore_readonly,
                    )
                    deleted = bool(set_file_information(
                        ctypes.c_void_p(handle_value),
                        file_disposition_information_ex,
                        ctypes.byref(disposition_ex),
                        ctypes.sizeof(disposition_ex),
                    ))
                    if not deleted:
                        disposition = FileDispositionInformation(1)
                        deleted = bool(set_file_information(
                            ctypes.c_void_p(handle_value),
                            file_disposition_information,
                            ctypes.byref(disposition), ctypes.sizeof(disposition),
                        ))
                    if not deleted:
                        delete_failed = True
                except (OSError, ValueError):
                    delete_failed = True
            failure_disposition["handle_invalidation_failed"] = delete_failed
        raise
    finally:
        for stream, _ in guarded.values():
            try:
                stream.close()
            except OSError:
                pass
        for stream, _ in metadata_guarded.values():
            try:
                stream.close()
            except OSError:
                pass
        for handle_value in reversed(directory_handles):
            close_handle(ctypes.c_void_p(handle_value))
        # A validated success is committed while these handles are live. Reporting
        # a synthetic failure after stdout was flushed would create contradictory
        # PASS/FAIL output; Windows process teardown is the final fail-safe release
        # for any handle whose ordinary close reported an error. On a body failure,
        # the original closed error remains authoritative and delete-pending handles
        # are likewise released at process teardown.


def _read_formal_evidence_guard(
        guarded: dict[str, tuple[Any, tuple[int, int, int]]],
) -> dict[str, bytes]:
    cache: dict[str, bytes] = {}
    for name, (stream, (_, size, _)) in guarded.items():
        stream.seek(0)
        data = stream.read(8 * 1024 * 1024 + 1)
        require(len(data) == size and len(data) <= 8 * 1024 * 1024,
                "formal evidence guard read")
        cache[name] = data
    return cache


def _assert_formal_evidence_guard_unchanged(
        controller: Path, guarded: dict[str, tuple[Any, tuple[int, int, int]]],
        expected: dict[str, bytes],
) -> None:
    require(_read_formal_evidence_guard(guarded) == expected,
            "formal evidence guard changed")
    controller = _assert_regular_path(controller, True, "formal controller evidence")
    entries = list(os.scandir(controller))
    require(sorted(entry.name for entry in entries) == sorted(guarded) and
            all(not entry.is_dir(follow_symlinks=False) and not entry.is_symlink()
                for entry in entries), "formal evidence guard final set")


def _formal_evidence_root_metadata(
        evidence_root: Path,
        guarded: dict[str, tuple[Any, tuple[int, int, int]]] | None = None,
) -> dict[str, bytes]:
    evidence_root = _assert_regular_path(evidence_root, True, "formal evidence root")
    entries = {entry.name: entry for entry in os.scandir(evidence_root)}
    require(set(entries) == {"controller", "plan.json", "state.json"} and
            entries["controller"].is_dir(follow_symlinks=False) and
            not entries["controller"].is_symlink() and
            all(not entries[name].is_dir(follow_symlinks=False) and
                not entries[name].is_symlink() for name in ("plan.json", "state.json")),
            "formal evidence root exact set")
    raw = (_read_formal_evidence_guard(guarded) if guarded is not None else {
        name: _read_limited(evidence_root / name, 2 * 1024 * 1024,
                            "formal evidence root metadata")
        for name in ("plan.json", "state.json")
    })
    require(set(raw) == {"plan.json", "state.json"},
            "formal evidence root metadata set")
    require(all(0 < len(raw[name]) <= 2 * 1024 * 1024 for name in raw),
            "formal evidence root metadata size")
    state_raw = raw["state.json"]
    require(state_raw.endswith(b"\r\n") and
            b"\r" not in state_raw.replace(b"\r\n", b"") and
            b"\n" not in state_raw.replace(b"\r\n", b"") and
            not state_raw.startswith(b"\xef\xbb\xbf"),
            "formal torn-down state encoding")
    try:
        state = json.loads(
            state_raw.decode("utf-8"), object_pairs_hook=_no_duplicates,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, GateError, ValueError) as exc:
        raise GateError("formal torn-down state") from exc
    require(isinstance(state, dict) and state.get("phase") == "TORN_DOWN",
            "formal torn-down state")
    return raw


def _formal_package_binding(package_root: Path,
                            bindings: dict[str, Any]) -> dict[str, Any]:
    package_root = _assert_regular_path(package_root, True, "formal PackageRoot")
    hashes, manifest_sha = _audit_package_manifest(package_root)
    require(manifest_sha == bindings["package_manifest_sha256"] and
            len(hashes) == bindings["package_manifest_entry_count"] and
            len(hashes) + 1 == bindings["package_file_count"] and
            hashes.get("emule.exe") == bindings["executable_sha256"] and
            hashes.get("BUILD_INFO.txt") == bindings["build_info_sha256"],
            "formal PackageRoot runtime binding")
    return {"manifest_sha256": manifest_sha, "hashes": hashes}


def _assert_formal_launch_inputs_unchanged(snapshot: dict[str, Any]) -> None:
    bindings = snapshot["bindings"]
    package_root = snapshot["package_root"]
    require(canonical(_formal_package_binding(package_root, bindings)) ==
            canonical(snapshot["package_before"]), "formal PackageRoot changed")
    node_before = snapshot["node_before"]
    node_after = _audit_node_distribution(node_before["node"], snapshot["immutable"])
    require(all(node_after[key] == node_before[key] for key in (
        "root", "node", "npm_cmd", "npm_cli", "identity_sha256",
        "file_count", "directory_count",
    )), "formal Node distribution changed")
    require(_read_limited(snapshot["runner"], 2 * 1024 * 1024,
                          "formal launcher runner") == snapshot["runner_raw"] and
            _file_sha256(snapshot["powershell"]) == PINNED_POWERSHELL_SHA256 and
            _blob(snapshot["h_commit"], H_PATHS[0]) == snapshot["activation_raw"] and
            _git_text("rev-parse", f"{snapshot['h_commit']}^{{tree}}") ==
                snapshot["h_tree"],
            "formal launcher inputs changed")
    _assert_external_checkout(
        REPO, snapshot["a_commit"], snapshot["a_tree"],
        "formal launcher A64 source changed",
    )
    credential_source = _assert_regular_path(
        snapshot["credential_source"], False, "formal launcher credential",
    )
    require(_file_sha256(credential_source) == snapshot["credential_sha"] and
            credential_source.stat().st_size == snapshot["credential_bytes"],
            "formal launcher credential changed")


def _paths_overlap(left: Path, right: Path) -> bool:
    try:
        common = Path(os.path.commonpath((str(left), str(right))))
    except ValueError:
        return False
    return common == left or common == right


def _formal_path_identity(path: Path, directory: bool) -> tuple[int, int]:
    path = _assert_regular_path(path, directory, "formal owned evidence identity")
    row = path.stat(follow_symlinks=False)
    return int(row.st_dev), int(row.st_ino)


def _claim_formal_pass_ownership(evidence_root: Path,
                                 ownership: dict[str, Any]) -> None:
    require(not ownership, "formal PASS ownership cardinality")
    controller = evidence_root / "controller"
    ownership.update({
        "claimed": True,
        "root": _formal_path_identity(evidence_root, True),
        "controller": _formal_path_identity(controller, True),
        "formal-run-result.json": _formal_path_identity(
            controller / "formal-run-result.json", False,
        ),
        "formal-validation.json": _formal_path_identity(
            controller / "formal-validation.json", False,
        ),
    })


def _remove_formal_pass_carriers(controller: Path,
                                 ownership: dict[str, Any]) -> None:
    require(ownership.get("claimed") is True and
            _formal_path_identity(controller.parent, True) == ownership.get("root") and
            _formal_path_identity(controller, True) == ownership.get("controller"),
            "formal PASS carrier ownership")
    if not os.path.lexists(controller):
        return
    for name in ("formal-run-result.json", "formal-validation.json"):
        path = controller / name
        if os.path.lexists(path):
            require(_formal_path_identity(path, False) == ownership.get(name),
                    "formal PASS carrier ownership")
            path = _assert_regular_path(path, False, "formal partial PASS carrier")
            path.unlink()
            require(not os.path.lexists(path), "formal partial PASS carrier cleanup")


@contextmanager
def _invalidate_formal_pass_on_failure(evidence_root: Path,
                                       ownership: dict[str, Any]):
    try:
        yield
    except BaseException as exc:
        try:
            if ownership.get("claimed") is True:
                _remove_formal_pass_carriers(evidence_root / "controller", ownership)
        except BaseException as cleanup_exc:
            raise GateError("formal PASS carrier invalidation") from cleanup_exc
        raise


def formal_run_gate(h_commit: str, evidence_root_arg: str, package_root_arg: str,
                    node_arg: str, credential_path_arg: str,
                    document: dict[str, Any], guard_stack: ExitStack,
                    pass_ownership: dict[str, Any]) -> tuple[
                        dict[str, Any], dict[str, Any], dict[str, Any],
                        dict[str, Any], dict[str, Any]
                    ]:
    require(os.name == "nt" and re.fullmatch(r"[0-9a-f]{40}", h_commit) is not None,
            "formal launcher platform and H64 identity")
    import ctypes
    require(bool(ctypes.windll.shell32.IsUserAnAdmin()),
            "formal launcher requires elevation")
    immutable = document["immutable_contract"]
    a_commit = _git_text("rev-parse", "HEAD")
    a_tree = _git_text("rev-parse", "HEAD^{tree}")
    _assert_external_checkout(REPO, a_commit, a_tree, "formal launcher A64 source")
    g_parents = _parents(a_commit)
    h_parents = _parents(h_commit)
    require(len(g_parents) == 1 and len(h_parents) == 1,
            "formal launcher topology")
    g_commit = g_parents[0]
    m_commit = h_parents[0]
    require(_parents(m_commit) == [a_commit], "formal launcher H64 ancestry")
    verify_m(m_commit, a_commit)
    verify_h(h_commit, m_commit, a_commit, g_commit, document)
    h_tree = _git_text("rev-parse", f"{h_commit}^{{tree}}")
    activation_raw = _blob(h_commit, H_PATHS[0])
    activation = load_json_bytes(activation_raw, "formal launcher H64 activation")
    manifest = load_json_bytes(
        _blob(m_commit, "docs/architecture/mod02_build_manifest_v1.json"),
        "formal launcher M64 build manifest",
    )
    bindings = _validate_runtime_bindings(
        activation.get("runtime_bindings"), manifest, immutable,
    )

    expected_package_root = _assert_regular_path(
        REPO / "dist" / RELEASE_TAG / "package", True,
        "formal launcher official PackageRoot",
    )
    require(Path(package_root_arg).is_absolute(), "formal launcher PackageRoot absolute")
    package_root = _assert_regular_path(Path(package_root_arg), True,
                                        "formal launcher PackageRoot")
    require(package_root == expected_package_root,
            "formal launcher official PackageRoot provenance")
    package_before = _formal_package_binding(package_root, bindings)
    node_before = _audit_node_distribution(node_arg, immutable)
    require(bindings["node_sha256"] == immutable["node_sha256"],
            "formal launcher Node binding")

    runner_relative = "tools/lab/run_v92_o01_formal.ps1"
    runner = _assert_regular_path(REPO / PurePosixPath(runner_relative), False,
                                  "formal launcher runner")
    runner_raw = _read_limited(runner, 2 * 1024 * 1024, "formal launcher runner")
    require(runner_raw == _blob(a_commit, runner_relative) and
            sha256(runner_raw) == A_SHA256[runner_relative],
            "formal launcher runner identity")
    powershell = _assert_regular_path(
        Path(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
        False, "formal launcher PowerShell",
    )
    require(_file_sha256(powershell) == PINNED_POWERSHELL_SHA256,
            "formal launcher PowerShell identity")

    require(Path(credential_path_arg).is_absolute(),
            "formal launcher credential absolute")
    credential_source = _assert_regular_path(Path(credential_path_arg), False,
                                              "formal launcher credential")
    credential_sha = _file_sha256(credential_source)
    credential_bytes = credential_source.stat().st_size
    evidence_candidate = Path(evidence_root_arg)
    require(evidence_candidate.is_absolute() and
            re.fullmatch(r"eSE-v9\.2-o01-formal-[0-9a-f]{12}",
                         evidence_candidate.name) is not None,
            "formal launcher evidence path")
    evidence_parent = _assert_regular_path(evidence_candidate.parent, True,
                                           "formal launcher evidence parent")
    evidence_root = evidence_parent / evidence_candidate.name
    require(not os.path.lexists(evidence_root), "fresh formal evidence root")
    for protected in (REPO, package_root, node_before["root"], credential_source):
        require(not _paths_overlap(evidence_root, protected),
                "formal launcher path overlap")
    input_snapshot = {
        "bindings": bindings, "package_root": package_root,
        "package_before": package_before, "node_before": node_before,
        "immutable": immutable, "runner": runner, "runner_raw": runner_raw,
        "powershell": powershell, "h_commit": h_commit, "h_tree": h_tree,
        "activation_raw": activation_raw, "a_commit": a_commit, "a_tree": a_tree,
        "credential_source": credential_source, "credential_sha": credential_sha,
        "credential_bytes": credential_bytes,
    }

    require(not pass_ownership, "formal PASS ownership initial")
    with tempfile.TemporaryDirectory(prefix="g12-formal-launch-") as temporary_name:
        temporary = _assert_regular_path(Path(temporary_name), True,
                                         "formal launcher temporary root")
        credential_runtime = temporary / "credential"
        isolated_credential = _copy_isolated_executable(
            credential_source, credential_runtime, "guest-credential.clixml",
            credential_sha, credential_bytes, "formal launcher isolated credential",
        )
        environment = _formal_runner_environment(temporary)
        launch_cwd = _assert_regular_path(temporary / "launch", True,
                                          "formal launcher cwd")
        argv = [
            str(powershell), "-NoLogo", "-NoProfile", "-NonInteractive",
            "-ExecutionPolicy", "Bypass", "-File", str(runner),
            "-EvidenceRoot", str(evidence_root), "-PackageRoot", str(package_root),
            "-ExpectedExeSha256", bindings["executable_sha256"],
            "-ExpectedBuildInfoSha256", bindings["build_info_sha256"],
            "-ExpectedPackageManifestSha256", bindings["package_manifest_sha256"],
            "-ExpectedNodeSha256", bindings["node_sha256"],
            "-GovernanceHCommit", h_commit, "-NodePath", str(node_before["node"]),
            "-VMName", "v92-o01-client", "-CredentialPath", str(isolated_credential),
        ]
        process_returncode: int | None = None
        launch_receipt: dict[str, Any] | None = None
        try:
            process_returncode, launch_receipt = _capture_formal_runner_receipt(
                argv, launch_cwd, environment,
            )
            controller = _assert_regular_path(evidence_root / "controller", True,
                                               "formal controller evidence")
            evidence_guard, metadata_guard = guard_stack.enter_context(
                _formal_evidence_read_guard(controller, pass_ownership),
            )
            root_metadata = _formal_evidence_root_metadata(
                evidence_root, metadata_guard,
            )
            cache = _read_formal_evidence_guard(evidence_guard)
            expected_receipt = _expected_formal_launch_receipt(
                cache, root_metadata, a_commit, a_tree, h_commit,
            )
            exact_keys(launch_receipt, FORMAL_LAUNCH_RECEIPT_KEYS,
                       "formal launch receipt")
            require_exact_value(launch_receipt, expected_receipt,
                                "formal launch receipt")
            _claim_formal_pass_ownership(evidence_root, pass_ownership)
            input_snapshot["root_metadata"] = root_metadata
            run = _validate_formal_evidence(
                lambda name: cache[name], bindings, a_commit, a_tree, h_commit,
                document, node_source=node_before["node"],
            )
            for forbidden in (
                "failure.json", "failure.json.tmp", "guest-run.vhdx",
                "node-runtime", "node-scratch", "host-config.json",
                "host-config.json.tmp",
            ):
                require(not os.path.lexists(evidence_root / forbidden),
                        "formal forbidden residual")
            _assert_formal_launch_inputs_unchanged(input_snapshot)
            _assert_formal_evidence_guard_unchanged(
                controller, evidence_guard, cache,
            )
            require(_formal_evidence_root_metadata(
                        evidence_root, metadata_guard,
                    ) == root_metadata,
                    "formal evidence root metadata changed")
        finally:
            _assert_isolated_executable(
                credential_runtime, isolated_credential, credential_sha,
                credential_bytes, "formal launcher isolated credential cleanup",
            )
            isolated_credential.unlink()
            require(list(os.scandir(credential_runtime)) == [],
                    "formal launcher isolated credential cleanup")
            credential_runtime.rmdir()
        require(process_returncode == 0 and not os.path.lexists(credential_runtime),
                "formal launcher cleanup")
    require(launch_receipt is not None and
            set(input_snapshot.get("root_metadata", {})) ==
                {"plan.json", "state.json"},
            "formal launch receipt unavailable")
    guard_state = {
        "controller": controller, "evidence_guard": evidence_guard,
        "metadata_guard": metadata_guard, "cache": cache,
        "root_metadata": root_metadata,
    }
    return run, launch_receipt, input_snapshot, pass_ownership, guard_state


def powershell_gate(name: str, node_arg: str, document: dict[str, Any], *,
                    executable_arg: str | None = None,
                    output_root_arg: str | None = None,
                    build_manifest_arg: str | None = None,
                    timeout_seconds: int | None = None) -> dict[str, Any]:
    scripts = {
        "MOD02_RUNTIME": "tools/architecture/run_mod02_stream_selftest.ps1",
        "RPC_PUMP_MOCK": "tools/lab/test_v92_o01_formal_rpc_pump_mock.ps1",
        "FORMAL_RUNNER_MOCK": "tools/lab/test_v92_o01_formal_runner_mock.ps1",
        "VM_SESSION_MOCK": "tools/lab/test_v92_o01_vm_session_mock.ps1",
        "FORMAL_PRODUCT_MOCK":
            "tools/lab/handoff93/test_product_mapper_formal_soak_mock.ps1",
    }
    require(name in scripts, "PowerShell gate name")
    immutable = document["immutable_contract"]
    python_path, _ = _assert_python_runtime(immutable)
    node_binding = _audit_node_distribution(node_arg, immutable)
    source_commit = _git_text("rev-parse", "HEAD")
    source_tree = _git_text("rev-parse", "HEAD^{tree}")
    _assert_external_checkout(REPO, source_commit, source_tree,
                              "PowerShell gate source")
    _assert_project_npm_configs_absent(REPO)
    script_relative = scripts[name]
    script_path = _assert_regular_path(REPO / PurePosixPath(script_relative), False,
                                       "PowerShell gate script")
    script_raw = script_path.read_bytes()
    require(script_raw == _blob(source_commit, script_relative),
            "PowerShell gate script identity")
    powershell = _assert_regular_path(
        Path(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
        False, "trusted Windows PowerShell",
    )
    require(_file_sha256(powershell) == PINNED_POWERSHELL_SHA256,
            "trusted Windows PowerShell identity")

    mod02_inputs: dict[str, Any] | None = None
    arguments = ""
    if name == "MOD02_RUNTIME":
        require(all(isinstance(value, str) and value for value in (
            executable_arg, output_root_arg, build_manifest_arg,
        )) and type(timeout_seconds) is int and timeout_seconds == 180,
                "MOD02 PowerShell gate arguments")
        executable = _assert_regular_path(Path(executable_arg), False,
                                           "MOD02 executable")
        executable_sha = _file_sha256(executable)
        build_manifest = _assert_regular_path(Path(build_manifest_arg), False,
                                              "MOD02 build manifest")
        manifest_raw = _read_limited(build_manifest, 1024 * 1024,
                                     "MOD02 build manifest")
        manifest = load_json_bytes(manifest_raw, "MOD02 build manifest")
        exact_keys(manifest, ["schema", "source_commit", "source_identity_sha256",
                              "executable_sha256"], "MOD02 build manifest")
        old = _import_old_verifier()
        require(manifest["schema"] == "ese.mod02.build-manifest/v1" and
                manifest["source_commit"] == source_commit and
                manifest["source_identity_sha256"] == old.MOD02_IDENTITY and
                manifest["executable_sha256"] == executable_sha,
                "MOD02 build manifest identity")
        output_root = Path(output_root_arg)
        require(not os.path.lexists(output_root), "fresh MOD02 output root")
        _assert_regular_path(output_root.parent, True, "MOD02 output parent")
        package_root = _assert_regular_path(
            REPO / "dist" / RELEASE_TAG / "package", True,
            "MOD02 package root",
        )
        package_executable = _assert_regular_path(
            package_root / "emule.exe", False, "MOD02 package executable",
        )
        package_ffmpeg = _assert_regular_path(
            package_root / "ffmpeg.exe", False, "MOD02 package FFmpeg",
        )
        executable_stat = executable.stat()
        package_ffmpeg_stat = package_ffmpeg.stat()
        require(_file_sha256(package_executable) == executable_sha and
                package_executable.stat().st_size == executable_stat.st_size and
                _file_sha256(package_ffmpeg) == immutable["ffmpeg_sha256"],
                "MOD02 package runtime identity")
        mod02_inputs = {
            "executable": executable, "build_manifest": build_manifest,
            "output_root": output_root, "executable_sha256": executable_sha,
            "manifest_sha256": sha256(manifest_raw),
            "package_executable": package_executable,
            "package_ffmpeg": package_ffmpeg,
            "executable_bytes": executable_stat.st_size,
            "executable_mtime_ns": executable_stat.st_mtime_ns,
            "ffmpeg_bytes": package_ffmpeg_stat.st_size,
            "ffmpeg_mtime_ns": package_ffmpeg_stat.st_mtime_ns,
        }
    else:
        require(executable_arg is None and output_root_arg is None and
                build_manifest_arg is None and timeout_seconds is None,
                "mock PowerShell gate arguments")

    with tempfile.TemporaryDirectory(prefix="g12-powershell-gate-") as temporary_name:
        temporary = Path(temporary_name)
        environment = _build_environment(
            node_binding, None, python_path, temporary, False,
        )
        isolated_mod02: dict[str, Path] | None = None
        isolated_mod02_expected: dict[str, tuple[str, int]] | None = None
        isolated_mod02_root: Path | None = None
        isolated_mod02_preference: Path | None = None
        if mod02_inputs is not None:
            isolated_mod02_root = temporary / "mod02-runtime"
            isolated_mod02, isolated_mod02_expected = \
                _copy_isolated_executable_set({
                    "emule.exe": (
                        mod02_inputs["executable"],
                        mod02_inputs["executable_sha256"],
                    ),
                    "ffmpeg.exe": (
                        mod02_inputs["package_ffmpeg"],
                        immutable["ffmpeg_sha256"],
                    ),
                }, isolated_mod02_root, "isolated MOD02 runtime")
            isolated_mod02_config = isolated_mod02_root / "config"
            require(not os.path.lexists(isolated_mod02_config),
                    "isolated MOD02 portable preference seed")
            isolated_mod02_config.mkdir()
            _assert_regular_path(
                isolated_mod02_config, True,
                "isolated MOD02 portable preference seed",
            )
            isolated_mod02_preference = isolated_mod02_config / "preferences.ini"
            with isolated_mod02_preference.open("xb") as seed_stream:
                seed_stream.write(MOD02_PORTABLE_SEED)
                seed_stream.flush()
                os.fsync(seed_stream.fileno())
            for executable_name, mtime_key in (
                ("emule.exe", "executable_mtime_ns"),
                ("ffmpeg.exe", "ffmpeg_mtime_ns"),
            ):
                isolated_path = isolated_mod02[executable_name]
                os.utime(
                    isolated_path,
                    ns=(isolated_path.stat().st_atime_ns,
                        mod02_inputs[mtime_key]),
                )
                require(isolated_path.stat().st_mtime_ns ==
                        mod02_inputs[mtime_key],
                        "isolated MOD02 runtime timestamp")
            _assert_mod02_runtime_initial(
                isolated_mod02_root, isolated_mod02_expected,
                (MOD02_PORTABLE_SEED_SHA256, len(MOD02_PORTABLE_SEED)),
                "isolated MOD02 runtime initial set",
            )
            arguments = (
                " -Executable " +
                _powershell_single_quote(str(isolated_mod02["emule.exe"])) +
                " -OutputRoot " +
                _powershell_single_quote(str(mod02_inputs["output_root"])) +
                " -BuildManifest " +
                _powershell_single_quote(str(mod02_inputs["build_manifest"])) +
                " -TimeoutSeconds 180"
            )
        module_path = r"C:\Windows\System32\WindowsPowerShell\v1.0\Modules"
        command_text = (
            "$ErrorActionPreference='Stop';$env:PSModulePath=" +
            _powershell_single_quote(module_path) + "; & " +
            _powershell_single_quote(str(script_path)) + arguments +
            ";if($LASTEXITCODE-ne0){exit $LASTEXITCODE}"
        )
        process = subprocess.run(
            [str(powershell), "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass",
             "-Command", command_text], cwd=REPO, env=environment, check=False,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=300 if name == "MOD02_RUNTIME" else 900,
        )
        if mod02_inputs is not None:
            require(isolated_mod02 is not None and
                    isolated_mod02_expected is not None and
                    isolated_mod02_root is not None and
                    isolated_mod02_preference is not None,
                    "isolated MOD02 runtime state")
            post_runtime = _assert_mod02_runtime_post(
                isolated_mod02_root, isolated_mod02_expected,
                "isolated MOD02 runtime changed",
            )
            isolated_emule = post_runtime["emule.exe"]
            isolated_ffmpeg = post_runtime["ffmpeg.exe"]
            require(isolated_emule.stat().st_size ==
                        isolated_mod02_expected["emule.exe"][1] and
                    _file_sha256(isolated_emule) ==
                        isolated_mod02_expected["emule.exe"][0] and
                    isolated_ffmpeg.stat().st_size ==
                        isolated_mod02_expected["ffmpeg.exe"][1] and
                    _file_sha256(isolated_ffmpeg) ==
                        isolated_mod02_expected["ffmpeg.exe"][0] and
                    isolated_emule.stat().st_mtime_ns ==
                        mod02_inputs["executable_mtime_ns"] and
                    isolated_ffmpeg.stat().st_mtime_ns ==
                        mod02_inputs["ffmpeg_mtime_ns"] and
                    mod02_inputs["executable"].stat().st_size ==
                        mod02_inputs["executable_bytes"] and
                    mod02_inputs["executable"].stat().st_mtime_ns ==
                        mod02_inputs["executable_mtime_ns"] and
                    _file_sha256(mod02_inputs["executable"]) ==
                        mod02_inputs["executable_sha256"] and
                    mod02_inputs["package_executable"].stat().st_size ==
                        mod02_inputs["executable_bytes"] and
                    _file_sha256(mod02_inputs["package_executable"]) ==
                        mod02_inputs["executable_sha256"] and
                    mod02_inputs["package_ffmpeg"].stat().st_size ==
                        mod02_inputs["ffmpeg_bytes"] and
                    mod02_inputs["package_ffmpeg"].stat().st_mtime_ns ==
                        mod02_inputs["ffmpeg_mtime_ns"] and
                    _file_sha256(mod02_inputs["package_ffmpeg"]) ==
                        immutable["ffmpeg_sha256"],
                    "MOD02 runtime inputs changed")
        require(process.returncode == 0 and len(process.stdout) <= 64 * 1024 * 1024 and
                len(process.stderr) <= 64 * 1024 * 1024,
                "PowerShell gate execution")

    if mod02_inputs is not None:
        require(isolated_mod02_root is not None and
                not os.path.lexists(isolated_mod02_root),
                "isolated MOD02 runtime cleanup")
    require(script_path.read_bytes() == script_raw and
            _file_sha256(powershell) == PINNED_POWERSHELL_SHA256 and
            _audit_node_distribution(node_binding["node"], immutable)["identity_sha256"] ==
            node_binding["identity_sha256"], "PowerShell gate inputs changed")
    if name != "MOD02_RUNTIME":
        require(process.stderr == b"", "PowerShell mock stderr")
        try:
            value = json.loads(process.stdout.decode("utf-8-sig").strip(),
                               object_pairs_hook=_no_duplicates)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GateError("PowerShell mock result") from exc
        expected = _gate_result(name, {}, {}, source_commit, source_tree, "", "")
        require_exact_value(value, expected, "PowerShell mock result identity")
        _assert_external_checkout(REPO, source_commit, source_tree,
                                  "PowerShell gate source changed")
        _assert_project_npm_configs_absent(REPO)
        return value

    require(mod02_inputs is not None, "MOD02 gate state")
    executable = mod02_inputs["executable"]
    build_manifest = mod02_inputs["build_manifest"]
    output_root = mod02_inputs["output_root"]
    executable_sha = mod02_inputs["executable_sha256"]
    manifest_sha = mod02_inputs["manifest_sha256"]
    summary_path = _assert_regular_path(output_root / "summary.json", False,
                                        "MOD02 summary")
    summary_raw = _read_limited(summary_path, 1024 * 1024, "MOD02 summary")
    summary = load_json_bytes(summary_raw, "MOD02 summary")
    exact_keys(summary, [
        "schema", "build_manifest_sha256", "source_commit",
        "source_identity_sha256", "source_tree_clean", "executable_sha256",
        "executable_write_utc", "latest_critical_source_write_utc", "timeout_seconds",
        "timed_out", "taskkill_started", "taskkill_finished", "taskkill_exit_code",
        "termination_confirmed", "exit_code", "expected_markers",
        "observed_markers_sanitized", "markers_verified", "marker_sha256", "verdict",
        "command", "isolation",
    ], "MOD02 summary")
    summary_executable_write = _parse_utc(
        summary["executable_write_utc"], True,
        "MOD02 executable timestamp",
    )
    source_executable_write = datetime.fromtimestamp(
        mod02_inputs["executable_mtime_ns"] / 1_000_000_000,
        tz=timezone.utc,
    )
    require(summary["schema"] == "ese.mod02.stream-selftest/v1" and
            summary["build_manifest_sha256"] == manifest_sha and
            summary["source_commit"] == source_commit and
            summary["source_identity_sha256"] == _import_old_verifier().MOD02_IDENTITY and
            summary["source_tree_clean"] is True and
            summary["executable_sha256"] == executable_sha and
            type(summary["timeout_seconds"]) is int and summary["timeout_seconds"] == 180 and
            summary["timed_out"] is False and summary["termination_confirmed"] is True and
            type(summary["exit_code"]) is int and summary["exit_code"] == 0 and
            summary["markers_verified"] is True and summary["verdict"] == "PASS" and
            summary["command"] == "--portable --ignoreinstances --selftest" and
            summary["isolation"] == "portable unique output root; no UI" and
            abs((summary_executable_write -
                 source_executable_write).total_seconds()) < 0.000002 and
            _file_sha256(executable) == executable_sha and
            _file_sha256(mod02_inputs["package_executable"]) == executable_sha and
            _file_sha256(mod02_inputs["package_ffmpeg"]) ==
                immutable["ffmpeg_sha256"] and
            _read_limited(build_manifest, 1024 * 1024, "MOD02 build manifest") and
            sha256(_read_limited(build_manifest, 1024 * 1024,
                                 "MOD02 build manifest")) == manifest_sha,
            "MOD02 summary identity")
    _assert_external_checkout(REPO, source_commit, source_tree,
                              "MOD02 source changed")
    _assert_project_npm_configs_absent(REPO)
    return {
        "schema": "ese.v92.o01-mod02-gate/v1", "verdict": "PASS",
        "source_commit": source_commit, "source_tree": source_tree,
        "summary_sha256": sha256(summary_raw),
    }


def package_audit(package_root_arg: str, zip_arg: str, node_arg: str,
                  release_tag: str, document: dict[str, Any]) -> dict[str, Any]:
    require(release_tag == RELEASE_TAG, "package audit release tag")
    m_commit = _git_text("rev-parse", "HEAD")
    require(len(_parents(m_commit)) == 1, "package audit M64 parent")
    a_commit = _parents(m_commit)[0]
    a_tree = _git_text("rev-parse", f"{a_commit}^{{tree}}")
    m_tree = _git_text("rev-parse", f"{m_commit}^{{tree}}")
    package_root = _assert_regular_path(Path(package_root_arg), True, "package root")
    build_root = package_root.parents[2]
    expected_package = build_root / "dist" / release_tag / "package"
    require(package_root == expected_package.resolve(strict=True), "package root layout")
    _assert_external_checkout(build_root, a_commit, a_tree,
                              "package build source identity")
    expected, manifest_sha = _audit_package_manifest(package_root)
    actual_hashes = {path: _file_sha256(_assert_regular_path(package_root / PurePosixPath(path),
                                                             False, "package file"))
                     for path in expected}
    require(actual_hashes == expected, "package changed after manifest audit")
    manifest_path = package_root / "SHA256SUMS.txt"
    package_hashes = dict(actual_hashes)
    package_hashes["SHA256SUMS.txt"] = _file_sha256(manifest_path)
    package_sizes = {
        path: _assert_regular_path(package_root / PurePosixPath(path), False,
                                   "package file").stat().st_size
        for path in package_hashes
    }
    require(manifest_sha == package_hashes["SHA256SUMS.txt"], "manifest hash identity")

    manifest = load_json_bytes(
        _blob(m_commit, "docs/architecture/mod02_build_manifest_v1.json"),
        "package audit M64 manifest",
    )
    old = _import_old_verifier()
    exact_keys(manifest, ["schema", "source_commit", "source_identity_sha256",
                          "executable_sha256"], "package audit M64 manifest")
    require(manifest["schema"] == "ese.mod02.build-manifest/v1" and
            manifest["source_commit"] == a_commit and
            manifest["source_identity_sha256"] == old.MOD02_IDENTITY,
            "package audit M64 manifest identity")
    exe_path = _assert_regular_path(package_root / "emule.exe", False, "package executable")
    exe_sha = _file_sha256(exe_path)
    require(exe_sha == manifest["executable_sha256"], "package executable identity")
    immutable = document["immutable_contract"]
    release_inputs, nodes_pin = _release_input_pins(a_commit, immutable)
    receipt_path = f"artifacts/v92-o01-release-build-{a_commit[:8]}/emule-release-build.json"
    receipt_raw = _blob(m_commit, receipt_path)
    receipt = _parse_release_receipt(receipt_raw, a_commit, release_tag,
                                     "package audit receipt")
    receipt_built = _parse_utc(receipt["builtAtUtc"], True, "package receipt timestamp")
    require(receipt["binarySha256"] == exe_sha.upper() and
            receipt["binaryLength"] == exe_path.stat().st_size,
            "package audit receipt identity")
    build_receipt_path = build_root / "tools/build_logs/emule-release-build.json.log"
    build_receipt_raw = _read_limited(
        build_receipt_path, MAX_RELEASE_RECEIPT_BYTES, "fresh build receipt",
    )
    require(build_receipt_raw == receipt_raw, "fresh build/M64 receipt identity")
    build_info_path = _assert_regular_path(package_root / "BUILD_INFO.txt", False,
                                           "BUILD_INFO")
    build_info_raw = _read_limited(build_info_path, MAX_BUILD_INFO_BYTES, "BUILD_INFO")
    build_info = _parse_build_info(build_info_raw)
    build_built = _parse_utc(build_info["built_utc"], False, "BUILD_INFO timestamp")
    require((build_built - receipt_built).total_seconds() >= 0,
            "BUILD_INFO/receipt chronology")
    ffmpeg_path = _assert_regular_path(package_root / "ffmpeg.exe", False,
                                        "package FFmpeg")
    ffprobe_path = _assert_regular_path(package_root / "ffprobe.exe", False,
                                         "package ffprobe")
    require({"ffmpeg.exe", "ffprobe.exe", "config/nodes.dat"} <= set(actual_hashes),
            "package pinned release inputs present")
    require(actual_hashes["ffmpeg.exe"].upper() == release_inputs["ffmpeg"]["sha256"] and
            actual_hashes["ffprobe.exe"].upper() == release_inputs["ffprobe"]["sha256"] and
            actual_hashes["config/nodes.dat"] == nodes_pin,
            "package pinned release input hashes")
    ffmpeg_process = subprocess.run(
        [str(ffmpeg_path), "-version"], check=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=30,
    )
    try:
        ffmpeg_version_line = ffmpeg_process.stdout.decode("utf-8").splitlines()[0]
    except (UnicodeDecodeError, IndexError) as exc:
        raise GateError("package FFmpeg version") from exc
    require_exact_value(build_info, {
        "release": release_tag, "commit": a_commit, "dirty": "false",
        "built_utc": build_info["built_utc"],
        "node": "v" + immutable["node_version"], "npm": immutable["npm_version"],
        "ffmpeg": ffmpeg_version_line,
        "ffmpeg_sha256": actual_hashes["ffmpeg.exe"].upper(),
        "ffprobe_sha256": actual_hashes["ffprobe.exe"].upper(),
        "nodes_dat_sha256": actual_hashes["config/nodes.dat"].upper(),
    }, "BUILD_INFO identity")
    require(build_info["ffmpeg"].startswith(
                "ffmpeg version " + release_inputs["ffmpeg"]["version"] + " "
            ), "package pinned release inputs")
    node_binding = _audit_node_distribution(node_arg, immutable)
    node_path = node_binding["node"]
    node_sha = _file_sha256(node_path)
    node_environment = _without_node_injection_environment()
    node_version_raw = subprocess.run(
        [str(node_path), "--version"], check=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=30, env=node_environment,
    ).stdout.decode("ascii").strip()
    require(node_version_raw == "v" + immutable["node_version"] and
            build_info["node"] == "v" + immutable["node_version"],
            "package audit Node identity")

    zip_path = _assert_regular_path(Path(zip_arg), False, "package ZIP")
    require(zip_path == (build_root / PurePosixPath(PACKAGE_ZIP_PATH)).resolve(strict=True),
            "package ZIP layout")
    zip_sha, zip_bytes, zip_entries = _audit_zip(zip_path, package_hashes, package_sizes)
    sidecar_path = _assert_regular_path(Path(str(zip_path) + ".sha256"), False,
                                        "package ZIP sidecar")
    sidecar_bytes = _read_limited(sidecar_path, MAX_ZIP_SIDECAR_BYTES,
                                  "package ZIP sidecar")
    expected_sidecar = (zip_sha.upper() + "  " + PACKAGE_ZIP_BASENAME + "\r\n").encode("ascii")
    require(sidecar_bytes == expected_sidecar, "package ZIP sidecar content")
    runtime = {
        "node_version": immutable["node_version"], "node_sha256": node_sha,
        "executable_sha256": exe_sha, "build_info_sha256": sha256(build_info_raw),
        "package_manifest_sha256": manifest_sha,
        "package_manifest_entry_count": len(expected),
        "package_file_count": len(expected) + 1,
    }
    build = {
        "release_tag": release_tag, "package_zip_path": PACKAGE_ZIP_PATH,
        "package_zip_sha256": zip_sha, "package_zip_bytes": zip_bytes,
        "package_zip_entry_count": zip_entries,
        "package_zip_sidecar_path": PACKAGE_ZIP_SIDECAR_PATH,
        "package_zip_sidecar_bytes": len(sidecar_bytes),
        "package_zip_sidecar_sha256": sha256(sidecar_bytes),
    }
    _validate_runtime_bindings(runtime, manifest, immutable)
    _validate_build_artifact_bindings(build, runtime)
    final_expected, final_manifest_sha = _audit_package_manifest(package_root)
    require(final_expected == expected and final_manifest_sha == manifest_sha,
            "package changed during audit")
    require(_read_limited(build_info_path, MAX_BUILD_INFO_BYTES, "BUILD_INFO") ==
            build_info_raw and _read_limited(
                build_receipt_path, MAX_RELEASE_RECEIPT_BYTES, "fresh build receipt",
            ) == receipt_raw, "build metadata changed during audit")
    final_node_binding = _audit_node_distribution(node_path, immutable)
    require(canonical({key: final_node_binding[key] for key in (
                "identity_sha256", "file_count", "directory_count",
            )}) == canonical({key: node_binding[key] for key in (
                "identity_sha256", "file_count", "directory_count",
            )}) and _file_sha256(node_path) == node_sha and subprocess.run(
        [str(node_path), "--version"], check=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=30, env=node_environment,
    ).stdout.decode("ascii").strip() == node_version_raw,
            "Node changed during audit")
    sidecar_path = _assert_regular_path(sidecar_path, False, "package ZIP sidecar")
    require(_read_limited(sidecar_path, MAX_ZIP_SIDECAR_BYTES,
                          "package ZIP sidecar") == sidecar_bytes,
            "ZIP sidecar changed during audit")
    zip_path = _assert_regular_path(zip_path, False, "package ZIP")
    require(_file_sha256(zip_path) == zip_sha and zip_path.stat().st_size == zip_bytes,
            "ZIP changed after audit")
    _assert_external_checkout(build_root, a_commit, a_tree,
                              "package source changed during audit")
    zip_path = _assert_regular_path(zip_path, False, "package ZIP")
    require(_file_sha256(zip_path) == zip_sha and zip_path.stat().st_size == zip_bytes,
            "ZIP changed after source audit")
    return _gate_result("PACKAGE_AUDIT", runtime, build, a_commit, a_tree,
                        m_commit, m_tree)


def powershell_parse_gate() -> dict[str, Any]:
    paths = [path for path in A_PATHS if path.endswith((".ps1", ".psm1"))]
    require(len(paths) == 4, "PowerShell parse path count")
    source_commit = _git_text("rev-parse", "HEAD")
    source_tree = _git_text("rev-parse", "HEAD^{tree}")
    _assert_external_checkout(REPO, source_commit, source_tree,
                              "PowerShell parse source")
    source_bytes = {
        path: _read_limited(REPO / PurePosixPath(path), 2 * 1024 * 1024,
                            "PowerShell parse input")
        for path in paths
    }
    quoted = ",".join("'" + path.replace("'", "''") + "'" for path in paths)
    script = (
        "$ErrorActionPreference='Stop';$env:PSModulePath='C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\Modules';$paths=@(" + quoted + ");"
        "foreach($p in $paths){$tokens=$null;$errors=$null;"
        "[void][Management.Automation.Language.Parser]::ParseFile((Resolve-Path -LiteralPath $p).Path,[ref]$tokens,[ref]$errors);"
        "if($errors.Count-ne0){throw 'O01_POWERSHELL_PARSE'}};"
        "[pscustomobject][ordered]@{schema='ese.v92.o01-powershell-parse/v1';verdict='PASS';"
        "powershell_version=($PSVersionTable.PSVersion.Major.ToString()+'.'+$PSVersionTable.PSVersion.Minor.ToString());"
        "edition=[string]$PSVersionTable.PSEdition;parsed_paths=$paths.Count}|ConvertTo-Json -Compress"
    )
    powershell = _assert_regular_path(
        Path(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
        False, "trusted Windows PowerShell",
    )
    require(_file_sha256(powershell) == PINNED_POWERSHELL_SHA256,
            "trusted Windows PowerShell identity")
    environment = _closed_git_environment()
    for key in list(environment):
        upper = key.upper()
        if (upper.startswith("COR_") or upper.startswith("COMPLUS_") or
                upper.startswith("DOTNET_") or upper in {
                    "PSMODULEPATH", "PATH", "PATHEXT", "COMSPEC", "SYSTEMROOT",
                }):
            del environment[key]
    _set_environment_value_ci(environment, "SystemRoot", r"C:\Windows")
    _set_environment_value_ci(environment, "COMSPEC", r"C:\Windows\System32\cmd.exe")
    _set_environment_value_ci(environment, "PATH", r"C:\Windows\System32")
    _set_environment_value_ci(environment, "PATHEXT", ".COM;.EXE;.BAT;.CMD")
    _set_environment_value_ci(
        environment, "PSModulePath",
        r"C:\Windows\System32\WindowsPowerShell\v1.0\Modules",
    )
    output = subprocess.run(
        [str(powershell), "-NoLogo", "-NoProfile", "-Command", script], cwd=REPO,
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120,
        env=environment,
    )
    try:
        value = json.loads(output.stdout.decode("utf-8-sig").strip(),
                           object_pairs_hook=_no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GateError("PowerShell parse result") from exc
    expected = _gate_result("POWERSHELL_PARSE", {}, {}, "", "", "", "")
    require_exact_value(value, expected, "PowerShell parse result identity")
    require(all(
        _read_limited(REPO / PurePosixPath(path), 2 * 1024 * 1024,
                      "PowerShell parse input") == raw
        for path, raw in source_bytes.items()
    ) and _file_sha256(powershell) == PINNED_POWERSHELL_SHA256,
            "PowerShell parse inputs changed")
    _assert_external_checkout(REPO, source_commit, source_tree,
                              "PowerShell parse source changed")
    return value


def diff_check_gate() -> dict[str, Any]:
    source_commit = _git_text("rev-parse", "HEAD")
    source_tree = _git_text("rev-parse", "HEAD^{tree}")
    _assert_external_checkout(REPO, source_commit, source_tree,
                              "diff-check source")
    process = subprocess.run(
        _git_command(REPO, "diff", "--check", "--no-ext-diff",
                     f"{BASE['h63_commit']}..{source_commit}", "--"),
        cwd=REPO, env=_closed_git_environment(), check=False,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120,
    )
    require(process.returncode == 0 and process.stdout == b"" and
            process.stderr == b"", "diff-check result")
    _assert_external_checkout(REPO, source_commit, source_tree,
                              "diff-check source changed")
    return _gate_result("DIFF_CHECK", {}, {}, "", "", "", "")


def result(mode: str, state: str) -> dict[str, Any]:
    return {
        "schema": "ese.v92.o01-rpc-failure-governance-verifier/v1",
        "verdict": "PASS",
        "mode": mode,
        "state": state,
        "base_h_commit": BASE["h63_commit"],
        "diagnostic_attempt": "a163",
        "diagnostic_release_gate": False,
        "a64_freeze": "FROZEN_EXACT13",
        "a64_paths": BUDGET[0],
        "a64_add": BUDGET[1],
        "a64_delete": BUDGET[2],
        "a64_net": BUDGET[3],
        "rpc_tuple_slots": 158,
    }


def _run_formal_gate_and_emit(args: argparse.Namespace,
                              document: dict[str, Any],
                              immutable: dict[str, Any]) -> int:
    evidence_root = Path(args.evidence_root)
    pass_ownership: dict[str, Any] = {}
    with _invalidate_formal_pass_on_failure(evidence_root, pass_ownership), \
            ExitStack() as guard_stack:
        (gate_output, launch_receipt, input_snapshot,
         returned_ownership, guard_state) = formal_run_gate(
            args.h_commit, args.evidence_root, args.package_root,
            args.node, args.credential_path, document, guard_stack,
            pass_ownership,
        )
        require(returned_ownership is pass_ownership and
                pass_ownership.get("claimed") is True,
                "formal PASS ownership final")
        controller = guard_state["controller"]
        evidence_guard = guard_state["evidence_guard"]
        metadata_guard = guard_state["metadata_guard"]
        cache = guard_state["cache"]
        root_metadata = _formal_evidence_root_metadata(
            evidence_root, metadata_guard,
        )
        require(root_metadata == guard_state["root_metadata"] ==
                input_snapshot["root_metadata"],
                "formal evidence root metadata epoch")
        exact_keys(launch_receipt, FORMAL_LAUNCH_RECEIPT_KEYS,
                   "formal launch receipt final")
        require_exact_value(
            launch_receipt,
            _expected_formal_launch_receipt(
                cache, root_metadata, launch_receipt["source_commit"],
                launch_receipt["source_tree"],
                launch_receipt["governance_h_commit"],
            ),
            "formal launch receipt final",
        )
        require(
            _formal_path_identity(evidence_root, True) ==
                pass_ownership["root"] and
            _formal_path_identity(controller, True) ==
                pass_ownership["controller"] and
            all(_formal_path_identity(controller / name, False) ==
                pass_ownership[name] for name in (
                    "formal-run-result.json", "formal-validation.json",
                )),
            "formal PASS ownership changed",
        )
        _assert_python_runtime(immutable)
        _assert_formal_launch_inputs_unchanged(input_snapshot)
        _assert_formal_evidence_guard_unchanged(
            controller, evidence_guard, cache,
        )
        require(_formal_evidence_root_metadata(
                    evidence_root, metadata_guard,
                ) == root_metadata,
                "formal evidence root metadata final")
        gate_bytes = (
            json.dumps(gate_output, sort_keys=True,
                       separators=(",", ":")).encode("ascii") + b"\n"
        )
        sys.stdout.buffer.write(gate_bytes)
        sys.stdout.buffer.flush()
    return 0


def main(argv: list[str] | None = None) -> int:
    mode = "ARGUMENTS"
    try:
        raw_argv = list(sys.argv[1:] if argv is None else argv)
        parser = GateArgumentParser(allow_abbrev=False)
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument("--document", action="store_true")
        group.add_argument("--check-worktree", action="store_true")
        group.add_argument("--verify", action="store_true")
        group.add_argument("--package-audit", action="store_true")
        group.add_argument("--powershell-parse", action="store_true")
        group.add_argument("--diff-check", action="store_true")
        group.add_argument("--build-all", action="store_true")
        group.add_argument("--node-tests", choices=("FULL", "FOCAL"))
        group.add_argument("--formal-run", action="store_true")
        group.add_argument("--powershell-gate", choices=(
            "MOD02_RUNTIME", "RPC_PUMP_MOCK", "FORMAL_RUNNER_MOCK",
            "VM_SESSION_MOCK", "FORMAL_PRODUCT_MOCK",
        ))
        parser.add_argument("--package-root")
        parser.add_argument("--zip")
        parser.add_argument("--node")
        parser.add_argument("--pkg-node")
        parser.add_argument("--ffmpeg")
        parser.add_argument("--release-tag")
        parser.add_argument("--executable")
        parser.add_argument("--output-root")
        parser.add_argument("--build-manifest")
        parser.add_argument("--timeout-seconds", type=int)
        parser.add_argument("--h-commit")
        parser.add_argument("--evidence-root")
        parser.add_argument("--credential-path")
        args = parser.parse_args(raw_argv)
        if args.formal_run:
            require(raw_argv == [
                "--formal-run", "--h-commit", args.h_commit,
                "--evidence-root", args.evidence_root,
                "--package-root", args.package_root,
                "--node", args.node,
                "--credential-path", args.credential_path,
            ], "formal run command-line contract")
        if args.document:
            mode = "DOCUMENT"
        elif args.check_worktree:
            mode = "CHECK_WORKTREE"
        elif args.verify:
            mode = "VERIFY"
        elif args.package_audit:
            mode = "PACKAGE_AUDIT"
        elif args.powershell_parse:
            mode = "POWERSHELL_PARSE"
        elif args.diff_check:
            mode = "DIFF_CHECK"
        elif args.build_all:
            mode = "BUILD_ALL"
        elif args.formal_run:
            mode = "FORMAL_RUN"
        elif args.powershell_gate:
            mode = args.powershell_gate
        else:
            mode = "NODE_TESTS_" + args.node_tests
        document, raw = load_json(DOCUMENT)
        validate_document(document)
        require(sha256(raw) == DOCUMENT_SHA256, "sealed document byte identity")
        verify_governance_tool_identity(document, lambda path: (REPO / path).read_bytes())
        verify_history(document)
        immutable = document["immutable_contract"]
        _assert_python_runtime(immutable)
        require(sys.flags.isolated == 1 and sys.flags.no_site == 1 and
                sys.flags.ignore_environment == 1 and sys.flags.safe_path == 1 and
                sys.flags.dont_write_bytecode == 1, "isolated Python invocation")
        optional_values = {
            "package_root": args.package_root, "zip": args.zip, "node": args.node,
            "pkg_node": args.pkg_node, "ffmpeg": args.ffmpeg,
            "release_tag": args.release_tag,
            "executable": args.executable, "output_root": args.output_root,
            "build_manifest": args.build_manifest,
            "timeout_seconds": args.timeout_seconds,
            "h_commit": args.h_commit, "evidence_root": args.evidence_root,
            "credential_path": args.credential_path,
        }
        if (args.package_audit or args.powershell_parse or args.diff_check or args.build_all or
                args.node_tests or args.powershell_gate or args.formal_run):
            gate_commit = _git_text("rev-parse", "HEAD")
            gate_tree = _git_text("rev-parse", "HEAD^{tree}")
            _assert_external_checkout(REPO, gate_commit, gate_tree, "gate worktree dirty")
            state = autodetect(document)
            if args.package_audit:
                require(state == "M64", "package audit requires clean M64")
                require(all(isinstance(value, str) and value for value in (
                    args.package_root, args.zip, args.node, args.release_tag,
                )) and all(optional_values[key] is None for key in (
                    "pkg_node", "ffmpeg", "executable", "output_root",
                    "build_manifest", "timeout_seconds", "h_commit",
                    "evidence_root", "credential_path",
                )),
                        "package audit arguments")
                gate_output = package_audit(
                    args.package_root, args.zip, args.node, args.release_tag, document,
                )
            elif args.powershell_parse:
                require(state == "M64" and all(value is None for value in
                                                optional_values.values()),
                        "PowerShell parse arguments")
                gate_output = powershell_parse_gate()
            elif args.diff_check:
                require(state == "M64" and all(value is None for value in
                                                optional_values.values()),
                        "diff-check arguments")
                gate_output = diff_check_gate()
            elif args.build_all:
                require(state == "A64" and all(isinstance(value, str) and value for value in (
                    args.node, args.pkg_node, args.ffmpeg, args.release_tag,
                )) and all(optional_values[key] is None for key in (
                    "package_root", "zip", "executable", "output_root",
                    "build_manifest", "timeout_seconds", "h_commit",
                    "evidence_root", "credential_path",
                )),
                        "official build arguments")
                gate_output = build_all_gate(
                    args.node, args.ffmpeg, args.pkg_node, args.release_tag, document,
                )
            elif args.formal_run:
                require(state == "A64" and all(
                    isinstance(value, str) and value for value in (
                        args.h_commit, args.evidence_root, args.package_root,
                        args.node, args.credential_path,
                    )
                ) and all(optional_values[key] is None for key in (
                    "zip", "pkg_node", "ffmpeg", "release_tag", "executable",
                    "output_root", "build_manifest", "timeout_seconds",
                )), "formal run arguments")
                return _run_formal_gate_and_emit(args, document, immutable)
            elif args.powershell_gate:
                common_unused = ("package_root", "zip", "pkg_node", "ffmpeg",
                                 "release_tag", "h_commit", "evidence_root",
                                 "credential_path")
                require(isinstance(args.node, str) and args.node and
                        all(optional_values[key] is None for key in common_unused),
                        "PowerShell gate common arguments")
                if args.powershell_gate == "MOD02_RUNTIME":
                    require(state == "A64" and all(
                        isinstance(value, str) and value for value in (
                            args.executable, args.output_root, args.build_manifest,
                        )
                    ) and type(args.timeout_seconds) is int and
                            args.timeout_seconds == 180,
                            "MOD02 PowerShell gate arguments")
                else:
                    require(state == "M64" and all(optional_values[key] is None for key in (
                        "executable", "output_root", "build_manifest", "timeout_seconds",
                    )), "mock PowerShell gate arguments")
                gate_output = powershell_gate(
                    args.powershell_gate, args.node, document,
                    executable_arg=args.executable, output_root_arg=args.output_root,
                    build_manifest_arg=args.build_manifest,
                    timeout_seconds=args.timeout_seconds,
                )
            else:
                require(state == "A64" and isinstance(args.node, str) and args.node and
                        all(optional_values[key] is None for key in (
                            "package_root", "zip", "pkg_node", "ffmpeg", "release_tag",
                            "executable", "output_root", "build_manifest", "timeout_seconds",
                            "h_commit", "evidence_root", "credential_path",
                        )), "Node test arguments")
                gate_output = node_test_gate(args.node_tests, args.node, document)
            gate_bytes = (
                json.dumps(gate_output, sort_keys=True,
                           separators=(",", ":")).encode("ascii") + b"\n"
            )
            _assert_python_runtime(immutable)
            sys.stdout.buffer.write(gate_bytes)
            sys.stdout.buffer.flush()
            return 0
        require(all(value is None for value in optional_values.values()),
                "unused command-line arguments")
        if args.check_worktree:
            verify_check_worktree(document, raw)
            state = "SEALED_WORKTREE"
        elif args.verify:
            verification_commit = _git_text("rev-parse", "HEAD")
            verification_tree = _git_text("rev-parse", "HEAD^{tree}")
            _assert_external_checkout(REPO, verification_commit, verification_tree,
                                      "verification worktree dirty")
            state = autodetect(document)
            _assert_external_checkout(REPO, verification_commit, verification_tree,
                                      "verification source changed")
        else:
            state = "DOCUMENT"
        sys.stdout.buffer.write(
            json.dumps(result(mode, state), sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
        )
        return 0
    except Exception as exc:
        reason = str(exc) if isinstance(exc, GateError) else type(exc).__name__
        failure = {
            "schema": "ese.v92.o01-rpc-failure-governance-verifier/v1",
            "verdict": "FAIL", "mode": mode, "release_gate": False,
            "code": "O01_G12_SEALED_GATE_FAILED", "reason": reason,
        }
        sys.stdout.buffer.write(
            json.dumps(failure, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
