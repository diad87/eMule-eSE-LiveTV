#!/usr/bin/env python3
"""Check that reserved server namespaces reject duplicate and drifting rows."""

import importlib.util
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("check_protocol_registry",
                                              ROOT / "tools" / "check_protocol_registry.py")
REGISTRY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REGISTRY)


class RegistryTest(unittest.TestCase):
    def test_vector_manifests(self):
        for folder, scenario in {"frame": "DS-03", "auth": "DS-09"}.items():
            with self.subTest(scenario=scenario):
                directory = ROOT / "tests" / "fixtures" / "server_interop" / folder
                manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
                self.assertEqual(scenario, manifest["case_id"])
                self.assertEqual({path.name for path in directory.glob("*.hex")}, set(manifest["sha256"]))
                for name, digest in manifest["sha256"].items():
                    self.assertEqual(digest, hashlib.sha256(bytes.fromhex((directory / name).read_text())).hexdigest())

    def run_checker(self, directory):
        output = StringIO()
        with patch.object(REGISTRY, "PROTO", directory), redirect_stdout(output):
            result = REGISTRY.main()
        return result, output.getvalue()

    def test_server_namespace_duplicate_is_rejected(self):
        with tempfile.TemporaryDirectory() as scratch:
            directory = Path(scratch)
            for name in REGISTRY.REGISTRY_FILES:
                shutil.copyfile(ROOT / "docs" / "protocol" / name, directory / name)
            self.assertEqual(0, self.run_checker(directory)[0])
            path = directory / "SERVER_MESSAGES.csv"
            original = path.read_text(encoding="utf-8")
            row = next(line for line in original.splitlines() if line.startswith("kEseWireServerPing,"))
            path.write_text(original + row.replace("kEseWireServerPing", "DuplicatePing", 1) + "\n",
                            encoding="utf-8")
            result, message = self.run_checker(directory)
            self.assertEqual(1, result)
            self.assertIn("DUPLICATE VALUE  ESE-SERVER/1 0x00FE", message)

            path.write_text(original.replace("kEseWireServerPing,number,0x00FE",
                                             "kEseWireServerPing,number,0x0100", 1),
                            encoding="utf-8")
            result, message = self.run_checker(directory)
            self.assertEqual(1, result)
            self.assertIn("DRIFT          kEseWireServerPing", message)


if __name__ == "__main__":
    unittest.main()
