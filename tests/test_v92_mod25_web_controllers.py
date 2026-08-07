"""MOD-2.5 typed Web controller extraction and integration contract."""

from __future__ import annotations

import json
import pathlib
import unittest
import xml.etree.ElementTree as ET


ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVER = ROOT / "srchybrid" / "WebServer.cpp"
TRANSFER_PROJECTION = ROOT / "srchybrid" / "WebTransferProjection.cpp"
PROJECT = ROOT / "srchybrid" / "emule.vcxproj"
MAKE = ROOT / "srchybrid" / "tests" / "make.bat"
NATIVE = ROOT / "srchybrid" / "tests" / "test_web_controllers.cpp"
CONTRACT = (
    ROOT / "docs" / "architecture" / "mod25_web_controllers_contract_v1.json"
)
MODULES = (
    "WebTransferController",
    "WebSearchController",
    "WebSharedController",
)


class Mod25WebControllersTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = SERVER.read_text(encoding="utf-8")
        cls.transfer_projection = TRANSFER_PROJECTION.read_text(encoding="utf-8")
        cls.make = MAKE.read_text(encoding="utf-8")
        cls.native = NATIVE.read_text(encoding="utf-8")
        cls.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        cls.sources = {
            name: (
                (ROOT / "srchybrid" / f"{name}.h").read_text(encoding="utf-8")
                + (ROOT / "srchybrid" / f"{name}.cpp").read_text(
                    encoding="utf-8"
                )
            )
            for name in MODULES
        }

    def test_modules_are_portable_typed_application_policies(self) -> None:
        for name, source in self.sources.items():
            for forbidden in (
                "stdafx.h",
                "WebServer.h",
                "CString",
                "windows.h",
                "theApp",
                "thePrefs",
                "SendMessage",
                "new ",
                "delete ",
            ):
                self.assertNotIn(forbidden, source, f"{name}: {forbidden}")
            self.assertIn(f"class {name}", source)
        self.assertIn("enum class WebTransferFileOperation", self.sources[
            "WebTransferController"
        ])
        self.assertIn("struct WebSearchRequest", self.sources[
            "WebSearchController"
        ])
        self.assertIn("enum class WebSharedPriority", self.sources[
            "WebSharedController"
        ])

    def test_every_controller_is_used_by_the_mfc_adapter(self) -> None:
        for header in MODULES:
            self.assertIn(f'#include "{header}.h"', self.server)
        for marker in (
            "RunWebTransferActions",
            "WebSearchController::PlanSearch",
            "WebSearchController::PlanDownloads",
            "WebSearchController::PlanColumnChange",
            "WebSearchController::PlanSort",
            "WebSearchController::ProjectResult",
            "WebSharedController::PlanSort",
            "WebSharedController::PlanPriority",
            "WebSharedController::PlanColumnChange",
            "WebSharedController::PlanReload",
            "WebSharedController::Compare",
            "WebSharedController::ProjectRow",
        ):
            self.assertIn(marker, self.server)
        # W4 owns rendering-time projection and sorting now.  Preserve the
        # MOD-2.5 comparison boundary at the final adapter instead of requiring
        # the superseded direct CWebServer call.
        for marker in ("int CompareDownload(", "int CompareUpload("):
            self.assertIn(marker, self.transfer_projection)
        self.assertIn("M2A_BIND_W4_AD763A5EE0", self.server)
        for obsolete in (
            "WSdownloadColumnHidden[iMenu]",
            "WSuploadColumnHidden[iMenu]",
            "WSqueueColumnHidden[iMenu]",
            "WSsearchColumnHidden[iMenu]",
            "WSsharedColumnHidden[iMenu]",
        ):
            self.assertNotIn(obsolete, self.server)

    def test_hostile_input_is_fail_closed_in_production_modules(self) -> None:
        combined = "".join(self.sources.values())
        for marker in (
            "parsedIndex >= limit",
            "parsedIndex >= 4",
            "parsedIndex >= 7",
            "available > 1000000u",
            "std::numeric_limits<std::uint64_t>::max() / 1048576u",
            "IsMd4Hex",
            "WebTransferFileOperation::None",
            "WebSharedPriority::None",
        ):
            self.assertIn(marker, combined)

    def test_native_vectors_cover_all_controller_boundaries(self) -> None:
        for marker in (
            "non-admin transfer mutation must fail closed",
            "every out-of-range transfer column must fail closed",
            "search size multiplication overflow must fail closed",
            "search downloads must retain only exact MD4 hex hashes",
            "search result source buckets must preserve every threshold",
            "shared priority must require admin and reject unknown values",
            "shared column bounds must be exact",
        ):
            self.assertIn(marker, self.native)

    def test_release_and_standalone_gates_compile_all_modules(self) -> None:
        namespace = {"m": "http://schemas.microsoft.com/developer/msbuild/2003"}
        project = ET.parse(PROJECT)
        for name in MODULES:
            compile_entry = project.find(
                f".//m:ClCompile[@Include='{name}.cpp']",
                namespace,
            )
            self.assertIsNotNone(compile_entry)
            self.assertEqual(
                compile_entry.findtext(
                    "m:PrecompiledHeader", namespaces=namespace
                ),
                "NotUsing",
            )
            self.assertEqual(
                compile_entry.findtext(
                    "m:TreatWarningAsError", namespaces=namespace
                ),
                "true",
            )
            self.assertIsNotNone(
                project.find(
                    f".//m:ClInclude[@Include='{name}.h']",
                    namespace,
                )
            )
            self.assertIn(f"{name}.cpp", self.make)
        self.assertIn("test_web_controllers.cpp", self.make)

    def test_contract_boundary_matches_implemented_ownership(self) -> None:
        self.assertEqual(
            [module["name"] for module in self.contract["modules"]],
            list(MODULES),
        )
        self.assertEqual(
            self.contract["boundary"]["owned_by_controllers"],
            [
                "request-to-action decisions",
                "sort and projection policy",
                "bounded hostile-input validation",
            ],
        )
        self.assertEqual(
            self.contract["modules"][1]["file_types"],
            [
                "Arc",
                "Audio",
                "Iso",
                "Doc",
                "Image",
                "Pro",
                "Video",
                "EmuleCollection",
            ],
        )


if __name__ == "__main__":
    unittest.main()
