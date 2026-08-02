"""M2A-00.4 portable composition and callback-order characterization."""
from __future__ import annotations

import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
HEADER = ROOT / "srchybrid" / "M2ABindingPort.h"
SOURCE = ROOT / "srchybrid" / "M2ABindingPort.cpp"
SCHEDULER = ROOT / "srchybrid" / "LiveTunnelScheduler.cpp"
PROJECT = ROOT / "srchybrid" / "emule.vcxproj"


class M2APortContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.header = HEADER.read_text(encoding="utf-8")
        cls.source = SOURCE.read_text(encoding="utf-8")
        cls.scheduler = SCHEDULER.read_text(encoding="utf-8")
        cls.project = PROJECT.read_text(encoding="utf-8")

    def test_parent_port_is_opaque_and_immutable(self) -> None:
        self.assertIn("struct M2AParentPort final", self.header)
        self.assertIn("void* const context", self.header)
        for concrete in (
            "CWebServer", "CLiveTunnel", "CLiveStreamManager",
            "CUpDownClient", "CKademlia", "SOCKET", "HWND",
        ):
            self.assertNotIn(concrete, self.header)

    def test_module_handle_has_one_move_only_owner(self) -> None:
        self.assertIn(
            "M2AModuleHandle(const M2AModuleHandle&) = delete",
            self.header,
        )
        self.assertIn(
            "M2AModuleHandle& operator=(const M2AModuleHandle&) = delete",
            self.header,
        )
        self.assertIn("M2AModuleHandle(M2AModuleHandle&& other)", self.header)
        self.assertIn("void Reset() noexcept", self.header)
        self.assertIn(
            "MakeM2AModuleHandle(new DestructionProbe(destroyed))",
            self.source,
        )
        self.assertIn("second.Reset()", self.source)

    def test_callback_characterization_unlocks_before_invocation(self) -> None:
        start = self.source.index("bool CharacterizeCallbackAfterUnlock()")
        end = self.source.index("\n}\n", start)
        body = self.source[start:end]
        lock_scope = body.index("std::lock_guard<std::mutex>")
        callback = body.index("return callback(snapshot)")
        self.assertLess(lock_scope, callback)
        self.assertIn("if (!mutex.try_lock())", body)
        self.assertIn("mutex.unlock()", body)
        # The lock guard is inside its own completed scope before callback.
        self.assertIn("    }\n    return callback(snapshot)", body)

    def test_characterization_is_compiled_and_on_headless_selftest_path(
        self,
    ) -> None:
        self.assertIn(
            '<ClCompile Include="M2ABindingPort.cpp">', self.project
        )
        self.assertIn(
            '<ClInclude Include="M2ABindingPort.h" />', self.project
        )
        self.assertIn(
            '#include "M2ABindingPort.h"', self.scheduler
        )
        self.assertIn(
            "&& RunM2ABindingPortCharacterizationSelfTest()",
            self.scheduler,
        )

    def test_public_port_header_has_no_pch_or_reverse_include(self) -> None:
        for include in (
            "stdafx.h", "pch.h", "LiveTunnel.h", "WebServer.h",
            "LiveStreamManager.h",
        ):
            self.assertNotIn(f'#include "{include}"', self.header)


if __name__ == "__main__":
    unittest.main(verbosity=2)
