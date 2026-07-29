"""MOD-1.2 host contract for LiveTunnel pending-state ownership."""

from __future__ import annotations

import pathlib
import re
import unittest
import xml.etree.ElementTree as ET


ROOT = pathlib.Path(__file__).resolve().parents[1]
HEADER = ROOT / "srchybrid" / "LiveTunnelPending.h"
SOURCE = ROOT / "srchybrid" / "LiveTunnelPending.cpp"
TUNNEL_HEADER = ROOT / "srchybrid" / "LiveTunnel.h"
TUNNEL_SOURCE = ROOT / "srchybrid" / "LiveTunnel.cpp"
NATIVE_TEST = ROOT / "srchybrid" / "tests" / "test_live_tunnel_pending.cpp"
PROJECT = ROOT / "srchybrid" / "emule.vcxproj"
MAKE = ROOT / "srchybrid" / "tests" / "make.bat"


class Mod12LiveTunnelPendingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.header = HEADER.read_text(encoding="utf-8")
        cls.source = SOURCE.read_text(encoding="utf-8")
        cls.tunnel_header = TUNNEL_HEADER.read_text(encoding="utf-8")
        cls.tunnel_source = TUNNEL_SOURCE.read_text(encoding="utf-8")
        cls.native = NATIVE_TEST.read_text(encoding="utf-8")

    def test_public_contract_is_portable_narrow_and_planned_size(self) -> None:
        includes = set(re.findall(
            r'#\s*include\s*[<"]([^>"]+)[>"]',
            self.header,
        ))
        self.assertEqual(includes, {
            "cstddef",
            "cstdint",
            "functional",
            "memory",
            "set",
            "vector",
        })
        forbidden = (
            "LiveTunnel.h",
            "LiveCircuit.h",
            "Kad",
            "Socket",
            "windows.h",
            "afx",
            "HANDLE",
            "CCriticalSection",
            "CSingleLock",
        )
        for token in forbidden:
            self.assertNotIn(token, self.header)
        module_loc = len(self.header.splitlines()) + len(self.source.splitlines())
        self.assertGreaterEqual(module_loc, 300)
        self.assertLessEqual(module_loc, 1200)

    def test_module_owns_records_waits_retries_and_exact_completion(self) -> None:
        for required in (
            "struct LiveTunnelPending::Entry",
            "std::condition_variable changed",
            "std::map<std::uint32_t, std::shared_ptr<Entry>> requests",
            "LiveTunnelPending::Register",
            "LiveTunnelPending::Configure",
            "LiveTunnelPending::SetCircuit",
            "LiveTunnelPending::Complete",
            "LiveTunnelPending::Wait",
            "LiveTunnelPending::CollectRetries",
        ):
            self.assertIn(required, self.source)
        self.assertIn("completed->terminal = true;", self.source)
        self.assertIn("completed->changed.notify_all();", self.source)
        self.assertLess(
            self.source.index("completed->terminal = true;"),
            self.source.index("completed->changed.notify_all();"),
        )

    def test_coordinator_has_no_pending_record_or_event_ownership(self) -> None:
        combined = self.tunnel_header + self.tunnel_source
        for forbidden in (
            "struct PendingRequest",
            "PendingRequest*",
            "m_pending;",
            "CreateEvent(",
            "WaitForSingleObject(",
            "CloseHandle(",
            "SetEvent(",
        ):
            self.assertNotIn(forbidden, combined)
        self.assertIn("LiveTunnelPending m_pendingRequests;", self.tunnel_header)
        self.assertEqual(self.tunnel_source.count("m_pendingRequests.Configure("), 9)
        self.assertIn("m_pendingRequests.SetCircuit(req.reqId, cid);", self.tunnel_source)

    def test_tick_uses_registry_snapshot_then_publishes_outside_pending(self) -> None:
        tick = self.tunnel_source[self.tunnel_source.index("void CLiveTunnel::Tick()"):]
        start = tick.index("// 5. v8.1 A4")
        end = tick.index("// 6. v8.1 A6")
        retry_slice = tick[start:end]
        self.assertIn("std::set<uint32_t> activeCircuitIds;", retry_slice)
        collect = retry_slice.index("m_pendingRequests.CollectRetries(activeCircuitIds)")
        queue_lock = retry_slice.index("CSingleLock lk(&m_mtLock, TRUE)")
        self.assertLess(collect, queue_lock)
        self.assertNotIn("m_pendingLock", retry_slice)
        self.assertNotIn("[&]", retry_slice)

    def test_native_tests_cover_deadline_retry_late_and_exactly_once(self) -> None:
        for required in (
            "registration rejects zero id",
            "registration rejects collision",
            "timeout unregisters request",
            "late completion is ignored",
            "active circuit is not retried",
            "retry action is an exact immutable snapshot",
            "retry exhaustion completes as failure",
            "completed request never retries",
            "fast completion preserves later circuit bookkeeping",
            "concurrent completion has exactly one winner",
            "consumed waiter handle cannot be reused",
            "a pending handle must have exactly one waiter owner",
        ):
            self.assertIn(required, self.native)
        self.assertNotIn("Sleep(", self.native)
        self.assertNotRegex(self.native, r"(?<!static_)assert\(")

    def test_project_and_standalone_gate_compile_the_module_strictly(self) -> None:
        tree = ET.parse(PROJECT)
        namespace = {"m": "http://schemas.microsoft.com/developer/msbuild/2003"}
        items = tree.findall(
            ".//m:ClCompile[@Include='LiveTunnelPending.cpp']",
            namespace,
        )
        self.assertEqual(len(items), 1)
        item = items[0]
        self.assertEqual(
            item.findtext("m:PrecompiledHeader", namespaces=namespace),
            "NotUsing",
        )
        self.assertEqual(
            item.findtext("m:LanguageStandard", namespaces=namespace),
            "stdcpp17",
        )
        self.assertEqual(
            item.findtext("m:WarningLevel", namespaces=namespace),
            "Level4",
        )
        self.assertEqual(
            item.findtext("m:TreatWarningAsError", namespaces=namespace),
            "true",
        )
        headers = tree.findall(
            ".//m:ClInclude[@Include='LiveTunnelPending.h']",
            namespace,
        )
        self.assertEqual(len(headers), 1)

        make = MAKE.read_text(encoding="utf-8")
        compile_line = next(
            line for line in make.splitlines()
            if "test_live_tunnel_pending.exe" in line
            and line.lstrip().startswith("cl ")
        )
        self.assertIn("/W4 /WX /std:c++17", compile_line)
        self.assertIn("tests\\test_live_tunnel_pending.cpp", compile_line)
        self.assertIn("LiveTunnelPending.cpp", compile_line)


if __name__ == "__main__":
    unittest.main(verbosity=2)
