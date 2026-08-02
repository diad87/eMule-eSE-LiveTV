#!/usr/bin/env python3
"""Unattended product gate for V9.2 L08 WebServer privacy."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class L08WebServerPrivacyContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        def read(relative: str) -> str:
            return (ROOT / relative).read_text(encoding="utf-8")

        cls.preferences_h = read("srchybrid/Preferences.h")
        cls.preferences = read("srchybrid/Preferences.cpp")
        cls.page = read("srchybrid/PPgWebServer.cpp")
        cls.base = read("srchybrid/UPnPImpl.cpp")
        cls.dialog = read("srchybrid/EmuleDlg.cpp")
        cls.websocket = read("srchybrid/WebSocket.cpp")
        cls.backends = {
            name: read(name)
            for name in (
                "srchybrid/UPnPImplMiniLib.cpp",
                "srchybrid/UPnPImplPCP.cpp",
                "srchybrid/UPnPImplNATPMP.cpp",
                "srchybrid/UPnPImplWinServ.cpp",
            )
        }
        cls.wp0 = read("tools/lab/test_t8_wp0.ps1")
        cls.runtime_gate = read(
            "tests/test_v92_l08_privacy_runtime.ps1"
        )

    def test_public_preference_can_never_request_web_mapping(self) -> None:
        getter = self.preferences_h[
            self.preferences_h.index("static bool\t\tGetWSUseUPnP()") :
            self.preferences_h.index(
                "static bool\t\tGetWSIsEnabled()"
            )
        ]
        self.assertIn("return false;", getter)
        self.assertIn(
            'm_bWebUseUPnP = false;', self.preferences
        )
        self.assertIn(
            'ini.WriteBool(_T("WebUseUPnP"), false);', self.preferences
        )

    def test_initial_mapping_entrypoint_always_passes_zero_web_port(self) -> None:
        start = self.dialog[
            self.dialog.index("impl->StartDiscovery(") :
            self.dialog.index(");", self.dialog.index("impl->StartDiscovery("))
            + 2
        ]
        self.assertRegex(start, r",\s*0\);")
        self.assertNotIn("GetWSPort", start)
        self.assertNotIn("GetWSUseUPnP", start)

    def test_preferences_ui_cannot_reenable_or_late_map(self) -> None:
        self.assertIn(
            "CheckDlgButton(IDC_WSUPNP, BST_UNCHECKED);", self.page
        )
        self.assertIn(
            "GetDlgItem(IDC_WSUPNP)->EnableWindow(FALSE);", self.page
        )
        apply = self.page[
            self.page.index("BOOL CPPgWebServer::OnApply()") :
            self.page.index("void CPPgWebServer::Localize()")
        ]
        self.assertIn("thePrefs.m_bWebUseUPnP = false;", apply)
        self.assertNotIn("LateEnableWebServerPort", apply)

    def test_late_enable_api_is_fail_closed(self) -> None:
        late = self.base[
            self.base.index("void CUPnPImpl::LateEnableWebServerPort(") :
            self.base.index("void CUPnPImpl::RecordLeaseSuccess()")
        ]
        self.assertIn("UNREFERENCED_PARAMETER(nPort);", late)
        self.assertIn("m_nTCPWebPort = 0;", late)
        self.assertIn("m_nExternalTCPWebPort = 0;", late)
        self.assertNotIn("CheckAndRefresh()", late)

    def test_every_mapper_discards_the_web_port_argument(self) -> None:
        signatures = {
            "srchybrid/UPnPImplMiniLib.cpp":
                "void CUPnPImplMiniLib::StartDiscovery(",
            "srchybrid/UPnPImplPCP.cpp":
                "void CUPnPImplPCP::StartDiscovery(",
            "srchybrid/UPnPImplNATPMP.cpp":
                "void CUPnPImplNATPMP::StartDiscovery(",
            "srchybrid/UPnPImplWinServ.cpp":
                "void CUPnPImplWinServ::StartDiscovery(",
        }
        for name, source in self.backends.items():
            start = source.index(signatures[name])
            body = source[start : start + 5000]
            with self.subTest(backend=name):
                self.assertIn("m_nTCPWebPort = 0;", body)
                self.assertIn("m_nExternalTCPWebPort = 0;", body)
                self.assertNotIn("m_nTCPWebPort = nTCPWebPort;", body)
                self.assertNotIn(
                    "m_nExternalTCPWebPort = nTCPWebPort;", body
                )

    def test_default_web_listener_is_loopback_not_wildcard(self) -> None:
        listener = self.websocket[
            self.websocket.index("UINT AFX_CDECL WebSocketListeningFunc(") :
            self.websocket.index("SOCKET hSocket", self.websocket.index(
                "UINT AFX_CDECL WebSocketListeningFunc("
            ))
        ]
        bind = self.websocket[
            self.websocket.index("SOCKADDR_IN stAddr;", self.websocket.index(
                "UINT AFX_CDECL WebSocketListeningFunc("
            )) :
            self.websocket.index("int bindRv", self.websocket.index(
                "UINT AFX_CDECL WebSocketListeningFunc("
            ))
        ]
        self.assertIn('"127.0.0.1"', listener)
        self.assertIn("htonl(INADDR_LOOPBACK)", bind)
        self.assertNotIn(": INADDR_ANY", bind)

    def test_runtime_privacy_gate_is_mandatory_in_wp0(self) -> None:
        self.assertIn(
            "test_v92_l08_privacy_runtime.ps1", self.wp0
        )
        self.assertIn("L08_RUNTIME_PASS", self.wp0)
        self.assertIn(
            "test_v92_l08_privacy_runtime.js", self.runtime_gate
        )
        self.assertIn(
            "collect_report.ps1", self.runtime_gate
        )
        self.assertIn(
            "Test-ReleaseZipIntegrity", self.runtime_gate
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
