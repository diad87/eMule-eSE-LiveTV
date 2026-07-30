"""Production binding and closed hardening checks for MOD-2.6."""

from __future__ import annotations

import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class Mod26WebStreamingProductionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.static_header = (
            ROOT / "srchybrid" / "WebStaticAssets.h"
        ).read_text(encoding="utf-8")
        cls.static_source = (
            ROOT / "srchybrid" / "WebStaticAssets.cpp"
        ).read_text(encoding="utf-8")
        cls.response_header = (
            ROOT / "srchybrid" / "WebSocketResponse.h"
        ).read_text(encoding="utf-8")
        cls.response_source = (
            ROOT / "srchybrid" / "WebSocketResponse.cpp"
        ).read_text(encoding="utf-8")
        cls.web_server = (
            ROOT / "srchybrid" / "WebServer.cpp"
        ).read_text(encoding="utf-8", errors="replace")
        cls.web_socket = (
            ROOT / "srchybrid" / "WebSocket.cpp"
        ).read_text(encoding="utf-8", errors="replace")
        cls.web_socket_header = (
            ROOT / "srchybrid" / "WebSocket.h"
        ).read_text(encoding="utf-8")

    def test_portable_modules_are_project_and_gate_wired(self) -> None:
        project = (ROOT / "srchybrid" / "emule.vcxproj").read_text()
        make = (ROOT / "srchybrid" / "tests" / "make.bat").read_text()
        for name in ("WebStaticAssets", "WebSocketResponse"):
            self.assertIn(f'{name}.cpp"', project)
            self.assertIn(f'{name}.h"', project)
            self.assertIn(f"{name}.cpp", make)
        self.assertIn("test_web_streaming.cpp", make)
        self.assertIn("test_web_streaming.exe", make)

    def test_range_policy_is_single_bounded_and_overflow_safe(self) -> None:
        for token in (
            '"bytes="',
            'HasCaseInsensitivePrefix(headerValue, "bytes=")',
            "find(',', 6)",
            "std::numeric_limits<std::uint64_t>::max()",
            "WebRangeStatus::Unsatisfiable",
            "416 Range Not Satisfiable",
            "Content-Range: bytes */",
            "206 Partial Content",
            "Accept-Ranges: bytes",
        ):
            self.assertIn(token, self.static_source)
        self.assertNotIn("HANDLE", self.static_header + self.static_source)
        self.assertNotIn("CFile", self.static_header + self.static_source)

    def test_response_queue_is_bounded_and_source_driven(self) -> None:
        for token in (
            "kMaxQueuedBytes = 2u * 1024u * 1024u",
            "kMaxQueuedChunks = 64u",
            "AttachSource",
            "PumpSource",
            "m_sourceBytesRemaining",
            "m_queuedBytes",
            "m_failed",
        ):
            self.assertIn(token, self.response_header)
        self.assertIn("byteCount > kMaxQueuedBytes - m_queuedBytes", self.response_source)
        self.assertIn("m_chunks.size() >= kMaxQueuedChunks", self.response_source)
        self.assertGreaterEqual(self.response_source.count("catch (...)"), 2)
        for concrete in ("SOCKET", "HANDLE", "CFile", "mbedtls"):
            self.assertNotIn(concrete, self.response_header + self.response_source)

    def test_socket_adapter_has_no_legacy_unbounded_queue_or_tls_spin(self) -> None:
        self.assertNotIn("class CChunk", self.web_socket_header)
        self.assertNotIn("m_pHead", self.web_socket)
        self.assertNotIn("m_pTail", self.web_socket)
        self.assertIn("m_response.Enqueue", self.web_socket)
        self.assertIn("m_response.PumpSource", self.web_socket)
        self.assertIn("WEBSOCKET_WAIT_SLICE_MS", self.web_socket)
        self.assertIn("cleanup must", self.web_socket)
        self.assertIn("never spin on WANT_READ/WANT_WRITE", self.web_socket)

    def test_every_file_route_uses_one_streaming_response_boundary(self) -> None:
        self.assertGreaterEqual(self.web_server.count("SendFileResponse("), 4)
        self.assertIn('header.name == "range"', self.web_socket)
        self.assertIn("Data.sRange", self.web_server)
        self.assertIn("rangeSeen", self.web_socket)
        self.assertIn("CollectRangeHeader", self.web_socket)
        self.assertIn("__duplicate_range__", self.static_source)
        self.assertIn("__empty_range__", self.static_source)
        self.assertNotIn("new BYTE[fileSize]", self.web_server)
        self.assertNotIn("new char[filesize]", self.web_server)
        self.assertNotIn("Content-Disposition: attachment; filename=\"%s", self.web_server)
        self.assertIn("filename*=UTF-8''", self.static_source)
        self.assertIn("X-Content-Type-Options: nosniff", self.static_source)


if __name__ == "__main__":
    unittest.main()
