"""M2A-W12 evidence for the final WebServer facade close."""
from __future__ import annotations
import json
import pathlib
import re
import unittest
from tools.architecture import generate_mod01_architecture_inventory as mod01
ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "srchybrid"
WEB = SRC / "WebServer.cpp"
WEB_HEADER = SRC / "WebServer.h"
HEADER = SRC / "WebServerFacade.h"
MODULE = SRC / "WebServerFacade.cpp"
AUTH_HEADER = SRC / "WebAuthPolicy.h"
AUTH_MODULE = SRC / "WebAuthPolicy.cpp"
DISPATCH_HEADER = SRC / "WebRequestDispatch.h"
DISPATCH_MODULE = SRC / "WebRequestDispatch.cpp"
HLS_HEADER = SRC / "WebHlsCapabilityController.h"
HLS_MODULE = SRC / "WebHlsCapabilityController.cpp"
HLS_NATIVE = SRC / "tests" / "test_web_hls_capability_controller.cpp"
ROUTE_MODULE = SRC / "WebRouteTable.cpp"
SOCKET_MODULE = SRC / "WebSocket.cpp"
SOCKET_HEADER = SRC / "WebSocket.h"
STATIC_MODULE = SRC / "WebStaticAssets.cpp"
STATIC_HEADER = SRC / "WebStaticAssets.h"
RESPONSE_MODULE = SRC / "WebSocketResponse.cpp"
RESPONSE_HEADER = SRC / "WebSocketResponse.h"
STREAM_HEADER = SRC / "LiveStreamManager.h"
STREAM_MODULE = SRC / "LiveStreamManager.cpp"
LEASE_HEADER = SRC / "LiveHlsReadLease.h"
LEASE_MODULE = SRC / "LiveHlsReadLease.cpp"
LEGACY_MODULE = SRC / "WebLiveApiLegacyController.cpp"
PROJECT = SRC / "emule.vcxproj"
MATRIX = ROOT / "docs" / "architecture" / "mod52_migration_matrix_v1.json"
SECURITY_PLAN = ROOT / "docs" / "architecture" / "MOD52_W12_SECURITY_EXPANSION_PLAN_2026-08-02.md"
W7 = ROOT / "tests" / "goldens" / "v92_m2a_w7_live_api_inventory_v1.json"
BINDING = "M2A_BIND_W12_B26D83D73F"
UNBIND = "M2A_UNBIND_W12_B26D83D73F"
EVIDENCE_PATH = "tests/test_v92_m2a_w12_webserver_close.py"
CANONICAL_HEADERS = {
    "WebLiveApiStreamController.h": (
        "W8LiveStreamOperation", "W8LiveStreamRequest", "W8LiveStreamPort",
    ),
    "WebLiveApiStatusController.h": (
        "W8LiveStatusOperation", "W8LiveStatusSnapshot", "W8LiveStatusPort",
    ),
    "WebLiveApiTransferController.h": (
        "W9LiveTransferOperation", "W9LiveTransferSnapshot", "W9LiveTransferPort",
    ),
    "WebLiveApiSearchController.h": (
        "W9SearchOperation", "W9SearchRequest", "W9SearchPort",
    ),
    "WebLiveApiSettingsController.h": (
        "W10SettingsOperation", "W10SettingsRequest", "W10SettingsPort",
    ),
    "WebLiveApiDiagnosticsController.h": (
        "W10DiagnosticsOperation", "W10DiagnosticsRequest", "W10DiagnosticsPort",
    ),
    "WebLiveApiLegacyController.h": (
        "W11LegacyOperation", "W11LegacyRequest", "W11LegacyPort",
    ),
}
def section(source: str, start: str, end: str) -> str:
    return source.split(start, 1)[1].split(end, 1)[0]
def compact(source: str) -> str:
    return re.sub(r"\s+", "", source)
def declaration(source: str, name: str) -> str:
    """Return a named type definition with comments/whitespace removed."""
    match = re.search(
        r"\b(?:enum\s+class|class|struct)\s+" + re.escape(name) + r"\b",
        source,
    )
    if match is None:
        raise AssertionError(f"missing type definition: {name}")
    opening = source.find("{", match.end())
    if opening < 0:
        raise AssertionError(f"incomplete type definition: {name}")
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                value = source[match.start():index + 1]
                without_comments = re.sub(
                    r"/\*.*?\*/|//[^\r\n]*", "", value, flags=re.S,
                )
                return re.sub(r"\s+", "", without_comments)
    raise AssertionError(f"unbalanced type definition: {name}")
class W12WebServerCloseEvidence(unittest.TestCase):
    def test_w12_security_error_paths_preserve_private_headers(self) -> None:
        dispatch = DISPATCH_MODULE.read_text(encoding="utf-8", errors="replace")
        common_headers = section(dispatch, "#define HTTPInit", "#define HTTPInitGZ")
        self.assertIn('"Cache-Control: no-store\\r\\n"', common_headers)
        self.assertIn('"Referrer-Policy: no-referrer\\r\\n"', common_headers)
        self.assertEqual(
            dispatch.count(
                '"HTTP/1.1 403 Forbidden\\r\\n"\n'
                '\t\t\t\t"Cache-Control: no-store\\r\\n"\n'
                '\t\t\t\t"Referrer-Policy: no-referrer\\r\\n"'
            )
            + dispatch.count(
                '"HTTP/1.1 403 Forbidden\\r\\n"\n'
                '\t\t\t"Cache-Control: no-store\\r\\n"\n'
                '\t\t\t"Referrer-Policy: no-referrer\\r\\n"'
            ),
            4,
        )
        process = section(
            dispatch,
            "void WebRequestDispatch::Process",
            "void RunWebClassicRequest",
        )
        exception_response = section(process, "} catch (...) {", "#endif")
        self.assertIn('"HTTP/1.1 500 Internal Server Error\\r\\n"', exception_response)
        self.assertIn('"Cache-Control: no-store\\r\\n"', exception_response)
        self.assertIn('"Referrer-Policy: no-referrer\\r\\n"', exception_response)
        self.assertIn("bool ProbeHardened", dispatch)
        self.assertIn("!ProbeHardened(parseThrow.headers)", dispatch)
        socket = SOCKET_MODULE.read_text(encoding="utf-8", errors="replace")
        request = section(
            socket,
            "void CWebSocket::OnRequestReceived",
            "void CWebSocket::OnReceived",
        )
        self.assertIn(
            'request.target.compare(0, 3, "/h/") == 0',
            request,
        )
        cookie_scan = section(request, "bool rangeSeen", "Data.sRange")
        self.assertIn("if (browserSessionCookieSeen)", cookie_scan)
        self.assertIn("browserSessionCookieInvalid = true", cookie_scan)
        self.assertIn(
            "status != ese::web::CookieStatus::NotFound",
            cookie_scan,
        )
        invalid_cookie = section(
            cookie_scan,
            "if (browserSessionCookieInvalid)",
            "Data.sRange",
        )
        invalid_cookie_compact = compact(invalid_cookie)
        self.assertIn("hlsCapabilityNamespace?", invalid_cookie_compact)
        self.assertIn("HTTP/1.1400BadRequest", invalid_cookie_compact)
        self.assertIn("Cache-Control:no-store", invalid_cookie_compact)
        self.assertIn("Referrer-Policy:no-referrer", invalid_cookie_compact)
        self.assertLess(
            invalid_cookie_compact.index("Cache-Control:no-store"),
            invalid_cookie_compact.index("Referrer-Policy:no-referrer"),
        )
        error_helper = section(
            socket,
            "void SendWebFileError",
            "} // namespace",
        )
        self.assertIn("WebStaticAssets::BuildErrorResponse", error_helper)
        self.assertIn("socket.SendData", error_helper)
        file_response = section(
            socket,
            "void CWebSocket::SendFileResponse",
            "void CWebSocket::FlushResponseQueue",
        )
        self.assertEqual(file_response.count("SendWebFileError("), 4)
        allocation = section(
            file_response,
            "file = std::make_unique<CFile>();",
            "if (!file->Open(",
        )
        opening = section(
            file_response,
            "if (!file->Open(",
            "ULONGLONG representationSize",
        )
        length = section(
            file_response,
            "representationSize = file->GetLength();",
            "if ((maximumBytes",
        )
        size_policy = section(
            file_response,
            "if ((maximumBytes",
            "ese::web::WebFileResponsePlan plan",
        )
        for branch, status in (
            (allocation, "InternalServerError"),
            (opening, "NotFound"),
            (length, "InternalServerError"),
            (size_policy, "Forbidden"),
        ):
            self.assertIn("SendWebFileError", branch)
            self.assertIn(f"WebFileErrorStatus::{status}, options", branch)
            self.assertIn("return;", branch)
        prepared = section(
            socket,
            "bool CWebSocket::PrepareBufferedFileResponse",
            "bool CWebSocket::SendPreparedFileResponse",
        )
        for marker in (
            "WebPreparedFileResponse::kMaximumBodyBytes",
            "(std::min)(maximumBytes, hardMaximum)",
            "WebStaticAssets::ReservePreparedBody",
            "WebFileErrorStatus::ServiceUnavailable",
            "prepared.body.resize",
            "file->Read(prepared.body.data() + total, requested)",
        ):
            self.assertIn(marker, prepared)
        self.assertNotIn("SendData", prepared)
        self.assertNotIn("SendReply", prepared)
        static_assets = STATIC_MODULE.read_text(encoding="utf-8")
        builder = section(
            static_assets,
            "std::string WebStaticAssets::BuildErrorResponse",
            "const char* WebStaticAssets::MimeTypeForPath",
        )
        self.assertIn("if (!options.cacheControl.empty())", builder)
        self.assertIn('"Cache-Control: " << options.cacheControl', builder)
        self.assertIn("if (options.noReferrer)", builder)
        self.assertIn('"Referrer-Policy: no-referrer', builder)
        static_header = STATIC_HEADER.read_text(encoding="utf-8")
        reserve = section(
            static_assets,
            "std::shared_ptr<void> WebStaticAssets::ReservePreparedBody",
            "std::uint64_t WebStaticAssets::ReservedPreparedBodyBytes",
        )
        self.assertIn("kMaximumBodyBytes", reserve)
        self.assertIn("kGlobalMaximumBodyBytes - byteCount", reserve)
        self.assertIn("compare_exchange_weak", reserve)
        self.assertIn("fetch_sub", reserve)
        self.assertIn("20ull * 1024ull * 1024ull", static_header)
        self.assertIn("64ull * 1024ull * 1024ull", static_header)
        response = RESPONSE_MODULE.read_text(encoding="utf-8")
        self.assertEqual(response.count("m_failed = true"), 1)
        self.assertIn("void WebSocketResponse::MarkFailedPreservingQueue", response)
        failure = section(
            response,
            "void WebSocketResponse::MarkFailedPreservingQueue",
            "bool WebSocketResponse::CloseRequested",
        )
        self.assertIn("m_completionReservation.reset()", failure)
        self.assertIn("m_source.reset()", failure)
        self.assertIn("std::shared_ptr<void> m_completionReservation", RESPONSE_HEADER.read_text(encoding="utf-8"))
    def test_m2a_f00e6b3c901ba632(self) -> None:
        self.assertTrue(MATRIX.is_file())
        matrix = json.loads(MATRIX.read_text(encoding="utf-8"))
        module = next(item for item in matrix["additional_modules"] if item["name"] == "WebServerFacade")
        self.assertEqual(module["card"], "W12")
        self.assertEqual((module["parent"], module["layer"], module["dependencies"]),
                         ("CWebServer", "facade", []))
        self.assertFalse((SRC / "WebServer_original.cpp").exists())
        self.assertNotIn("WebServer_original.cpp", (ROOT / "tools/check_direct_port_usage.py").read_text(encoding="utf-8"))
        web = WEB.read_text(encoding="utf-8", errors="replace")
        self.assertLessEqual(len(web.splitlines()), 2100)
        plan = SECURITY_PLAN.read_text(encoding="utf-8")
        for amendment in (
            "Enmienda v2: lease, buffer inmutable y presupuesto del adaptador",
            "de 1.756 a 2.048 LOC",
            "a 2.100 LOC",
            "exclusivamente cableado sin estado",
            "LiveHlsReadLease.h/.cpp",
        ):
            self.assertIn(amendment, plan)
        web_header = WEB_HEADER.read_text(encoding="utf-8")
        fields = mod01.fields(
            web_header.splitlines(), "CWebServer", "srchybrid/WebServer.h",
        )
        self.assertEqual(
            {item["name"] for item in fields},
            {
                "m_authPolicy", "m_Params", "m_uCurIP", "m_iSearchSortby",
                "m_nIntruderDetect", "m_bServerWorking", "m_bSearchAsc",
                "m_bIsTempDisabled",
            },
        )
        self.assertNotIn("SortParams", web_header)
        self.assertNotIn("CWebServer::_DownloadCmp", web)
        self.assertNotIn("CWebServer::_UploadCmp", web)
        # The literal W7-SEC-02 close is an approved PRE-A expansion.  At this
        # stage source ownership and state bounds are authoritative; A freezes
        # the final LOC/overlay hashes only after this security slice is green.
        for path in (
            HEADER, MODULE, HLS_HEADER, HLS_MODULE,
            LEASE_HEADER, LEASE_MODULE,
        ):
            self.assertTrue(path.is_file(), path)
            self.assertLessEqual(len(path.read_text(encoding="utf-8").splitlines()), 1500)
        self.assertNotIn("class CWebServer", HLS_HEADER.read_text(encoding="utf-8"))
    def test_m2a_441a78dac75bb845(self) -> None:
        self.assertTrue(HEADER.is_file() and MODULE.is_file())
        header, source = HEADER.read_text(encoding="utf-8"), MODULE.read_text(encoding="utf-8")
        combined = header + source
        self.assertLessEqual(len(combined.splitlines()), 700)
        self.assertIn('#include "M2ABindingPort.h"', header)
        self.assertIn("HardenLiveResponseHeaders", combined)
        self.assertIn("BuildRejectedLiveSessionLog", combined)
        self.assertIn("BuildRejectedHlsCapabilityLog", combined)
        self.assertNotIn('"invalid or expired HLS capability"', WEB.read_text(encoding="utf-8"))
        self.assertGreaterEqual(WEB.read_text(encoding="utf-8").count('"access denied"'), 4)
        self.assertIn("BuildHlsCapabilityPlaylistPath", combined)
        self.assertIn("RewriteLiveIndexForCookieSession", combined)
        self.assertIn("RewriteLivePlayerForHlsCapability", combined)
        self.assertIn("RunWebServerFacadeCharacterizationSelfTest", combined)
        self.assertIn("Referrer-Policy", source)
        self.assertIn("no-referrer", source)
        self.assertIn("Cache-Control", source)
        self.assertIn("no-store", source)
        self.assertIn("W12-SEC-02-CANARY-TOKEN", source)
        self.assertIn("live response policy idempotence", source)
        selftest = section(source, "bool RunWebServerFacadeCharacterizationSelfTest", "} } // namespace ese::web")
        self.assertIn("Content-Type: text/html; charset=utf-8", selftest)
        self.assertIn("productive HTML response policy", selftest)
        self.assertIn('invalidSessionUrl = "/s/" + credentialCanary + "/live"', selftest)
        self.assertIn("rejected.find(credentialCanary)", selftest)
        self.assertIn("rejected.find(invalidSessionUrl)", selftest)
        self.assertIn("BuildRejectedHlsCapabilityLog", selftest)
        self.assertIn("rejectedCapability.find(capabilityToken)", selftest)
        self.assertIn("rejectedCapability.find(capabilityPath)", selftest)
        self.assertIn('playerBody.find("/s/")', selftest)
        for forbidden in (
            "WebServer.h", "CWebSocket", "CString", "theApp", "thePrefs", "windows.h",
            "LiveStreamManager", "SendData", "SendFileResponse",
        ):
            self.assertNotIn(forbidden, combined)
        project = PROJECT.read_text(encoding="utf-8")
        node = re.search(r'<ClCompile Include="WebServerFacade\.cpp">(.*?)</ClCompile>', project, re.S)
        self.assertIsNotNone(node)
        for setting in (
            "<PrecompiledHeader>NotUsing</PrecompiledHeader>",
            "<WarningLevel>Level4</WarningLevel>",
            "<TreatWarningAsError>true</TreatWarningAsError>",
            "<LanguageStandard>stdcpp17</LanguageStandard>",
        ):
            self.assertIn(setting, node.group(1))
        hls_node = re.search(
            r'<ClCompile Include="WebHlsCapabilityController\.cpp">(.*?)</ClCompile>',
            project,
            re.S,
        )
        self.assertIsNotNone(hls_node)
        for setting in (
            "<PrecompiledHeader>NotUsing</PrecompiledHeader>",
            "<WarningLevel>Level4</WarningLevel>",
            "<TreatWarningAsError>true</TreatWarningAsError>",
            "<LanguageStandard>stdcpp17</LanguageStandard>",
        ):
            self.assertIn(setting, hls_node.group(1))
        self.assertIn('<ClInclude Include="WebHlsCapabilityController.h" />', project)
        self.assertIn('<ClInclude Include="LiveHlsReadLease.h" />', project)
        self.assertIn('<ClCompile Include="LiveHlsReadLease.cpp">', project)
        native_gate = (SRC / "tests" / "make.bat").read_text(encoding="utf-8")
        self.assertIn("WebHlsCapabilityController.cpp", native_gate)
        for relative in (
            "tools/architecture/verify_mod02_characterization.py",
            "tools/architecture/run_mod02_stream_selftest.ps1",
        ):
            critical = (ROOT / relative).read_text(encoding="utf-8")
            self.assertIn("WebServerFacade.cpp", critical)
            self.assertIn("WebServerFacade.h", critical)
            self.assertIn("WebHlsCapabilityController.cpp", critical)
            self.assertIn("WebHlsCapabilityController.h", critical)
            self.assertIn("LiveHlsReadLease.h", critical)
            self.assertIn("LiveHlsReadLease.cpp", critical)
    def test_m2a_0e90ac3902566867(self) -> None:
        self.assertTrue(HLS_HEADER.is_file() and HLS_MODULE.is_file())
        header = HLS_HEADER.read_text(encoding="utf-8")
        source = HLS_MODULE.read_text(encoding="utf-8")
        candidate = section(
            source,
            "WebHlsCapabilityReadDecision RunWebHlsCapabilityRead",
            "bool CommitWebHlsCapabilityRead",
        )
        commit = section(
            source,
            "bool CommitWebHlsCapabilityRead",
            "bool RunWebHlsCapabilityControllerSelfTest",
        )
        for contract_type in (
            "WebHlsCapabilityReadPort",
            "WebHlsCapabilityReadRequest",
            "WebHlsCapabilityReadDecision",
        ):
            self.assertIn(contract_type, header)
        self.assertNotIn("CommitHlsReadCapability", candidate)
        self.assertEqual(candidate.count("port.copy_live_source("), 2)
        self.assertIn("SameSource(first, confirmed)", candidate)
        self.assertIn("policy.CommitHlsReadCapability", commit)
        self.assertIn("commit_now_ms", commit)
        self.assertNotIn("CWebServer", header + source)
        native = HLS_NATIVE.read_text(encoding="utf-8")
        for test_name in (
            "TestRolloverBeforeLeaseHasNoEffects",
            "TestExpiryBetweenInspectAndCommit",
            "TestEightConcurrentReadsDoNotDeadlock",
        ):
            self.assertIn(test_name + "();", native)
    def test_m2a_91346142cac586d4(self) -> None:
        self.assertTrue(LEASE_HEADER.is_file() and LEASE_MODULE.is_file())
        header = LEASE_HEADER.read_text(encoding="utf-8")
        source = LEASE_MODULE.read_text(encoding="utf-8")
        lease = section(
            source,
            "LiveHlsReadExecution CLiveStreamManager::ExecuteHlsReadIfCurrent",
            "return LiveHlsReadExecution::Prepared;",
        )
        ordered = compact(lease)
        lock_at = ordered.index("CSingleLocklock(&m_lock,TRUE)")
        validate_at = ordered.index(
            "CopyHlsSourceSnapshotLocked(expected.streamKey,current)", lock_at,
        )
        prepare_at = ordered.index("prepare(context)", validate_at)
        self.assertLess(lock_at, validate_at)
        self.assertLess(validate_at, prepare_at)
        self.assertIn("struct LiveHlsSourceSnapshot", header)
        self.assertIn("current.generation != expected.generation", lease)
        self.assertIn("current.broadcast != expected.broadcast", lease)
        self.assertIn("memcmp(current.streamKey, expected.streamKey", lease)
        self.assertIn("LiveHlsReadExecution::Stale", source)
        self.assertIn("const std::vector<BYTE> capturedBytes(currentRead.bytes)", source)
        for forbidden_send in (
            "SendData", "SendReply", "SendPreparedFileResponse", "send(",
        ):
            self.assertNotIn(forbidden_send, lease)
    def test_m2a_5937deca79e7480d(self) -> None:
        self.assertIn(
            "W12ProcessHlsCapability",
            WEB.read_text(encoding="utf-8", errors="replace"),
        )
        web = WEB.read_text(encoding="utf-8", errors="replace")
        auth = AUTH_HEADER.read_text(encoding="utf-8") + AUTH_MODULE.read_text(encoding="utf-8")
        facade = MODULE.read_text(encoding="utf-8")
        socket = SOCKET_MODULE.read_text(encoding="utf-8")
        self.assertIn('request.target.compare(0, 3, "/h/") == 0', socket)
        self.assertIn("browser_token_digest", auth)
        self.assertIn("token_digest", auth)
        self.assertNotRegex(auth, r"\bbrowser_token\b")
        self.assertIn("BuildRejectedHlsCapabilityLog", facade)
        self.assertIn("Referrer-Policy", facade + socket)
        self.assertIn("no-referrer", facade + socket)
        rejected = section(
            web,
            "static bool W12AuthorizeLiveRequest",
            "void CWebServer::_ProcessLiveAPI",
        )
        self.assertNotIn("url=%s", rejected)
        finding = next(
            item for item in json.loads(W7.read_text(encoding="utf-8"))["known_findings"]
            if item["id"] == "W7-SEC-02"
        )
        self.assertEqual(
            finding["vector"],
            "bad token canary must not appear in logs or outbound Referer",
        )
    def test_m2a_f8a465bd040b2192(self) -> None:
        self.assertTrue(SECURITY_PLAN.is_file())
        plan = SECURITY_PLAN.read_text(encoding="utf-8")
        runner = (ROOT / "tools/architecture/run_w12_security_runtime.ps1").read_text(encoding="utf-8")
        collector = (ROOT / "tools/architecture/collect_w12_browser_cdp.mjs").read_text(encoding="utf-8")
        verifier = (ROOT / "tools/architecture/verify_w12_security_evidence.py").read_text(encoding="utf-8")
        for schema in (
            "browser-handoff/v3", "browser-ready/v3", "browser-done/v3",
        ):
            self.assertIn(schema, runner + collector)
        self.assertIn("browser-collector-claim/v3", collector)
        self.assertIn("180000", collector)
        self.assertIn("no-store", runner + collector)
        self.assertIn("no-referrer", runner + collector)
        self.assertIn("W12-RUNTIME-STOP-REVOCATION", runner)
        for artifact in (
            "activation.json", "runtime.json", "browser-challenge.json",
            "browser-cdp-trace.json", "verdict.json",
        ):
            self.assertIn(artifact, runner + verifier + plan)
        for transient in ("handoff", "ready", "claim", "raw", "done"):
            self.assertIn(transient, plan)
        self.assertIn("W7-SEC-02", plan)
    def test_m2a_38f53fea74e4d1f3(self) -> None:
        self.assertTrue(WEB.is_file())
        web = WEB.read_text(encoding="utf-8", errors="replace")
        self.assertIn(BINDING, web)
        self.assertRegex(web, rf"M2AModuleHandle\s+{BINDING}\(const M2AParentPort&\)")
        self.assertRegex(web, rf"void\s+{UNBIND}\(const M2AParentPort&\)")
        start = section(web, "void CWebServer::StartServer", "void CWebServer::StopServer")
        stop = section(web, "void CWebServer::StopServer", "void CWebServer::AddStatsLine")
        destructor = section(web, "CWebServer::~CWebServer", "void CWebServer::_SaveWIConfigArray")
        self.assertIn(f"{BINDING}(M2AParentPort{{this}})", start)
        self.assertIn(f"{UNBIND}(M2AParentPort{{this}})", stop)
        self.assertIn(f"{UNBIND}(M2AParentPort{{this}})", destructor)
        self.assertIn("m_authPolicy.RevokeAllHlsCapabilities()", start)
        self.assertIn("m_authPolicy.RevokeAllHlsCapabilities()", stop)
        self.assertIn("m_authPolicy.RevokeAllHlsCapabilities()", destructor)
        restart = section(web, "void CWebServer::RestartSockets", "void CWebServer::StartServer")
        self.assertIn("m_authPolicy.RevokeAllHlsCapabilities()", restart)
        facade_source = MODULE.read_text(encoding="utf-8")
        self.assertIn("facade deliberately owns no process or socket state", facade_source)
        self.assertIn("Stateless and therefore idempotent", facade_source)
        self.assertIn("RunWebServerFacadeCharacterizationSelfTest", web)
        self.assertIn("RunWebHlsCapabilityControllerSelfTest", web)
        self.assertGreaterEqual(web.count("HardenLiveResponseHeaders"), 3)
        send_legacy = section(web, "static void SendW11Response", "static bool RunW11LiveLegacyStaticFile")
        send_legacy_compact = re.sub(r"\s+", "", send_legacy)
        self.assertIn(
            "if(r.file_response){", send_legacy_compact,
            "HLS/static file forwarding must remain on its unchanged byte/range path",
        )
        self.assertIn(
            "conststd::stringh=ese::web::HardenLiveResponseHeaders(r.header,true);",
            send_legacy_compact,
        )
        self.assertLess(send_legacy_compact.index("return;}"),
                        send_legacy_compact.index("HardenLiveResponseHeaders"))
        legacy_source = LEGACY_MODULE.read_text(encoding="utf-8")
        page = section(legacy_source, "bool Page(W11LegacyOperation operation", "const char* B(bool value)")
        self.assertIn("Content-Type: text/html; charset=utf-8", legacy_source)
        self.assertIn("response.header = PageHeader", page)
        self.assertIn("LivePlayerHtml(request.resource)", page)
        module_dispatch = section(legacy_source, "bool RunW11LiveLegacyApi", "bool RunW11LiveLegacyCharacterizationSelfTest")
        for operation in ("Dashboard", "LiveIndex", "LivePlayer"):
            self.assertIn("case W11LegacyOperation::" + operation + ": return Page", module_dispatch)
        live_dispatch = section(web, "void CWebServer::_ProcessLiveAPI", "void CWebServer::_ProcessFileReq")
        live_dispatch_compact = compact(live_dispatch)
        legacy_run = live_dispatch_compact.index("RunW11LiveLegacyApi")
        legacy_send = live_dispatch_compact.index("SendW11Response", legacy_run)
        self.assertLess(legacy_run, legacy_send)
        self.assertIn("W12ProcessHlsCapability", live_dispatch)
        self.assertIn("W12AuthorizeLiveRequest", live_dispatch)
        self.assertIn("W12RewritePlayerCapability", live_dispatch)
        authorization = section(
            web,
            "static bool W12AuthorizeLiveRequest",
            "void CWebServer::_ProcessLiveAPI",
        )
        authorization_compact = compact(authorization)
        self.assertIn(
            'if(output.url.GetLength()>3&&strncmp(output.url,"/s/",3)==0)',
            authorization_compact,
        )
        self.assertIn(
            "if(!loopback||locator<=0||!resolve(static_cast<std::uint32_t>(locator),output.session))",
            authorization_compact,
        )
        self.assertIn("BuildRejectedLiveSessionLog", authorization)
        rejection_block = authorization.split("BuildRejectedLiveSessionLog", 1)[1]
        self.assertNotIn("url=%s", rejection_block)
        self.assertNotIn("inputUrl", rejection_block)
        # Inspect is side-effect free.  Commit and bounded immutable capture
        # share the exact manager lease; socket delivery follows its release.
        hls = HLS_MODULE.read_text(encoding="utf-8")
        hls_header = HLS_HEADER.read_text(encoding="utf-8")
        candidate = section(
            hls,
            "WebHlsCapabilityReadDecision RunWebHlsCapabilityRead",
            "bool CommitWebHlsCapabilityRead",
        )
        calls = [
            candidate.index("InspectHlsReadCapability"),
            candidate.index("copy_live_source"),
            candidate.index(
                "copy_live_source",
                candidate.index("copy_live_source") + 1,
            ),
        ]
        self.assertEqual(calls, sorted(calls))
        self.assertEqual(candidate.count("port.copy_live_source("), 2)
        self.assertNotIn("CommitHlsReadCapability", candidate)
        self.assertIn("SameSource(first, confirmed)", candidate)
        self.assertIn("inspected.source_role != confirmed.role", candidate)
        self.assertIn("inspected.generation != confirmed.generation", candidate)
        self.assertIn(
            "decision.status = WebHlsCapabilityReadStatus::Candidate",
            candidate,
        )
        self.assertIn("decision.source = confirmed", candidate)
        commit = section(
            hls,
            "bool CommitWebHlsCapabilityRead",
            "bool RunWebHlsCapabilityControllerSelfTest",
        )
        self.assertIn("std::uint64_t commit_now_ms", commit)
        self.assertIn("policy.CommitHlsReadCapability", commit)
        self.assertIn("commit_now_ms", commit)
        self.assertIn("WebHlsCapabilityReadPort", hls_header)
        self.assertIn("WebHlsCapabilityReadRequest", hls_header)
        self.assertIn("WebHlsCapabilityReadDecision", hls_header)
        self.assertIn("std::uint64_t commit_now_ms", hls_header)
        self.assertNotIn("CWebServer", hls_header + hls)
        hls_selftest = hls.split("bool RunWebHlsCapabilityControllerSelfTest", 1)[1]
        self.assertIn("invalid HLS capability side effects", hls_selftest)
        self.assertIn("probe.copies != 0", hls_selftest)
        self.assertIn("probe.copies != 2", hls_selftest)
        self.assertIn("WebHlsCapabilityReadStatus::Candidate", hls_selftest)
        self.assertIn("ownerBeforeCommit.last_seen_ms", hls_selftest)
        native_hls = HLS_NATIVE.read_text(encoding="utf-8")
        main_hls = native_hls.split("int main()", 1)[1]
        for required_test in (
            "TestCandidateDoesNotTouchOwner",
            "TestRolloverBeforeLeaseHasNoEffects",
            "TestLogoutBetweenCandidateAndCommit",
            "TestExpiryBetweenInspectAndCommit",
            "TestCommitWinsBeforeLogout",
            "TestCapturedBytesAreImmutableAfterLease",
            "TestTransitionWaitsForCaptureLease",
            "TestNoteRequiresViewerSuccessfulBody",
            "TestExactRangeRetry",
            "TestEightConcurrentReadsDoNotDeadlock",
            "TestMixedReadRejoinLogoutStressDoesNotDeadlock",
        ):
            self.assertIn(required_test + "();", main_hls)
        self.assertIn("AbortOnWatchdogTimeout", native_hls)
        self.assertIn("std::chrono::seconds(5)", native_hls)
        self.assertIn("std::abort()", native_hls)
        self.assertIn("expiredCommitNow", native_hls)
        self.assertIn("logout after an authorized capture", native_hls)
        self.assertIn("generation transition must wait", native_hls)
        self.assertIn("mixed read, leave/rejoin, and logout", native_hls)
        adapter = section(
            web,
            "static bool W12CopyHlsSource",
            "struct W12LiveAuthorization",
        )
        adapter_compact = compact(adapter)
        self.assertIn("CopyHlsSourceSnapshot", adapter)
        self.assertIn(
            'source.role==ese::web::WebHlsSourceRole::Broadcast',
            adapter_compact,
        )
        self.assertIn('_T("%seMule_RTMP\\\\%s")', adapter)
        self.assertIn('_T("%seMule_RTMP\\\\%s\\\\%s")', adapter)
        self.assertIn('options.cacheControl = "no-store"', adapter)
        self.assertIn("options.noReferrer = true", adapter)
        prepare = section(
            adapter,
            "static LiveHlsReadPreparation W12PrepareWebHlsRead",
            "static bool W12MakeLiveHlsLeaseSnapshot",
        )
        prepare_compact = compact(prepare)
        fresh_now = prepare_compact.index(
            "commitNowMs=eSELive::WebRequestAuthNowMs()"
        )
        commit_at = prepare_compact.index("CommitWebHlsCapabilityRead", fresh_now)
        capture_at = prepare_compact.index("PrepareBufferedFileResponse", commit_at)
        self.assertLess(fresh_now, commit_at)
        self.assertLess(commit_at, capture_at)
        for forbidden_send in (
            "SendData", "SendReply", "SendPreparedFileResponse", "Disconnect",
        ):
            self.assertNotIn(forbidden_send, prepare)
        capability_adapter = adapter.split(
            "static W12HlsDispatchResult W12ProcessHlsCapability", 1
        )[1]
        self.assertIn("DigestWebRequestToken(raw)", capability_adapter)
        self.assertIn("RunWebHlsCapabilityRead(policy, request, port)", capability_adapter)
        self.assertNotIn("corsOrigin", capability_adapter)
        capability_adapter_compact = compact(capability_adapter)
        inspected = capability_adapter_compact.index("RunWebHlsCapabilityRead")
        candidate_check = capability_adapter_compact.index(
            "decision.status==ese::web::WebHlsCapabilityReadStatus::Rejected",
            inspected,
        )
        execute = capability_adapter_compact.index(
            "ExecuteHlsReadIfCurrent", candidate_check
        )
        send = capability_adapter_compact.index(
            "SendPreparedFileResponse", execute
        )
        self.assertLess(inspected, candidate_check)
        self.assertLess(candidate_check, execute)
        self.assertLess(execute, send)
        self.assertIn("LiveHlsReadExecution::Stale", capability_adapter)
        self.assertIn("RevokeHlsCapabilityDigest", capability_adapter)
        self.assertNotIn("W12NoteWebViewerFetch", capability_adapter)
        self.assertNotIn("W12ServeWebHlsResource", capability_adapter)
        stream_header = STREAM_HEADER.read_text(encoding="utf-8")
        stream_module = STREAM_MODULE.read_text(encoding="utf-8")
        self.assertNotRegex(stream_module, r'LIVE_LOG\([^\n]*(?:key=%s|for key=%s|pubkey.*stream %s)')
        lease_header = LEASE_HEADER.read_text(encoding="utf-8")
        lease_module = LEASE_MODULE.read_text(encoding="utf-8")
        snapshot = section(
            lease_module,
            "bool CLiveStreamManager::CopyHlsSourceSnapshot",
            "LiveHlsReadExecution CLiveStreamManager::ExecuteHlsReadIfCurrent",
        )
        self.assertIn("struct LiveHlsSourceSnapshot", lease_header)
        self.assertIn('#include "LiveHlsReadLease.h"', stream_header)
        self.assertNotIn("CopyHlsSourceSnapshot", stream_module)
        self.assertIn("CSingleLock lock(&m_lock, TRUE)", snapshot)
        self.assertIn("m_broadcastSession.Generation()", snapshot)
        self.assertIn("m_viewerSession.Generation()", snapshot)
        self.assertIn("out.broadcast = true", snapshot)
        self.assertIn("out.broadcast = false", snapshot)
        lease = section(
            lease_module,
            "LiveHlsReadExecution CLiveStreamManager::ExecuteHlsReadIfCurrent",
            "return LiveHlsReadExecution::Prepared;",
        )
        lease_compact = compact(lease)
        locked = lease_compact.index("CSingleLocklock(&m_lock,TRUE)")
        revalidated = lease_compact.index(
            "CopyHlsSourceSnapshotLocked(expected.streamKey,current)", locked
        )
        callback = lease_compact.index("prepare(context)", revalidated)
        self.assertLess(locked, revalidated)
        self.assertLess(revalidated, callback)
        for exact in (
            "current.broadcast != expected.broadcast",
            "current.generation != expected.generation",
            "memcmp(current.streamKey, expected.streamKey",
        ):
            self.assertIn(exact, lease)
        self.assertIn(
            "prepared == LiveHlsReadPreparation::PreparedWithBody",
            lease,
        )
        self.assertIn("!current.broadcast", lease)
        self.assertIn("m_viewerSession.NotePlayerFetch", lease)
        for forbidden_send in (
            "SendData", "SendReply", "SendPreparedFileResponse", "send(",
        ):
            self.assertNotIn(forbidden_send, lease)
        self.assertLessEqual(len(stream_header.splitlines()), 700)
        manager_selftest = section(
            stream_module,
            "bool CLiveStreamManager::RunIsolatedLoopbackSelfTest",
            "void CLiveStreamManager::StopBroadcast",
        )
        self.assertIn(
            "RunHlsReadLeaseSelfTest(sourceInfo.streamKey, outFailure)",
            manager_selftest,
        )
        real_lease_selftest = lease_module.split(
            "bool CLiveStreamManager::RunHlsReadLeaseSelfTest", 1
        )[1]
        for marker in (
            "CopyHlsSourceSnapshot(streamKey, active)",
            'eMule_RTMP\\\\stream.m3u8',
            "20ull * 1024ull * 1024ull",
            'memcmp(context->bytes.data(), "#EXTM3U", 7)',
            "LiveHlsReadPreparation::PreparedWithBody",
            "const std::vector<BYTE> capturedBytes(currentRead.bytes)",
            "StopBroadcastFull()",
            "currentRead.bytes != capturedBytes",
            "LiveHlsReadExecution::Stale",
            "staleRead.invoked",
        ):
            self.assertIn(marker, real_lease_selftest)
        route = ROUTE_MODULE.read_text(encoding="utf-8")
        match = section(route, "WebRouteMatch MatchGetPath", "} // namespace")
        self.assertLess(
            match.index('if (path.compare(0, 3, "/h/") == 0)'),
            match.index("if (IsStaticAssetPath(path))"),
        )
        socket = SOCKET_MODULE.read_text(encoding="utf-8")
        self.assertIn('request.target.compare(0, 3, "/h/") == 0', socket)
        self.assertIn("Cache-Control: no-store", socket)
        self.assertIn("Referrer-Policy: no-referrer", socket)
        auth = AUTH_HEADER.read_text(encoding="utf-8") + AUTH_MODULE.read_text(encoding="utf-8")
        dispatch = DISPATCH_HEADER.read_text(encoding="utf-8") + DISPATCH_MODULE.read_text(encoding="utf-8")
        self.assertIn("browser_token_digest", auth)
        self.assertIn("token_digest", auth)
        self.assertNotRegex(auth, r"\bbrowser_token\b")
        self.assertIn("DigestWebRequestToken", dispatch)
        self.assertIn("Set-Cookie: eSEWebSession=", dispatch)
        finding = next(item for item in json.loads(W7.read_text(encoding="utf-8"))["known_findings"]
                       if item["id"] == "W7-SEC-02")
        self.assertEqual(finding["vector"], "bad token canary must not appear in logs or outbound Referer")
        for header_name, names in CANONICAL_HEADERS.items():
            header = (SRC / header_name).read_text(encoding="utf-8")
            self.assertNotIn(f'#include "{header_name}"', web)
            self.assertNotIn(header_name.removesuffix(".h"), web)
            for name in names:
                self.assertEqual(
                    declaration(web, name),
                    declaration(header, name),
                    name,
                )
        for name in (
            "M2A_BIND_W8_4974C0F316", "M2A_BIND_W8_E988965D5A",
            "M2A_BIND_W9_52CC9DEBDD", "M2A_BIND_W9_3B359EBB1A",
            "M2A_BIND_W10_E9722EA045", "M2A_BIND_W10_47570D3256",
            "M2A_BIND_W11_55908BF94D",
        ):
            self.assertRegex(web, rf"M2AModuleHandle\s+{name}\(const M2AParentPort&\)")
if __name__ == "__main__":
    unittest.main()
