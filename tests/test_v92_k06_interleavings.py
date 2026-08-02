#!/usr/bin/env python3
"""K06 source contracts for mapper shutdown and late-result interleavings."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def source(relative_path: str) -> str:
    return (
        (ROOT / relative_path)
        .read_bytes()
        .decode("latin-1")
        .replace("\r\n", "\n")
    )


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


dialog = source("srchybrid/EmuleDlg.cpp")
upnp = source("srchybrid/UPnPImpl.cpp")
mailbox = source("libnatmap/src/mapping_result_mailbox.cpp")

require(
    "mailbox->Publish(resultData)" in upnp
    and "std::lock_guard<std::mutex> lock(m_resultMutex);" in upnp,
    "mapper publication must be serialized with callback invalidation",
)
require(
    upnp.count("::PostMessage(resultWindow, resultMessage, messageToken, 0)")
    == 3
    and "PublishPcpUpstreamBundle(bundle)" in upnp,
    "all mapper result paths must use the fenced message dispatch",
)
require(
    "MailboxPublishStatus::Closed" in mailbox
    and "bool MappingResultMailbox::Close()" in mailbox,
    "shutdown must have a terminal mailbox fence",
)
require(
    "ConsumeForCurrentRoute" in dialog
    and "ConsumeLegacyEnvelopeForCurrentRoute" in dialog
    and "ResultAcceptance::RouteMismatch" in dialog,
    "the UI consumer must reject a result from the previous network route",
)
require(
    "SetMessageOnResult(NULL, 0)" in dialog
    and "StopAsyncFind();" in dialog,
    "shutdown and cancellation must invalidate the callback and stop discovery",
)
require(
    "m_mappingResultGate.CancelPending();" in dialog
    and "m_mappingResultMailbox->Close();" in dialog,
    "shutdown must cancel the request gate and close its mailbox",
)
require(
    "PM_REMOVE" in dialog and "UM_UPNP_RESULT" in dialog,
    "shutdown must drain already queued mapper window messages",
)
require(
    "SwitchImplentation()" in dialog
    and "StartUPnP(false, 0, 0, m_bUPnPExplicitRequest)" in dialog,
    "mapper fallback must retain request fencing across implementation switch",
)
resume = dialog[
    dialog.index("case PBT_APMRESUMEAUTOMATIC:")
    : dialog.index("case PBT_APMSUSPEND:")
]
require(
    resume.index("CheckUPnPLease()") < resume.index("RefreshUPnP(true)"),
    "resume must retire an expired finite lease before refresh or reconnect",
)
require(
    "m_bUPnPRouteRecoveryPending = true;" in dialog
    and "network route restored; mapper recovery round=" in dialog
    and "m_bUPnPRouteRecoveryPending = false;" in dialog,
    "temporary route loss must retain an explicit bounded recovery obligation",
)
suspend = dialog[
    dialog.index("case PBT_APMSUSPEND:")
    : dialog.index("return FALSE; // we do not process this message")
]
require(
    "m_bUPnPResumeMappingRequired" in suspend
    and suspend.index("SetMessageOnResult(NULL, 0)")
    < suspend.index("StopAsyncFind();")
    < suspend.index("m_mappingResultGate.CancelPending();")
    < suspend.index("m_mappingResultMailbox->Clear();"),
    "suspend must fence and drain an in-flight mapper result before sleeping",
)
require(
    "if (resumeMappingRequired)" in resume
    and "StartUPnP(" in resume,
    "resume must replace a suspended request with fresh discovery",
)
require(
    "resumeMappingRequired || reconnectNetworks" in resume,
    "a suspended mapper request must restart even when startup delayed all networks",
)
require(
    "if (reconnectNetworks)" in resume
    and resume.rindex("if (reconnectNetworks)")
    < resume.index("PostMessage(WM_SYSCOMMAND, MP_CONNECT, 0)"),
    "resume must reconnect networks only when they were active before suspend",
)
require(
    "m_bUPnPResumeMappingRequired || mapperRequestPending" in suspend
    and "if (mapperRequestPending" in suspend,
    "repeated suspend notifications must not erase a pending resume obligation",
)
start = dialog[
    dialog.index("void CemuleDlg::StartUPnP(")
    : dialog.index("void CemuleDlg::StopUPnP()")
]
no_route = start[
    start.index("if (!hasRoute) {")
    : start.index("impl->BeginMappingRequest(")
]
require(
    "m_bUPnPRouteRecoveryPending = true;" in no_route
    and "PostLocalUPnPFailure" not in no_route,
    "resume before route restoration must defer discovery without exhausting fallback",
)

print("test_v92_k06_interleavings: 16 checks, 0 failures")
