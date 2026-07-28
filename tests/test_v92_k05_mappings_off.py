#!/usr/bin/env python3
"""K05 regression contract for the mappings-disabled baseline."""

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
require(
    "if (thePrefs.IsUPnPEnabled())\n\t\tStartUPnP();" in dialog,
    "startup must not enter mapper discovery while mappings are disabled",
)
require(
    dialog.count("m_hUPnPLeaseTimer = ::SetTimer") == 1,
    "only StartUPnP may arm the mapper lease timer",
)
require(
    "m_hIPv6HealthTimer = ::SetTimer" in dialog
    and "SEC2MS(30), IPv6HealthTimer" in dialog,
    "IPv6 health scheduling must be independent from the mapper timer",
)
require(
    "if (!theApp.IsRunning() || !thePrefs.IsUPnPEnabled()" in dialog,
    "the lease scheduler must fail closed when mappings are disabled",
)
require(
    "void CemuleDlg::RefreshUPnP(bool bRequestAnswer)\n{\n"
    "\tif (!thePrefs.IsUPnPEnabled())\n\t\treturn;" in dialog,
    "refresh must not create mapper traffic while mappings are disabled",
)
require(
    "if (!thePrefs.IsUPnPEnabled() && !bExplicitRequest)" in dialog
    and "mapping start skipped while automatic mappings are disabled" in dialog,
    "automatic mapper start must fail closed after an ON-to-OFF transition",
)
require(
    "if (!thePrefs.IsUPnPEnabled() && !m_bUPnPExplicitRequest)" in dialog
    and "discarded mapper callback while automatic mappings are disabled" in dialog,
    "late mapper callbacks must fail closed after mappings are disabled",
)
require(
    "void CemuleDlg::StopUPnP()" in dialog
    and "m_mappingResultGate.CancelPending();" in dialog
    and "impl->StopAsyncFind();" in dialog
    and "impl->DeletePortsForGeneration(generation);" in dialog,
    "disabling mappings must cancel pending work and clean up owned mappings",
)

connection_page = source("srchybrid/PPgConnection.cpp")
require(
    "if (!enableUPnP)\n\t\t\ttheApp.emuledlg->StopUPnP();" in connection_page
    and "thePrefs.m_bEnableUPnP = enableUPnP;" in connection_page,
    "the preference transition must stop mapper activity before publishing OFF",
)

wizard = source("srchybrid/PShtWiz1.cpp")
require(
    "true, GetTCPPort(), GetUDPPort(), true);" in wizard,
    "the wizard's user-initiated mapper probe must remain an explicit exception",
)

miniupnp = source("srchybrid/UPnPImplMiniLib.cpp")
require(
    miniupnp.count("LoadOwnershipLedger();") == 1
    and "void CUPnPImplMiniLib::StartDiscovery" in miniupnp,
    "the ownership journal may be loaded only from mapper discovery",
)
require(
    "m_bOwnershipLedgerLoaded()\n\t, m_bSucceededOnce()" in miniupnp,
    "the mapper constructor must leave the ownership journal inactive",
)

wrapper = source("srchybrid/UPnPImplWrapper.cpp")
require(
    "StartDiscovery(" not in wrapper,
    "constructing the mapper wrapper must not open discovery sockets",
)

manager = source("srchybrid/DirectReachabilityManager.cpp")
require(
    "m_nAdvertisedTcpPort.store(nLocalTcpPort" in manager
    and "m_nAdvertisedUdpPort.store(nLocalUdpPort" in manager,
    "the disabled baseline must initialize advertised ports to classic locals",
)
require(
    "bool CDirectReachabilityManager::DisableMappingsByPreference()" in manager
    and "natmap::ReasonCode::DisabledByPreference" in manager,
    "runtime OFF must withdraw mapper-derived advertised ports",
)

app = source("srchybrid/Emule.cpp")
require(
    "? directreachability->GetAdvertisedTcpPort() : thePrefs.GetLocalTcpPort()"
    in app
    and "? directreachability->GetAdvertisedUdpPort() : thePrefs.GetLocalUdpPort()"
    in app,
    "advertised getters must preserve classic local fallback",
)

preferences = source("srchybrid/Preferences.cpp")
require(
    'ini.GetBool(_T("EnableUPnP"), true, _T("UPnP"))' in preferences,
    "the legacy EnableUPnP key and its established missing-key default must remain stable",
)
require(
    'ini.WriteBool(_T("EnableUPnP"), m_bEnableUPnP, _T("UPnP"))'
    in preferences,
    "an explicit legacy OFF value must continue to round-trip",
)

print("test_v92_k05_mappings_off: 18 checks, 0 failures")
