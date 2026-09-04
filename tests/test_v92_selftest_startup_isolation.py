#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "srchybrid" / "Emule.cpp").read_text(encoding="utf-8")
CONNECTION_SOURCE = (ROOT / "srchybrid" / "PPgConnection.cpp").read_text(encoding="utf-8")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def exact_count(needle: str, count: int = 1) -> None:
    actual = SOURCE.count(needle)
    require(actual == count, f"expected {count} occurrence(s) of {needle!r}, found {actual}")


exact_count("\t, m_pFirewallOpener()")
exact_count("if (!m_bSelfTest && thePrefs.IsRunAsUserEnabled())")
exact_count("if (!m_bSelfTest && thePrefs.AutoTakeED2KLinks())")

block_anchor = "\tif (!m_bSelfTest) {\n\t\t// Barry - Auto-take ed2k links"
exact_count(block_anchor)
block_start = SOURCE.index(block_anchor)
block_end = SOURCE.index("\n\t}\n\n\t// UPnP Port forwarding", block_start) + len("\n\t}")
startup_block = SOURCE[block_start:block_end]

guarded_calls = (
    "Ask4RegFix(false, true, false);",
    "SetAutoStart(thePrefs.GetAutoStart());",
    "m_pFirewallOpener = new CFirewallOpener();",
    "m_pFirewallOpener->Init(true);",
    "m_pFirewallOpener->RemoveRule(EMULE_DEFAULTRULENAME_UDP);",
    "m_pFirewallOpener->RemoveRule(EMULE_DEFAULTRULENAME_TCP);",
    "m_pFirewallOpener->OpenPort(thePrefs.GetPort(), NAT_PROTOCOL_TCP",
    "m_pFirewallOpener->OpenPort(thePrefs.GetUDPPort(), NAT_PROTOCOL_UDP",
)
for call in guarded_calls:
    exact_count(call)
    require(call in startup_block, f"selftest guard does not contain {call!r}")

secure_guard = "if (!m_bSelfTest && thePrefs.IsRunAsUserEnabled())"
secure_start = SOURCE.index(secure_guard)
secure_end = SOURCE.index("\n\t}\n\n\tif (thePrefs.GetRTLWindowsLayout())", secure_start)
require("RestartSecure();" in SOURCE[secure_start:secure_end], "secure-user restart escaped selftest guard")
exact_count("RestartSecure();")

revert_guard = "if (!m_bSelfTest && thePrefs.AutoTakeED2KLinks())"
revert_start = SOURCE.index(revert_guard)
revert_end = SOURCE.index("\n\n\t::CloseHandle", revert_start)
require("RevertReg();" in SOURCE[revert_start:revert_end], "registry revert escaped selftest guard")
exact_count("RevertReg();")

command_flag = 'm_bSelfTest    |= (_tcsicmp(pszParam, _T("selftest")) == 0);'
exact_count(command_flag)
init_start = SOURCE.index("BOOL CemuleApp::InitInstance()")
init_end = SOURCE.index("bool CemuleApp::ProcessCommandline()", init_start)
init = SOURCE[init_start:init_end]
process_commandline = init.index("if (ProcessCommandline())")
preferences_init = init.index("thePrefs.Init();")
secure = init.index(secure_guard)
startup = init.index(block_anchor)
modal = init.index("emuledlg->DoModal();")
revert = init.index(revert_guard)
require(
    process_commandline < preferences_init < secure < startup < modal < revert,
    "selftest startup/shutdown guard order changed",
)

handler_start = CONNECTION_SOURCE.index("void CPPgConnection::OnBnClickedOpenports()")
handler_end = CONNECTION_SOURCE.index("\n}\n", handler_start)
handler = CONNECTION_SOURCE[handler_start:handler_end]
handler_guard = "if (theApp.m_bSelfTest || theApp.m_pFirewallOpener == NULL)"
require(CONNECTION_SOURCE.count(handler_guard) == 1, "firewall handler guard must be unique")
require(handler.index(handler_guard) < handler.index("OnApply();"), "firewall handler mutates before guard")
for call in (
    "m_pFirewallOpener->RemoveRule",
    "m_pFirewallOpener->DoesRuleExist",
    "m_pFirewallOpener->OpenPort",
):
    require(call in handler, f"expected firewall handler call missing: {call}")
    require(handler.index(handler_guard) < handler.index(call), f"firewall call escaped handler guard: {call}")

print("v9.2 selftest startup isolation source guard PASS")
