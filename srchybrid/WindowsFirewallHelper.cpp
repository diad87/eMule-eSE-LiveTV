//this file is part of eMule
//Copyright (C)2002-2024 Merkur ( strEmail.Format("%s@%s", "devteam", "emule-project.net") / https://www.emule-project.net )
//
//This program is free software; you can redistribute it and/or
//modify it under the terms of the GNU General Public License
//as published by the Free Software Foundation; either
//version 2 of the License, or (at your option) any later version.
//
//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License
//along with this program; if not, write to the Free Software
//Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

// Modern Windows Firewall helper using INetFwPolicy2 (Vista+)
// Replaces the legacy ICS-based FirewallOpener that only worked on WinXP pre-SP2
//
// The old FirewallOpener used INetSharingManager (ICS API) which:
//   1) Only worked on Windows XP pre-SP2
//   2) Required ICS (Internet Connection Sharing) to be active
//   3) Was completely non-functional on Vista, 7, 8, 10, 11
//
// This new implementation uses INetFwPolicy2 which:
//   1) Works on Windows Vista through Windows 11
//   2) Directly manages Windows Firewall rules (no ICS dependency)
//   3) Can add inbound allow rules for eMule's TCP and UDP ports
//   4) Properly handles rule uniqueness (removes old rules before adding)

#include "StdAfx.h"
#include "WindowsFirewallHelper.h"
#include "Log.h"
#include "OtherFunctions.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

// CLSID and IID for NetFwPolicy2 - defined here to avoid linker issues
// {E2B3C97F-6AE1-41AC-817A-F6F92166D7DD}
static const CLSID CLSID_NetFwPolicy2_ =
	{0xE2B3C97F, 0x6AE1, 0x41AC, {0x81, 0x7A, 0xF6, 0xF9, 0x21, 0x66, 0xD7, 0xDD}};

// {98325047-C671-4174-8D81-DEFCD3F03186}
static const CLSID CLSID_NetFwRule_ =
	{0x2C5BC43E, 0x3369, 0x4C33, {0xAB, 0x0C, 0xBE, 0x94, 0x69, 0x67, 0x7A, 0xF4}};


CWindowsFirewallHelper::CWindowsFirewallHelper()
	: m_pPolicy(NULL)
	, m_bInited(false)
	, m_bCOMInitialized(false)
{
}

CWindowsFirewallHelper::~CWindowsFirewallHelper()
{
	UnInit();
}

bool CWindowsFirewallHelper::IsModernFirewallAvailable()
{
	// INetFwPolicy2 is available on Windows Vista and later
	OSVERSIONINFOEX osvi = {};
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	// Vista = 6.0. We need >= 6.0
	// Use a simple version check - any modern Windows will pass
	osvi.dwMajorVersion = 6;
	DWORDLONG dwlConditionMask = 0;
	VER_SET_CONDITION(dwlConditionMask, VER_MAJORVERSION, VER_GREATER_EQUAL);
	return VerifyVersionInfo(&osvi, VER_MAJORVERSION, dwlConditionMask) != FALSE;
}

bool CWindowsFirewallHelper::Init()
{
	if (m_bInited)
		return true;

	if (!IsModernFirewallAvailable()) {
		DebugLogWarning(_T("WindowsFirewallHelper: Modern firewall API not available (pre-Vista OS)"));
		return false;
	}

	HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	if (SUCCEEDED(hr) || hr == S_FALSE) {
		m_bCOMInitialized = (hr != S_FALSE); // only uninit if we initialized
	} else {
		DebugLogError(_T("WindowsFirewallHelper: CoInitializeEx failed: 0x%08X"), hr);
		return false;
	}

	if (!InitPolicy()) {
		if (m_bCOMInitialized) {
			CoUninitialize();
			m_bCOMInitialized = false;
		}
		return false;
	}

	m_bInited = true;
	DebugLog(_T("WindowsFirewallHelper: Successfully initialized (INetFwPolicy2)"));
	return true;
}

bool CWindowsFirewallHelper::InitPolicy()
{
	HRESULT hr = CoCreateInstance(
		__uuidof(NetFwPolicy2), NULL,
		CLSCTX_INPROC_SERVER,
		__uuidof(INetFwPolicy2),
		(void**)&m_pPolicy);

	if (FAILED(hr) || m_pPolicy == NULL) {
		DebugLogError(_T("WindowsFirewallHelper: Failed to create INetFwPolicy2 instance: 0x%08X"), hr);
		m_pPolicy = NULL;
		return false;
	}

	return true;
}

void CWindowsFirewallHelper::ReleasePolicy()
{
	if (m_pPolicy != NULL) {
		m_pPolicy->Release();
		m_pPolicy = NULL;
	}
}

void CWindowsFirewallHelper::UnInit()
{
	if (!m_bInited)
		return;

	ReleasePolicy();

	if (m_bCOMInitialized) {
		CoUninitialize();
		m_bCOMInitialized = false;
	}

	m_bInited = false;
}

bool CWindowsFirewallHelper::IsFirewallEnabled()
{
	if (!m_bInited && !Init())
		return false;

	// Check if the firewall is enabled for any profile
	VARIANT_BOOL bEnabled = VARIANT_FALSE;

	// Check current profile(s)
	long profilesBitmask = 0;
	HRESULT hr = m_pPolicy->get_CurrentProfileTypes(&profilesBitmask);
	if (FAILED(hr))
		return false;

	hr = m_pPolicy->get_FirewallEnabled((NET_FW_PROFILE_TYPE2)profilesBitmask, &bEnabled);
	if (FAILED(hr))
		return false;

	return (bEnabled == VARIANT_TRUE);
}

bool CWindowsFirewallHelper::AddPortRule(uint16 nPort, bool bTCP, LPCTSTR szRuleName, LPCTSTR szDescription)
{
	if (!m_bInited && !Init())
		return false;

	// First, remove any existing rule with this name to avoid duplicates
	RemoveRule(szRuleName);

	INetFwRules *pRules = NULL;
	HRESULT hr = m_pPolicy->get_Rules(&pRules);
	if (FAILED(hr) || pRules == NULL) {
		DebugLogError(_T("WindowsFirewallHelper: Failed to get firewall rules collection: 0x%08X"), hr);
		return false;
	}

	INetFwRule *pRule = NULL;
	hr = CoCreateInstance(
		__uuidof(NetFwRule), NULL,
		CLSCTX_INPROC_SERVER,
		__uuidof(INetFwRule),
		(void**)&pRule);

	if (FAILED(hr) || pRule == NULL) {
		DebugLogError(_T("WindowsFirewallHelper: Failed to create INetFwRule: 0x%08X"), hr);
		pRules->Release();
		return false;
	}

	// Configure the rule
	CString sPort;
	sPort.Format(_T("%hu"), nPort);

	CString sDesc;
	if (szDescription != NULL)
		sDesc = szDescription;
	else
		sDesc.Format(_T("eMule %s port %hu"), bTCP ? _T("TCP") : _T("UDP"), nPort);

	// Get the full path to the current executable
	TCHAR szExePath[MAX_PATH];
	GetModuleFileName(NULL, szExePath, MAX_PATH);

	pRule->put_Name(CComBSTR(szRuleName));
	pRule->put_Description(CComBSTR(sDesc));
	pRule->put_ApplicationName(CComBSTR(szExePath));
	pRule->put_Protocol(bTCP ? NET_FW_IP_PROTOCOL_TCP : NET_FW_IP_PROTOCOL_UDP);
	pRule->put_LocalPorts(CComBSTR(sPort));
	pRule->put_Direction(NET_FW_RULE_DIR_IN);
	pRule->put_Action(NET_FW_ACTION_ALLOW);
	pRule->put_Enabled(VARIANT_TRUE);
	// Apply to all profiles (Domain, Private, Public)
	pRule->put_Profiles(NET_FW_PROFILE2_ALL);
	pRule->put_Grouping(CComBSTR(_T("eMule")));

	hr = pRules->Add(pRule);

	bool bSuccess = SUCCEEDED(hr);
	if (bSuccess)
		DebugLog(_T("WindowsFirewallHelper: Successfully added firewall rule '%s' for %s port %hu"),
			szRuleName, bTCP ? _T("TCP") : _T("UDP"), nPort);
	else
		DebugLogError(_T("WindowsFirewallHelper: Failed to add firewall rule '%s': 0x%08X"), szRuleName, hr);

	pRule->Release();
	pRules->Release();

	return bSuccess;
}

bool CWindowsFirewallHelper::RemoveRule(LPCTSTR szRuleName)
{
	if (!m_bInited && !Init())
		return false;

	INetFwRules *pRules = NULL;
	HRESULT hr = m_pPolicy->get_Rules(&pRules);
	if (FAILED(hr) || pRules == NULL)
		return false;

	hr = pRules->Remove(CComBSTR(szRuleName));

	bool bSuccess = SUCCEEDED(hr);
	if (bSuccess)
		DebugLog(_T("WindowsFirewallHelper: Removed firewall rule '%s'"), szRuleName);
	// Don't log error for rule not found - this is expected when cleaning up

	pRules->Release();
	return bSuccess;
}

bool CWindowsFirewallHelper::DoesRuleExist(LPCTSTR szRuleName)
{
	if (!m_bInited && !Init())
		return false;

	INetFwRules *pRules = NULL;
	HRESULT hr = m_pPolicy->get_Rules(&pRules);
	if (FAILED(hr) || pRules == NULL)
		return false;

	INetFwRule *pRule = NULL;
	hr = pRules->Item(CComBSTR(szRuleName), &pRule);

	bool bExists = SUCCEEDED(hr) && pRule != NULL;

	if (pRule != NULL)
		pRule->Release();
	pRules->Release();

	return bExists;
}

bool CWindowsFirewallHelper::DoesPortRuleExist(uint16 nPort, bool bTCP)
{
	if (!m_bInited && !Init())
		return false;

	INetFwRules *pRules = NULL;
	HRESULT hr = m_pPolicy->get_Rules(&pRules);
	if (FAILED(hr) || pRules == NULL)
		return false;

	// Enumerate all rules to find one matching our port and protocol
	IUnknown *pEnumUnk = NULL;
	hr = pRules->get__NewEnum(&pEnumUnk);
	if (FAILED(hr) || pEnumUnk == NULL) {
		pRules->Release();
		return false;
	}

	IEnumVARIANT *pEnum = NULL;
	hr = pEnumUnk->QueryInterface(__uuidof(IEnumVARIANT), (void**)&pEnum);
	pEnumUnk->Release();
	if (FAILED(hr) || pEnum == NULL) {
		pRules->Release();
		return false;
	}

	bool bFound = false;
	VARIANT var;
	VariantInit(&var);
	ULONG cFetched = 0;

	CString sTargetPort;
	sTargetPort.Format(_T("%hu"), nPort);
	long nTargetProtocol = bTCP ? NET_FW_IP_PROTOCOL_TCP : NET_FW_IP_PROTOCOL_UDP;

	while (!bFound && pEnum->Next(1, &var, &cFetched) == S_OK && cFetched == 1) {
		INetFwRule *pRule = NULL;
		if (V_VT(&var) == VT_DISPATCH
			&& SUCCEEDED(V_DISPATCH(&var)->QueryInterface(__uuidof(INetFwRule), (void**)&pRule)))
		{
			long nProtocol = 0;
			BSTR bsLocalPorts = NULL;
			NET_FW_RULE_DIRECTION dir = NET_FW_RULE_DIR_MAX;
			NET_FW_ACTION action = NET_FW_ACTION_MAX;
			VARIANT_BOOL bEnabled = VARIANT_FALSE;

			pRule->get_Protocol(&nProtocol);
			pRule->get_LocalPorts(&bsLocalPorts);
			pRule->get_Direction(&dir);
			pRule->get_Action(&action);
			pRule->get_Enabled(&bEnabled);

			if (nProtocol == nTargetProtocol
				&& dir == NET_FW_RULE_DIR_IN
				&& action == NET_FW_ACTION_ALLOW
				&& bEnabled == VARIANT_TRUE
				&& bsLocalPorts != NULL
				&& sTargetPort.CompareNoCase(bsLocalPorts) == 0)
			{
				bFound = true;
			}

			SysFreeString(bsLocalPorts);
			pRule->Release();
		}
		VariantClear(&var);
	}

	pEnum->Release();
	pRules->Release();

	return bFound;
}

bool CWindowsFirewallHelper::EnsureEmulePorts(uint16 nTCPPort, uint16 nUDPPort)
{
	if (!m_bInited && !Init())
		return false;

	// Only proceed if firewall is actually enabled
	if (!IsFirewallEnabled()) {
		DebugLog(_T("WindowsFirewallHelper: Windows Firewall is disabled, no rules needed"));
		return true; // Not an error - firewall is off
	}

	DebugLog(_T("WindowsFirewallHelper: Ensuring eMule firewall rules for TCP:%hu UDP:%hu"), nTCPPort, nUDPPort);

	// Remove any old eMule rules first
	RemoveEmuleRules();

	// Add TCP rule
	bool bResult = AddPortRule(nTCPPort, true, _T("eMule TCP"),
		_T("eMule P2P file sharing - TCP port (required for High ID)"));

	if (!bResult) {
		DebugLogError(_T("WindowsFirewallHelper: Failed to add TCP rule for port %hu"), nTCPPort);
		return false;
	}

	// Add UDP rule if UDP port is configured
	if (nUDPPort != 0) {
		bResult = AddPortRule(nUDPPort, false, _T("eMule UDP"),
			_T("eMule P2P file sharing - UDP port (required for Kademlia)"));

		if (!bResult) {
			DebugLogError(_T("WindowsFirewallHelper: Failed to add UDP rule for port %hu"), nUDPPort);
			// Don't return false - TCP rule was added successfully
			// UDP is important but not strictly required for High ID
		}
	}

	DebugLog(_T("WindowsFirewallHelper: eMule firewall rules configured successfully"));
	return true;
}

bool CWindowsFirewallHelper::RemoveEmuleRules()
{
	if (!m_bInited && !Init())
		return false;

	// Remove rules by the names we create them with
	RemoveRule(_T("eMule TCP"));
	RemoveRule(_T("eMule UDP"));

	// Also remove legacy rule names from old FirewallOpener
	RemoveRule(_T("eMule_TCP_Port"));
	RemoveRule(_T("eMule_UDP_Port"));

	return true;
}
