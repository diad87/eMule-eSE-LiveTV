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

// class to configure the Windows Firewall
// Uses INetFwPolicy2 (Vista+) as primary method, falls back to ICS on WinXP

#include "StdAfx.h"
#include "firewallopener.h"
#include "WindowsFirewallHelper.h"
#include "emule.h"
#include "preferences.h"
#include "otherfunctions.h"
#include "Log.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

// Global modern firewall helper instance (used on Vista+)
static CWindowsFirewallHelper s_modernFirewall;


#define RETURN_ON_FAIL(x)	if (!SUCCEEDED(x)) return false;

CFirewallOpener::CFirewallOpener()
	: m_pINetSM()
	, m_bInited()
{
}

CFirewallOpener::~CFirewallOpener()
{
	UnInit();
}

bool CFirewallOpener::Init(bool bPreInit)
{
	if (!m_bInited) {
		ASSERT(m_liAddedRules.IsEmpty());

		// Try the modern firewall API first (Vista+)
		if (CWindowsFirewallHelper::IsModernFirewallAvailable()) {
			if (s_modernFirewall.Init()) {
				DebugLog(_T("FirewallOpener: Using modern INetFwPolicy2 API"));
				m_bInited = true;
				return true;
			}
			DebugLogWarning(_T("FirewallOpener: Modern API init failed, trying legacy ICS"));
		}

		// Legacy path: ICS-based firewall (WinXP pre-SP2 only)
		if (thePrefs.GetWindowsVersion() != _WINVER_XP_ || !SUCCEEDED(CoInitialize(NULL)))
			return false;
		HRESULT hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_PKT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
		if (!SUCCEEDED(hr) || !SUCCEEDED(CoCreateInstance(__uuidof(NetSharingManager), NULL, CLSCTX_ALL, __uuidof(INetSharingManager), (void**)&m_pINetSM))) {
			CoUninitialize();
			return false;
		}
	}
	m_bInited = true;
	if (bPreInit) {
		return true;
	}

	if (m_pINetSM == NULL && !s_modernFirewall.IsInited()) {
		if (!SUCCEEDED(CoCreateInstance(__uuidof(NetSharingManager), NULL, CLSCTX_ALL, __uuidof(INetSharingManager), (void**)&m_pINetSM))) {
			UnInit();
			return false;
		}
	}
	return true;
}

void CFirewallOpener::UnInit()
{
	if (!m_bInited)
		return;

	for (INT_PTR i = m_liAddedRules.GetCount(); --i >= 0;)
		if (m_liAddedRules[i].m_bRemoveOnExit)
			// Avoid the public removal wrapper here: it also updates the
			// tracking list and would mutate the array while we iterate it.
			DoAction(FOC_DELETERULEEXCACT, m_liAddedRules[i]);

	m_liAddedRules.RemoveAll();

	m_bInited = false;

	// Modern firewall path: cleanup is handled by CWindowsFirewallHelper destructor
	if (s_modernFirewall.IsInited()) {
		// No COM cleanup needed here - handled by CWindowsFirewallHelper
		return;
	}

	// Legacy ICS path cleanup
	if (m_pINetSM != NULL) {
		m_pINetSM->Release();
		m_pINetSM = NULL;
	} else
		ASSERT(0);
	CoUninitialize();
}

bool CFirewallOpener::DoAction(const EFOCAction eAction, const CICSRuleInfo &riPortRule)
{
	if (!Init())
		return false;

	// If the modern firewall API is active, delegate to it
	if (s_modernFirewall.IsInited()) {
		switch (eAction) {
		case FOC_ADDRULE:
			{
				bool bTCP = (riPortRule.m_byProtocol == NAT_PROTOCOL_TCP);
				bool bResult = s_modernFirewall.AddPortRule(
					riPortRule.m_nPortNumber, bTCP, riPortRule.m_strRuleName);
				if (bResult && riPortRule.m_bRemoveOnExit)
					m_liAddedRules.Add(riPortRule); // track for cleanup
				return bResult;
			}
		case FOC_DELETERULEBYNAME:
		case FOC_DELETERULEEXCACT:
			return s_modernFirewall.RemoveRule(riPortRule.m_strRuleName);
		case FOC_FINDRULEBYNAME:
			return s_modernFirewall.DoesRuleExist(riPortRule.m_strRuleName);
		case FOC_FINDRULEBYPORT:
			return s_modernFirewall.DoesPortRuleExist(
				riPortRule.m_nPortNumber,
				riPortRule.m_byProtocol == NAT_PROTOCOL_TCP);
		case FOC_FWCONNECTIONEXISTS:
			return s_modernFirewall.IsFirewallEnabled();
		default:
			ASSERT(0);
			return false;
		}
	}

	// Legacy ICS path (WinXP only)
	bool bSuccess = true;
	bool bPartialSucceeded = false;
	bool bFoundAtLeastOneConn = false;

	INetSharingEveryConnectionCollectionPtr NSECCP;
	IEnumVARIANTPtr varEnum;
	IUnknownPtr pUnk;
	RETURN_ON_FAIL(m_pINetSM->get_EnumEveryConnection(&NSECCP));
	RETURN_ON_FAIL(NSECCP->get__NewEnum(&pUnk));
	RETURN_ON_FAIL(pUnk->QueryInterface(__uuidof(IEnumVARIANT), (void**)&varEnum));

	_variant_t var;
	while (S_OK == varEnum->Next(1, &var, NULL)) {
		INetConnectionPtr NCP;
		if (V_VT(&var) == VT_UNKNOWN
			&& SUCCEEDED(V_UNKNOWN(&var)->QueryInterface(__uuidof(INetConnection), (void**)&NCP)))
		{
			INetConnectionPropsPtr pNCP;
			if (!SUCCEEDED(m_pINetSM->get_NetConnectionProps(NCP, &pNCP)))
				continue;
			DWORD dwCharacteristics = 0;
			pNCP->get_Characteristics(&dwCharacteristics);
			if (dwCharacteristics & (NCCF_FIREWALLED)) {
				NETCON_MEDIATYPE MediaType = NCM_NONE;
				pNCP->get_MediaType(&MediaType);
				if ((MediaType != NCM_SHAREDACCESSHOST_LAN) && (MediaType != NCM_SHAREDACCESSHOST_RAS)) {
					INetSharingConfigurationPtr pNSC;
					if (!SUCCEEDED(m_pINetSM->get_INetSharingConfigurationForINetConnection(NCP, &pNSC)))
						continue;
					VARIANT_BOOL varbool = VARIANT_FALSE;
					pNSC->get_InternetFirewallEnabled(&varbool);
					if (varbool == VARIANT_FALSE)
						continue;
					bFoundAtLeastOneConn = true;
					switch (eAction) {
					case FOC_ADDRULE:
						{
							bool bResult;
							// we do not want to overwrite an existing rule
							if (FindRule(FOC_FINDRULEBYPORT, riPortRule, pNSC, NULL))
								bResult = true;
							else
								bResult = AddRule(riPortRule, pNSC, pNCP);
							bSuccess = bSuccess && bResult;
							if (bResult && !bPartialSucceeded)
								m_liAddedRules.Add(riPortRule); // keep track of added rules
							bPartialSucceeded = bPartialSucceeded || bResult;
							break;
						}
					case FOC_FWCONNECTIONEXISTS:
						return true;
					case FOC_DELETERULEBYNAME:
					case FOC_DELETERULEEXCACT:
						bSuccess = bSuccess && FindRule(eAction, riPortRule, pNSC, NULL);
						break;
					case FOC_FINDRULEBYNAME:
						if (FindRule(FOC_FINDRULEBYNAME, riPortRule, pNSC, NULL))
							return true;
						else
							bSuccess = false;
						break;
					case FOC_FINDRULEBYPORT:
						if (FindRule(FOC_FINDRULEBYPORT, riPortRule, pNSC, NULL))
							return true;
						else
							bSuccess = false;
						break;
					default:
						ASSERT(0);
					}
				}
			}
		}
		var.Clear();
	}
	return bSuccess && bFoundAtLeastOneConn;
}

bool CFirewallOpener::AddRule(const CICSRuleInfo &riPortRule, const INetSharingConfigurationPtr &pNSC, const INetConnectionPropsPtr &pNCP)
{
	INetSharingPortMappingPtr pNSPM;
	HRESULT hr = pNSC->AddPortMapping(riPortRule.m_strRuleName.AllocSysString()
		, riPortRule.m_byProtocol
		, riPortRule.m_nPortNumber
		, riPortRule.m_nPortNumber
		, 0
		, CComBSTR(L"127.0.0.1")
		, ICSTT_IPADDRESS
		, &pNSPM);
	CComBSTR bstrName;
	pNCP->get_Name(&bstrName);
	const CString sName(bstrName);
	if (SUCCEEDED(hr) && SUCCEEDED(pNSPM->Enable())) {
		theApp.QueueDebugLogLine(false, _T("Succeeded to add Rule '%s' for Port '%u' on Connection '%s'"), (LPCTSTR)riPortRule.m_strRuleName, riPortRule.m_nPortNumber, (LPCTSTR)sName);
		return true;
	}
	theApp.QueueDebugLogLine(false, _T("Failed to add Rule '%s' for Port '%u' on Connection '%s'"), (LPCTSTR)riPortRule.m_strRuleName, riPortRule.m_nPortNumber, (LPCTSTR)sName);
	return false;
}

bool CFirewallOpener::FindRule(const EFOCAction eAction, const CICSRuleInfo &riPortRule, const INetSharingConfigurationPtr &pNSC, INetSharingPortMappingPropsPtr *outNSPMP)
{
	INetSharingPortMappingCollectionPtr pNSPMC;
	RETURN_ON_FAIL(pNSC->get_EnumPortMappings(ICSSC_DEFAULT, &pNSPMC));

	INetSharingPortMappingPtr pNSPM;
	IEnumVARIANTPtr varEnum;
	IUnknownPtr pUnk;
	RETURN_ON_FAIL(pNSPMC->get__NewEnum(&pUnk));
	RETURN_ON_FAIL(pUnk->QueryInterface(__uuidof(IEnumVARIANT), (void**)&varEnum));
	_variant_t var;
	while (S_OK == varEnum->Next(1, &var, NULL)) {
		INetSharingPortMappingPropsPtr pNSPMP;
		if (V_VT(&var) == VT_DISPATCH
			&& SUCCEEDED(V_DISPATCH(&var)->QueryInterface(__uuidof(INetSharingPortMapping), (void**)&pNSPM))
			&& SUCCEEDED(pNSPM->get_Properties(&pNSPMP)))
		{
			UCHAR ucProt = 0;
			long uExternal = 0;
			CComBSTR bstrName;
			pNSPMP->get_IPProtocol(&ucProt);
			pNSPMP->get_ExternalPort(&uExternal);
			pNSPMP->get_Name(&bstrName);
			switch (eAction) {
			case FOC_FINDRULEBYPORT:
				if (riPortRule.m_nPortNumber == uExternal && riPortRule.m_byProtocol == ucProt) {
					if (outNSPMP != NULL)
						*outNSPMP = pNSPM;
					return true;
				}
				break;
			case FOC_FINDRULEBYNAME:
				if (riPortRule.m_strRuleName == CString(bstrName)) {
					if (outNSPMP != NULL)
						*outNSPMP = pNSPM;
					return true;
				}
				break;
			case FOC_DELETERULEEXCACT:
				if (riPortRule.m_strRuleName == CString(bstrName)
					&& riPortRule.m_nPortNumber == uExternal && riPortRule.m_byProtocol == ucProt)
				{
					RETURN_ON_FAIL(pNSC->RemovePortMapping(pNSPM));
					theApp.QueueDebugLogLine(false, _T("Rule removed"));
				}
				break;
			case FOC_DELETERULEBYNAME:
				if (riPortRule.m_strRuleName == CString(bstrName)) {
					RETURN_ON_FAIL(pNSC->RemovePortMapping(pNSPM));
					theApp.QueueDebugLogLine(false, _T("Rule removed"));
				}
				break;
			default:
				ASSERT(0);
			}
		}
		var.Clear();
	}

	return (eAction == FOC_DELETERULEBYNAME || eAction == FOC_DELETERULEEXCACT);
}

bool CFirewallOpener::RemoveRule(const CString &strName)
{
	const bool result = DoAction(FOC_DELETERULEBYNAME,
		CICSRuleInfo(0, 0, strName));
	// An explicit remove-by-name is also used before replacing a temporary
	// startup rule with a persistent user rule. Forget the old cleanup token,
	// otherwise shutdown would delete the replacement merely because it shares
	// the same name.
	for (INT_PTR i = m_liAddedRules.GetCount(); --i >= 0;)
		if (m_liAddedRules[i].m_strRuleName == strName)
			m_liAddedRules.RemoveAt(i);
	return result;
}

bool CFirewallOpener::RemoveRule(const CICSRuleInfo &riPortRule)
{
	return DoAction(FOC_DELETERULEEXCACT, riPortRule);
}

bool CFirewallOpener::DoesRuleExist(const CString &strName)
{
	return DoAction(FOC_FINDRULEBYNAME, CICSRuleInfo(0, 0, strName));
}

bool CFirewallOpener::DoesRuleExist(const uint16 nPortNumber, const uint8 byProtocol)
{
	return DoAction(FOC_FINDRULEBYPORT, CICSRuleInfo(nPortNumber, byProtocol, _T("")));
}

bool CFirewallOpener::OpenPort(const uint16 nPortNumber, const uint8 byProtocol, const CString &strRuleName, const bool bRemoveOnExit)
{
	return DoAction(FOC_ADDRULE, CICSRuleInfo(nPortNumber, byProtocol, strRuleName, bRemoveOnExit));
}

bool CFirewallOpener::OpenPort(const CICSRuleInfo &riPortRule)
{
	return DoAction(FOC_ADDRULE, riPortRule);
}

bool CFirewallOpener::DoesFWConnectionExist()
{
	return DoAction(FOC_FWCONNECTIONEXISTS, CICSRuleInfo());
}
