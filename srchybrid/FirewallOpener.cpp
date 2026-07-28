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
#include "natmap/instance_isolation.h"
#include <bcrypt.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

// Global modern firewall helper instance (used on Vista+)
static CWindowsFirewallHelper s_modernFirewall;

namespace {

const TCHAR kFirewallOwnerFileName[] = _T("ese_firewall_owner.bin");

bool ReadFirewallOwnerToken(const CString& path, std::uint64_t& token)
{
	token = 0;
	HANDLE file = CreateFile(path, GENERIC_READ, FILE_SHARE_READ,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE)
		return false;
	DWORD read = 0;
	BYTE extra = 0;
	DWORD extraRead = 0;
	const bool ok =
		ReadFile(file, &token, sizeof(token), &read, NULL) != FALSE
		&& read == sizeof(token)
		&& ReadFile(file, &extra, sizeof(extra), &extraRead, NULL) != FALSE
		&& extraRead == 0
		&& token != 0;
	CloseHandle(file);
	if (!ok)
		token = 0;
	return ok;
}

bool LoadOrCreateFirewallOwnerToken(std::uint64_t& token)
{
	const CString configDir =
		thePrefs.GetMuleDirectory(EMULE_CONFIGDIR);
	CString path;
	path.Format(_T("%s\\%s"), static_cast<LPCTSTR>(configDir),
		kFirewallOwnerFileName);
	if (ReadFirewallOwnerToken(path, token))
		return true;
	const DWORD attributes = GetFileAttributes(path);
	if (attributes != INVALID_FILE_ATTRIBUTES)
		return false; // An existing malformed identity is never overwritten.
	const DWORD attributeError = GetLastError();
	if (attributeError != ERROR_FILE_NOT_FOUND
		&& attributeError != ERROR_PATH_NOT_FOUND)
		return false;

	std::uint64_t candidate = 0;
	for (unsigned attempt = 0; attempt < 2 && candidate == 0; ++attempt)
		if (BCryptGenRandom(NULL,
				reinterpret_cast<PUCHAR>(&candidate),
				static_cast<ULONG>(sizeof(candidate)),
				BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
			return false;
	if (candidate == 0)
		return false;

	CString temporaryPath;
	HANDLE file = INVALID_HANDLE_VALUE;
	for (unsigned attempt = 0;
		attempt < 4 && file == INVALID_HANDLE_VALUE; ++attempt)
	{
		std::uint64_t temporaryNonce = 0;
		if (BCryptGenRandom(NULL,
				reinterpret_cast<PUCHAR>(&temporaryNonce),
				static_cast<ULONG>(sizeof(temporaryNonce)),
				BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
			return false;
		temporaryPath.Format(_T("%s\\%s.%016I64x.tmp"),
			static_cast<LPCTSTR>(configDir),
			kFirewallOwnerFileName, temporaryNonce);
		file = CreateFile(temporaryPath, GENERIC_WRITE, 0, NULL,
			CREATE_NEW,
			FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED,
			NULL);
		if (file == INVALID_HANDLE_VALUE
			&& GetLastError() != ERROR_FILE_EXISTS)
			return false;
	}
	if (file == INVALID_HANDLE_VALUE)
		return false;

	DWORD written = 0;
	const bool writtenAndFlushed =
		WriteFile(file, &candidate, sizeof(candidate), &written, NULL) != FALSE
		&& written == sizeof(candidate)
		&& FlushFileBuffers(file) != FALSE;
	CloseHandle(file);
	std::uint64_t verifiedCandidate = 0;
	if (!writtenAndFlushed
		|| !ReadFirewallOwnerToken(temporaryPath, verifiedCandidate)
		|| verifiedCandidate != candidate) {
		DeleteFile(temporaryPath);
		return false;
	}

	if (!MoveFileEx(temporaryPath, path, MOVEFILE_WRITE_THROUGH)) {
		const DWORD moveError = GetLastError();
		DeleteFile(temporaryPath);
		if (moveError == ERROR_ALREADY_EXISTS
			|| moveError == ERROR_FILE_EXISTS)
			return ReadFirewallOwnerToken(path, token);
		return false;
	}
	if (!ReadFirewallOwnerToken(path, token) || token != candidate) {
		token = 0;
		return false;
	}
	return true;
}

} // namespace


#define RETURN_ON_FAIL(x)	if (!SUCCEEDED(x)) return false;

CFirewallOpener::CFirewallOpener()
	: m_pINetSM()
	, m_profileOwnerToken()
	, m_bInited()
{
	if (!LoadOrCreateFirewallOwnerToken(m_profileOwnerToken))
		DebugLogError(_T("FirewallOpener: per-profile owner token unavailable"));
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

	CICSRuleInfo ownedRule;
	const CICSRuleInfo* effectiveRule = &riPortRule;
	if (eAction != FOC_FINDRULEBYPORT
		&& eAction != FOC_FWCONNECTIONEXISTS)
	{
		if (!BuildOwnedRuleInfo(riPortRule, ownedRule)) {
			DebugLogError(_T("FirewallOpener: invalid per-profile rule identity"));
			return false;
		}
		effectiveRule = &ownedRule;
	}
	const CICSRuleInfo& rule = *effectiveRule;

	// If the modern firewall API is active, delegate to it
	if (s_modernFirewall.IsInited()) {
		switch (eAction) {
		case FOC_ADDRULE:
			{
				bool bTCP = (rule.m_byProtocol == NAT_PROTOCOL_TCP);
				bool bResult = s_modernFirewall.AddPortRule(
					rule.m_nPortNumber, bTCP, rule.m_strRuleName,
					m_profileOwnerToken);
				if (bResult && riPortRule.m_bRemoveOnExit)
					m_liAddedRules.Add(riPortRule); // track for cleanup
				return bResult;
			}
		case FOC_DELETERULEBYNAME:
			return s_modernFirewall.RemoveOwnedPortRule(
				0, rule.m_byProtocol == NAT_PROTOCOL_TCP,
				rule.m_strRuleName, m_profileOwnerToken);
		case FOC_DELETERULEEXCACT:
			return s_modernFirewall.RemoveOwnedPortRule(
				rule.m_nPortNumber,
				rule.m_byProtocol == NAT_PROTOCOL_TCP,
				rule.m_strRuleName, m_profileOwnerToken);
		case FOC_FINDRULEBYNAME:
			return s_modernFirewall.DoesRuleExist(rule.m_strRuleName);
		case FOC_FINDRULEBYPORT:
			return s_modernFirewall.DoesPortRuleExist(
				rule.m_nPortNumber,
				rule.m_byProtocol == NAT_PROTOCOL_TCP);
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
							// Reuse only our exact per-profile name. A rule on
							// the same port with another name is foreign and
							// must produce an explicit failure, never borrowed
							// ownership.
							if (FindRule(FOC_FINDRULEBYNAME, rule, pNSC, NULL))
								bResult = true;
							else if (FindRule(FOC_FINDRULEBYPORT, rule, pNSC, NULL))
								bResult = false;
							else
								bResult = AddRule(rule, pNSC, pNCP);
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
						bSuccess = bSuccess && FindRule(eAction, rule, pNSC, NULL);
						break;
					case FOC_FINDRULEBYNAME:
						if (FindRule(FOC_FINDRULEBYNAME, rule, pNSC, NULL))
							return true;
						else
							bSuccess = false;
						break;
					case FOC_FINDRULEBYPORT:
						if (FindRule(FOC_FINDRULEBYPORT, rule, pNSC, NULL))
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

bool CFirewallOpener::BuildOwnedRuleInfo(
	const CICSRuleInfo &source, CICSRuleInfo &owned) const
{
	const bool tcpProtocol =
		source.m_byProtocol == NAT_PROTOCOL_TCP;
	const bool udpProtocol =
		source.m_byProtocol == NAT_PROTOCOL_UDP;
	const bool tcpLogicalName =
		source.m_strRuleName == EMULE_DEFAULTRULENAME_TCP;
	const bool udpLogicalName =
		source.m_strRuleName == EMULE_DEFAULTRULENAME_UDP;
	if ((tcpProtocol && udpLogicalName)
		|| (udpProtocol && tcpLogicalName))
		return false;

	natmap::Transport transport;
	if (tcpProtocol || tcpLogicalName) {
		transport = natmap::Transport::Tcp;
	} else if (udpProtocol || udpLogicalName) {
		transport = natmap::Transport::Udp;
	} else {
		return false;
	}

	const natmap::OwnedFirewallRuleName name =
		natmap::BuildOwnedFirewallRuleName(
			m_profileOwnerToken, transport);
	if (!natmap::IsOwnedFirewallRuleName(
			m_profileOwnerToken, transport, name))
		return false;
	if (source.m_nPortNumber != 0) {
		natmap::FirewallRuleProof proof{};
		proof.profile_owner_token = m_profileOwnerToken;
		proof.transport = transport;
		proof.local_port = source.m_nPortNumber;
		proof.rule_name = name;
		if (natmap::EvaluateFirewallCleanup(
				proof, m_profileOwnerToken, transport,
				source.m_nPortNumber, name) !=
			natmap::FirewallCleanupDecision::Owned)
			return false;
	}
	owned = source;
	owned.m_byProtocol = transport == natmap::Transport::Tcp
		? NAT_PROTOCOL_TCP : NAT_PROTOCOL_UDP;
	owned.m_strRuleName = CString(name.data());
	return true;
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
		theApp.QueueDebugLogLine(false, _T("Succeeded to add owned firewall rule for Port '%u' on Connection '%s'"), riPortRule.m_nPortNumber, (LPCTSTR)sName);
		return true;
	}
	theApp.QueueDebugLogLine(false, _T("Failed to add owned firewall rule for Port '%u' on Connection '%s'"), riPortRule.m_nPortNumber, (LPCTSTR)sName);
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
				if (riPortRule.m_strRuleName == CString(bstrName)
					&& (riPortRule.m_nPortNumber == 0
						|| (riPortRule.m_nPortNumber == uExternal
							&& riPortRule.m_byProtocol == ucProt))) {
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
