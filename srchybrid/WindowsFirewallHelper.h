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

#pragma once

#include <netfw.h>

class CWindowsFirewallHelper
{
public:
	CWindowsFirewallHelper();
	~CWindowsFirewallHelper();

	// Initialize/cleanup COM interfaces
	bool	Init();
	void	UnInit();
	bool	IsInited() const							{ return m_bInited; }

	// Core operations - these match the old CFirewallOpener interface signatures
	bool	AddPortRule(uint16 nPort, bool bTCP, LPCTSTR szRuleName, LPCTSTR szDescription = NULL);
	bool	RemoveRule(LPCTSTR szRuleName);
	bool	DoesRuleExist(LPCTSTR szRuleName);
	bool	DoesPortRuleExist(uint16 nPort, bool bTCP);
	bool	IsFirewallEnabled();

	// High-level convenience methods
	bool	EnsureEmulePorts(uint16 nTCPPort, uint16 nUDPPort);
	bool	RemoveEmuleRules();

	// Static helper: check if the modern API is available (Vista+)
	static bool	IsModernFirewallAvailable();

private:
	bool	InitPolicy();
	void	ReleasePolicy();

	INetFwPolicy2	*m_pPolicy;
	bool			m_bInited;
	bool			m_bCOMInitialized;
};
