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
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License
//along with this program; if not, write to the Free Software
//Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#pragma once
#include "UPnPImpl.h"
#include "natmap/ownership_ledger.h"

#include <atomic>
#include <string>

struct UPNPUrls;
struct IGDdatas;

class CUPnPImplMiniLib : public CUPnPImpl
{
public:
	CUPnPImplMiniLib();
	virtual	~CUPnPImplMiniLib();

	virtual void StartDiscovery(uint16 nTCPPort, uint16 nUDPPort, uint16 nTCPWebPort);
	virtual bool CheckAndRefresh();
	virtual void StopAsyncFind();
	virtual bool DeferDestructionIfWorkerActive();
	virtual void DeletePorts();
	virtual bool IsReady();
	virtual int GetImplementationID()				{ return UPNP_IMPL_MINIUPNPLIB; }
	virtual natmap::MapperKind GetMapperKind() const
		{ return natmap::MapperKind::UpnpIgd; }
	virtual natmap::MapperSource GetMapperSource() const
		{ return natmap::MapperSource::UpnpIgd; }
	static bool RunDeferredReaperSelfTest();

	class CStartDiscoveryThread
	{
	public:
		explicit CStartDiscoveryThread(CUPnPImplMiniLib* owner);
		static DWORD WINAPI ThreadProc(void* context) noexcept;
		DWORD Run();

	private:
		bool OpenPort(
			uint16 nPort,
			bool bTCP,
			char *pachLANIP,
			bool bCheckAndRefresh,
			bool *pReadbackMatches = NULL,
			bool *pOwnershipMatches = NULL,
			bool *pCreatedByOperation = NULL);

		void SendFailure(natmap::ReasonCode reason);
		CUPnPImplMiniLib *m_pOwner;
		MappingOperationContext m_operation;
	};

protected:
	void DeletePorts(bool bSkipLock);

private:
	friend class CUPnPMiniLibDeferredReaper;
	void Cleanup();
	bool ReapCompletedWorker();
	void DeletePort(uint16 port, LPCTSTR prot);
	void GetOldPorts();
	void StartThread();
	void LoadOwnershipLedger();
	bool SaveOwnershipLedger();
	void RecoverOwnedMappings();
	natmap::OwnershipDecision PreflightOwnedMapping(
		const natmap::UpnpOwnershipRecord& record) const;
	natmap::OwnershipDecision ObserveOwnedMapping(
		const natmap::UpnpOwnershipRecord& record, bool& absent) const;
	bool CleanupOwnedRecordAttempt(
		const natmap::UpnpOwnershipRecord& record,
		bool& deleteSucceeded, bool& absenceVerified);
	bool RecordOwnedMapping(uint16 nLocalPort, uint16 nExternalPort,
		bool bTCP, const char* pachLANIP, uint32 nLifetimeSeconds,
		const natmap::OwnershipDescription& description);
	bool DeleteEphemeralOwnedMapping(uint16 nLocalPort,
		uint16 nExternalPort, bool bTCP, const char* pachLANIP,
		uint32 nLifetimeSeconds,
		const natmap::OwnershipDescription& description,
		const char* observedClient, const char* observedPort,
		const char* observedDescription,
		std::size_t observedDescriptionCapacity);
	void RemoveOwnershipRecord(std::size_t index);
	bool RemoveOwnershipRecordDurably(std::size_t index);
	std::uint64_t CurrentGatewayFingerprint() const;
	static bool GenerateOwnerToken(std::uint64_t& token);
	static bool ParseIPv4(const char* text, natmap::IpAddress& address);

	HANDLE m_hBusyMutex;
	CRITICAL_SECTION m_workerGlobalGate;

	UPNPUrls *m_pURLs;
	IGDdatas *m_pIGDData;
	// Owned raw Win32 worker handle and its heap context.
	HANDLE m_hThreadHandle;
	CStartDiscoveryThread* m_pWorkerThread;
	char m_achLanIP[40];
	char m_achWanIP[40];
	natmap::OwnershipLedger m_ownershipLedger;
	std::uint64_t m_ownerToken;
	std::uint64_t m_mappingGeneration;
	natmap::IpAddress m_mappingLocalAddress;
	natmap::IpAddress m_mappingGatewayAddress;
	bool m_bOwnershipLedgerLoaded;
	std::string m_bindAddressSnapshot;
	std::wstring m_journalPathSnapshot;

	bool m_bSucceededOnce;
	bool m_bDeferredReap;
	DWORD m_stopTimeoutMilliseconds;
	HANDLE m_testDeletionEvent;
	std::atomic_bool m_bAbortDiscovery;
};
