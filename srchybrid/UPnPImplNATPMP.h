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

// NAT-PMP (RFC 6886) implementation for automatic port forwarding
// NAT-PMP is simpler and more reliable than UPnP for many routers
// Supported by Apple AirPort, many OpenWrt/DD-WRT routers, and pfSense

#pragma once
#include "UPnPImpl.h"

class CUPnPImplNATPMP : public CUPnPImpl
{
public:
    CUPnPImplNATPMP();
    virtual ~CUPnPImplNATPMP();

    virtual void StartDiscovery(uint16 nTCPPort, uint16 nUDPPort, uint16 nTCPWebPort);
    virtual bool CheckAndRefresh();
    virtual void StopAsyncFind();
    virtual void DeletePorts();
    virtual bool IsReady();
    virtual int  GetImplementationID()  { return UPNP_IMPL_NATPMP; }

    // Thread class for async discovery
    class CStartDiscoveryThread : public CWinThread
    {
        DECLARE_DYNCREATE(CStartDiscoveryThread)
    protected:
        CStartDiscoveryThread();

    public:
        virtual BOOL InitInstance();
        virtual int Run();
        void SetValues(CUPnPImplNATPMP *pOwner) { m_pOwner = pOwner; }

    private:
        CUPnPImplNATPMP *m_pOwner;
    };

protected:
    void DeletePorts(bool bSkipLock);

private:
    // NAT-PMP protocol constants (RFC 6886)
    static const uint16 NATPMP_PORT = 5351;
    static const uint8  NATPMP_VERSION = 0;
    // Opcodes
    static const uint8  NATPMP_OP_EXTERNALADDR = 0;
    static const uint8  NATPMP_OP_MAP_UDP = 1;
    static const uint8  NATPMP_OP_MAP_TCP = 2;
    // Response opcodes = opcode + 128
    static const uint8  NATPMP_RESP_EXTERNALADDR = 128;
    static const uint8  NATPMP_RESP_MAP_UDP = 129;
    static const uint8  NATPMP_RESP_MAP_TCP = 130;
    // Result codes
    static const uint16 NATPMP_RESULT_SUCCESS = 0;
    static const uint16 NATPMP_RESULT_UNSUPPORTED_VERSION = 1;
    static const uint16 NATPMP_RESULT_NOT_AUTHORIZED = 2;
    static const uint16 NATPMP_RESULT_NETWORK_FAILURE = 3;
    static const uint16 NATPMP_RESULT_OUT_OF_RESOURCES = 4;
    static const uint16 NATPMP_RESULT_UNSUPPORTED_OPCODE = 5;

    // Internal helpers
    static uint32 GetDefaultGateway();
    bool SendMapRequest(SOCKET sock, uint32 gatewayIP, uint16 nPrivatePort, bool bTCP, uint32 nLifetime);
    bool ReceiveMapResponse(SOCKET sock, uint16 &nMappedPort, uint32 &nLifetime);
    bool SendExternalAddrRequest(SOCKET sock, uint32 gatewayIP);
    bool ReceiveExternalAddrResponse(SOCKET sock, uint32 &nExternalIP);

    bool MapPort(uint32 gatewayIP, uint16 nPort, bool bTCP, uint32 nLifetime);
    bool UnmapPort(uint32 gatewayIP, uint16 nPort, bool bTCP);

    void StartThread();

    static CMutex m_mutBusy;

    uint32 m_dwGatewayIP;
    HANDLE m_hThreadHandle;

    bool m_bSucceededOnce;
    volatile bool m_bAbortDiscovery;
};
