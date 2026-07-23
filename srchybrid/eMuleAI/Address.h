//This file is part of eMule AI
//Copyright (C)2013 David Xanatos ( XanatosDavid (a) gmail.com / http://NeoLoader.to )
//Copyright (C)2026 eMule AI
//
#pragma once
#include <string>
#include "kademlia/utils/UInt128.h"

class CAddress
{
  public:
    enum EAF
    {
        None = 0,
        IPv4,
        IPv6
    };

    CAddress(EAF eAF = None);
    explicit CAddress(const byte* IP);
    explicit CAddress(CString IP, const bool bCheckForIntegerIPv4);
    explicit CAddress(uint32 IP, bool bReverse);
    explicit CAddress(Kademlia::CUInt128 IP, bool bReverse);
    virtual ~CAddress();

    bool operator < (const CAddress &Other) const;
    bool operator > (const CAddress &Other) const;
    bool operator == (const CAddress &Other) const;
    bool operator != (const CAddress &Other) const;

    const bool      FromString(const std::string Str, const bool bCheckForIntegerIPv4);
    const bool      FromString(const CString Str, const bool bCheckForIntegerIPv4);
    const std::string ToString() const;
    const std::wstring ToStringW() const;
    const CString	ToStringC() const;
    const Kademlia::CUInt128 ToUInt128(bool bReverse) const;
    const uint32	ToUInt32(bool bReverse) const;
    const bool		IsNull() const;
    const bool		IsMappedIPv4() const;
    const bool      IsPublicIP() const;
    const bool		Convert(const EAF eAF);
    void			FromSA(const sockaddr* sa, const int sa_len, uint16* pPort = NULL) ;
    void			ToSA(sockaddr* sa, int *sa_len, const uint16 uPort = 0) const;
    const int		GetAF() const;
    const EAF		GetType() const;
    const unsigned char* 	Data() const;
    const size_t	GetSize() const;

    // ── v0.71 IPv6 Sprint 1 — wire serialization, hashing, subnet ops ──
    // Wire format: [family 1B] [length 1B] [addr length B]
    //   family=0 None : length=0, 0-byte addr   (total 2 bytes)
    //   family=4 IPv4 : length=4, 4-byte addr   (total 6 bytes)
    //   family=6 IPv6 : length=16, 16-byte addr (total 18 bytes)
    // ReadFromBuffer returns false on malformed wire data.
    void			WriteToBuffer(class CSafeMemFile* file) const;
    bool			ReadFromBuffer(class CSafeMemFile* file);

    // CMap<CAddress, ...> support — collides only on weak (full-byte) flips.
    UINT			HashKey() const;

    // Subnet ops for anti-Sybil and PeX diversity.
    // prefixBits is 0..32 for IPv4 and 0..128 for IPv6.
    CAddress		GetSubnet(int prefixBits) const;
    bool			InSameSubnet(const CAddress& other, int prefixBits) const;

    // Host-order convenience matching Kad's convention. (m_uIp in Contact is
    // historically host-order, m_uNetIp network-order; ToUInt32(bool) already
    // serves both via the bReverse param. These wrappers are sugar.)
    static CAddress FromKadHostOrder(uint32 hostIp);
    uint32			ToKadHostOrder() const;

    // Synthetic uint32 representation of an IPv6 address. Lossy by design:
    // intended ONLY for legacy data structures (e.g. CClientList CMap key)
    // that haven't yet been migrated to CAddress. Never goes on the wire.
    // High bit (0x80000000) is forced set to avoid collision with real v4.
    uint32			ToSyntheticUInt32() const;

  protected:
    byte			m_IP[16];
    EAF				m_eAF;
};

const char* _inet_ntop(const int af, const void* src, char* dst, const int size);
const int _inet_pton(const int af, const char* src, const void* dst);

static const bool IsNullIP(Kademlia::CUInt128 IP) { return IP.m_uData[0] == 0 && IP.m_uData[1] == 0 && (IP.m_uData[2] == 0 || IP.m_uData[2] == 0xffff0000) && IP.m_uData[3] == 0; }

// eMule AI: Below functions are inlined for faster execution.
__inline uint32 _ntohl(uint32 IP)
{
    uint32 ReverseIP;
    ((byte*)&ReverseIP)[0] = ((byte*)&IP)[3];
    ((byte*)&ReverseIP)[1] = ((byte*)&IP)[2];
    ((byte*)&ReverseIP)[2] = ((byte*)&IP)[1];
    ((byte*)&ReverseIP)[3] = ((byte*)&IP)[0];
    return ReverseIP;
}

__inline uint16 _ntohs(uint16 PT)
{
    uint16 TP;
    ((byte*)&TP)[0] = ((byte*)&PT)[1];
    ((byte*)&TP)[1] = ((byte*)&PT)[0];
    return TP;
}

__inline const Kademlia::CUInt128 ntohl(const Kademlia::CUInt128 &ulIP)
{
    Kademlia::CUInt128 ReverseIP;
    for (int iIndex = 4; --iIndex >= 0;) 
        ReverseIP.m_uData[iIndex] = _ntohl(ulIP.m_uData[iIndex]);
    return ReverseIP;
}
