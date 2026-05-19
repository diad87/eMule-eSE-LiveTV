//This file is part of eMule AI
//Copyright (C)2013 David Xanatos ( XanatosDavid (a) gmail.com / http://NeoLoader.to )
//Copyright (C)2026 eMule AI
//

#include "stdafx.h"
#include "Address.h"
#include "../SafeFile.h"           // v0.71 IPv6 Sprint 1 — WriteToBuffer/ReadFromBuffer
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wspiapi.h>
#include "kademlia/utils/UInt128.h"

#define EAFNOSUPPORT    102

CAddress::CAddress(EAF eAF)
{
   m_eAF = eAF;
   memset(m_IP, 0, 16);
}

CAddress::CAddress(const byte* IP)
{
    m_eAF = None;
    memset(m_IP, 0, 16);
    memcpy(m_IP, IP, 16);
    if (!Convert(IPv4))
        m_eAF = IPv6;
}

CAddress::CAddress(CString strIP, const bool bCheckForIntegerIPv4)
{
    CAddress::FromString(strIP, bCheckForIntegerIPv4);
}

CAddress::CAddress(uint32 IP, bool bReverse)
{
    m_eAF = IPv4;
    if (bReverse)
        IP = _ntohl(IP);
    memset(m_IP, 0, 16);
    memcpy(m_IP, &IP, 4);
}

CAddress::CAddress(Kademlia::CUInt128 IP, bool bReverse)
{
    m_eAF = None;
    if (bReverse)
        IP = ntohl(IP);
    memset(m_IP, 0, 16);
    memcpy(m_IP, &IP, 16);
    if (!Convert(IPv4))
        m_eAF = IPv6;
}

CAddress::~CAddress()
{
}

bool CAddress::operator < (const CAddress &Other) const
{
    if (m_eAF != Other.m_eAF)
        return m_eAF < Other.m_eAF;
    return memcmp(m_IP, Other.m_IP, GetSize()) < 0;
}

bool CAddress::operator > (const CAddress &Other) const
{
    if (m_eAF != Other.m_eAF)
        return m_eAF > Other.m_eAF;
    return memcmp(m_IP, Other.m_IP, GetSize()) > 0;
}

bool CAddress::operator == (const CAddress &Other) const
{
    return (m_eAF == Other.m_eAF) && memcmp(m_IP, Other.m_IP, GetSize()) == 0;
}

bool CAddress::operator != (const CAddress &Other) const
{
    return !(*this == Other);
}

const uint32 CAddress::ToUInt32(bool bReverse) const
{
    if (m_eAF == IPv4) {
        uint32 ip = 0;
        memcpy(&ip, m_IP, 4);
        if (bReverse)
            ip = _ntohl(ip);
        return ip;
    } else if (m_eAF == IPv6)
        return UINT_MAX;

    return 0;
}

const Kademlia::CUInt128 CAddress::ToUInt128(bool bReverse) const
{
    CAddress IP;
    memcpy(IP.m_IP, m_IP, 16);
    IP.Convert(IPv6);
    Kademlia::CUInt128 IP128(0ul);
    memcpy(&IP128, IP.m_IP, 16);

    if (bReverse)
        IP128 = ntohl(IP128);

    return IP128;
}

const size_t CAddress::GetSize() const
{
    switch (m_eAF)
    {
        case IPv4:	return 4;
        case IPv6:	return 16;
        default:	return 0;
    }
}

const int CAddress::GetAF() const 
{
    return m_eAF == IPv6 ? AF_INET6 : AF_INET;
}

const CAddress::EAF	CAddress::GetType() const
{
    return m_eAF;
}

const unsigned char* CAddress::Data() const
{
    return m_IP;
}

const std::string CAddress::ToString() const
{
    char Dest[65] = {'\0'};
    _inet_ntop(GetAF(), m_IP, Dest, 65);
    return Dest;
}

const std::wstring CAddress::ToStringW() const
{
    std::string s = ToString();
    return std::wstring(s.begin(), s.end());
}

const CString CAddress::ToStringC() const {
    std::string ipv6 = ToString();
    return CString(ipv6.c_str());
}

const bool CAddress::FromString(const std::string Str, const bool bCheckForIntegerIPv4)
{
    m_eAF = None;
    memset(m_IP, 0, 16);

    if (Str.find(".") != std::string::npos)
        m_eAF = IPv4;
    else if (Str.find(":") != std::string::npos)
        m_eAF = IPv6;
    else if (bCheckForIntegerIPv4) {
		// Check if the string is a valid decimal representation of an IPv4 address
		if (!Str.empty() && Str.find_first_not_of("0123456789") == std::string::npos) { // Check if it contains only digits
            // Valid decimal IPv4: 1-10 digits, no leading zero (except single '0'), 1-4294967295
            if (Str.size() == 0 || Str.size() > 10 || (Str.size() > 1 && Str[0] == '0')) {
                ASSERT(0);
                return false;
            }

            unsigned long long ipDec = std::strtoull(Str.c_str(), nullptr, 10);
            if (ipDec == 0 || ipDec > 0xFFFFFFFFULL) {
                ASSERT(0);
                return false;
            }

            uint32_t ipNet = htonl(static_cast<uint32_t>(ipDec));
            m_eAF = IPv4;
            memcpy(m_IP, &ipNet, sizeof(ipNet));
            return true;
        }

        ASSERT(0);
        return false;
    } else {
        ASSERT(0);
        return false;
    }

    bool retval = (_inet_pton(GetAF(), Str.c_str(), m_IP) == 1);

    if (m_eAF == IPv6)
        Convert(IPv4);

    return retval;
}

const bool CAddress::FromString(const CString Str, const bool bCheckForIntegerIPv4)
{
    CT2CA pszConvertedAnsiString(Str);
    std::string ipstr(pszConvertedAnsiString);
    return CAddress::FromString(ipstr, bCheckForIntegerIPv4);
}

void CAddress::FromSA(const sockaddr* sa, const int sa_len, uint16* pPort)
{
    switch (sa->sa_family)
    {
        case AF_INET: {
            ASSERT(sizeof(sockaddr_in) == sa_len);
            sockaddr_in* sa4 = (sockaddr_in*)sa;

            m_eAF = IPv4;
            *((uint32*)m_IP) = sa4->sin_addr.s_addr;
            if (pPort)
                *pPort = ntohs(sa4->sin_port);
            break;
        }
        case AF_INET6: {
            ASSERT(sizeof(sockaddr_in6) == sa_len);
            sockaddr_in6* sa6 = (sockaddr_in6*)sa;

            m_eAF = IPv6;
            memcpy(m_IP, &sa6->sin6_addr, 16);
            if (pPort)
                *pPort  = ntohs(sa6->sin6_port);

            if (!Convert(IPv4))
                m_eAF = IPv6;

            break;
        }
        default: {
            //WiZaRd: happens e.g. when a disconnect occurs and we don't have the IP, yet
            m_eAF = None;
            memset(m_IP, 0, 16);
            break;
        }
    }
}

void CAddress::ToSA(sockaddr* sa, int *sa_len, const uint16 uPort) const
{
    switch (m_eAF)
    {
        case IPv4: {
            ASSERT(sizeof(sockaddr_in) <= *sa_len);
            sockaddr_in* sa4 = (sockaddr_in*)sa;
            *sa_len = sizeof(sockaddr_in);
            memset(sa, 0, *sa_len);

            sa4->sin_family = AF_INET;
            sa4->sin_addr.s_addr = *((uint32*)m_IP);
            sa4->sin_port = htons(uPort);
            break;
        }
        case IPv6: {
            ASSERT(sizeof(sockaddr_in6) <= *sa_len);
            sockaddr_in6* sa6 = (sockaddr_in6*)sa;
            *sa_len = sizeof(sockaddr_in6);
            memset(sa, 0, *sa_len);

            sa6->sin6_family = AF_INET6;
            memcpy(&sa6->sin6_addr, m_IP, 16);
            sa6->sin6_port = htons(uPort);
            break;
        }
        default:
            ASSERT(0);
    }
}

const bool CAddress::IsNull() const
{
    switch (m_eAF)
    {
        case None:	return true;
        case IPv4:	return *((uint32*)m_IP) == INADDR_ANY;
        case IPv6:	return ((uint64*)m_IP)[0] == 0 && ((uint64*)m_IP)[1] == 0;
    }
    return true;
}

const bool CAddress::IsMappedIPv4() const
{
    if (m_eAF == IPv6 && m_IP[10] == 0xFF && m_IP[11] == 0xFF && !m_IP[0] && !m_IP[1] && !m_IP[2] && !m_IP[3] && !m_IP[4] && !m_IP[5] && !m_IP[6] && !m_IP[7] && !m_IP[8] && !m_IP[9])
        return true;
    return false;
}

const bool CAddress::IsPublicIP() const
{
    // https://en.wikipedia.org/wiki/Reserved_IP_addresses

    if (m_eAF == None)
        return false;
    else if (m_eAF == IPv4) {
        // Checks are sorted by probabilty
        if (m_IP[0] == 0 || m_IP[0] == 10 || m_IP[0] == 127) // Loopback & private
            return false;

        if (m_IP[0] == 192 && m_IP[1] == 168) // Private
            return false;

        if (m_IP[0] == 172 && m_IP[1] >= 16 && m_IP[1] <= 31) // Private
            return false;

        if (m_IP[0] == 169 && m_IP[1] == 254) // Reserved
            return false;

        if (m_IP[0] >= 224 && m_IP[0] <= 239) // Reserved
            return false;

        if (m_IP[0] >= 240) // Reserved
            return false;

        if (m_IP[0] == 100 && m_IP[1] >= 64 && m_IP[1] <= 127) // Reserved
            return false;

        if (m_IP[0] == 192 && m_IP[1] == 0 && (m_IP[2] == 0 || m_IP[2] == 2)) // Reserved
            return false;

        if (m_IP[0] == 192 && m_IP[1] == 88 && m_IP[2] == 99) // Reserved
            return false;

        if (m_IP[0] == 198 && (m_IP[1] == 18 || m_IP[1] == 19)) // Reserved
            return false;

        if (m_IP[0] == 198 && m_IP[1] == 51 && m_IP[2] == 100) // Reserved
            return false;

        if (m_IP[0] == 203 && m_IP[1] == 0 && m_IP[2] == 113) // Reserved
            return false;

        if (m_IP[0] == 233 && m_IP[1] == 252 && m_IP[2] == 0) // Reserved
            return false;
    } else if (m_eAF == IPv6) {
        // Check for unspecified and loopback addresses & (::/128)
        if (m_IP[0] == 0 && m_IP[1] == 0 && m_IP[2] == 0 && m_IP[3] == 0 &&
            m_IP[4] == 0 && m_IP[5] == 0 && m_IP[6] == 0 && m_IP[7] == 0 &&
            m_IP[8] == 0 && m_IP[9] == 0 && m_IP[10] == 0 && m_IP[11] == 0 &&
            m_IP[12] == 0 && m_IP[13] == 0 && m_IP[14] == 0 && m_IP[15] <= 1)
            return false;

        // Link-local addresses (fe80::/10)
        if ((m_IP[0] == 0xfe) && ((m_IP[1] & 0xc0) == 0x80))
            return false;

        // Unique local addresses (fc00::/7)
        if ((m_IP[0] & 0xfe) == 0xfc)
            return false;


        // IPv4-translated addresses (::ffff:0:0:0/96)
        if (m_IP[0] == 0 && m_IP[1] == 0 && m_IP[2] == 0 && m_IP[3] == 0 &&
            m_IP[4] == 0 && m_IP[5] == 0 && m_IP[6] == 0 && m_IP[7] == 0 &&
            m_IP[8] == 0 && m_IP[9] == 0 && m_IP[10] == 0xff && m_IP[11] == 0xff)
            return false;

        // IPv4/IPv6 translation (64:ff9b::/96)
        if (m_IP[0] == 0x64 && m_IP[1] == 0xff && m_IP[2] == 0x9b)
            return false;

        // IPv4/IPv6 translation (64:ff9b:1::/48)
        if (m_IP[0] == 0x64 && m_IP[1] == 0xff && m_IP[2] == 0x9b && m_IP[3] == 0x01)
            return false;

        // Discard prefix (100::/64)
        if (m_IP[0] == 0x01 && m_IP[1] == 0x00)
            return false;

        // Teredo tunneling (2001::/32)
        if (m_IP[0] == 0x20 && m_IP[1] == 0x01 && m_IP[2] == 0x00 && m_IP[3] == 0x00)
            return false;

        // ORCHIDv2 (2001:20::/28)
        if (m_IP[0] == 0x20 && m_IP[1] == 0x01 && (m_IP[2] & 0xf0) == 0x20)
            return false;

        // Documentation and example source code (2001:db8::/32)
        if (m_IP[0] == 0x20 && m_IP[1] == 0x01 && m_IP[2] == 0x0d && m_IP[3] == 0xb8)
            return false;

        // 6to4 addressing scheme (deprecated) (2002::/16)
        if (m_IP[0] == 0x20 && m_IP[1] == 0x02)
            return false;

        // IPv6 Segment Routing (SRv6) (5f00::/16)
        if (m_IP[0] == 0x5f && m_IP[1] == 0x00)
            return false;

        // Multicast addresses (ff00::/8)
        if (m_IP[0] == 0xff)
            return false;
    }

    return true;
}

const bool CAddress::Convert(const EAF eAF)
{
    if (eAF == m_eAF)
        return true;
    if (eAF == IPv6) {
        m_IP[12] = m_IP[0];
        m_IP[13] = m_IP[1];
        m_IP[14] = m_IP[2];
        m_IP[15] = m_IP[3];
        m_IP[10] = m_IP[11] = 0xFF;
        m_IP[0] = m_IP[1] = m_IP[2] = m_IP[3] = m_IP[4] = m_IP[5] = m_IP[6] = m_IP[7] = m_IP[8] = m_IP[9] = 0;
    } else if (m_IP[10] == 0xFF && m_IP[11] == 0xFF && !m_IP[0] && !m_IP[1] && !m_IP[2] && !m_IP[3] && !m_IP[4] && !m_IP[5] && !m_IP[6] && !m_IP[7] && !m_IP[8] && !m_IP[9]) {
        m_IP[0] = m_IP[12];
        m_IP[1] = m_IP[13];
        m_IP[2] = m_IP[14];
        m_IP[3] = m_IP[15];
        m_IP[4] = m_IP[5] = m_IP[6] = m_IP[7] = m_IP[8] = m_IP[9] = m_IP[10] = m_IP[11] = m_IP[12] = m_IP[13] = m_IP[14] = m_IP[15] = 0;
    } else
        return false;
    m_eAF = eAF;
    return true;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// eMule AI: Below functions are inlined for faster execution.
// from BSD sources: http://code.google.com/p/plan9front/source/browse/sys/src/ape/lib/bsd/?r=320990f52487ae84e28961517a4fa0d02d473bac

inline const char* _inet_ntop(const int af, const void *src, char *dst, const int size)
{
    unsigned char *p;
    char *t;
    int i;

    if (af == AF_INET) {
        if (size < INET_ADDRSTRLEN) {
            errno = ENOSPC;
            return NULL;
        }
        p = (unsigned char*)&(((struct in_addr*)src)->s_addr);
        _snprintf_s(dst, size, _TRUNCATE, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
        return dst;
    }

    if (af != AF_INET6) {
        errno = EAFNOSUPPORT;
        return NULL;
    }

    if (size < INET6_ADDRSTRLEN) {
        errno = ENOSPC;
        return NULL;
    }

    p = (unsigned char*)((struct in6_addr*)src)->s6_addr;
    t = dst;
    for (i=0; i<16; i += 2)
    {
        unsigned int w;

        if (i > 0)
            *t++ = ':';
        w = p[i]<<8 | p[i+1];
        _snprintf_s(t, static_cast<size_t>(dst + size - t), _TRUNCATE, "%x", w);
        t += strlen(t);
    }
    return dst;
}

inline const int _inet_aton(const char *from, struct in_addr *in)
{
    #define CLASS(x)        (x[0]>>6)
    unsigned char *to;
    unsigned long x;
    char *p;
    int i;

    in->s_addr = 0;
    to = (unsigned char*)&in->s_addr;
    if (*from == 0)
        return 0;
    for (i = 0; i < 4 && *from; i++, from = p) {
        x = strtoul(from, &p, 0);
        if (x != (unsigned char)x || p == from)
            return 0;       /* parse error */
        to[i] = (unsigned char)x;
        if (*p == '.')
            p++;
        else if (*p != 0)
            return 0;       /* parse error */
    }

    switch (CLASS(to)) {
        case 0: /* class A - 1 byte net */
        case 1:
            if (i == 3) {
                to[3] = to[2];
                to[2] = to[1];
                to[1] = 0;
            } else if (i == 2) {
                to[3] = to[1];
                to[1] = 0;
            }
            break;
        case 2: /* class B - 2 byte net */
            if (i == 3) {
                to[3] = to[2];
                to[2] = 0;
            }
            break;
    }
    return 1;
}

inline const static int ipcharok(const int c)
{
    return c == ':' || isascii(c) && isxdigit(c);
}

inline const static int delimchar(const int c)
{
    if (c == '\0')
        return 1;
    if (c == ':' || isascii(c) && isalnum(c))
        return 0;
    return 1;
}

inline const int _inet_pton(const int af, const char *src, const void *dst)
{
    int i, elipsis = 0;
    unsigned char *to;
    unsigned long x;
    const char *p, *op;

    if (af == AF_INET)
        return _inet_aton(src, (struct in_addr*)dst);

    if (af != AF_INET6) {
        errno = EAFNOSUPPORT;
        return -1;
    }

    to = ((struct in6_addr*)dst)->s6_addr;
    memset(to, 0, 16);

    p = src;
    for (i = 0; i < 16 && ipcharok(*p); i+=2) {
        op = p;
        x = strtoul(p, (char**)&p, 16);

        if (x != (unsigned short)x || *p != ':' && !delimchar(*p))
            return 0;                       /* parse error */

        to[i] = (unsigned char)(x>>8);
        to[i+1] = (unsigned char)x;
        if (*p == ':') {
            if (*++p == ':') {      /* :: is elided zero short(s) */
                if (elipsis)
                    return 0;       /* second :: */
                elipsis = i+2;
                p++;
            }
        }  else if (p == op)               /* strtoul made no progress? */
            break;
    }
    if (p == src || !delimchar(*p))
        return 0;                               /* parse error */
    if (i < 16) {
        memmove(&to[elipsis+16-i], &to[elipsis], i-elipsis);
        memset(&to[elipsis], 0, 16-i);
    }
    return 1;
}


// ────────────────────────────────────────────────────────────────────────
// v0.71 IPv6 Sprint 1 — wire serialization, hashing, subnet ops.
// Reference: docs/IPV6_PLAN.md §5.1.
// ────────────────────────────────────────────────────────────────────────

void CAddress::WriteToBuffer(CSafeMemFile* file) const
{
    if (!file) return;
    uint8 fam = 0;
    uint8 len = 0;
    switch (m_eAF) {
    case IPv4: fam = 4;  len = 4;  break;
    case IPv6: fam = 6;  len = 16; break;
    case None: fam = 0;  len = 0;  break;
    }
    file->WriteUInt8(fam);
    file->WriteUInt8(len);
    if (len > 0)
        file->Write(m_IP, len);
}

bool CAddress::ReadFromBuffer(CSafeMemFile* file)
{
    if (!file) return false;
    // Need at least 2 bytes for the prefix.
    if (file->GetPosition() + 2 > file->GetLength()) return false;
    uint8 fam = file->ReadUInt8();
    uint8 len = file->ReadUInt8();
    EAF type;
    uint8 expected;
    switch (fam) {
    case 0: type = None; expected = 0;  break;
    case 4: type = IPv4; expected = 4;  break;
    case 6: type = IPv6; expected = 16; break;
    default: return false;
    }
    if (len != expected) return false;
    if (file->GetPosition() + len > file->GetLength()) return false;
    memset(m_IP, 0, 16);
    if (len > 0)
        file->Read(m_IP, len);
    m_eAF = type;
    return true;
}

UINT CAddress::HashKey() const
{
    // FNV-1a 32-bit over the 17-byte (family + 16 raw addr) tuple. Cheap and
    // distributes well enough for CMap; collisions are functionally tolerated
    // because CMap probes the equality operator after a hash hit.
    UINT h = 2166136261u;
    h ^= (UINT)m_eAF;       h *= 16777619u;
    for (int i = 0; i < 16; ++i) { h ^= (UINT)m_IP[i]; h *= 16777619u; }
    return h;
}

CAddress CAddress::GetSubnet(int prefixBits) const
{
    if (m_eAF == None || prefixBits <= 0) {
        CAddress out(*this);
        memset(out.m_IP, 0, 16);
        return out;
    }
    int maxBits = (m_eAF == IPv4) ? 32 : 128;
    if (prefixBits >= maxBits) return *this;

    CAddress out(*this);
    // Bytes fully kept, bytes fully zeroed, plus the partial byte at the seam.
    int byteCount = prefixBits / 8;
    int leftover  = prefixBits % 8;
    if (leftover == 0) {
        // Zero everything from byteCount onward (within the addr family len).
        int total = (m_eAF == IPv4) ? 4 : 16;
        for (int i = byteCount; i < total; ++i) out.m_IP[i] = 0;
    } else {
        uint8 mask = (uint8)(0xFFu << (8 - leftover));
        out.m_IP[byteCount] &= mask;
        int total = (m_eAF == IPv4) ? 4 : 16;
        for (int i = byteCount + 1; i < total; ++i) out.m_IP[i] = 0;
    }
    return out;
}

bool CAddress::InSameSubnet(const CAddress& other, int prefixBits) const
{
    if (m_eAF != other.m_eAF) return false;
    if (m_eAF == None) return true;
    return GetSubnet(prefixBits) == other.GetSubnet(prefixBits);
}

CAddress CAddress::FromKadHostOrder(uint32 hostIp)
{
    // Kad's m_uIp is host-order (high byte first in human terms); our internal
    // m_IP is the raw network-order bytes. Reverse to convert.
    return CAddress(hostIp, /*bReverse=*/true);
}

uint32 CAddress::ToKadHostOrder() const
{
    return ToUInt32(/*bReverse=*/true);
}

uint32 CAddress::ToSyntheticUInt32() const
{
    // Synthetic uint32 for IPv6 addresses: hash + high bit forced on so the
    // legacy CMap<uint32, …> never collides with a real public IPv4 (which
    // never starts with bit 0x80000000 set in network order — actually it can,
    // since 128.0.0.0/1 is valid v4; we use a magic prefix instead).
    if (m_eAF == IPv4) return ToUInt32(/*bReverse=*/false);
    if (m_eAF == None) return 0;
    // IPv6: synthesize. Use FNV-1a 32-bit over the 16 addr bytes, then force
    // the top byte to 0xFE — explicitly chosen because 254.x.x.x/8 is
    // reserved-future and never appears as a real public IPv4. Any collision
    // here is by definition a different IPv6 that synthesizes to the same
    // 24-bit suffix, which is acceptable for CMap probing.
    uint32 h = 2166136261u;
    for (int i = 0; i < 16; ++i) { h ^= (uint32)m_IP[i]; h *= 16777619u; }
    return (uint32)((h & 0x00FFFFFFu) | 0xFE000000u);
}