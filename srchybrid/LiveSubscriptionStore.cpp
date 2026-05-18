// this file is part of eMule eSE — Live subscription store impl (F2)
#include "stdafx.h"
#include "LiveSubscriptionStore.h"
#include "LiveOnionCrypto.h"     // SecureRandomBytes (cover traffic shuffle)
#include "Preferences.h"

#include <wincrypt.h>            // DPAPI
#include <shlobj.h>              // SHGetFolderPath

#pragma comment(lib, "crypt32.lib")

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

namespace eSELive {

namespace {

// File-format magic + version so future updates can detect old files.
const uint8_t SUB_MAGIC[4] = { 'e', 'S', 'U', 'B' };
const uint8_t SUB_VERSION  = 1;

bool DPAPIEncrypt(const std::vector<uint8_t>& plain, std::vector<uint8_t>& cipher)
{
    DATA_BLOB in;
    in.pbData = const_cast<BYTE*>(plain.data());
    in.cbData = (DWORD)plain.size();
    DATA_BLOB out = { 0 };
    if (!CryptProtectData(&in, L"eSE Live subscriptions", NULL, NULL, NULL,
                          CRYPTPROTECT_UI_FORBIDDEN, &out))
        return false;
    cipher.assign(out.pbData, out.pbData + out.cbData);
    LocalFree(out.pbData);
    return true;
}

bool DPAPIDecrypt(const std::vector<uint8_t>& cipher, std::vector<uint8_t>& plain)
{
    DATA_BLOB in;
    in.pbData = const_cast<BYTE*>(cipher.data());
    in.cbData = (DWORD)cipher.size();
    DATA_BLOB out = { 0 };
    if (!CryptUnprotectData(&in, NULL, NULL, NULL, NULL,
                            CRYPTPROTECT_UI_FORBIDDEN, &out))
        return false;
    plain.assign(out.pbData, out.pbData + out.cbData);
    SecureZeroMemory(out.pbData, out.cbData);
    LocalFree(out.pbData);
    return true;
}

}  // namespace

CLiveSubscriptionStore::CLiveSubscriptionStore()
    : m_loaded(false)
{}

CLiveSubscriptionStore& CLiveSubscriptionStore::Get()
{
    static CLiveSubscriptionStore s_instance;
    return s_instance;
}

CStringW CLiveSubscriptionStore::StorePath()
{
    // %APPDATA%\eMule\ese\subscriptions.dat
    wchar_t path[MAX_PATH];
    if (FAILED(SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, path)))
        return CStringW();
    CStringW out(path);
    out += L"\\eMule\\ese";
    SHCreateDirectoryExW(NULL, out, NULL);
    out += L"\\subscriptions.dat";
    return out;
}

bool CLiveSubscriptionStore::SerializeUnencrypted(std::vector<uint8_t>& out) const
{
    out.clear();
    out.insert(out.end(), SUB_MAGIC, SUB_MAGIC + 4);
    out.push_back(SUB_VERSION);

    const uint32_t count = (uint32_t)m_entries.size();
    for (int i = 0; i < 4; ++i)
        out.push_back((uint8_t)((count >> (i * 8)) & 0xFF));

    for (const auto& e : m_entries) {
        out.insert(out.end(), e.channel_pubkey, e.channel_pubkey + 32);
        // name: uint8 len + UTF-8 bytes (cap 255)
        const int nlen = (e.name.GetLength() > 255 ? 255 : e.name.GetLength());
        out.push_back((uint8_t)nlen);
        out.insert(out.end(),
                   (const uint8_t*)(LPCSTR)e.name,
                   (const uint8_t*)(LPCSTR)e.name + nlen);
        // added_unix_ts: uint64 LE
        for (int i = 0; i < 8; ++i)
            out.push_back((uint8_t)((e.added_unix_ts >> (i * 8)) & 0xFF));
        out.push_back(e.notifications ? 1 : 0);
    }
    return true;
}

bool CLiveSubscriptionStore::ParseUnencrypted(const uint8_t* in, size_t inLen)
{
    if (inLen < 4 + 1 + 4) return false;
    if (memcmp(in, SUB_MAGIC, 4) != 0) return false;
    if (in[4] != SUB_VERSION) return false;

    const uint8_t* p = in + 5;
    const uint8_t* end = in + inLen;

    if (p + 4 > end) return false;
    uint32_t count = 0;
    for (int i = 0; i < 4; ++i) count |= ((uint32_t)p[i]) << (i * 8);
    p += 4;

    m_entries.clear();
    m_entries.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        if (p + 32 + 1 > end) return false;
        SubscriptionEntry e;
        memcpy(e.channel_pubkey, p, 32); p += 32;
        const uint8_t nlen = *p++;
        if (p + nlen > end) return false;
        e.name = CStringA((const char*)p, nlen);
        p += nlen;
        if (p + 8 + 1 > end) return false;
        e.added_unix_ts = 0;
        for (int j = 0; j < 8; ++j) e.added_unix_ts |= ((uint64_t)p[j]) << (j * 8);
        p += 8;
        e.notifications = (*p++ != 0);
        m_entries.push_back(e);
    }
    return true;
}

bool CLiveSubscriptionStore::Load()
{
    CSingleLock lock(&m_lock, TRUE);
    if (m_loaded) return true;

    const CStringW path = StorePath();
    if (path.IsEmpty()) return false;

    CFile f;
    CFileException ex;
    if (!f.Open(path, CFile::modeRead | CFile::shareDenyWrite | CFile::typeBinary, &ex)) {
        // Not existing == empty store, first run.
        if (ex.m_cause == CFileException::fileNotFound) {
            m_entries.clear();
            m_loaded = true;
            return true;
        }
        return false;
    }
    const ULONGLONG sz = f.GetLength();
    if (sz == 0 || sz > 16 * 1024 * 1024) { f.Close(); return false; }
    std::vector<uint8_t> cipher(static_cast<size_t>(sz));
    f.Read(cipher.data(), (UINT)sz);
    f.Close();

    std::vector<uint8_t> plain;
    if (!DPAPIDecrypt(cipher, plain)) return false;
    const bool ok = ParseUnencrypted(plain.data(), plain.size());
    SecureWipe(plain.data(), plain.size());
    if (ok) m_loaded = true;
    return ok;
}

bool CLiveSubscriptionStore::Save() const
{
    CSingleLock lock(&m_lock, TRUE);
    std::vector<uint8_t> plain;
    if (!SerializeUnencrypted(plain)) return false;
    std::vector<uint8_t> cipher;
    if (!DPAPIEncrypt(plain, cipher)) { SecureWipe(plain.data(), plain.size()); return false; }
    SecureWipe(plain.data(), plain.size());

    const CStringW path = StorePath();
    const CStringW pathNew = path + L".new";

    CFile f;
    CFileException ex;
    if (!f.Open(pathNew, CFile::modeWrite | CFile::modeCreate
                       | CFile::shareDenyWrite | CFile::typeBinary, &ex))
        return false;
    f.Write(cipher.data(), (UINT)cipher.size());
    f.Close();
    return MoveFileExW(pathNew, path, MOVEFILE_REPLACE_EXISTING) != FALSE;
}

bool CLiveSubscriptionStore::Add(const SubscriptionEntry& e)
{
    CSingleLock lock(&m_lock, TRUE);
    for (const auto& cur : m_entries) {
        if (memcmp(cur.channel_pubkey, e.channel_pubkey, 32) == 0) return false;
    }
    m_entries.push_back(e);
    return true;
}

bool CLiveSubscriptionStore::Remove(const uint8_t channel_pubkey[32])
{
    CSingleLock lock(&m_lock, TRUE);
    for (auto it = m_entries.begin(); it != m_entries.end(); ++it) {
        if (memcmp(it->channel_pubkey, channel_pubkey, 32) == 0) {
            m_entries.erase(it);
            return true;
        }
    }
    return false;
}

bool CLiveSubscriptionStore::IsSubscribed(const uint8_t channel_pubkey[32]) const
{
    CSingleLock lock(&m_lock, TRUE);
    for (const auto& e : m_entries)
        if (memcmp(e.channel_pubkey, channel_pubkey, 32) == 0) return true;
    return false;
}

size_t CLiveSubscriptionStore::Count() const
{
    CSingleLock lock(&m_lock, TRUE);
    return m_entries.size();
}

bool CLiveSubscriptionStore::GetAll(std::vector<SubscriptionEntry>& out) const
{
    CSingleLock lock(&m_lock, TRUE);
    out = m_entries;
    return true;
}

void CLiveSubscriptionStore::PickCoverTrafficSet(
    const std::vector<std::vector<uint8_t>>& knownNotSubscribed,
    size_t n,
    std::vector<std::vector<uint8_t>>& out) const
{
    out.clear();
    if (knownNotSubscribed.empty() || n == 0) return;
    // Fisher-Yates partial shuffle over `knownNotSubscribed`, draw first `n`.
    std::vector<size_t> idx;
    idx.reserve(knownNotSubscribed.size());
    for (size_t i = 0; i < knownNotSubscribed.size(); ++i) idx.push_back(i);
    const size_t k = (n < idx.size()) ? n : idx.size();
    for (size_t i = 0; i < k; ++i) {
        uint8_t rnd[4];
        SecureRandomBytes(rnd, 4);
        const uint32_t r = (uint32_t)rnd[0] | ((uint32_t)rnd[1] << 8)
                         | ((uint32_t)rnd[2] << 16) | ((uint32_t)rnd[3] << 24);
        const size_t pick = i + (size_t)(r % (uint32_t)(idx.size() - i));
        std::swap(idx[i], idx[pick]);
    }
    out.reserve(k);
    for (size_t i = 0; i < k; ++i)
        out.push_back(knownNotSubscribed[idx[i]]);
}

}  // namespace eSELive
