// this file is part of eMule eSE — persistent per-node Ed25519 identity (impl)
//
// Uses PCH (stdafx.h) and MFC (CPreferences::GetMuleDirectory). The hard,
// platform-specific bytes-on-disk work is delegated to INodeIdentityStorage; the
// Ed25519 primitives are reused from LiveCrypto (generic ed25519 gen/sign).
//
// See docs/AUTHENTICATED_TUNNEL_HANDSHAKE_PLAN.md §1.
#include "stdafx.h"
#include "NodeIdentity.h"
#include "INodeIdentityStorage.h"
#include "LiveCrypto.h"        // eSELive::GenerateBroadcasterKeypair / SignMessage (generic Ed25519)
#include "Preferences.h"       // thePrefs.GetMuleDirectory + EMULE_CONFIGDIR
#include "Log.h"               // AddDebugLogLine
#include <string>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

namespace {

bool    s_ready    = false;
uint8_t s_pub[32]  = {0};
uint8_t s_priv[32] = {0};      // kept in memory for the process lifetime (sign path)

std::string WideToUtf8(const wchar_t* w)
{
    if (!w || !*w) return std::string();
    int n = ::WideCharToMultiByte(CP_UTF8, 0, w, -1, NULL, 0, NULL, NULL);
    if (n <= 1) return std::string();
    std::string s((size_t)(n - 1), '\0');   // n includes the NUL terminator
    ::WideCharToMultiByte(CP_UTF8, 0, w, -1, &s[0], n - 1, NULL, NULL);
    return s;
}

std::string IdentityFilePath()
{
    CString dir = thePrefs.GetMuleDirectory(EMULE_CONFIGDIR);
    if (dir.IsEmpty()) return std::string();
    const TCHAR last = dir[dir.GetLength() - 1];
    if (last != _T('\\') && last != _T('/'))
        dir += _T('\\');
    dir += _T("node_identity.dat");
    return WideToUtf8((LPCWSTR)dir);
}

} // namespace

namespace eSELive {

bool NodeIdentityInit()
{
    if (s_ready) return true;

    const std::string path = IdentityFilePath();
    if (path.empty()) return false;

    std::unique_ptr<INodeIdentityStorage> store = CreateNodeIdentityStorage(path);
    if (!store) return false;

    // Stored blob = pub(32) || priv(32). Loading both avoids re-deriving the pub.
    uint8_t blob[64];
    if (store->LoadKey(blob, sizeof blob)) {
        memcpy(s_pub,  blob,      32);
        memcpy(s_priv, blob + 32, 32);
        ::SecureZeroMemory(blob, sizeof blob);
        s_ready = true;
        return true;
    }

    // First run (or unreadable / foreign blob): generate a fresh identity.
    if (!GenerateBroadcasterKeypair(s_pub, s_priv))
        return false;
    memcpy(blob,      s_pub,  32);
    memcpy(blob + 32, s_priv, 32);
    if (!store->SaveKey(blob, sizeof blob)) {
        // Persist failed (e.g. read-only config dir). We still run this session
        // with the in-memory key; a fresh one is generated next launch.
        AddDebugLogLine(false, _T("eSE node identity: generated but PERSIST FAILED (ephemeral this session)"));
    }
    ::SecureZeroMemory(blob, sizeof blob);
    s_ready = true;
    return true;
}

const uint8_t* NodeIdentityPub()
{
    return s_ready ? s_pub : NULL;
}

bool NodeIdentitySign(const uint8_t* msg, std::size_t msgLen, uint8_t sig[64])
{
    if (!s_ready) return false;
    return SignMessage(s_priv, s_pub, msg, msgLen, sig);
}

} // namespace eSELive
