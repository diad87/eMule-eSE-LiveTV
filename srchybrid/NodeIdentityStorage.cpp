// this file is part of eMule eSE — node identity key storage (backends + factory)
//
// MFC-FREE and PCH-FREE on purpose (no stdafx.h). When added to emule.vcxproj
// this file MUST be set to "Not Using Precompiled Headers" (/Y-), because it
// also compiles standalone for the CI unit test (tests/test_node_identity_storage.cpp)
// and for the Phase-5 Linux daemon. Mirrors the libreach standalone discipline.
//
// Two backends, selected at compile time by the platform; the inactive branch is
// preprocessed out so neither build references the other's symbols:
//   _WIN32  -> WinDpapiStorage   (DPAPI, user-bound encryption at rest)
//   else    -> PosixFileStorage  (raw bytes, protected by 0600 file perms)
//
// See docs/AUTHENTICATED_TUNNEL_HANDSHAKE_PLAN.md §1.2.

#include "INodeIdentityStorage.h"

#include <vector>
#include <cstring>

// ===========================================================================
#ifdef _WIN32
// ===========================================================================
#include <windows.h>
#include <wincrypt.h>   // CryptProtectData / CryptUnprotectData (DPAPI)
#pragma comment(lib, "Crypt32.lib")   // DPAPI lives here; pragma avoids a vcxproj linker edit (MSVC only, ignored by g++)

namespace {

std::wstring Utf8ToWide(const std::string& s)
{
    if (s.empty()) return std::wstring();
    int n = ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    if (n <= 0) return std::wstring();
    std::wstring w((size_t)n, L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
}

class WinDpapiStorage : public INodeIdentityStorage {
public:
    explicit WinDpapiStorage(std::wstring path) : m_path(std::move(path)) {}
    const char* BackendName() const override { return "dpapi"; }

    bool SaveKey(const unsigned char* key, std::size_t len) override
    {
        DATA_BLOB in{ (DWORD)len, const_cast<BYTE*>(key) };
        DATA_BLOB out{ 0, nullptr };
        // CRYPTPROTECT_UI_FORBIDDEN: never prompt — mandatory for headless / daemon.
        if (!::CryptProtectData(&in, L"ese-node-identity", nullptr, nullptr, nullptr,
                                CRYPTPROTECT_UI_FORBIDDEN, &out))
            return false;
        bool ok = WriteAll(out.pbData, out.cbData);
        if (out.pbData) ::LocalFree(out.pbData);
        return ok;
    }

    bool LoadKey(unsigned char* outKey, std::size_t len) override
    {
        std::vector<unsigned char> blob;
        if (!ReadAll(blob) || blob.empty()) return false;
        DATA_BLOB in{ (DWORD)blob.size(), blob.data() };
        DATA_BLOB out{ 0, nullptr };
        if (!::CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr,
                                  CRYPTPROTECT_UI_FORBIDDEN, &out))
            return false;
        bool ok = (out.cbData == (DWORD)len);          // size mismatch -> caller regenerates
        if (ok) std::memcpy(outKey, out.pbData, len);
        if (out.pbData) { ::SecureZeroMemory(out.pbData, out.cbData); ::LocalFree(out.pbData); }
        return ok;
    }

private:
    std::wstring m_path;

    bool WriteAll(const BYTE* p, DWORD n)
    {
        HANDLE h = ::CreateFileW(m_path.c_str(), GENERIC_WRITE, 0, nullptr,
                                 CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return false;
        DWORD wrote = 0;
        bool ok = (::WriteFile(h, p, n, &wrote, nullptr) != FALSE) && wrote == n;
        ::CloseHandle(h);
        return ok;
    }

    bool ReadAll(std::vector<unsigned char>& out)
    {
        HANDLE h = ::CreateFileW(m_path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                                 OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return false;
        LARGE_INTEGER sz{};
        bool ok = (::GetFileSizeEx(h, &sz) != FALSE) && sz.QuadPart > 0 && sz.QuadPart < (1 << 20);
        if (ok) {
            out.resize((size_t)sz.QuadPart);
            DWORD rd = 0;
            ok = (::ReadFile(h, out.data(), (DWORD)out.size(), &rd, nullptr) != FALSE)
                 && rd == out.size();
        }
        ::CloseHandle(h);
        return ok;
    }
};

} // namespace

std::unique_ptr<INodeIdentityStorage> CreateNodeIdentityStorage(const std::string& path)
{
    return std::unique_ptr<INodeIdentityStorage>(new WinDpapiStorage(Utf8ToWide(path)));
}

// ===========================================================================
#else  // POSIX
// ===========================================================================
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

namespace {

class PosixFileStorage : public INodeIdentityStorage {
public:
    explicit PosixFileStorage(std::string path) : m_path(std::move(path)) {}
    const char* BackendName() const override { return "posix"; }

    bool SaveKey(const unsigned char* key, std::size_t len) override
    {
        // 0600 at creation; the key is protected by POSIX perms (SSH-key model),
        // not encrypted at rest. A Phase-5 daemon may layer age/SOPS on top.
        int fd = ::open(m_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
        if (fd < 0) return false;
        ::fchmod(fd, S_IRUSR | S_IWUSR);   // enforce 0600 even if umask/prior file widened it
        bool ok = WriteAll(fd, key, len);
        ::close(fd);
        return ok;
    }

    bool LoadKey(unsigned char* out, std::size_t len) override
    {
        int fd = ::open(m_path.c_str(), O_RDONLY);
        if (fd < 0) return false;
        bool ok = ReadAll(fd, out, len);
        ::close(fd);
        return ok;
    }

private:
    std::string m_path;

    static bool WriteAll(int fd, const unsigned char* p, std::size_t n)
    {
        std::size_t off = 0;
        while (off < n) {
            ssize_t w = ::write(fd, p + off, n - off);
            if (w <= 0) return false;
            off += (std::size_t)w;
        }
        return true;
    }

    static bool ReadAll(int fd, unsigned char* p, std::size_t n)
    {
        std::size_t off = 0;
        while (off < n) {
            ssize_t r = ::read(fd, p + off, n - off);
            if (r <= 0) return false;          // EOF before len -> short/absent key
            off += (std::size_t)r;
        }
        return true;
    }
};

} // namespace

std::unique_ptr<INodeIdentityStorage> CreateNodeIdentityStorage(const std::string& path)
{
    return std::unique_ptr<INodeIdentityStorage>(new PosixFileStorage(path));
}

#endif  // _WIN32
