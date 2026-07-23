// this file is part of eMule eSE — node identity key storage (abstraction)
//
// MFC-FREE on purpose: only <cstddef>/<string>/<memory>. Compiles unchanged on
// the MSVC/MFC build (emule.exe, DPAPI backend) AND on a bare POSIX toolchain
// (the CI unit test + the Phase-5 Linux daemon, file-perms backend). Do NOT add
// MFC / eMule headers here — that would break the cross-platform contract.
//
// Implementations persist the Ed25519 seed without exposing storage details to
// the tunnel protocol.
#pragma once

#include <cstddef>
#include <string>
#include <memory>

class INodeIdentityStorage {
public:
    virtual ~INodeIdentityStorage() = default;

    // Persist `len` raw key bytes. Returns true on success. The Windows backend
    // encrypts at rest (DPAPI, user-bound); the POSIX backend relies on 0600
    // file permissions (SSH-key model). Overwrites any existing key.
    virtual bool SaveKey(const unsigned char* key, std::size_t len) = 0;

    // Load exactly `len` bytes into `out`. Returns false if the key is absent or
    // the stored size does not match `len` (caller then generates a fresh key).
    virtual bool LoadKey(unsigned char* out, std::size_t len) = 0;

    // "dpapi" on Windows, "posix" elsewhere. Lets the CI test assert that the
    // factory selected the right backend for the build platform — without RTTI.
    virtual const char* BackendName() const = 0;
};

// Platform-selected factory. `path` is the file the key blob lives in (UTF-8).
// On _WIN32 returns the DPAPI backend; otherwise the POSIX file backend. The
// inactive branch is preprocessed out, so neither build links the other's code.
std::unique_ptr<INodeIdentityStorage> CreateNodeIdentityStorage(const std::string& path);
