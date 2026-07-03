// test_node_identity_storage.cpp — standalone unit test for INodeIdentityStorage
// and the platform factory CreateNodeIdentityStorage(). Mirrors the libreach
// harness style (CHECK macro, exit code = failure count, no test framework).
//
// Validates exactly what the CI question asks: that the factory instantiates the
// RIGHT backend for the build platform, and that the POSIX backend persists with
// 0600 perms when compiled "headless" outside Win32.
//
// Standalone build (no MFC, no eMule headers, no CryptoPP on POSIX), from repo root:
//   POSIX:    g++ -std=c++17 -O2 -Wall -Wextra \
//                 srchybrid/NodeIdentityStorage.cpp tests/test_node_identity_storage.cpp \
//                 -o storage_test && ./storage_test
//   Windows:  cl /EHsc /O2 /W4 /std:c++17 ^
//                 srchybrid\NodeIdentityStorage.cpp tests\test_node_identity_storage.cpp ^
//                 Crypt32.lib /Fe:storage_test.exe  &&  storage_test.exe
//   Exit 0 = all pass, non-zero = failure count.

#include "../srchybrid/INodeIdentityStorage.h"

#include <cstdio>
#include <cstring>
#include <string>

#ifndef _WIN32
#  include <sys/stat.h>
#endif

static int g_fail = 0;
static int g_pass = 0;

#define CHECK(cond, msg) do { if (cond) { ++g_pass; } else { ++g_fail; \
    std::printf("  FAIL: %s  (%s:%d)\n", msg, __FILE__, __LINE__); } } while (0)

int main()
{
    const std::string path = "._test_node_identity.dat";
    std::remove(path.c_str());

    auto store = CreateNodeIdentityStorage(path);
    CHECK(store != nullptr, "factory returns a backend");
    if (!store) { std::printf("FATAL: null backend\n"); return 1; }

    // 1. Factory dispatch: the right backend for this build platform (the CI question).
#ifdef _WIN32
    CHECK(std::strcmp(store->BackendName(), "dpapi") == 0, "factory selects dpapi on Win32");
#else
    CHECK(std::strcmp(store->BackendName(), "posix") == 0, "factory selects posix off Win32");
#endif

    // 2. Load when absent -> false (do not invent a key).
    unsigned char absent[64] = {0};
    CHECK(store->LoadKey(absent, sizeof absent) == false, "load-absent returns false");

    // 3. Round-trip: save then load yields identical bytes.
    unsigned char key[64];
    for (int i = 0; i < 64; ++i) key[i] = (unsigned char)(i * 7 + 1);
    CHECK(store->SaveKey(key, sizeof key) == true, "save succeeds");
    unsigned char back[64] = {0};
    CHECK(store->LoadKey(back, sizeof back) == true, "load succeeds");
    CHECK(std::memcmp(key, back, sizeof key) == 0, "round-trip bytes identical");

    // 4. Size mismatch on load -> false (guards against truncated/foreign blobs).
    unsigned char wrong[32] = {0};
    CHECK(store->LoadKey(wrong, sizeof wrong) == false, "load with wrong length fails");

    // 5. POSIX: the persisted file must be exactly mode 0600 (headless safety).
#ifndef _WIN32
    struct stat st {};
    CHECK(::stat(path.c_str(), &st) == 0, "stat the key file");
    CHECK((st.st_mode & 0777) == 0600, "key file is chmod 0600");
#endif

    // 6. Overwrite: a second save replaces the first.
    unsigned char key2[64];
    for (int i = 0; i < 64; ++i) key2[i] = (unsigned char)(255 - i);
    CHECK(store->SaveKey(key2, sizeof key2) == true, "overwrite save succeeds");
    CHECK(store->LoadKey(back, sizeof back) == true, "load after overwrite");
    CHECK(std::memcmp(key2, back, sizeof key2) == 0, "overwrite bytes win");

    std::remove(path.c_str());

    std::printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail;   // exit code = failure count (0 = all pass)
}
