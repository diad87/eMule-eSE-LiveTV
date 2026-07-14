// SPDX-License-Identifier: MIT
//
// test_kad6_smoke.cpp — toolchain + scaffolding sanity. Exercises the shared
// ByteReader/ByteWriter cursor and the constant-time compare. If this builds
// clean at /W4 and exits 0, the libkad6 build path (vcvars + cl via make.bat)
// and the base headers are good — every codec ticket builds on this.
//
//   from libkad6/:  make.bat test_kad6_smoke tests\test_kad6_smoke.cpp
#include "kad6/kad6_bytes.h"
#include "kad6/kad6_types.h"

#include <cstdio>
#include <vector>

using namespace kad6;

static int g_fail = 0;
static int g_pass = 0;

#define CHECK(cond, msg) do { if (cond) { ++g_pass; } else { ++g_fail; \
    std::printf("  FAIL: %s  (%s:%d)\n", msg, __FILE__, __LINE__); } } while (0)

int main() {
    // Round-trip every scalar width through writer -> reader.
    std::vector<Byte> buf;
    {
        ByteWriter w(buf);
        w.u8(0xAB);
        w.u16le(0x1234);
        w.u32le(0xDEADBEEFu);
        w.u64le(0x0102030405060708ull);
        const Byte blob[3] = {0x11, 0x22, 0x33};
        w.bytes(blob, 3);
    }
    CHECK(buf.size() == 1 + 2 + 4 + 8 + 3, "writer size");

    {
        ByteReader r(buf.data(), buf.size());
        CHECK(r.u8() == 0xAB, "u8");
        CHECK(r.u16le() == 0x1234, "u16le");
        CHECK(r.u32le() == 0xDEADBEEFu, "u32le");
        CHECK(r.u64le() == 0x0102030405060708ull, "u64le");
        Byte out[3] = {0, 0, 0};
        CHECK(r.bytes(out, 3), "bytes ok");
        CHECK(out[0] == 0x11 && out[1] == 0x22 && out[2] == 0x33, "bytes value");
        CHECK(r.remaining() == 0, "consumed all");
        CHECK(r.ok(), "reader still ok");
    }

    // Short read latches failure and never reads past the buffer.
    {
        const Byte two[2] = {0x01, 0x02};
        ByteReader r(two, 2);
        (void)r.u32le();                 // asks for 4, only 2 present
        CHECK(!r.ok(), "short read latched failure");
    }
    // Null buffer with non-zero length is flagged, not dereferenced.
    {
        ByteReader r(nullptr, 5);
        CHECK(r.null_arg(), "null arg flagged");
        CHECK(!r.ok(), "null arg not ok");
    }
    // Constant-time compare.
    {
        const Byte a[4] = {1, 2, 3, 4};
        const Byte b[4] = {1, 2, 3, 4};
        const Byte c[4] = {1, 2, 3, 5};
        CHECK(Kad6CtEqual(a, b, 4), "ct equal");
        CHECK(!Kad6CtEqual(a, c, 4), "ct not equal");
    }

    std::printf("test_kad6_smoke: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
