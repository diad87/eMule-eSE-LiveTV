// SPDX-License-Identifier: MIT
//
// test_kad6_frame.cpp — K6FrameV1 codec tests (ticket K6-0.4): golden layout,
// round-trip, producer-strict / consumer-prudent rejects, reserved-flag
// tolerance on decode, and a fixed-seed fuzz loop over DecodeK6Frame.
//
//   from libkad6/:  make.bat test_kad6_frame tests\test_kad6_frame.cpp src\kad6_frame.cpp
#include "kad6/kad6_frame.h"
#include "kad6/kad6_bytes.h"
#include "kad6/kad6_types.h"

#include <cstdio>
#include <cstdint>
#include <vector>

using namespace kad6;

static int g_fail = 0;
static int g_pass = 0;

#define CHECK(cond, msg) do { if (cond) { ++g_pass; } else { ++g_fail; \
    std::printf("  FAIL: %s  (%s:%d)\n", msg, __FILE__, __LINE__); } } while (0)

// Build raw K6FrameV1 wire bytes by hand (bypassing EncodeK6Frame's producer
// validation) so decode-side tests can feed it inputs the encoder would
// refuse to produce (a declared body_len that doesn't match the bytes
// actually supplied, a reserved flag bit, an unsupported version, ...).
static std::vector<Byte> RawHeader(Byte version, Byte msg_type,
                                    std::uint16_t flags,
                                    std::uint32_t request_id,
                                    std::uint64_t session_id,
                                    std::uint32_t body_len_field) {
    std::vector<Byte> buf;
    ByteWriter w(buf);
    w.u8(version);
    w.u8(msg_type);
    w.u16le(flags);
    w.u32le(request_id);
    w.u64le(session_id);
    w.u32le(body_len_field);
    return buf;
}

// Tiny fixed-seed LCG (never time/rand) so the fuzz loop is reproducible.
class Lcg32 {
public:
    explicit Lcg32(std::uint32_t seed) : state_(seed) {}
    std::uint32_t next() noexcept {
        state_ = state_ * 1664525u + 1013904223u;
        return state_;
    }
    Byte nextByte() noexcept { return static_cast<Byte>(next() >> 24); }

private:
    std::uint32_t state_;
};

static void TestGoldenMinimalFrame() {
    K6Frame f; // version=1, msg_type=0, flags=0, request_id=0, session_id=0, body empty
    std::vector<Byte> out;
    const Kad6Status st = EncodeK6Frame(f, out);
    CHECK(st == Kad6Status::Ok, "golden encode ok");
    CHECK(out.size() == kK6FrameHeaderSize, "golden size == 20");
    CHECK(K6FrameEncodedSize(f) == kK6FrameHeaderSize, "golden K6FrameEncodedSize == 20");

    static const Byte expected[20] = {
        1, 0,             // version, msg_type
        0, 0,             // flags LE
        0, 0, 0, 0,       // request_id LE
        0, 0, 0, 0, 0, 0, 0, 0, // session_id LE
        0, 0, 0, 0,       // body_len LE
    };
    bool bytesMatch = out.size() == 20;
    for (std::size_t i = 0; bytesMatch && i < 20; ++i)
        if (out[i] != expected[i]) bytesMatch = false;
    CHECK(bytesMatch, "golden byte layout");

    // Round-trip it back.
    K6Frame decoded;
    std::size_t consumed = 0;
    const Kad6Status dst = DecodeK6Frame(out.data(), out.size(), decoded, &consumed);
    CHECK(dst == Kad6Status::Ok, "golden decode ok");
    CHECK(consumed == 20, "golden consumed == 20");
    CHECK(decoded.version == 1 && decoded.msg_type == 0 && decoded.flags == 0 &&
              decoded.request_id == 0 && decoded.session_id == 0 && decoded.body.empty(),
          "golden decoded fields");
}

static void TestGoldenLayoutMixedValues() {
    // Exercise every field with a distinct, non-zero value and hand-check the
    // little-endian byte offsets against the spec table.
    K6Frame f;
    f.version = 1;
    f.msg_type = 0x07;
    f.flags = static_cast<std::uint16_t>(kK6FlagResponse | kK6FlagFinal | kK6FlagNativeKad6); // 0x0085
    f.request_id = 0xDEADBEEFu;
    f.session_id = 0x0102030405060708ull;
    f.body = {0xAA, 0xBB, 0xCC};

    std::vector<Byte> out;
    const Kad6Status st = EncodeK6Frame(f, out);
    CHECK(st == Kad6Status::Ok, "layout encode ok");
    CHECK(out.size() == 23, "layout size == 20+3");

    CHECK(out[0] == 1, "layout version byte");
    CHECK(out[1] == 0x07, "layout msg_type byte");
    CHECK(out[2] == 0x85 && out[3] == 0x00, "layout flags LE");
    CHECK(out[4] == 0xEF && out[5] == 0xBE && out[6] == 0xAD && out[7] == 0xDE,
          "layout request_id LE");
    CHECK(out[8] == 0x08 && out[9] == 0x07 && out[10] == 0x06 && out[11] == 0x05 &&
              out[12] == 0x04 && out[13] == 0x03 && out[14] == 0x02 && out[15] == 0x01,
          "layout session_id LE");
    CHECK(out[16] == 3 && out[17] == 0 && out[18] == 0 && out[19] == 0,
          "layout body_len LE");
    CHECK(out[20] == 0xAA && out[21] == 0xBB && out[22] == 0xCC, "layout body bytes");
}

static void TestRoundTripBodySizes() {
    const std::size_t sizes[] = {0, 1, 1000};
    for (std::size_t n : sizes) {
        K6Frame f;
        f.version = 1;
        f.msg_type = 0x42;
        f.flags = kK6FlagMore | kK6FlagStrict;
        f.request_id = 0x11223344u;
        f.session_id = 0x99887766AABBCCDDull;
        f.body.resize(n);
        for (std::size_t i = 0; i < n; ++i)
            f.body[i] = static_cast<Byte>(i & 0xFF);

        std::vector<Byte> wire;
        const Kad6Status est = EncodeK6Frame(f, wire);
        CHECK(est == Kad6Status::Ok, "roundtrip encode ok");
        CHECK(wire.size() == kK6FrameHeaderSize + n, "roundtrip wire size");
        CHECK(K6FrameEncodedSize(f) == wire.size(), "roundtrip encoded-size matches");

        K6Frame back;
        std::size_t consumed = 0;
        const Kad6Status dst = DecodeK6Frame(wire.data(), wire.size(), back, &consumed);
        CHECK(dst == Kad6Status::Ok, "roundtrip decode ok");
        CHECK(consumed == wire.size(), "roundtrip consumed == wire size");
        CHECK(back.version == f.version && back.msg_type == f.msg_type &&
                  back.flags == f.flags && back.request_id == f.request_id &&
                  back.session_id == f.session_id,
              "roundtrip scalar fields");
        CHECK(back.body == f.body, "roundtrip body bytes");
    }
}

static void TestRejectBodyTooLargeOnDecodeNoHugeAlloc() {
    // Declare a body_len far past the cap while supplying only the 20-byte
    // header (no body bytes at all). If the implementation checked the cap
    // before the length arithmetic / allocation, this returns instantly;
    // if it tried to size a buffer for the declared length first, this test
    // would hang or crash the process.
    std::vector<Byte> raw = RawHeader(1, 0, 0, 0, 0, 0xFFFFFFFFu);
    K6Frame out;
    const Kad6Status st = DecodeK6Frame(raw.data(), raw.size(), out, nullptr);
    CHECK(st == Kad6Status::TooLarge, "decode TooLarge on huge body_len");
    CHECK(out.body.empty(), "decode TooLarge leaves out.body empty");

    // Also just past the cap by one byte.
    std::vector<Byte> raw2 = RawHeader(1, 0, 0, 0, 0,
                                        static_cast<std::uint32_t>(kK6FrameMaxBody + 1));
    K6Frame out2;
    const Kad6Status st2 = DecodeK6Frame(raw2.data(), raw2.size(), out2, nullptr);
    CHECK(st2 == Kad6Status::TooLarge, "decode TooLarge on cap+1 body_len");
}

static void TestRejectBodyTooLargeOnEncode() {
    K6Frame f;
    f.version = 1;
    f.body.resize(kK6FrameMaxBody + 1);
    std::vector<Byte> out;
    const Kad6Status st = EncodeK6Frame(f, out);
    CHECK(st == Kad6Status::TooLarge, "encode TooLarge on oversized body");
    CHECK(out.empty(), "encode TooLarge clears out");
}

static void TestRejectUnsupportedVersion() {
    // Decode side.
    std::vector<Byte> raw = RawHeader(2, 0, 0, 0, 0, 0);
    K6Frame out;
    const Kad6Status st = DecodeK6Frame(raw.data(), raw.size(), out, nullptr);
    CHECK(st == Kad6Status::UnsupportedVersion, "decode rejects version=2");
    // out is reset to a default-constructed K6Frame on failure; the default
    // K6Frame::version is 1 (see kad6_frame.h), so that's what "reset" means
    // here — not the version byte that was rejected on the wire.
    CHECK(out.body.empty() && out.version == 1, "decode UnsupportedVersion resets out");

    // Encode side.
    K6Frame f;
    f.version = 2;
    std::vector<Byte> wire;
    const Kad6Status est = EncodeK6Frame(f, wire);
    CHECK(est == Kad6Status::UnsupportedVersion, "encode rejects version=2");
    CHECK(wire.empty(), "encode UnsupportedVersion clears out");
}

static void TestRejectDeclaredBodyLenExceedsBytesPresent() {
    // Header declares body_len=100 but only 5 body bytes actually follow.
    std::vector<Byte> raw = RawHeader(1, 0, 0, 0, 0, 100);
    for (int i = 0; i < 5; ++i) raw.push_back(static_cast<Byte>(i));
    K6Frame out;
    const Kad6Status st = DecodeK6Frame(raw.data(), raw.size(), out, nullptr);
    CHECK(st == Kad6Status::Truncated || st == Kad6Status::Malformed,
          "decode rejects body_len exceeding bytes present");
    CHECK(st != Kad6Status::Ok, "decode never Ok on short body");

    // Bonus: the opposite mismatch (more bytes present than declared) is
    // documented as Malformed in kad6_frame.h.
    std::vector<Byte> raw2 = RawHeader(1, 0, 0, 0, 0, 2);
    raw2.push_back(0xAA);
    raw2.push_back(0xBB);
    raw2.push_back(0xCC); // one extra trailing byte beyond the declared body_len
    K6Frame out2;
    const Kad6Status st2 = DecodeK6Frame(raw2.data(), raw2.size(), out2, nullptr);
    CHECK(st2 == Kad6Status::Malformed, "decode rejects trailing bytes beyond body_len");
}

static void TestEncoderRejectsReservedFlagBit() {
    K6Frame f;
    f.version = 1;
    f.flags = kK6FlagReservedMask & 0x0200; // bit 9, lowest reserved bit
    std::vector<Byte> out;
    const Kad6Status st = EncodeK6Frame(f, out);
    CHECK(st == Kad6Status::BadValue, "encode rejects reserved flag bit 9");
    CHECK(out.empty(), "encode BadValue clears out");

    K6Frame f2;
    f2.version = 1;
    f2.flags = kK6FlagReservedMask; // all reserved bits
    std::vector<Byte> out2;
    const Kad6Status st2 = EncodeK6Frame(f2, out2);
    CHECK(st2 == Kad6Status::BadValue, "encode rejects all-reserved flags");
}

static void TestDecodeTolerantOfReservedFlagBit() {
    // A reserved bit (9) set in the input must NOT fail decode; it round-
    // trips verbatim in K6Frame::flags (documented choice in kad6_frame.h).
    const std::uint16_t flagsWithReserved =
        static_cast<std::uint16_t>(kK6FlagResponse | 0x0200 /* bit 9 */);
    std::vector<Byte> raw = RawHeader(1, 0, flagsWithReserved, 0xCAFEBABEu, 0, 0);
    K6Frame out;
    const Kad6Status st = DecodeK6Frame(raw.data(), raw.size(), out, nullptr);
    CHECK(st == Kad6Status::Ok, "decode tolerates reserved flag bit");
    CHECK(out.flags == flagsWithReserved, "decode preserves reserved flag bit verbatim");
}

static void TestFuzzNeverCrashesNeverFalsePositiveOk() {
    Lcg32 rng(0x5EED1234u); // fixed seed — reproducible, never time/rand
    const int kIterations = 1000;
    int okCount = 0;
    for (int iter = 0; iter < kIterations; ++iter) {
        // Vary the buffer length across the run: small lengths hammer the
        // header-truncation paths; a few larger ones exercise body parsing.
        const std::size_t len = static_cast<std::size_t>(rng.next() % 300);
        std::vector<Byte> buf(len);
        for (std::size_t i = 0; i < len; ++i)
            buf[i] = rng.nextByte();

        K6Frame out;
        std::size_t consumed = 0xFFFFFFFFu;
        const Byte* p = buf.empty() ? nullptr : buf.data();
        const Kad6Status st = DecodeK6Frame(p, buf.size(), out, &consumed);

        if (st == Kad6Status::Ok) {
            ++okCount;
            // Whenever Ok is returned the result must be self-consistent: a
            // real frame, not a mis-parsed one.
            CHECK(out.version == 1, "fuzz Ok implies version==1");
            CHECK(out.body.size() <= kK6FrameMaxBody, "fuzz Ok implies body within cap");
            CHECK(consumed == kK6FrameHeaderSize + out.body.size(),
                  "fuzz Ok implies consumed == header+body");
            CHECK(consumed == buf.size(), "fuzz Ok implies consumed == whole buffer");
        } else {
            CHECK(consumed == 0, "fuzz non-Ok leaves *consumed == 0");
        }
    }
    // Sanity: with random garbage and len capped at <300 bytes, hitting a
    // structurally valid frame should be rare but is not itself a failure —
    // the loop's CHECKs above are what actually pin correctness.
    std::printf("  (fuzz: %d/%d buffers decoded Ok)\n", okCount, kIterations);
}

int main() {
    TestGoldenMinimalFrame();
    TestGoldenLayoutMixedValues();
    TestRoundTripBodySizes();
    TestRejectBodyTooLargeOnDecodeNoHugeAlloc();
    TestRejectBodyTooLargeOnEncode();
    TestRejectUnsupportedVersion();
    TestRejectDeclaredBodyLenExceedsBytesPresent();
    TestEncoderRejectsReservedFlagBit();
    TestDecodeTolerantOfReservedFlagBit();
    TestFuzzNeverCrashesNeverFalsePositiveOk();

    std::printf("test_kad6_frame: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
