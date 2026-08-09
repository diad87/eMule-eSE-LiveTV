#include "natmap/ownership_ledger.h"

#include <array>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#endif

namespace {

struct ExpectedPair {
    std::uint64_t generation = 0;
    std::uint16_t tcp_local = 0;
    std::uint16_t tcp_external = 0;
    std::uint16_t udp_local = 0;
    std::uint16_t udp_external = 0;
    std::array<std::uint8_t, 32> journal_sha256{};
};

enum class PairStatus : unsigned {
    Match = 0,
    WrongCount = 1,
    DuplicateTransport = 2,
    Mismatch = 3,
};

bool ParseU64(const std::string& text, std::uint64_t& value) noexcept {
    if (text.empty())
        return false;
    std::uint64_t parsed = 0;
    const std::uint64_t maximum =
        (std::numeric_limits<std::uint64_t>::max)();
    for (const char character : text) {
        if (character < '0' || character > '9')
            return false;
        const std::uint64_t digit =
            static_cast<std::uint64_t>(character - '0');
        if (parsed > (maximum - digit) / 10)
            return false;
        parsed = parsed * 10 + digit;
    }
    value = parsed;
    return true;
}

bool ParsePort(const std::string& text, std::uint16_t& value) noexcept {
    std::uint64_t parsed = 0;
    if (!ParseU64(text, parsed) || parsed == 0 ||
        parsed > (std::numeric_limits<std::uint16_t>::max)())
        return false;
    value = static_cast<std::uint16_t>(parsed);
    return true;
}

bool IsSafeBasename(const char* text) noexcept {
    if (text == nullptr || *text == '\0' ||
        std::strcmp(text, ".") == 0 || std::strcmp(text, "..") == 0)
        return false;
    for (const unsigned char character : std::string(text))
        if (character < 0x20 || character == 0x7f ||
            character == '/' || character == '\\' || character == ':')
            return false;
    return true;
}

bool ReadField(const char* key, std::string& value) {
    std::string line;
    if (!std::getline(std::cin, line))
        return false;
    if (!line.empty() && line.back() == '\r')
        line.pop_back();
    const std::string prefix = std::string(key) + "=";
    if (line.compare(0, prefix.size(), prefix) != 0)
        return false;
    value = line.substr(prefix.size());
    return true;
}

bool ReadExpectedPair(ExpectedPair& expected) {
    std::string generation;
    std::string tcp_local;
    std::string tcp_external;
    std::string udp_local;
    std::string udp_external;
    std::string journal_sha256;
    if (!ReadField("generation", generation) ||
        !ReadField("tcp_local", tcp_local) ||
        !ReadField("tcp_external", tcp_external) ||
        !ReadField("udp_local", udp_local) ||
        !ReadField("udp_external", udp_external) ||
        !ReadField("journal_sha256", journal_sha256))
        return false;
    std::string extra;
    if (std::getline(std::cin, extra))
        return false;
    if (journal_sha256.size() != expected.journal_sha256.size() * 2)
        return false;
    for (std::size_t i = 0; i < expected.journal_sha256.size(); ++i) {
        const auto Hex = [](char value) -> int {
            if (value >= '0' && value <= '9') return value - '0';
            if (value >= 'a' && value <= 'f') return value - 'a' + 10;
            return -1;
        };
        const int high = Hex(journal_sha256[i * 2]);
        const int low = Hex(journal_sha256[i * 2 + 1]);
        if (high < 0 || low < 0)
            return false;
        expected.journal_sha256[i] = static_cast<std::uint8_t>(high * 16 + low);
    }
    return ParseU64(generation, expected.generation) &&
        expected.generation != 0 &&
        ParsePort(tcp_local, expected.tcp_local) &&
        ParsePort(tcp_external, expected.tcp_external) &&
        ParsePort(udp_local, expected.udp_local) &&
        ParsePort(udp_external, expected.udp_external);
}

#ifdef _WIN32
bool Sha256(const std::uint8_t* bytes, std::size_t size,
            std::array<std::uint8_t, 32>& digest) noexcept {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD object_size = 0;
    DWORD copied = 0;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM,
            nullptr, 0) < 0 ||
        BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size),
            &copied, 0) < 0) {
        if (algorithm != nullptr) BCryptCloseAlgorithmProvider(algorithm, 0);
        return false;
    }
    std::vector<std::uint8_t> object(object_size);
    const bool ok = BCryptCreateHash(algorithm, &hash, object.data(),
            object_size, nullptr, 0, 0) >= 0 &&
        BCryptHashData(hash, const_cast<PUCHAR>(bytes),
            static_cast<ULONG>(size), 0) >= 0 &&
        BCryptFinishHash(hash, digest.data(),
            static_cast<ULONG>(digest.size()), 0) >= 0;
    if (hash != nullptr) BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return ok;
}
#endif

PairStatus CompareExpectedPair(const natmap::OwnershipLedger& ledger,
                               const ExpectedPair& expected) noexcept {
    if (ledger.count != 2)
        return PairStatus::WrongCount;
    bool tcp = false;
    bool udp = false;
    for (std::uint8_t i = 0; i < ledger.count; ++i) {
        const natmap::UpnpOwnershipRecord& record = ledger.records[i];
        if (record.generation != expected.generation)
            return PairStatus::Mismatch;
        if (record.transport == natmap::Transport::Tcp) {
            if (tcp)
                return PairStatus::DuplicateTransport;
            tcp = true;
            if (record.local_port != expected.tcp_local ||
                record.external_port != expected.tcp_external)
                return PairStatus::Mismatch;
        } else if (record.transport == natmap::Transport::Udp) {
            if (udp)
                return PairStatus::DuplicateTransport;
            udp = true;
            if (record.local_port != expected.udp_local ||
                record.external_port != expected.udp_external)
                return PairStatus::Mismatch;
        } else {
            return PairStatus::Mismatch;
        }
    }
    return tcp && udp ? PairStatus::Match : PairStatus::Mismatch;
}

const char* DecodeClass(natmap::OwnershipLedgerDecodeStatus status) noexcept {
    using Status = natmap::OwnershipLedgerDecodeStatus;
    switch (status) {
    case Status::Ok: return "PASS";
    case Status::BadChecksum: return "CHECKSUM_FAIL";
    case Status::UnsupportedVersion:
    case Status::BadRecordSize:
    case Status::BadMagic: return "SCHEMA_FAIL";
    case Status::TooManyRecords:
    case Status::BadLength:
    case Status::Truncated: return "LENGTH_FAIL";
    case Status::InvalidRecord: return "RECORD_FAIL";
    default: return "DECODE_FAIL";
    }
}

int Inspect(const char* path, const ExpectedPair& expected) {
#ifdef _WIN32
    const HANDLE file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        const DWORD error = GetLastError();
        const bool missing = error == ERROR_FILE_NOT_FOUND ||
            error == ERROR_PATH_NOT_FOUND;
        std::printf("codec=FAIL reason=%s\n", missing ? "NOT_FOUND" : "READ");
        return missing ? 3 : 5;
    }
    BY_HANDLE_FILE_INFORMATION before{};
    if (!GetFileInformationByHandle(file, &before) ||
        (before.dwFileAttributes &
            (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
        CloseHandle(file);
        std::printf("codec=FAIL reason=READ\n");
        return 5;
    }
    std::array<std::uint8_t, natmap::kOwnershipLedgerMaxEncodedSize + 1>
        bytes{};
    DWORD read = 0;
    const BOOL read_ok = ReadFile(file, bytes.data(),
        static_cast<DWORD>(bytes.size()), &read, nullptr);
    BY_HANDLE_FILE_INFORMATION after{};
    const bool stable = read_ok && GetFileInformationByHandle(file, &after) &&
        before.dwVolumeSerialNumber == after.dwVolumeSerialNumber &&
        before.nFileIndexHigh == after.nFileIndexHigh &&
        before.nFileIndexLow == after.nFileIndexLow &&
        before.nFileSizeHigh == after.nFileSizeHigh &&
        before.nFileSizeLow == after.nFileSizeLow &&
        before.ftLastWriteTime.dwHighDateTime == after.ftLastWriteTime.dwHighDateTime &&
        before.ftLastWriteTime.dwLowDateTime == after.ftLastWriteTime.dwLowDateTime;
    CloseHandle(file);
    if (!stable) {
        std::printf("codec=FAIL reason=READ\n");
        return 5;
    }
    const std::size_t size = static_cast<std::size_t>(read);
#else
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        std::error_code error;
        const bool exists = std::filesystem::exists(path, error);
        std::printf("codec=FAIL reason=%s\n",
                    exists && !error ? "READ" : "NOT_FOUND");
        return exists && !error ? 5 : 3;
    }
    std::array<std::uint8_t, natmap::kOwnershipLedgerMaxEncodedSize + 1>
        bytes{};
    file.read(reinterpret_cast<char*>(bytes.data()),
              static_cast<std::streamsize>(bytes.size()));
    const std::streamsize read = file.gcount();
    if (file.bad() || read < 0) {
        std::printf("codec=FAIL reason=READ\n");
        return 5;
    }
    const std::size_t size = static_cast<std::size_t>(read);
    if (size > natmap::kOwnershipLedgerMaxEncodedSize) {
        std::printf("codec=FAIL reason=LENGTH\n");
        return 4;
    }
    // Reading capacity+1 and requiring EOF makes growth before/during the
    // bounded snapshot visible instead of silently decoding a valid prefix.
    if (!file.eof()) {
        const int next = file.peek();
        if (next != std::char_traits<char>::eof()) {
            std::printf("codec=FAIL reason=LENGTH\n");
            return 4;
        }
    }
#endif
    if (size > natmap::kOwnershipLedgerMaxEncodedSize) {
        std::printf("codec=FAIL reason=LENGTH\n");
        return 4;
    }
#ifdef _WIN32
    std::array<std::uint8_t, 32> actual_hash{};
    if (!Sha256(bytes.data(), size, actual_hash) ||
        actual_hash != expected.journal_sha256) {
        std::printf("codec=FAIL reason=HASH\n");
        return 6;
    }
#endif
    natmap::OwnershipLedger ledger{};
    const natmap::OwnershipLedgerDecodeStatus decoded =
        natmap::DecodeOwnershipLedger(bytes.data(), size, ledger);
    if (decoded != natmap::OwnershipLedgerDecodeStatus::Ok) {
        std::printf("codec=FAIL class=%s\n", DecodeClass(decoded));
        return 6;
    }
    const PairStatus pair = CompareExpectedPair(ledger, expected);
    std::printf("codec=PASS schema=PASS checksum=PASS count=%s pair=%s\n",
                ledger.count == 2 ? "PASS" : "FAIL",
                pair == PairStatus::Match ? "PASS" : "FAIL");
    return pair == PairStatus::Match ? 0 : 7;
}

natmap::UpnpOwnershipRecord Record(natmap::Transport transport,
                                   std::uint16_t local,
                                   std::uint16_t external,
                                   std::uint64_t generation) {
    natmap::UpnpOwnershipRecord record{};
    record.owner_token = 0x123456789abcdef0ULL;
    record.gateway_fingerprint = 0x0fedcba987654321ULL;
    record.transport = transport;
    record.local_address = natmap::IpAddress::V4(192, 0, 2, 10);
    record.local_port = local;
    record.external_port = external;
    record.lifetime_seconds = 3600;
    record.acquired_unix_seconds = 1;
    record.generation = generation;
    record.description = natmap::BuildOwnershipDescription(
        record.owner_token, transport);
    return record;
}

int SelfTest() {
    const ExpectedPair expected{9, 41001, 42001, 41002, 42002};
    natmap::OwnershipLedger ledger{};
    ledger.count = 2;
    ledger.records[0] = Record(
        natmap::Transport::Tcp, expected.tcp_local,
        expected.tcp_external, expected.generation);
    ledger.records[1] = Record(
        natmap::Transport::Udp, expected.udp_local,
        expected.udp_external, expected.generation);
    std::array<std::uint8_t, natmap::kOwnershipLedgerMaxEncodedSize> bytes{};
    const std::size_t size = natmap::EncodeOwnershipLedger(
        ledger, bytes.data(), bytes.size());
    natmap::OwnershipLedger decoded{};
    if (size == 0 || natmap::DecodeOwnershipLedger(
            bytes.data(), size, decoded) !=
            natmap::OwnershipLedgerDecodeStatus::Ok ||
        CompareExpectedPair(decoded, expected) != PairStatus::Match)
        return 10;
    ExpectedPair wrong = expected;
    ++wrong.udp_external;
    if (CompareExpectedPair(decoded, wrong) != PairStatus::Mismatch)
        return 11;
    natmap::OwnershipLedger one = ledger;
    one.count = 1;
    if (CompareExpectedPair(one, expected) != PairStatus::WrongCount)
        return 12;
    natmap::OwnershipLedger duplicate = ledger;
    duplicate.records[1] = duplicate.records[0];
    if (CompareExpectedPair(duplicate, expected) !=
        PairStatus::DuplicateTransport)
        return 13;
    std::array<std::uint8_t, natmap::kOwnershipLedgerMaxEncodedSize> corrupt =
        bytes;
    corrupt[size - 1] ^= 1;
    if (natmap::DecodeOwnershipLedger(corrupt.data(), size, decoded) !=
        natmap::OwnershipLedgerDecodeStatus::BadChecksum)
        return 14;
    corrupt = bytes;
    corrupt[8] ^= 1;
    if (natmap::DecodeOwnershipLedger(corrupt.data(), size, decoded) !=
        natmap::OwnershipLedgerDecodeStatus::UnsupportedVersion)
        return 15;
    if (natmap::DecodeOwnershipLedger(bytes.data(), size - 1, decoded) !=
        natmap::OwnershipLedgerDecodeStatus::BadLength)
        return 16;
    std::uint64_t parsed = 0;
    if (!ParseU64("18446744073709551615", parsed) ||
        parsed != (std::numeric_limits<std::uint64_t>::max)() ||
        ParseU64("18446744073709551616", parsed) ||
        ParseU64("+1", parsed) || ParseU64(" 1", parsed) ||
        ParseU64("1 ", parsed) || ParseU64("1\t", parsed) ||
        ParseU64("0x1", parsed) || ParseU64("", parsed))
        return 17;
    std::printf("natmap ownership inspect selftest: PASS\n");
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    if (argc == 2 && std::strcmp(argv[1], "--selftest") == 0)
        return SelfTest();
    if (argc != 3 || std::strcmp(argv[1], "--expect-pair") != 0 ||
        !IsSafeBasename(argv[2])) {
        std::fprintf(stderr,
            "usage: natmap_ownership_inspect --expect-pair <journal-basename>\n");
        return 2;
    }
    ExpectedPair expected{};
    if (!ReadExpectedPair(expected)) {
        std::printf("codec=FAIL reason=INVALID_EXPECTATION\n");
        return 2;
    }
    return Inspect(argv[2], expected);
}
