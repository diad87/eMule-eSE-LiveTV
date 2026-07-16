#include "natmap/ownership_ledger.h"

#include <array>
#include <cstdio>
#include <fstream>

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(stderr, "usage: natmap_ownership_inspect <journal>\n");
        return 2;
    }

    std::ifstream file(argv[1], std::ios::binary | std::ios::ate);
    if (!file) {
        std::fprintf(stderr, "journal: not found\n");
        return 3;
    }
    const std::streamoff signed_size = file.tellg();
    if (signed_size < 0 || static_cast<unsigned long long>(signed_size) >
            natmap::kOwnershipLedgerMaxEncodedSize) {
        std::fprintf(stderr, "journal: invalid length\n");
        return 4;
    }
    const std::size_t size = static_cast<std::size_t>(signed_size);
    std::array<std::uint8_t, natmap::kOwnershipLedgerMaxEncodedSize> bytes{};
    file.seekg(0);
    if (!file.read(reinterpret_cast<char*>(bytes.data()),
                   static_cast<std::streamsize>(size))) {
        std::fprintf(stderr, "journal: read failed\n");
        return 5;
    }

    natmap::OwnershipLedger ledger{};
    const natmap::OwnershipLedgerDecodeStatus status =
        natmap::DecodeOwnershipLedger(bytes.data(), size, ledger);
    std::printf("decode_status=%u records=%u\n",
                static_cast<unsigned>(status),
                status == natmap::OwnershipLedgerDecodeStatus::Ok
                    ? static_cast<unsigned>(ledger.count) : 0u);
    if (status != natmap::OwnershipLedgerDecodeStatus::Ok)
        return 6;

    for (std::uint8_t i = 0; i < ledger.count; ++i) {
        const natmap::UpnpOwnershipRecord& record = ledger.records[i];
        std::printf("  %s local=%u.%u.%u.%u:%u external=%u "
                    "lifetime=%u generation=%llu\n",
                    record.transport == natmap::Transport::Tcp ? "TCP" : "UDP",
                    static_cast<unsigned>(record.local_address.bytes[0]),
                    static_cast<unsigned>(record.local_address.bytes[1]),
                    static_cast<unsigned>(record.local_address.bytes[2]),
                    static_cast<unsigned>(record.local_address.bytes[3]),
                    static_cast<unsigned>(record.local_port),
                    static_cast<unsigned>(record.external_port),
                    static_cast<unsigned>(record.lifetime_seconds),
                    static_cast<unsigned long long>(record.generation));
    }
    return 0;
}
