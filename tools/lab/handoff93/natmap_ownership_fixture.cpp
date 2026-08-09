#include "natmap/ownership_ledger.h"

#include <array>
#include <cstring>
#include <fstream>

namespace {
natmap::UpnpOwnershipRecord Record(natmap::Transport transport,
                                   std::uint16_t local,
                                   std::uint16_t external) {
    natmap::UpnpOwnershipRecord record{};
    record.owner_token = 0x123456789abcdef0ULL;
    record.gateway_fingerprint = 0x0fedcba987654321ULL;
    record.transport = transport;
    record.local_address = natmap::IpAddress::V4(192, 0, 2, 10);
    record.local_port = local;
    record.external_port = external;
    record.lifetime_seconds = 3600;
    record.acquired_unix_seconds = 1;
    record.generation = 9;
    record.description = natmap::BuildOwnershipDescription(
        record.owner_token, transport);
    return record;
}
} // namespace

int main(int argc, char** argv) {
    if (argc != 3 || std::strchr(argv[1], '/') != nullptr ||
        std::strchr(argv[1], '\\') != nullptr)
        return 2;
    natmap::OwnershipLedger ledger{};
    ledger.count = 2;
    ledger.records[0] = Record(natmap::Transport::Tcp, 41001, 42001);
    ledger.records[1] = Record(natmap::Transport::Udp, 41002, 42002);
    std::array<std::uint8_t, natmap::kOwnershipLedgerMaxEncodedSize + 1>
        bytes{};
    std::size_t size = natmap::EncodeOwnershipLedger(
        ledger, bytes.data(), bytes.size());
    if (size == 0)
        return 3;
    if (std::strcmp(argv[2], "crc") == 0)
        bytes[size - 1] ^= 1;
    else if (std::strcmp(argv[2], "schema") == 0)
        bytes[8] ^= 1;
    else if (std::strcmp(argv[2], "truncated") == 0)
        --size;
    else if (std::strcmp(argv[2], "oversize") == 0)
        size = bytes.size();
    else if (std::strcmp(argv[2], "valid") != 0)
        return 2;
    std::ofstream output(argv[1], std::ios::binary | std::ios::trunc);
    if (!output.write(reinterpret_cast<const char*>(bytes.data()),
                      static_cast<std::streamsize>(size)))
        return 4;
    return 0;
}
