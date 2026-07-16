#pragma once

#include "natmap/natmap_types.h"

#include <array>
#include <cstddef>
#include <cstdint>

namespace natmap {

// UPnP descriptions are deliberately short because a number of consumer IGDs
// cap this field well below the limit in the specification. The full 64-bit
// token remains visible, making accidental ownership collisions negligible.
constexpr std::size_t kOwnershipDescriptionCapacity = 24;
constexpr std::size_t kMaxOwnershipRecords = 8;

using OwnershipDescription =
    std::array<char, kOwnershipDescriptionCapacity>;

OwnershipDescription BuildOwnershipDescription(
    std::uint64_t owner_token, Transport transport) noexcept;

// Durable proof of a UPnP rule created by this eMule instance. The host writes
// the ledger atomically only after the router returns the exact description,
// internal client and internal port that were requested.
struct UpnpOwnershipRecord {
    std::uint64_t owner_token = 0;
    std::uint64_t gateway_fingerprint = 0;
    Transport transport = Transport::Tcp;
    IpAddress local_address{};
    std::uint16_t local_port = 0;
    std::uint16_t external_port = 0;
    std::uint32_t lifetime_seconds = 0;
    std::uint64_t acquired_unix_seconds = 0;
    std::uint64_t generation = 0;
    OwnershipDescription description{};

    bool IsStructurallyValid() const noexcept;
};

// Current router state returned by GetSpecificPortMappingEntry.
struct ObservedUpnpMapping {
    Transport transport = Transport::Tcp;
    IpAddress local_address{};
    std::uint16_t local_port = 0;
    std::uint16_t external_port = 0;
    OwnershipDescription description{};

    bool IsStructurallyValid() const noexcept;
};

enum class OwnershipDecision : std::uint8_t {
    Owned = 0,
    InvalidRecord = 1,
    InvalidObservation = 2,
    GatewayMismatch = 3,
    TransportMismatch = 4,
    ExternalPortMismatch = 5,
    InternalClientMismatch = 6,
    InternalPortMismatch = 7,
    DescriptionMismatch = 8,
};

// This is the only authorization gate for crash-recovery deletion. A persisted
// port number alone is never sufficient.
OwnershipDecision EvaluateOwnershipForDeletion(
    const UpnpOwnershipRecord& record,
    std::uint64_t current_gateway_fingerprint,
    const ObservedUpnpMapping& observed) noexcept;

struct OwnershipLedger {
    std::array<UpnpOwnershipRecord, kMaxOwnershipRecords> records{};
    std::uint8_t count = 0;

    bool IsStructurallyValid() const noexcept;
};

enum class OwnershipLedgerDecodeStatus : std::uint8_t {
    Ok = 0,
    Truncated = 1,
    BadMagic = 2,
    UnsupportedVersion = 3,
    BadRecordSize = 4,
    TooManyRecords = 5,
    BadLength = 6,
    BadChecksum = 7,
    InvalidRecord = 8,
};

constexpr std::size_t kOwnershipLedgerMaxEncodedSize =
    16u + kMaxOwnershipRecords * 84u + 4u;

// Fixed-width, checksummed codec. File I/O intentionally remains in the host
// so libnatmap stays deterministic and independent of MFC/Win32.
std::size_t EncodeOwnershipLedger(const OwnershipLedger& ledger,
                                  std::uint8_t* out,
                                  std::size_t capacity) noexcept;
OwnershipLedgerDecodeStatus DecodeOwnershipLedger(
    const std::uint8_t* bytes, std::size_t length,
    OwnershipLedger& ledger) noexcept;

} // namespace natmap
