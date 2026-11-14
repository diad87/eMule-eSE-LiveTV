#pragma once
#include <cstdint>

namespace ese::server {
inline constexpr char kEseWireServerAlpn[] = "ese-server/1";
inline constexpr char kEseWireServerMagic[] = "ESES";
inline constexpr char kEseWireServerExporterLabel[] = "EXPORTER-eSE-server-v1";
inline constexpr char kEseWireServerAuthDomain[] = "ESE-SERVER-AUTH/1";
inline constexpr char kEseWireRdv2ExporterLabel[] = "EXPORTER-eSE-rdv2-v1";
inline constexpr char kEseWireRdv2Magic[] = "ESERDV2\0";
inline constexpr char kEseWireRdv2CookieDomain[] = "ESE-RDV-COOKIE/1";

inline constexpr std::uint16_t kEseWireServerClientHello = 0x0001;
inline constexpr std::uint16_t kEseWireServerServerHello = 0x0002;
inline constexpr std::uint16_t kEseWireServerServerProof = 0x0003;
inline constexpr std::uint16_t kEseWireServerClientProof = 0x0004;
inline constexpr std::uint16_t kEseWireServerAuthOk = 0x0005;
inline constexpr std::uint16_t kEseWireServerSessionRenew = 0x0006;
inline constexpr std::uint16_t kEseWireServerEd2kCommand = 0x0010;
inline constexpr std::uint16_t kEseWireServerEd2kEvent = 0x0011;
inline constexpr std::uint16_t kEseWireServerAck = 0x0012;
inline constexpr std::uint16_t kEseWireServerSourceHintsGet = 0x0014;
inline constexpr std::uint16_t kEseWireServerSourceHints = 0x0015;
inline constexpr std::uint16_t kEseWireServerPubBegin = 0x0020;
inline constexpr std::uint16_t kEseWireServerPubChunk = 0x0021;
inline constexpr std::uint16_t kEseWireServerPubCommit = 0x0022;
inline constexpr std::uint16_t kEseWireServerPubStateGet = 0x0023;
inline constexpr std::uint16_t kEseWireServerPubState = 0x0024;
inline constexpr std::uint16_t kEseWireServerVoucherGet = 0x0030;
inline constexpr std::uint16_t kEseWireServerVoucher = 0x0031;
inline constexpr std::uint16_t kEseWireServerPairRequest = 0x0032;
inline constexpr std::uint16_t kEseWireServerConsentQuery = 0x0033;
inline constexpr std::uint16_t kEseWireServerConsentReply = 0x0034;
inline constexpr std::uint16_t kEseWireServerPairResult = 0x0035;
inline constexpr std::uint16_t kEseWireServerRegStatus = 0x0036;
inline constexpr std::uint16_t kEseWireServerProbeRequest = 0x0040;
inline constexpr std::uint16_t kEseWireServerProbeResult = 0x0041;
inline constexpr std::uint16_t kEseWireServerProbeReady = 0x0042;
inline constexpr std::uint16_t kEseWireServerProbeArm = 0x0043;
inline constexpr std::uint16_t kEseWireServerPong = 0x00FD;
inline constexpr std::uint16_t kEseWireServerPing = 0x00FE;
inline constexpr std::uint16_t kEseWireServerError = 0x00FF;

inline constexpr std::uint16_t kEseWireServerResponse = 0x0001;
inline constexpr std::uint16_t kEseWireServerFinal = 0x0002;

inline constexpr std::uint32_t kEseWireServerCapEd2kEnvelope = 0x00000001;
inline constexpr std::uint32_t kEseWireServerCapIpv6EnodeV1 = 0x00000002;
inline constexpr std::uint32_t kEseWireServerCapRdv2 = 0x00000004;
inline constexpr std::uint32_t kEseWireServerCapCrossCallback = 0x00000008;
inline constexpr std::uint32_t kEseWireServerCapAtomicPublish = 0x00000010;
inline constexpr std::uint32_t kEseWireServerCapIpv6Connectback = 0x00000020;

inline constexpr std::uint16_t kEseWireServerMalformed = 1;
inline constexpr std::uint16_t kEseWireServerUnsupported = 2;
inline constexpr std::uint16_t kEseWireServerAuthRequired = 3;
inline constexpr std::uint16_t kEseWireServerAuthFailed = 4;
inline constexpr std::uint16_t kEseWireServerExpired = 5;
inline constexpr std::uint16_t kEseWireServerReplay = 6;
inline constexpr std::uint16_t kEseWireServerNoConsent = 7;
inline constexpr std::uint16_t kEseWireServerRateLimit = 8;
inline constexpr std::uint16_t kEseWireServerResourceLimit = 9;
inline constexpr std::uint16_t kEseWireServerConflict = 10;
inline constexpr std::uint16_t kEseWireServerTargetGone = 11;
inline constexpr std::uint16_t kEseWireServerFiltered = 12;
inline constexpr std::uint16_t kEseWireServerWrongState = 13;

inline constexpr std::uint8_t kEseWireRdv2Register = 1;
inline constexpr std::uint8_t kEseWireRdv2Challenge = 2;
inline constexpr std::uint8_t kEseWireRdv2Echo = 3;
inline constexpr std::uint8_t kEseWireRdv2Keepalive = 4;
}
