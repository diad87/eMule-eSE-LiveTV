#include "natmap/natpmp_codec.h"
#include "natmap/pcp_codec.h"

#include <array>
#include <cstdio>
#include <cstring>

using namespace natmap;

namespace {

int checks = 0;
int failures = 0;
#define CHECK(expr) do { ++checks; if (!(expr)) { ++failures; \
    std::printf("FAIL line %d: %s\n", __LINE__, #expr); } } while (0)

void Put16(std::uint8_t* p, std::uint16_t v) {
    p[0] = static_cast<std::uint8_t>(v >> 8); p[1] = static_cast<std::uint8_t>(v);
}
void Put32(std::uint8_t* p, std::uint32_t v) {
    p[0] = static_cast<std::uint8_t>(v >> 24); p[1] = static_cast<std::uint8_t>(v >> 16);
    p[2] = static_cast<std::uint8_t>(v >> 8); p[3] = static_cast<std::uint8_t>(v);
}

void TestNatPmpVectors() {
    std::array<std::uint8_t, 12> request{};
    CHECK(EncodeNatPmpMapRequest(NatPmpTransport::Tcp, 4662, 443, 7200,
                                 request.data(), request.size()));
    const std::array<std::uint8_t, 12> expected{
        0, 2, 0, 0, 0x12, 0x36, 0x01, 0xBB, 0, 0, 0x1C, 0x20};
    CHECK(request == expected);

    CHECK(EncodeNatPmpMapRequest(NatPmpTransport::Tcp, 4662, 443, 0,
                                 request.data(), request.size()));
    CHECK(request[6] == 0 && request[7] == 0);

    std::array<std::uint8_t, 16> response{};
    response[1] = 130;
    Put32(response.data() + 4, 99);
    Put16(response.data() + 8, 4662);
    Put16(response.data() + 10, 52144);
    Put32(response.data() + 12, 3600);
    NatPmpMapResponse decoded{};
    CHECK(DecodeNatPmpMapResponse(response.data(), response.size(),
        NatPmpTransport::Tcp, 4662, decoded) == NatPmpDecodeStatus::Ok);
    CHECK(decoded.external_port == 52144);
    CHECK(decoded.epoch == 99 && decoded.lifetime_seconds == 3600);
    CHECK(DecodeNatPmpMapResponse(response.data(), response.size(),
        NatPmpTransport::Udp, 4662, decoded) == NatPmpDecodeStatus::BadOpcode);
    CHECK(DecodeNatPmpMapResponse(response.data(), response.size(),
        NatPmpTransport::Tcp, 4672, decoded) == NatPmpDecodeStatus::WrongInternalPort);

	std::array<std::uint8_t, 12> externalResponse{};
	externalResponse[1] = 128;
	Put32(externalResponse.data() + 4, 42);
	externalResponse[8] = 88;
	externalResponse[9] = 11;
	externalResponse[10] = 22;
	externalResponse[11] = 4;
	NatPmpExternalAddressResponse externalDecoded{};
	CHECK(DecodeNatPmpExternalAddressResponse(externalResponse.data(),
		externalResponse.size(), externalDecoded) == NatPmpDecodeStatus::Ok);
	CHECK(externalDecoded.epoch == 42);
	CHECK(std::memcmp(&externalDecoded.external_ip_network_order,
		externalResponse.data() + 8, 4) == 0);
}

PcpMapRequest Request() {
    PcpMapRequest request{};
    request.lifetime_seconds = 7200;
    request.client_ip = PcpIpv4Mapped(192, 168, 1, 20);
    for (std::size_t i = 0; i < request.nonce.size(); ++i)
        request.nonce[i] = static_cast<std::uint8_t>(i + 1);
    request.protocol = 6;
    request.internal_port = 4662;
    request.suggested_external_port = 443;
    return request;
}

void TestPcpRequestVectors() {
    std::array<std::uint8_t, 128> bytes{};
    PcpMapRequest request = Request();
    std::size_t size = EncodePcpMapRequest(request, bytes.data(), bytes.size());
    CHECK(size == 60);
    CHECK(bytes[0] == 2 && bytes[1] == 1);
    CHECK(bytes[18] == 0xFF && bytes[19] == 0xFF);
    CHECK(bytes[20] == 192 && bytes[23] == 20);
    CHECK(bytes[36] == 6 && bytes[40] == 0x12 && bytes[41] == 0x36);
    CHECK(bytes[42] == 0x01 && bytes[43] == 0xBB);

    request.prefer_failure = true;
    size = EncodePcpMapRequest(request, bytes.data(), bytes.size());
    CHECK(size == 64);
    CHECK(bytes[60] == 2 && bytes[61] == 0 && bytes[62] == 0 && bytes[63] == 0);

    request.prefer_failure = false;
    request.port_set_size = 32;
    request.first_internal_port = request.internal_port;
    request.preserve_parity = true;
    size = EncodePcpMapRequest(request, bytes.data(), bytes.size());
    CHECK(size == 72);
    CHECK(bytes[60] == 130 && bytes[63] == 5);
    CHECK(bytes[64] == 0 && bytes[65] == 32);
    CHECK(bytes[66] == 0x12 && bytes[67] == 0x36 && bytes[68] == 1);

    request.lifetime_seconds = 0;
    request.port_set_size = 0;
    size = EncodePcpMapRequest(request, bytes.data(), bytes.size());
    CHECK(size == 60);
    bool zero = true;
    for (std::size_t i = 42; i < 60; ++i) zero = zero && bytes[i] == 0;
    CHECK(zero);
}

void TestPcpResponseValidation() {
    const PcpMapRequest request = Request();
    std::array<std::uint8_t, 72> response{};
    response[0] = 2;
    response[1] = 0x81;
    Put32(response.data() + 4, 3600);
    Put32(response.data() + 8, 1234);
    std::memcpy(response.data() + 24, request.nonce.data(), request.nonce.size());
    response[36] = request.protocol;
    Put16(response.data() + 40, request.internal_port);
    Put16(response.data() + 42, 52144);
    const auto external = PcpIpv4Mapped(88, 11, 22, 4);
    std::memcpy(response.data() + 44, external.data(), external.size());
    response[60] = 130;
    Put16(response.data() + 62, 5);
    Put16(response.data() + 64, 32);
    Put16(response.data() + 66, request.internal_port);

    PcpMapResponse decoded{};
    CHECK(DecodePcpMapResponse(response.data(), response.size(), request, decoded)
          == PcpDecodeStatus::Ok);
    CHECK(decoded.external_port == 52144 && decoded.epoch == 1234);
    CHECK(decoded.has_port_set && decoded.port_set_size == 32);
    CHECK(decoded.external_ip == external);
	response[3] = static_cast<std::uint8_t>(PcpResultCode::CannotProvideExternal);
	CHECK(DecodePcpMapResponse(response.data(), response.size(), request, decoded)
		== PcpDecodeStatus::Ok);
	CHECK(decoded.result == PcpResultCode::CannotProvideExternal);
	response[3] = 0;

    response[24] ^= 1;
    CHECK(DecodePcpMapResponse(response.data(), response.size(), request, decoded)
          == PcpDecodeStatus::WrongNonce);
    response[24] ^= 1;
    Put16(response.data() + 62, 80);
    CHECK(DecodePcpMapResponse(response.data(), response.size(), request, decoded)
          == PcpDecodeStatus::MalformedOption);
    CHECK(DecodePcpMapResponse(response.data(), 59, request, decoded)
          == PcpDecodeStatus::Truncated);
}

void TestAnnounce() {
    std::array<std::uint8_t, 24> bytes{};
    const auto client = PcpIpv4Mapped(192, 168, 1, 20);
    CHECK(EncodePcpAnnounceRequest(client, bytes.data(), bytes.size()) == 24);
    CHECK(bytes[0] == 2 && bytes[1] == 0);
    CHECK(std::memcmp(bytes.data() + 8, client.data(), client.size()) == 0);
	std::array<std::uint8_t, 24> response{};
	response[0] = 2;
	response[1] = 0x80;
	response[3] = static_cast<std::uint8_t>(PcpResultCode::NotAuthorized);
	Put32(response.data() + 8, 9876);
	PcpAnnounceResponse decoded{};
	CHECK(DecodePcpAnnounceResponse(response.data(), response.size(), decoded)
		== PcpDecodeStatus::Ok);
	CHECK(decoded.result == PcpResultCode::NotAuthorized && decoded.epoch == 9876);
}

} // namespace

int main() {
    TestNatPmpVectors();
    TestPcpRequestVectors();
    TestPcpResponseValidation();
    TestAnnounce();
    std::printf("test_mapping_codecs: %d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
