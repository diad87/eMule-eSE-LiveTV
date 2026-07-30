#include "../WebSocketResponse.h"
#include "../WebStaticAssets.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <limits>
#include <memory>
#include <string>
#include <vector>

namespace {

int failures = 0;

class TestSource final : public ese::web::IWebResponseSource
{
public:
	explicit TestSource(std::string value)
		: m_value(std::move(value))
	{
	}

	bool Read(
		std::uint8_t* destination,
		std::size_t capacity,
		std::size_t& bytesRead) override
	{
		bytesRead = std::min(capacity, m_value.size() - m_offset);
		if (bytesRead == 0)
			return false;
		std::memcpy(destination, m_value.data() + m_offset, bytesRead);
		m_offset += bytesRead;
		return true;
	}

private:
	std::string m_value;
	std::size_t m_offset = 0;
};

void Check(bool condition, const char* message)
{
	if (!condition) {
		std::cerr << "FAIL: " << message << '\n';
		++failures;
	}
}

} // namespace

int main()
{
	using ese::web::WebRangeStatus;
	using ese::web::WebFileResponseOptions;
	using ese::web::WebSocketResponse;
	using ese::web::WebStaticAssets;

	const auto none = WebStaticAssets::ParseRange("", 100);
	Check(none.status == WebRangeStatus::None, "missing range");

	const auto closed = WebStaticAssets::ParseRange("bytes=10-19", 100);
	Check(closed.status == WebRangeStatus::Satisfiable, "closed range status");
	Check(closed.offset == 10 && closed.length == 10, "closed range values");

	const auto open = WebStaticAssets::ParseRange("bytes=90-", 100);
	Check(open.status == WebRangeStatus::Satisfiable, "open range status");
	Check(open.offset == 90 && open.length == 10, "open range values");
	const auto uppercase = WebStaticAssets::ParseRange("BYTES=0-1", 100);
	Check(
		uppercase.status == WebRangeStatus::Satisfiable &&
			uppercase.offset == 0 && uppercase.length == 2,
		"range unit is case-insensitive");

	const auto suffix = WebStaticAssets::ParseRange("bytes=-25", 100);
	Check(suffix.status == WebRangeStatus::Satisfiable, "suffix status");
	Check(suffix.offset == 75 && suffix.length == 25, "suffix values");

	const auto oversizedSuffix = WebStaticAssets::ParseRange("bytes=-250", 100);
	Check(
		oversizedSuffix.offset == 0 && oversizedSuffix.length == 100,
		"oversized suffix is whole representation");

	for (const char* invalid : {
		"bytes=1-2,4-5",
		"bytes=-",
		"bytes=4-3",
		"bytes=18446744073709551616-",
		"items=0-1",
		"bytes=0-1x",
	}) {
		const auto parsed = WebStaticAssets::ParseRange(invalid, 100);
		Check(
			parsed.status == WebRangeStatus::Invalid ||
				parsed.status == WebRangeStatus::Unsatisfiable,
			"hostile range fails closed");
	}
	Check(
		WebStaticAssets::ParseRange("bytes=100-", 100).status ==
			WebRangeStatus::Unsatisfiable,
		"past-end range is unsatisfiable");
	Check(
		WebStaticAssets::ParseRange("bytes=0-", 0).status ==
			WebRangeStatus::Unsatisfiable,
		"zero-length representation is unsatisfiable");
	std::string collectedRange;
	bool rangeSeen = false;
	Check(
		WebStaticAssets::CollectRangeHeader(
			collectedRange, rangeSeen, "bytes=0-1"),
		"first range field accepted");
	Check(
		!WebStaticAssets::CollectRangeHeader(
			collectedRange, rangeSeen, "bytes=2-3"),
		"duplicate range field rejected");
	Check(
		WebStaticAssets::ParseRange(collectedRange, 100).status ==
			WebRangeStatus::Invalid,
		"duplicate range collection maps to 416");
	std::string emptyRange;
	bool emptyRangeSeen = false;
	Check(
		!WebStaticAssets::CollectRangeHeader(
			emptyRange, emptyRangeSeen, ""),
		"empty range field rejected");
	Check(
		emptyRangeSeen &&
			WebStaticAssets::ParseRange(emptyRange, 100).status ==
				WebRangeStatus::Invalid,
		"empty range collection maps to 416");

	Check(
		std::strcmp(WebStaticAssets::MimeTypeForPath("A.JPEG"), "image/jpeg") == 0,
		"jpeg MIME normalized");
	Check(
		std::strcmp(
			WebStaticAssets::MimeTypeForPath("stream.m3u8"),
			"application/vnd.apple.mpegurl") == 0,
		"playlist MIME");
	Check(
		std::strcmp(
			WebStaticAssets::MimeTypeForPath("unknown.bin"),
			"application/octet-stream") == 0,
		"unknown MIME is safe");

	WebFileResponseOptions responseOptions;
	responseOptions.corsOrigin = "*";
	responseOptions.attachmentUtf8 = "bad\r\nname\".bin";
	const auto response = WebStaticAssets::PlanResponse(
		"movie.ts",
		"bytes=10-19",
		100,
		responseOptions);
	Check(response.statusCode == 206, "partial response status");
	Check(response.offset == 10 && response.length == 10, "partial response span");
	Check(
		response.headers.find("Content-Range: bytes 10-19/100") !=
			std::string::npos,
		"partial content-range header");
	Check(
		response.headers.find("Access-Control-Allow-Origin: *") !=
			std::string::npos,
		"CORS response header");
	Check(
		response.headers.find("\r\nname") == std::string::npos,
		"attachment cannot inject headers");
	Check(
		response.headers.find("%0D%0A") != std::string::npos,
		"attachment is RFC 5987 encoded");
	const auto rejected = WebStaticAssets::PlanResponse(
		"movie.ts",
		"bytes=100-",
		100,
		responseOptions);
	Check(rejected.statusCode == 416, "range rejection status");
	Check(
		rejected.headers.find("Content-Range: bytes */100") != std::string::npos,
		"range rejection content-range");
	Check(
		rejected.headers.find("Access-Control-Allow-Origin: *") !=
			std::string::npos,
		"range rejection retains CORS policy");

	WebSocketResponse queue;
	const char first[] = "abcd";
	const char second[] = "ef";
	Check(queue.Enqueue(first, 4), "first queue append");
	Check(queue.Enqueue(second, 2), "second queue append");
	Check(queue.QueuedBytes() == 6 && queue.QueuedChunks() == 2, "queue accounting");
	Check(queue.FrontSize() == 4, "front size");
	Check(queue.Consume(2), "partial consume");
	Check(queue.FrontSize() == 2 && queue.QueuedBytes() == 4, "partial suffix retained");
	Check(queue.Consume(2), "finish first chunk");
	Check(queue.FrontSize() == 2 && queue.QueuedChunks() == 1, "advance queue");
	queue.RequestClose();
	Check(queue.CloseRequested(), "close requested");
	Check(!queue.Enqueue(first, 4), "enqueue after close fails");
	Check(queue.Failed(), "enqueue after close marks failure");

	WebSocketResponse bounded;
	std::vector<std::uint8_t> maximum(WebSocketResponse::kMaxQueuedBytes, 0x5a);
	Check(bounded.Enqueue(maximum.data(), maximum.size()), "maximum queue accepted");
	Check(!bounded.Enqueue(first, 1), "queue byte overflow rejected");
	Check(bounded.Failed() && bounded.QueuedBytes() == maximum.size(), "overflow fail closed");

	WebSocketResponse chunkBounded;
	for (std::size_t index = 0; index < WebSocketResponse::kMaxQueuedChunks; ++index)
		Check(chunkBounded.Enqueue(first, 1), "chunk within bound");
	Check(!chunkBounded.Enqueue(first, 1), "chunk count overflow rejected");

	WebSocketResponse invalidConsume;
	Check(invalidConsume.Enqueue(first, 4), "invalid consume setup");
	Check(!invalidConsume.Consume(5), "over-consume rejected");
	Check(invalidConsume.Failed(), "over-consume fails queue");

	WebSocketResponse streamed;
	Check(
		streamed.AttachSource(
			std::make_unique<TestSource>("abcdefghij"),
			10),
		"attach response source");
	Check(streamed.PumpSource(4), "pump first stream chunk");
	Check(streamed.SourceAttached(), "source retained after partial pump");
	Check(streamed.FrontSize() == 4, "stream chunk is bounded");
	Check(streamed.Consume(4), "consume first stream chunk");
	Check(streamed.PumpSource(8), "pump final stream chunk");
	Check(!streamed.SourceAttached(), "source released at declared length");
	Check(streamed.FrontSize() == 6, "final stream chunk length");
	Check(streamed.Consume(6) && !streamed.Pending(), "stream fully drained");

	if (failures == 0)
		std::cout << "web streaming tests: PASS\n";
	return failures == 0 ? 0 : 1;
}
