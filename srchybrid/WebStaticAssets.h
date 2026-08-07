#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace ese {
namespace web {

enum class WebRangeStatus {
	None,
	Satisfiable,
	Unsatisfiable,
	Invalid
};

struct WebByteRange {
	WebRangeStatus status = WebRangeStatus::None;
	std::uint64_t offset = 0;
	std::uint64_t length = 0;
};

struct WebFileResponseOptions {
	std::string cacheControl;
	std::string corsOrigin;
	std::string lastModified;
	std::string etag;
	std::string attachmentUtf8;
	bool noReferrer = false;
};

struct WebFileResponsePlan {
	int statusCode = 500;
	std::uint64_t offset = 0;
	std::uint64_t length = 0;
	std::string headers;

	bool IsSuccess() const
	{
		return statusCode == 200 || statusCode == 206;
	}
};

struct WebPreparedFileResponse {
	static constexpr std::uint64_t kMaximumBodyBytes =
		20ull * 1024ull * 1024ull;
	static constexpr std::uint64_t kGlobalMaximumBodyBytes =
		64ull * 1024ull * 1024ull;

	WebFileResponsePlan plan;
	std::vector<std::uint8_t> body;
	std::shared_ptr<void> bodyReservation;

	bool Ready() const
	{
		return !plan.headers.empty();
	}
};

enum class WebFileErrorStatus {
	Forbidden = 403,
	NotFound = 404,
	InternalServerError = 500,
	ServiceUnavailable = 503
};

class WebStaticAssets final
{
public:
	static WebByteRange ParseRange(
		const std::string& headerValue,
		std::uint64_t representationSize);
	static bool CollectRangeHeader(
		std::string& destination,
		bool& seen,
		const std::string& value);

	static WebFileResponsePlan PlanResponse(
		const std::string& path,
		const std::string& rangeHeader,
		std::uint64_t representationSize,
		const WebFileResponseOptions& options);
	static std::string BuildErrorResponse(
		WebFileErrorStatus status,
		const WebFileResponseOptions& options);
	static std::shared_ptr<void> ReservePreparedBody(
		std::uint64_t byteCount);
	static std::uint64_t ReservedPreparedBodyBytes();

	static const char* MimeTypeForPath(const std::string& path);
	static const char* CacheControlForPath(const std::string& path);
	static bool IsPlaylist(const std::string& path);
	static bool IsMediaSegment(const std::string& path);
	static std::size_t ReadChunkBytes();
};

bool RunWebStaticAssetsSelfTest(std::string& failure);

} // namespace web
} // namespace ese
