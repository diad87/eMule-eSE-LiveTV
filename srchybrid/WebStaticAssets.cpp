#include "WebStaticAssets.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <limits>
#include <sstream>

namespace ese {
namespace web {
namespace {

std::atomic<std::uint64_t> preparedBodyBytes{0};

bool HasSuffix(const std::string& path, const char* suffix)
{
	const std::string expected(suffix);
	if (path.size() < expected.size())
		return false;
	const std::size_t offset = path.size() - expected.size();
	for (std::size_t index = 0; index < expected.size(); ++index) {
		const unsigned char left =
			static_cast<unsigned char>(path[offset + index]);
		const unsigned char right =
			static_cast<unsigned char>(expected[index]);
		if (std::tolower(left) != std::tolower(right))
			return false;
	}
	return true;
}

bool ParseUnsigned(
	const std::string& text,
	std::size_t begin,
	std::size_t end,
	std::uint64_t& value)
{
	if (begin >= end)
		return false;
	value = 0;
	for (std::size_t index = begin; index < end; ++index) {
		const char byte = text[index];
		if (byte < '0' || byte > '9')
			return false;
		const unsigned digit = static_cast<unsigned>(byte - '0');
		if (value >
			(std::numeric_limits<std::uint64_t>::max() - digit) / 10u)
			return false;
		value = value * 10u + digit;
	}
	return true;
}

bool HasCaseInsensitivePrefix(const std::string& value, const char* prefix)
{
	const std::string expected(prefix);
	if (value.size() < expected.size())
		return false;
	for (std::size_t index = 0; index < expected.size(); ++index) {
		const unsigned char left =
			static_cast<unsigned char>(value[index]);
		const unsigned char right =
			static_cast<unsigned char>(expected[index]);
		if (std::tolower(left) != std::tolower(right))
			return false;
	}
	return true;
}

std::string EncodeHeaderParameter(const std::string& value)
{
	static const char kHex[] = "0123456789ABCDEF";
	std::string encoded;
	encoded.reserve(value.size() * 3u);
	for (const unsigned char byte : value) {
		const bool unreserved =
			(byte >= 'a' && byte <= 'z') ||
			(byte >= 'A' && byte <= 'Z') ||
			(byte >= '0' && byte <= '9') ||
			byte == '-' || byte == '.' || byte == '_';
		if (unreserved) {
			encoded.push_back(static_cast<char>(byte));
		} else {
			encoded.push_back('%');
			encoded.push_back(kHex[byte >> 4u]);
			encoded.push_back(kHex[byte & 0x0fu]);
		}
	}
	return encoded;
}

} // namespace

WebByteRange WebStaticAssets::ParseRange(
	const std::string& headerValue,
	std::uint64_t representationSize)
{
	WebByteRange result;
	if (headerValue.empty())
		return result;
	if (!HasCaseInsensitivePrefix(headerValue, "bytes=") ||
		headerValue.find(',', 6) != std::string::npos) {
		result.status = WebRangeStatus::Invalid;
		return result;
	}

	const std::size_t dash = headerValue.find('-', 6);
	if (dash == std::string::npos ||
		headerValue.find('-', dash + 1) != std::string::npos) {
		result.status = WebRangeStatus::Invalid;
		return result;
	}
	if (representationSize == 0) {
		result.status = WebRangeStatus::Unsatisfiable;
		return result;
	}

	std::uint64_t left = 0;
	std::uint64_t right = 0;
	const bool hasLeft = dash > 6;
	const bool hasRight = dash + 1 < headerValue.size();
	if (!hasLeft && !hasRight) {
		result.status = WebRangeStatus::Invalid;
		return result;
	}
	if (hasLeft && !ParseUnsigned(headerValue, 6, dash, left)) {
		result.status = WebRangeStatus::Invalid;
		return result;
	}
	if (hasRight &&
		!ParseUnsigned(headerValue, dash + 1, headerValue.size(), right)) {
		result.status = WebRangeStatus::Invalid;
		return result;
	}

	if (!hasLeft) {
		if (right == 0) {
			result.status = WebRangeStatus::Unsatisfiable;
			return result;
		}
		result.length = std::min(right, representationSize);
		result.offset = representationSize - result.length;
		result.status = WebRangeStatus::Satisfiable;
		return result;
	}
	if (left >= representationSize || (hasRight && right < left)) {
		result.status = WebRangeStatus::Unsatisfiable;
		return result;
	}

	const std::uint64_t inclusiveEnd = hasRight
		? std::min(right, representationSize - 1u)
		: representationSize - 1u;
	result.offset = left;
	result.length = inclusiveEnd - left + 1u;
	result.status = WebRangeStatus::Satisfiable;
	return result;
}

bool WebStaticAssets::CollectRangeHeader(
	std::string& destination,
	bool& seen,
	const std::string& value)
{
	if (seen) {
		destination = "__duplicate_range__";
		return false;
	}
	seen = true;
	if (value.empty()) {
		destination = "__empty_range__";
		return false;
	}
	destination = value;
	return true;
}

WebFileResponsePlan WebStaticAssets::PlanResponse(
	const std::string& path,
	const std::string& rangeHeader,
	std::uint64_t representationSize,
	const WebFileResponseOptions& options)
{
	WebFileResponsePlan plan;
	const WebByteRange range = ParseRange(rangeHeader, representationSize);
	if (range.status == WebRangeStatus::Invalid ||
		range.status == WebRangeStatus::Unsatisfiable) {
		plan.statusCode = 416;
		std::ostringstream response;
		response
			<< "HTTP/1.1 416 Range Not Satisfiable\r\n"
			<< "Connection: close\r\n"
			<< "X-Content-Type-Options: nosniff\r\n"
			<< "Cache-Control: no-store\r\n"
			<< "Accept-Ranges: bytes\r\n"
			<< "Content-Range: bytes */" << representationSize << "\r\n";
		if (!options.corsOrigin.empty())
			response << "Access-Control-Allow-Origin: " << options.corsOrigin << "\r\n";
		if (options.noReferrer)
			response << "Referrer-Policy: no-referrer\r\n";
		response << "Content-Length: 0\r\n\r\n";
		plan.headers = response.str();
		return plan;
	}

	const bool partial = range.status == WebRangeStatus::Satisfiable;
	plan.statusCode = partial ? 206 : 200;
	plan.offset = partial ? range.offset : 0u;
	plan.length = partial ? range.length : representationSize;

	std::ostringstream response;
	response
		<< "HTTP/1.1 "
		<< (partial ? "206 Partial Content" : "200 OK") << "\r\n"
		<< "Connection: close\r\n"
		<< "Content-Type: " << MimeTypeForPath(path) << "\r\n"
		<< "X-Content-Type-Options: nosniff\r\n"
		<< "Accept-Ranges: bytes\r\n"
		<< "Cache-Control: "
		<< (options.cacheControl.empty()
			? CacheControlForPath(path)
			: options.cacheControl.c_str())
		<< "\r\n";
	if (!options.corsOrigin.empty())
		response << "Access-Control-Allow-Origin: " << options.corsOrigin << "\r\n";
	if (options.noReferrer)
		response << "Referrer-Policy: no-referrer\r\n";
	if (!options.lastModified.empty())
		response << "Last-Modified: " << options.lastModified << "\r\n";
	if (!options.etag.empty())
		response << "ETag: " << options.etag << "\r\n";
	if (!options.attachmentUtf8.empty()) {
		response
			<< "Content-Disposition: attachment; filename=\"download\"; "
			<< "filename*=UTF-8''"
			<< EncodeHeaderParameter(options.attachmentUtf8) << "\r\n";
	}
	if (partial) {
		response
			<< "Content-Range: bytes " << plan.offset << '-'
			<< (plan.offset + plan.length - 1u) << '/'
			<< representationSize << "\r\n";
	}
	response << "Content-Length: " << plan.length << "\r\n\r\n";
	plan.headers = response.str();
	return plan;
}

std::string WebStaticAssets::BuildErrorResponse(
	WebFileErrorStatus status,
	const WebFileResponseOptions& options)
{
	const char* reason = "Internal Server Error";
	switch (status) {
	case WebFileErrorStatus::Forbidden:
		reason = "Forbidden";
		break;
	case WebFileErrorStatus::NotFound:
		reason = "Not Found";
		break;
	case WebFileErrorStatus::InternalServerError:
		break;
	case WebFileErrorStatus::ServiceUnavailable:
		reason = "Service Unavailable";
		break;
	}
	std::ostringstream response;
	response << "HTTP/1.1 " << static_cast<int>(status) << ' '
		<< reason << "\r\nConnection: close\r\n";
	if (!options.cacheControl.empty())
		response << "Cache-Control: " << options.cacheControl << "\r\n";
	if (options.noReferrer)
		response << "Referrer-Policy: no-referrer\r\n";
	if (status == WebFileErrorStatus::ServiceUnavailable)
		response << "Retry-After: 1\r\n";
	response << "Content-Length: 0\r\n\r\n";
	return response.str();
}

std::shared_ptr<void> WebStaticAssets::ReservePreparedBody(
	std::uint64_t byteCount)
{
	if (byteCount == 0u ||
		byteCount > WebPreparedFileResponse::kMaximumBodyBytes ||
		byteCount > WebPreparedFileResponse::kGlobalMaximumBodyBytes)
		return std::shared_ptr<void>();
	std::uint64_t current =
		preparedBodyBytes.load(std::memory_order_relaxed);
	for (;;) {
		if (current >
			WebPreparedFileResponse::kGlobalMaximumBodyBytes - byteCount)
			return std::shared_ptr<void>();
		if (preparedBodyBytes.compare_exchange_weak(
				current, current + byteCount,
				std::memory_order_acq_rel,
				std::memory_order_relaxed))
			break;
	}
	try {
		return std::shared_ptr<void>(
			&preparedBodyBytes,
			[byteCount](void*) {
				preparedBodyBytes.fetch_sub(
					byteCount, std::memory_order_acq_rel);
			});
	} catch (...) {
		preparedBodyBytes.fetch_sub(byteCount, std::memory_order_acq_rel);
		return std::shared_ptr<void>();
	}
}

std::uint64_t WebStaticAssets::ReservedPreparedBodyBytes()
{
	return preparedBodyBytes.load(std::memory_order_acquire);
}

const char* WebStaticAssets::MimeTypeForPath(const std::string& path)
{
	if (HasSuffix(path, ".bmp"))
		return "image/bmp";
	if (HasSuffix(path, ".gif"))
		return "image/gif";
	if (HasSuffix(path, ".jpeg") || HasSuffix(path, ".jpg"))
		return "image/jpeg";
	if (HasSuffix(path, ".png"))
		return "image/png";
	if (HasSuffix(path, ".ico"))
		return "image/x-icon";
	if (HasSuffix(path, ".css"))
		return "text/css; charset=utf-8";
	if (HasSuffix(path, ".js"))
		return "text/javascript; charset=utf-8";
	if (IsPlaylist(path))
		return "application/vnd.apple.mpegurl";
	if (IsMediaSegment(path))
		return "video/mp2t";
	return "application/octet-stream";
}

const char* WebStaticAssets::CacheControlForPath(const std::string& path)
{
	if (IsPlaylist(path))
		return "no-cache";
	if (IsMediaSegment(path))
		return "public, max-age=30";
	return "no-cache";
}

bool WebStaticAssets::IsPlaylist(const std::string& path)
{
	return HasSuffix(path, ".m3u8");
}

bool WebStaticAssets::IsMediaSegment(const std::string& path)
{
	return HasSuffix(path, ".ts");
}

std::size_t WebStaticAssets::ReadChunkBytes()
{
	return 64u * 1024u;
}

bool RunWebStaticAssetsSelfTest(std::string& failure)
{
	failure.clear();
	const WebByteRange range =
		WebStaticAssets::ParseRange("bytes=3-7", 10);
	if (range.status != WebRangeStatus::Satisfiable ||
		range.offset != 3u || range.length != 5u) {
		failure = "web static range self-test failed";
		return false;
	}
	const WebFileResponsePlan plan = WebStaticAssets::PlanResponse(
		"segment.ts",
		"bytes=-2",
		10,
		WebFileResponseOptions{});
	if (plan.statusCode != 206 || plan.offset != 8u ||
		plan.length != 2u ||
		plan.headers.find("Content-Range: bytes 8-9/10") ==
			std::string::npos) {
		failure = "web static response-plan self-test failed";
		return false;
	}
	WebFileResponseOptions capabilityOptions;
	capabilityOptions.cacheControl = "no-store";
	capabilityOptions.noReferrer = true;
	const std::string error = WebStaticAssets::BuildErrorResponse(
		WebFileErrorStatus::NotFound, capabilityOptions);
	if (error.find("HTTP/1.1 404 Not Found") == std::string::npos ||
		error.find("Cache-Control: no-store") == std::string::npos ||
		error.find("Referrer-Policy: no-referrer") == std::string::npos) {
		failure = "web static error-policy self-test failed";
		return false;
	}
	return true;
}

} // namespace web
} // namespace ese
