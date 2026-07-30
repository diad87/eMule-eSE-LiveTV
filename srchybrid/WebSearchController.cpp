#include "WebSearchController.h"

#include <charconv>
#include <cctype>
#include <limits>

namespace ese {
namespace web {
namespace {

bool IsMd4Hex(const std::string& value)
{
	if (value.size() != 32)
		return false;
	for (const unsigned char ch : value) {
		if (!std::isxdigit(ch))
			return false;
	}
	return true;
}

bool ParseUnsigned(const std::string& value, std::uint64_t& output)
{
	if (value.empty()) {
		output = 0;
		return true;
	}
	const std::from_chars_result parsed = std::from_chars(
		value.data(), value.data() + value.size(), output);
	return parsed.ec == std::errc() &&
		parsed.ptr == value.data() + value.size();
}

bool IsFileType(const std::string& value)
{
	return value.empty() || value == "archive" || value == "audio" ||
		value == "cdimage" || value == "document" || value == "image" ||
		value == "program" || value == "video" ||
		value == "emulecollection";
}

} // namespace

WebSearchRequest WebSearchController::PlanSearch(
	bool isAdmin,
	const std::string& expression,
	const std::string& fileType,
	const std::string& minimumMiB,
	const std::string& maximumMiB,
	const std::string& availability,
	const std::string& extension,
	const std::string& method)
{
	WebSearchRequest request;
	if (!isAdmin || expression.empty() || !IsFileType(fileType))
		return request;
	std::uint64_t minimum = 0;
	std::uint64_t maximum = 0;
	std::uint64_t available = 0;
	if (!ParseUnsigned(minimumMiB, minimum) ||
		!ParseUnsigned(maximumMiB, maximum) ||
		!ParseUnsigned(availability, available) ||
		minimum > std::numeric_limits<std::uint64_t>::max() / 1048576u ||
		maximum > std::numeric_limits<std::uint64_t>::max() / 1048576u ||
		available > 1000000u)
		return request;
	request.method = method == "kademlia"
		? WebSearchMethod::Kademlia
		: (method == "global"
			? WebSearchMethod::Global : WebSearchMethod::Server);
	request.expression = expression;
	request.file_type = fileType;
	request.extension = extension;
	request.minimum_bytes = minimum * 1048576u;
	request.maximum_bytes = maximum * 1048576u;
	if (request.maximum_bytes < request.minimum_bytes)
		request.maximum_bytes = 0;
	request.availability = static_cast<unsigned>(available);
	request.allowed = true;
	return request;
}

std::vector<std::string> WebSearchController::PlanDownloads(
	bool isAdmin,
	const std::string& pipeSeparatedHashes)
{
	std::vector<std::string> hashes;
	if (!isAdmin)
		return hashes;
	std::size_t begin = 0;
	while (begin <= pipeSeparatedHashes.size()) {
		const std::size_t separator =
			pipeSeparatedHashes.find('|', begin);
		const std::size_t end = separator == std::string::npos
			? pipeSeparatedHashes.size() : separator;
		const std::string value =
			pipeSeparatedHashes.substr(begin, end - begin);
		if (IsMd4Hex(value))
			hashes.push_back(value);
		if (separator == std::string::npos)
			break;
		begin = separator + 1;
	}
	return hashes;
}

WebSearchColumnChange WebSearchController::PlanColumnChange(
	const std::string& index,
	const std::string& hidden)
{
	WebSearchColumnChange change;
	unsigned parsedIndex = 0;
	long parsedHidden = 0;
	const std::from_chars_result indexResult = std::from_chars(
		index.data(), index.data() + index.size(), parsedIndex);
	const std::from_chars_result hiddenResult = std::from_chars(
		hidden.data(), hidden.data() + hidden.size(), parsedHidden);
	if (index.empty() || hidden.empty() ||
		indexResult.ec != std::errc() ||
		indexResult.ptr != index.data() + index.size() ||
		hiddenResult.ec != std::errc() ||
		hiddenResult.ptr != hidden.data() + hidden.size() ||
		parsedIndex >= 4)
		return change;
	change.allowed = true;
	change.index = parsedIndex;
	change.hidden = parsedHidden != 0;
	return change;
}

WebSearchSortDecision WebSearchController::PlanSort(
	const std::string& column,
	const std::string& ascending,
	unsigned currentColumn,
	bool currentAscending)
{
	WebSearchSortDecision decision;
	decision.column = currentColumn;
	decision.ascending = currentAscending;
	if (!column.empty()) {
		unsigned parsedColumn = 0;
		const std::from_chars_result result = std::from_chars(
			column.data(), column.data() + column.size(), parsedColumn);
		if (result.ec != std::errc() ||
			result.ptr != column.data() + column.size() ||
			parsedColumn >= 4)
			return decision;
		decision.column = parsedColumn;
	}
	if (!ascending.empty()) {
		if (ascending == "1" || ascending == "true")
			decision.ascending = true;
		else if (ascending == "0" || ascending == "false")
			decision.ascending = false;
		else
			return WebSearchSortDecision{};
	}
	decision.allowed = true;
	return decision;
}

const char* WebSearchController::SourceImageBucket(unsigned sources)
{
	if (sources < 5) return "0";
	if (sources < 10) return "5";
	if (sources < 25) return "10";
	if (sources < 50) return "25";
	return "50";
}

} // namespace web
} // namespace ese
