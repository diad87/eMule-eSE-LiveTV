#include "WebSharedController.h"

#include <charconv>
#include <cctype>

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

WebSharedSort SortValue(const std::string& value, bool& defaultReverse)
{
	defaultReverse = value == "name";
	if (value == "state") return WebSharedSort::State;
	if (value == "type") return WebSharedSort::Type;
	if (value == "name") return WebSharedSort::Name;
	if (value == "size") return WebSharedSort::Size;
	if (value == "transferred") return WebSharedSort::Transferred;
	if (value == "alltimetransferred")
		return WebSharedSort::AllTimeTransferred;
	if (value == "requests") return WebSharedSort::Requests;
	if (value == "alltimerequests") return WebSharedSort::AllTimeRequests;
	if (value == "accepts") return WebSharedSort::Accepts;
	if (value == "alltimeaccepts") return WebSharedSort::AllTimeAccepts;
	if (value == "completes") return WebSharedSort::Completes;
	if (value == "priority") return WebSharedSort::Priority;
	return WebSharedSort::None;
}

} // namespace

WebSharedSortDecision WebSharedController::PlanSort(
	bool isAdmin,
	const std::string& sort,
	const std::string& explicitReverse)
{
	WebSharedSortDecision decision;
	if (!isAdmin || (sort.empty() && explicitReverse.empty()))
		return decision;
	bool defaultReverse = false;
	if (!sort.empty()) {
		decision.sort = SortValue(sort, defaultReverse);
		if (decision.sort == WebSharedSort::None)
			return decision;
		decision.target_index = static_cast<unsigned>(decision.sort) - 1;
		decision.update_sort = true;
		decision.update_reverse = true;
		decision.reverse = defaultReverse;
	}
	if (!explicitReverse.empty()) {
		if (explicitReverse == "true")
			decision.reverse = true;
		else if (explicitReverse == "false")
			decision.reverse = false;
		else
			return WebSharedSortDecision{};
		decision.update_reverse = true;
	}
	decision.allowed = true;
	return decision;
}

WebSharedPriorityDecision WebSharedController::PlanPriority(
	bool isAdmin,
	const std::string& fileHash,
	const std::string& priority)
{
	WebSharedPriorityDecision decision;
	if (!isAdmin || !IsMd4Hex(fileHash))
		return decision;
	if (priority == "verylow")
		decision.priority = WebSharedPriority::VeryLow;
	else if (priority == "low")
		decision.priority = WebSharedPriority::Low;
	else if (priority == "normal")
		decision.priority = WebSharedPriority::Normal;
	else if (priority == "high")
		decision.priority = WebSharedPriority::High;
	else if (priority == "release")
		decision.priority = WebSharedPriority::Release;
	else if (priority == "auto")
		decision.priority = WebSharedPriority::Auto;
	else
		return decision;
	decision.allowed = true;
	decision.file_hash = fileHash;
	return decision;
}

WebSharedColumnChange WebSharedController::PlanColumnChange(
	bool isAdmin,
	const std::string& index,
	const std::string& hidden)
{
	WebSharedColumnChange change;
	if (!isAdmin)
		return change;
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
		parsedIndex >= 7)
		return change;
	change.allowed = true;
	change.index = parsedIndex;
	change.hidden = parsedHidden != 0;
	return change;
}

bool WebSharedController::PlanReload(
	bool isAdmin,
	const std::string& value)
{
	return isAdmin && value == "true";
}

int WebSharedController::Compare(
	unsigned targetIndex,
	bool reverse,
	const WebSharedComparison& comparison)
{
	const int* values[] = {
		&comparison.state, &comparison.type, &comparison.name,
		&comparison.size, &comparison.transferred,
		&comparison.all_time_transferred, &comparison.requests,
		&comparison.all_time_requests, &comparison.accepts,
		&comparison.all_time_accepts, &comparison.completes,
		&comparison.priority
	};
	if (targetIndex >= sizeof values / sizeof values[0])
		return 0;
	const int value = (*values[targetIndex] > 0) -
		(*values[targetIndex] < 0);
	return reverse ? value : -value;
}

WebSharedRowProjection WebSharedController::ProjectRow(
	bool autoPriority,
	WebSharedPriority priority,
	bool partFile,
	std::uint64_t fileSize,
	std::uint64_t maximumDownloadMiB,
	unsigned completeSourcesLow,
	unsigned completeSourcesHigh)
{
	WebSharedRowProjection projection;
	if (autoPriority)
		projection.priority_token = "Auto";
	else {
		switch (priority) {
		case WebSharedPriority::VeryLow:
			projection.priority_token = "VeryLow"; break;
		case WebSharedPriority::Low:
			projection.priority_token = "Low"; break;
		case WebSharedPriority::Normal:
			projection.priority_token = "Normal"; break;
		case WebSharedPriority::High:
			projection.priority_token = "High"; break;
		case WebSharedPriority::Release:
			projection.priority_token = "Release"; break;
		default:
			break;
		}
	}
	projection.downloadable = !partFile &&
		(maximumDownloadMiB == 0 ||
			fileSize < maximumDownloadMiB * 1048576u);
	if (completeSourcesLow == 0)
		projection.complete_sources =
			"< " + std::to_string(completeSourcesHigh);
	else if (completeSourcesLow == completeSourcesHigh)
		projection.complete_sources = std::to_string(completeSourcesLow);
	else
		projection.complete_sources =
			std::to_string(completeSourcesLow) + " - " +
			std::to_string(completeSourcesHigh);
	return projection;
}

} // namespace web
} // namespace ese
