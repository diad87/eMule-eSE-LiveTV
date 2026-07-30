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
	const std::string& sort,
	const std::string& explicitReverse)
{
	WebSharedSortDecision decision;
	bool defaultReverse = false;
	decision.sort = SortValue(sort, defaultReverse);
	if (decision.sort == WebSharedSort::None)
		return decision;
	decision.target_index = static_cast<unsigned>(decision.sort) - 1;
	decision.reverse = defaultReverse;
	if (!explicitReverse.empty()) {
		if (explicitReverse == "true")
			decision.reverse = true;
		else if (explicitReverse == "false")
			decision.reverse = false;
		else
			return WebSharedSortDecision{};
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
	const std::string& index,
	const std::string& hidden)
{
	WebSharedColumnChange change;
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

} // namespace web
} // namespace ese
