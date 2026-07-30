#pragma once

#include <string>

namespace ese {
namespace web {

enum class WebSharedSort {
	None,
	State,
	Type,
	Name,
	Size,
	Transferred,
	AllTimeTransferred,
	Requests,
	AllTimeRequests,
	Accepts,
	AllTimeAccepts,
	Completes,
	Priority
};

enum class WebSharedPriority {
	None,
	VeryLow,
	Low,
	Normal,
	High,
	Release,
	Auto
};

struct WebSharedSortDecision {
	bool allowed = false;
	WebSharedSort sort = WebSharedSort::None;
	unsigned target_index = 0;
	bool reverse = false;
};

struct WebSharedPriorityDecision {
	bool allowed = false;
	WebSharedPriority priority = WebSharedPriority::None;
	std::string file_hash;
};

struct WebSharedColumnChange {
	bool allowed = false;
	unsigned index = 0;
	bool hidden = false;
};

class WebSharedController {
public:
	static WebSharedSortDecision PlanSort(
		const std::string& sort,
		const std::string& explicitReverse);

	static WebSharedPriorityDecision PlanPriority(
		bool isAdmin,
		const std::string& fileHash,
		const std::string& priority);

	static WebSharedColumnChange PlanColumnChange(
		const std::string& index,
		const std::string& hidden);
};

} // namespace web
} // namespace ese
