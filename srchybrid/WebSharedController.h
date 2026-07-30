#pragma once

#include <cstdint>
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
	bool update_sort = false;
	bool update_reverse = false;
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

struct WebSharedComparison {
	int state = 0;
	int type = 0;
	int name = 0;
	int size = 0;
	int transferred = 0;
	int all_time_transferred = 0;
	int requests = 0;
	int all_time_requests = 0;
	int accepts = 0;
	int all_time_accepts = 0;
	int completes = 0;
	int priority = 0;
};

struct WebSharedRowProjection {
	const char* priority_token = "";
	bool downloadable = false;
	std::string complete_sources;
};

class WebSharedController {
public:
	static WebSharedSortDecision PlanSort(
		bool isAdmin,
		const std::string& sort,
		const std::string& explicitReverse);

	static WebSharedPriorityDecision PlanPriority(
		bool isAdmin,
		const std::string& fileHash,
		const std::string& priority);

	static WebSharedColumnChange PlanColumnChange(
		bool isAdmin,
		const std::string& index,
		const std::string& hidden);

	static bool PlanReload(
		bool isAdmin,
		const std::string& value);

	static int Compare(
		unsigned targetIndex,
		bool reverse,
		const WebSharedComparison& comparison);

	static WebSharedRowProjection ProjectRow(
		bool autoPriority,
		WebSharedPriority priority,
		bool partFile,
		std::uint64_t fileSize,
		std::uint64_t maximumDownloadMiB,
		unsigned completeSourcesLow,
		unsigned completeSourcesHigh);
};

} // namespace web
} // namespace ese
