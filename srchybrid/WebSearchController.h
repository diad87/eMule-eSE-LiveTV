#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace ese {
namespace web {

enum class WebSearchMethod {
	Server,
	Global,
	Kademlia
};

struct WebSearchRequest {
	bool allowed = false;
	WebSearchMethod method = WebSearchMethod::Server;
	std::string expression;
	std::string file_type;
	std::string extension;
	std::uint64_t minimum_bytes = 0;
	std::uint64_t maximum_bytes = 0;
	unsigned availability = 0;
};

struct WebSearchColumnChange {
	bool allowed = false;
	unsigned index = 0;
	bool hidden = false;
};

struct WebSearchSortDecision {
	bool allowed = false;
	unsigned column = 0;
	bool ascending = false;
};

class WebSearchController {
public:
	static WebSearchRequest PlanSearch(
		bool isAdmin,
		const std::string& expression,
		const std::string& fileType,
		const std::string& minimumMiB,
		const std::string& maximumMiB,
		const std::string& availability,
		const std::string& extension,
		const std::string& method);

	static std::vector<std::string> PlanDownloads(
		bool isAdmin,
		const std::string& pipeSeparatedHashes);

	static WebSearchColumnChange PlanColumnChange(
		const std::string& index,
		const std::string& hidden);

	static WebSearchSortDecision PlanSort(
		const std::string& column,
		const std::string& ascending,
		unsigned currentColumn,
		bool currentAscending);

	static const char* SourceImageBucket(unsigned sources);
};

} // namespace web
} // namespace ese
