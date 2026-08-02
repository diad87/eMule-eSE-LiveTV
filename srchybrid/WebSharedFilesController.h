#pragma once

#include "M2ABindingPort.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace eSELive {

enum class WebSharedFilesSort : unsigned {
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

enum class WebSharedFilePriority : std::uint8_t {
	VeryLow,
	Low,
	Normal,
	High,
	Release
};

struct WebSharedFilesRow {
	std::wstring hash;
	std::wstring fileName;
	std::wstring fileState;
	std::wstring fileType;
	std::wstring ed2kLink;
	std::wstring priorityLabel;
	std::wstring fileSizeText;
	std::wstring transferredText;
	std::wstring allTimeTransferredText;
	std::array<std::wstring, 3> textOrder{};
	std::uint64_t fileSizeBytes = 0;
	std::uint64_t transferredBytes = 0;
	std::uint64_t allTimeTransferredBytes = 0;
	std::uint32_t requests = 0;
	std::uint32_t allTimeRequests = 0;
	std::uint32_t accepts = 0;
	std::uint32_t allTimeAccepts = 0;
	std::uint32_t completeSourcesLow = 0;
	std::uint32_t completeSourcesHigh = 0;
	std::uint32_t completeSourcesOrder = 0;
	std::uint32_t priorityOrder = 0;
	WebSharedFilePriority priority = WebSharedFilePriority::Normal;
	bool partFile = false;
	bool autoPriority = false;
};

struct WebSharedFilesInput {
	std::wstring pageTemplate;
	std::wstring rowTemplate;
	std::wstring session;
	std::wstring selectedHash;
	std::wstring message;
	std::wstring upArrow;
	std::wstring downArrow;
	std::wstring upDoubleArrow;
	std::wstring downDoubleArrow;
	std::array<std::wstring, 7> columnNames{};
	std::wstring actionsLabel;
	std::wstring reloadLabel;
	std::wstring sharedListLabel;
	std::array<bool, 7> hidden{};
	WebSharedFilesSort sort = WebSharedFilesSort::Name;
	bool reverse = false;
	bool admin = false;
	std::uint64_t maximumDownloadMiB = 0;
	std::size_t shortNameLimit = 40;
	std::vector<std::pair<std::wstring, std::wstring>> replacements;
	std::vector<WebSharedFilesRow> rows;
};

class WebSharedFilesController {
public:
	explicit WebSharedFilesController(const M2AParentPort& parent);
	std::wstring Render(const WebSharedFilesInput& input) const;

private:
	M2AParentPort m_parent;
};

M2AModuleHandle M2A_BIND_W6_B161DA740E(
	const M2AParentPort&);
void M2A_UNBIND_W6_B161DA740E(const M2AParentPort&);
std::wstring RunWebSharedFilesController(
	const M2AParentPort&, const WebSharedFilesInput&);
bool RunWebSharedFilesControllerCharacterizationSelfTest();

} // namespace eSELive
