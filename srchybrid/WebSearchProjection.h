#pragma once

#include "M2ABindingPort.h"
#include <array>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace eSELive {

struct WebSearchProjectionRow {
	std::wstring fileName;
	std::wstring limitedName;
	std::wstring typeImage;
	std::wstring sizeText;
	std::uint64_t sizeBytes = 0;
	std::wstring hash;
	std::wstring sources;
	std::wstring sourceBucket;
	std::uint8_t red = 0;
	std::uint8_t green = 0;
	std::uint8_t blue = 0;
};

struct WebSearchProjectionInput {
	std::wstring pageTemplate;
	std::wstring headerTemplate;
	std::wstring rowTemplate;
	std::wstring message;
	std::wstring categoryBox;
	std::wstring session;
	std::wstring upArrow;
	std::wstring downArrow;
	std::array<bool, 4> hidden{};
	unsigned sortColumn = 0;
	bool ascending = true;
	std::vector<std::pair<std::wstring, std::wstring>> replacements;
	std::array<std::wstring, 4> columnNames;
	std::vector<WebSearchProjectionRow> rows;
};

class WebSearchProjection {
public:
	explicit WebSearchProjection(const M2AParentPort& parent);
	std::wstring Render(const WebSearchProjectionInput& input) const;
private:
	M2AParentPort m_parent;
};

M2AModuleHandle M2A_BIND_W6_64C04005E2(const M2AParentPort&);
void M2A_UNBIND_W6_64C04005E2(const M2AParentPort&);
std::wstring RunWebSearchProjection(
	const M2AParentPort&, const WebSearchProjectionInput&);
bool RunWebSearchProjectionCharacterizationSelfTest();

}
