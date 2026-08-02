#pragma once
#include "M2ABindingPort.h"
#include <afxstr.h>
#include <array>
#include <cstdint>
#include <vector>

namespace eSELive {

enum class WebServerAction : std::uint8_t {
	Connect, Disconnect, Remove, AddStatic, RemoveStatic,
	PriorityLow, PriorityNormal, PriorityHigh
};

struct WebServerRow {
	CString description, fullIp, ip, name, priorityText, state, version;
	std::uint32_t files = 0, hardLimit = 0, maxUsers = 0, ping = 0;
	std::uint32_t softLimit = 0, users = 0;
	int failed = 0, port = 0;
	std::uint8_t priority = 0;
	bool isStatic = false;
};

struct WebServerPageInput {
	CString url, pageTemplate, rowTemplate, addTemplate, upArrow, downArrow;
	bool admin = false;
	unsigned sort = 0;
	bool reverse = false;
	std::array<bool, 10> hidden{};
};

struct WebServerPageResult {
	CString html;
	unsigned sort = 0;
	bool reverse = false;
	std::array<bool, 10> hidden{};
};

struct WebServerGuiPort {
	void* context = nullptr;
	CString (*parse)(void*, const CString&, const CString&) = nullptr;
	CString (*plain)(void*, unsigned) = nullptr;
	void (*action)(void*, WebServerAction, const CString&, int) = nullptr;
	bool (*addServer)(void*, const CString&, int, const CString&, const CString&,
		bool, bool, CString&) = nullptr;
	void (*updateServerMet)(void*, const CString&, CString&) = nullptr;
	void (*saveHidden)(void*, const std::array<bool, 10>&) = nullptr;
	void (*snapshot)(void*, std::vector<WebServerRow>&) = nullptr;
	bool Complete() const noexcept;
};

class WebServerListController {
public:
	explicit WebServerListController(const M2AParentPort& parent) noexcept;
	WebServerPageResult Render(const WebServerPageInput& input,
		const WebServerGuiPort& port) const;
private:
	const void* m_parent = nullptr;
};

M2AModuleHandle M2A_BIND_W3_F05B56128F(const M2AParentPort&);
void M2A_UNBIND_W3_F05B56128F(const M2AParentPort&);
WebServerPageResult RunWebServerPage(const M2AParentPort&,
	const WebServerPageInput&, const WebServerGuiPort&);
bool RunWebServerPageCharacterizationSelfTest();

} // namespace eSELive
