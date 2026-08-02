#pragma once
#include "M2ABindingPort.h"
#include <afxstr.h>
#include <cstdint>
#include <vector>
namespace eSELive {
enum class WebTemplateLogView : std::uint8_t { Log, ServerInfo, DebugLog };
struct WebHeaderRuntime {
	CString version, serverName;
	std::uint32_t serverUsers = 0, serverMaxUsers = 0, serverFiles = 0;
	std::uint32_t allUsers = 0, allFiles = 0, openSockets = 0;
	double downloadRate = 0.0, uploadRate = 0.0;
	bool serverConnecting = false, serverConnected = false, highId = false;
	bool kad2Connected = false, kadFirewalled = false;
	bool kad6Connected = false, kadRunning = false;
};
struct WebCommentRow { CString user, file, text, rating; };
struct WebCommentListInput {
	bool found = false;
	CString fileName;
	std::vector<WebCommentRow> rows;
};
class WebHeaderFooter {
public:
	explicit WebHeaderFooter(const M2AParentPort& parent) noexcept;
	CString Header(const CString& page, const CString& category,
		const CString& action, long session, bool admin,
		std::uint32_t requestWord, const CString& source,
		const CString& stylesheet, const CString& categoryArrow,
		const WebHeaderRuntime& runtime) const;
	CString Footer(const CString& source) const;
	CString Login(const CString& source, const CStringA& nonce,
		bool failed, const CString& version) const;
private:
	const void* m_parent = nullptr;
};
M2AModuleHandle M2A_BIND_W2_9330EBAD15(const M2AParentPort&);
void M2A_UNBIND_W2_9330EBAD15(const M2AParentPort&);
CString RenderWebHeader(const M2AParentPort&, const CString&, const CString&,
	const CString&, long, bool, std::uint32_t, const CString&, const CString&,
	const CString&, const WebHeaderRuntime&);
CString RenderWebFooter(const M2AParentPort&, const CString&);
CString RenderWebLogin(const M2AParentPort&, const CString&, const CStringA&,
	bool, const CString&);
CString RenderWebLogView(WebTemplateLogView, const CString&, const CString&,
	const CString&);
CString RenderWebMyInfo(const CString&, const CString&);
CString RenderWebStats(const CString&, const CString&);
CString RenderWebCommentList(const WebCommentListInput&, const CString&,
	const CString&);
void InsertWebCategoryBox(CString&, int, LPCTSTR, bool, bool,
	const CString&, const CString&, int, bool);
bool RunWebPageChromeCharacterizationSelfTest();
} // namespace eSELive
