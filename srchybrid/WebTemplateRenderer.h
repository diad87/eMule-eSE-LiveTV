#pragma once
#include "M2ABindingPort.h"
#include <afxstr.h>
#include <array>
#include <cstdint>
#include <mutex>
namespace eSELive {
enum class WebTemplateId : std::uint8_t {
	Header, HeaderStylesheet, Footer, ServerList, ServerLine, TransferImages, TransferList, TransferDownHeader, TransferDownFooter, TransferDownLine, TransferUpHeader, TransferUpFooter, TransferUpLine,
	TransferUpQueueShow, TransferUpQueueHide, TransferUpQueueLine, TransferUpQueueBannedShow, TransferUpQueueBannedHide, TransferUpQueueBannedLine, TransferUpQueueFriendShow, TransferUpQueueFriendHide, TransferUpQueueFriendLine,
	SharedList, SharedLine, Graphs, Log, ServerInfo, DebugLog, Stats, Preferences, Login, AddServerBox, Search, ProgressbarWidth, SearchHeader, SearchResultLine, ProgressbarImgs, ProgressbarImgsPercent, CatArrow,
	DownArrow, UpArrow, DownDoubleArrow, UpDoubleArrow, Kad,
	BootstrapLine, MyInfoLog, CommentList, CommentListLine, Count
};
class WebTemplateRenderer {
public:
	explicit WebTemplateRenderer(const M2AParentPort& parent) noexcept;
	bool Reload(const CString& path, bool enabled, bool working,
		bool& stopServer);
	CString Get(WebTemplateId id) const;
	CString LastModified() const;
	CString ETag() const;
	void Capture(std::array<CString, static_cast<std::size_t>(WebTemplateId::Count)>& values,
		CString& lastModified, CString& etag) const;
private:
	const void* m_parent = nullptr;
	mutable std::mutex m_mutex;
	std::array<CString, static_cast<std::size_t>(WebTemplateId::Count)> m_values;
	CString m_lastModified;
	CString m_etag;
};
M2AModuleHandle M2A_BIND_W2_071B3D442B(const M2AParentPort&);
void M2A_UNBIND_W2_071B3D442B(const M2AParentPort&);
bool ReloadWebTemplates(const M2AParentPort&, const CString&, bool, bool, bool&);
CString GetWebTemplate(const M2AParentPort&, WebTemplateId);
CString GetWebTemplateLastModified(const M2AParentPort&);
CString GetWebTemplateETag(const M2AParentPort&);
M2AModuleHandle CaptureWebTemplateSnapshot(const M2AParentPort&);
CString EscapeWebTemplateText(const CString&, bool);
CString GetWebPlainResource(UINT, bool);
bool RunWebTemplateCharacterizationSelfTest();
} // namespace eSELive
