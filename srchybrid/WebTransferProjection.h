#pragma once

#include "M2ABindingPort.h"
#include "Types.h"
#include <afxtempl.h>
#include <afxstr.h>
#include <array>
#include <cstdint>

typedef struct
{
	CString	sCategory;
	CString	sED2kLink;
	CString	sFileHash;
	CString	sFileInfo;
	CString	sFileName;
	CString	sFileNameJS;
	CString	sFileState;
	CString	sFileType;
	CString	sDownloadGraph;
	double	m_dblCompleted;
	uint64	m_qwFileSize;
	uint64	m_qwFileTransferred;
	uint32	lFileSpeed;
	long	lNotCurrentSourceCount;
	long	lSourceCount;
	long	lTransferringSourceCount;
	bool	bFileAutoPrio;
	int		iComment;
	int		iFileState;
	int		nFilePrio;
	int		nFileStatus;
	int		nCategory;
	bool	bIsComplete;
	bool	bIsGetFLC;
	bool	bIsPreview;
} DownloadFiles;

typedef struct
{
	CString	sClientState;
	CString	sUserHash;
	CString	sActive;
	CString sFileInfo;
	CString	sClientExtra;
	CString	sUserName;
	CString	sFileName;
	CString	sClientNameVersion;
	uint64	nTransferredDown;
	uint64	nTransferredUp;
	int		nDataRate;
	TCHAR	sClientSoft[2];
} UploadUsers;

typedef struct
{
	CString	sClientExtra;
	CString	sClientNameVersion;
	CString	sClientSoftSpecial;
	CString	sClientState;
	CString	sClientStateSpecial;
	CString	sFileName;
	CString	sIndex;
	CString	sUserHash;
	CString	sUserName;
	uint32	nScore;
	TCHAR	sClientSoft[2];
} QueueUsers;

namespace eSELive {

enum class WebTransferTemplate : std::uint8_t {
	Images, List, DownHeader, DownFooter, DownLine, UpHeader, UpFooter,
	UpLine, QueueShow, QueueHide, QueueLine, QueueBannedShow,
	QueueBannedHide, QueueBannedLine, QueueFriendShow, QueueFriendHide,
	QueueFriendLine, ProgressbarWidth, CatArrow, DownArrow, UpArrow
};

struct WebTransferProjectionInput {
	CString url, session, categorySuffix, selectedFile;
	int category = 0;
	bool admin = false;
	unsigned downloadSort = 0, uploadSort = 0, queueSort = 0;
	bool downloadReverse = false, uploadReverse = false, queueReverse = false;
	bool showQueue = false, showBanned = false, showFriend = false;
	unsigned maxWebUploadFileSizeMB = 0;
	std::array<bool, 8> downloadHidden{};
	std::array<bool, 5> uploadHidden{};
	std::array<bool, 4> queueHidden{};
};

struct WebTransferSnapshot {
	CArray<DownloadFiles> downloads;
	CArray<UploadUsers> uploads;
	CArray<QueueUsers> queue;
	int queueCount = 0, bannedCount = 0, friendCount = 0;
	int queueSecure = 0, bannedSecure = 0, friendSecure = 0;
};

struct WebTransferProjectionPort {
	void* context = nullptr;
	CString (*templateText)(void*, WebTransferTemplate) = nullptr;
	CString (*plain)(void*, unsigned) = nullptr;
	CString (*special)(void*, const CString&, bool) = nullptr;
	void (*insertCategory)(void*, CString&, int, LPCTSTR, bool, bool,
		const CString&, const CString&, int) = nullptr;
	void (*snapshot)(void*, int, unsigned, bool, unsigned, bool, unsigned,
		bool, bool, bool, bool, WebTransferSnapshot&) = nullptr;
	bool Complete() const noexcept;
};

class WebTransferProjection {
public:
	explicit WebTransferProjection(const M2AParentPort& parent) noexcept;
	CString Render(const WebTransferProjectionInput& input,
		const WebTransferProjectionPort& port) const;
private:
	const void* m_parent = nullptr;
};

M2AModuleHandle M2A_BIND_W4_AD763A5EE0(const M2AParentPort&);
void M2A_UNBIND_W4_AD763A5EE0(const M2AParentPort&);
CString RunWebTransferProjection(const M2AParentPort&,
	const WebTransferProjectionInput&, const WebTransferProjectionPort&);
bool RunWebTransferProjectionCharacterizationSelfTest();

} // namespace eSELive
