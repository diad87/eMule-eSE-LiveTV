#include "stdafx.h"
#include "WebTransferProjection.h"
#include "OtherFunctions.h"
#include "resource.h"
#include <algorithm>
#include <memory>
#include <mutex>

namespace eSELive {
namespace {

std::mutex bindingMutex;
std::shared_ptr<WebTransferProjection> binding;
const void* bindingParent = nullptr;

CString Template(const WebTransferProjectionPort& port, WebTransferTemplate id) {
	return port.templateText(port.context, id);
}

CString Plain(const WebTransferProjectionPort& port, unsigned id) {
	return port.plain(port.context, id);
}

CString Special(const WebTransferProjectionPort& port, const CString& value,
	bool noquote = false) {
	return port.special(port.context, value, noquote);
}

template <typename Value>
int Compare(const Value& left, const Value& right) {
	return left < right ? -1 : (left > right ? 1 : 0);
}

struct ProjectionSort {
	unsigned index;
	bool reverse;
};

int CompareDownload(void* raw, const void* left, const void* right) {
	const DownloadFiles& first = *static_cast<const DownloadFiles*>(left);
	const DownloadFiles& second = *static_cast<const DownloadFiles*>(right);
	const ProjectionSort& sort = *static_cast<const ProjectionSort*>(raw);
	int order = 0;
	switch (sort.index) {
	case 0: order = Compare(first.iFileState, second.iFileState); break;
	case 1: order = first.sFileType.CompareNoCase(second.sFileType); break;
	case 2: order = first.sFileName.CompareNoCase(second.sFileName); break;
	case 3: order = Compare(first.m_qwFileSize, second.m_qwFileSize); break;
	case 4: order = Compare(first.m_qwFileTransferred, second.m_qwFileTransferred); break;
	case 5: order = Compare(first.lFileSpeed, second.lFileSpeed); break;
	case 6: order = Compare(first.m_dblCompleted, second.m_dblCompleted); break;
	case 7: order = Compare(first.lSourceCount, second.lSourceCount); break;
	case 8: order = Compare(first.nFilePrio, second.nFilePrio); break;
	case 9: order = first.sCategory.CompareNoCase(second.sCategory); break;
	default: return 0;
	}
	return sort.reverse ? order : -order;
}

int CompareUpload(void* raw, const void* left, const void* right) {
	const UploadUsers& first = *static_cast<const UploadUsers*>(left);
	const UploadUsers& second = *static_cast<const UploadUsers*>(right);
	const ProjectionSort& sort = *static_cast<const ProjectionSort*>(raw);
	int order = 0;
	switch (sort.index) {
	case 0: order = Compare(*first.sClientSoft, *second.sClientSoft); break;
	case 1: order = first.sUserName.CompareNoCase(second.sUserName); break;
	case 2: order = first.sClientNameVersion.CompareNoCase(second.sClientNameVersion); break;
	case 3: order = first.sFileName.CompareNoCase(second.sFileName); break;
	case 4: order = Compare(first.nTransferredUp, second.nTransferredUp); break;
	case 5: order = Compare(first.nDataRate, second.nDataRate); break;
	default: return 0;
	}
	return sort.reverse ? order : -order;
}

void ReplaceSortLinks(CString& output, const WebTransferProjectionInput& input) {
	static const LPCTSTR downloadTokens[] = {
		_T("State"), _T("Type"), _T("Name"), _T("Size"), _T("Transferred"),
		_T("Speed"), _T("Progress"), _T("Sources"), _T("Priority"), _T("Category")
	};
	static const LPCTSTR uploadTokens[] = {
		_T("Client"), _T("User"), _T("Version"), _T("Filename"),
		_T("Transferred"), _T("Speed")
	};
	const CString downloadToggle(input.downloadReverse
		? _T("&amp;sortreverse=false") : _T("&amp;sortreverse=true"));
	const CString uploadToggle(input.uploadReverse
		? _T("&amp;sortreverse=false") : _T("&amp;sortreverse=true"));
	for (unsigned index = 0; index < _countof(downloadTokens); ++index) {
		CString token;
		token.Format(_T("[SortD%s]"), downloadTokens[index]);
		output.Replace(token, input.downloadSort == index ? downloadToggle : _T(""));
	}
	for (unsigned index = 0; index < _countof(uploadTokens); ++index) {
		CString token;
		token.Format(_T("[SortU%s]"), uploadTokens[index]);
		output.Replace(token, input.uploadSort == index ? uploadToggle : _T(""));
	}
}

void ReplaceTitle(CString& output, LPCTSTR stem, const CString& title,
	bool hidden, bool selected, const CString& icon) {
	CString image, menu;
	image.Format(_T("[%sI]"), stem);
	menu.Format(_T("[%sM]"), stem);
	CString text;
	text.Format(_T("[%s]"), stem);
	output.Replace(image, hidden ? _T("") : (selected ? icon : _T("")));
	output.Replace(text, hidden ? _T("") : title);
	output.Replace(menu, title);
}

void RenderHeaders(CString& output, const WebTransferProjectionInput& input,
	const WebTransferProjectionPort& port) {
	ReplaceSortLinks(output, input);
	const CString downloadIcon(input.downloadReverse
		? Template(port, WebTransferTemplate::UpArrow)
		: Template(port, WebTransferTemplate::DownArrow));
	const CString uploadIcon(input.uploadReverse
		? Template(port, WebTransferTemplate::UpArrow)
		: Template(port, WebTransferTemplate::DownArrow));
	struct Title {
		LPCTSTR stem;
		unsigned resource;
		unsigned sort;
	};
	static const Title download[] = {
		{_T("DFilename"), IDS_DL_FILENAME, 2},
		{_T("DSize"), IDS_DL_SIZE, 3},
		{_T("DTransferred"), IDS_DL_TRANSFCOMPL, 4},
		{_T("DProgress"), IDS_DL_PROGRESS, 6},
		{_T("DSpeed"), IDS_DL_SPEED, 5},
		{_T("DSources"), IDS_DL_SOURCES, 7},
		{_T("DPriority"), IDS_PRIORITY, 8},
		{_T("DCategory"), IDS_CAT, 9}
	};
	static const Title upload[] = {
		{_T("UUser"), IDS_QL_USERNAME, 1},
		{_T("UVersion"), IDS_CD_VERSION, 2},
		{_T("UFilename"), IDS_DL_FILENAME, 3},
		{_T("UTransferred"), IDS_STATS_SRATIO, 4},
		{_T("USpeed"), IDS_DL_SPEED, 5}
	};
	for (unsigned index = 0; index < _countof(download); ++index)
		ReplaceTitle(output, download[index].stem, Plain(port, download[index].resource),
			input.downloadHidden[index], input.downloadSort == download[index].sort,
			downloadIcon);
	for (unsigned index = 0; index < _countof(upload); ++index)
		ReplaceTitle(output, upload[index].stem, Plain(port, upload[index].resource),
			input.uploadHidden[index], input.uploadSort == upload[index].sort,
			uploadIcon);
	output.Replace(_T("[DownloadList]"), Plain(port, IDS_TW_DOWNLOADS));
	output.Replace(_T("[UploadList]"), Plain(port, IDS_TW_UPLOADS));
	output.Replace(_T("[Actions]"), Plain(port, IDS_WEB_ACTIONS));
	output.Replace(_T("[TotalDown]"), Plain(port, IDS_INFLST_USER_TOTALDOWNLOAD));
	output.Replace(_T("[TotalUp]"), Plain(port, IDS_INFLST_USER_TOTALUPLOAD));
	output.Replace(_T("[admin]"), input.admin ? _T("admin") : _T(""));
}

CString DownloadPriority(const DownloadFiles& file) {
	if (file.bFileAutoPrio) return _T("Auto");
	switch (file.nFilePrio) {
	case 0: return _T("Low");
	case 1: return _T("Normal");
	case 2: return _T("High");
	default: return CString();
	}
}

void RenderDownloads(CString& output, const WebTransferProjectionInput& input,
	const WebTransferProjectionPort& port, const CArray<DownloadFiles>& files) {
	CString rows, temporary;
	double totalSize = 0, totalTransferred = 0, totalSpeed = 0;
	const CString rowTemplate(Template(port, WebTransferTemplate::DownLine));
	for (INT_PTR index = 0; index < files.GetCount(); ++index) {
		const DownloadFiles& file = files[index];
		CString row(rowTemplate);
		row.Replace(_T("[LastChangedDataset]"),
			file.sFileHash == input.selectedFile ? _T("checked") : _T("checked_no"));
		CString scriptInfo(file.sFileInfo), displayInfo(file.sFileInfo);
		scriptInfo.Replace(_T("\\"), _T("\\\\"));
		scriptInfo.Replace(_T("'"), _T("&#8217;"));
		scriptInfo.Replace(_T("\n"), _T("\\n"));
		displayInfo.Replace(_T("\n"), _T("<br>"));
		const bool active = file.sFileState.CompareNoCase(_T("downloading")) == 0
			|| file.sFileState.CompareNoCase(_T("waiting")) == 0;
		row.Replace(_T("[HASCOMMENT]"), file.iComment ? _T("") : _T("<!--"));
		row.Replace(_T("[HASCOMMENT_END]"), file.iComment ? _T("") : _T("-->"));
		row.Replace(_T("[ISACTIVE]"), active ? _T("<!--") : _T(""));
		row.Replace(_T("[ISACTIVE_END]"), active ? _T("-->") : _T(""));
		row.Replace(_T("[!ISACTIVE]"), active ? _T("") : _T("<!--"));
		row.Replace(_T("[!ISACTIVE_END]"), active ? _T("") : _T("-->"));
		CString ed2k(file.sED2kLink);
		ed2k.Replace(_T("'"), _T("&#8217;"));
		CString fileSize;
		fileSize.Format(_T("%I64u"), file.m_qwFileSize);
		CString getFileLink;
		if (!file.bIsPreview)
			getFileLink = file.bIsGetFLC ? _T("enabled") : _T("disabled");
		row.Replace(_T("[admin]"), input.admin ? _T("admin") : _T(""));
		row.Replace(_T("[finfo]"), scriptInfo);
		row.Replace(_T("[fcomments]"), file.iComment ? _T("yes") : _T(""));
		row.Replace(_T("[ed2k]"), Special(port, ed2k, true));
		row.Replace(_T("[DownState]"), file.sFileState);
		row.Replace(_T("[isgetflc]"), getFileLink);
		row.Replace(_T("[fname]"), Special(port, file.sFileNameJS, true));
		row.Replace(_T("[fsize]"), fileSize);
		row.Replace(_T("[session]"), input.session);
		row.Replace(_T("[filehash]"), file.sFileHash);
		row.Replace(_T("[down-priority]"), DownloadPriority(file));
		row.Replace(_T("[FileType]"), file.sFileType);
		row.Replace(_T("[downloadable]"), input.admin
			&& (input.maxWebUploadFileSizeMB == 0 || file.m_qwFileSize
				< static_cast<uint64>(input.maxWebUploadFileSizeMB) * 1024 * 1024)
			? _T("yes") : _T("no"));
		row.Replace(_T("[FileCommentIcon]"),
			file.iComment == 1 ? _T("cmtgood")
			: (file.iComment == 2 ? _T("cmtbad") : _T("none")));
		row.Replace(_T("[FileIsGetFLC]"),
			!file.bIsPreview && file.bIsGetFLC ? _T("getflc") : _T("halfnone"));
		if (input.downloadHidden[0]) row.Replace(_T("[ShortFileName]"), _T(""));
		else if (file.sFileName.GetLength() > 60)
			row.Replace(_T("[ShortFileName]"), file.sFileName.Left(57) + _T("..."));
		else row.Replace(_T("[ShortFileName]"), file.sFileName);
		row.Replace(_T("[FileInfo]"), displayInfo);
		totalSize += file.m_qwFileSize;
		row.Replace(_T("[2]"), input.downloadHidden[1]
			? _T("") : static_cast<LPCTSTR>(CastItoXBytes(file.m_qwFileSize)));
		if (input.downloadHidden[2]) row.Replace(_T("[3]"), _T(""));
		else if (file.m_qwFileTransferred > 0) {
			totalTransferred += file.m_qwFileTransferred;
			row.Replace(_T("[3]"), CastItoXBytes(file.m_qwFileTransferred));
		} else row.Replace(_T("[3]"), _T("-"));
		row.Replace(_T("[DownloadBar]"), input.downloadHidden[3] ? _T("")
			: file.sDownloadGraph);
		if (input.downloadHidden[4]) temporary.Empty();
		else if (file.lFileSpeed > 0) {
			totalSpeed += file.lFileSpeed;
			temporary.Format(_T("%8.2f"), file.lFileSpeed / 1024.0);
		} else temporary = _T("-");
		row.Replace(_T("[4]"), temporary);
		if (input.downloadHidden[5]) temporary.Empty();
		else if (file.lSourceCount > 0)
			temporary.Format(_T("%li&nbsp;/&nbsp;%8li&nbsp;(%li)"),
				file.lSourceCount - file.lNotCurrentSourceCount,
				file.lSourceCount, file.lTransferringSourceCount);
		else temporary = _T("-");
		row.Replace(_T("[5]"), temporary);
		if (input.downloadHidden[6] || file.nFilePrio < 0 || file.nFilePrio > 2)
			row.Replace(_T("[PrioVal]"), _T(""));
		else {
			static const UINT priority[2][3] = {
				{IDS_PRIOLOW, IDS_PRIONORMAL, IDS_PRIOHIGH},
				{IDS_PRIOAUTOLOW, IDS_PRIOAUTONORMAL, IDS_PRIOAUTOHIGH}
			};
			row.Replace(_T("[PrioVal]"),
				GetResString(priority[static_cast<unsigned>(file.bFileAutoPrio)]
					[file.nFilePrio]));
		}
		row.Replace(_T("[Category]"),
			input.downloadHidden[7] ? _T("") : static_cast<LPCTSTR>(file.sCategory));
		port.insertCategory(port.context, row, 0, _T(""), false, false,
			input.session, file.sFileHash, file.nCategory);
		rows += row;
	}
	output.Replace(_T("[DownloadFilesList]"), rows);
	output.Replace(_T("[TotalDownSize]"), CastItoXBytes(totalSize));
	output.Replace(_T("[TotalDownTransferred]"), CastItoXBytes(totalTransferred));
	temporary.Format(_T("%8.2f"), totalSpeed / 1024.0);
	output.Replace(_T("[TotalDownSpeed]"), temporary);
	temporary.Format(_T("%s: %i"), static_cast<LPCTSTR>(GetResString(IDS_SF_FILE)),
		static_cast<int>(files.GetCount()));
	output.Replace(_T("[TotalFiles]"), temporary);
	temporary.Format(_T("%i"), static_cast<uint16>(
		_tstoi(Template(port, WebTransferTemplate::ProgressbarWidth))));
	output.Replace(_T("[PROGRESSBARWIDTHVAL]"), temporary);
}

void RenderUploads(CString& output, const WebTransferProjectionInput& input,
	const WebTransferProjectionPort& port, const CArray<UploadUsers>& uploads) {
	CString rowTemplate(Template(port, WebTransferTemplate::UpLine));
	rowTemplate.Replace(_T("[admin]"), input.admin ? _T("admin") : _T(""));
	CString rows, temporary;
	double totalDown = 0, totalUp = 0, totalSpeed = 0;
	for (INT_PTR index = 0; index < uploads.GetCount(); ++index) {
		const UploadUsers& user = uploads[index];
		CString row(rowTemplate);
		row.Replace(_T("[UserHash]"), user.sUserHash);
		row.Replace(_T("[UpState]"), user.sActive);
		row.Replace(_T("[FileInfo]"), user.sFileInfo);
		row.Replace(_T("[ClientState]"), user.sClientState);
		row.Replace(_T("[ClientSoft]"), user.sClientSoft);
		row.Replace(_T("[ClientExtra]"), user.sClientExtra);
		row.Replace(_T("[1]"), input.uploadHidden[0] ? _T("") : user.sUserName);
		row.Replace(_T("[ClientSoftV]"),
			input.uploadHidden[1] ? _T("") : user.sClientNameVersion);
		row.Replace(_T("[2]"), input.uploadHidden[2] ? _T("") : user.sFileName);
		if (input.uploadHidden[3]) temporary.Empty();
		else {
			totalDown += user.nTransferredDown;
			totalUp += user.nTransferredUp;
			temporary.Format(_T("%s / %s"),
				static_cast<LPCTSTR>(CastItoXBytes(user.nTransferredDown)),
				static_cast<LPCTSTR>(CastItoXBytes(user.nTransferredUp)));
		}
		row.Replace(_T("[3]"), temporary);
		if (input.uploadHidden[4]) temporary.Empty();
		else {
			totalSpeed += user.nDataRate;
			temporary.Format(_T("%8.2f "), max(user.nDataRate / 1024.0, 0.0));
		}
		row.Replace(_T("[4]"), temporary);
		rows += row;
	}
	output.Replace(_T("[UploadFilesList]"), rows);
	temporary.Format(_T("%s / %s"), static_cast<LPCTSTR>(CastItoXBytes(totalDown)),
		static_cast<LPCTSTR>(CastItoXBytes(totalUp)));
	output.Replace(_T("[TotalUpTransferred]"), temporary);
	temporary.Format(_T("%8.2f "), max(totalSpeed / 1024, 0.0));
	output.Replace(_T("[TotalUpSpeed]"), temporary);
}

CString RenderQueueRows(const WebTransferProjectionInput& input,
	const WebTransferProjectionPort& port, const CArray<QueueUsers>& queue,
	LPCTSTR group, WebTransferTemplate lineTemplate) {
	CString rowTemplate(Template(port, lineTemplate)), rows;
	if (lineTemplate == WebTransferTemplate::QueueLine)
		rowTemplate.Replace(_T("[admin]"), input.admin ? _T("admin") : _T(""));
	for (INT_PTR index = 0; index < queue.GetCount(); ++index) {
		const QueueUsers& user = queue[index];
		if (user.sClientExtra != group) continue;
		CString row(rowTemplate), score;
		row.Replace(_T("[UserName]"),
			input.queueHidden[0] ? _T("") : user.sUserName);
		row.Replace(_T("[ClientSoftV]"),
			input.queueHidden[1] ? _T("") : user.sClientNameVersion);
		row.Replace(_T("[FileName]"),
			input.queueHidden[2] ? _T("") : user.sFileName);
		if (!input.queueHidden[3]) score.Format(_T("%i"), user.nScore);
		row.Replace(_T("[Score]"), score);
		row.Replace(_T("[ClientState]"), user.sClientState);
		row.Replace(_T("[ClientStateSpecial]"), user.sClientStateSpecial);
		row.Replace(_T("[ClientSoft]"), user.sClientSoft);
		row.Replace(_T("[ClientExtra]"), user.sClientExtra);
		row.Replace(_T("[UserHash]"), user.sUserHash);
		rows += row;
	}
	return rows;
}

void RenderQueue(CString& output, const WebTransferProjectionInput& input,
	const WebTransferProjectionPort& port, const WebTransferSnapshot& snapshot) {
	struct Group {
		bool show;
		LPCTSTR group, outer, heading, list;
		unsigned headingResource;
		WebTransferTemplate shown, hidden, line;
	};
	const Group groups[] = {
		{input.showQueue, _T("none"), _T("[UploadQueue]"),
			_T("[UploadQueueList]"), _T("[QueueList]"), IDS_ONQUEUE,
			WebTransferTemplate::QueueShow, WebTransferTemplate::QueueHide,
			WebTransferTemplate::QueueLine},
		{input.showBanned, _T("banned"), _T("[UploadQueueBanned]"),
			_T("[UploadQueueBannedList]"), _T("[QueueListBanned]"), IDS_BANNED,
			WebTransferTemplate::QueueBannedShow,
			WebTransferTemplate::QueueBannedHide,
			WebTransferTemplate::QueueBannedLine},
		{input.showFriend, _T("friend"), _T("[UploadQueueFriend]"),
			_T("[UploadQueueFriendList]"), _T("[QueueListFriend]"),
			IDS_IRC_ADDTOFRIENDLIST, WebTransferTemplate::QueueFriendShow,
			WebTransferTemplate::QueueFriendHide,
			WebTransferTemplate::QueueFriendLine}
	};
	for (const Group& group : groups) {
		output.Replace(group.outer, Template(port, group.show ? group.shown : group.hidden));
		if (group.show) {
			output.Replace(group.heading, Plain(port, group.headingResource));
			output.Replace(group.list,
				RenderQueueRows(input, port, snapshot.queue, group.group, group.line));
		}
	}
	CString counter;
	const struct { LPCTSTR token; int value; } counters[] = {
		{_T("[CounterQueue]"), snapshot.queueCount},
		{_T("[CounterQueueBanned]"), snapshot.bannedCount},
		{_T("[CounterQueueFriend]"), snapshot.friendCount},
		{_T("[CounterQueueSecure]"), snapshot.queueSecure},
		{_T("[CounterQueueBannedSecure]"), snapshot.bannedSecure},
		{_T("[CounterQueueFriendSecure]"), snapshot.friendSecure},
		{_T("[CounterAll]"), snapshot.queueCount + snapshot.bannedCount
			+ snapshot.friendCount},
		{_T("[CounterAllSecure]"), snapshot.queueSecure + snapshot.bannedSecure
			+ snapshot.friendSecure}
	};
	for (const auto& item : counters) {
		counter.Format(_T("%i"), item.value);
		output.Replace(item.token, counter);
	}
	output.Replace(_T("[ShowUploadQueue]"), Plain(port, IDS_VIEWQUEUE));
	output.Replace(_T("[ShowUploadQueueList]"),
		Plain(port, IDS_WEB_SHOW_UPLOAD_QUEUE));
	output.Replace(_T("[ShowUploadQueueListBanned]"),
		Plain(port, IDS_WEB_SHOW_UPLOAD_QUEUE_BANNED));
	output.Replace(_T("[ShowUploadQueueListFriend]"),
		Plain(port, IDS_WEB_SHOW_UPLOAD_QUEUE_FRIEND));
	const CString toggle(input.queueReverse
		? _T("&amp;sortreverse=false") : _T("&amp;sortreverse=true"));
	static const LPCTSTR sortTokens[] = {
		_T("Client"), _T("User"), _T("Version"), _T("Filename"), _T("Score")
	};
	for (unsigned index = 0; index < _countof(sortTokens); ++index) {
		CString token;
		token.Format(_T("[SortQ%s]"), sortTokens[index]);
		output.Replace(token, input.queueSort == index ? toggle : _T(""));
	}
	const CString icon(input.queueReverse
		? Template(port, WebTransferTemplate::UpArrow)
		: Template(port, WebTransferTemplate::DownArrow));
	static const struct { LPCTSTR stem; unsigned resource; unsigned sort; } titles[] = {
		{_T("UserNameTitle"), IDS_QL_USERNAME, 1},
		{_T("Version"), IDS_CD_CSOFT, 2},
		{_T("FileNameTitle"), IDS_DL_FILENAME, 3},
		{_T("ScoreTitle"), IDS_SCORE, 4}
	};
	for (unsigned index = 0; index < _countof(titles); ++index)
		ReplaceTitle(output, titles[index].stem, Plain(port, titles[index].resource),
			input.queueHidden[index], input.queueSort == titles[index].sort, icon);
}

struct SelfTestState {
	int snapshots = 0;
	int escaped = 0;
	int categoryCalls = 0;
	int lastCategory = -1;
	bool renderStarted = false;
	bool escapeMode = true;
	CString events;
};

CString SelfTemplate(void* raw, WebTransferTemplate id) {
	SelfTestState& state = *static_cast<SelfTestState*>(raw);
	state.renderStarted = true;
	state.events += _T("R");
	switch (id) {
	case WebTransferTemplate::List:
		return _T("[DownloadHeader][DownloadFooter][UploadHeader][UploadFooter]"
			"[DownloadFilesList][UploadFilesList][UploadQueue][UploadQueueBanned]"
			"[UploadQueueFriend][Session][CatSel]");
	case WebTransferTemplate::DownLine:
		return _T("[Category][DownloadBar][filehash]|");
	case WebTransferTemplate::UpLine: return _T("[UserHash]|");
	case WebTransferTemplate::QueueShow: return _T("Q:[QueueList]");
	case WebTransferTemplate::QueueBannedShow: return _T("B:[QueueListBanned]");
	case WebTransferTemplate::QueueFriendShow: return _T("F:[QueueListFriend]");
	case WebTransferTemplate::QueueLine:
	case WebTransferTemplate::QueueBannedLine:
	case WebTransferTemplate::QueueFriendLine: return _T("[admin][UserHash]|");
	default: return CString();
	}
}

CString SelfPlain(void*, unsigned id) {
	CString value;
	value.Format(_T("R%u"), id);
	return value;
}

CString SelfSpecial(void* raw, const CString& value, bool noquote) {
	SelfTestState& state = *static_cast<SelfTestState*>(raw);
	++state.escaped;
	state.escapeMode = state.escapeMode && noquote;
	return value;
}
void SelfCategory(void* raw, CString&, int, LPCTSTR, bool, bool,
	const CString&, const CString&, int fileCategory) {
	SelfTestState& state = *static_cast<SelfTestState*>(raw);
	++state.categoryCalls;
	state.lastCategory = fileCategory;
}
void SelfSnapshot(void* raw, int, unsigned, bool, unsigned, bool, unsigned,
	bool, bool, bool, bool, WebTransferSnapshot& snapshot) {
	SelfTestState& state = *static_cast<SelfTestState*>(raw);
	if (state.renderStarted) state.events += _T("!");
	state.events += _T("S");
	++state.snapshots;
	DownloadFiles first{}, second{};
	first.sFileHash = _T("B"); first.sFileName = _T("Bravo");
	first.sFileNameJS = _T("Br'av\\no"); first.sED2kLink = _T("ed'2k");
	first.sCategory = _T("C"); first.sDownloadGraph = _T("G");
	first.nCategory = 2;
	second.sFileHash = _T("A"); second.sFileName = _T("Alpha");
	snapshot.downloads.Add(first); snapshot.downloads.Add(second);
	for (int index = 0; index < 3; ++index) {
		QueueUsers user{};
		user.sClientExtra = index == 0 ? _T("none")
			: (index == 1 ? _T("banned") : _T("friend"));
		user.sUserHash.Format(_T("%i"), index);
		snapshot.queue.Add(user);
	}
}

} // namespace

bool WebTransferProjectionPort::Complete() const noexcept {
	return templateText && plain && special && insertCategory && snapshot;
}

WebTransferProjection::WebTransferProjection(
	const M2AParentPort& parent) noexcept : m_parent(parent.context) {}

CString WebTransferProjection::Render(const WebTransferProjectionInput& input,
	const WebTransferProjectionPort& port) const {
	if (m_parent == nullptr || !port.Complete()) return CString();
	WebTransferSnapshot snapshot;
	port.snapshot(port.context, input.category, input.downloadSort,
		input.downloadReverse, input.uploadSort, input.uploadReverse,
		input.queueSort, input.queueReverse, input.showQueue, input.showBanned,
		input.showFriend, snapshot);
	ProjectionSort downloadSort{input.downloadSort, input.downloadReverse};
	ProjectionSort uploadSort{input.uploadSort, input.uploadReverse};
	if (snapshot.downloads.GetCount() > 1)
		qsort_s(snapshot.downloads.GetData(), snapshot.downloads.GetCount(),
			sizeof(DownloadFiles), CompareDownload, &downloadSort);
	if (snapshot.uploads.GetCount() > 1)
		qsort_s(snapshot.uploads.GetData(), snapshot.uploads.GetCount(),
			sizeof(UploadUsers), CompareUpload, &uploadSort);
	CString output(Template(port, WebTransferTemplate::Images));
	output += Template(port, WebTransferTemplate::List);
	output.Replace(_T("[DownloadHeader]"), Template(port, WebTransferTemplate::DownHeader));
	output.Replace(_T("[DownloadFooter]"), Template(port, WebTransferTemplate::DownFooter));
	output.Replace(_T("[UploadHeader]"), Template(port, WebTransferTemplate::UpHeader));
	output.Replace(_T("[UploadFooter]"), Template(port, WebTransferTemplate::UpFooter));
	port.insertCategory(port.context, output, input.category,
		Template(port, WebTransferTemplate::CatArrow), true, true,
		input.session, _T(""), input.category);
	RenderHeaders(output, input, port);
	port.insertCategory(port.context, output, input.category, _T(""), true,
		true, input.session, _T(""), input.category);
	RenderDownloads(output, input, port, snapshot.downloads);
	RenderUploads(output, input, port, snapshot.uploads);
	RenderQueue(output, input, port, snapshot);
	output.Replace(_T("[Session]"), input.session);
	output.Replace(_T("[CatSel]"), input.categorySuffix);
	return output;
}

M2AModuleHandle M2A_BIND_W4_AD763A5EE0(const M2AParentPort& parent) {
	if (!parent) return M2AModuleHandle();
	std::lock_guard<std::mutex> lock(bindingMutex);
	if (bindingParent != parent.context || !binding) {
		binding = std::make_shared<WebTransferProjection>(parent);
		bindingParent = parent.context;
	}
	return MakeM2AModuleHandle(new WebTransferProjection(parent));
}

void M2A_UNBIND_W4_AD763A5EE0(const M2AParentPort& parent) {
	std::lock_guard<std::mutex> lock(bindingMutex);
	if (bindingParent == parent.context) {
		binding.reset();
		bindingParent = nullptr;
	}
}

CString RunWebTransferProjection(const M2AParentPort& parent,
	const WebTransferProjectionInput& input,
	const WebTransferProjectionPort& port) {
	std::shared_ptr<WebTransferProjection> module;
	{
		std::lock_guard<std::mutex> lock(bindingMutex);
		if (bindingParent == parent.context) module = binding;
	}
	return module ? module->Render(input, port) : CString();
}

bool RunWebTransferProjectionCharacterizationSelfTest() {
	SelfTestState state;
	WebTransferProjectionPort port;
	port.context = &state;
	port.templateText = SelfTemplate;
	port.plain = SelfPlain;
	port.special = SelfSpecial;
	port.insertCategory = SelfCategory;
	port.snapshot = SelfSnapshot;
	WebTransferProjectionInput input;
	input.session = _T("7");
	input.downloadSort = 2;
	input.downloadReverse = true;
	input.admin = true;
	input.showQueue = input.showBanned = input.showFriend = true;
	WebTransferProjection module(M2AParentPort{&state});
	const CString html(module.Render(input, port));
	return state.snapshots == 1 && state.events.GetLength() > 1
		&& state.events[0] == _T('S') && state.escaped == 4 && state.escapeMode
		&& state.categoryCalls == 4 && state.lastCategory == 2
		&& html.Find(_T("A|CGB|")) >= 0
		&& html.Find(_T("Q:admin0|")) >= 0
		&& html.Find(_T("B:[admin]1|")) >= 0
		&& html.Find(_T("F:[admin]2|")) >= 0;
}

} // namespace eSELive
