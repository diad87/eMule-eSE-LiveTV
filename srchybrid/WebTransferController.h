#pragma once

#include <string>

namespace ese
{
namespace web
{

enum class WebTransferFileOperation
{
    None,
    Stop,
    Pause,
    Resume,
    Cancel,
    GetFileLink,
    Rename,
    PriorityLow,
    PriorityNormal,
    PriorityHigh,
    PriorityAuto,
    SetCategory,
    StreamSeek
};

enum class WebTransferFriendOperation
{
    None,
    Add,
    Remove
};

enum class WebTransferColumnGroup
{
    None,
    Download,
    Upload,
    Queue
};

enum class WebTransferSort
{
    None,
    DownloadState,
    DownloadType,
    DownloadName,
    DownloadSize,
    DownloadTransferred,
    DownloadSpeed,
    DownloadProgress,
    DownloadSources,
    DownloadPriority,
    DownloadCategory,
    UploadUser,
    UploadClient,
    UploadVersion,
    UploadFilename,
    UploadTransferred,
    UploadSpeed,
    QueueClient,
    QueueUser,
    QueueVersion,
    QueueFilename,
    QueueScore
};

enum class WebTransferSortDomain
{
    None,
    Download,
    Upload,
    Queue
};

enum class WebTransferCategoryPriority
{
    None,
    Low,
    Normal,
    High,
    Auto
};

struct WebTransferFileAction
{
    bool allowed = false;
    WebTransferFileOperation operation =
        WebTransferFileOperation::None;
    std::string file_hash;
    std::string text;
    long value = -1;
};

struct WebTransferFriendAction
{
    bool allowed = false;
    WebTransferFriendOperation operation =
        WebTransferFriendOperation::None;
    std::string user_hash;
};

struct WebTransferColumnChange
{
    bool allowed = false;
    WebTransferColumnGroup group =
        WebTransferColumnGroup::None;
    unsigned index = 0;
    bool hidden = false;
};

struct WebTransferSortDecision
{
    bool allowed = false;
    WebTransferSort sort = WebTransferSort::None;
    WebTransferSortDomain domain =
        WebTransferSortDomain::None;
    unsigned target_index = 0;
    bool reverse = false;
};

struct WebTransferPriorityDecision
{
    bool allowed = false;
    WebTransferCategoryPriority priority =
        WebTransferCategoryPriority::None;
};

struct WebTransferClearAction
{
    bool allowed = false;
    bool all = false;
    std::string file_hash;
};

struct WebTransferAddAction
{
    bool allowed = false;
    std::string link;
};

struct WebTransferDownloadComparison
{
    int state = 0;
    int type = 0;
    int name = 0;
    int size = 0;
    int transferred = 0;
    int speed = 0;
    int progress = 0;
    int sources = 0;
    int priority = 0;
    int category = 0;
};

struct WebTransferUploadComparison
{
    int client = 0;
    int user = 0;
    int version = 0;
    int filename = 0;
    int transferred = 0;
    int speed = 0;
};

class WebTransferController
{
  public:
    static WebTransferClearAction PlanClearCompleted(
        bool isAdmin, const std::string &value);

    static WebTransferAddAction PlanAddDownload(
        bool isAdmin, const std::string &link);

    static WebTransferFileAction PlanFileAction(
        bool isAdmin, const std::string &operation,
        const std::string &fileHash,
        const std::string &text,
        const std::string &numericValue);

    static WebTransferFriendAction PlanFriendAction(
        bool isAdmin, const std::string &operation,
        const std::string &userHash);

    static WebTransferColumnChange PlanColumnChange(
        bool isAdmin, const std::string &command,
        const std::string &index,
        const std::string &hidden);

    static WebTransferSortDecision PlanSort(
        bool isAdmin, const std::string &sort,
        const std::string &explicitReverse);

    static WebTransferPriorityDecision PlanCategoryPriority(
        bool isAdmin, const std::string &priority);

    static bool TryApplyBoolean(bool isAdmin,
                                bool currentValue,
                                const std::string &input,
                                bool &output);

    static int CompareDownload(
        unsigned targetIndex, bool reverse,
        const WebTransferDownloadComparison &comparison);

    static int CompareUpload(
        unsigned targetIndex, bool reverse,
        const WebTransferUploadComparison &comparison);
};

} // namespace web
} // namespace ese
