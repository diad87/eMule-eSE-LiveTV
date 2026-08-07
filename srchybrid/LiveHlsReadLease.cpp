#include "stdafx.h"
#include "LiveStreamManager.h"

bool CLiveStreamManager::CopyBroadcastStreamKey(uchar outKey[16]) const
{
    if (outKey == NULL)
        return false;
    CSingleLock lock(&m_lock, TRUE);
    if (!m_broadcastSession.IsActive())
        return false;
    memcpy(outKey, m_broadcastStreamInfo.streamKey, 16);
    return true;
}

bool CLiveStreamManager::CopyViewerStreamKey(uchar outKey[16]) const
{
    if (outKey == NULL)
        return false;
    CSingleLock lock(&m_lock, TRUE);
    if (!m_viewerSession.IsActive())
        return false;
    memcpy(outKey, m_streamInfo.streamKey, 16);
    return true;
}

void CLiveStreamManager::NotePlayerFetch()
{
    m_viewerSession.NotePlayerFetch(
        static_cast<std::uint32_t>(::GetTickCount()));
}

void CLiveStreamManager::MarkWebPlayerSession()
{
    m_viewerSession.MarkWebPlayerSession(
        static_cast<std::uint32_t>(::GetTickCount()));
}

bool CLiveStreamManager::CopyHlsSourceSnapshot(
    const uchar streamKey[16], LiveHlsSourceSnapshot& out) const
{
    out = LiveHlsSourceSnapshot();
    if (streamKey == NULL)
        return false;
    CSingleLock lock(&m_lock, TRUE);
    return CopyHlsSourceSnapshotLocked(streamKey, out);
}

bool CLiveStreamManager::CopyHlsSourceSnapshotLocked(
    const uchar streamKey[16], LiveHlsSourceSnapshot& out) const
{
    out = LiveHlsSourceSnapshot();
    if (streamKey == NULL)
        return false;
    // Preserve the historical Broadcast-first resolver precedence.
    if (m_broadcastSession.IsActive() &&
        memcmp(m_broadcastStreamInfo.streamKey, streamKey, 16) == 0) {
        memcpy(out.streamKey, m_broadcastStreamInfo.streamKey,
            sizeof out.streamKey);
        out.generation = m_broadcastSession.Generation();
        out.broadcast = true;
        return out.generation != 0;
    }
    if (m_viewerSession.IsActive() &&
        memcmp(m_streamInfo.streamKey, streamKey, 16) == 0) {
        memcpy(out.streamKey, m_streamInfo.streamKey, sizeof out.streamKey);
        out.generation = m_viewerSession.Generation();
        out.broadcast = false;
        return out.generation != 0;
    }
    return false;
}

LiveHlsReadExecution CLiveStreamManager::ExecuteHlsReadIfCurrent(
    const LiveHlsSourceSnapshot& expected,
    LiveHlsReadPrepareCallback prepare,
    void* context)
{
    if (prepare == NULL || expected.generation == 0)
        return LiveHlsReadExecution::Failed;

    CSingleLock lock(&m_lock, TRUE);
    LiveHlsSourceSnapshot current;
    if (!CopyHlsSourceSnapshotLocked(expected.streamKey, current) ||
        current.broadcast != expected.broadcast ||
        current.generation != expected.generation ||
        memcmp(current.streamKey, expected.streamKey,
            sizeof current.streamKey) != 0) {
        return LiveHlsReadExecution::Stale;
    }

    // The audited lock order is manager -> WebAuthPolicy.  The callback may
    // Commit and capture a bounded local file, but never sends or re-enters.
    LiveHlsReadPreparation prepared = LiveHlsReadPreparation::Failed;
    try {
        prepared = prepare(context);
    } catch (...) {
        return LiveHlsReadExecution::Failed;
    }
    if (prepared == LiveHlsReadPreparation::Failed)
        return LiveHlsReadExecution::Failed;
    if (prepared == LiveHlsReadPreparation::PreparedWithBody &&
        !current.broadcast) {
        m_viewerSession.NotePlayerFetch(
            static_cast<std::uint32_t>(::GetTickCount()));
    }
    return LiveHlsReadExecution::Prepared;
}

bool CLiveStreamManager::RunHlsReadLeaseSelfTest(const uchar streamKey[16], CString& outFailure)
{
    const auto fail = [&outFailure](LPCTSTR reason) { outFailure = reason; return false; };
    LiveHlsSourceSnapshot active;
    if (!CopyHlsSourceSnapshot(streamKey, active) || !active.broadcast || active.generation == 0)
        return fail(_T("HLS lease could not snapshot the active broadcast"));

    TCHAR tempRoot[MAX_PATH] = {0};
    const DWORD tempLength = ::GetTempPath(_countof(tempRoot), tempRoot);
    if (tempLength == 0 || tempLength >= _countof(tempRoot))
        return fail(_T("HLS lease could not resolve the real playlist path"));
    CString playlistPath;
    playlistPath.Format(_T("%seMule_RTMP\\stream.m3u8"), tempRoot);

    struct PlaylistReadContext {
        explicit PlaylistReadContext(const CString& sourcePath) : path(sourcePath), invoked(false) {}
        CString path;
        std::vector<BYTE> bytes;
        bool invoked;
    };
    const LiveHlsReadPrepareCallback preparePlaylist =
        [](void* opaque) -> LiveHlsReadPreparation {
            PlaylistReadContext* context = static_cast<PlaylistReadContext*>(opaque);
            if (context == NULL)
                return LiveHlsReadPreparation::Failed;
            context->invoked = true;
            context->bytes.clear();
            CFile playlist;
            if (!playlist.Open(context->path,
                    CFile::modeRead | CFile::typeBinary | CFile::shareDenyNone))
                return LiveHlsReadPreparation::Failed;
            const ULONGLONG length = playlist.GetLength();
            const ULONGLONG kMaximumResponseBytes = 20ull * 1024ull * 1024ull;
            if (length < 7 || length > kMaximumResponseBytes)
                return LiveHlsReadPreparation::Failed;
            context->bytes.resize(static_cast<std::size_t>(length));
            const UINT read = playlist.Read(context->bytes.data(),
                static_cast<UINT>(context->bytes.size()));
            if (read != static_cast<UINT>(context->bytes.size()) ||
                memcmp(context->bytes.data(), "#EXTM3U", 7) != 0) {
                context->bytes.clear();
                return LiveHlsReadPreparation::Failed;
            }
            return LiveHlsReadPreparation::PreparedWithBody;
        };

    PlaylistReadContext currentRead(playlistPath);
    const LiveHlsReadExecution currentResult = ExecuteHlsReadIfCurrent(
        active, preparePlaylist, &currentRead);
    if (currentResult != LiveHlsReadExecution::Prepared ||
        !currentRead.invoked || currentRead.bytes.empty())
        return fail(_T("HLS lease did not capture real stream.m3u8"));
    const std::vector<BYTE> capturedBytes(currentRead.bytes);

    LiveHlsSourceSnapshot beforeStop;
    if (!CopyHlsSourceSnapshot(streamKey, beforeStop) ||
        beforeStop.generation != active.generation || !beforeStop.broadcast)
        return fail(_T("HLS lease generation changed before stop transition"));

    // No manager lock is held: the real transition invalidates the session.
    StopBroadcastFull();
    PlaylistReadContext staleRead(playlistPath);
    const LiveHlsReadExecution staleResult = ExecuteHlsReadIfCurrent(
        beforeStop, preparePlaylist, &staleRead);
    if (currentRead.bytes != capturedBytes)
        return fail(_T("HLS captured bytes changed after StopBroadcastFull"));
    if (staleResult != LiveHlsReadExecution::Stale || staleRead.invoked)
        return fail(_T("HLS stale lease callback executed after StopBroadcastFull"));
    return true;
}
