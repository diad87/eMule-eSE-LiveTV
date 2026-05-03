//this file is part of eMule
// eSE — Kad Bridge for Live Stream Discovery
// Publishes and discovers live streams using the Kad DHT network
// without modifying the Kad core code.
#pragma once

#include "LiveProtocol.h"

struct KadDebugSnapshot;  // Forward declaration (defined in LiveStreamManager.h)

class CUpDownClient;

// Discovery entry for a found live stream
struct LiveStreamEntry {
    uchar       streamKey[16];
    CString     title;
    CString     category;
    CString     language;
    uint16      bitrate;
    uint32      viewerCount;
    uint32      broadcasterIP;
    uint16      broadcasterPort;
    DWORD       lastSeen;       // GetTickCount() when last seen/refreshed
    uint32      startedAt;      // Unix timestamp
    bool        isOwnStream;
};

class CLiveKadBridge
{
public:
    CLiveKadBridge();
    ~CLiveKadBridge();

    // === Publishing (Broadcaster side) ===

    // Publish a live stream to the Kad network
    // Creates keyword entries based on the stream title
    // Returns true if publish was initiated
    bool PublishStream(const LiveStreamInfo& info);

    // Remove a published stream from the local directory
    void UnpublishStream(const uchar* streamKey);

    // Re-publish (called periodically, e.g. every 5 min)
    void RepublishIfNeeded();

    // === Discovery (Viewer side) ===

    // Search for live streams by keyword
    // Results arrive asynchronously via OnStreamFound callback
    bool SearchStreams(const CString& keyword);

    // Get current directory of known streams
    void GetKnownStreams(CArray<LiveStreamEntry>& outList) const;

    // Lookup a specific stream by key
    bool GetStreamInfo(const uchar* streamKey, LiveStreamEntry& outEntry) const;

    // === Network Callbacks ===

    // Called when we receive a Kad search result that's a live stream
    void OnKadSearchResult(const uchar* streamKey, const CString& title,
        const CString& category, uint32 broadcasterIP, uint16 broadcasterPort,
        uint16 bitrate, uint32 viewerCount);

    // === Periodic Maintenance ===

    // Called from CLiveStreamManager::Process()
    void Process();

    // Prune stale entries (not seen in > 5 min)
    void PruneStaleEntries();

    // === Accessors ===
    int GetDirectoryCount() const;

    // Phase 0: Debug accessors
    DWORD GetLastPublishTime() const { return m_dwLastPublishTime; }
    DWORD GetLastSearchTime() const  { return m_dwLastSearchTime; }
    uint32 GetLastResultIP() const   { return m_dwLastResultIP; }
    uint16 GetLastResultPort() const { return m_wLastResultPort; }
    DWORD GetLastResultTime() const  { return m_dwLastResultTime; }

    // Thread-safe snapshot of all debug fields (takes m_lock)
    KadDebugSnapshot BuildDebugKadSnapshot() const;

private:
    // Local directory of known streams
    CMap<CString, LPCTSTR, LiveStreamEntry, LiveStreamEntry&> m_streamDirectory;

    // Publish state
    bool    m_bPublished;
    DWORD   m_dwLastPublishTime;
    DWORD   m_dwLastSearchTime;
    DWORD   m_dwLastPruneTime;
    CString m_strLastSearchKeyword;

    LiveStreamInfo m_publishedInfo;  // Info of our own stream (if broadcasting)

    mutable CCriticalSection m_lock;

    // Phase 0: Last discovery result tracking
    uint32  m_dwLastResultIP;
    uint16  m_wLastResultPort;
    DWORD   m_dwLastResultTime;

    // Helper: generate Kad keyword hash from stream title
    CString StreamKeyToString(const uchar* streamKey) const;

    // Helper: encode stream info into Kad-compatible tag format
    void EncodeStreamTags(const LiveStreamInfo& info, CByteArray& outData) const;
};
