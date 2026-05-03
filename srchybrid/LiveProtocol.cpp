//this file is part of eMule — eSE Live Streaming Extension
//Copyright (C)2024 eSE Team
#include "stdafx.h"
#include "LiveProtocol.h"
#include "SafeFile.h"
#include "Packets.h"
#include "UpDownClient.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

// ========================================================
// Wire format serialization / deserialization
// ========================================================

// Write a LiveStreamInfo to a CSafeMemFile (for OP_LIVE_ANNOUNCE)
void WriteLiveAnnounce(CSafeMemFile* pFile, const LiveStreamInfo& info)
{
	pFile->WriteHash16(info.streamKey);
	pFile->WriteString(info.title, UTF8strRaw);
	pFile->WriteString(info.category, UTF8strRaw);
	pFile->WriteString(info.language, UTF8strRaw);
	pFile->WriteUInt32(info.bitrate);
	pFile->WriteUInt8(info.isBroadcaster ? 1 : 0);
}

// Read a LiveStreamInfo from a CSafeMemFile
bool ReadLiveAnnounce(CSafeMemFile* pFile, LiveStreamInfo& info)
{
	try {
		pFile->ReadHash16(info.streamKey);
		info.title = pFile->ReadString(true);
		info.category = pFile->ReadString(true);
		info.language = pFile->ReadString(true);
		info.bitrate = pFile->ReadUInt32();
		info.isBroadcaster = (pFile->ReadUInt8() != 0);
		return true;
	}
	catch (...) {
		return false;
	}
}

// Write OP_LIVE_REQUEST
void WriteLiveRequest(CSafeMemFile* pFile, const uchar* streamKey, uint32 segmentIndex)
{
	pFile->WriteHash16(streamKey);
	pFile->WriteUInt32(segmentIndex);
}

// Write OP_LIVE_CHUNK header (payload follows separately)
void WriteLiveChunkHeader(CSafeMemFile* pFile, const uchar* streamKey,
	uint32 segmentIndex, uint32 chunkSize)
{
	pFile->WriteHash16(streamKey);
	pFile->WriteUInt32(segmentIndex);
	pFile->WriteUInt32(chunkSize);
}

// Write OP_LIVE_SUBSCRIBE / OP_LIVE_UNSUBSCRIBE
void WriteLiveSubscribe(CSafeMemFile* pFile, const uchar* streamKey, const uchar* viewerHash)
{
	pFile->WriteHash16(streamKey);
	pFile->WriteHash16(viewerHash);
}

// Write OP_LIVE_HEARTBEAT (peer bitmap exchange)
void WriteLiveHeartbeat(CSafeMemFile* pFile, const uchar* streamKey,
	uint16 bitmap, uint32 oldestSeq)
{
	pFile->WriteHash16(streamKey);
	pFile->WriteUInt16(bitmap);
	pFile->WriteUInt32(oldestSeq);
}

// Write OP_LIVE_DENY
void WriteLiveDeny(CSafeMemFile* pFile, const uchar* streamKey, uint8 reason)
{
	pFile->WriteHash16(streamKey);
	pFile->WriteUInt8(reason);
}

// Write OP_LIVE_END (stream shutdown)
void WriteLiveEnd(CSafeMemFile* pFile, const uchar* streamKey, uint8 reason)
{
	pFile->WriteHash16(streamKey);
	pFile->WriteUInt8(reason);
}
