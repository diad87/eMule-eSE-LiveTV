//this file is part of eMule — eSE Live Protocol Handlers
//Stub handlers — protocol dispatch is handled in ListenSocket.cpp
//Full handler logic is in LiveStreamManager.cpp (Process/OnChunkReceived/etc.)
//Copyright (C)2024 eSE Team
#include "stdafx.h"
#include "LiveStreamManager.h"
#include "LiveProtocol.h"
#include "SafeFile.h"
#include "UpDownClient.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

// ========================================================
// Protocol handlers — called by ListenSocket packet processor
// These delegate to the main CLiveStreamManager methods.
// The actual mesh logic is in LiveStreamManager.cpp and LiveMeshManager.cpp.
// ========================================================

// Stub: handled directly in ListenSocket.cpp → LiveStreamManager
