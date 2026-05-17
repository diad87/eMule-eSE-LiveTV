#pragma once

// ============================================================================
//  eSEHelpers — utilities for bridging eMule.exe and ese-server.exe
//
//  The Streaming Engine (ese-server.exe) needs to authenticate against
//  eMule's WebServer (port 4711). To make installation foolproof, eMule.exe
//  generates a per-install plaintext password, syncs it to its own WebServer
//  preferences in-memory, and passes it to the child via env var so they
//  always agree without any user intervention.
// ============================================================================

class CString;

namespace eSEHelpers
{
	// Returns a stable per-install plaintext password.
	// Reads from <configDir>\eSE_pass.bin if present; otherwise generates a
	// fresh 32-char hex string, persists it, and returns it. Never throws.
	CString EnsureSharedPassword(LPCTSTR configDir);
}
