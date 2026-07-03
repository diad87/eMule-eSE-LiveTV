#include "stdafx.h"
#include "eSEHelpers.h"
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

namespace eSEHelpers
{

static const TCHAR kPassFileName[] = _T("eSE_pass.bin");

// Generate 16 cryptographically-random bytes → 32 hex chars.
// Uses BCrypt (CNG) with the system-preferred RNG; falls back to rand() if
// that fails (extremely unlikely on Win7+, but keep things robust).
static CString GenerateRandomHexPassword()
{
	BYTE rnd[16] = {0};
	bool ok = false;

	NTSTATUS status = BCryptGenRandom(NULL, rnd, (ULONG)sizeof(rnd), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	ok = BCRYPT_SUCCESS(status);

	if (!ok) {
		srand((unsigned)GetTickCount() ^ GetCurrentProcessId());
		for (int i = 0; i < (int)sizeof(rnd); ++i)
			rnd[i] = (BYTE)(rand() & 0xFF);
	}

	CString hex;
	for (int i = 0; i < (int)sizeof(rnd); ++i)
		hex.AppendFormat(_T("%02x"), rnd[i]);
	return hex;
}

CString EnsureSharedPassword(LPCTSTR configDir)
{
	CString path;
	path.Format(_T("%s\\%s"), configDir, kPassFileName);

	// Try to read existing password
	HANDLE h = CreateFile(path, GENERIC_READ, FILE_SHARE_READ, NULL,
	                      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h != INVALID_HANDLE_VALUE) {
		char buf[128] = {0};
		DWORD read = 0;
		ReadFile(h, buf, sizeof(buf) - 1, &read, NULL);
		CloseHandle(h);

		// Trim whitespace/newlines
		while (read > 0 && (buf[read-1] == '\r' || buf[read-1] == '\n' ||
		                    buf[read-1] == ' '  || buf[read-1] == '\t'))
			buf[--read] = '\0';

		if (read >= 8 && read <= 64) {
			// Validate hex-ish (allow any printable ASCII to be permissive
			// for users who hand-edit the file)
			bool valid = true;
			for (DWORD i = 0; i < read; ++i) {
				if (buf[i] < 0x20 || buf[i] > 0x7E) { valid = false; break; }
			}
			if (valid)
				return CString(buf);
		}
	}

	// Generate fresh password
	CString pw = GenerateRandomHexPassword();

	// Ensure directory exists (CreateDirectory is a no-op if it does)
	CreateDirectory(configDir, NULL);

	// Persist (best-effort; failure means next run will regenerate, which
	// would then cause a one-time desync — acceptable, user just re-clicks eSE)
	h = CreateFile(path, GENERIC_WRITE, 0, NULL,
	               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h != INVALID_HANDLE_VALUE) {
		CStringA pwA(pw);
		DWORD written = 0;
		WriteFile(h, (LPCSTR)pwA, pwA.GetLength(), &written, NULL);
		CloseHandle(h);
	}

	return pw;
}

} // namespace eSEHelpers
