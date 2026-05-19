// this file is part of eMule eSE — v7.x → V1 migration impl (F5b)
#include "stdafx.h"
#include "LiveMigrationV7.h"

#include <shlobj.h>

namespace eSELive {

namespace {

CStringW AppDataConfigDir()
{
    wchar_t path[MAX_PATH] = {0};
    if (FAILED(SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, path)))
        return CStringW();
    CStringW out(path);
    out += L"\\eMule\\config";
    return out;
}

bool FileExists(const CStringW& p)
{
    DWORD attrs = GetFileAttributesW(p);
    return (attrs != INVALID_FILE_ATTRIBUTES) && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
}

}  // namespace

CStringW CLiveMigrationV7::MarkerPath()
{
    return AppDataConfigDir() + L"\\ese_migration_v1.done";
}

CStringW CLiveMigrationV7::LegacyDirectoryPath()
{
    return AppDataConfigDir() + L"\\eselive_directory.dat";
}

CStringW CLiveMigrationV7::LegacyLastStreamsPath()
{
    return AppDataConfigDir() + L"\\last_streams.json";
}

bool CLiveMigrationV7::ImportDirectoryDat()
{
    const CStringW p = LegacyDirectoryPath();
    if (!FileExists(p)) return false;
    CStdioFile f;
    if (!f.Open(p, CFile::modeRead | CFile::typeText)) return false;
    // Format is key=value lines as written by CLiveKadBridge. V1 doesn't
    // parse the format here — instead it lets CLiveKadBridge::Load*FromDisk
    // do its job. We only confirm the file is non-empty, then let the
    // bridge pick it up naturally on its first tick (Process() lazy-loads).
    ULONGLONG len = f.GetLength();
    f.Close();
    return len > 0;
}

bool CLiveMigrationV7::ImportLastStreamsJson()
{
    const CStringW p = LegacyLastStreamsPath();
    if (!FileExists(p)) return false;
    // Same approach: file is preserved in place; LiveStreamManager's
    // BootstrapPingCachedStreams in v7.x.x reads it directly. V1 ships
    // identical loader, so no migration needed beyond detection.
    return true;
}

int CLiveMigrationV7::RunIfNeeded()
{
    if (FileExists(MarkerPath())) return 0;
    return ForceRun();
}

int CLiveMigrationV7::ForceRun()
{
    int imported = 0;
    if (ImportDirectoryDat())     ++imported;
    if (ImportLastStreamsJson())  ++imported;

    // Write marker so this doesn't repeat. Even with 0 imports we mark
    // done — a clean install on a machine that never had v7 doesn't need
    // to re-check the missing files at every launch.
    CStdioFile fmark;
    if (fmark.Open(MarkerPath(),
                   CFile::modeWrite | CFile::modeCreate | CFile::typeText))
    {
        CTime t = CTime::GetCurrentTime();
        CStringW line;
        line.Format(L"# eSE Live V1 migration completed at %s UTC\r\n# Imported legacy files: %d\r\n",
                    (LPCWSTR)t.FormatGmt(_T("%Y-%m-%dT%H:%M:%S")),
                    imported);
        fmark.WriteString(line);
        fmark.Close();
    }
    return imported;
}

}  // namespace eSELive
