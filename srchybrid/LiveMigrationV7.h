// this file is part of eMule eSE — v7.x → V1 migration helpers (F5b)
//
// Imports legacy state files from v7.x.x of the fork so users updating to
// V1 keep their discovery cache + recent streams.
//
// Legacy files (left in place by v7.x):
//   - %APPDATA%\eMule\config\eselive_directory.dat — text key=value lines
//     written by CLiveKadBridge::SaveDirectoryToDisk()
//   - %APPDATA%\eMule\config\last_streams.json — bootstrap cache JSON
//
// V1 reads these once at first launch, imports valid entries into
// CLiveKadBridge's directory + the bootstrap pinger, and leaves the files
// in place so v7.x still loads them. A marker file `migration_v1.done` is
// written so the importer is idempotent.
#pragma once

namespace eSELive {

class CLiveMigrationV7 {
public:
    // Called once at app startup, before LiveStreamManager starts. Returns
    // the number of entries imported (0 if no legacy file, no migration
    // needed; -1 on error). Idempotent: if the marker file exists, no-op.
    static int RunIfNeeded();

    // Force re-run (for manual user trigger). Resets the marker.
    static int ForceRun();

    static CStringW MarkerPath();
    static CStringW LegacyDirectoryPath();
    static CStringW LegacyLastStreamsPath();

private:
    static bool ImportDirectoryDat();
    static bool ImportLastStreamsJson();
};

}  // namespace eSELive
