#pragma once
#include "EsePeerTrust.h"
#include <windows.h>
#include <cwchar>
#include <string>

namespace ese { namespace trust {
enum class LoadResult { Loaded, Missing, Invalid, IoError };
enum class SaveResult { Created, AlreadyKnown, Changed, Invalid, IoError };
// Paths belong to the caller's private profile. Parent directory ownership and
// ACLs remain the profile's responsibility; this is not a network import API.
inline LoadResult LoadRecord(const wchar_t* path,Record& output) noexcept {
    if(!path || !*path) return LoadResult::Invalid;
    HANDLE file=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    if(file==INVALID_HANDLE_VALUE) {
        const auto error=GetLastError();
        return error==ERROR_FILE_NOT_FOUND || error==ERROR_PATH_NOT_FOUND ? LoadResult::Missing : LoadResult::IoError;
    }
    BY_HANDLE_FILE_INFORMATION info{}; LARGE_INTEGER size{};
    std::array<std::uint8_t,RecordSize> bytes{}; DWORD read=0;
    const bool validFile=GetFileInformationByHandle(file,&info) &&
        !(info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT)) &&
        GetFileSizeEx(file,&size) && size.QuadPart==RecordSize;
    const bool readOk=validFile && ReadFile(file,bytes.data(),static_cast<DWORD>(bytes.size()),&read,nullptr) && read==bytes.size();
    const bool closed=CloseHandle(file)!=FALSE;
    if(!validFile) return LoadResult::Invalid;
    if(!readOk || !closed) return LoadResult::IoError;
    return Decode(bytes.data(),bytes.size(),output) ? LoadResult::Loaded : LoadResult::Invalid;
}
inline SaveResult ExistingResult(LoadResult result,const Record& existing,const Record& desired) noexcept {
    if(result==LoadResult::Invalid) return SaveResult::Invalid;
    if(result!=LoadResult::Loaded) return SaveResult::IoError;
    return existing.node==desired.node ? SaveResult::AlreadyKnown : SaveResult::Changed;
}
// Complete write + flush + close before non-replacing atomic publication.
// A concurrent publisher wins without its file being overwritten. Temporary
// file is deleted only after we successfully created it ourselves.
inline SaveResult PersistFirstUse(const wchar_t* path,const wchar_t* temporary,
    const binding::Session& session,const std::array<std::uint8_t,32>& expected) noexcept {
    if(!path || !*path || !temporary || !*temporary || !_wcsicmp(path,temporary)) return SaveResult::Invalid;
    const auto* peer=session.BoundPeer();
    if(!peer || peer->node!=expected) return SaveResult::Invalid;
    Record existing;
    const auto prior=LoadRecord(path,existing);
    const Record desired{expected,1,Kind::Tofu};
    if(prior!=LoadResult::Missing) return ExistingResult(prior,existing,desired);
    const auto prepared=PrepareFirstUse(session,expected,std::nullopt);
    std::array<std::uint8_t,RecordSize> bytes{};
    if(!prepared || !Encode(*prepared,bytes)) return SaveResult::Invalid;
    HANDLE file=CreateFileW(temporary,GENERIC_WRITE,0,nullptr,CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL|FILE_FLAG_WRITE_THROUGH,nullptr);
    if(file==INVALID_HANDLE_VALUE) return SaveResult::IoError;
    DWORD written=0;
    const bool complete=WriteFile(file,bytes.data(),static_cast<DWORD>(bytes.size()),&written,nullptr) &&
        written==bytes.size() && FlushFileBuffers(file);
    const bool closed=CloseHandle(file)!=FALSE;
    if(!complete || !closed) { DeleteFileW(temporary); return SaveResult::IoError; }
    if(MoveFileExW(temporary,path,MOVEFILE_WRITE_THROUGH)) return SaveResult::Created;
    DeleteFileW(temporary);
    // No replacement flag: even if an existing destination appears after our
    // initial load, its trust remains authoritative and unchanged.
    return ExistingResult(LoadRecord(path,existing),existing,desired);
}
class FileCommitter final : public Committer {
public:
    FileCommitter(std::wstring path,std::wstring temporary)
        : path_(std::move(path)),temporary_(std::move(temporary)) {}
    CommitResult Commit(const binding::Session& session,
        const std::array<std::uint8_t,32>& expected) noexcept override {
        const auto saved=PersistFirstUse(path_.c_str(),temporary_.c_str(),session,expected);
        if(saved==SaveResult::Created || saved==SaveResult::AlreadyKnown) return CommitResult::Stored;
        return saved==SaveResult::Changed ? CommitResult::PinChanged : CommitResult::PersistenceFailed;
    }
private:
    std::wstring path_,temporary_;
};
} }
