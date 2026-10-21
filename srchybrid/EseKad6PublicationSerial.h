#pragma once
#include "EseKad6ContactCacheFile.h"
#include "EseControlCookieCrypto.h"
#include "LiveCrypto.h"
#include <algorithm>
namespace ese { namespace discovery {
// Private profile state, not a network message. Sign and flush each allocated
// high-water before constructing a publication. Failure never returns a serial.
class PublicationSerial {
public:
    bool Ready() const noexcept { return ready_; }
    bool Initialize(const wchar_t* path,const std::array<std::uint8_t,32>& node) noexcept {
        if(ready_ || !path || !*path) return false;
        try {
            std::array<wchar_t,32768> absolute{};
            const auto length=GetFullPathNameW(path,static_cast<DWORD>(absolute.size()),absolute.data(),nullptr);
            unsigned key=0; for(auto b:node) key|=b;
            if(!length || length>=absolute.size() || !key) return false;
            const std::wstring target=absolute.data(),temporary=target+L".new";
            std::uint64_t current=0,pending=0; bool missing=false,tempMissing=false;
            if(!Read(target.c_str(),node,current,missing) || !Read(temporary.c_str(),node,pending,tempMissing)) return false;
            if(!tempMissing) {
                if(pending>current) {
                    if(!MoveFileExW(temporary.c_str(),target.c_str(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)) return false;
                    current=pending;
                } else if(!DeleteFileW(temporary.c_str())) return false; // verified owned completed journal only
            }
            target_=target; temporary_=temporary; node_=node; last_=current; ready_=true; return true;
        } catch(...) { return false; }
    }
    bool Allocate(control::Signer& signer,std::uint64_t& serial) noexcept {
        serial=0;
        if(!ready_ || last_==(std::numeric_limits<std::uint64_t>::max)()) return false;
        // Initial profiles start above an old small counter without depending
        // on randomness. Loaded high-water remains authoritative on clock rollback.
        FILETIME time{}; GetSystemTimeAsFileTime(&time);
        const auto clock=(static_cast<std::uint64_t>(time.dwHighDateTime)<<32)|time.dwLowDateTime;
        const auto next=(std::max)(last_+1,clock);
        std::array<std::uint8_t,112> bytes{}; std::memcpy(bytes.data(),"ESK6SQ1",7);
        std::memcpy(bytes.data()+8,node_.data(),32);
        for(unsigned i=0;i<8;++i) bytes[40+i]=static_cast<std::uint8_t>(next>>(56-8*i));
        std::array<std::uint8_t,64> signature{};
        if(!signer.Sign(bytes.data(),48,signature) || !eSELive::VerifySignature(node_.data(),bytes.data(),48,signature.data())) return false;
        std::memcpy(bytes.data()+48,signature.data(),64);
        HANDLE file=CreateFileW(temporary_.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
        if(file==INVALID_HANDLE_VALUE) { ready_=false; return false; }
        DWORD written=0;
        const bool flushed=WriteFile(file,bytes.data(),static_cast<DWORD>(bytes.size()),&written,nullptr)!=FALSE &&
            written==bytes.size() && FlushFileBuffers(file)!=FALSE;
        const bool closed=CloseHandle(file)!=FALSE;
        if(!flushed || !closed) { DeleteFileW(temporary_.c_str()); ready_=false; return false; }
        if(!MoveFileExW(temporary_.c_str(),target_.c_str(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)) {
            ready_=false; return false; // completed signed journal is recoverable
        }
        last_=next; serial=next; return true;
    }
private:
    static bool Read(const wchar_t* path,const std::array<std::uint8_t,32>& node,std::uint64_t& serial,bool& missing) noexcept {
        serial=0; missing=false;
        HANDLE file=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
        if(file==INVALID_HANDLE_VALUE) {
            missing=GetLastError()==ERROR_FILE_NOT_FOUND; return missing;
        }
        BY_HANDLE_FILE_INFORMATION info{}; LARGE_INTEGER size{}; DWORD read=0; std::array<std::uint8_t,112> bytes{};
        const bool valid=GetFileInformationByHandle(file,&info)!=FALSE &&
            !(info.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT)) &&
            GetFileSizeEx(file,&size)!=FALSE && size.QuadPart==112 &&
            ReadFile(file,bytes.data(),static_cast<DWORD>(bytes.size()),&read,nullptr)!=FALSE && read==bytes.size();
        CloseHandle(file);
        if(!valid || std::memcmp(bytes.data(),"ESK6SQ1",7) || bytes[7] || std::memcmp(bytes.data()+8,node.data(),32) ||
            !eSELive::VerifySignature(node.data(),bytes.data(),48,bytes.data()+48)) return false;
        serial=ReadBe(bytes.data()+40,8); return serial!=0;
    }
    std::wstring target_,temporary_; std::array<std::uint8_t,32> node_{};
    std::uint64_t last_=0; bool ready_=false;
};
} }
