#pragma once
#include <windows.h>
#include <string>
#include <cstring>
#include "EseKad6ContactCache.h"
namespace ese { namespace discovery {
// Resolve the Vista+ API without raising the host's legacy SDK target.
// Missing API fails closed rather than substituting locale-sensitive equality.
inline int CompareContactCachePaths(const wchar_t* left,const wchar_t* right) noexcept {
    using Compare = int (WINAPI*)(LPCWCH,int,LPCWCH,int,BOOL);
    const auto module=GetModuleHandleW(L"kernel32.dll");
    const auto address=module ? GetProcAddress(module,"CompareStringOrdinal") : nullptr;
    Compare compare=nullptr;
    static_assert(sizeof(compare)==sizeof(address),"Windows function pointer size");
    std::memcpy(&compare,&address,sizeof(compare));
    return compare ? compare(left,-1,right,-1,TRUE) : 0;
}
inline bool SaveContactCache(const Kad6ContactCache& cache,const wchar_t* target,const wchar_t* temporary) noexcept {
    if(!target || !temporary || !*target || !*temporary) return false;
    try {
        std::array<wchar_t,32768> finalPath{},tempPath{};
        const auto a=GetFullPathNameW(target,static_cast<DWORD>(finalPath.size()),finalPath.data(),nullptr);
        const auto b=GetFullPathNameW(temporary,static_cast<DWORD>(tempPath.size()),tempPath.data(),nullptr);
        if(!a || !b || a>=finalPath.size() || b>=tempPath.size()) return false;
        std::wstring final(finalPath.data()),temp(tempPath.data());
        const auto samePath=CompareContactCachePaths(final.c_str(),temp.c_str());
        if(!samePath || samePath==CSTR_EQUAL) return false;
        const auto parentFinal=final.substr(0,final.find_last_of(L"\\/"));
        const auto parentTemp=temp.substr(0,temp.find_last_of(L"\\/"));
        if(CompareContactCachePaths(parentFinal.c_str(),parentTemp.c_str())!=CSTR_EQUAL) return false;
        std::array<std::uint8_t,32768> bytes{}; std::size_t size=0;
        if(!cache.Serialize(bytes,size)) return false;
        HANDLE file=CreateFileW(temp.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
        if(file==INVALID_HANDLE_VALUE) return false;
        DWORD written=0;
        const bool flushed=WriteFile(file,bytes.data(),static_cast<DWORD>(size),&written,nullptr)!=FALSE && written==size && FlushFileBuffers(file)!=FALSE;
        const bool closed=CloseHandle(file)!=FALSE;
        const bool moved=flushed && closed && MoveFileExW(temp.c_str(),final.c_str(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)!=FALSE;
        if(!moved) DeleteFileW(temp.c_str()); // only the file created successfully above
        return moved;
    } catch(...) { return false; }
}
inline bool LoadContactCache(Kad6ContactCache& cache,const wchar_t* path,const kad6::Kad6CryptoHooks& crypto) noexcept {
    if(!path || !*path) return false;
    HANDLE file=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    if(file==INVALID_HANDLE_VALUE) return false;
    BY_HANDLE_FILE_INFORMATION info{}; LARGE_INTEGER length{}; std::array<std::uint8_t,32768> bytes{}; DWORD read=0;
    const bool valid=GetFileInformationByHandle(file,&info)!=FALSE && !(info.dwFileAttributes&(FILE_ATTRIBUTE_REPARSE_POINT|FILE_ATTRIBUTE_DIRECTORY)) &&
        GetFileSizeEx(file,&length)!=FALSE && length.QuadPart>=12 && length.QuadPart<=32768 &&
        ReadFile(file,bytes.data(),static_cast<DWORD>(length.QuadPart),&read,nullptr)!=FALSE && read==length.QuadPart;
    CloseHandle(file);
    return valid && cache.Load(bytes.data(),read,crypto);
}
} }
