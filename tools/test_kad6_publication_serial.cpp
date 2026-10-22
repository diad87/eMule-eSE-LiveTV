#include "../srchybrid/EseKad6PublicationSerial.h"
#include <cstdio>
#include <cstdlib>
using namespace ese;
static unsigned checks=0;
static void Check(bool ok) { ++checks; if(!ok) { std::printf("FAIL serial check%u\n",checks); std::exit(1); } }
struct Identity final : control::Signer {
    std::array<std::uint8_t,32> pub{},secret{};
    Identity() { Check(eSELive::GenerateBroadcasterKeypair(pub.data(),secret.data())); }
    ~Identity() { SecureZeroMemory(secret.data(),secret.size()); }
    bool Sign(const std::uint8_t* p,std::size_t n,std::array<std::uint8_t,64>& out) noexcept override {
        return eSELive::SignMessage(secret.data(),pub.data(),p,n,out.data());
    }
};
int main() {
    Identity owner,foreign;
    std::array<wchar_t,MAX_PATH> path{};
    Check(GetTempFileNameW(L"D:\\tmp",L"ksq",0,path.data())!=0);
    Check(DeleteFileW(path.data())!=FALSE);
    const std::wstring journal=std::wstring(path.data())+L".new";
    struct Cleanup { const wchar_t* path; const std::wstring& journal;
        ~Cleanup() { DeleteFileW(path); DeleteFileW(journal.c_str()); }
    } cleanup{path.data(),journal};
    discovery::PublicationSerial serials; std::uint64_t first=0,second=0,next=0;
    Check(!serials.Allocate(owner,first) && first==0);
    Check(serials.Initialize(path.data(),owner.pub) && serials.Ready());
    Check(!serials.Initialize(path.data(),owner.pub));
    Check(!serials.Allocate(foreign,first) && first==0);
    Check(serials.Allocate(owner,first) && first>0);
    Check(serials.Allocate(owner,second) && second>first);
    discovery::PublicationSerial restarted;
    Check(restarted.Initialize(path.data(),owner.pub));
    Check(restarted.Allocate(owner,next) && next>second);
    discovery::PublicationSerial wrongNode;
    Check(!wrongNode.Initialize(path.data(),foreign.pub));
    Check(GetFileAttributesW(path.data())!=INVALID_FILE_ATTRIBUTES);
    // A completed journal left before rename is recovered, not reset/reused.
    Check(CopyFileW(path.data(),journal.c_str(),TRUE)!=FALSE);
    Check(DeleteFileW(path.data())!=FALSE);
    discovery::PublicationSerial recovered;
    Check(recovered.Initialize(path.data(),owner.pub));
    Check(GetFileAttributesW(journal.c_str())==INVALID_FILE_ATTRIBUTES);
    second=next; Check(recovered.Allocate(owner,next) && next>second);
    // Existing journal prevents overwriting. Recovery of our valid equal
    // journal is explicit and the new allocation remains strictly newer.
    Check(CopyFileW(path.data(),journal.c_str(),TRUE)!=FALSE);
    Check(!recovered.Allocate(owner,first) && first==0 && !recovered.Ready());
    Check(recovered.Initialize(path.data(),owner.pub));
    second=next; Check(recovered.Allocate(owner,next) && next>second);
    // Corrupted profile state is a failure, not an invitation to start at1.
    HANDLE file=CreateFileW(path.data(),GENERIC_WRITE,0,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
    Check(file!=INVALID_HANDLE_VALUE); DWORD written=0; const BYTE corrupt=0xff;
    Check(WriteFile(file,&corrupt,1,&written,nullptr)!=FALSE && written==1 && FlushFileBuffers(file)!=FALSE);
    Check(CloseHandle(file)!=FALSE);
    discovery::PublicationSerial corrupted;
    Check(!corrupted.Initialize(path.data(),owner.pub));
    Check(!corrupted.Allocate(owner,first) && first==0);
    Check(GetFileAttributesW(path.data())!=INVALID_FILE_ATTRIBUTES);
    std::printf("Kad6 publication serial: %u checks PASS (real signed durable profile/journal; no network publication claim)\n",checks);
}
