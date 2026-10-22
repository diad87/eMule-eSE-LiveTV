#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "../srchybrid/MapperWindowsNotification.h"
#include "natmap/mapper_result_mailbox.h"
#include <thread>
#include <cstdio>
#include <cstdlib>
static unsigned checks=0;
static void Check(bool condition) { ++checks; if(!condition) std::exit(1); }
int main() {
    constexpr UINT message=WM_APP+41;
    HWND window=::CreateWindowExW(0,L"STATIC",L"mapper test",0,0,0,0,0,HWND_MESSAGE,nullptr,::GetModuleHandleW(nullptr),nullptr);
    Check(window!=nullptr);
    auto queue=std::make_shared<natmap::MapperResultMailbox>();
    natmap::MapperOperation op;
    op.id=0xFEDCBA9887654321ULL; op.generation=7; op.started=100; op.deadline=200;
    op.mapper=natmap::MapperKind::Pcp; op.tcp=4662; op.udp=4672;
    natmap::MapperResult result;
    result.success=true; result.external_ipv4=123; result.external_tcp=50000; result.external_udp=50001;
    Check(queue->Begin(op));
    natmap::MapperResultPublisher publisher(queue,op.id);
    bool sent=false;
    std::thread worker([&] { sent=publisher.Publish(result,[&](std::uint64_t id) { return natmap::PostMapperOperation(window,message,id); }); });
    worker.join(); Check(sent);
    MSG msg{}; Check(::PeekMessageW(&msg,window,message,message,PM_REMOVE)!=FALSE);
    Check(natmap::DecodeMapperOperation(msg.wParam,msg.lParam)==op.id);
    natmap::OwnedMapperResult owned;
    Check(queue->Take(natmap::DecodeMapperOperation(msg.wParam,msg.lParam),7,199,owned));
    Check(owned.result.external_tcp==50000 && owned.operation.tcp==4662);
    Check(!queue->Take(op.id,7,199,owned));
    ++op.id; Check(queue->Begin(op));
    natmap::MapperResultPublisher cancelled(queue,op.id);
    Check(cancelled.Publish(result,[&](std::uint64_t id) { return natmap::PostMapperOperation(window,message,id); }));
    cancelled.Cancel();
    Check(::PeekMessageW(&msg,window,message,message,PM_REMOVE)!=FALSE);
    Check(!queue->Take(natmap::DecodeMapperOperation(msg.wParam,msg.lParam),7,199,owned));
    ++op.id; Check(queue->Begin(op));
    natmap::MapperResultPublisher stale(queue,op.id);
    Check(stale.Publish(result,[&](std::uint64_t id) { return natmap::PostMapperOperation(window,message,id); }));
    Check(::PeekMessageW(&msg,window,message,message,PM_REMOVE)!=FALSE);
    Check(!queue->Take(natmap::DecodeMapperOperation(msg.wParam,msg.lParam),8,199,owned));
    Check(owned.operation.id==0);
    Check(::DestroyWindow(window)!=FALSE);
    ++op.id; Check(queue->Begin(op));
    natmap::MapperResultPublisher deadWindow(queue,op.id);
    Check(!deadWindow.Publish(result,[&](std::uint64_t id) { return natmap::PostMapperOperation(window,message,id); }));
    Check(!queue->Take(op.id,7,199,owned));
    Check(!natmap::PostMapperOperation(nullptr,message,op.id));
    Check(!natmap::PostMapperOperation(window,0,op.id));
    Check(!natmap::PostMapperOperation(window,message,0));
    std::printf("mapper Windows messages: %u checks PASS (real PostMessage; not router/MFC acceptance)\n",checks);
}
