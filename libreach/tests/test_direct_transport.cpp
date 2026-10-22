// SPDX-License-Identifier: MIT
#include "reach/direct_transport.h"
#include <cstdio>
#include <memory>
using namespace reach;
static int checks=0,failures=0;
#define CHECK(x) do {++checks; if(!(x)){++failures; std::printf("FAIL line %d: %s\n",__LINE__,#x);}} while(0)
int main()
{
    DirectBufferPool pool(12);
    const std::uint8_t bytes[]={1,2,3,4,5,6,7,8};
    {
        DirectBufferPool global(12),tx(global,8),rx(global,8);
        DirectTransportBuffers data(tx,rx);
        CHECK(data.Send({bytes,8}).accepted==8 && tx.Used()==8 && global.Used()==8);
        CHECK(data.Receive({bytes,8}).accepted==4 && rx.Used()==4 && global.Used()==12);
        CHECK(!rx.ReserveExact(1) && rx.Used()==4 && global.Used()==12);
        CHECK(data.AcknowledgeThrough(3) && tx.Used()==8); // owning chunk retained
        CHECK(data.AcknowledgeThrough(8) && tx.Used()==0 && global.Used()==4);
        CHECK(data.Receive({bytes,8}).accepted==4 && rx.Used()==8);
        CHECK(!rx.ReserveExact(1) && global.Used()==8); // session cap despite global room
        CHECK(data.ConsumeReceived(4) && rx.Used()==4 && global.Used()==4);
        CHECK(rx.ReserveExact(4) && rx.Used()==8 && global.Used()==8); // parser/copy shares RX
        CHECK(data.Receive({bytes,1}).accepted==0);
        data.Close(); CHECK(rx.Used()==4 && global.Used()==4);
        rx.Release(4); CHECK(rx.Used()==0 && tx.Used()==0 && global.Used()==0);
        CHECK(tx.ReserveUpTo(100)==8 && global.Used()==8);
        CHECK(rx.ReserveUpTo(100)==4 && global.Used()==12);
        tx.Release(8); rx.Release(4); CHECK(global.Used()==0);
    }
    {
        DirectTransportBuffers a(pool,8,8),b(pool,8,8);
        CHECK(a.Send({nullptr,1}).status==DirectIoStatus::Invalid && pool.Used()==0);
        CHECK(a.Send({bytes,8}).accepted==8 && pool.Used()==8);
        CHECK(a.Send({bytes,1}).status==DirectIoStatus::WouldBlock);
        auto partial=b.Send({bytes,8});
        CHECK(partial.status==DirectIoStatus::Accepted && partial.accepted==4 && pool.Used()==12);
        CHECK(b.Receive({bytes,1}).status==DirectIoStatus::WouldBlock);
        CHECK(!a.AcknowledgeThrough(9) && pool.Used()==12);
        CHECK(a.AcknowledgeThrough(3) && pool.Used()==12);
        CHECK(a.TransmitFront().size==5 && a.TransmitFront().data[0]==4);
        CHECK(a.AcknowledgeThrough(3) && pool.Used()==12);
        CHECK(!a.AcknowledgeThrough(2));
        CHECK(a.Receive({bytes,8}).status==DirectIoStatus::WouldBlock);
        CHECK(b.AcknowledgeThrough(4) && pool.Used()==8);
        CHECK(a.Receive({bytes,8}).accepted==4 && pool.Used()==12);
        a.SetReceiveBudget(0);
        CHECK(a.Receive({bytes,1}).status==DirectIoStatus::WouldBlock && a.ReceiveFront().size==4);
        CHECK(!a.ConsumeReceived(5) && pool.Used()==12);
        CHECK(a.ConsumeReceived(2) && pool.Used()==12 && a.ReceiveFront().data[0]==3);
        CHECK(a.AcknowledgeThrough(8) && a.TransmitFront().size==0 && pool.Used()==4);
        a.SetReceiveBudget(8);
        CHECK(a.Receive({bytes,8}).accepted==4 && pool.Used()==8);
        CHECK(a.ConsumeReceived(6) && pool.Used()==0 && a.ReceiveFront().size==0);
        CHECK(b.AcknowledgeThrough(4) && pool.Used()==0);
        CHECK(a.Send({bytes,8}).accepted==8 && a.Snapshot().accepted_offset==16);
        a.Close(); a.Close();
        CHECK(pool.Used()==0 && a.Snapshot().closed && a.TransmitFront().size==0);
        CHECK(a.Send({bytes,1}).status==DirectIoStatus::Closed);
        CHECK(a.Receive({bytes,1}).status==DirectIoStatus::Closed);
    }
    CHECK(pool.Used()==0);
    {
        DirectTransportBuffers a(pool,8,8);
        a.Send({bytes,8});
    }
    CHECK(pool.Used()==0); // destructor drains outstanding ownership
    {
        DirectBufferPool streamPool(32);
        DirectTransportBuffers stream(streamPool,32,32);
        DirectStreamWriter writer(stream);
        CHECK(writer.Pending().size==0 && writer.Submitted(0));
        CHECK(stream.Send({bytes,4}).accepted==4);
        const auto first=writer.Pending();
        CHECK(first.size==4 && writer.Submitted(2));
        CHECK(writer.Pending().data==first.data+2 && writer.Pending().size==2);
        CHECK(stream.Send({bytes+4,4}).accepted==4 && first.data[0]==1 && first.data[3]==4);
        CHECK(!writer.Submitted(3) && writer.SubmittedOffset()==2);
        CHECK(!writer.Acknowledged(0,3) && !writer.Acknowledged(1,1));
        CHECK(writer.Acknowledged(0,1) && streamPool.Used()==8 && first.data[3]==4);
        CHECK(stream.TransmitAt(0).size==0 && stream.TransmitAt(1).data[0]==2);
        CHECK(writer.Pending().data==first.data+2 && writer.Submitted(2));
        CHECK(writer.Pending().size==4 && writer.Pending().data[0]==5);
        CHECK(writer.Submitted(4) && writer.SubmittedOffset()==8 && writer.Pending().size==0);
        CHECK(!writer.Acknowledged(1,UINT64_MAX));
        CHECK(writer.Acknowledged(1,3) && streamPool.Used()==4);
        CHECK(writer.Acknowledged(4,4) && streamPool.Used()==0);
        CHECK(writer.Acknowledged(8,0)); // empty FIN ACK
        CHECK(!writer.Acknowledged(0,8));
        CHECK(stream.Send({bytes,8}).accepted==8 && writer.Pending().size==8);
        stream.Close();
        CHECK(writer.Pending().size==0 && !writer.Submitted(0) && !writer.Acknowledged(8,0));
    }

    // Datagram ingestion must never accept a truncated packet or leak credit.
    {
        DirectBufferPool atomicPool(12);
        DirectTransportBuffers a(atomicPool,8,8),b(atomicPool,8,8);
        CHECK(a.ReceiveAtomic({nullptr,1}).status==DirectIoStatus::Invalid);
        CHECK(a.ReceiveAtomic({bytes,8}).accepted==8 && atomicPool.Used()==8);
        CHECK(b.ReceiveAtomic({bytes,8}).status==DirectIoStatus::WouldBlock);
        CHECK(b.ReceiveFront().size==0 && atomicPool.Used()==8);
        CHECK(b.ReceiveAtomic({bytes,4}).accepted==4 && atomicPool.Used()==12);
        CHECK(a.ConsumeReceived(4) && atomicPool.Used()==12);
        CHECK(a.ReceiveAtomic({bytes,1}).status==DirectIoStatus::WouldBlock);
        CHECK(a.ConsumeReceived(4) && atomicPool.Used()==4);
        a.SetReceiveBudget(3);
        CHECK(a.ReceiveAtomic({bytes,4}).status==DirectIoStatus::WouldBlock);
        CHECK(a.ReceiveFront().size==0 && atomicPool.Used()==4);
        CHECK(a.ReceiveAtomic({bytes,3}).accepted==3 && atomicPool.Used()==7);
        a.Close(); b.Close();
        CHECK(atomicPool.Used()==0);
        CHECK(a.ReceiveAtomic({bytes,1}).status==DirectIoStatus::Closed);
    }

    // Production limits, sharing one real pool across adapters.
    DirectBufferPool global;
    std::vector<std::uint8_t> block(kDirectSessionBufferLimit,0x5a);
    std::vector<std::unique_ptr<DirectTransportBuffers>> sessions;
    for(int i=0;i<16;++i) {
        auto session=std::make_unique<DirectTransportBuffers>(global);
        CHECK(session->Send({block.data(),block.size()}).accepted==block.size());
        CHECK(session->Receive({block.data(),block.size()}).accepted==block.size());
        CHECK(session->Send({bytes,1}).status==DirectIoStatus::WouldBlock);
        sessions.push_back(std::move(session));
    }
    CHECK(global.Used()==kDirectGlobalBufferLimit);
    DirectTransportBuffers overflow(global);
    CHECK(overflow.Send({bytes,1}).status==DirectIoStatus::WouldBlock);
    sessions.front()->Close();
    CHECK(overflow.Send({bytes,8}).accepted==8);
    sessions.clear(); overflow.Close();
    CHECK(global.Used()==0);
    DirectBufferPool metadata_pool;
    DirectTransportBuffers tiny(metadata_pool);
    for(std::size_t i=0;i<kDirectBufferChunkLimit;++i) tiny.Send({bytes,1});
    CHECK(tiny.Send({bytes,1}).status==DirectIoStatus::WouldBlock);
    CHECK(tiny.AcknowledgeThrough(1024) && metadata_pool.Used()==0);
    std::printf("test_direct_transport: %d checks, %d failures\n",checks,failures);
    return failures ? 1 : 0;
}
