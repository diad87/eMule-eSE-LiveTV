#pragma once
#include "EseEd2kFramer.h"
#include "EseQuicTransport.h"
namespace ese {
struct QuicEd2kPumpResult { std::size_t bytes=0,frames=0; bool valid=true; };
// Owning thread only. Framer must be destroyed before retiring the transport's
// RX pool; deliver must not retire the transport or pump UI messages.
template<class Deliver>
QuicEd2kPumpResult PumpQuicEd2k(QuicTransport& transport,Ed2kFramer& framer,
    reach::DirectHandle handle,std::uint32_t route,std::uint64_t epoch,Deliver deliver,
    std::size_t byteBudget=64*1024,std::size_t frameBudget=64) {
    QuicEd2kPumpResult result;
    if(&framer.Pool()!=&transport.RxPool() || !transport.AllowsDelivery(handle,route,epoch)) {
        result.valid=false; return result; // stale caller cannot consume or close winner
    }
    while(result.bytes<byteBudget && result.frames<frameBudget) {
        const auto view=transport.ReceivedFront(); if(!view.size) break;
        std::size_t consumed=0;
        const auto status=framer.Feed({view.data,(std::min)(view.size,byteBudget-result.bytes)},consumed);
        if(consumed && !transport.ConsumeReceived(consumed)) {
            framer.Abort(); transport.Close(reach::DirectReason::DirectUnreachable); result.valid=false; break;
        }
        result.bytes+=consumed;
        if(status==Ed2kFrameStatus::Invalid || status==Ed2kFrameStatus::ResourceLimit) {
            framer.Abort(); transport.Close(status==Ed2kFrameStatus::ResourceLimit ?
                reach::DirectReason::ResourceLimit : reach::DirectReason::DirectUnreachable);
            result.valid=false; break;
        }
        if(status==Ed2kFrameStatus::Frame) {
            bool accepted=false;
            try { accepted=transport.AllowsDelivery(handle,route,epoch) && deliver(framer); }
            catch(...) { framer.Abort(); transport.Close(reach::DirectReason::ResourceLimit); result.valid=false; break; }
            framer.Next();
            if(!accepted) { transport.Close(reach::DirectReason::DirectUnreachable); result.valid=false; break; }
            ++result.frames;
        } else if(!consumed) break;
    }
    return result;
}
}
