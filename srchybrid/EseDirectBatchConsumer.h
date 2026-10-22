#pragma once
#include "reach/direct_coordinator.h"
#include <utility>
namespace ese {
class DirectBatchConsumer {
public:
    virtual ~DirectBatchConsumer() = default;
    // Takes ownership of every action/terminal notification on the main thread.
    // Must not throw, pump UI messages, or destroy/replace itself in this call.
    virtual void Accept(std::vector<reach::DirectCoordinatorBatch>&&) noexcept = 0;
    virtual void Poll() noexcept {} // main-thread IO also when no coordinator actions arrive
};
class DirectBatchPump {
public:
    bool Busy() const noexcept { return busy_; }
    template<class Pump> bool Tick(DirectBatchConsumer* consumer,Pump pump) {
        if(!consumer || busy_) return false; // never drain without a receiver
        busy_=true;
        struct Reset { bool& value; ~Reset() { value=false; } } reset{busy_};
        auto batches=pump();
        if(!batches.empty()) consumer->Accept(std::move(batches));
        consumer->Poll();
        return true;
    }
private:
    bool busy_=false;
};
}
