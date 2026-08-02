#pragma once
#include <cstdint>
namespace eSELive {
enum class LiveTunnelGatewayStoreOperation : std::uint8_t { Entries, Find, ActiveSize, CanPublish, CanAccept, AddBound, MarkPublished, MarkServing, BeginDrain, Close, EraseClosed, QueueCircuitTeardown, DrainQueuedCircuits, Expire, CohortRegister, CohortSetServing, CohortSelect, CohortReleaseStream, AdmissionPermille, Admit, NoteOverload, Enqueue, TakeDue, Remove, PublishExpire };
}
