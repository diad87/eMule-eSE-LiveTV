#pragma once
#include "EseUdpDemux.h"
namespace ese { namespace udp {
// Library-owned parsing only; no allocation, connection creation or callbacks.
bool DecodeQuicHeader(const std::uint8_t*,std::size_t,std::size_t shortCidSize,Header&) noexcept;
bool AcceptQuicInitial(const std::uint8_t*,std::size_t) noexcept;
} }
